// Nintendo SDK NSO（entry_32848007）的装载器。
//
// 为什么必须有它：main NSO 导入的 1001 个 nn::* 符号**绝大部分由 SDK NSO 导出**
// （SDK 导出 23,000 个符号）。只装 main ⇒ 那些由 SDK 初始化的全局管理器永远 NULL
// ⇒ 客机一碰就崩（实测崩在「对 NULL 对象调虚函数」，映像偏移 0x24F2C）。
//
// 基址安排（实测得出）：
//   - main 必须映射在 0x100000000：SDK 的 .data 里有 85 个指针直接写死
//     「0x100000000 + main 内部偏移」；main 自己的 .data 里也有 1168 个这种形态
//     （映射在 0x100000000 时它们天然正确，不用改）。
//   - SDK 可以映射在**任意地址**：它的 .text 里没有硬编码基址，代码是位置无关的；
//     它那 85 个指向 main 的指针因为 main 就在 0x100000000 而天然正确。
//
// SDK 自己的内部指针（.data 里 24,977 个模块内偏移）由基址重定位修正 ✓。

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "za_common.h"
#include "za_mod.h"

// SDK 的「os 上下文」对象（za_sdk_load 里建，za_guest_boot 用）。
void *za_sdk_ctx = NULL;
#include "za_mem.h"
#include "za_guest_api.h"
#include "za_guest_info.h"
#include "za_os.h"
#include "za_sdk.h"
#include "za_svc_patch.h"
#include "za_tlsro_patch.h"
#include "za_tlsbase_patch.h"
extern long za_horizon_svc(long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long nr);
extern volatile unsigned long za_horizon_regs[16];
// 崩溃现场要用它把地址换算成「sdk+偏移」（定义在 za_guest.c）
volatile int za_cnctp_ready;   /* CNTPCT 桩/hook 槽已装好（看门狗门控用） */

// ── NvOsHeapAllocatorAlloc 入口探针 ──────────────────────────────────
// SDK+0x44f9f0 的首指令被换成 b <探针桩>；桩保留全部调用者寄存器，
// 回调这里打一次日志，然后跳回 0x44f9f4 继续原函数。
// 目的：一次运行就能拿到 nvn 堆对象的 arena 字段（+0x38 基址 / +0x40 大小）
// 到底是什么值、以及分配发生前它有没有被正确初始化。
static void za_nvn_probe_hook(unsigned long long heap)
{
    static int once;
    if (once) return;
    once = 1;
    unsigned long long b = 0, s = 0;
    memcpy(&b, (const void *)(uintptr_t)(heap + 0x38), 8);
    memcpy(&s, (const void *)(uintptr_t)(heap + 0x40), 8);
    ZLOGI("★ NvOsHeap probe: heap=%#llx  [heap+0x38]=%#llx  [heap+0x40]=%#llx",
          heap, b, s);
}

// 探针桩（27 条指令，objdump 验证过）：
//   stp x29,x30,[sp,#-0x30]!        ← 原文首指令 1:1
//   sub sp,sp,#0x90
//   stp/ldp x0..x17                  ← 保存/恢复全部调用者寄存器
//   ldr x0,[sp]                      ← heap 参数
//   adrp/ldr/blr x16                 ← hook 槽 (base+0xc90608)
//   add sp,sp,#0x90 ; ldp x29,x30,[sp] ; b 0x44f9f4
static const unsigned int za_nvn_probe_stub[27] = {
    0xA9BD7BFD, 0xD10243FF, 0xA90007E0, 0xA9010FE2, 0xA90217E4, 0xA9031FE6,
    0xA90427E8, 0xA9052FEA, 0xA90637EC, 0xA9073FEE, 0xA90847F0, 0xF94003E0,
    0x90000010, 0xF9430610, 0xD63F0200,
    0xA94007E0, 0xA9410FE2, 0xA94217E4, 0xA9431FE6, 0xA94427E8, 0xA9452FEA,
    0xA94637EC, 0xA9473FEE, 0xA94847F0, 0x910243FF,
    /* ⚠ 这里**不能带写回**：原函数首指令（stp x29,x30,[sp,#-0x30]!）已被本桩
     *   1:1 模拟并**不会**再执行，所以恢复后 sp 必须停在 S-0x30，
     *   让调用者自己的 epilogue（ldp ...,#0x30）回到 S。
     *   带写回 ⇒ sp 比应有值高 0x30 ⇒ 第二次调用就把返回地址踩坏
     *   （实测：pc=sdk+0xb9eb80，跳到数据段）。 */
    0xA9407BFD,
    0x17DEFD23,
};
extern volatile unsigned long za_sdk_base;
extern volatile unsigned long za_sdk_size;
extern unsigned char *za_guest_base;      // main 映像基址（za_guest.c）
// 只读 TLS 页的绝对地址（SDK 装载时填）。za_horizon.c 的临界区要按同一来源取 owner_id。
volatile unsigned long za_ro_tls_page = 0;

// ── 通用入口探针（用于把「SDK 里的断言/ABORT」打出人话）────────────────
// 桩：保存 x0–x17 → x0=&保存区 → blr hook → 恢复 → 执行原首指令 → 回 +4。
// ⚠ 末尾必须是 **ldp x29,x30,[sp],#0x30（带写回）**：不带写回会让 sp 每次
//   下移 0x30（原版 nvn 探针就踩过这个坑 —— 每次分配泄漏 48 字节栈）。
// 每个探针各自限流（共用一个计数器会让先触发的探针把后面的全吃掉）
static int *za_probe_budget(const char *name)
{
    static struct { const char *name; int used; } b[8];
    static int nb;
    for (int i = 0; i < nb; i++) if (b[i].name == name) return &b[i].used;
    if (nb >= 8) return &b[0].used;
    b[nb].name = name; b[nb].used = 0;
    return &b[nb++].used;
}
static void za_probe_log(const char *name, const unsigned long long *r)
{
    int *used = za_probe_budget(name);
    if (*used >= 8) return;
    (*used)++;
    ZLOGI("★ 探针 %s: x0=%#llx x1=%#llx x2=%#llx x3=%#llx x4=%#llx x5=%#llx x6=%#llx x7=%#llx"
          "  fp=%#llx lr=%#llx", name, r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7],
          r[18], r[19]);
    // 把「看起来是 SDK/main 映像内地址」的参数当 C 字符串打出来
    for (int i = 0; i < 6; i++)
    {
        unsigned long long v = r[i];
        int in_sdk = (za_sdk_base && v >= za_sdk_base && v < za_sdk_base + za_sdk_size);
        int in_main = (za_guest_base && v >= (unsigned long long)(uintptr_t)za_guest_base &&
                       v < (unsigned long long)(uintptr_t)za_guest_base + ZA_IMAGE_SIZE);
        if (!in_sdk && !in_main) continue;
        const unsigned char *p = (const unsigned char *)(uintptr_t)v;
        int ok = 0;
        for (int k = 0; k < 128; k++)
        {
            unsigned char c = p[k];
            if (!c) { ok = 1; break; }
            if (c < 0x20 && c != '\t' && c != '\n') break;
        }
        if (ok) ZLOGI("   %s arg%d = \"%s\"", name, i, (const char *)p);
    }
}
static void za_hook_assert_entry(unsigned long long *r) { za_probe_log("assert-entry", r); }
static void za_hook_assert_wrap(unsigned long long *r)  { za_probe_log("assert-wrap", r); }
static void za_hook_assert_var(unsigned long long *r)   { za_probe_log("assert-va", r); }
static void za_hook_assert_onfail(unsigned long long *r) { za_probe_log("assert-onfail", r); }
// Abort 入口：除了参数，还要把 **调用者帧链** 走出来 —— abort 本身没有消息，
// 唯一能定位的就是「谁调了它」。fp 是 0x9aba0 的帧指针（x29），
// [fp]=上一帧 fp，[fp+8]=返回地址。
static void za_hook_abort_entry(unsigned long long *r)
{
    static int n;
    za_probe_log("abort-entry", r);
    if (n++ >= 3) return;
    unsigned long long fp = r[18];
    for (int i = 0; i < 14 && fp; i++)
    {
        int plausible = (fp >= 0x400000000ull && fp < 0x920000000ull) ||
                        (fp >= 0x6d00000000ull && fp < 0x8000000000ull) ||
                        (fp >= 0x100000000ull && fp < 0x300000000ull);
        if (!plausible || (fp & 7)) break;
        unsigned long long nfp = 0, ra = 0;
        memcpy(&nfp, (const void *)(uintptr_t)fp, 8);
        memcpy(&ra, (const void *)(uintptr_t)(fp + 8), 8);
        if (ra >= za_sdk_base && ra < za_sdk_base + za_sdk_size)
            ZLOGI("   abort fp[%d] ret=sdk+%#llx", i, ra - za_sdk_base);
        else if (za_guest_base && ra >= (unsigned long long)(uintptr_t)za_guest_base &&
                 ra < (unsigned long long)(uintptr_t)za_guest_base + ZA_IMAGE_SIZE)
            ZLOGI("   abort fp[%d] ret=main+%#llx", i,
                  ra - (unsigned long long)(uintptr_t)za_guest_base);
        else
            ZLOGI("   abort fp[%d] ret=%#llx", i, ra);
        if (nfp <= fp) break;
        fp = nfp;
    }
}

static void za_install_entry_probe(unsigned char *base, unsigned int func_off,
                                   unsigned int stub_off, unsigned int hook_off,
                                   void (*hook)(unsigned long long *))
{
    unsigned int *s = (unsigned int *)(base + stub_off);
    unsigned int orig = *(unsigned int *)(base + func_off);
    /* 保存区布局（r[] 下标 = 字节偏移/8）：
     *   [0..7]  x0..x7      [8..17] x8..x17
     *   [18]    x29（调用者 fp）   [19]    x30（调用者返回地址）
     * 有了 x30 就能直接知道「是谁调了这个函数」——断言/ABORT 定位的关键。 */
    static const unsigned int seq[27] = {
        0xA9BD7BFD, 0xD10283FF,               /* stp x29,x30,[sp,#-0x30]! ; sub sp,sp,#0xa0 */
        0xA9097BFD,                           /* stp x29,x30,[sp,#0x90] */
        0xA90007E0, 0xA9010FE2, 0xA90217E4, 0xA9031FE6,
        0xA90427E8, 0xA9052FEA, 0xA90637EC, 0xA9073FEE, 0xA90847F0,
        0x910003E0,                           /* mov x0, sp  */
        0x90000010, 0xF9400000,               /* adrp/ldr x16 → hook（下面回填） */
        0xD63F0200,                           /* blr x16 */
        0xA94007E0, 0xA9410FE2, 0xA94217E4, 0xA9431FE6,
        0xA94427E8, 0xA9452FEA, 0xA94637EC, 0xA9473FEE, 0xA94847F0,
        0x910283FF,                           /* add sp,sp,#0xa0 */
        0xA8C37BFD,                           /* ldp x29,x30,[sp],#0x30  ← 必须写回 */
    };
    memcpy(s, seq, sizeof seq);
    long long pg = ((long long)(hook_off & ~0xFFFull) -
                    (long long)(stub_off & ~0xFFFull)) >> 12;
    s[13] = 0x90000000u | ((unsigned)(pg & 3) << 29) |
            ((unsigned)((pg >> 2) & 0x7FFFF) << 5) | 16u;
    s[14] = 0xF9400000u | (((hook_off & 0xFFFull) >> 3) << 10) | (16u << 5) | 16u;
    s[27] = orig;                              /* 原函数首指令 */
    {   /* b 回原函数 +4 */
        long long d = (long long)(func_off + 4) - (long long)(stub_off + 28 * 4);
        s[28] = 0x14000000u | (unsigned)((d >> 2) & 0x3FFFFFFu);
    }
    {   /* 原函数入口 → b 桩 */
        long long d = (long long)stub_off - (long long)func_off;
        *(unsigned int *)(base + func_off) = 0x14000000u | (unsigned)((d >> 2) & 0x3FFFFFFu);
    }
    *(unsigned long long *)(base + hook_off) = (unsigned long long)(uintptr_t)hook;
    __builtin___clear_cache((char *)base + stub_off, (char *)base + stub_off + 29 * 4);
    __builtin___clear_cache((char *)base + func_off, (char *)base + func_off + 4);
}
extern volatile unsigned long za_sdk_size;

#define ZA_SDK_IMG_SIZE (ZA_SDK_DATA_OFF + ZA_SDK_DATA_SIZE + ZA_SDK_BSS_SIZE)
// 门区（Horizon svc 宿主门）+ 只读 TLS 页都要在映像末尾扩展区里
#define ZA_SDK_TOTAL_SIZE (ZA_SDK_EXT_SIZE)

// 极少数 .data 槽位里放的是「数值」而不是模块内偏移，启发式必须放过它们。
// 已知：nvn 堆对象 @0xb88fa0 的 arena 描述符
//   +0x38 = 0xc11764 （arena 起始 = SDK bss 内偏移 ⇒ 需要加基址）
//   +0x40 = 0x20000  （arena 字节数，不是指针 ⇒ 加了基址就变成 8.6GB）
// 这两个槽都不在 SDK 官方重定位表里（表只覆盖 heap 开头那几个函数指针），
// 所以只能在这里显式排除尺寸槽。误伤的后果：分配器把 end-0x48 写到未映射区。
static int za_sdk_is_non_pointer_slot(size_t off)
{
    return off == (0x40 + 0xb88fa0) - ZA_SDK_DATA_OFF;   /* heap+0x40 = arena size */
}

// 基址重定位：只扫 .data，规则与 main NSO 相同
// （0x1000 <= v < 映像大小 ⇒ 视为模块内指针，加基址）
static unsigned long long za_sdk_relocate_base(unsigned char *base)
{
    unsigned long long moved = 0, skipped = 0;
    for (size_t off = 0; off + 8 <= ZA_SDK_DATA_SIZE; off += 8)
    {
        unsigned long long *slot = (unsigned long long *)(base + ZA_SDK_DATA_OFF + off);
        unsigned long long v = *slot;
        if (v >= 0x1000 && v < ZA_SDK_IMG_SIZE)
        {
            if (za_sdk_is_non_pointer_slot(off)) { skipped++; continue; }
            *slot = (unsigned long long)base + v;
            moved++;
        }
    }
    if (skipped) ZLOGI("SDK 重定位：跳过 %llu 个已知非指针槽（nvn arena size）", skipped);
    return moved;
}

// 造一块「启动信息块」给 SDK 的 __nnmusl_init_dso / nn::init::Start。
//
// SDK 在 0x145af8 处这样解析它（实测反汇编）：
//     svc#6 QueryMemory(查询 addr = 这个块)   ← **必须是已映射的 RW**，否则 abort
//     检查 MemoryInfo+0x18(perm) == 3
//     x21 = (P+7) & ~7
//     A   = (int32)[x21+4]        ← 字符串区大小
//     B   = (uint32)[x21]         ← **分配空间总大小**（用来推 argv 槽位数）
//     x21 += 0x20                 ← 字符串区起点
//     x24 = x21 + A               ← 字符串区终点
//     x20 = (A + x24 + 9) & ~7    ← argv 指针数组位置（由 SDK 自己填）
//     x25 = B + (P - x20) >> 3    ← **argv 槽位上限**
//     然后从 x21 扫到 x24，按引号规则分词，把每个 token 搬到 x24 之后
//     并把指针写进 argv 数组（`str x22,[x20,x19,lsl 3]`）
//
// ⚠⚠ 2026-10-25 实测的坑：B 不能用一个小值（原来给 0x100）——
//   x25 是 argv 槽位上限，SDK 会按它往 x20 之后连续写指针；
//   块按 switchbrew 的惯例给 **0x9000**（"Normally 0x9000"）。
#define ZA_ARGDATA_TOTAL 0x9000u
void *za_build_startup_info(void)
{
    unsigned char *p = (unsigned char *)calloc(1, ZA_ARGDATA_TOTAL);
    if (!p) return NULL;
    const unsigned int A = 8;              // 字符串区大小（"main\0" + 对齐）
    *(unsigned int *)(p + 0x00) = ZA_ARGDATA_TOTAL;   // 分配空间总大小
    *(unsigned int *)(p + 0x04) = A;                  // 字符串区大小
    memcpy(p + 0x20, "main", 5);                      // 实际参数字符串
    ZLOGI("参数区 @%p：总量 %#x、字符串区 %#x、argv=\"main\"", (void *)p, ZA_ARGDATA_TOTAL, A);
    return p;
}

int za_sdk_load(za_mod_t *sdk,
                const unsigned char *text, size_t text_size,
                const unsigned char *rodata, size_t rodata_size,
                const unsigned char *data, size_t data_size,
                size_t bss,
                const unsigned char *exp_bin, size_t exp_len,
                const unsigned char *rel_bin, size_t rel_len,
                const unsigned char *gate_bin, size_t gate_len,
                void *(*resolve_host)(const char *name, void *ctx),
                void *(*resolve_main)(const char *name, void *ctx),
                void *ctx)
{
    // 1) 映射映像
    //
    // ⚠⚠⚠ **基址必须是 0x100000000 基准的 4GB 对齐地址**，不能随便 mmap！
    //   Nintendo SDK 的 NSO 和 main 一样，**链接基址是 0x100000000**：
    //   它 text 里的 adrp 指令是按「链接基址 + 段内偏移」编码的。
    //   main 我们放在 0x100000000（正好），SDK 放在 **0x200000000**。
    //   ⇒ 之前把 SDK 映射到随机 mmap 地址 ⇒ **SDK 里每一个 adrp 都偏了 4GB**，
    //      读到的全是无关内存 ⇒ 垃圾指针 ⇒ 跳空(pc=0) / 随机崩溃。
    //   （实测证据：SDK 要访问的 .data 槽 base+0xb740128 在随机基址下落在映像外 ⇒ 直接 fault。）
    //
    //   选 0x200000000 的原因：main 占了 0x100000000 这一段。
    size_t mapped = (ZA_SDK_TOTAL_SIZE + 0xFFF) & ~(size_t)0xFFF;
    unsigned char *base = (unsigned char *)mmap((void *)(uintptr_t)ZA_SDK_BASE_ADDR,
                                               mapped, PROT_READ | PROT_WRITE,
                                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (base == MAP_FAILED)
    {
        // 固定地址被占（很罕见）：退回到任意地址，但**必须警告**，
        // 因为那时 SDK 的 adrp 会全部指错。
        ZLOGE("SDK 映像固定基址 %#lx 被占，改用任意地址（SDK 的 adrp 会指错！）：%s",
              (unsigned long)ZA_SDK_BASE_ADDR, strerror(errno));
        base = (unsigned char *)mmap(NULL, mapped, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (base == MAP_FAILED) { ZLOGE("SDK 映像映射失败: %s", strerror(errno)); return -1; }
    za_sdk_base = (unsigned long)base;
    za_sdk_size = (unsigned long)ZA_SDK_TOTAL_SIZE;
    memcpy(base + ZA_SDK_TEXT_OFF, text, text_size);
    memcpy(base + ZA_SDK_RODATA_OFF, rodata, rodata_size);
    memcpy(base + ZA_SDK_DATA_OFF, data, data_size);
    memset(base + ZA_SDK_DATA_OFF + ZA_SDK_DATA_SIZE, 0, ZA_SDK_BSS_SIZE);
    memset(base + ZA_SDK_IMG_SIZE, 0, mapped - ZA_SDK_IMG_SIZE);

    // 2) 导出符号表
    if (za_mod_from_exports(sdk, base, exp_bin, exp_len) != 0) { ZLOGE("SDK 导出表坏了"); return -1; }
    sdk->size = mapped;

    // 3) 基址重定位（先做；后面 ELF 重定位会覆盖同一批槽，顺序不能反）
    unsigned long long moved = za_sdk_relocate_base(base);

    // 4) 应用 SDK 自己的重定位表
    if (rel_len < 4) { ZLOGE("SDK 重定位表太短"); return -1; }
    uint32_t nrel;
    memcpy(&nrel, rel_bin, 4);
    const uint32_t *rel = (const uint32_t *)(rel_bin + 4);
    unsigned resolved = 0, unresolved = 0;
    char namebuf[256];
    for (uint32_t i = 0; i < nrel; i++)
    {
        const uint32_t *r = rel + i * 4;
        uint32_t slot = r[0], kind = r[1], symidx = r[2], addend = r[3];
        void **p = (void **)(base + slot);
        if (kind == 1)
        {
            *p = (void *)(base + addend);            // 基址 + 符号值 + 加数
        }
        else if (kind == 2)
        {
            *p = (void *)(base + addend);            // 基址 + 加数
        }
        else if (kind == 3)
        {
            *p = NULL;
        }
        else
        {
            // kind 0：未定义符号 —— 依次找：宿主 → main 模块 → SDK 自己
            const char *name = za_mod_sym_name(sdk, symidx, namebuf, sizeof namebuf);
            void *fn = NULL;
            if (name)
            {
                if (resolve_host) fn = resolve_host(name, ctx);
                if (!fn && resolve_main) fn = resolve_main(name, ctx);
                if (!fn) fn = za_mod_lookup(sdk, name);
            }
            if (fn) { *p = fn; resolved++; }
            else { *p = NULL; unresolved++; if (name) ZLOGI("SDK 未解析符号: %s", name); }
            // ⚠ 数据符号要特别当心：`__nnDetailNintendoSdkRuntimeObjectFile`
            //   是「SDK runtime object 文件」的**数据**指针，不是函数。
            //   解析到桩地址的话，客机会拿它去 zlib 解压 ⇒ 炸。
            //   ⇒ 把每个未定义符号的解析结果都打出来，一眼就能看出有没有解析错。
            if (name && (resolved + unresolved) <= 40)
                ZLOGI("SDK 导入 %s -> %p%s", name, fn,
                      fn ? "" : "（未解析）");
        }
    }

    // 关键跳板的 GOT 槽值：这些槽一旦是 0，客机 `br` 过去就是跳空（pc=0）。
    {
        static const unsigned long probe[] = {
            0xb74078,    // 我们自己填的 os 上下文槽
            0xb738e8,    // 我们自己填的 musl arg0 槽
            0xb7a860,   // InternalCriticalSectionImplByHorizon::C1
            0xb7a868,   // InternalConditionVariableImplByHorizon::C1
            0xb7a880,   // InternalCriticalSectionImplByHorizon::Enter
            0xb7acf0,   // SetupThreadObjectUnsafe
            0xb7ad80,   // ThreadManager::ThreadManager
            0xb7af60,   // TlsManager::TlsManager
            0xb7af70,   // AddressSpaceAllocatorBase::C2
            0xb7afb0,   // RngManager::C1
        };
        for (unsigned i = 0; i < sizeof probe / sizeof probe[0]; i++)
            ZLOGI("SDK GOT[%#lx] = %p", probe[i], *(void **)(base + probe[i]));
    }

    // 5) Horizon svc 宿主门：门区机器码 + 改写 58 处 svc + 填 C 函数指针槽
    if (gate_bin && gate_len >= ZA_SVC_GATE_SIZE)
    {
        memcpy(base + ZA_SVC_GATE_BASE, gate_bin, ZA_SVC_GATE_SIZE);
        for (unsigned i = 0; i < ZA_SVC_PATCH_COUNT; i++)
        {
            unsigned int *slot = (unsigned int *)(base + za_svc_patches[i].off);
            *slot = za_svc_patches[i].w;
        }
        // 槽里放宿主 C 函数地址（trampoline 用 adr 从这里读）
        *(void **)(base + ZA_SVC_SLOT_OFF) = (void *)za_horizon_svc;
        // 另一个槽放 za_horizon_regs[] 的地址 —— trampoline 用它回写 x1..x7
        // （Horizon 的出参在 W1/W2，C 函数只能返回一个值）
        *(void **)(base + ZA_SVC_REGS_OFF) = (void *)za_horizon_regs;
        // ★★★ 第三个槽：宿主栈顶。
        //   svc 门会**把栈切到这里**再调 C 函数 —— 因为客人的 svc 包装函数只预留
        //   0x10 字节栈空间，而我们的 C 调度器链很深（几百字节），在客人的栈上跑
        //   会把**调用者的整个栈帧**踩烂（实测：saved x29/x30 被覆盖 ⇒ 客人的
        //   ret 跳回自己 ⇒ 无限循环 ⇒ sp 越过栈顶 256MB ⇒ pc=0 跳空）。
        //   切到独立栈之后，宿主 C 代码一个字节都不碰客人的栈。
        {
            size_t hsz = 1u << 20;   // 1MB：足够深�� C 调用链
            void *hs = mmap(NULL, hsz, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (hs == MAP_FAILED)
            {
                ZLOGE("宿主栈 mmap 失败 ⇒ svc 门会踩坏客人的栈帧！");
            }
            else
            {
                // 顶端留 64 字节：门要 `str x9,[sp]` 写服务号，不能越界
                void *top = (void *)((char *)hs + hsz - 64);
                *(void **)(base + ZA_SVC_STACK_OFF) = top;
                ZLOGI("宿主栈: %p（顶 %p，%zu 字节）—— svc 门在这里跑 C 调度器，不碰客人的栈",
                      hs, top, hsz);
            }
        }
        ZLOGI("Horizon svc 门：改写 %u 处，门区=%p，C 入口=%p",
              ZA_SVC_PATCH_COUNT, (void *)(base + ZA_SVC_GATE_BASE), (void *)za_horizon_svc);
    }
    else
    {
        ZLOGE("SDK svc 门区资产缺失（gate=%p len=%zu 需要 %zu）",
              (void *)gate_bin, gate_len, (size_t)ZA_SVC_GATE_SIZE);
    }

    // 5.5) HLE 接管：把某些 SDK 导出函数换成宿主桩
    //
    // 为什么要接管：这些函数在真机上会去连 Horizon 的系统服务（IPC）。
    // 我们没有那些服务进程 —— 客机走 CMIF 时拿不到出参对象，
    // SDK+0x3fcbf4 对全局 SDK+0xc024b8 做 NULL 解引用 ⇒ SIGSEGV
    // （真机实测：signal 0xb，pc=SDK+0x3fcbf4，addr=0x0）。
    //
    // ★ 路线与已上线成品 d2r-and 完全一致（按函数名接管，见
    //   d2r-android/dm/host/hle_sdkinit.c 的 HLE_FORCE("_ZN2nn4pctl10InitializeEv", …)）。
    //   本版是最小实现：把函数体改写成「直接返回」。
    //   （要调宿主 C 函数的通用版，可复用 svc 门区那套 trampoline：
    //    门区里放一个 `mov w9,#hle_id ; b za_horizon_tramp` 小跳板，
    //    宿主在 za_horizon_dispatch 里按 hle_id 分派。）
    //
    // ⚠ 改写长度必须 ≤ 该函数的真实长度，否则会踩坏下一个函数。
    //   nn::pctl::Initialize（SDK+0x3fbbc0）只是 1 条尾调用跳板 `b 0x6457f0`
    //   ⇒ 只能写 1 个字（4 字节）。
    {
        typedef struct
        {
            unsigned int off;     /* SDK 映像内偏移（函数入口） */
            unsigned int words;   /* 要改写的字数（4 字节/字） */
            unsigned int w[2];    /* 改写内容 */
            const char *name;
        } za_hle_stub_t;

        /* ★ 目前**没有**需要接管的函数。
         *   pctl 的问题已经从**协议层**解决（应答槽+0x20 写非 0 token，
         *   见 za_horizon.c 的 za_write_cmif_reply），所以这里恢复走真实 CMIF 路径。
         *   保留这张表：以后遇到「SDK 一进去就连某个我们没有的系统服务」的导出函数，
         *   就照 d2r-and 的 hle_sdkinit.c 那样按函数名接管。 */
        static const za_hle_stub_t g_hle[] = {
            /* nn::oe::SetPerformanceModeChangedNotificationEnabled(bool)（SDK+0x3f7050）
             *   → GetSelfController()（SDK+0x1c6670，读全局 SDK+0xbacbd0）
             *   → 我们是宿主环境，没有 am applet 服务 ⇒ 全局恒 NULL
             *   ⇒ SDK+0x3f7064 `ldr x8,[x0]` 崩（实测 addr=0x0，调用链
             *      main+0x1a04ce0 ← main+0x19dc9e8 ← main+0xb10ddc ← …）。
             *   「性能模式变更通知」在安卓上没有对等物，直接返回 0（成功）。 */
            { 0x3f7050, 2, { 0x52800000u, 0xD65F03C0u },
              "nn::oe::SetPerformanceModeChangedNotificationEnabled" },
        };

        for (unsigned i = 0; i < sizeof g_hle / sizeof g_hle[0]; i++)
        {
            if (!g_hle[i].name) continue;
            unsigned int *p = (unsigned int *)(base + g_hle[i].off);
            for (unsigned k = 0; k < g_hle[i].words && k < 2; k++)
                p[k] = g_hle[i].w[k];
            ZLOGI("HLE 接管：%s（SDK+%#x）→ 直接返回", g_hle[i].name, g_hle[i].off);
        }
    }

    // 5.6) 假的 ApplicationFunctions
    //
    // nn::am::GetApplicationFunctions()（SDK+0x1c61c0）只是读全局 SDK+0xbaca10：
    //     ldr x19,[x8,#0xa10] ; cbz x19, <返回 NULL> ; ... ; mov x0,x19
    // 它是 0 的时候，nn::diag::InitializeApplicationAbortObserver 注册的回调
    // （SDK+0x349e40）会 `ldr x8,[x0]` 解引用 NULL ⇒ SIGSEGV
    // （真机实测：pc=SDK+0x349e64 addr=0x0，x1=0x2a2）。
    //
    // 我们没有真的 am 服务 ⇒ 自己造一个「什么都返回 0」的空壳对象，
    // 并把 GetApplicationFunctions 改成直接返回它。
    // ⚠ 不能只填全局：SDK 的 am 初始化会把那个全局重新写回 0。
    {
        /* 代码页：mov w0,#0 ; ret（客机可以直接 blr 过去）
         * ⚠ 必须先 RW 映射、写完再 mprotect 成 R+X —— 直接以 R+X 映射然后
         *   str 会 SIGSEGV（真机实测：pc=za_sdk_load+1688，恰在 5.6 步）。 */
        unsigned int *stub = (unsigned int *)mmap(NULL, 0x1000, PROT_READ | PROT_WRITE,
                                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (stub == MAP_FAILED)
        {
            ZLOGE("假的 ApplicationFunctions：代码页 mmap 失败");
        }
        else
        {
            stub[0] = 0x52800000u;      /* mov w0, #0 */
            stub[1] = 0xd65f03c0u;      /* ret */

            mprotect(stub, 0x1000, PROT_READ | PROT_EXEC);

            /* 数据页：vtable + 对象（对象第 0 格放 vtable 指针） */
            unsigned long long *data = (unsigned long long *)mmap(NULL, 0x1000,
                                                                  PROT_READ | PROT_WRITE,
                                                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (data == MAP_FAILED)
            {
                ZLOGE("假的 ApplicationFunctions：数据页 mmap 失败");
                munmap(stub, 0x1000);
            }
            else
            {
                enum { ZA_DUMMY_VT_SLOTS = 24 };
                for (int i = 0; i < ZA_DUMMY_VT_SLOTS; i++)
                    data[i] = (unsigned long long)(uintptr_t)stub;
                unsigned long long *obj = data + ZA_DUMMY_VT_SLOTS;
                obj[0] = (unsigned long long)(uintptr_t)data;   /* vtable */

                /* 打补丁：nn::am::GetApplicationFunctions 直接返回 obj
                 *   movz x0, #lo16 ; movk x0, #m16, lsl #16 ; movk x0, #m32, lsl #32 ; ret
                 * ⚠ 必须 3 条指令拼满 64 位：只写低 32 位的话高位是调用方残留
                 *   （真机实测：SDK+0x349e64 `ldr x8,[x0]` 解引用截断指针 ⇒ SIGSEGV）。
                 * （原函数 0x44 字节，够写；写 4 条指令，不动后面的代码；
                 *   movz 自带清零高位，48 位用户地址的 bits48..63 = 0 无需再 movk） */
                unsigned int *fn = (unsigned int *)(base + 0x1c61c0);
                unsigned long long a = (unsigned long long)(uintptr_t)obj;
                fn[0] = 0xd2800000u | (unsigned int)(a & 0xffffu);        /* movz x0, #lo16 */
                fn[1] = 0xf2a00000u | (unsigned int)((a >> 16) & 0xffffu); /* movk x0, #m16, lsl 16 */
                fn[2] = 0xf2c00000u | (unsigned int)((a >> 32) & 0xffffu); /* movk x0, #m32, lsl 32 */
                fn[3] = 0xd65f03c0u;                                        /* ret */

                /* 同时把全局也填上（万一别处直接读它） */
                *(unsigned long long *)(base + 0xbaca10) = a;

                ZLOGI("假的 ApplicationFunctions：对象=%p vtable=%p（GetApplicationFunctions 已改写）",
                      (void *)obj, (void *)data);
            }
        }
    }

    // 5.65) fs 分配器默认槽的基址修正。
    //   实测：SDK+0xb88898/0xb888a0 文件值 = 0xdcb90/0xdcba0（SDK 内建默认
    //   alloc/free），但**重定位表里没有这两个槽** ⇒ 不 rebase 就永远不等于
    //   base+0xdcb90 ⇒ nn::fs::SetAllocator（SDK+0xdc810）的前置检查失败
    //   ⇒ 它进错误汇报分支（GetSystemTick 循环/断链）且**不保存 main 的分配器**
    //   ⇒ 之后 nn::fs::detail::Allocate 从 [0xb88898] 取到垃圾指针 ⇒ blr 跳空
    //   （实测 pc=0x20、x30=sdk+0xdca0c）。
    {
        unsigned long long *a = (unsigned long long *)(base + 0xb88898);
        if (*a == 0xdcb90ull) *a = (unsigned long long)(uintptr_t)(base + 0xdcb90);
        if (*(a + 1) == 0xdcba0ull) *(a + 1) = (unsigned long long)(uintptr_t)(base + 0xdcba0);
        ZLOGI("fs 分配器默认槽：%#llx / %#llx（已加基址）", *a, *(a + 1));
    }

    // 5.7) SDK 的 abort 观察者链在我们环境里必然踩空：InvokeSdkAbortObserver
    //      （SDK+0x9c630）遍历的观察者对象由 SDK 运行时注册，我们没有真的
    //      diag/am 运行时 ⇒ 列表里是垃圾 ⇒ abort 一发生就在这里 SIGSEGV，
    //      把真正的错误盖住（2026-10-25 实测：连续三轮「不同」的崩溃
    //      0x349e64 / 0x349e6c / ret-to-0x206409e58 全是这一条链的次生崩溃，
    //      链上真实的一环是 CriticalSection::Leave ⇒ AbortImpl）。
    //      ⇒ 打成直接 ret，让 abort 流程走到 svc#38 Break（宿主已实现并打日志），
    //        这样能看到真正的断言原因。
    *(unsigned int *)(base + 0x9c630) = 0xd65f03c0u;   /* ret */

    // 5.8) CNTPCT_EL0 读取替换：这台设备的内核在 EL0 挡了 CNTPCT
    //      （实测 SIGILL：pc=sdk+0x13d9a0 = GetSystemTick 的 `mrs x0,CNTPCT_EL0`）。
    //      SDK 有 40 处 `mrs Xt,CNTPCT_EL0`，每处换成 `b <桩>`；桩从槽
    //      （base+0xc90600，门区尾部 padding，实测全零）调宿主 hook 取 tick
    //      写回 Xt，再跳回原址下一条。桩体放门区 padding（0xc80200 起），
    //      步骤 7 的 clear_cache/R|X 覆盖整个门区。
    {
        *(unsigned long long *)(base + 0xc90600) = (unsigned long long)(uintptr_t)za_host_tick_hook;
        unsigned long long bump = 0xc90000ull;
        unsigned patched = 0;
        for (unsigned off = 0; off + 4 <= (unsigned)ZA_SDK_RODATA_OFF; off += 4)
        {
            unsigned int w = *(const unsigned int *)(base + off);
            if ((w & 0xFFFFFCE0u) != 0xD53BE020u) continue;   /* mrs Xt,CNTPCT_EL0 */
            unsigned rt = w & 0x1Fu;
            unsigned long long stub_off = bump;
            bump += 0x1C;                                      /* 7 条指令 */
            unsigned int *s = (unsigned int *)(base + stub_off);
            {   /* adrp x16, <0xc90600 页>
                 * imm21 = 页差；低 2 位放 immlo（bits30-29），高 19 位放 immhi（bits23-5）。
                 * ⚠ 拆反了会 ×4 错位（实测桩读到自己 ⇒ 跳垃圾地址）。 */
                long long pg = ((long long)(0xc90600ull & ~0xFFFull) -
                                (long long)(stub_off & ~0xFFFull)) >> 12;
                unsigned immlo = (unsigned)(pg & 3);
                unsigned immhi = (unsigned)((pg >> 2) & 0x7FFFF);
                s[0] = 0x90000000u | (immlo << 29) | (immhi << 5) | 16u;
            }
            /* ldr x16,[x16,#页内偏移] —— ⚠ imm12 按 8 缩放；漏了偏移会读到
             *   桩自己的指令（实测 x16 = 头两条指令字 ⇒ blr 跳垃圾）。 */
            s[1] = 0xF9400000u | (((0xc90600ull & 0xFFFull) >> 3) << 10) | (16u << 5) | 16u;
            /* ★ 必须保存/恢复 x30！被替换的 mrs 站点可能是**叶子函数**
             *   （GetSystemTick 就是：x30 = 调用者的返回地址，没有 prologue 保护）。
             *   blr 覆盖 x30 后，`b 回原址` 落到函数末尾的 `ret` ⇒ ret 跳回桩里
             *   ⇒ 桩↔ret 无限乒乓（实测：pc 恒在 GetSystemTick+4，x30=桩+0xc，
             *   100% CPU、无 svc、看门狗 1 秒判死）。 */
            s[2] = 0xF81F0FFEu;                                /* str x30,[sp,#-0x10]! */
            s[3] = 0xD63F0200u;                                /* blr  x16         */
            s[4] = 0xF84107FEu;                                /* ldr  x30,[sp],#0x10  */
            s[5] = 0xAA0003E0u | rt;                           /* mov  Xt, x0      */
            {   /* b 回原址+4 */
                long long delta = (long long)(off + 4) - (long long)(stub_off + 0x18);
                s[6] = 0x14000000u | (unsigned)((delta >> 2) & 0x3FFFFFFu);
            }
            {   /* 原址 mrs → b <桩> */
                long long delta = (long long)stub_off - (long long)off;
                *(unsigned int *)(base + off) =
                    0x14000000u | (unsigned)((delta >> 2) & 0x3FFFFFFu);
            }
            patched++;
        }
        ZLOGI("CNTPCT 替换：%u 处 → 门区桩（hook @base+0xc90600）", patched);

        // ★ NvOsHeapAllocatorAlloc 探针：桩 @0xc90500，hook 槽 @0xc90608，
        //   原函数入口 0x44f9f0 换成 b <桩>。见 za_nvn_probe_stub 的注释。
        memcpy((void *)(uintptr_t)(base + 0xc90500), za_nvn_probe_stub,
               sizeof za_nvn_probe_stub);
        *(unsigned long long *)(base + 0xc90608) =
            (unsigned long long)(uintptr_t)za_nvn_probe_hook;
        {
            long long d = 0xc90500 - 0x44f9f0;
            *(unsigned int *)(base + 0x44f9f0) =
                0x14000000u | (unsigned)((d >> 2) & 0x3FFFFFFu);
        }
        ZLOGI("NvOsHeap 探针已装：入口 0x44f9f0 → 桩 0xc90500");

        // ★ 断言路径探针：把 SDK 内部断言/ABORT 的表达式、函数名、文件名打出来。
        //   实测崩溃链：某个 main 工作线程 → sdk+0x9ac00 一族（__assert_fail 形态）
        //   → svc#38 Break(reason=0)。没有消息文本根本没法修。
        //   0x9b010 = nndetailDiagOnAssertionFailure（对外入口）
        //   0x9acb0 / 0x9ac00 = 内部 wrapper / 变参处理器
        za_install_entry_probe(base, 0x9b010, 0xc90580, 0xc90610, za_hook_assert_entry);
        za_install_entry_probe(base, 0x9acb0, 0xc90620, 0xc906a0, za_hook_assert_wrap);
        za_install_entry_probe(base, 0x9ac00, 0xc906b0, 0xc90730, za_hook_assert_var);
        // 0x9ad10 = 真正的断言处理器（GOT 0xb78e18 指向它）：
        //   签名从反汇编看是 (w0=result, x1, x2, w4, x5, ...) 外加 q0-q7 变参，
        //   内部会取 nn::diag 的断言信息结构 → 这里能拿到文件/行号/表达式。
        za_install_entry_probe(base, 0x9ad10, 0xc90740, 0xc907c0, za_hook_assert_onfail);
        // 0x9aa70 = ABORT 实现入口（0x632450 的 GOT 目标）；x30 = 谁调了 Abort。
        za_install_entry_probe(base, 0x9aa70, 0xc907d0, 0xc90848, za_hook_abort_entry);
        ZLOGI("断言探针已装：0x9b010 / 0x9acb0 / 0x9ac00 / 0x9ad10 / 0x9aa70");

        // ★ 互斥 owner 检查旁路（临时，等 nn::os 同步家族整体改道后再撤）
        //   SDK 的 WaitConditionVariable（SDK+0x1387f0）开头：
        //       ldr x8,[mutex+0x10]          ; owner = 持锁线程对象
        //       mrs x9,tpidrro_el0 ; ldr x9,[x9,#0x1f8]  ; 当前线程对象
        //       cmp x8,x9 ; b.ne abort       ; 不持锁就 wait ⇒ 直接 abort
        //   而游戏的 LockMutex 走的是我们的宿主实现（za_os_lock_mutex），
        //   根本不写 SDK MutexType 的 owner 字段 ⇒ 必然不等 ⇒ abort。
        //   这里先旁路这条检查（b.ne → nop），让 wait 继续走 SDK 自己的
        //   「减递归计数 → svcWaitSynchronization」路径，观察后续。
        *(unsigned int *)(base + 0x13880c) = 0xD503201Fu;   /* nop */
        __builtin___clear_cache((char *)base + 0x13880c, (char *)base + 0x138810);
        za_cnctp_ready = 1;
    }

    // 6) 只读 TLS：客机 SDK 有 123 处 `mrs Xt,TPIDRRO_EL0`，
    //    而安卓/bionic **从不设置 TPIDRRO_EL0**（一直是 0）⇒ 客机读到空指针直接崩。
    //    做法：把 `mrs` 1:1 换成 `adrp Xt,<我们自备的只读 TLS 页>`（相对偏移全部不变），
    //    再把那一页的内容填成客机期望的样子。
    //    ⚠ 必须在下面「段权限收紧」之前做 —— 那时 text 已经是 R+X，写不进去。
    //    页里的布局（从 123 处用法反推）：
    //      +0x00 +0x20 +0x70 +0x78 +0x80 +0x1e0 +0x1f0 +0x1f8  = 指针
    //      +0x10 = 32 位值   +0x100/+0x102 = 16 位计数器/标志   +0x104 = 字节标志
    //      +0x1b0 = 32 位「代数」
    //    +0x1f8 是「当前线程自己」的指针（会与对象里存的指针比较），
    //    客机还会往 +0x1f0 写 ⇒ 这一页必须可写（它落在映像末尾扩展区，默认 RW）。
    //
    // ★★ 2026-10-26 重做：只读 TLS 必须**每线程一份**。
    //   证据：SDK 的 123 处访问里，+0x100/+0x102/+0x104 是**本线程**的 busy 标记
    //   （InternalCriticalSection 的忙等协议），+0x1f0 是本线程 TPIDR，
    //   +0x1f8 是本线程对象；而且这一页还是 **CMIF IPC 的应答缓冲**
    //   （内核把应答写回 [TPIDRRO+槽位]）。全局一张页会让线程互相踩 ⇒ 活锁。
    //   实测 TPIDRRO_EL0 在 EL0 **不可写**（msr 直接 SIGILL），所以只能改代码。
    //   做法：把 `mrs Xt,TPIDRRO_EL0`（1 条）换成 `b <每站点桩>`，
    //   桩保存 x0–x17/x30 → 调宿主 za_os_tls_ro_area() 取**本线程**的页 →
    //   `ldr Xt,[sp,#0x98]` 写回原寄存器 → 跳回 site+4。
    for (unsigned i = 0; i < ZA_TLSRO_PATCH_COUNT; i++)
    {
        const za_tlsro_patch_t *p = &za_tlsro_patches[i];
        memcpy((void *)(uintptr_t)(base + p->stub), p->seq, 28 * 4);
        long long d = (long long)p->stub - (long long)p->off;
        *(unsigned int *)(base + p->off) =
            0x14000000u | (unsigned)((d >> 2) & 0x3FFFFFFu);
    }
    *(unsigned long long *)(base + ZA_TLSRO_HOOK_SLOT) =
        (unsigned long long)(uintptr_t)&za_os_tls_ro_area;
    ZLOGI("只读 TLS：%u 处 TPIDRRO_EL0 → 每站点桩（%#x..），每线程页由宿主提供",
          ZA_TLSRO_PATCH_COUNT, (unsigned)ZA_TLSRO_STUB_BASE);

    // 8) 客机不许动 bionic 的 TLS 指针
    //    客机（SDK）里有 `msr TPIDR_EL0, xN`（写 TPIDR_EL0）—— 那在安卓上就是
    //    **bionic 的 TLS 指针**！客机一写，bionic 的 TLS 就废了 ⇒ 后续任何 libc
    //    调用（malloc/pthread/logcat…）必崩，症状是「进程被 SIGSEGV 静默杀掉」。
    //    ⇒ 全部 NOP 掉（客机 TLS 走影子描述符，不依赖这个寄存器）。
    //    另外 SDK 有 2 处 `mrs xN,TPIDR_EL0` 是**真·TLS 基址访问**
    //    （musl 的 __tls_get_addr 快速路径）⇒ 改读我们自建的 TLS 上下文页。
    for (unsigned i = 0; i < ZA_TLSBASE_SDK_WRITE_COUNT; i++)
    {
        unsigned int *slot = (unsigned int *)(base + za_tlsbase_sdk_writes[i].off);
        *slot = za_tlsbase_sdk_writes[i].w;
    }
    for (unsigned i = 0; i < ZA_TLSBASE_READ_COUNT; i++)
    {
        unsigned int *slot = (unsigned int *)(base + za_tlsbase_reads[i].off);
        *slot = za_tlsbase_reads[i].w;
    }
    {
        // musl 的 __tls_get_addr 快速路径末尾那句 `sub x0,x0,x3`
        // 把「变量绝对地址」变成「相对 TLS 基址的偏移」，
        // 而调用方要的是**地址**（SDK 里已经没有别的 mrs TPIDR_EL0 了）
        // ⇒ 客机拿一个野偏移当地址用 ⇒ 跳到野地址崩。NOP 掉它。
        unsigned n = sizeof(za_tlsbase_subfix) / sizeof(za_tlsbase_subfix[0]);
        for (unsigned i = 0; i < n; i++)
        {
            unsigned int *slot = (unsigned int *)(base + za_tlsbase_subfix[i].off);
            *slot = za_tlsbase_subfix[i].w;
        }
    }
    {
        // SDK 自己的 TLS 上下文页（16KB 对齐）
        unsigned char *ctx = base + ZA_SDK_TLSCTX_OFF;
        unsigned char *tab = base + ZA_SDK_TLSTAB_OFF;
        memset(ctx, 0, ZA_SDK_TLSCTX_SIZE);
        memset(tab, 0, ZA_SDK_TLSTAB_SIZE);
        // 动态 TLS 表：每项 0x200 ⇒ 取到的变量落在上下文页内（映射着），不会跑飞。
        //   表项非 0 ⇒ musl 的 __tls_get_addr 走**快速路径**，不进慢路径（慢路径会
        //   去分配 TLS 块，而我们没有 musl 的堆语义）。
        for (unsigned i = 0; i < ZA_SDK_TLSTAB_SIZE / 8; i++)
            ((unsigned long long *)tab)[i] = 0x200ull;
        *(unsigned long long *)(ctx + 0x08) = (unsigned long long)(uintptr_t)tab;
        *(unsigned int *)(ctx + 0x13) = 0x2000;   // 本模块的 TLS 描述符
        ZLOGI("SDK TLS 上下文：页=%p 表=%p（读改写 %u 处、禁写 %u 处）",
              (void *)ctx, (void *)tab, ZA_TLSBASE_READ_COUNT, ZA_TLSBASE_SDK_WRITE_COUNT);
    }

    // 7) 段权限收紧（门区要可执行）
    // ★ 先做指令缓存维护：上面改写了 text（HLE 桩 / mrs→adrp / svc 门分支）。
    //   ARM64 架构上「写了指令再执行」必须显式 IC 维护，否则 I-cache 可能
    //   还是旧内容 ⇒ 补丁随机不生效（实测：同一份补丁一次崩一次不崩）。
    __builtin___clear_cache((char *)base, (char *)base + ZA_SDK_RODATA_OFF);
    __builtin___clear_cache((char *)base + ZA_SVC_GATE_BASE,
                            (char *)base + ZA_SVC_GATE_BASE + ZA_SVC_GATE_SIZE);
    // ★ CNTPCT 替换桩 + hook 槽（0xc90000..0xc90700，见 5.8）：区域在门区之外，
    //   初始 mmap 是 RW ⇒ 不收紧就是 NX。mprotect 成 R+X。
    //   ⚠ clear_cache 也必须做 —— 漏了就是「客机在桩区间弹跳」的实锤
    //   （0xc9028c，看门狗 SIGSEGV 抓到的现行）。
    __builtin___clear_cache((char *)base + 0xc90000, (char *)base + 0xc97000);
    mprotect(base + 0xc90000, 0x7000, PROT_READ | PROT_EXEC);
    mprotect(base, ZA_SDK_RODATA_OFF, PROT_READ | PROT_EXEC);
    mprotect(base + ZA_SVC_GATE_BASE, ZA_SVC_GATE_SIZE, PROT_READ | PROT_EXEC);
    mprotect(base + ZA_SDK_RODATA_OFF, ZA_SDK_DATA_OFF - ZA_SDK_RODATA_OFF, PROT_READ);
    mprotect(base + ZA_SDK_DATA_OFF, ZA_SDK_DATA_SIZE + ZA_SDK_BSS_SIZE, PROT_READ | PROT_WRITE);

    // 8) OS 侧该做的事（真机上这些是 Switch OS 在装载 NN 时做的，我们就是那个 OS）
    //    ⚠ 必须在上面「段权限收紧」之后 —— 这一步要**调用 SDK 里的函数**
    //      （映像初始 mmap 没带 PROT_EXEC，权限收紧后 text 才可执行）。
    //
    //  8a) 注册「线程局部内存分配器」
    //       SDK 的 nnosAllocate/FreeMemoryForThreadLocal 只是壳，真正的实现在 OS 侧；
    //       SDK 导出了注册函数 nn::os::SetMemoryAllocatorForThreadLocal（映像偏移 0x140d20），
    //       它把两个函数指针写进 .bss 的固定槽 0xb9b008 / 0xb9b010（文件里是 0）。
    //       不注册 ⇒ SDK 一分配就 `br 0` 跳空。
    //  8b) __nnmusl_init_dso 的第 0 个参数（真机上由 OS 填进 SDK 的 .data 槽 0xb738e8）
    //       文件里是 0 ⇒ SDK 的 __nnmusl_init_dso 直接早退，整个 nn::os 运行时都不初始化
    //       ⇒ 后面 ThreadManager 的线程链表头是 NULL ⇒ SetZeroToAllThreadsTlsSafe 崩。
    //       这里给它一块清零的页。
    {
        // 客机地址空间（ASLR/alias/stack/heap 四块区域）必须**先**准备好：
        // nnosInitialize 会通过 svc #41 GetInfo 问我们要这些值，
        // 拿不到自洽的布局 ⇒ SDK 的 AddressSpaceAllocator 在空区间上空转（栈溢出）。
        za_mem_init();

        // ★ 2026-10-25：**不再在这里注册**！SetMemoryAllocatorForThreadLocal
        //   （SDK+0x140d20）对 [0xb9b008]!=0 直接 AbortImpl —— main 的
        //   nninitStartup（main+0x19e8910）在 init::Start 之后会自己注册，
        //   我们抢先注册 ⇒ 它再注册 ⇒ 「已注册」断言 ⇒ abort（实测）。
        //   真机流程就是 main 注册的，OS 侧不碰。

        void *arg0 = za_build_startup_info();
        *(void **)(base + 0xb738e8) = arg0;
        ZLOGI("OS 注入：__nnmusl_init_dso 的第 0 参数 = %p（原本是 0 ⇒ SDK 早退）", arg0);

        // 8c) 「os 上下文」对象：SDK 的全局槽 [0xb74078] 指向它。
        //     nnosInitialize 在它上面构造 RngManager(+0)/AddressSpaceAllocator(+0x18)/
        //     ThreadManager(+0xf0)/TlsManager(+0x2e0)…（真机上由 OS 建好再交给 SDK）。
        void *ctx = calloc(1, 0x800);
        *(void **)(base + 0xb74078) = ctx;
        za_sdk_ctx = ctx;

        // 8d) nnosInitialize **不在这里调** —— 真机上它由 nnrtld 在
        //     「模块都装好之后」按 nn::init::Start 的顺序调，见 za_guest_boot()。
        //     ⚠ 参数很关键：
        //       x0 = **主线程句柄**（SDK 把它写进 0xb740128 槽，
        //           之后 ThreadManagerImplByHorizon 读它的低 32 位当
        //           **临界区 owner_id** ⇒ 传错的话 owner_id 是随机堆地址，
        //           临界区的加锁/自旋逻辑全乱）
        //       x1 = 0（真机上没有启动块；我们伪造的块会让 SDK 走
        //           QueryMemory 校验分支而报错）
        //     真正调用在 za_guest_boot()，顺序照 d2r-and（已上线成品）。
    }

    // SDK 的 _init（映像偏移 0x400）会把这 21 个槽（0xb73898..0xb73938）当参数
    // 传给 __nnmusl_init_dso（经 0x62f360 跳板 → GOT 0xb77160）。
    // 其中 5 个在**文件里本来就是 0**（静态初始化的表，全 text 扫过：没有任何代码写它），
    // 在真机上也是 0；__nnmusl_init_dso 对 arg0 做 NULL 检查后早退，属正常路径。
    // ⇒ 这里只是把运行时值打出来核对，不是崩溃原因（之前误判过一次）。
    {
        const unsigned long long *got = (const unsigned long long *)(base + 0xb73898);
        char line[768];
        int off = 0, zeros = 0;
        off += snprintf(line + off, sizeof line - off, "GOT: ");
        for (int i = 0; i < 21 && off < (int)sizeof line - 24; i++)
        {
            if (got[i] == 0) zeros++;
            off += snprintf(line + off, sizeof line - off, "%#lx ", got[i]);
        }
        ZLOGI("SDK _init 传给 __nnmusl_init_dso 的 21 个参数（NULL 个数=%d）: %s", zeros, line);
    }

    ZLOGI("SDK 装载: 基址=%p 导出=%u 重定位=%u（解析 %u，未解析 %u）基址重定位 %llu 个指针",
          (void *)base, sdk->export_count, nrel, resolved, unresolved, moved);

    // 指令探针（必须放在**所有补丁之后**）：确认关键位置的指令真的被改写了。
    // 0x144618 = `mrs x8,TPIDRRO_EL0`（应已被换成 adrp ⇒ 0x9000xxxx）
    // 0x144620 = `msr TPIDR_EL0,x2`（应已被 NOP ⇒ 0xD503201F）
    {
        static const unsigned long code_probe[] = { 0x144610, 0x144618, 0x144620, 0x144a90 };
        for (unsigned i = 0; i < sizeof code_probe / sizeof code_probe[0]; i++)
        {
            const unsigned int *w = (const unsigned int *)(base + code_probe[i]);
            ZLOGI("SDK code[%#lx] = %#x %#x", code_probe[i], w[0], w[1]);
        }
    }
    // ★ adrp 实际指向哪：adrp 的立即数是 **PC 相对**的，
    //   target = (PC & ~0xFFF) + (imm21 << 12)。
    //   运行时解出来对照「我们期望的页」，一眼看出补丁有没有指错。
    {
        struct { unsigned long off; const char *what; unsigned long want; } q[] = {
            { 0x144618, "RO TLS 页(应为 base+0xF00000)", ZA_TLSRO_OFF },
            { 0x9751c,  "SDK TLS 上下文页(应为 base+0xF10000)", ZA_SDK_TLSCTX_OFF },
        };
        for (unsigned i = 0; i < sizeof q / sizeof q[0]; i++)
        {
            unsigned w = *(const unsigned *)(base + q[i].off);
            if ((w & 0x9F000000u) != 0x90000000u)
            {
                ZLOGI("adrp 检查[%#lx]：不是 adrp（%#x）", q[i].off, w);
                continue;
            }
            long imm = (long)(((w >> 5) & 0x7FFFFu) << 2) | (long)((w >> 29) & 3u);
            if (imm & (1L << 20)) imm -= (1L << 21);
            unsigned long pc_page = ((unsigned long)base + q[i].off) & ~0xFFFul;
            unsigned long target = pc_page + ((unsigned long)(imm << 12) & 0xFFFFFFFFul);
            unsigned long want = (unsigned long)base + q[i].want;
            ZLOGI("adrp 检查[%#lx] %s：实际=%#lx 期望=%#lx %s",
                  q[i].off, q[i].what, target, want, target == want ? "✓" : "✗ 指错了！");
        }
    }
    return 0;
}

int za_sdk_run_init(za_mod_t *sdk)
{
    if (!sdk || !sdk->base) return -1;
    unsigned char *base = sdk->base;
    if (ZA_SDK_INIT)
    {
        void (*init)(void) = (void (*)(void))(base + ZA_SDK_INIT);
        ZLOGI("SDK: 调 _init @%#x", (unsigned long long)ZA_SDK_INIT);
        init();
    }
    if (ZA_SDK_INIT_ARRSZ)
    {
        unsigned long long n = ZA_SDK_INIT_ARRSZ / 8;
        void (**arr)(void) = (void (**)(void))(base + ZA_SDK_INIT_ARRAY);
        ZLOGI("SDK: 调 %llu 个静态构造器", n);
        for (unsigned long long i = 0; i < n; i++)
            if (arr[i]) arr[i]();
    }
    return 0;
}

// 只读 TLS 页的 +0x1f0 = 「SDK init 结尾要恢复回 TPIDR_EL0 的值」。
// 必须填**本线程真实的 TPIDR_EL0**（真机上就是这样：SDK 初始化期间会切走 TPIDR，
// 结束时从只读 TLS 里把真值取回来）。
// ⚠ 填成 SDK 自己的结构体 ⇒ SDK 把客机 TPIDR_EL0 指到 SDK 的结构
//   ⇒ 客机 TLS 基准错位 ⇒ 野指针（实测 pc=0x6d00000000）。
// 调用时机：**客机线程里**、调 SDK 的 init（nnosInitialize）之前。
// 只读 TLS 页 +0x1f8 = 「当前线程对象指针」。
// SDK 在 sdk+0x13edb4 处 `str x20,[x8,#0x1f8]`（x20 = 线程对象+8）把它写成当前线程，
// 之后又从这个槽取回来当对象用。它必须落在**可写**的客机 TLS 区里（不能指我们自造的 ro2，
// 否则 SDK 写进去的是「指向 ro2 的指针」，取回来当对象访问 ⇒ 字段错位 ⇒ 读到 0 ⇒ blr 0）。
// ★ 只读 TLS 现在是**每线程**一份（za_os_tls_ro_area()），这里写当前线程的页。
void za_sdk_set_ro_tls_self(unsigned long self)
{
    unsigned long ro = za_os_tls_ro_area();
    if (!ro) return;
    *(unsigned long long *)(ro + 0x1f8) = (unsigned long long)self;
}
void za_sdk_set_ro_tls_tpidr(unsigned long tp)
{
    unsigned long ro = za_os_tls_ro_area();
    if (!ro) return;
    *(unsigned long long *)(ro + 0x1f0) = (unsigned long long)tp;
}
// ── 模块链表登记（扮演 nnrtld）────────────────────────────────────
//
// 2026-10-25：SDK 的 `nn::ro::LoadModule`（SDK 导出，text 0x14afb0）实测反汇编：
//
//   两条链表头：SDK .data 的 0xb74170（自动装载）/ 0xb74150（手动装载），
//              文件里是 0，靠基址重定位变成 base+0xb9c470 / base+0xb9c478（环形哨兵）。
//   遍历：node = sentinel[+0x08]；node == sentinel 时结束 ⇒ **循环链表**。
//   节点字段（本轮从代码定死）：
//       +0x08  next
//       +0x28  模块基址        ← `cmp node[0x28], addr ; b.hi next`
//       +0xb8  模块大小        ← `ldr node[0xb8]; add base,size ; cmp ,addr ; b.ls next`
//       +0x04  一个字节（与 0x10 比较，走另一分支）
//   ⇒ 命中判据是 **[base, base+size)** 覆盖查询地址。
//
// 真机上这些节点由 **nnrtld 在装载时生成**（MOD0 头 +0x18 = 「runtime-generated
// module object」的偏移，Z-A main = magic+0xdb7180 = 映像 0x3DFF1C8，落在 BSS 里）。
// 我们没装 nnrtld ⇒ BSS 是零 ⇒ 链表空 ⇒ SDK 拿不到主模块信息 ⇒ 客机跳野指针
// （实测 pc=0x6d00000000 = 主模块基址 + 垃圾）。
//
// 这里由宿主代造节点并链进两条链表。
#define ZA_RO_LIST_AUTO   0xB74170u   // SDK .data：自动装载链表头（存哨兵地址）
#define ZA_RO_LIST_MANUAL 0xB74150u   // SDK .data：手动装载链表头
#define ZA_RO_OBJ_OFF     0x3DFF1C8u  // main 的 MOD0[+0x18] 指向的 module object
#define ZA_RO_OBJ_SIZE    0x100u      // 一个节点占 0x100 字节（0xb8 之后留余量）

static unsigned long long za_ro_node_base(unsigned char *node) { return *(unsigned long long *)(node + 0x28); }
static unsigned long long za_ro_node_size(unsigned char *node) { return *(unsigned long long *)(node + 0xb8); }
static void za_ro_node_set(unsigned char *node, void *next,
                           unsigned long long base, unsigned long long size, unsigned char kind)
{
    memset(node, 0, ZA_RO_OBJ_SIZE);
    *(void **)(node + 0x08) = next;
    *(unsigned long long *)(node + 0x28) = base;
    *(unsigned long long *)(node + 0xb8) = size;
    *(unsigned char *)(node + 0x04) = kind;
}

// 从 MOD0 头读「runtime module object」的映像偏移（真机由 nnrtld 放在这里）。
// MOD0 约定：magic 的地址在「映像基址+4」的 u32 里；所有字段都是**相对 magic** 的有符号 32 位。
static unsigned long long za_ro_object_off(unsigned char *base, unsigned long long limit)
{
    if (!base) return 0;
    unsigned int mod0 = 0;
    memcpy(&mod0, base + 4, 4);
    if (!mod0 || mod0 + 0x1C > limit) return 0;
    if (memcmp(base + mod0, "MOD0", 4)) return 0;
    int32_t rel = 0;
    memcpy(&rel, base + mod0 + 0x18, 4);
    long long at = (long long)mod0 + rel;
    if (at < 0 || (unsigned long long)at + 0x100 > limit) return 0;
    return (unsigned long long)at;
}

// 把 main 与 SDK 两个模块登记进 SDK 的模块链表。
// 必须在 **SDK 加载完成后、调 nnosInitialize 之前** 调用（链表头已被基址重定位）。
int za_sdk_register_modules(unsigned char *main_base, unsigned long long main_size)
{
    if (!za_sdk_base) return -1;
    unsigned char *sdk = (unsigned char *)(uintptr_t)za_sdk_base;
    unsigned long long sdk_size = (unsigned long long)ZA_SDK_DATA_OFF + ZA_SDK_DATA_SIZE + ZA_SDK_BSS_SIZE;
    unsigned char *main = main_base;

    // 两个链表头的「哨兵」地址（重定位已填好：base+0xb9c470 / base+0xb9c478）
    void *sent_a = *(void **)(sdk + ZA_RO_LIST_AUTO);
    void *sent_m = *(void **)(sdk + ZA_RO_LIST_MANUAL);

    // ① main 的节点：写在 main 的 MOD0 指定位置（映像 0x3d7f1c8，在 BSS 里）
    unsigned char *n_main = NULL;
    if (main)
    {
        unsigned long long at = za_ro_object_off(main, main_size);
        if (!at) at = ZA_RO_OBJ_OFF;                       // 兜底：已知的 Z-A main 位置
        n_main = main + at;
        za_ro_node_set(n_main, sent_a, (unsigned long long)(uintptr_t)main, main_size, 0x10);
        ZLOGI("模块链表：main 节点@%p (MOD0 指定 %#llx) base=%#llx size=%#llx",
              (void *)n_main, at, (unsigned long long)(uintptr_t)main, main_size);
    }
    // ② SDK 自己的节点：同样写在 **SDK 的 MOD0 指定位置**（实测 0xb90008，在 SDK 的 BSS 里）
    //   ⚠ 之前放在「BSS 尾部」，位置不对 —— 那块地址没人会用，链表串起来也没意义。
    unsigned char *n_sdk = NULL;
    {
        unsigned long long at = za_ro_object_off(sdk, sdk_size);
        if (at)
        {
            n_sdk = sdk + at;
            za_ro_node_set(n_sdk, sent_a, (unsigned long long)(uintptr_t)sdk, sdk_size, 0x10);
            ZLOGI("模块链表：sdk 节点@%p (MOD0 指定 %#llx) base=%#llx size=%#llx",
                  (void *)n_sdk, at, (unsigned long long)(uintptr_t)sdk, sdk_size);
        }
        else
        {
            ZLOGE("SDK 的 MOD0 没给出 runtime module object 位置，跳过 SDK 节点");
        }
    }

    // ③ 链进去：哨兵是节点，它的 [+0x08] 是 first；末尾节点的 next 指回哨兵
    if (sent_a)
    {
        unsigned char *first = n_main ? n_main : n_sdk;
        unsigned char *last = n_sdk ? n_sdk : n_main;
        if (first)
        {
            *(void **)((unsigned char *)sent_a + 0x08) = first;
            *(void **)((unsigned char *)first + 0x08) = (first == last) ? sent_a : last;
            if (first != last) *(void **)((unsigned char *)last + 0x08) = sent_a;
        }
    }
    // 手动链表也挂一份（SDK 有两条，查哪条都能命中）
    if (sent_m && sent_m != sent_a && n_main)
        *(void **)((unsigned char *)sent_m + 0x08) = n_main;

    ZLOGI("模块链表已登记：自动表哨兵=%p 首节点=%p", sent_a, (void *)(n_main ? n_main : n_sdk));
    return 0;
}