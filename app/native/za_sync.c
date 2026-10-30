// process_vm_readv 要 _GNU_SOURCE（bionic 的 <sys/uio.h> 才声明它）
// ⚠ 必须在任何系统头文件之前定义
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

// Horizon 的「锁交接 + 条件变量」内核模拟（svc#26/#27/#28/#29）。
//
// 为什么独立成文件、且**不用 pthread 锁/条件变量**：
//   · 这四个 svc 是在「客机线程 + 门切换到宿主栈」的上下文里调用的，之前用
//     pthread_cond_wait 实现，实测启动早期就崩在 bionic 的 syscall/条件变量里
//     （pc=syscall+0x28、x30=__futex_wait_ex+148）。
//   · 这里只依赖两样东西：宿主自己的原子量 + SYS_futex。没有任何 libc 锁，
//     不会和客机/宿主其它锁互相影响，也不会在信号上下文里死锁。
//
// 语义（照 d2r-and 的 dm/host/hle_thread.c，真机跑通的成品）：
//   ArbitrateLock(owner, addr, tag)
//     用户态快路径刚把锁字 CAS 成 `owner|0x40000000`（有等待者位）并失败，
//     才进来。锁字仍等于 `owner|等待者位` ⇒ 登记为 addr 的锁等待者、睡眠；
//     被别人交接时锁字已被写成我的 tag ⇒ 返回（视为拿到锁）。
//     锁字已经变了 ⇒ 立刻返回，让用户态按自己的逻辑重试。
//   ArbitrateUnlock(addr)
//     把锁**交给**等待队列里的第一个线程（锁字 = 它的 tag，还有别人就保留
//     等待者位）；没有等待者才清零。
//   WaitProcessWideKeyAtomic(addr, key, tag, timeout)
//     先置 *key = 1（SDK 的 SignalConditionVariable 看到 0 就不发 svc#29），
//     再放锁，然后等唤醒；超时不重新拿锁。
//   SignalProcessWideKey(key, n)
//     唤醒 n 个（<=0 全部）等在该键上的线程并把锁交给它们；没有剩余等待者
//     时把 *key 清零。
//
// 与内核的偏差：等待者用「自己的唤醒字 + 5ms 分片 futex 等待」，不是内核
// 队列，所以偶发伪唤醒是可能的——两者都是允许的（ConditionVariable 本来就
// 允许伪唤醒，调用方会重判条件）。锁交接本身是原子的（在自旋锁里完成）。
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <sys/uio.h>

#include "za_common.h"
#include "za_guest_api.h"
#include "za_sync.h"
#include "za_guest_info.h"

// za_guest.c / za_sdk.c：客机映像的范围（用来把地址翻译成 main+0x… / sdk+0x…）
extern unsigned char *za_guest_base;
extern volatile unsigned long za_sdk_base, za_sdk_size;

static int za_sync_read(void *dst, unsigned long long addr, size_t len)
{
    struct iovec l = { dst, len }, r = { (void *)(uintptr_t)addr, len };
    return process_vm_readv((pid_t)syscall(SYS_getpid), &l, 1, &r, 1, 0) == (ssize_t)len;
}

// 把地址翻译成 main+… / sdk+… 并打印。返回 1 = 落在映像内。
static int za_sync_print_addr(const char *what, unsigned long long pc)
{
    extern unsigned char *za_guest_base;
    unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
    if (pc >= mb && pc < mb + ZA_IMAGE_SIZE) {
        ZLOGI("      %s=main+%#llx", what, pc - mb);
        return 1;
    }
    if (za_sdk_base && pc >= za_sdk_base && pc < za_sdk_base + za_sdk_size) {
        ZLOGI("      %s=sdk+%#llx", what, pc - za_sdk_base);
        return 1;
    }
    ZLOGI("      %s=%#llx", what, pc);
    return 0;
}

static int za_sync_in_image(unsigned long long x)
{
    extern unsigned char *za_guest_base;
    unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
    if (x >= mb && x < mb + ZA_IMAGE_SIZE) return 1;
    if (za_sdk_base && x >= za_sdk_base && x < za_sdk_base + za_sdk_size) return 1;
    return 0;
}

// 扫栈（**只作兜底**）：从 sp 往上找前若干个落在映像内的字。
// ★ 这是启发式：映像内的数据指针也会命中，曾经两次把非调用点当成帧
//   （main+0x1738a18 / main+0x173a01c 都被反汇编证伪）。有 fp 时不要用。
static int za_scan_words = 2048;
static void za_sync_scan_chain(unsigned long long sp, const char *why)
{
    extern unsigned char *za_guest_base;
    unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
    unsigned long long v[24];
    int kind[24];   // 1 = main, 2 = sdk
    int n = 0, is_worker = 0;
    for (int k = 0; k < za_scan_words && n < 24; k++) {
        unsigned long long x = 0;
        if (!za_sync_read(&x, sp + (unsigned long)k * 8, 8)) break;
        if (x >= mb && x < mb + ZA_IMAGE_SIZE) {
            if (x - mb == 0x1bab754ull || x - mb == 0x1bac54cull) is_worker = 1;
            v[n] = x - mb; kind[n++] = 1;
        } else if (za_sdk_base && x >= za_sdk_base && x < za_sdk_base + za_sdk_size) {
            v[n] = x - za_sdk_base; kind[n++] = 2;
        }
    }
    int show = is_worker ? (n < 6 ? n : 6) : n;
    if (!is_worker) ZLOGI("      ★ 扫栈兜底（%s）——结果不可信，仅供参考：%d 帧", why, show);
    for (int i = 0; i < show; i++)
        ZLOGI("        %s%#llx", kind[i] == 1 ? "main+" : "sdk+", v[i]);
}

// ── 不依赖 svc 门的 x29 链重建 ─────────────────────────────────────────
// 主线程的门没有把 x29 存进槽位（实测它的 sp/x30/x29 读出来全是 0），
// 所以只能在它的栈区里**反向**把链拼回来：
//   ① 扫栈，收集所有「像一帧」的候选：W 处 [W]=下一帧 fp、[W+8]=返回地址，
//      且下一帧 fp > W（ARM64 栈向低地址增长，帧指针向高地址走）。
//   ② 把候选按「下一帧 fp」首尾相接串成链；只认**接得最长**的那条。
//   ③ 用线程入口校验：18 条工作线程的链尾都是 sdk+0xc90a50，主线程同一入口。
// 这比「把所有像代码地址的字当返回地址」强得多：后者会命中映像内的数据指针。
#define ZA_CAND_MAX 512
typedef struct { unsigned long long fp, lr, next; } za_cand_t;
static za_cand_t za_cands[ZA_CAND_MAX];

static void za_sync_recover_chain(unsigned long long lo, unsigned long long hi)
{
    // 按 4KB 分块读，避免 8 字节一次 readv 的上万次系统调用
    static unsigned char buf[4096 + 8];
    int n = 0;
    for (unsigned long long a = lo; a < hi && n < ZA_CAND_MAX; ) {
        size_t len = (size_t)((hi - a) < 4096 ? (hi - a) : 4096);
        if (!za_sync_read(buf, a, len)) { a += 4096; continue; }
        for (size_t o = 0; o + 16 <= len && n < ZA_CAND_MAX; o += 8) {
            unsigned long long fp = a + o;
            unsigned long long next, lr;
            memcpy(&next, buf + o, 8);
            memcpy(&lr, buf + o + 8, 8);
            if (!za_sync_in_image(lr)) continue;
            if (next <= fp) continue;
            if (next - fp > 0x100000ull) continue;
            za_cands[n].fp = fp;
            za_cands[n].lr = lr;
            za_cands[n].next = next;
            n++;
        }
        a += len;
    }
    if (!n) { ZLOGI("      （反向重建：栈区里没有任何合法帧）"); return; }

    // 链：从某帧出发，反复找「fp == 当前帧的 next」的那一帧
    int best = -1, bestlen = 0;
    unsigned long long entry_lr = za_sdk_base ? za_sdk_base + 0xc90a50ull : 0;
    for (int i = 0; i < n; i++) {
        int cur = i, len = 1;
        unsigned long long outer_lr = za_cands[i].lr;
        for (int k = 0; k < 40; k++) {
            int j = -1;
            for (int t = 0; t < n; t++)
                if (za_cands[t].fp == za_cands[cur].next) { j = t; break; }
            if (j < 0) break;
            cur = j; len++;
            outer_lr = za_cands[cur].lr;
        }
        // 命中线程入口的链优先级最高
        int hit_entry = (entry_lr && outer_lr == entry_lr);
        if (hit_entry && bestlen < 1000) { best = i; bestlen = 1000 + len; continue; }
        if (bestlen < 1000 && len > bestlen) { best = i; bestlen = len; }
    }
    if (best < 0) { ZLOGI("      （反向重建：链都没接上）"); return; }
    int real_len = bestlen >= 1000 ? bestlen - 1000 : bestlen;
    ZLOGI("      ★ 反向 fp 链（%s，共 %d 帧）：",
          bestlen >= 1000 ? "已与线程入口 sdk+0xc90a50 对齐" : "未命中入口，仅按最长链接",
          real_len);
    {
        extern unsigned char *za_guest_base;
        unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
        int cur = best;
        for (int k = 0; k < real_len && k < 40; k++) {
            unsigned long long lr = za_cands[cur].lr;
            if (lr >= mb && lr < mb + ZA_IMAGE_SIZE)
                ZLOGI("        [%d] fp=%#llx lr=main+%#llx", k, za_cands[cur].fp, lr - mb);
            else
                ZLOGI("        [%d] fp=%#llx lr=sdk+%#llx", k, za_cands[cur].fp, lr - za_sdk_base);
            int j = -1;
            for (int t = 0; t < n; t++)
                if (za_cands[t].fp == za_cands[cur].next) { j = t; break; }
            if (j < 0) break;
            cur = j;
        }
    }
    // 帧内容：每帧 prologue 都会把 callee-saved 寄存器（x19/x20/…）压进帧里。
    // 把帧底往下 0x40 字节的**指针**挑出来打印 —— 主线程等的那个对象
    // （`[self+0x158]` 状态机）就在其中某个 x19/x20 槽里。
    {
        extern unsigned char *za_guest_base;
        unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
        ZLOGI("      ★ 帧内指针（x19/x20… 的溢出槽，找等待对象用）：");
        int cur2 = best;
        for (int k = 0; k < real_len && k < 10; k++) {
            unsigned long long fp = za_cands[cur2].fp;
            unsigned long long w[8];
            if (fp < 0x60 || !za_sync_read(w, fp - 0x40, sizeof w)) {
                /* 跳过 */
            } else {
                for (int t = 0; t < 8; t++) {
                    unsigned long long x = w[t];
                    if (!x) continue;
                    int is_code = za_sync_in_image(x);
                    int is_heap = (x >> 40) == 0xb40000ull;
                    if (!is_code && !is_heap) continue;
                    ZLOGI("        [%d] fp%+#x = %#llx%s", k, t * 8 - 0x40, x,
                          is_code ? "（代码）" : "（客机堆）");
                }
            }
            int j = -1;
            for (int t = 0; t < n; t++)
                if (za_cands[t].fp == za_cands[cur2].next) { j = t; break; }
            if (j < 0) break;
            cur2 = j;
        }
    }
}

// 沿 x29 帧指针链回溯。ARM64 标准帧布局：
//     [fp + 0] = 调用者的 fp
//     [fp + 8] = 返回地址（本函数的 lr）
// 门桩把 svc 那一刻的客机 x29 存进 regs[17]，所以起点是**真实的帧指针**。
// 停止条件：fp 未对齐 / 不可读 / 不递增 / 跨度异常 / 该帧的 lr 不在映像内。
static void za_sync_dump_guest_chain(unsigned long long fp, unsigned long long sp,
                                     unsigned long long pc)
{
    if (pc) za_sync_print_addr("客机等待点 x30", pc);
    if (!fp) {
        ZLOGI("      （没有 fp：退回扫栈）");
        if (sp) za_sync_scan_chain(sp, "无 fp");
        return;
    }
    unsigned long long cur = fp, prev = 0;
    int i, stop = 0, printed = 0;
    for (i = 0; i < 32; i++) {
        if (!cur || (cur & 7u)) { stop = 1; break; }               // 未对齐
        unsigned long long hdr[2] = { 0, 0 };
        if (!za_sync_read(hdr, cur, sizeof hdr)) { stop = 2; break; }  // 不可读
        unsigned long long next = hdr[0], lr = hdr[1];
        int in_img = za_sync_in_image(lr);
        if (in_img) {
            extern unsigned char *za_guest_base;
            unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
            if (lr >= mb && lr < mb + ZA_IMAGE_SIZE)
                ZLOGI("        [%d] fp=%#llx lr=main+%#llx", i, cur, lr - mb);
            else
                ZLOGI("        [%d] fp=%#llx lr=sdk+%#llx", i, cur, lr - za_sdk_base);
            printed++;
        } else {
            ZLOGI("        [%d] fp=%#llx lr=%#llx（不在映像内，链在此断）", i, cur, lr);
            stop = 5;
            break;
        }
        // 只有当前帧的 lr 合法才继续往上走
        if (next <= cur) { stop = 3; break; }                     // 必须向高地址
        if (next - cur > 0x100000ull) { stop = 4; break; }        // 跨度异常
        prev = cur;
        cur = next;
    }
    if (!printed) {
        ZLOGI("      （fp 链解不动：fp=%#llx stop=%d）→ 退回扫栈", fp, stop);
        if (sp) za_sync_scan_chain(sp, "fp 链失败");
    } else {
        ZLOGI("      ↑ fp 链共 %d 帧（stop=%d，起点 fp=%#llx，末帧 fp=%#llx）",
              printed, stop, fp, prev ? prev : fp);
    }
}


// za_horizon.c：按 tid 倒出 svc 环形记录（阻塞中的那条 ret 是哨兵 0xdead）
void za_dump_ret_ring_for(long tid);

#ifndef FUTEX_WAIT_PRIVATE
#define FUTEX_WAIT_PRIVATE 128
#endif
#ifndef FUTEX_WAKE_PRIVATE
#define FUTEX_WAKE_PRIVATE 129
#endif

#define ZA_WAITERS_BIT 0x40000000u
// ★ E38：64 太小。客机启动期会起 100+ 条线程，而槽位按 tid 永久占用、
//   从不回收 ⇒ 第 65 条以后全部退回 `tid % ZS_MAX` 共用槽位，等待登记互相
//   覆盖，解锁交接找不到人 —— 真机表现就是「锁字 0（空闲）却 10+ 线程睡死
//   在 sdk+0x145930、NVN 0 次调用」。现在扩到 256，并在分配时回收已退出
//   线程（tgkill(pid,tid,0) == ESRCH）的槽位。
#define ZS_MAX 256                // 同时等待的线程上限
#define ZS_SLICE_NS 5000000L      // 5ms 分片（等锁用）
// 条件变量的「无限等待」分片：返回越频繁，SDK 重判条件的开销越大；
// 太长又会拖慢丢唤醒的恢复。20ms 是旧实现验证过的值。
#define ZS_CV_SLICE_NS 20000000L  // 20ms

typedef struct {
    volatile long tid;            // 0 = 空闲槽
    volatile int kind;            // 0=空闲, 1=等锁, 2=等条件变量, 3=等地址
    volatile int granted;         // 1 = 已唤醒（锁已交接 / 条件已满足）
    volatile unsigned int futex;  // 唤醒字
    unsigned long long addr;      // 锁地址（kind 1/2/3 都记）
    unsigned long long key;       // 条件键地址（仅 kind 2）
    unsigned int tag;             // 我的 tag
    unsigned long long wseq;      // 登记序号：内核按「先登记先服务」
    unsigned long long gsp, gpc;  // 进 svc#28 时的客机 sp / x30（等待点调用链用）
    unsigned long long gfp;       // 进 svc#28 时的客机 x29（真正的帧指针）
} zs_slot_t;

static zs_slot_t zs_slots[ZS_MAX];
static volatile unsigned int zs_spin;
static volatile unsigned long long zs_wseq;

static void zs_lock(void)
{
    while (__atomic_exchange_n(&zs_spin, 1u, __ATOMIC_ACQUIRE))
        while (__atomic_load_n(&zs_spin, __ATOMIC_RELAXED)) { }
}
static void zs_unlock(void) { __atomic_store_n(&zs_spin, 0u, __ATOMIC_RELEASE); }

// 键级统计（定义在文件后半，svc#1C/#1D 要用）
static void zs_key_note(unsigned long long key, int is_sig);

static zs_slot_t *zs_self(void)
{
    long tid = (long)syscall(SYS_gettid);
    for (int i = 0; i < ZS_MAX; i++)
        if (__atomic_load_n(&zs_slots[i].tid, __ATOMIC_ACQUIRE) == tid) return &zs_slots[i];
    for (int i = 0; i < ZS_MAX; i++) {
        long expect = 0;
        if (__atomic_compare_exchange_n(&zs_slots[i].tid, &expect, tid, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return &zs_slots[i];
    }
    // 槽位用完：先回收「线程已经退出」的槽（E38）。不回收的话，启动期
    // 退出过的线程会把槽位永久占住，后来者只能共用 → 丢唤醒。
    for (int i = 0; i < ZS_MAX; i++) {
        long t = __atomic_load_n(&zs_slots[i].tid, __ATOMIC_ACQUIRE);
        if (t == 0 || t == tid) continue;
        if (syscall(SYS_tgkill, getpid(), (int)t, 0) == 0) continue;  // 还活着
        long expect = t;
        if (__atomic_compare_exchange_n(&zs_slots[i].tid, &expect, 0, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED)) {
            expect = 0;
            if (__atomic_compare_exchange_n(&zs_slots[i].tid, &expect, tid, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
                return &zs_slots[i];
            break;
        }
    }
    return &zs_slots[tid % ZS_MAX];   // 仍然用完：退回取模（可能互相干扰，但不会崩）
}

static void zs_wake(zs_slot_t *w)
{
    // 照参考版 wake()：摘出等待链（kind=0）+ 置已唤醒 + 通知它自己的等待字。
    w->kind = 0;
    __atomic_store_n(&w->granted, 1, __ATOMIC_RELEASE);
    __atomic_add_fetch(&w->futex, 1u, __ATOMIC_RELEASE);
    syscall(SYS_futex, (int *)&w->futex, FUTEX_WAKE_PRIVATE, 0x7fffffff, NULL, NULL, 0);
}

// 等自己的唤醒字变化；返回 1 = 已授予，0 = 本片超时
static int zs_wait_granted(zs_slot_t *w, long long slice_ns)
{
    unsigned int seen;
    if (__atomic_load_n(&w->granted, __ATOMIC_ACQUIRE)) return 1;
    seen = __atomic_load_n(&w->futex, __ATOMIC_ACQUIRE);
    if (__atomic_load_n(&w->granted, __ATOMIC_ACQUIRE)) return 1;
    {
        struct timespec ts;
        ts.tv_sec = (time_t)(slice_ns / 1000000000LL);
        ts.tv_nsec = (long)(slice_ns % 1000000000LL);
        syscall(SYS_futex, (int *)&w->futex, FUTEX_WAIT_PRIVATE, seen, &ts, NULL, 0);
    }
    return __atomic_load_n(&w->granted, __ATOMIC_ACQUIRE) ? 1 : 0;
}

// 按内核顺序挑等待者（照 d2r 参考版 pick()）：
//   kind 2 按条件键匹配，kind 1/3 按地址匹配；同组里**先登记者优先**（wseq 小）。
//   以前按槽位下标挑，等于随机 —— 两个等待者同时被信号时会挑错人。
static zs_slot_t *zs_pick(int kind, unsigned long long what)
{
    zs_slot_t *best = NULL;
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *w = &zs_slots[i];
        if (__atomic_load_n(&w->tid, __ATOMIC_RELAXED) == 0) continue;
        if (w->kind != kind) continue;
        if ((kind == 2 ? w->key : w->addr) != what) continue;
        if (!best || w->wseq < best->wseq) best = w;
    }
    return best;
}

// ★ 2026-10-31 E18：Horizon 内核的「锁等待队列」是按**地址**共享的——
//   svc#26(ArbitrateLock) 与 svc#28(WaitProcessWideKeyAtomic，SDK 19 的新式
//   互斥锁慢路径) 都把等待者挂在**同一个锁地址**上，svc#27(ArbitrateUnlock)
//   交接时把锁交给该地址上**第一个等待者**，不论它是哪条 svc 登记的。
//   我们的实现把 kind=1/kind=2 分开匹配，于是新式互斥锁（#28 登记 kind=2）
//   在解锁方走慢路径 #27 时永远交接不到人 ⇒ 16 条线程睡死在 sdk+0x145930。
//   files/za-handoff28 打开后：按地址跨 kind 交接。
static int za_handoff28_enabled(void)
{
    static int m = -1;
    if (m < 0)
        m = access("/data/user/0/org.pokelegza.android.port/files/za-handoff28",
                   F_OK) == 0;
    return m;
}

// ★ E36：交接的**否决**位。真机实测：两个线程在同一个 key 上分别等 0xd / 0xe，
//   交接会把锁字在两者 tag 之间来回写，145 秒里 svc#28 连发、而该 key 上再没有
//   任何 svc#29 信号 ⇒ 互相转交的乒乓活锁。打开这个标记后 wait_key 不再交接，
//   等待者按原语义睡到真正的 Signal。旧式 ArbitrateLock（svc#26/27）不受影响。
static int za_nohandoff28(void)
{
    static int m = -1;
    if (m < 0)
        m = access("/data/user/0/org.pokelegza.android.port/files/za-nohandoff",
                   F_OK) == 0;
    return m;
}

static int za_rel0_mode(void)
{
    static int m = -1;
    if (m < 0)
        m = access("/data/user/0/org.pokelegza.android.port/files/za-rel0",
                   F_OK) == 0;
    return m;
}

static int za_handoff0_mode(void){
    static int m = -1;
    if (m < 0)
        m = access("/data/user/0/org.pokelegza.android.port/files/za-handoff0",
                   F_OK) == 0;
    return m;
}

// ★ E36c：**按地址**的交接风暴闸。同一地址 200ms 内被交接太多次 = 乒乓
//   （真机：0x455800058 上两个线程以 0xd/0xe 互转 145 秒）。命中后只对这个
//   地址改成「释放写 0 + 唤醒」，其它地址仍按 tag 转交 —— 全局 handoff0 会
//   在 24 纹理处把 SDK 互斥协议弄崩，所以只能在风暴地址上局部降级。
#define ZA_STORM_N 8
static struct { unsigned long long addr, t0; unsigned n; } za_storm_tab[ZA_STORM_N];

static int za_storm_mode(void)
{
    static int m = -1;
    if (m < 0)
        m = access("/data/user/0/org.pokelegza.android.port/files/za-storm",
                   F_OK) == 0;
    return m;
}

static int za_storm_hit(unsigned long long addr)
{
    if (!za_storm_mode()) return 0;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned long long now = (unsigned long long)ts.tv_sec * 1000000000ull + ts.tv_nsec;
    int slot = (int)((addr >> 5) & (ZA_STORM_N - 1));
    if (za_storm_tab[slot].addr != addr ||
        now - za_storm_tab[slot].t0 > 200000000ull) {
        za_storm_tab[slot].addr = addr;
        za_storm_tab[slot].t0 = now;
        za_storm_tab[slot].n = 0;
    }
    za_storm_tab[slot].n++;
    return za_storm_tab[slot].n > 8;
}

// 解锁交接：把锁字写成第一个等待者的 tag；还有别人就保留等待者位。
// 调用方必须持 zs_spin。
static void zs_handoff_locked(unsigned long long addr, zs_slot_t *exclude)
{
    int xk = za_handoff28_enabled();
    zs_slot_t *w = NULL;
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *t = &zs_slots[i];
        if (t == exclude) continue;                    // 自己不算「交接目标」
        if (__atomic_load_n(&t->tid, __ATOMIC_RELAXED) == 0) continue;
        int match = (t->kind == 1 && t->addr == addr);
        if (xk && t->kind == 2 && t->addr == addr) match = 1;
        if (!match) continue;
        if (!w || t->wseq < w->wseq) w = t;
    }
    if (!w) {
        __atomic_store_n((unsigned int *)(uintptr_t)addr, 0u, __ATOMIC_RELEASE);
        return;
    }
    // ★ E36b：files/za-handoff0 打开后，对 **#28 等待者（kind=2）** 只做
    //   「释放 + 唤醒」，不把锁字写成对方的 tag、也不置 granted。
    //   理由：真机实测两个线程在同一 key 上以 0xd/0xe 互相交接，145 秒全在
    //   svc#28 乒乓而没有任何 svc#29 —— 双方都以为拿到了所有权，却谁都没有
    //   推进状态。真实内核被 Signal 唤醒时锁字是 0，醒来由用户态自己 CAS。
    //   旧式 #26/#27（kind=1）仍按 Horizon 的 tag 交接语义走。
    if (w->kind == 2 && (za_handoff0_mode() || za_storm_hit(addr))) {
        __atomic_store_n((unsigned int *)(uintptr_t)addr, 0u, __ATOMIC_RELEASE);
        zs_wake(w);
        return;
    }
    int more = 0;
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *t = &zs_slots[i];
        if (t == w || t == exclude) continue;
        if (__atomic_load_n(&t->tid, __ATOMIC_RELAXED) == 0) continue;
        int match = (t->kind == 1 && t->addr == addr);
        if (xk && t->kind == 2 && t->addr == addr) match = 1;
        if (match) { more = 1; break; }
    }
    __atomic_store_n((unsigned int *)(uintptr_t)addr,
                     w->tag | (more ? ZA_WAITERS_BIT : 0u), __ATOMIC_RELEASE);
    __atomic_store_n(&w->granted, 1, __ATOMIC_RELEASE);
    zs_wake(w);
}

// 让 w 去拿 addr 处的锁：空闲就直接写 tag 唤醒；被占就置等待者位、转成锁等待。
// 调用方必须持 zs_spin。
static void zs_acquire_for_locked(zs_slot_t *w, unsigned long long addr, unsigned int tag)
{
    volatile unsigned int *lock = (volatile unsigned int *)(uintptr_t)addr;
    unsigned int v = __atomic_load_n(lock, __ATOMIC_ACQUIRE);
    for (int guard = 0; guard < 100000; guard++) {
        if (v == 0) {
            if (__atomic_compare_exchange_n(lock, &v, tag, 0, __ATOMIC_ACQ_REL,
                                            __ATOMIC_ACQUIRE)) {
                __atomic_store_n(&w->granted, 1, __ATOMIC_RELEASE);
                zs_wake(w);
                return;
            }
            continue;
        }
        if (__atomic_compare_exchange_n(lock, &v, v | ZA_WAITERS_BIT, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
            break;
    }
    w->kind = 1;
    w->addr = addr;
    w->tag = tag;
    // 内核把它**新插进**锁持有者的等待队列：同优先级排在已有锁等待者之后。
    w->wseq = ++zs_wseq;
    __atomic_store_n(&w->granted, 0, __ATOMIC_RELEASE);
}

unsigned long za_sync_arbitrate_lock(unsigned int owner, unsigned long long addr, unsigned int tag)
{
    volatile unsigned int *lock = (volatile unsigned int *)(uintptr_t)addr;
    zs_slot_t *w;
    if (!addr) return 0;
    w = zs_self();
    zs_lock();
    {
        unsigned int cur = __atomic_load_n(lock, __ATOMIC_ACQUIRE);
        // ★ 已经是自己持有（递归进入 / 陈旧状态）：立刻返回。
        //   不判这一条会**自己睡死**——锁字是自己的 tag 时没有任何人会再交接。
        //   （旧实现里就有这条早退，改写时漏掉了。）
        if ((cur & ~ZA_WAITERS_BIT) == tag) {
            zs_unlock();
            return 0;
        }
        // ★ 2026-10-28 真机：主线程卡在 word=0x656c6261（ASCII "able"）的「锁」上
        //   —— 客机把一段文本缓冲当成 mutex 传进来了。这种字永远不会有人 unlock，
        //   永久阻塞就等于整条线死掉。Horizon 的 tag 是线程句柄（小整数，实测
        //   ≤ 0x13），所以 owner 超出合理范围就当成「未被占用」，直接取走。
        // 锁空闲 ⇒ 直接返回，让用户态自己的 CAS 去拿（参考版同样不在这里取锁）。
        // 以前这里替客机写 tag，会和用户态的 CAS 抢同一把锁，制造「锁字是 A、
        // 持有者却是 B」的错乱状态。
        if (cur == 0) {
            zs_unlock();
            return 0;
        }
        if ((cur & ~ZA_WAITERS_BIT) > 0xffffu) {
            static int nbad;
            if (nbad++ < 6)
                ZLOGE("svc#26 锁字不可信 lock=%p word=%#x ⇒ 直接取走（不阻塞）",
                      (void *)lock, cur);
            __atomic_store_n(lock, tag, __ATOMIC_RELEASE);
            zs_unlock();
            return 0;
        }
        if (cur != (owner | ZA_WAITERS_BIT)) {
            zs_unlock();
            return 0;
        }
        w->kind = 1;
        w->addr = addr;
        w->tag = tag;
        __atomic_store_n(&w->granted, 0, __ATOMIC_RELEASE);
        // ★ 诊断：锁字的高位像 ASCII 的可打印字符 ⇒ 这把「锁」其实是一段文本。
        //   真机实测 word=0x656c6261 = "able"，指向客机栈上的字符串缓冲，
        //   说明客机把某个结构体当成锁在用（或者栈上的锁被文本覆盖了）。
        //   把这 0x100 字节按文本倒出来，就能直接看到那条消息。
        if ((cur >> 24) >= 0x20u && (cur >> 24) <= 0x7eu) {
            static int n;
            if (n < 4) {
                n++;
                ZLOGE("★ 锁字像 ASCII：lock=%p word=%#x，附近 0x100 字节：", (void *)lock, cur);
                const char *p2 = (const char *)lock - 0x40;
                for (int i = 0; i < 0x100; i += 0x40) {
                    char line[160];
                    int k = 0;
                    for (int j = 0; j < 0x40 && k < (int)sizeof line - 2; j++) {
                        unsigned char c = (unsigned char)p2[i + j];
                        line[k++] = (c >= 0x20 && c < 0x7f) ? (char)c : '.';
                    }
                    line[k] = 0;
                    ZLOGE("    +%#04x |%s|", i - 0x40, line);
                }
            }
        }
    }
    zs_unlock();
    {
        int slices = 0;
        unsigned int first_word = __atomic_load_n(lock, __ATOMIC_ACQUIRE);
        for (;;) {
            if (zs_wait_granted(w, ZS_SLICE_NS)) break;
            // ★ 陈旧持有者兜底：锁字 1 秒都没变过 ⇒ 持有者已经退出、或者它自己
            //   卡在别的等待里（实测：等锁线程 tag=0x9，锁字 0x40000045，
            //   持有者 tag 0x45 在等待表里根本不存在）。强制取得并报一次，
            //   宁可短暂破坏互斥也不能让整条线永久停摆。
            {
                unsigned int cur = __atomic_load_n(lock, __ATOMIC_ACQUIRE);
                if (cur != first_word) { first_word = cur; slices = 0; }
            }
            // 分片超时：持有者可能走了用户态快路径直接清零（不发 svc#27）。
            // 这种情况我们自己抢下来，否则会永久睡死。
            {
                unsigned int expect = 0;
                if (__atomic_compare_exchange_n(lock, &expect, tag, 0, __ATOMIC_ACQ_REL,
                                                __ATOMIC_ACQUIRE))
                    break;
                if ((expect & ~ZA_WAITERS_BIT) == tag) break;   // 已经是自己
            }
            // ★ 兜底：1 秒还没拿到 ⇒ 视为陈旧（持有者线程可能已退出）。
            //   强制取得并报一次 —— 宁可破坏互斥也不能让整条线永久卡死。
            if (++slices >= 200) {
                static int nforce;
                unsigned int cur = __atomic_load_n(lock, __ATOMIC_ACQUIRE);
                if (nforce++ < 8)
                    ZLOGE("svc#26 1s 未交接 lock=%p word=%#x me=%u ⇒ 强制取得", (void *)lock,
                          cur, tag);
                __atomic_store_n(lock, tag, __ATOMIC_RELEASE);
                break;
            }
        }
    }
    zs_lock();
    w->kind = 0;
    zs_unlock();
    return 0;
}

unsigned long za_sync_arbitrate_unlock(unsigned long long addr)
{
    if (!addr) return 0;
    zs_lock();
    zs_handoff_locked(addr, NULL);
    zs_unlock();
    return 0;
}

unsigned long za_sync_wait_key(unsigned long long addr, unsigned long long key, unsigned int tag,
                               long long ns)
{
    volatile unsigned int *cond = (volatile unsigned int *)(uintptr_t)key;
    zs_slot_t *w;
    if (!addr || !key) return 0;
    w = zs_self();
    zs_lock();
    // ★ E37：**原子复核等待条件**。Horizon 的 WaitProcessWideKeyAtomic 语义是
    //   「*addr == expected 才睡，否则立即返回」。我们以前无条件登记睡眠：
    //   真机实测 10+ 条线程睡在 sdk+0x145930，各自锁字已经是 **0（空闲）**，
    //   而 NVN 最近 0 次调用 —— 解锁方在 svc 之前把字清 0 了，等待者却照样
    //   挂上去，从此没人再叫醒它（丢唤醒）。这里在登记前复核一次，条件已变
    //   就直接返回，让客机按它自己的算法重判/重抢。
    {
        unsigned int cur = __atomic_load_n((unsigned int *)(uintptr_t)addr,
                                           __ATOMIC_ACQUIRE);
        if ((cur & ~ZA_WAITERS_BIT) != tag) {
            zs_unlock();
            return 0;
        }
    }
    // ★ E39b：把「有等待者」位标进锁字。SDK 的解锁（sdk+0x145ffc）是：
    //     if (word == mytag) { word = 0; return; }        // 快路径，**不发信号**
    //     else → 慢路径 svc#27 → 交接
    //   我们的 #28 等待者以前从不置这一位 ⇒ 解锁方永远走快路径清 0，
    //   等待者就永远睡死（真机：10+ 线程、锁字 0、NVN 0 次调用）。
    __atomic_fetch_or((unsigned int *)(uintptr_t)addr, ZA_WAITERS_BIT,
                      __ATOMIC_RELEASE);
    // ★ 顺序照参考版（d2r hle_thread.c 的 svc 0x1C）：
    //   ① 先把条件键置 1（SDK 的 Signal 在用户态先读它，为 0 就**根本不发** svc#29），
    //   ② 登记等待槽，③ 再放锁，④ 最后睡。
    //   以前把「放锁」排在「置键」之前：放锁后、置键前的窗口里，别的线程可以在
    //   用户态抢到锁、改完条件、读到键 0 就不唤醒，本线程随后挂上去永远等不到
    //   —— 这正是之前 15 条线程一起睡死的机制。
    __atomic_store_n(cond, 1u, __ATOMIC_RELEASE);
    zs_key_note(key, 0);
    w->kind = 2;
    w->addr = addr;
    w->key = key;
    w->tag = tag;
    w->wseq = ++zs_wseq;
    __atomic_store_n(&w->granted, 0, __ATOMIC_RELEASE);
    // ★ E18：只有「锁字就是我的 tag」（旧式：我持有并主动让出）才在本次等待里
    //   释放锁。新式互斥锁（SDK 19 的 0x1458e8）的等待者**不持有锁**，
    //   锁字是别人的 tag；之前无条件 handoff 会把持有者的锁字清成 0，
    //   持有者随后解锁时锁字已不符 → 走 #27 慢路径 → 交接不到 → 睡死。
    if (za_rel0_mode()) {
        // ★ E39：SDK 的互斥等待（sdk+0x1458e8）在「字就是我」时把 **自己的
        //   句柄** 当 expected 调 #28 —— 这是「持锁等条件变量」：正确动作是
        //   原子释放（字写 0）然后睡，醒来由调用方重新 CAS 抢锁。
        //   把锁转交给另一个等待者会让对方以为条件满足，两边每轮都白跑
        //   （实测 0xd/0xe 互转 1177 次）。这里只释放、不转交、不唤醒。
        unsigned int cur = __atomic_load_n((unsigned int *)(uintptr_t)addr,
                                           __ATOMIC_ACQUIRE);
        if ((cur & ~ZA_WAITERS_BIT) == tag)
            __atomic_store_n((unsigned int *)(uintptr_t)addr, 0u, __ATOMIC_RELEASE);
    } else if (za_nohandoff28()) {
        /* E36：不交接，按原语义睡到真正的 Signal */
    } else if (za_handoff28_enabled()) {
        unsigned int cur = __atomic_load_n((unsigned int *)(uintptr_t)addr,
                                           __ATOMIC_ACQUIRE);
        if ((cur & ~ZA_WAITERS_BIT) == tag)
            zs_handoff_locked(addr, w);
    } else {
        zs_handoff_locked(addr, w);
    }
    zs_unlock();
    {
        long long deadline = 0;
        if (ns >= 0) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            deadline = (long long)now.tv_sec * 1000000000LL + now.tv_nsec + ns;
        }
        for (;;) {
            long long slice = (ns < 0) ? ZS_CV_SLICE_NS : ZS_SLICE_NS;
            if (ns >= 0) {
                struct timespec now;
                long long left;
                clock_gettime(CLOCK_MONOTONIC, &now);
                left = deadline - ((long long)now.tv_sec * 1000000000LL + now.tv_nsec);
                if (left <= 0) break;
                if (left < slice) slice = left;
            }
            if (zs_wait_granted(w, slice)) break;
            if (ns >= 0) {
                struct timespec now;
                clock_gettime(CLOCK_MONOTONIC, &now);
                if (deadline <= (long long)now.tv_sec * 1000000000LL + now.tv_nsec) break;
            }
            // 无限等待继续睡；丢唤醒由看门狗伪唤醒兜底（调用方会重判条件）。
        }
    }
    zs_lock();
    {
        int granted = __atomic_load_n(&w->granted, __ATOMIC_ACQUIRE);
        w->kind = 0;
        zs_unlock();
        // ★ 照参考版：**超时/伪唤醒时不重新拿锁**。锁由用户态自己重试；
        //   以前这里强行 CAS(0→tag) 会把一把不属于自己的锁抢过来，
        //   随后解锁就写坏了别人的锁（锁字在 0/1/2 之间乱跳的根源）。
        return granted ? 0u : 0xEA01u;
    }
}

// 等待表快照（看门狗/崩溃诊断用）：谁在等哪把锁/哪个条件键。
// 记录「进等待时的客机 sp / x30」——等待表里据此扫栈找客机返回地址。
// svc#52 WaitForAddress 的等待者：登记进同一张表，让看门狗的伪唤醒够得着。
// 这条路径以前完全在表外 —— 真机实测卡住时有线程睡在这里，而看门狗只看到
// 「0 个/1 个线程」，伪唤醒打不到它。
void za_sync_note_addr_wait(unsigned long long addr, unsigned int value, int type,
                            unsigned long long sp, unsigned long long pc,
                            unsigned long long fp)
{
    zs_slot_t *w = zs_self();
    if (!w) return;
    w->kind = 3;
    w->addr = addr;
    w->key = 0;
    w->tag = (unsigned int)value;
    w->gsp = sp;   // ★ 真正的客机 sp（以前这里存的是 type，导致扫栈永远 0 帧）
    w->gpc = pc;   // 调用方客机 pc：谁在等这个地址
    w->gfp = fp;   // 调用方 x29：fp 链回溯的起点
    w->wseq = ++zs_wseq;
    __atomic_store_n(&w->granted, 0, __ATOMIC_RELEASE);
}

void za_sync_addr_wait_done(void)
{
    zs_slot_t *w = zs_self();
    if (!w) return;
    if (w->kind == 3) w->kind = 0;
}

void za_sync_note_guest(unsigned long long sp, unsigned long long pc,
                        unsigned long long fp)
{
    zs_slot_t *w = zs_self();
    w->gsp = sp;
    w->gpc = pc;
    w->gfp = fp;
}

// ── svc#52 最热线程：谁在原地打转 ─────────────────────────────────────
// 自旋的线程永远不登记进等待表（每次都是 FA01 立刻返回），所以等待表里
// 看不到它。这里按 tid 记一份「最后一次调用 svc#52 时的客机 sp/fp/pc」，
// 停摆时挑调用次数最多的那个线程，把它的 **fp 链**打出来 —— 这才是
// 「游戏卡在哪个子系统」的直接答案。
typedef struct {
    volatile long tid;
    unsigned long long sp, fp, pc, addr;
    unsigned int cnt;
} zs_spin_rec_t;
static zs_spin_rec_t zs_spin_rec[64];

void za_sync_note_spin(long tid, unsigned long long sp, unsigned long long fp,
                       unsigned long long pc, unsigned long long addr)
{
    zs_spin_rec_t *r = &zs_spin_rec[(unsigned)tid & 63];
    r->tid = tid;
    r->sp = sp; r->fp = fp; r->pc = pc; r->addr = addr;
    r->cnt++;
}

void za_sync_dump_top_spinner(void)
{
    zs_spin_rec_t *best = NULL;
    for (int i = 0; i < 64; i++) {
        zs_spin_rec_t *r = &zs_spin_rec[i];
        if (!r->tid) continue;
        if (!best || r->cnt > best->cnt) best = r;
    }
    if (!best) { ZLOGE("      （还没有 svc#52 记录）"); return; }
    ZLOGE("★ svc#52 最热线程 tid=%ld 累计 %u 次，等待字 %#llx sp=%#llx fp=%#llx：",
          best->tid, best->cnt, best->addr, best->sp, best->fp);
    if (best->pc) za_sync_print_addr("  它的 pc", best->pc);
    if (best->fp) za_sync_dump_guest_chain(best->fp, best->sp, 0);
    else ZLOGE("      （没有 fp，无法回溯）");
}

// 最热线程在等的那个字：停摆时要扫的是**它**的持有者，不是主线程的。
unsigned long long za_sync_top_spin_addr(void)
{
    zs_spin_rec_t *best = NULL;
    for (int i = 0; i < 64; i++) {
        zs_spin_rec_t *r = &zs_spin_rec[i];
        if (!r->tid) continue;
        if (!best || r->cnt > best->cnt) best = r;
    }
    return best ? best->addr : 0;
}

void za_sync_dump_chain_for(long tid)
{
    zs_slot_t *w = NULL;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++)
        if (__atomic_load_n(&zs_slots[i].tid, __ATOMIC_RELAXED) == tid) { w = &zs_slots[i]; break; }
    unsigned long long sp = w ? w->gsp : 0, pc = w ? w->gpc : 0;
    unsigned long long fp = w ? w->gfp : 0;
    int kind = w ? w->kind : 0;
    zs_unlock();
    ZLOGI("      主线程链（tid=%ld kind=%d sp=%#llx fp=%#llx）：", tid, kind, sp, fp);
    // 没有 fp（主线程的门不写槽）：在它自己的栈区里反向重建 x29 链。
    if (!fp) {
        extern const za_stack_region_t *za_stack_find(long tid);
        const za_stack_region_t *sr = za_stack_find(tid);
        if (sr && sr->hi > sr->lo) {
            ZLOGI("      （无 fp ⇒ 反向重建栈区 [%#lx,%#lx)）", sr->lo, sr->hi);
            za_sync_recover_chain((unsigned long long)sr->lo, (unsigned long long)sr->hi);
        } else {
            ZLOGI("      （无 fp，且找不到栈区）");
        }
    }
    if (pc) za_sync_print_addr("客机等待点 x30", pc);
    if (fp) za_sync_dump_guest_chain(fp, sp, 0);
}

// 找出「谁还可能握着这个地址」：扫描所有已登记客机线程的栈，
// 看哪条栈上出现过该锁地址。持有者一定在某个 callee-saved 寄存器
// （x19..x28）里拿着它，而它们在 prologue 里都会被溢出到帧内。
void za_sync_scan_for_addr(unsigned long long val)
{
    if (!val) return;
    // ① 锁对象本身：把 ±0x40 打出来。nn::os 的互斥对象里除了锁字还有
    //    内部临界区、计数器和**持有者记录**，靠它能直接认出持有者。
    {
        unsigned char raw[0x80];
        if (za_sync_read(raw, val - 0x40, sizeof raw)) {
            ZLOGI("      ★ 锁对象 %#llx ±0x40：", val);
            for (int r = 0; r < 8; r++)
                ZLOGI("        %+#04x: %02x %02x %02x %02x %02x %02x %02x %02x"
                      "  %02x %02x %02x %02x %02x %02x %02x %02x",
                      r * 16 - 0x40,
                      raw[r*16+0], raw[r*16+1], raw[r*16+2], raw[r*16+3],
                      raw[r*16+4], raw[r*16+5], raw[r*16+6], raw[r*16+7],
                      raw[r*16+8], raw[r*16+9], raw[r*16+10], raw[r*16+11],
                      raw[r*16+12], raw[r*16+13], raw[r*16+14], raw[r*16+15]);
        } else {
            ZLOGI("      ★ 锁对象 %#llx 不可读", val);
        }
    }
    int hits = 0;
    for (int i = 0; i < ZS_MAX; i++) {
        long t = __atomic_load_n(&zs_slots[i].tid, __ATOMIC_RELAXED);
        if (!t) continue;
        const za_stack_region_t *sr = za_stack_find(t);
        if (!sr || sr->hi <= sr->lo) continue;
        unsigned long long hi = (unsigned long long)sr->hi;
        unsigned long long lo = hi - 0x40000ull;      // 栈顶 256KB
        if (lo < (unsigned long long)sr->lo) lo = (unsigned long long)sr->lo;
        static unsigned char b2[4096 + 8];
        int found = 0;
        for (unsigned long long a = lo; a < hi && found < 3; ) {
            size_t len = (size_t)((hi - a) < 4096 ? (hi - a) : 4096);
            if (!za_sync_read(b2, a, len)) { a += 4096; continue; }
            for (size_t o = 0; o + 8 <= len; o += 8) {
                unsigned long long x;
                memcpy(&x, b2 + o, 8);
                if (x == val) {
                    ZLOGI("      ↳ tid=%ld 栈上出现该锁地址（%#llx，距栈顶 %+#llx）",
                          t, a + o, (unsigned long long)(a + o) - hi);
                    found++;
                    hits++;
                    if (found >= 3) break;
                }
            }
            a += len;
        }
        if (found) {
            // 这条线程自己此刻在等什么（kind=1 等锁 / 2 等条件变量 / 3 等地址）
            if (zs_slots[i].kind)
                ZLOGI("        ↳ 它的等待：kind=%d lock=%#llx key=%#llx tag=%#x",
                      zs_slots[i].kind, zs_slots[i].addr, zs_slots[i].key,
                      zs_slots[i].tag);
            else
                ZLOGI("        ↳ 它**没有**在等待表里（kind=0）⇒ 可能正是它持有锁");
            // 关键：它停在客机哪条调用链上。队满时「谁认识这个队列」这条线程
            // 的 fp 链直接告诉我们是哪个 handler 卡住了消费。
            {
                long tv = t;
                zs_slot_t *ws = NULL;
                for (int k = 0; k < ZS_MAX; k++)
                    if (__atomic_load_n(&zs_slots[k].tid, __ATOMIC_RELAXED) == tv) { ws = &zs_slots[k]; break; }
                if (ws && (ws->gfp || ws->gsp))
                    za_sync_dump_guest_chain(ws->gfp, ws->gsp, ws->gpc);
                else
                    ZLOGI("        （没有客机 sp/fp 记录，无法回溯调用链）");
            }
            za_dump_ret_ring_for(t);
        }
    }
    ZLOGI("      ↳ 全线程栈扫描：%d 处命中", hits);
}

// ── LightMessageQueue 配对诊断 ────────────────────────────────────────
// SDK 里 nn::os::LightMessageQueue 的布局（反汇编 sdk+0x13b370 TryReceive 确认）：
//   +0x00 数组指针  +0x08 容量  +0x0c 已用  +0x10 头下标  +0x18 用户态自旋锁
//   +0x20 **发送方**等待字（队列满时 Send 睡在这里，等接收方腾位置）
//   +0x28 **接收方**等待字（队列空时 Receive 睡在这里，等发送方投递）
// 两个方向互相唤醒：发送方投递后 svc#53(q+0x28)，接收方取出后应 svc#53(q+0x20)。
// 死锁形状：队满 + 发送方睡在 +0x20 + 接收方睡在 +0x28 ⇒ 谁也叫不醒谁。
//
// 停摆时把每个 kind=3 等待者对应的候选队列打出来（+0x20 与 +0x28 两种解释都试），
// 用 used/cap 和两个等待字立刻能分辨是「队满没人取」还是「队空没人投」。
void za_sync_dump_lq_pairs(void)
{
    unsigned long long qs[ZS_MAX];
    unsigned long long fullq[2];
    int nq = 0, nfull = 0;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *w = &zs_slots[i];
        if (!__atomic_load_n(&w->tid, __ATOMIC_RELAXED)) continue;
        if (w->kind != 3 || !w->addr) continue;
        unsigned long long cand[2] = { w->addr - 0x20, w->addr - 0x28 };
        for (int k = 0; k < 2; k++) {
            int j = 0;
            while (j < nq && qs[j] != cand[k]) j++;
            if (j == nq && nq < ZS_MAX) qs[nq++] = cand[k];
        }
    }
    ZLOGE("★ LightMessageQueue 候选（%d 个）：", nq);
    for (int i = 0; i < nq; i++) {
        unsigned long long q = qs[i];
        unsigned long long arr = 0;
        unsigned int cap = 0, used = 0, head = 0, w20 = 0, w28 = 0;
        if (!za_sync_read(&arr, q, 8)) continue;
        if (!za_sync_read(&cap, q + 8, 4)) continue;
        if (!za_sync_read(&used, q + 0xc, 4)) continue;
        if (!za_sync_read(&head, q + 0x10, 4)) continue;
        if (!za_sync_read(&w20, q + 0x20, 4)) continue;
        if (!za_sync_read(&w28, q + 0x28, 4)) continue;
        // 只打印「像 LQ」的：数组指针是堆地址且容量合理
        int looks = (cap > 0 && cap <= 0x10000 && used <= cap);
        if (!looks) continue;
        int sw = 0, rw = 0;
        for (int s = 0; s < ZS_MAX; s++) {
            zs_slot_t *w = &zs_slots[s];
            if (!__atomic_load_n(&w->tid, __ATOMIC_RELAXED)) continue;
            if (w->kind != 3) continue;
            if (w->addr == q + 0x20) sw++;
            if (w->addr == q + 0x28) rw++;
        }
        ZLOGE("    q=%#llx arr=%#llx used=%u/%u head=%u  send_wait(+20)=%u recv_wait(+28)=%u"
              "  等待者: 发送方 %d / 接收方 %d%s",
              q, arr, used, cap, head, w20, w28, sw, rw,
              (used == cap && sw && !rw) ? "  ← 队满+发送方在等：接收方没在等 ⇒ 没人取" :
              (used == cap && sw && rw) ? "  ← 队满+两边都在等 ⇒ 双向死锁" :
              (used == 0 && rw) ? "  ← 队空+接收方在等 ⇒ 没人投递" : "");
        // 队满且没有接收方 ⇒ 找出「谁认识这个工作队列对象」：如果连一条线程的
        // 栈上都没有它，说明负责消费的那个 runner 根本不存在/没在跑。
        // ⚠ 扫栈很慢，而且要在**放锁之后**做（扫描本身会读栈/取别的锁，
        //   持 zs_lock 会与其它线程形成 ABBA 死锁——真机上直接把进程卡住）。
        if (used == cap && !rw && nfull < 2) fullq[nfull++] = q - 0x40;
    }
    zs_unlock();
    // 放锁之后再扫栈（很慢，且会取别的锁）
    for (int i = 0; i < nfull; i++) {
        extern void za_sync_scan_for_addr(unsigned long long val);
        ZLOGE("      ↳ 扫线程栈找工作队列对象 %#llx（=q-0x40）的持有者：", fullq[i]);
        za_sync_scan_for_addr(fullq[i]);
    }
}

// ── 满队列扩容（实验）────────────────────────────────────────────────
// 死锁形状：消费者卡在处理内部 → 队列塞满 100/100 → 所有生产者堵在 Send。
// 这里在停摆时把「满且有人等」的队列原地扩到 4 倍容量：
//   新数组按 head 顺序把现有 used 条抄过去，cap*=4、head=0、used 不变。
// 语义上等价于「这个队列一开始就开得更大」，不丢消息。
// ⚠ 新数组是宿主 malloc 的；引擎 finalize 时可能会用自己的分配器去 free 它
//   （届时可能崩在退出阶段，可接受）。仅用于判断「满队列是不是死锁的那一环」。
int za_sync_grow_full_lq(void)
{
    unsigned long long qs[8];
    int nq = 0, grown = 0;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *w = &zs_slots[i];
        if (!__atomic_load_n(&w->tid, __ATOMIC_RELAXED)) continue;
        if (w->kind != 3 || !w->addr) continue;
        // 等待字是 q+0x20（发送方）或 q+0x28（接收方），两种都当候选，
        // 后面再用 cap/used 的有效性筛一遍。
        unsigned long long cand[2] = { w->addr - 0x20, w->addr - 0x28 };
        for (int k = 0; k < 2; k++) {
            int j = 0;
            while (j < nq && qs[j] != cand[k]) j++;
            if (j == nq && nq < 8) qs[nq++] = cand[k];
        }
    }
    for (int i = 0; i < nq; i++) {
        unsigned long long q = qs[i];
        unsigned long long arr = 0;
        unsigned int cap = 0, used = 0, head = 0;
        if (!za_sync_read(&arr, q, 8)) continue;
        if (!za_sync_read(&cap, q + 8, 4)) continue;
        if (!za_sync_read(&used, q + 0xc, 4)) continue;
        if (!za_sync_read(&head, q + 0x10, 4)) continue;
        // 触发条件：**必须真的满**（used == cap）且容量/数组指针都合法。
        // ⚠ 校验要严：候选里混进了非队列结构（cap=2）时，曾经把别人的内存改坏；
        //   启动阶段的短暂「有发送方在等」也不该扩（扩容是有代价的动作）。
        if (cap < 8 || cap > 0x10000 || used != cap) continue;
        // 数组指针可能带 TBI 标记（0xb4…）或落在宿主堆，先掩掉高位再判断。
        {
            unsigned long long am = arr & 0x00FFFFFFFFFFFFFFull;
            if (am < 0x10000ull || am >= 0x800000000000ull || (am & 7)) continue;
            arr = am;
        }

        if (cap >= 0x10000) continue;
        // A/B 结论：+16 渐进扩容进程能活更久但推进更少（tex 恒 10）；
        //   ×4 一次性扩容推进明显更多（tex 10→25、buf 12→37）。下游崩溃与
        //   burst 无关（两种都崩/都卡），故选推进更多的 ×4。
        unsigned int ncap = cap * 4;
        unsigned long long *na = calloc(ncap, 8);
        if (!na) continue;
        int ok = 1;
        for (unsigned int k = 0; k < used; k++) {
            unsigned long long v = 0;
            unsigned long src = arr + (unsigned long)((head + k) % cap) * 8;
            if (!za_sync_read(&v, src, 8)) { ok = 0; break; }
            na[k] = v;
        }
        if (!ok) { free(na); continue; }
        {
            // 拿队列的用户态自旋锁（q+0x18）：Push/TryReceive 都在它保护下改环。
            // 拿不到就放弃本轮（下一轮再看），绝不无锁换数组——那会丢消息。
            unsigned int lk = 0;
            if (!__atomic_compare_exchange_n((unsigned int *)(uintptr_t)(q + 0x18), &lk, 1u,
                                             0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                free(na);
                continue;
            }
        }
        __atomic_store_n((unsigned long long *)(uintptr_t)q, (unsigned long long)(uintptr_t)na,
                         __ATOMIC_RELEASE);
        __atomic_store_n((unsigned int *)(uintptr_t)(q + 8), ncap, __ATOMIC_RELEASE);
        __atomic_store_n((unsigned int *)(uintptr_t)(q + 0xc), used, __ATOMIC_RELEASE);
        __atomic_store_n((unsigned int *)(uintptr_t)(q + 0x10), 0u, __ATOMIC_RELEASE);
        __atomic_store_n((unsigned int *)(uintptr_t)(q + 0x18), 0u, __ATOMIC_RELEASE);   // 解锁
        ZLOGE("★ 满队列扩容 %#llx：%u/100 → %u，%u 条消息已搬移", q, used, ncap, used);
        grown++;
    }
    zs_unlock();
    return grown;
}

void za_sync_dump(void)
{
    long tid[ZS_MAX];
    int kind[ZS_MAX], granted[ZS_MAX];
    unsigned long long addr[ZS_MAX], key[ZS_MAX];
    unsigned int tag[ZS_MAX], word[ZS_MAX];
    unsigned long long gsp[ZS_MAX], gpc[ZS_MAX], gfp[ZS_MAX];
    int n = 0;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++) {
        if (!__atomic_load_n(&zs_slots[i].tid, __ATOMIC_RELAXED)) continue;
        if (zs_slots[i].kind == 0) continue;   // 已经不在等了（stale 槽位）
        tid[n] = zs_slots[i].tid;
        kind[n] = zs_slots[i].kind;
        granted[n] = zs_slots[i].granted;
        addr[n] = zs_slots[i].addr;
        key[n] = zs_slots[i].key;
        tag[n] = zs_slots[i].tag;
        word[n] = 0;
        if (addr[n]) {
            unsigned int wv = 0;
            if (za_sync_read(&wv, addr[n], 4)) word[n] = wv;
        }
        gsp[n] = zs_slots[i].gsp;
        gpc[n] = zs_slots[i].gpc;
        gfp[n] = zs_slots[i].gfp;
        n++;
    }
    zs_unlock();
    ZLOGI("sync 等待表（%d 个线程）：", n);
    for (int i = 0; i < n; i++)
    {
        ZLOGI("    tid=%ld kind=%d granted=%d lock=%#llx(word=%#x) key=%#llx tag=%#x pc=%#llx",
              tid[i], kind[i], granted[i], addr[i], word[i], key[i], tag[i], gpc[i]);
        // ★ 2026-10-30：等待的锁/条件变量本身是不是**已经被释放**？
        //   真机已多次看到「等待者睡着、对象被 free」⇒ 这里直接对照释放环。
        {
            extern int za_free_ring_find(unsigned long long p, unsigned long *lr,
                                         long *tid, unsigned *age);
            unsigned long flr = 0; long ftid = 0; unsigned fage = 0;
            if (addr[i] && za_free_ring_find(addr[i], &flr, &ftid, &fage))
                ZLOGE("      ↳ ★ 这个等待地址在 %u 次释放前被 %#lx（tid=%ld）释放过",
                      fage, flr, ftid);
        }
        if (kind[i] != 2 || i < 6) za_dump_ret_ring_for(tid[i]);   // 它最后几条 svc
        // 客机侧调用链：x30 + 沿 x29 链逐帧回溯（无 fp 时才退回扫栈）
        if (kind[i] != 2 && i < 8 && (gfp[i] || gsp[i]))
            za_sync_dump_guest_chain(gfp[i], gsp[i], gpc[i]);
        else if (kind[i] == 2 && i < 4 && (gfp[i] || gsp[i]))
            za_sync_dump_guest_chain(gfp[i], gsp[i], gpc[i]);
        // ★ 锁对象前后的内存：nn::os 的 EventType 是「若干状态字节 + 计数器 +
        //   临界区 + 两个条件变量」，cs/cv 的相对位置固定。把它打出来才能找到
        //   `signaled` 那一字节 —— 如果它一直是 0，就说明游戏在等一个
        //   永远不会被信号的事件（最可疑：vi 的 vsync）。
        if (kind[i] == 2 && i < 2 && addr[i]) {
            unsigned char raw[0x60];
            if (za_sync_read(raw, addr[i] - 0x20, sizeof raw)) {
                for (int r = 0; r < 6; r++)
                    ZLOGI("      lock%+03x: %02x %02x %02x %02x %02x %02x %02x %02x"
                          "  %02x %02x %02x %02x %02x %02x %02x %02x",
                          r * 16 - 0x20,
                          raw[r * 16 + 0], raw[r * 16 + 1], raw[r * 16 + 2], raw[r * 16 + 3],
                          raw[r * 16 + 4], raw[r * 16 + 5], raw[r * 16 + 6], raw[r * 16 + 7],
                          raw[r * 16 + 8], raw[r * 16 + 9], raw[r * 16 + 10], raw[r * 16 + 11],
                          raw[r * 16 + 12], raw[r * 16 + 13], raw[r * 16 + 14], raw[r * 16 + 15]);
            }
        }
    }
}


// 对所有条件变量等待者做一次**合法伪唤醒**（ConditionVariable 本来就允许
// 伪唤醒，调用方会重判条件）。用途：
//   · 诊断：如果游戏在伪唤醒后继续推进，说明卡住的原因是「丢了一次唤醒」；
//   · 兜底：真机上所有线程都睡死时，不让整个进程永久停摆。
// 做法与 svc#29 相同：先把条件键置 1（SDK 的信号方按 *cv != 0 才发 svc），
// 再把锁交给等待者。
unsigned za_sync_poke_all(void)
{
    unsigned n = 0;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *w = &zs_slots[i];
        if (__atomic_load_n(&w->tid, __ATOMIC_RELAXED) == 0) continue;
        if (w->kind == 3) {
            // WaitForAddress：现在走自己的等待槽（不再直接 futex 等客机地址），
            // 所以用 zs_wake 唤醒它，调用方会重判条件。
            zs_wake(w);
            n++;
            continue;
        }
        if (w->kind != 2) continue;
        // 照参考版：伪唤醒 = 把锁交给它（或转成锁等待），调用方会重判条件。
        // 不再递减「等待者计数」—— 条件键现在是布尔量（signal 时无等待者才清 0）。
        zs_acquire_for_locked(w, w->addr, w->tag);
        n++;
    }
    zs_unlock();
    return n;
}

unsigned long za_sync_signal_key(unsigned long long key, int count)
{
    volatile unsigned int *cond = (volatile unsigned int *)(uintptr_t)key;
    if (!key) return 0;
    zs_lock();
    // 照参考版（svc 0x1D）：按内核顺序挑 kind 2，唤醒并把锁交给它；
    // 已经没有 kind 2 等待者时把条件键清 0（SDK 靠它决定要不要发 signal）。
    zs_key_note(key, 1);
    for (int n = 0; count <= 0 || n < count; n++) {
        zs_slot_t *w = zs_pick(2, key);
        if (!w) break;
        zs_acquire_for_locked(w, w->addr, w->tag);
    }
    if (!zs_pick(2, key))
        __atomic_store_n(cond, 0u, __ATOMIC_RELEASE);
    zs_unlock();
    return 0;
}

// ── 地址等待 / 唤醒（svc#52 / svc#53）────────────────────────────────
// 语义照参考版 dm/host/hle_thread.c 的 svc 0x34 / 0x35（真机跑通的成品）：
//   WaitForAddress(addr, type, val, ns)：
//       type 2 ⇒ 值**等于** val 才等；其它（0/1）⇒ 值**小于** val 才等；
//       type 1 ⇒ 先原子减一再等（"等到小于"的计数用法）。
//       条件不成立 ⇒ 返回 0xFA01（SDK 明确把它当「值有变化，重判」）。
//   SignalToAddress(addr, type, val, count)：
//       type 0 ⇒ 只唤醒；
//       type 1 ⇒ 若值等于 val 则 +1 并唤醒（CAS 失败返回 0xFA01）；
//       type 2 ⇒ 按等待者数量改值再唤醒。
//   以前这里只做 futex 等待/唤醒、完全不碰等待表 ⇒ 与客机的 0/1/2 互斥字
//   状态机对不上，锁字卡在 1 时没人能把它推到 2。
static int zs_block_registered(zs_slot_t *w, long long ns)
{
    long long deadline = 0;
    if (ns >= 0) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        deadline = (long long)now.tv_sec * 1000000000LL + now.tv_nsec + ns;
    }
    for (;;) {
        long long slice = (ns < 0) ? ZS_CV_SLICE_NS : ZS_SLICE_NS;
        if (ns >= 0) {
            struct timespec now;
            long long left;
            clock_gettime(CLOCK_MONOTONIC, &now);
            left = deadline - ((long long)now.tv_sec * 1000000000LL + now.tv_nsec);
            if (left <= 0) return 0;
            if (left < slice) slice = left;
        }
        if (zs_wait_granted(w, slice)) return 1;
    }
}

unsigned long za_sync_wait_addr(unsigned long long addr, int type, int val, long long ns)
{
    zs_slot_t *t;
    volatile unsigned int *p = (volatile unsigned int *)(uintptr_t)addr;
    if (!addr) return 0xFA01u;
    t = zs_self();
    if (!t) return 0xFA01u;
    zs_lock();
    {
        unsigned int v = __atomic_load_n(p, __ATOMIC_ACQUIRE);
        // type 是「哪种关系成立才等」（真机实测，见 SDK+0x13a670 与 0x13a854）：
        //   0 = Equal   ⇒ 等 v == val
        //   1 = Less    ⇒ 等 v <  val（成功后再减一，语义是信号量 Acquire）
        //   2 = Greater ⇒ 等 v >  val
        //   3 = NotEqual⇒ 等 v != val
        // 互斥字 0/1/2 的握手就是靠 (2, 1)：等 word > 1，也就是等持有者把它推成 2。
        // 以前把 2 当成 ==，于是 word==1 的等待者永远睡着（没人需要写 2），整机停摆。
        int ok;
        switch (type) {
        case 0: ok = ((int)v == val); break;
        // ★ 2026-10-28 实测确认：这个 SDK 的 (type=2, value=1) 用在**工作队列**上
        //   （SDK+0x13b2d0..0x13b334）：
        //     word == 2 → 直接试着出队（工作已就绪）
        //     word == 0 → 先 CAS 0→1 把自己登记成「有人在等」，再 svc#52
        //     word == 1 → svc#52 睡下去，等生产方把它推成 2
        //   生产方 svc#53(type=1, value=1) 做 CAS 1→2 并唤醒。
        //   ⇒ 等待条件是 **v == value**（睡在自己的「等待中」标记上）。
        //   按 v > value 判会变成纯自旋（实测 120 万次/秒、队列永远空）。
        case 2: ok = ((int)v == val); break;
        case 1: ok = ((int)v < val); break;
        case 3: ok = ((int)v != val); break;
        default: ok = 0; break;
        }
        if (!ok) {
            zs_unlock();
            return 0xFA01u;
        }
        if (type == 1) {
            while (!__atomic_compare_exchange_n(p, &v, v - 1u, 0,
                                                __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
                if (!((int)v < val)) { ok = 0; break; }
            }
        }
        if (!ok) {
            zs_unlock();
            return 0xFA01u;
        }
        t->kind = 3;
        t->addr = addr;
        t->key = 0;
        t->wseq = ++zs_wseq;
        __atomic_store_n(&t->granted, 0, __ATOMIC_RELEASE);
    }
    zs_unlock();
    {
        int r = zs_block_registered(t, ns);
        zs_lock();
        t->kind = 0;
        zs_unlock();
        return r ? 0u : 0xEA01u;
    }
}

// ── 每个等待地址收到过多少信号 ────────────────────────────────────────
// 用来回答「消费者睡在队列上，到底有没有人 signal 过它」。
// 没有信号 ⇒ 生产方根本没入队；有信号但没唤醒 ⇒ 值/CAS 对不上。
typedef struct {
    unsigned long long addr;
    unsigned int sig, woke;
} zs_sig_stat_t;
#define ZS_SIGSTAT_N 64
static zs_sig_stat_t zs_sig_stat[ZS_SIGSTAT_N];

// 调用方必须持 zs_spin。
static void zs_sig_note(unsigned long long addr, int woke)
{
    if (!addr) return;
    for (int i = 0; i < ZS_SIGSTAT_N; i++) {
        zs_sig_stat_t *s = &zs_sig_stat[i];
        if (s->addr == addr) { s->sig++; if (woke > 0) s->woke += (unsigned)woke; return; }
        if (!s->addr) { s->addr = addr; s->sig = 1; if (woke > 0) s->woke = (unsigned)woke; return; }
    }
}

// ── svc#28 / svc#29 的「键级」统计 ───────────────────────────────────
// 回答「worker 睡在条件键 K 上，到底有没有人 SignalProcessWideKey(K)」。
// 以前只有 svc#53（地址唤醒）有统计，svc#29 完全没有 ⇒ 无法区分
// 「没人发信号」和「发到了别的键」。
typedef struct {
    unsigned long long key;
    unsigned int waits, sigs;
} zs_key_stat_t;
#define ZS_KEYSTAT_N 48
static zs_key_stat_t zs_key_stat[ZS_KEYSTAT_N];

// 调用方必须持 zs_lock。
static void zs_key_note(unsigned long long key, int is_sig)
{
    if (!key) return;
    for (int i = 0; i < ZS_KEYSTAT_N; i++) {
        zs_key_stat_t *s = &zs_key_stat[i];
        if (s->key == key) { if (is_sig) s->sigs++; else s->waits++; return; }
        if (!s->key) { s->key = key; if (is_sig) s->sigs = 1; else s->waits = 1; return; }
    }
}

void za_sync_dump_key_stats(void)
{
    zs_lock();
    int n = 0;
    for (int i = 0; i < ZS_KEYSTAT_N; i++) if (zs_key_stat[i].key) n++;
    ZLOGE("★ 条件变量键统计（%d 个）：键 / 等待 / 信号", n);
    for (int i = 0; i < ZS_KEYSTAT_N; i++)
        if (zs_key_stat[i].key)
            ZLOGE("    %#llx  W=%u  S=%u%s", zs_key_stat[i].key, zs_key_stat[i].waits,
                  zs_key_stat[i].sigs, zs_key_stat[i].sigs ? "" : "  ← 从没人发");
    zs_unlock();
}

int za_sync_sig_stat(unsigned long long addr, unsigned int *sig, unsigned int *woke)
{
    int found = 0;
    if (sig) *sig = 0;
    if (woke) *woke = 0;
    zs_lock();
    for (int i = 0; i < ZS_SIGSTAT_N; i++) {
        if (zs_sig_stat[i].addr == addr) {
            if (sig) *sig = zs_sig_stat[i].sig;
            if (woke) *woke = zs_sig_stat[i].woke;
            found = 1;
            break;
        }
    }
    zs_unlock();
    return found;
}

unsigned long za_sync_signal_addr(unsigned long long addr, int type, int val, int count)
{
    unsigned long r = 0;
    int nw = 0;
    int woke = 0;
    volatile unsigned int *p = (volatile unsigned int *)(uintptr_t)addr;
    if (!addr) return 0xFA01u;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *w = &zs_slots[i];
        if (!__atomic_load_n(&w->tid, __ATOMIC_RELAXED)) continue;
        if (w->kind == 3 && w->addr == addr) nw++;
    }
    if (type != 0) {
        int nv = val + 1;
        if (type == 2) {
            if (count <= 0) nv = nw > 0 ? val - 1 : val + 1;
            else nv = nw == 0 ? val + 1 : (nw <= count ? val - 1 : val);
        }
        {
            unsigned int e = (unsigned int)val;
            if (!__atomic_compare_exchange_n(p, &e, (unsigned int)nv, 0,
                                             __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                r = 0xFA01u;
        }
    }
    if (!r) {
        for (int n = 0; count <= 0 || n < count; n++) {
            zs_slot_t *w = zs_pick(3, addr);
            if (!w) break;
            zs_wake(w);
            woke++;
        }
    }
    zs_sig_note(addr, woke);
    zs_unlock();
    return r;
}

// ── 修复「等待环被写满」的锁 ──────────────────────────────────────────
// SDK 的阻塞互斥对象布局（反汇编 0x13a790 确认）：
//   +0x00 = 等待者数组指针   +0x08 = 容量   +0x0c = 已用   +0x10 = 头下标
// 入队路径被 `cmp 已用, 容量 ; b.ge 跳过` 卡住 —— 一旦「已用」涨到容量，
// 新等待者再也登记不进去，持有者的交接也就找不到人，整把锁永久停摆。
// 真机实测：卡死的互斥对象都是 100/100，而同一时刻只有 2~6 个线程真的在等
// ⇒ 里面 90 多个是陈旧条目（等待者被唤醒/重试后没有出队）。
// 这里只把「已用」清 0，不动数组内容、不碰锁字本身 —— 陈旧条目再也不会被读到，
// 也不会释放任何指针，所以不会破坏互斥保护的数据。
// 返回修复了几个对象。
int za_sync_repair_full_wait_ring(void)
{
    unsigned long long addrs[ZS_MAX];
    int na = 0, fixed = 0;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *w = &zs_slots[i];
        if (!__atomic_load_n(&w->tid, __ATOMIC_RELAXED)) continue;
        if (w->kind != 3) continue;
        int k = 0;
        while (k < na && addrs[k] != w->addr) k++;
        if (k == na) { addrs[na++] = w->addr; }
    }
    for (int k = 0; k < na; k++) {
        for (int d = 0x20; d <= 0x28; d += 8) {
            unsigned long long base = addrs[k] - (unsigned long long)d;
            unsigned long long arr = 0;
            unsigned int cap = 0, used = 0;
            if (!za_sync_read(&arr, base, 8)) continue;
            if (!za_sync_read(&cap, base + 8, 4)) continue;
            if (!za_sync_read(&used, base + 0xc, 4)) continue;
            if (!ZA_PTR_OK(arr)) continue;
            if (cap == 0 || cap > 4096) continue;
            if (used < cap) continue;                 // 没满，不管
            __atomic_store_n((unsigned int *)(uintptr_t)(base + 0xc), 0u, __ATOMIC_RELEASE);
            ZLOGE("★ 等待环写满：%#llx (obj=%#llx) 已用 %u/%u ⇒ 清 0 并唤醒全部等待者",
                  addrs[k], base, used, cap);
            for (;;) {
                zs_slot_t *x = zs_pick(3, addrs[k]);
                if (!x) break;
                zs_wake(x);
            }
            fixed++;
            break;
        }
    }
    zs_unlock();
    return fixed;
}

// 伪唤醒所有「地址等待」(kind=3) 线程。内核允许伪唤醒，调用方必须重判条件，
// 所以这在语义上是合法的。用途是**分辨两种停摆**：
//   伪唤醒后系统能推进 ⇒ 是我们丢了一次唤醒（真 bug 在信号侧）；
//   伪唤醒后等待者立刻又睡回去 ⇒ 对方确实没释放，得去找持有者。
int za_sync_poke_addr_waiters(void)
{
    int n = 0;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *w = &zs_slots[i];
        if (!__atomic_load_n(&w->tid, __ATOMIC_RELAXED)) continue;
        if (w->kind != 3) continue;
        zs_wake(w);
        n++;
    }
    zs_unlock();
    return n;
}

// 「按新协议交接」的强制唤醒：把等待字推到 value+1 再唤醒全部等待者。
//
// 为什么不能像 za_sync_force_release_stuck 那样清 0：SDK 的
// InternalConditionVariable::Wait（sdk+0x13a5d0）醒来后的判定是
//   0 → CAS 0→1 后**再睡**；1 → svc#52（睡在自己的等待标记上）；2 → 消费信号并返回。
// 所以清 0 只会让等待者立刻又睡回去（真机实测：伪唤醒 19 个线程 × 多轮，毫无进展）。
// 唯一能让它们真正返回的是把字写成 2（= 已通知）。
//
// 语义上等价于「持有者已经死了，代替它完成一次 Signal 交接」：会破坏互斥，
// 只用于判定死锁性质。返回动了几个地址。
int za_sync_force_signal_stuck(void)
{
    unsigned long long addrs[ZS_MAX];
    unsigned int vals[ZS_MAX];
    int cnt[ZS_MAX], na = 0, done = 0;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *w = &zs_slots[i];
        if (!__atomic_load_n(&w->tid, __ATOMIC_RELAXED)) continue;
        if (w->kind != 3) continue;
        int k = 0;
        while (k < na && addrs[k] != w->addr) k++;
        if (k == na) { addrs[na] = w->addr; vals[na] = w->tag; cnt[na] = 0; na++; }
        cnt[k]++;
    }
    for (int k = 0; k < na; k++) {
        unsigned int *p = (unsigned int *)(uintptr_t)addrs[k];
        unsigned int cur = __atomic_load_n(p, __ATOMIC_ACQUIRE);
        if ((int)cur != (int)vals[k]) continue;      // 条件已不成立 ⇒ 等待者自己会走
        unsigned int nv = cur + 1u;
        __atomic_store_n(p, nv, __ATOMIC_RELEASE);
        ZLOGE("★ 强制交接 %#llx：word %#x → %#x（%d 个等待者仍在等）",
              addrs[k], cur, nv, cnt[k]);
        for (;;) {
            zs_slot_t *w = zs_pick(3, addrs[k]);
            if (!w) break;
            zs_wake(w);
        }
        done++;
    }
    zs_unlock();
    return done;
}

// 诊断性强制解锁：只对「同一地址上 >= 2 个等待者」的锁字执行 SDK 解锁路径的
// 动作（把 1 或 2 写成 0）再唤醒全部等待者。
// ⚠ 这会破坏互斥（被保护的数据可能被两个线程同时改）。仅用于**判定死锁性质**：
//   能推进 ⇒ 锁是被「泄漏」的（持有者已经不存在）；崩溃 ⇒ 锁确实还在保护数据。
// 调用方负责限流；这里只返回动了几个地址。
int za_sync_force_release_stuck(void)
{
    unsigned long long addrs[ZS_MAX];
    int cnt[ZS_MAX], na = 0, done = 0;
    zs_lock();
    for (int i = 0; i < ZS_MAX; i++) {
        zs_slot_t *w = &zs_slots[i];
        if (!__atomic_load_n(&w->tid, __ATOMIC_RELAXED)) continue;
        if (w->kind != 3) continue;
        int k = 0;
        while (k < na && addrs[k] != w->addr) k++;
        if (k == na) { addrs[na] = w->addr; cnt[na] = 0; na++; }
        cnt[k]++;
    }
    for (int k = 0; k < na; k++) {
        if (cnt[k] < 2) continue;           // 只有一个等待者 ⇒ 可能只是正常等锁
        unsigned int *p = (unsigned int *)(uintptr_t)addrs[k];
        unsigned int old = __atomic_load_n(p, __ATOMIC_ACQUIRE);
        if (old != 1 && old != 2) continue;
        __atomic_store_n(p, 0u, __ATOMIC_RELEASE);
        ZLOGE("★ 强制解锁 %#llx：word %#x → 0（%d 个等待者）", addrs[k], old, cnt[k]);
        for (;;) {
            zs_slot_t *w = zs_pick(3, addrs[k]);
            if (!w) break;
            zs_wake(w);
        }
        done++;
    }
    zs_unlock();
    return done;
}
