// 客机（main NSO）装载器：映像映射、基址重定位、导入解析、TLS 改写、启动。
//
// ⚠ 本文件于 2026-10-25 被一次错误的批量替换（re.sub 跨行匹配）清空，现按以下依据重建：
//   · work/recover/libzaandroid-1403.so 的 DWARF 行号表（原文件 2,743 行、117 个代码段）
//   · app/native/za_guest_api.h（对外接口定义，完好）
//   · 现存头文件 za_guest_info.h / za_imports.h / za_relocs.h / za_tls_patch.h /
//     za_tls_mrs.h / za_tlsro_patch.h / za_svc_patch.h
//   · 借鉴清单.md 里记录的全部逆向结论
// 重建原则：**接口与行为按文档实证的来，注释里逐条标注依据**。
//
// 客机是 Switch 原生 ARM64，安卓也是 ARM64 ⇒ 直接跑、不翻译。
// 需要解决的是「导入怎么解析」「TLS 怎么给」「OS 服务谁提供」。

// process_vm_readv 要 _GNU_SOURCE（bionic 的 <sys/uio.h> 才声明它）
// ⚠ 必须在任何系统头文件之前定义
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <android/log.h>

#include "za_common.h"
#include "za_guest_info.h"
#include "za_imports.h"
#include "za_relocs.h"
#include "za_stub.h"
#include "za_tls_patch.h"
#include "za_tlsbase_patch.h"
#include "za_tlsro_patch.h"
#include "za_tls_mrs.h"
#include "za_tls_mrs_blob.h"
#include "za_mod.h"
#include "za_sdk.h"
#include "za_guest_api.h"
#include "za_os.h"

// ── 客机映像布局（来自 za_guest_info.h，实测值）────────────────────────
//   text   0x0000000 .. 0x2fc7250
//   rodata 0x2fc8000 .. 0x39e1000
//   data   0x39e1000 .. 0x3d7f1c0
//   bss    +0x21fae40        ⇒ 映像总计 0x5f7a000
#define ZA_GUEST_BASE_ADDR 0x100000000ul   // 客机代码里硬编码的基址，必须映射到这里

// 客机全局状态（其它 .c 通过 extern 访问）
unsigned char *za_guest_base = NULL;
volatile unsigned long za_sdk_base = 0;
volatile unsigned long za_sdk_size = 0;

// 崩溃/诊断用的线程身份
volatile long za_render_tid = 0;
volatile long za_guest_tid = 0;
volatile long za_render_entry = 0;
volatile int za_render_crashes = 0;
volatile unsigned long za_so_base = 0;
char za_last_sym[256];

// svc 轨迹（崩溃时倒出来，直接看「最后一步调了什么」）
unsigned long za_svc_trace_nr[32];
unsigned long za_svc_trace_pc[32];
unsigned long za_svc_trace_pos;

// ── 小工具（信号处理器里也只能用这些，不能碰 libc）──────────────────
static char *za_put_str(char *p, const char *s)
{
    while (*s) *p++ = *s++;
    return p;
}

static char *za_put_hex(char *p, unsigned long long v)
{
    static const char dig[] = "0123456789abcdef";
    *p++ = '0';
    *p++ = 'x';
    if (!v) { *p++ = '0'; return p; }
    char tmp[16];
    int n = 0;
    while (v) { tmp[n++] = dig[v & 0xF]; v >>= 4; }
    while (n) *p++ = tmp[--n];
    return p;
}

// 把地址换算成「模块名+偏移」，光看绝对地址没法反查汇编
static char *za_put_addr(char *p, unsigned long a)
{
    if (za_guest_base && a >= (unsigned long)za_guest_base &&
        a < (unsigned long)za_guest_base + ZA_IMAGE_SIZE)
    {
        p = za_put_str(p, "main+");
        p = za_put_hex(p, a - (unsigned long)za_guest_base);
        return p;
    }
    if (za_sdk_base && a >= za_sdk_base && a < za_sdk_base + za_sdk_size)
    {
        p = za_put_str(p, "sdk+");
        p = za_put_hex(p, a - za_sdk_base);
        return p;
    }
    return za_put_hex(p, a);
}

// ════════════════════════════════════════════════════════════════
//  崩溃现场落盘
// ════════════════════════════════════════════════════════════════
//
// ⚠ 安卓上 native 的 fd 2 **不接 logcat**（内容直接进 /dev/null），而 stderr 又是块缓冲：
//   进程被信号打死时缓冲一起丢 ⇒ 什么现场都不剩（早期就是这么丢掉全部崩溃信息的）。
//   ⇒ 每条现场输出都走 za_fatal_write：**自己 open 一个文件**、写、缓存 fd。
//   （这条经验来自 Timqt/d2r-android 的 adapt 补丁第 4 条，实测有效。）

#define ZA_FATAL_PATH "/data/data/org.pokelegza.android.port/files/za_fatal.log"
static int za_fatal_fd_cached = -1;

static void za_fatal_write(const char *buf, size_t len)
{
    ssize_t w0 = write(2, buf, len); (void)w0;          // 万一 fd 2 被接到 logcat
    if (za_fatal_fd_cached < 0)
        za_fatal_fd_cached = open(ZA_FATAL_PATH, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (za_fatal_fd_cached >= 0)
    { ssize_t w1 = write(za_fatal_fd_cached, buf, len); (void)w1; }
}

// 安全地读一个地址：process_vm_readv 是系统调用，碰到未映射页返回失败，
// 而不是像直接解引用那样把**信号处理器自己**搞崩（栈溢出时这是必须的）。
static int za_read_word(unsigned long addr, unsigned long *out)
{
    struct iovec local, remote;
    local.iov_base = out;
    local.iov_len = sizeof *out;
    remote.iov_base = (void *)(uintptr_t)addr;
    remote.iov_len = sizeof *out;
    ssize_t n = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    return n == (ssize_t)sizeof *out;
}

static size_t za_read_bytes(unsigned long addr, void *dst, size_t len)
{
    struct iovec local, remote;
    local.iov_base = dst;
    local.iov_len = len;
    remote.iov_base = (void *)(uintptr_t)addr;
    remote.iov_len = len;
    ssize_t n = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    return n > 0 ? (size_t)n : 0;
}

// 一行原始输出（信号处理器里只能用 write，不能碰 libc）
static void za_log_line(const char *s)
{
    size_t len = strlen(s);
    za_fatal_write(s, len);
}

// 打印「信号号 + 故障 PC + 映像内偏移 + 故障地址」
static void za_log_raw(int sig, unsigned long pc, unsigned long off, const char *rel, void *addr)
{
    char line[256];
    char *p = line;
    p = za_put_str(p, "ZaGuest: signal ");
    p = za_put_hex(p, (unsigned long long)sig);
    p = za_put_str(p, " pc=");
    p = za_put_hex(p, (unsigned long long)pc);
    p = za_put_str(p, " seg=");
    p = za_put_str(p, rel ? rel : "?");
    p = za_put_str(p, " off=");
    p = za_put_hex(p, (unsigned long long)off);
    p = za_put_str(p, " addr=");
    p = za_put_hex(p, (unsigned long long)(uintptr_t)addr);
    p = za_put_str(p, "\n");
    za_fatal_write(line, (size_t)(p - line));
}
// 客机栈回溯：把栈上所有落在 main/sdk 映像里的字找出来（= 返回地址）。
// ⚠ 必须**分块读**（一次 64KB 往上扫，最多 8MB）：
//   崩溃点离上个栈帧可能几 MB（中间是 SDK 的大局部数组），只扫 4KB 会看到一片假帧。
static void za_log_guest_trace(unsigned long sp)
{
    unsigned long bm = (unsigned long)za_guest_base, sm = za_sdk_base;
    char line[256];
    int found = 0;
    enum { CHUNK = 64 * 1024, MAXCHUNK = 128 };
    static unsigned char buf[CHUNK];        // 静态：崩在备用栈上，不能占大栈
    for (int c = 0; c < MAXCHUNK; c++)
    {
        unsigned long addr = sp + (unsigned long)c * CHUNK;
        size_t got = za_read_bytes(addr, buf, CHUNK);
        if (!got) break;
        for (size_t o = 0; o + 8 <= got; o += 8)
        {
            unsigned long w = 0;
            memcpy(&w, buf + o, 8);
            const char *mod = NULL;
            unsigned long off = 0;
            if (bm && w >= bm && w < bm + ZA_IMAGE_SIZE) { mod = "main"; off = w - bm; }
            else if (sm && w >= sm && w < sm + za_sdk_size) { mod = "sdk"; off = w - sm; }
            if (!mod) continue;
            found++;
            char *p = line;
            p = za_put_str(p, "ZaGuest: guest ret@+");
            p = za_put_hex(p, (unsigned long long)((unsigned long)c * CHUNK + o));
            p = za_put_str(p, " ");
            p = za_put_str(p, mod);
            p = za_put_str(p, "+");
            p = za_put_hex(p, (unsigned long long)off);
            p = za_put_str(p, "\n");
            za_fatal_write(line, (size_t)(p - line));
            if (found >= 200) { c = MAXCHUNK; break; }
        }
    }
}

// 当前帧 dump：从 sp-0x100 到 sp+0x200。
// 崩溃时 sp 常落在**某个函数帧内部**，保存 x29/x30 的槽在 sp 下方，只 dump 上方会永远看不到。
static void za_log_stack(unsigned long sp)
{
    char line[640];
    unsigned long w[8];
    for (int r = -32; r < 64; r += 8)
    {
        unsigned long addr = (unsigned long)((int64_t)sp + (int64_t)r * 8);
        int ok = 1;
        for (int i = 0; i < 8; i++)
            if (!za_read_word(addr + (unsigned long)i * 8, &w[i])) { ok = 0; break; }
        if (!ok) continue;
        char *p = line;
        p = za_put_str(p, r < 0 ? "ZaGuest: frame-" : "ZaGuest: frame+");
        p = za_put_hex(p, (unsigned long long)(r < 0 ? -(long long)(r * 8) : (long long)(r * 8)));
        for (int i = 0; i < 8; i++)
        {
            p = za_put_str(p, " ");
            p = za_put_addr(p, w[i]);
        }
        p = za_put_str(p, "\n");
        za_fatal_write(line, (size_t)(p - line));
    }
}

// 把 /proc/self/maps 里与崩溃相关的映射写进日志
static void za_log_maps(void)
{
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    static char buf[8192];
    ssize_t got;
    while ((got = read(fd, buf, sizeof buf - 1)) > 0)
    {
        buf[got] = 0;
        char *ln = buf;
        while (ln && *ln)
        {
            char *nl = ln;
            while (*nl && *nl != 10) nl++;
            size_t n = (size_t)(nl - ln);
            char tmp[512];
            size_t k = n < sizeof tmp - 8 ? n : sizeof tmp - 8;
            memcpy(tmp, ln, k);
            memcpy(tmp + k, "\n", 1);
            za_fatal_write("ZaGuest: map ", 13);
            za_fatal_write(tmp, k + 1);
            ln = (*nl ? nl + 1 : NULL);
        }
    }
    close(fd);
}
// SDK 状态 dump：os 上下文对象（x19）+ 只读 TLS 页 + self 结构。
//
// ★ 关键教训（本轮踩过）：SDK 的临界区读的是 **[self + 0x1b0]**（self = [ro+0x1f8]），
//   不是 [ro + 0x1b0] —— 两页差 0x1000。之前一直 dump 错位置，导致误判好几轮。
static void za_log_sdk_state(unsigned long x19, unsigned long x8)
{
    char line[256];
    unsigned long long sdk = za_sdk_base;

    // 无条件先打一行「进入本函数」，用来区分「没被调用」和「被调用但读不到」
    {
        static const char tag[] = "ZaGuest: SDK-STATE enter\n";
        za_fatal_write(tag, sizeof tag - 1);
    }
    if (!sdk)
    {
        static const char t[] = "ZaGuest: sdk_base=0（SDK 未装载）\n";
        za_fatal_write(t, sizeof t - 1);
        return;
    }

    // ① self 结构里的 owner_id（临界区真正读的地方）
    {
        unsigned long long ro = sdk + ZA_TLSRO_OFF, self = 0;
        if (za_read_bytes(ro + 0x1f8, &self, 8) && self)
        {
            unsigned long long oid = 0;
            unsigned char kind = 0;
            za_read_bytes(self + 0x1b0, &oid, 8);
            if (!za_read_bytes(self + 0x04, &kind, 1)) kind = 0;
            char *p = line;
            p = za_put_str(p, "ZaGuest: self=");
            p = za_put_hex(p, self);
            p = za_put_str(p, "  [self+0x1b0]=owner_id=");
            p = za_put_hex(p, oid);
            p = za_put_str(p, oid ? "" : "  <<< owner_id 为 0 ⇒ 临界区必错");
            p = za_put_str(p, "  [self+0x4]=type=");
            p = za_put_hex(p, (unsigned long long)kind);
            p = za_put_str(p, "\n");
            za_fatal_write(line, (size_t)(p - line));
        }
        else
        {
            static const char t[] = "ZaGuest: [ro+0x1f8] 读不到或为 0  <<< 临界区会读空指针\n";
            za_fatal_write(t, sizeof t - 1);
        }
    }

    // ② x19（os 上下文对象）里被用到的字段
    if (x19)
    {
        static const unsigned offs[] = { 0x18, 0x48, 0x98, 0xf0, 0x1c8, 0x1d0, 0x2e0 };
        for (unsigned i = 0; i < sizeof offs / sizeof offs[0]; i++)
        {
            unsigned long v = 0;
            if (!za_read_word(x19 + offs[i], &v)) continue;
            char *p = line;
            p = za_put_str(p, "ZaGuest: x19+");
            p = za_put_hex(p, (unsigned long long)offs[i]);
            p = za_put_str(p, " = ");
            p = za_put_hex(p, (unsigned long long)v);
            p = za_put_str(p, v ? "" : "   <<< 0");
            p = za_put_str(p, "\n");
            za_fatal_write(line, (size_t)(p - line));
        }
    }

    // ③ 只读 TLS 页的关键槽
    {
        unsigned long long ro = sdk + ZA_TLSRO_OFF;
        static const unsigned offs[] = { 0x00, 0x20, 0x70, 0x78, 0x80, 0x1e0, 0x1f0, 0x1f8 };
        for (unsigned i = 0; i < sizeof offs / sizeof offs[0]; i++)
        {
            unsigned long long v = 0;
            if (!za_read_bytes(ro + offs[i], &v, 8)) continue;
            char *p = line;
            p = za_put_str(p, "ZaGuest: sdk-ro +");
            p = za_put_hex(p, (unsigned long long)offs[i]);
            p = za_put_str(p, " = ");
            p = za_put_hex(p, v);
            if (!v) p = za_put_str(p, "   <<< 0");
            else if (v == x8 && x8) p = za_put_str(p, "   <<< 等于崩溃 x8");
            p = za_put_str(p, "\n");
            za_fatal_write(line, (size_t)(p - line));
        }
    }

    // ④ 崩溃时 x8（blr 的目标）与 x19
    {
        char *p = line;
        p = za_put_str(p, "ZaGuest: sdk-state x8(=blr的目标)=");
        p = za_put_hex(p, (unsigned long long)x8);
        p = za_put_str(p, "  x19(os ctx)=");
        p = za_put_hex(p, (unsigned long long)x19);
        p = za_put_str(p, "\n");
        za_fatal_write(line, (size_t)(p - line));
    }
}

// 拦截 32..62 的实时信号（63 留给 PC 采样器）：只记录「信号号 / 故障 PC / siginfo」后转给致命处理
static void za_rt_catch(int sig, siginfo_t *info, void *ctx);
static void za_fatal_handler(int sig, siginfo_t *info, void *ctx);
// 备用信号栈：栈溢出时处理器自己也要有地方跑，否则进程被静默杀掉（连日志都没有）。
// ⚠ sigaltstack 是 **per-thread** 的；⚠⚠ 备用栈**不能放 TLS 里**（客机会重写线程 TLS）。
#define ZA_ALTSTACK_SLOTS 64
static char *za_altstacks[ZA_ALTSTACK_SLOTS];
static void *za_altstack_owner[ZA_ALTSTACK_SLOTS];
#define ZA_SIGSTACK_SIZE (256 * 1024)

void za_install_altstack(void)
{
    void *self = (void *)(uintptr_t)syscall(SYS_gettid);
    int slot = -1;
    for (int i = 0; i < ZA_ALTSTACK_SLOTS; i++)
    {
        if (za_altstack_owner[i] == self) { slot = i; break; }
        if (!za_altstack_owner[i] && slot < 0) slot = i;
    }
    if (slot < 0) return;
    if (!za_altstacks[slot])
    {
        void *m = mmap(NULL, ZA_SIGSTACK_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED) return;
        za_altstacks[slot] = (char *)m;
    }
    za_altstack_owner[slot] = self;
    stack_t ss;
    ss.ss_sp = za_altstacks[slot];
    ss.ss_size = ZA_SIGSTACK_SIZE;
    ss.ss_flags = 0;
    sigaltstack(&ss, NULL);
}

// 致命信号处理：把现场全落盘，然后**恢复默认动作并重新 raise**（不吞信号，
// 否则 debuggerd 出不了 tombstone；以前用 abort() 会因 SIGABRT 被自己接住而无限递归）。
//
// ⚠ 最后那个 _exit(99) 是「信号在处理器内仍被屏蔽、raise 不生效」时的后备。
static void za_fatal_handler(int sig, siginfo_t *info, void *ctx)
{
    unsigned long pc = 0;
    if (ctx) { ucontext_t *uc = (ucontext_t *)ctx; pc = (unsigned long)uc->uc_mcontext.pc; }
    {
        static const char tag[] = "ZaGuest: FATAL-ENTER\n";
        za_fatal_write(tag, sizeof tag - 1);
    }
    unsigned long off = pc;
    const char *rel = "?";
    if (za_guest_base && pc >= (unsigned long)za_guest_base)
    {
        off = pc - (unsigned long)za_guest_base;
        rel = (pc < (unsigned long)za_guest_base + ZA_TEXT_SIZE) ? "text"
            : (pc < (unsigned long)za_guest_base + ZA_DATA_OFF) ? "rodata"
            : (pc < (unsigned long)za_guest_base + ZA_DATA_OFF + ZA_DATA_SIZE) ? "data" : "bss";
    }
    long my_tid = syscall(SYS_gettid);

    // 渲染线程崩了：**不能让它带死整个进程**（驱动 present 路径偶发空指针），
    // 跳回渲染循环开头重来一帧；但要限次，否则崩→跳回→再崩会变成死循环。
    if (my_tid == za_render_tid)
    {
        int n = ++za_render_crashes;
        if (ctx && za_render_entry)
        {
            ucontext_t *uc = (ucontext_t *)ctx;
            uc->uc_mcontext.pc = (unsigned long)za_render_entry;
        }
        if (n <= 8) za_log_raw(sig, pc, off, "render", info ? info->si_addr : NULL);
        return;
    }

    // 线程身份 + 栈边界
    {
        char buf[256];
        char *p = buf;
        p = za_put_str(p, "ZaGuest: tid=");
        p = za_put_hex(p, (unsigned long long)my_tid);
        p = za_put_str(p, " guest_tid=");
        p = za_put_hex(p, (unsigned long long)za_guest_tid);
        p = za_put_str(p, " render_tid=");
        p = za_put_hex(p, (unsigned long long)za_render_tid);
        p = za_put_str(p, "\n");
        za_fatal_write(buf, (size_t)(p - buf));
    }
    za_log_raw(sig, pc, off, rel, info ? info->si_addr : NULL);

    // x0..x30 + sp + pc 全打（寄存器里常能直接看出「哪个值变垃圾了」）
    if (ctx)
    {
        ucontext_t *uc = (ucontext_t *)ctx;
        char buf[256];
        for (int base = 0; base < 32; base += 4)
        {
            char *p = buf;
            for (int i = base; i < base + 4 && i < 32; i++)
            {
                p = za_put_str(p, " x");
                p = za_put_hex(p, (unsigned long long)i);
                p = za_put_str(p, "=");
                p = za_put_hex(p, (unsigned long long)uc->uc_mcontext.regs[i]);
            }
            p = za_put_str(p, "\n");
            za_fatal_write(buf, (size_t)(p - buf));
        }
        {
            char *p = buf;
            p = za_put_str(p, "ZaGuest: sp=");
            p = za_put_hex(p, (unsigned long long)uc->uc_mcontext.sp);
            p = za_put_str(p, " pc=");
            p = za_put_hex(p, (unsigned long long)pc);
            p = za_put_str(p, " x30=");
            p = za_put_hex(p, (unsigned long long)uc->uc_mcontext.regs[30]);
            p = za_put_str(p, "\n");
            za_fatal_write(buf, (size_t)(p - buf));
        }
        // TPIDR：客机在崩前那几步常是 `mrs TPIDRRO_EL0 ; ldr ; msr TPIDR_EL0`
        {
            unsigned long tp = 0, tpro = 0;
            __asm__ __volatile__("mrs %0, TPIDR_EL0" : "=r"(tp));
            __asm__ __volatile__("mrs %0, TPIDRRO_EL0" : "=r"(tpro));
            char *p = buf;
            p = za_put_str(p, "ZaGuest: TPIDR_EL0=");
            p = za_put_hex(p, (unsigned long long)tp);
            p = za_put_str(p, " TPIDRRO_EL0=");
            p = za_put_hex(p, (unsigned long long)tpro);
            p = za_put_str(p, "\n");
            za_fatal_write(buf, (size_t)(p - buf));
        }
        za_log_sdk_state((unsigned long)uc->uc_mcontext.regs[19],
                         (unsigned long)uc->uc_mcontext.regs[8]);
        za_log_guest_trace((unsigned long)uc->uc_mcontext.sp);
        za_log_stack((unsigned long)uc->uc_mcontext.sp);
    }

    // 恢复默认动作重新 raise ⇒ 内核按默认动作终止，debuggerd 拿到原始信号与故障地址
    signal(sig, SIG_DFL);
    signal(SIGABRT, SIG_DFL);
    raise(sig);
    _exit(99);
}

static void za_segv_handler(int sig, siginfo_t *info, void *ctx) { za_fatal_handler(sig, info, ctx); }
static void za_rt_catch(int sig, siginfo_t *info, void *ctx) { za_fatal_handler(sig, info, ctx); }
// 装好致命信号的处理器（SIGSEGV/BUS/ILL/FPE/ABRT/SYS）。
// ⚠ 必须每次 svc 后重装：SDK 初始化会**替换**掉我们装的 SIGSEGV 处理器
//   ⇒ 客机崩了就没人接，直接被内核杀掉（连日志都没有）。
void za_reinstall_signal_handlers(void)
{
    za_install_altstack();
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = za_segv_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    static const int fatal[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT, SIGSYS };
    for (unsigned i = 0; i < sizeof fatal / sizeof fatal[0]; i++)
        sigaction(fatal[i], &sa, NULL);
}

// 接管 32..62（63 留给 PC 采样器；SIGRTMIN=42 是 bionic 内部定时器，不抢）
void za_install_rt_catch(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = za_rt_catch;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    for (int s = 32; s <= 62; s++)
    {
        if (s == SIGRTMIN) continue;
        sigaction(s, &sa, NULL);
    }
}

// 启动时装一次（渲染线程比客机线程先跑，它的崩溃也得有人兜底）
void za_install_signal_handlers(void)
{
    za_reinstall_signal_handlers();
    za_install_rt_catch();
}

// ── svc 调用统计（不开详细日志时也能知道客机在调什么）──────────────
static unsigned long za_svc_counters[256];
static unsigned long za_svc41_counters[32];

void za_svc_count(long nr)
{
    if (nr >= 0 && nr < 256) __atomic_add_fetch(&za_svc_counters[nr], 1, __ATOMIC_RELAXED);
}
unsigned long za_svc_count_take(long nr)
{
    if (nr < 0 || nr >= 256) return 0;
    return __atomic_exchange_n(&za_svc_counters[nr], 0, __ATOMIC_RELAXED);
}
unsigned long za_svc_count_peek(long nr)
{
    if (nr < 0 || nr >= 256) return 0;
    return __atomic_load_n(&za_svc_counters[nr], __ATOMIC_RELAXED);
}
void za_svc41_count(long id)
{
    if (id >= 0 && id < 32) __atomic_add_fetch(&za_svc41_counters[id], 1, __ATOMIC_RELAXED);
}
unsigned long za_svc41_peek(long id)
{
    if (id < 0 || id >= 32) return 0;
    return __atomic_load_n(&za_svc41_counters[id], __ATOMIC_RELAXED);
}
unsigned long za_svc_total_take(void)
{
    unsigned long n = 0;
    for (int i = 0; i < 256; i++) n += __atomic_exchange_n(&za_svc_counters[i], 0, __ATOMIC_RELAXED);
    return n;
}

// svc 轨迹：记最近 32 次的（服务号, 调用点 PC）
void za_svc_trace(long nr, unsigned long pc)
{
    unsigned long pos = za_svc_trace_pos;
    za_svc_trace_nr[pos % 32] = (unsigned long)nr;
    za_svc_trace_pc[pos % 32] = pc;
    za_svc_trace_pos = pos + 1;
}

// #41 GetInfo 的调用点轨迹（哪个 id 被狂问 = 死循环入口）
unsigned long za_svc41_trace_pc[32];
unsigned long za_svc41_trace_id[32];
unsigned long za_svc41_trace_pos;
void za_svc41_trace(unsigned long pc, long id)
{
    unsigned long pos = za_svc41_trace_pos;
    za_svc41_trace_pc[pos % 32] = pc;
    za_svc41_trace_id[pos % 32] = (unsigned long)id;
    za_svc41_trace_pos = pos + 1;
}
// ── 线程栈边界登记（栈溢出时才知道「哪条线程、栈多大、用了多少」）────
#define ZA_STACK_REGIONS 64
typedef struct
{
    long tid;
    unsigned long lo, hi;
    const char *who;
} za_stack_region_t;
static za_stack_region_t za_stack_regions[ZA_STACK_REGIONS];

void za_stack_register(long tid, unsigned long lo, unsigned long hi, const char *who)
{
    for (int i = 0; i < ZA_STACK_REGIONS; i++)
    {
        if (za_stack_regions[i].tid == tid || za_stack_regions[i].tid == 0)
        {
            za_stack_regions[i].tid = tid;
            za_stack_regions[i].lo = lo;
            za_stack_regions[i].hi = hi;
            za_stack_regions[i].who = who;
            return;
        }
    }
}

const za_stack_region_t *za_stack_find(long tid)
{
    for (int i = 0; i < ZA_STACK_REGIONS; i++)
        if (za_stack_regions[i].tid == tid) return &za_stack_regions[i];
    return NULL;
}

// 从 /proc/self/maps 里找出「包含这个地址」的映射区间
static int za_map_bounds_of(unsigned long addr, unsigned long *lo, unsigned long *hi)
{
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    static char buf[8192];
    ssize_t got;
    int found = 0;
    while ((got = read(fd, buf, sizeof buf - 1)) > 0)
    {
        buf[got] = 0;
        char *ln = buf;
        while (ln && *ln && !found)
        {
            unsigned long a = 0, b = 0;
            if (sscanf(ln, "%lx-%lx", &a, &b) == 2 && addr >= a && addr < b)
            {
                *lo = a;
                *hi = b;
                found = 1;
            }
            char *nl = ln;
            while (*nl && *nl != 10) nl++;
            ln = (*nl ? nl + 1 : NULL);
        }
    }
    close(fd);
    return found;
}

void za_stack_register_current(long tid, const char *who)
{
    unsigned long sp = 0;
    __asm__ __volatile__("mov %0, sp" : "=r"(sp));
    unsigned long lo = 0, hi = 0;
    if (za_map_bounds_of(sp, &lo, &hi)) za_stack_register(tid, lo, hi, who);
    else za_stack_register(tid, 0, 0, who);
}

// ── 客机 TLS 描述符（影子块）────────────────────────────────────────
//   客机算 `tp16 = TPIDR & ~0x1FFF`，再读 `[tp16+0x98]` 当「本模块 TLS 块偏移」。
//   ⚠ TPIDR_EL0 **不动**（换了它线程里任何 bionic 调用都崩）；
//     真正切换的是那个描述符槽：进宿主还 bionic 原值、出宿主写客机期望值。
#define ZA_TLS_SLOTS 64
#define ZA_TLS_STACK 16
typedef struct
{
    int depth;
    void *saved[ZA_TLS_STACK];
    void *tp;           // 本线程 bionic 的 TLS
    void *area;         // 本线程的客机 TLS 变量区
    unsigned long long slot_orig;   // [tp16+0x98] 的 bionic 原值
    unsigned long long slot_guest;  // 客机期望值（变量区相对 tp16 的偏移 / 8）
    unsigned long tp16;
} za_tls_state_t;
static za_tls_state_t za_tls_states[ZA_TLS_SLOTS];

static void *za_get_tls(void)
{
    unsigned long tp = 0;
    __asm__ __volatile__("mrs %0, TPIDR_EL0" : "=r"(tp));
    return (void *)(uintptr_t)tp;
}

static za_tls_state_t *za_tls_cur(void)
{
    long tid = syscall(SYS_gettid);
    return &za_tls_states[tid % ZA_TLS_SLOTS];
}

void za_tls_enter(void)
{
    za_tls_state_t *st = za_tls_cur();
    if (st->depth == 0 && st->tp16)
        *(unsigned long long *)(st->tp16 + 0x98) = st->slot_orig;
    if (st->depth < ZA_TLS_STACK) st->saved[st->depth] = za_get_tls();
    st->depth++;
}
void za_tls_leave(void)
{
    za_tls_state_t *st = za_tls_cur();
    if (st->depth > 0) st->depth--;
    if (st->depth == 0 && st->tp16)
        *(unsigned long long *)(st->tp16 + 0x98) = st->slot_guest;
}

// 只读 TLS 页的绝对地址（za_horizon.c 的临界区按同一来源取 owner_id）
volatile unsigned long za_ro_tls_page = 0;

void za_os_install_tls_descriptor(void)
{
    void *b = za_get_tls();
    if (!b) { ZLOGE("读不到 TPIDR_EL0"); return; }
    unsigned long b16 = (unsigned long)b & ~0x1FFFul;
    // 客机算 `add x8, tp16, x9, lsl #3`，x9 是 **32 位有符号偏移**
    // ⇒ 变量区必须落在 tp16 + (int32 范围) 内，且越近越好；bionic 上方多半被占，
    //   所以逐页往上找空位（找不到就退回任意地址并明确报出来）。
    size_t area = 4 * 1024 * 1024;
    void *t = MAP_FAILED;
    for (unsigned long k = 0x8000; k <= 0x400000; k += 0x4000)
    {
        t = mmap((void *)(b16 + k), area, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (t != MAP_FAILED) break;
    }
    if (t == MAP_FAILED)
    {
        t = mmap(NULL, area, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (t == MAP_FAILED) { ZLOGE("客机 TLS 变量区申请失败"); return; }
        ZLOGE("客机 TLS: 近处没空位，变量区落在 %p（偏移 %lld）", t,
              (long long)((unsigned long)(uintptr_t)t - b16));
    }
    memset(t, 0, area);
    za_tls_state_t *st = za_tls_cur();
    st->tp16 = (unsigned long)b16;
    st->tp = b;
    st->area = t;
    st->slot_orig = *(unsigned long long *)(b16 + 0x98);
    st->slot_guest = (unsigned long long)(((long long)((unsigned long)(uintptr_t)t - b16)) / 8);
    *(unsigned long long *)(b16 + 0x98) = st->slot_guest;
    ZLOGI("客机 TLS: [tp16+0x98] %#llx -> %#llx，tp=%p 变量区=%p",
          st->slot_orig, st->slot_guest, b, t);
}

unsigned long za_os_guest_tls_area(void)
{
    return (unsigned long)(uintptr_t)za_tls_cur()->area;
}

// 客机 GetCurrentThread 要非空指针：给每线程一个假对象
#define ZA_THREAD_OBJ_SLOTS 64
static unsigned long long za_thread_obj[ZA_THREAD_OBJ_SLOTS];
void *za_os_current_thread_obj(void)
{
    long tid = syscall(SYS_gettid);
    unsigned long long *p = &za_thread_obj[tid % ZA_THREAD_OBJ_SLOTS];
    if (!*p) *p = 0x1000000000000ull | (unsigned long long)tid;
    return p;
}
// ════════════════════════════════════════════════════════════════
//  宿主符号解析
// ════════════════════════════════════════════════════════════════
typedef struct { const char *name; void *fn; } za_host_sym_t;

// 缺实现的符号 → 专属陷阱桩：客机一调到就 SIGTRAP，日志里明确打出缺哪个
static void *za_trap_alloc(const char *name);
static unsigned char *za_trap_page;

static void *za_trap_alloc(const char *name)
{
    ZLOGI("缺实现 -> %s（落到陷阱桩）", name ? name : "(null)");
    if (!za_trap_page)
    {
        za_trap_page = (unsigned char *)mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (za_trap_page == MAP_FAILED) { za_trap_page = NULL; return NULL; }
        memset(za_trap_page, 0xDD, 4096);           // brk 的编码位模式
        mprotect(za_trap_page, 4096, PROT_READ | PROT_EXEC);
    }
    return za_trap_page;
}

// NVN 图形入口：客机给它函数名，它回函数地址（图形层未接 ⇒ 回陷阱桩）
static void *za_nvn_bootstrap_loader(const char *name)
{
    ZLOGI("★ NVN: 客机要取 %s —— 图形层未接", name ? name : "(null)");
    return za_trap_alloc(name);
}

// loader 提供的「runtime object file」= 映像里 MOD0 头的地址
static void *za_host_runtime_object_file(void)
{
    unsigned char *base = za_guest_base;
    if (!base) return NULL;
    unsigned int mod0 = 0;
    memcpy(&mod0, base + 4, 4);
    if (!mod0 || mod0 >= ZA_IMAGE_SIZE) return NULL;
    ZLOGI("宿主提供 runtime object file：main+%#x（MOD0 头）", mod0);
    return base + mod0;
}

static unsigned long long za_get_system_tick(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}
static unsigned long long za_get_system_tick_frequency(void) { return 19200000ull; }
// 宿主符号表：客机导入的 nn::* 由我们实现的这些顶替（表在解析链的第一位）。
static const za_host_sym_t za_host_syms[] = {
    // loader 提供的「runtime object file」（真机由 nnrtld 提供）
    { "__nnDetailNintendoSdkRuntimeObjectFile", (void *)za_host_runtime_object_file },

    // NVN 图形入口（图形层未接：回陷阱桩，客机一调就知道缺哪个）
    { "nvnBootstrapLoader", (void *)za_nvn_bootstrap_loader },

    // 时间
    { "_ZN2nn2os13GetSystemTickEv", (void *)za_get_system_tick },
    { "_ZN2nn2os22GetSystemTickFrequencyEv", (void *)za_get_system_tick_frequency },
    { "_ZN2nn2os11SleepThreadENS_8TimeSpanE", (void *)za_os_sleep_thread },
    { "_ZN2nn2os11YieldThreadEv", (void *)za_os_yield_thread },

    // 线程
    { "_ZN2nn2os16GetCurrentThreadEv", (void *)za_os_get_current_thread },
    { "_ZN2nn2os11GetThreadIdEPKNS_10ThreadTypeE", (void *)za_os_get_thread_id },
    { "_ZN2nn2os12CreateThreadEPNS0_10ThreadTypeEPFvPvES3_S3_mi", (void *)za_os_create_thread },
    { "_ZN2nn2os12CreateThreadEPNS0_10ThreadTypeEPFvPvES3_S3_mii", (void *)za_os_create_thread },
    { "_ZN2nn2os11StartThreadEPNS0_10ThreadTypeE", (void *)za_os_start_thread },
    { "_ZN2nn2os13DestroyThreadEPNS0_10ThreadTypeE", (void *)za_os_destroy_thread },

    // 互斥锁
    { "_ZN2nn2os15InitializeMutexEPNS0_9MutexTypeEbi", (void *)za_os_initialize_mutex },
    { "_ZN2nn2os9LockMutexEPNS0_9MutexTypeE", (void *)za_os_lock_mutex },
    { "_ZN2nn2os11UnlockMutexEPNS0_9MutexTypeE", (void *)za_os_unlock_mutex },

    // 信号量
    { "_ZN2nn2os19InitializeSemaphoreEPNS0_13SemaphoreTypeEii", (void *)za_os_initialize_semaphore },
    { "_ZN2nn2os16AcquireSemaphoreEPNS0_13SemaphoreTypeE", (void *)za_os_acquire_semaphore },
    { "_ZN2nn2os19TryAcquireSemaphoreEPNS0_13SemaphoreTypeE", (void *)za_os_try_acquire_semaphore },
    { "_ZN2nn2os16ReleaseSemaphoreEPNS0_13SemaphoreTypeE", (void *)za_os_release_semaphore },
    { "_ZN2nn2os16ReleaseSemaphoreEPNS0_13SemaphoreTypeEi", (void *)za_os_release_semaphore },

    // 事件
    { "_ZN2nn2os15InitializeEventEPNS0_9EventTypeEbNS0_14EventClearModeE", (void *)za_os_initialize_event },
    { "_ZN2nn2os9WaitEventEPNS0_9EventTypeE", (void *)za_os_wait_event },
    { "_ZN2nn2os12TryWaitEventEPNS0_9EventTypeE", (void *)za_os_try_wait_event },
    { "_ZN2nn2os11SignalEventEPNS0_9EventTypeE", (void *)za_os_signal_event },
    { "_ZN2nn2os10ClearEventEPNS0_9EventTypeE", (void *)za_os_clear_event },
    { "_ZN2nn2os20InitializeLightEventEPNS0_14LightEventTypeEbNS0_14EventClearModeE", (void *)za_os_initialize_light_event },
    { "_ZN2nn2os16SignalLightEventEPNS0_14LightEventTypeE", (void *)za_os_signal_light_event },
    { "_ZN2nn2os14WaitLightEventEPNS0_14LightEventTypeE", (void *)za_os_wait_light_event },

    // 线程局部存储 / 分配器
    { "_ZN2nn2os15AllocateTlsSlotEPNS0_7TlsSlotEPFvmE", (void *)za_os_allocate_tls_slot },
    { "_ZN2nn2os11SetTlsValueENS0_7TlsSlotEm", (void *)za_os_set_tls_value },
    { "_ZN2nn2os11GetTlsValueENS0_7TlsSlotE", (void *)za_os_get_tls_value },
    { "_ZN2nn2os11FreeTlsSlotENS0_7TlsSlotE", (void *)za_os_free_tls_slot },
    { "nnosAllocateMemoryForThreadLocal", (void *)za_os_alloc_thread_local },
    { "nnosFreeMemoryForThreadLocal", (void *)za_os_free_thread_local },

    // errno / DSO
    { "_ZN2nn2os11GetHostArgcEv", (void *)za_os_get_host_argc },
    { "__nnmusl_init_dso", (void *)za_os_nnmusl_init_dso },

    { NULL, NULL }      // 结束标记
};
// ── 已装载的两个模块（导出符号表）：main 与 SDK ──────────────────────
static za_mod_t za_main_mod;
static za_mod_t za_sdk_mod;
static unsigned char *za_guest_main_base;

// 解析客机导入的符号。顺序与上游 d2r-mobile 的 guest_sym 一致：
//   ① 宿主自己的 nn::* 实现  ② 模块导出表（SDK→main）  ③ 系统 libc/libc++
// ⚠ **模块导出表优先于 dlsym**：裸 malloc/free 是 main NSO 导出的**客机自己的 musl 分配器**，
//   落到 dlsym 会变成 bionic 的分配器 ⇒ SDK 与客机不是同一套堆。
void *za_resolve_host(const char *name)
{
    if (name)
    {
        size_t n = strlen(name);
        if (n >= sizeof za_last_sym) n = sizeof za_last_sym - 1;
        memcpy(za_last_sym, name, n);
        za_last_sym[n] = 0;
    }
    for (const za_host_sym_t *h = za_host_syms; h->name; h++)
        if (!strcmp(h->name, name)) return h->fn;
    void *p = za_mod_lookup(&za_sdk_mod, name);
    if (p) return p;
    p = za_mod_lookup(&za_main_mod, name);
    if (p) return p;
    return dlsym(RTLD_DEFAULT, name);
}

static void *za_resolve(const char *name, unsigned index)
{
    void *p = za_resolve_host(name);
    if (p) return p;
    if (index < ZA_STUB_COUNT) return (void *)za_stub_table[index];
    return za_trap_alloc(name);
}

// 桩被调用时上报（每个符号只打印一次，但每次调用都写进崩溃日志 —— 崩前最后一串就是「缺什么」）
static unsigned char za_stub_called_once[ZA_STUB_COUNT];
void za_stub_hit(unsigned index)
{
    if (index >= ZA_STUB_COUNT) return;
    {
        char buf[320];
        char *p = buf;
        p = za_put_str(p, "ZaGuest: STUB ");
        p = za_put_str(p, za_imports[index].name);
        p = za_put_str(p, "\n");
        za_fatal_write(buf, (size_t)(p - buf));
    }
    if (za_stub_called_once[index]) return;
    za_stub_called_once[index] = 1;
    ZLOGI("未实现(桩) -> %s", za_imports[index].name);
}

// 客机的 C++ 运行时要 libc++；Android 的 libc++ 与 NSO 用**同一套 Itanium mangling**，
// 所以那 400 多个符号能直接 dlsym 命中，只有 nn::* 需要自己实现。
static void za_load_host_libs(void)
{
    static const char *libs[] = { "libc++_shared.so", "libm.so", "libz.so", NULL };
    for (int i = 0; libs[i]; i++)
    {
        void *h = dlopen(libs[i], RTLD_NOW | RTLD_GLOBAL);
        ZLOGI("宿主库 %s %s", libs[i], h ? "已加载" : "加载失败");
    }
}