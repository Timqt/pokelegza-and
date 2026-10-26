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
#include <setjmp.h>
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
// 前置声明：mrs TPIDR_EL0 替换桩的宿主回调（实现在后面）
unsigned long za_tls_mrs_hook(void);
unsigned long za_os_guest_tls_area(void);
// 宿主分配器（fs 分配器桩 + 线程上下文对象 vtable 共用，实现在后面）
void *za_fs_vt_alloc(void *obj, unsigned long size, unsigned long align);
void za_fs_vt_free(void *obj, void *ptr, unsigned long size, unsigned long align);

static char *za_put_str(char *p, const char *s)
{
    while (*s) *p++ = *s++;
    return p;
}

static char *za_put_dec(char *p, unsigned long long v)
{
    char tmp[24];
    int n = 0;
    if (!v) { *p++ = '0'; return p; }
    while (v) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n) *p++ = tmp[--n];
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
// ── Break(svc#38) 现场取证 ─────────────────────────────────────────
//
// 客机 nn::diag::detail::Abort(const nn::Result*) 在 **SDK text+0x9c560**：
//     0x9c560: stp x29,x30,[sp,#-0x10]!
//     0x9c564: mov  x29,sp
//     0x9c568: mov  x1,x0          ← x1 = Result*（断言结果）
//     0x9c56c: mov  w0,wzr         ← x0 = reason = 0（AssertionFailed）
//     0x9c570: mov  w2,#0x4        ← x2 = size = 4
//     0x9c574: bl   0x17018c       ← 那里是**叶子**包装：svc #0x26 ; ret（无栈帧）
//     0x9c578: nop
//
// ⇒ svc 现场（gate 入口）：
//     x30 = 0x9c578            （在 Abort 内部，**不是** Abort 的调用者）
//     sp  = Abort 的栈帧       （gate 改的是包装函数入口，客机 sp 不变）
//     [sp+0] = Abort 保存的 x29 = **调用者的帧指针**
//     [sp+8] = Abort 保存的 x30 = **调用 Abort 的那个函数的返回地址**
//                （= 调用者里 bl 之后那条指令的地址 ⇒ 直接指出是哪个 assert）
//
// 之后按 x29 链往上走：fp=[fp], ret=[fp+8]。
extern volatile unsigned long za_horizon_regs[32];

static void za_dump_break_ctx(void)
{
    char line[256];
    unsigned long sp = za_horizon_regs[9];    // 客机 sp（gate 入口处）
    unsigned long x30 = za_horizon_regs[11];  // 客机 x30
    unsigned long x29 = za_horizon_regs[17];  // 客机 x29
    unsigned long info = za_horizon_regs[1];  // Break 的第 2 参 = nn::Result*
    unsigned long size = za_horizon_regs[2];  // Break 的第 3 参 = 4

    {
        char *p = line;
        p = za_put_str(p, "ZaGuest: break-ctx svc#38 sp=");
        p = za_put_hex(p, sp);
        p = za_put_str(p, " x30=");
        p = za_put_addr(p, x30);
        p = za_put_str(p, " x29=");
        p = za_put_addr(p, x29);
        p = za_put_str(p, " info=");
        p = za_put_hex(p, info);
        p = za_put_str(p, " size=");
        p = za_put_dec(p, size);
        p = za_put_str(p, "\n");
        za_fatal_write(line, (size_t)(p - line));
    }
    if (!sp) return;

    // sp 附近的原始字：sp+0 = Abort 的 x29，sp+8 = Abort 的 x30（= 调用者返回地址）
    for (int i = 0; i <= 4; i++)
    {
        unsigned long w = 0;
        if (!za_read_word(sp + (unsigned long)i * 8, &w)) break;
        char *p = line;
        p = za_put_str(p, "ZaGuest: break-ctx sp+");
        p = za_put_hex(p, (unsigned long long)i * 8);
        p = za_put_str(p, "=");
        p = za_put_addr(p, w);
        p = za_put_str(p, " raw=");
        p = za_put_hex(p, w);
        p = za_put_str(p, "\n");
        za_fatal_write(line, (size_t)(p - line));
    }

    // frame[0] = Abort 的调用者返回地址（[sp+8]），frame 链从 Abort 保存的 x29（[sp+0]）起
    {
        unsigned long fp = 0, ret = 0;
        if (za_read_word(sp + 0, &fp) && za_read_word(sp + 8, &ret))
        {
            char *p = line;
            p = za_put_str(p, "ZaGuest: break-ctx frame[0] ret=");
            p = za_put_addr(p, ret);
            p = za_put_str(p, " fp=");
            p = za_put_addr(p, fp);
            p = za_put_str(p, "\n");
            za_fatal_write(line, (size_t)(p - line));
            // 往上 2~3 层
            for (int i = 1; i <= 6 && fp; i++)
            {
                unsigned long nf = 0, nr = 0;
                if (!za_read_word(fp, &nf)) break;
                if (!za_read_word(fp + 8, &nr)) break;
                p = line;
                p = za_put_str(p, "ZaGuest: break-ctx frame[");
                p = za_put_dec(p, (unsigned long long)i);
                p = za_put_str(p, "] ret=");
                p = za_put_addr(p, nr);
                p = za_put_str(p, " fp=");
                p = za_put_addr(p, nf);
                p = za_put_str(p, "\n");
                za_fatal_write(line, (size_t)(p - line));
                if (!nf || nf <= fp) break;   // 链断
                fp = nf;
            }
        }
    }

    // nn::Result 附近的原始字节（info 指向 4 字节 Result，前后各 32 字节）
    if (info)
    {
        static unsigned char raw[64];
        unsigned long base = info >= 32 ? info - 32 : 0;
        if (za_read_bytes(base, raw, sizeof raw))
        {
            for (int r = 0; r < 4; r++)
            {
                char *p = line;
                p = za_put_str(p, "ZaGuest: break-ctx raw[");
                p = za_put_hex(p, (unsigned long long)(r * 16));
                p = za_put_str(p, "]=");
                for (int k = 0; k < 16; k++)
                {
                    static const char dg[] = "0123456789abcdef";
                    *p++ = dg[raw[r * 16 + k] >> 4];
                    *p++ = dg[raw[r * 16 + k] & 0xF];
                }
                p = za_put_str(p, "\n");
                za_fatal_write(line, (size_t)(p - line));
            }
        }
    }
}

// ── x29 帧链遍历（AAPCS64）──────────────────────────────────────────
// 每个帧：[x29+0]=上一层的 x29，[x29+8]=上一层的 x30（返回地址）。
// 沿链走就是精确调用序列 —— 这是唯一能区分「真返回地址」和「栈上垃圾」的办法。
// 之前只做「sp 往上扫客机地址」，混进大量数据/局部变量，据此推理连错三轮。
static void za_dump_fp_chain(unsigned long fp, unsigned long pc, unsigned long sp)
{
    char line[256];
    {
        char *p = line;
        p = za_put_str(p, "ZaGuest: fp-chain enter fp=");
        p = za_put_hex(p, (unsigned long long)fp);
        p = za_put_str(p, " sp=");
        p = za_put_hex(p, (unsigned long long)sp);
        p = za_put_str(p, "\n");
        za_fatal_write(line, (size_t)(p - line));
    }
    // 先报当前 PC（abort 现场本身）
    {
        char *p = line;
        unsigned long bm = (unsigned long)za_guest_base, sm = za_sdk_base;
        if (sm && pc >= sm && pc < sm + za_sdk_size)
        {
            p = za_put_str(p, "ZaGuest:   frame[00] pc sdk+");
            p = za_put_hex(p, (unsigned long long)(pc - sm));
        }
        else if (bm && pc >= bm && pc < bm + ZA_IMAGE_SIZE)
        {
            p = za_put_str(p, "ZaGuest:   frame[00] pc main+");
            p = za_put_hex(p, (unsigned long long)(pc - bm));
        }
        else
        {
            p = za_put_str(p, "ZaGuest:   frame[00] pc outside");
            p = za_put_hex(p, (unsigned long long)pc);
        }
        p = za_put_str(p, "\n");
        za_fatal_write(line, (size_t)(p - line));
    }

    unsigned long bm = (unsigned long)za_guest_base, sm = za_sdk_base;
    for (int i = 1; i <= 24; i++)
    {
        // 帧指针必须 16 字节对齐、且在栈区里，否则视为链断
        if (!fp || (fp & 0xF) || (sp && fp < sp - 0x10000)) break;
        unsigned long next_fp = 0, ret = 0;
        if (!za_read_word(fp, &next_fp)) break;
        if (!za_read_word(fp + 8, &ret)) break;
        // next_fp 必须递增且对齐，否则链坏
        if (next_fp && (next_fp & 0xF)) break;
        if (next_fp && next_fp <= fp) break;

        char *p = line;
        p = za_put_str(p, "ZaGuest:   frame[");
        p = za_put_dec(p, (unsigned long long)i);
        p = za_put_str(p, "] ret=");
        if (sm && ret >= sm && ret < sm + za_sdk_size)
        {
            p = za_put_str(p, "sdk+");
            p = za_put_hex(p, (unsigned long long)(ret - sm));
        }
        else if (bm && ret >= bm && ret < bm + ZA_IMAGE_SIZE)
        {
            p = za_put_str(p, "main+");
            p = za_put_hex(p, (unsigned long long)(ret - bm));
        }
        else
        {
            p = za_put_hex(p, (unsigned long long)ret);
        }
        p = za_put_str(p, "  fp=");
        p = za_put_hex(p, (unsigned long long)next_fp);
        p = za_put_str(p, "\n");
        za_fatal_write(line, (size_t)(p - line));
        fp = next_fp;
    }
}

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
        unsigned long long ro = (unsigned long long)za_os_tls_ro_area(), self = 0;
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
        unsigned long long ro = (unsigned long long)za_os_tls_ro_area();
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

// 帧快照（定义在 za_horizon.c）：0x14457c 三条 svc 时刻的整帧内容
#define ZA_SNAP_N 18
extern volatile unsigned long za_frame_snap[4][ZA_SNAP_N];
extern volatile unsigned long za_frame_snap_pc[4];
extern volatile unsigned long za_frame_snap_sp[4];
extern volatile int za_frame_snap_n;
static void za_dump_frame_snap(void)
{
    char line[320];
    int n = za_frame_snap_n;
    {
        char *p = line;
        p = za_put_str(p, "ZaGuest: frame-snap n=");
        p = za_put_dec(p, (unsigned long long)n);
        p = za_put_str(p, " (each = whole 0x14457c frame, idx3=sp0+0x18 x30=idx9)\n");
        za_fatal_write(line, (size_t)(p - line));
    }
    for (int k = 0; k < n && k < 4; k++)
    {
        char *p = line;
        p = za_put_str(p, "ZaGuest:  snap#");
        p = za_put_dec(p, (unsigned long long)k);
        p = za_put_str(p, " pc=");
        p = za_put_hex(p, (unsigned long long)za_frame_snap_pc[k]);
        p = za_put_str(p, " sp0=");
        p = za_put_hex(p, (unsigned long long)za_frame_snap_sp[k]);
        p = za_put_str(p, "\n");
        za_fatal_write(line, (size_t)(p - line));
        for (int i = 0; i < ZA_SNAP_N; i += 4)
        {
            char *q = line;
            q = za_put_str(q, "ZaGuest:    +");
            q = za_put_hex(q, (unsigned long long)(i * 8));
            q = za_put_str(q, ":");
            for (int j = i; j < i + 4 && j < ZA_SNAP_N; j++)
            {
                q = za_put_str(q, " ");
                q = za_put_hex(q, (unsigned long long)za_frame_snap[k][j]);
            }
            q = za_put_str(q, "\n");
            za_fatal_write(line, (size_t)(q - line));
        }
    }
}

// 崩溃时倒出 svc 轨迹（定义在后面）
void za_dump_svc_trace(void);
// 客机 PC 采样环形轨迹（定义在后面；fatal handler 在它之前）
#define ZA_PC_RING 16
volatile unsigned long za_disp_count;   // svc 派发计数（看门狗判卡死用）
void za_disp_count_bump(void) { za_disp_count++; }
volatile unsigned long za_pc_ring[ZA_PC_RING];
extern volatile unsigned long za_pc_ring_pos;
static void za_dump_pc_ring(void)
{
    char line[256];
    unsigned long pos = za_pc_ring_pos;
    {
        char *p = line;
        p = za_put_str(p, "ZaGuest: pc-ring total=");
        p = za_put_dec(p, (unsigned long long)pos);
        p = za_put_str(p, " (newest first)\n");
        za_fatal_write(line, (size_t)(p - line));
    }
    unsigned long n = pos < ZA_PC_RING ? pos : ZA_PC_RING;
    for (unsigned long k = 1; k <= n; k++)
    {
        unsigned long pc = za_pc_ring[(pos - k) % ZA_PC_RING];
        const char *tag = "?";
        unsigned long off = pc;
        if (za_sdk_base && pc >= za_sdk_base) { off = pc - za_sdk_base; tag = "sdk"; }
        else if (za_guest_base && pc >= (unsigned long)za_guest_base)
        { off = pc - (unsigned long)za_guest_base; tag = "main"; }
        char *p = line;
        p = za_put_str(p, "ZaGuest:   pc ");
        p = za_put_str(p, tag);
        p = za_put_str(p, "+");
        p = za_put_hex(p, (unsigned long long)off);
        p = za_put_str(p, "\n");
        za_fatal_write(line, (size_t)(p - line));
    }
}
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
// dump 里会解引用寄存器里的值（fp、x0 对象…）。栈被破坏时这些值是垃圾，
// dump 自己就会二次 fault —— 以前实测：SIGBUS 现场 fp/ x29 是 ASCII 文本，
// 打 FRAME0 时再次 SIGSEGV，日志戛然而止，后面的 svc 轨迹全丢。
// ⇒ 用 siglongjmp 兜住：嵌套 fault 时放弃剩余 dump，继续走原信号收尾。
static sigjmp_buf za_fatal_jmp;
static volatile sig_atomic_t za_fatal_dumping;

// 「像不像一个用户态地址」：dump 前的廉价检查（8 对齐 + 47 位内）
static int za_va_plausible(unsigned long v)
{
    return (v & 7) == 0 && v >= 0x10000ul && v < 0x800000000000ul;
}

static void za_fatal_handler(int sig, siginfo_t *info, void *ctx)
{
    if (za_fatal_dumping) siglongjmp(za_fatal_jmp, 1);   // dump 中二次 fault
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
                p = za_put_dec(p, (unsigned long long)i);
                p = za_put_str(p, "=");
                p = za_put_hex(p, (unsigned long long)uc->uc_mcontext.regs[i]);
            }
            p = za_put_str(p, "\n");
            za_fatal_write(buf, (size_t)(p - buf));
        }
        // ★ 崩在**宿主**代码里时，pc 不在 main/sdk 映像里 —— 用 dladdr 把
        //   函数名解出来（否则只会看到一个 0x6d… 的裸地址）。信号安全上
        //   dladdr 不是严格 AS-safe，但实测可用，而且是纯诊断用途。
        {
            int in_guest = 0;
            extern unsigned char *za_guest_base;
            extern volatile unsigned long za_sdk_base, za_sdk_size;
            if (za_guest_base && pc >= (unsigned long)za_guest_base &&
                pc < (unsigned long)za_guest_base + ZA_IMAGE_SIZE) in_guest = 1;
            if (za_sdk_base && pc >= za_sdk_base && pc < za_sdk_base + za_sdk_size) in_guest = 1;
            if (!in_guest)
            {
                Dl_info di;
                memset(&di, 0, sizeof di);
                if (dladdr((void *)pc, &di))
                {
                    unsigned long off = di.dli_saddr ? (unsigned long)(pc - (unsigned long)di.dli_saddr)
                                                     : (unsigned long)(pc - (unsigned long)di.dli_fbase);
                    ZLOGE("ZaGuest: 宿主崩溃 pc=%p = %s+%#lx（模块 %s，模块内偏移 %#lx）",
                          (void *)pc, di.dli_sname ? di.dli_sname : "?", off,
                          di.dli_fname ? di.dli_fname : "?", 
                          (unsigned long)(pc - (unsigned long)di.dli_fbase));
                }
                else
                {
                    ZLOGE("ZaGuest: 宿主崩溃 pc=%p（dladdr 无符号）", (void *)pc);
                }
            }
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
        // ★ GetApplicationFunctions 补丁现场回读：pc 崩在 SDK+0x349e4x 一带时，
        //   直接看补丁是否还活着（0x1c61c0 的 4 条指令 / GOT 槽 / 全局）。
        {
            extern volatile unsigned long za_sdk_base;
            if (za_sdk_base)
            {
                unsigned long long b = za_sdk_base;
                const unsigned int *fn = (const unsigned int *)(b + 0x1c61c0);
                const unsigned long long *got = (const unsigned long long *)(b + 0xb7cb90);
                const unsigned long long *g = (const unsigned long long *)(b + 0xbaca10);
                char *p = buf;
                p = za_put_str(p, "ZaGuest: AMFN fn=");
                p = za_put_hex(p, fn[0]); p = za_put_str(p, " ");
                p = za_put_hex(p, fn[1]); p = za_put_str(p, " ");
                p = za_put_hex(p, fn[2]); p = za_put_str(p, " ");
                p = za_put_hex(p, fn[3]);
                p = za_put_str(p, " got=");
                p = za_put_hex(p, *got);
                p = za_put_str(p, " global=");
                p = za_put_hex(p, *g);
                p = za_put_str(p, "\n");
                za_fatal_write(buf, (size_t)(p - buf));
            }
        }
        // 从这里开始全是「解引用寄存器」的危险 dump：二次 fault 就放弃剩余部分。
        za_fatal_dumping = 1;
        if (sigsetjmp(za_fatal_jmp, 1) != 0)
        {
            static const char ab[] = "ZaGuest: (dump aborted: nested fault)\n";
            za_fatal_write(ab, sizeof ab - 1);
            za_fatal_dumping = 0;
        }
        else
        {
        // ★ 帧内保存的寄存器：fp 往前 0x40 字节（读函数入参/局部）
        {
            unsigned long long fp = (unsigned long long)uc->uc_mcontext.regs[29];
            if (!za_va_plausible(fp)) fp = 0;      // 栈被破坏时 fp 常是 ASCII 文本
            for (int f = 0; f < 2 && fp; f++)
            {
                char *q = buf;
                q = za_put_str(q, "ZaGuest: FRAME");
                q = za_put_dec(q, f);
                q = za_put_str(q, "=");
                for (int i = 0; i < 8; i++)
                {
                    q = za_put_str(q, " ");
                    q = za_put_hex(q, *(unsigned long long *)(uintptr_t)(fp + i * 8));
                }
                q = za_put_str(q, "\n");
                za_fatal_write(buf, (size_t)(q - buf));
                unsigned long long nfp = *(unsigned long long *)(uintptr_t)fp;
                if (nfp <= fp) break;
                fp = nfp;
            }
        }
        // ★ 通用：x0 指向 SDK bss 时 dump 该对象（nvn 堆结构等就在这里）。
        {
            unsigned long long x0v = (unsigned long long)uc->uc_mcontext.regs[0];
            if (za_sdk_base && x0v >= za_sdk_base && x0v < za_sdk_base + za_sdk_size)
            {
                for (int i = 0; i < 32; i++)
                {
                    char *q = buf;
                    q = za_put_str(q, "ZaGuest: X0OBJ[+");
                    q = za_put_hex(q, (unsigned long long)(i * 8));
                    q = za_put_str(q, "]=");
                    q = za_put_hex(q, *(unsigned long long *)(uintptr_t)(x0v + i * 8));
                    q = za_put_str(q, "\n");
                    za_fatal_write(buf, (size_t)(q - buf));
                }
                ZLOGI("  (x0 对象偏移 = sdk+%#llx)", x0v - za_sdk_base);
            }
        }
        // ★ main 的 fs 分配器对象现场（0x3de4b90）+ 它的 vtable（0x3af0ac8）。
        //   实测崩溃：vtable+0x10 = 0x20 ⇒ br 0x20。看运行时表里到底是什么。
        {
            extern unsigned char *za_guest_base;
            if (za_guest_base)
            {
                unsigned long long obj = (unsigned long long)(uintptr_t)za_guest_base + 0x3de4b90ull;
                unsigned long long vt = 0;
                memcpy(&vt, (void *)(uintptr_t)obj, 8);
                char *p2 = buf;
                p2 = za_put_str(p2, "ZaGuest: MAIN obj=");
                p2 = za_put_hex(p2, *(unsigned long long *)(uintptr_t)obj);
                p2 = za_put_str(p2, " obj+8=");
                p2 = za_put_hex(p2, *(unsigned long long *)(uintptr_t)(obj + 8));
                p2 = za_put_str(p2, "\n");
                za_fatal_write(buf, (size_t)(p2 - buf));
                if (vt >= (unsigned long long)(uintptr_t)za_guest_base &&
                    vt < (unsigned long long)(uintptr_t)za_guest_base + ZA_IMAGE_SIZE)
                {
                    unsigned long long o = vt - (unsigned long long)(uintptr_t)za_guest_base;
                    for (int i = 0; i < 6; i++)
                    {
                        char *q = buf;
                        q = za_put_str(q, "ZaGuest: MAIN vt[");
                        q = za_put_dec(q, i);
                        q = za_put_str(q, "]=");
                        q = za_put_hex(q, *(unsigned long long *)(uintptr_t)(vt + i * 8));
                        q = za_put_str(q, "\n");
                        za_fatal_write(buf, (size_t)(q - buf));
                    }
                    ZLOGI("  (vtable 偏移 = main+%#llx)", o);
                }
                else
                {
                    ZLOGE("  MAIN obj[0] = %#llx（不在 main 映像内！）", vt);
                }
            }
        }
        za_log_sdk_state((unsigned long)uc->uc_mcontext.regs[19],
                         (unsigned long)uc->uc_mcontext.regs[8]);
        // svc 轨迹：崩溃前最后几次 svc 的服务号 + 调用点 PC + 寄存器
        za_dump_svc_trace();
        // 客机 PC 采样轨迹：崩溃前最后若干条真实执行地址
        za_dump_pc_ring();
        // 帧快照：0x14457c 三条 svc 各自时刻的整帧
        za_dump_frame_snap();
        // x29 帧链：精确调用序列（优先看这个，不要看下面 sp 扫描的混合值）
        za_dump_fp_chain((unsigned long)uc->uc_mcontext.regs[29],
                         (unsigned long)pc,
                         (unsigned long)uc->uc_mcontext.sp);
        za_log_guest_trace((unsigned long)uc->uc_mcontext.sp);
        za_log_stack((unsigned long)uc->uc_mcontext.sp);
        za_fatal_dumping = 0;
        }
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
    // ★ svc#38 = Horizon Break：客机断言（nn::diag::detail::Abort）走这条路。
    //   每次 svc 都会经过这里（za_horizon.c 的分派体里），所以能拿到**第一现场**：
    //   客机 sp / x30，以及 [sp+8] = 调用 Abort 的那个函数的返回地址。
    if (nr == 38)
    {
        static int n = 0;
        if (n < 3) { n++; za_dump_break_ctx(); }   // 客机可能反复 Abort，只打前 3 次
    }
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
// 另记 x0/x2（第 1/3 参）与 x19（callee-saved）—— 崩溃点几乎总是紧跟在
// 某条 svc 之后（客机在 svc 前把状态准备好，返回后立刻用它去跳转），
// 只有记下这条 svc 的现场，才能把「svc 返回了什么」和「客机拿它干了什么」对上。
unsigned long za_svc_trace_arg0[32];
unsigned long za_svc_trace_arg2[32];
unsigned long za_svc_trace_x19[32];
unsigned long za_svc_trace_sp[32];
unsigned long za_svc_trace_retv[32];
// 回填最近一次 svc 的返回值（由 za_horizon.c 在分派返回后调用）
void za_svc_trace_ret(long r)
{
    unsigned long pos = za_svc_trace_pos;
    if (!pos) return;
    za_svc_trace_retv[(pos - 1) % 32] = (unsigned long)r;
}
void za_svc_trace_rich(long nr, unsigned long pc,
                       unsigned long a0, unsigned long a2, unsigned long x19)
{
    unsigned long pos = za_svc_trace_pos;
    unsigned long i = pos % 32;
    za_svc_trace_nr[i] = (unsigned long)nr;
    za_svc_trace_pc[i] = pc;
    za_svc_trace_arg0[i] = a0;
    za_svc_trace_arg2[i] = a2;
    za_svc_trace_x19[i] = x19;
    za_svc_trace_sp[i] = (unsigned long)za_horizon_guest_sp();
    za_svc_trace_pos = pos + 1;
}
void za_svc_trace(long nr, unsigned long pc)
{
    za_svc_trace_rich(nr, pc, 0, 0, 0);
}
// 崩溃时倒出 svc 轨迹（由新到旧）。这是定位「最后一步」最直接的证据。
void za_dump_svc_trace(void)
{
    char line[256];
    unsigned long pos = __atomic_load_n(&za_svc_trace_pos, __ATOMIC_RELAXED);
    {
        char *p = line;
        p = za_put_str(p, "ZaGuest: svc-trace total=");
        p = za_put_dec(p, (unsigned long long)pos);
        p = za_put_str(p, " (newest first, nr pc x0 x2 x19)\n");
        za_fatal_write(line, (size_t)(p - line));
    }
    unsigned long n = pos < 32 ? pos : 32;
    for (unsigned long k = 1; k <= n; k++)
    {
        unsigned long i = (pos - k) % 32;
        char *p = line;
        p = za_put_str(p, "ZaGuest:   svc#");
        p = za_put_dec(p, (unsigned long long)za_svc_trace_nr[i]);
        p = za_put_str(p, " pc=");
        p = za_put_hex(p, (unsigned long long)za_svc_trace_pc[i]);
        p = za_put_str(p, " x0=");
        p = za_put_hex(p, (unsigned long long)za_svc_trace_arg0[i]);
        p = za_put_str(p, " x2=");
        p = za_put_hex(p, (unsigned long long)za_svc_trace_arg2[i]);
        p = za_put_str(p, " x19=");
        p = za_put_hex(p, (unsigned long long)za_svc_trace_x19[i]);
        p = za_put_str(p, " sp=");
        p = za_put_hex(p, (unsigned long long)za_svc_trace_sp[i]);
        p = za_put_str(p, " ret=");
        p = za_put_hex(p, (unsigned long long)za_svc_trace_retv[i]);
        p = za_put_str(p, "\n");
        za_fatal_write(line, (size_t)(p - line));
    }
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
// za_stack_region_t 由 za_guest_api.h 提供，这里只放存储
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
    long tid;           // 归属线程（0 = 槽位空闲）
    void *ro;           // 本线程的只读 TLS 页（TPIDRRO 语义 + CMIF 应答缓冲）
} za_tls_state_t;
static za_tls_state_t za_tls_states[ZA_TLS_SLOTS];

static void *za_get_tls(void)
{
    unsigned long tp = 0;
    __asm__ __volatile__("mrs %0, TPIDR_EL0" : "=r"(tp));
    return (void *)(uintptr_t)tp;
}

// 按 tid 认领固定槽位：不能只用 tid % 64，否则两个线程会共用一份
// state（tp16/area/slot_guest 全是另一个线程的）⇒ mrs 桩算出别人的 TLS 区。
static za_tls_state_t *za_tls_cur(void)
{
    long tid = syscall(SYS_gettid);
    unsigned idx = (unsigned)tid % ZA_TLS_SLOTS;
    if (za_tls_states[idx].tid == tid) return &za_tls_states[idx];
    for (unsigned i = 0; i < ZA_TLS_SLOTS; i++)
        if (za_tls_states[i].tid == tid) return &za_tls_states[i];
    for (unsigned i = 0; i < ZA_TLS_SLOTS; i++)
    {
        long expect = 0;
        if (__atomic_compare_exchange_n(&za_tls_states[i].tid, &expect, tid, 0,
                                        __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
            return &za_tls_states[i];
    }
    return &za_tls_states[idx];   // 线程数超过槽位：退回取模槽（可能互相干扰）
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
// za_ro_tls_page 由 za_sdk.c 定义并写入（SDK 装载时填真实页地址）
extern volatile unsigned long za_ro_tls_page;

void za_os_install_tls_descriptor(void)
{
    za_tls_state_t *st_chk = za_tls_cur();
    if (st_chk->tp16) return;            // 本线程已装过（幂等）
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

    // ── 每线程的只读 TLS 页（TPIDRRO 语义）────────────────────────────
    // 布局（从 SDK 的 123 处用法反推）：
    //   +0x100/+0x102/+0x104 = 本线程 busy 标记（CriticalSection 忙等协议）
    //   +0x1e0 / +0x20 / +0x70… = 指向「本线程结构」的指针
    //   +0x1f0 = 本线程 TPIDR_EL0（SDK 线程入口会 `msr tpidr_el0, [ro+0x1f0]`）
    //   +0x1f8 = 本线程对象（SDK 线程入口写入 ThreadType*）
    // ★ 这一页同时是 **CMIF IPC 的应答缓冲**（内核写 [ro+槽位]）⇒ 必须每线程一份。
    {
        unsigned char *ro  = (unsigned char *)t + 0x300000;
        unsigned char *ro2 = (unsigned char *)t + 0x301000;
        unsigned long long p2 = (unsigned long long)(uintptr_t)ro2;
        static const int ptr_slots[] = { 0x00, 0x20, 0x70, 0x78, 0x80, 0x1e0, 0x1f8 };
        for (unsigned i = 0; i < sizeof ptr_slots / sizeof ptr_slots[0]; i++)
            *(unsigned long long *)(ro + ptr_slots[i]) = p2;
        *(unsigned long long *)(ro + 0x1f0) = (unsigned long long)(uintptr_t)b;
        // owner_id 必须非 0，且要和 svc#37 GetThreadId 同源（用宿主 tid 目前自洽）
        *(unsigned int *)(ro2 + 0x1b0) = (unsigned int)syscall(SYS_gettid);
        st->ro = ro;
    }
    ZLOGI("客机 TLS: [tp16+0x98] %#llx -> %#llx，tp=%p 变量区=%p RO页=%p",
          st->slot_orig, st->slot_guest, b, t, st->ro);
}

unsigned long za_os_guest_tls_area(void)
{
    return (unsigned long)(uintptr_t)za_tls_cur()->area;
}

// TPIDRRO_EL0 的每线程替代：SDK 的 123 处站点经桩调到这里。
unsigned long za_os_tls_ro_area(void)
{
    return (unsigned long)(uintptr_t)za_tls_cur()->ro;
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
    // ★ 2026-10-26：**不再接管 CreateThread/StartThread/DestroyThread**。
    //   接管掉它们等于跳过 SDK 的 ThreadType 状态机 ⇒ SDK 自己的线程入口/临界区
    //   读到未初始化的 ThreadType，实测在新线程里触发 nn::diag abort（无消息）。
    //   正确分层：SDK 实现 nn::os，我们只提供 svc#8/svc#9（CreateThread/StartThread）。
    //   保留 GetCurrentThread / GetThreadId 的宿主实现（返回非空对象，成本低）。
    { "_ZN2nn2os16GetCurrentThreadEv", (void *)za_os_get_current_thread },
    { "_ZN2nn2os11GetThreadIdEPKNS_10ThreadTypeE", (void *)za_os_get_thread_id },

    // 互斥锁
    // ★ 2026-10-26：**不再接管** mutex。SDK 的 mutex 是纯用户态实现
    //   （InitializeMutex 只初始化结构体；Lock/Unlock 走 SDK 自己的临界区，
    //    争用才用 svc#26/27 + svc#52/53 —— 这几个我们已经实现）。
    //   接管掉 LockMutex 会让 SDK 的 MutexType 状态对不上，随后 SDK 的
    //   WaitConditionVariable 里 `mutex->owner == [tpidrro+0x1f8]` 必然失败 ⇒ abort。
    //   （实测 abort 链：main+0x1bab754 → sdk+0x1387f0 WaitConditionVariable → assert）

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
// ════════════════════════════════════════════════════════════════
//  映像映射与重定位
// ════════════════════════════════════════════════════════════════

// 映射客机映像到固定基址 0x100000000（客机代码里硬编码，不能换）。
// 映射范围除映像本身外，还要留：
//   · 客机 TLS 描述符区 + 变量区（见 za_tls_patch.h）
//   · mrs TPIDR_EL0 的替换桩区（见 za_tls_mrs_blob.h）
//
// ⚠ 整块先按可读写映射（GOT 在 .data 里、装载时要写），text/rodata 的只读权限等重定位做完再收紧。
int za_guest_map(const unsigned char *text, const unsigned char *rodata,
                 const unsigned char *data_seg, size_t bss, unsigned char **out_base)
{
    if (!text || !rodata || !data_seg || !out_base) return -1;
    size_t page = 4096;
    size_t total = ZA_DATA_OFF + ZA_DATA_SIZE + bss;
    size_t tls_end = ZA_TLS_VAR_OFF + ZA_TLS_VAR_SIZE;
    if (tls_end > total) total = tls_end;
    size_t stub_end = ZA_TLS_HOOK_SLOT + 8;
    if (stub_end > total) total = stub_end;
    size_t mapped = (total + page - 1) & ~(page - 1);

    void *want = (void *)ZA_GUEST_BASE_ADDR;
    unsigned char *base = (unsigned char *)mmap(want, mapped, PROT_READ | PROT_WRITE,
                                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (base == MAP_FAILED || base != want)
    {
        // 固定地址拿不到就退回随机地址（客机里的硬编码常量会错，但至少能跑起来看日志）
        base = (unsigned char *)mmap(NULL, mapped, PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (base == MAP_FAILED) { ZLOGE("客机映像映射失败"); return -1; }
        ZLOGE("客机映像没能映射到 %#lx（实际 %p），硬编码地址会错", ZA_GUEST_BASE_ADDR, (void *)base);
    }
    memcpy(base + ZA_TEXT_OFF, text, ZA_TEXT_SIZE);
    memcpy(base + ZA_RODATA_OFF, rodata, ZA_RODATA_SIZE);
    memcpy(base + ZA_DATA_OFF, data_seg, ZA_DATA_SIZE);
    memset(base + ZA_DATA_OFF + ZA_DATA_SIZE, 0, bss);

    za_guest_base = base;

    // TLS helper 改写：`mrs Xt,TPIDR_EL0 / ubfm|and` → `adrp Xt,<描述符区> / nop`
    // （这批表由 tools/patch_tls_helpers.py 生成，4756 条：ubfm 697 + and 4059）
    {
        unsigned int n = 0;
        for (unsigned i = 0; i < ZA_TLS_PATCH_COUNT; i++)
        {
            unsigned int *at = (unsigned int *)(base + za_tls_patches[i].off);
            *at = za_tls_patches[i].w0;
            *(unsigned int *)(base + za_tls_patches[i].off + 4) = za_tls_patches[i].w1;
            n++;
        }
        // ★★ 描述符槽必须写：(改写后的 helper 算的是) P + [P+0x98]*8，
        //    所以 [P+0x98] 必须是 (V-P)/8 = 0x2000。之前这个写入丢了 ⇒
        //    helper 站点算出的「TLS 区」变成描述符页 P 本身（不是变量区 V），
        //    与 mrs 桩（返回 V）不一致，且 P 被当对象用时全是 0。
        *(unsigned long long *)(base + ZA_TLS_DESC_OFF + 0x98) =
            (unsigned long long)((ZA_TLS_VAR_OFF - ZA_TLS_DESC_OFF) / 8);
        // ★ 有些站点把「TPIDR & ~0x1FFF」（改写后 = P）当**线程上下文对象**：
        //     mrs x8 ; and ; ... ; str x8,[obj+8]      ← 存的是这个指针
        //     之后 ldr x8,[ctx] ; ldr x8,[x8,#0x10] ; blr x8
        //   实测回调语义 = Allocate(size,align)（main+0x1a09d58，崩在 pc=0x10）。
        //   ⇒ 给 P 一个最小 vtable：槽 2 = 宿主 Allocate，槽 3 = 宿主 Free。
        {
            unsigned long long *vt = (unsigned long long *)(base + ZA_TLS_DESC_OFF + 0x1000);
            vt[2] = (unsigned long long)(uintptr_t)&za_fs_vt_alloc;
            vt[3] = (unsigned long long)(uintptr_t)&za_fs_vt_free;
            *(unsigned long long *)(base + ZA_TLS_DESC_OFF) = (unsigned long long)(uintptr_t)vt;
        }
        ZLOGI("客机 TLS: 改写 %u 个 helper，描述符区=%#x（+0x98=%#llx）变量区=%#x；"
              "上下文 vtable=%#x",
              n, (unsigned)ZA_TLS_DESC_OFF,
              *(unsigned long long *)(base + ZA_TLS_DESC_OFF + 0x98),
              (unsigned)ZA_TLS_VAR_OFF, (unsigned)(ZA_TLS_DESC_OFF + 0x1000));
    }

    // mrs TPIDR_EL0 全量替换：`b <桩>`，桩里内联算线程 TLS 基址（10,193 条）：
    //    mrs x16,tpidr ; and ~0x1FFF ; ldr x17,[x16,#0x98] ; add x16,x16,x17,lsl3
    // ⚠ 桩内联、**不调用 C 函数**：调 C 会按 AAPCS 改掉 x0–x17，而 mrs 只写目标寄存器。
    {
        memcpy(base + ZA_TLS_STUB_OFF, za_tls_mrs_blob, (size_t)ZA_TLS_STUB_SIZE);
        // 桩区末尾这格只作为映射上界标记（本版桩不再从这里取回调）
        *(unsigned long long *)(base + ZA_TLS_HOOK_SLOT) = (unsigned long long)(uintptr_t)za_tls_mrs_hook;
        // ★ 桩区必须可执行！它在文件映像（bss 末 0x5f7a000）之外、初始 mmap 是
        //   RW ⇒ 不收紧就是 NX ⇒ mrs 替换点第一次执行就 SIGSEGV（pc=桩地址）。
        //   实测：main+0x16526E0 的 TLS 桩 0x602E3B4，boot 首次跑到就崩。
        mprotect(base + ZA_TLS_STUB_OFF, (ZA_TLS_HOOK_SLOT + 8 - ZA_TLS_STUB_OFF + 0xFFF) & ~0xFFFull,
                 PROT_READ | PROT_EXEC);
        unsigned int patched = 0;
        for (unsigned i = 0; i < ZA_TLS_MRS_COUNT; i++)
        {
            const za_tls_mrs_t *e = &za_tls_mrs[i];
            if (e->off + 4 > ZA_TEXT_SIZE) continue;
            unsigned int *at = (unsigned int *)(base + e->off);
            if (*at != e->orig) continue;                 // 只改原字节仍匹配的
            long long delta = (long long)e->stub - (long long)e->off;
            if (delta < -(1LL << 27) || delta >= (1LL << 27)) continue;
            *at = 0x14000000u | (unsigned int)((delta >> 2) & 0x3FFFFFF);
            patched++;
        }
        ZLOGI("TLS mrs 改写：%u / %u 条已替换（桩区 %#x..%#x）",
              patched, (unsigned)ZA_TLS_MRS_COUNT,
              (unsigned)ZA_TLS_STUB_OFF, (unsigned)(ZA_TLS_STUB_OFF + ZA_TLS_STUB_SIZE));
        // ★ 指令缓存维护：ARM64 上「写了指令再执行」必须显式 IC 维护，
        //   否则 I-cache 可能还是旧内容 ⇒ 补丁随机不生效（与 za_sdk.c 同理）。
        __builtin___clear_cache((char *)base, (char *)base + ZA_TEXT_SIZE);
        __builtin___clear_cache((char *)base + ZA_TLS_STUB_OFF,
                                (char *)base + ZA_TLS_STUB_OFF + ZA_TLS_STUB_SIZE);
    }

    *out_base = base;
    return 0;
}
// mrs TPIDR_EL0 替换桩的宿主回调：返回本线程的客机 TLS 基址。
// 桩里是 `adrp x16,<桩区>; ldr x16,[x16,#off]; blr x16; mov xN,x0`，
// 所以这里返回什么，客机的 `mrs TPIDR_EL0` 就得到什么。
// ⚠ 本函数不能依赖 TPIDR_EL0（此时它还可能是 bionic 的）；
//   za_tls_cur() 用 syscall(SYS_gettid)，符合要求。
unsigned long za_os_guest_tls_area(void);   // 前置声明（定义在后面）

unsigned long za_tls_mrs_hook(void)
{
    return za_os_guest_tls_area();
}

// fs 模块的宿主分配器（main 的 fs 分配器桩被劫持到这里）。
// 客机与本进程同地址空间 ⇒ 宿主堆内存客机可直接读写。
void *za_fs_alloc_host(unsigned long size)
{
    return malloc((size_t)size);
}
void za_fs_free_host(void *p)
{
    free(p);
}

// 同一个分配器的 **vtable 版本**（首参是分配器对象）。
//   Allocate(x0=obj, x1=size, x2=align)
//   Free    (x0=obj, x1=ptr,  x2=size, x3=align)
// 游戏里的 vector/resize 走 helper 0x24f20 → `ldr x8,[obj]; ldr x8,[x8,#0x10]; blr x8`，
// 不经过 fs 的那两个跳板，所以必须直接填 vtable。
void *za_fs_vt_alloc(void *obj, unsigned long size, unsigned long align)
{
    (void)obj;
    if (align < sizeof(void *)) align = sizeof(void *);
    if ((align & (align - 1)) != 0) align = 16;      // 非 2 的幂：退回 16
    void *p = NULL;
    if (posix_memalign(&p, (size_t)align, size ? (size_t)size : 1) != 0) return NULL;
    return p;
}
void za_fs_vt_free(void *obj, void *ptr, unsigned long size, unsigned long align)
{
    (void)obj; (void)size; (void)align;
    free(ptr);
}

// ── 基址重定位 ──────────────────────────────────────────────────
// NSO 里**一条 RELATIVE 重定位都没有**：.data 里的模块内指针要自己加基址。
// 判据：0x1000 <= v < 映像大小 ⇒ 视为模块内指针。
static unsigned long long za_relocate_base(unsigned char *base)
{
    unsigned long long moved = 0;
    for (size_t off = 0; off + 8 <= ZA_DATA_SIZE; off += 8)
    {
        unsigned long long *slot = (unsigned long long *)(base + ZA_DATA_OFF + off);
        unsigned long long v = *slot;
        if (v >= 0x1000 && v < ZA_IMAGE_SIZE)
        {
            *slot = (unsigned long long)(uintptr_t)base + v;
            moved++;
        }
    }
    return moved;
}

// 导入解析 + 重定位表应用。za_relocs[] 由 tools/gen_guest_headers.py 从 .dynamic 生成：
//   kind 0 = 写宿主解析出的符号地址（host_index 指向 za_imports[]）
//   kind 1 = 写「基址 + 符号值」   kind 2 = 写「基址 + addend」
int za_guest_relocate(unsigned char *base, za_guest_t *out)
{
    if (!base || !out) return -1;
    memset(out, 0, sizeof *out);
    out->base = base;
    out->size = ZA_IMAGE_SIZE;

    unsigned long long moved = za_relocate_base(base);
    ZLOGI("基址重定位：修正 %llu 个模块内指针", moved);

    int resolved = 0, stubbed = 0, missing = 0;
    for (unsigned i = 0; i < ZA_RELOC_COUNT; i++)
    {
        const za_reloc_t *r = &za_relocs[i];
        if (r->slot + 8 > ZA_IMAGE_SIZE) continue;
        void **slot = (void **)(base + r->slot);
        if (r->kind == 0)
        {
            const char *name = (r->host_index < ZA_IMPORT_COUNT)
                             ? za_imports[r->host_index].name : NULL;
            void *p = name ? za_resolve(name, r->host_index) : NULL;
            if (p)
            {
                // 分清「真实现」和「自动桩」：桩的地址落在 za_stub_table 里
                int is_stub = 0;
                for (unsigned k = 0; k < ZA_STUB_COUNT; k++)
                    if ((void *)za_stub_table[k] == p) { is_stub = 1; break; }
                if (is_stub) stubbed++; else resolved++;
                *slot = p;
            }
            else
            {
                missing++;
                *slot = za_trap_alloc(name);
            }
        }
        else if (r->kind == 1) *slot = (void *)(uintptr_t)((unsigned long long)(uintptr_t)base + r->value);
        else if (r->kind == 2) *slot = (void *)(uintptr_t)((unsigned long long)(uintptr_t)base + r->value);
        else *slot = NULL;
    }
    out->resolved = resolved;
    out->stubbed = stubbed;
    out->missing = missing;
    ZLOGI("映像 %p（%u 字节），重定位 %u 条；宿主符号：系统解析 %d，落到自动桩 %d，无解 %d",
          (void *)base, (unsigned)ZA_IMAGE_SIZE, (unsigned)ZA_RELOC_COUNT,
          resolved, stubbed, missing);

    // ★ fs 分配器桩劫持到宿主 malloc/free。
    //   main 交给 nn::fs 的两个桩（main+0x19e8c68 alloc / +0x19e8c84 free）都
    //   经过游戏自己的全局分配器对象（main+0x3de4b90）→ 表（main+0x3af0ac8）
    //   → [表+0x10]/[表+0x18]。实测该两槽运行时是 0x20/0x98（**不是函数**，
    //   且 main 的 1912 个静态构造器在我们的启动顺序里根本还没跑）⇒ alloc/free
    //   双双 br 0x20 崩。fs 模块只用这块内存做路径/缓冲，宿主内存客机可直接
    //   读写 ⇒ 直接换成 malloc/free，语义等价且绕开游戏分配器。
    {
        unsigned int *a = (unsigned int *)(base + 0x19e8c68);
        unsigned int *f = (unsigned int *)(base + 0x19e8c84);
        unsigned long long ap = (unsigned long long)(uintptr_t)&za_fs_alloc_host;
        unsigned long long fp = (unsigned long long)(uintptr_t)&za_fs_free_host;
        /* movz x16,#lo16 ; movk x16,#m16,lsl16 ; movk x16,#m32,lsl32 ; br x16 */
        a[0] = 0xD2800000u | (unsigned int)((ap & 0xFFFFu) << 5) | 16u;
        a[1] = 0xF2A00000u | (unsigned int)(((ap >> 16) & 0xFFFFu) << 5) | 16u;
        a[2] = 0xF2C00000u | (unsigned int)(((ap >> 32) & 0xFFFFu) << 5) | 16u;
        a[3] = 0xD61F0200u;                                  /* br x16 */
        f[0] = 0xD2800000u | (unsigned int)((fp & 0xFFFFu) << 5) | 16u;
        f[1] = 0xF2A00000u | (unsigned int)(((fp >> 16) & 0xFFFFu) << 5) | 16u;
        f[2] = 0xF2C00000u | (unsigned int)(((fp >> 32) & 0xFFFFu) << 5) | 16u;
        f[3] = 0xD61F0200u;
        __builtin___clear_cache((char *)a, (char *)a + 16);
        __builtin___clear_cache((char *)f, (char *)f + 16);
        // ★ 还有第二条路：vector/resize 的 helper（main+0x24f20）直接
        //   `ldr x8,[obj]; ldr x8,[x8,#0x10]; blr x8`，**不经过上面两个跳板**。
        //   分配器对象 main+0x3de4b90 的 vtable（main+0x3af0ac8）槽 2/3 = 0x20/0x98
        //   ⇒ blr 0x20（实测崩溃 pc=0x20，调用点 main+0x24f38）。
        //   槽 2 = Allocate(size,align)，槽 3 = Free(ptr,size,align)，都换成宿主实现。
        unsigned long long *vt = (unsigned long long *)(base + 0x3af0ac8);
        vt[2] = (unsigned long long)(uintptr_t)&za_fs_vt_alloc;
        vt[3] = (unsigned long long)(uintptr_t)&za_fs_vt_free;
        ZLOGI("fs 分配器桩 → 宿主：alloc=%p free=%p；vtable[2/3] ← %p/%p",
              (void *)za_fs_alloc_host, (void *)za_fs_free_host,
              (void *)za_fs_vt_alloc, (void *)za_fs_vt_free);
    }
    // 段权限收紧：text=RX / rodata=R / data=RW
    mprotect(base + ZA_TEXT_OFF, ZA_TEXT_SIZE, PROT_READ | PROT_EXEC);
    mprotect(base + ZA_RODATA_OFF, ZA_DATA_OFF - ZA_RODATA_OFF, PROT_READ);
    mprotect(base + ZA_DATA_OFF, (ZA_DATA_SIZE + ZA_BSS_SIZE + 0xFFF) & ~0xFFFul,
             PROT_READ | PROT_WRITE);

    ZLOGI("段权限: text=RX rodata=R data=RW");
    return 0;
}

// 建立 main 模块的导出符号视图（SDK 查 nnMain/nninitStartup 用）
int za_guest_mod_init(unsigned char *base, const unsigned char *exp_bin, size_t exp_len)
{
    if (za_mod_from_exports(&za_main_mod, base, exp_bin, exp_len) != 0) return -1;
    za_guest_main_base = base;
    ZLOGI("main 导出符号 %u 个（基址 %p）", za_main_mod.export_count, (void *)base);
    return 0;
}
// ════════════════════════════════════════════════════════════════
//  启动：扮演 nnrtld，按真机顺序驱动 SDK
// ════════════════════════════════════════════════════════════════

// 查 SDK 导出表里的符号
static void *za_sdk_sym(const char *n)
{
    return za_mod_lookup(&za_sdk_mod, n);
}

// rtld 三回调：A 只置标志（略）、B = 各模块 DT_INIT、C = 析构（不做）
static void za_rtld_flag_cb(void) {}

static void za_rtld_module_inits_cb(void)
{
    ZLOGI("里程碑 M4: 回调B（各模块 DT_INIT）");
    za_sdk_run_init(&za_sdk_mod);
    if (ZA_DT_INIT)
    {
        void (*init)(void) = (void (*)(void))(za_guest_main_base + ZA_DT_INIT);
        ZLOGI("调 main _init @%#x", (unsigned long long)ZA_DT_INIT);
        init();
    }
    if (ZA_DT_INIT_ARRAY && ZA_DT_INIT_ARRAYSZ)
    {
        unsigned long long n = ZA_DT_INIT_ARRAYSZ / 8;
        void (**arr)(void) = (void (**)(void))(za_guest_main_base + ZA_DT_INIT_ARRAY);
        ZLOGI("调 %llu 个静态构造器", n);
        for (unsigned long long i = 0; i < n; i++)
            if (arr[i]) arr[i]();
    }
    // 进程参数交给 SDK（真机上由 nn::init 从参数区取，经 SetHostArgc/Argv 交给 SDK）
    static char *argv[] = { (char *)"main", NULL };
    void (*set_argc)(int) = (void (*)(int))za_sdk_sym("_ZN2nn2os11SetHostArgcEi");
    void (*set_argv)(char **) = (void (*)(char **))za_sdk_sym("_ZN2nn2os11SetHostArgvEPPc");
    if (set_argc) { ZLOGI("SetHostArgc(1)"); set_argc(1); }
    if (set_argv) { ZLOGI("SetHostArgv"); set_argv(argv); }
    ZLOGI("里程碑 M5: SetHostArgc/Argv 已设置（即将进 nnMain）");
}

static void za_rtld_fini_cb(void) {}

// 客机启动。顺序（全部实测确认）：
//   ① 模块链表登记（扮演 nnrtld —— SDK 靠它认识模块）
//   ② 只读 TLS 页 +0x1f0 / +0x1f8（临界区要读 [self+0x1b0]=owner_id）
//   ③ 参数区 → 调 SDK 的 nn::init::Start（真机上由 nnrtld 调它）
//
// ⚠ ①②必须在 Start 之前 —— 写成 `start(); return 0;` 会让它们永远不执行。
int za_guest_boot(za_guest_t *g)
{
    if (!g || !g->base) return -1;
    za_guest_start_sampler();
    za_os_install_tls_descriptor();
    // 实测（2026-10-26，平板）：`msr TPIDRRO_EL0, x` 在 EL0 直接 SIGILL
    // —— 这个寄存器对 EL0 是只读的，所以 123 处 `mrs tpidrro_el0` 只能
    // 靠代码改写；「每线程的只读 TLS」也必须靠别的手段实现。
    za_guest_tid = syscall(SYS_gettid);

    {
        sigset_t cur;
        pthread_sigmask(SIG_BLOCK, NULL, &cur);
        ZLOGI("客机线程信号屏蔽: TERM=%d ABRT=%d SEGV=%d",
              sigismember(&cur, SIGTERM), sigismember(&cur, SIGABRT), sigismember(&cur, SIGSEGV));
    }
    za_guest_main_base = g->base;

    // ① 模块链表：SDK 的 nn::ro::LoadModule 靠这条链找模块
    za_sdk_register_modules(g->base, (unsigned long long)ZA_IMAGE_SIZE);

    // ② 只读 TLS 的两个关键指针槽
    {
        unsigned long tp = 0;
        __asm__ __volatile__("mrs %0, TPIDR_EL0" : "=r"(tp));
        unsigned long guest_tls = za_os_guest_tls_area();
        int use_guest = 0;
        {
            const char *e = getenv("ZA_TLS_TP");
            if (e && *e) use_guest = (*e != '0');
        }
        unsigned long val = (use_guest && guest_tls) ? guest_tls : tp;
        za_sdk_set_ro_tls_tpidr(val);
        ZLOGI("只读 TLS: +0x1f0 ← %p（%s）  客机区=%p bionic_tp=%p",
              (void *)val, use_guest ? "客机 TLS 区" : "bionic tp",
              (void *)guest_tls, (void *)tp);
    }

    // ③ 走 SDK 自己的 nn::init::Start（= 真机上 nnrtld 做的事）
    {
        typedef void (*za_cb)(void);
        void (*start)(unsigned long, unsigned long, za_cb, za_cb, za_cb) =
            (void (*)(unsigned long, unsigned long, za_cb, za_cb, za_cb))
            za_sdk_sym("_ZN2nn4init5StartEmmPFvvES2_S2_");
        if (start)
        {
            void *argdata = za_build_startup_info();
            ZLOGI("里程碑 M3: 进入 nn::init::Start(argc=1, argdata=%p, A, B, C)", argdata);
            za_reinstall_signal_handlers();
            start(1, (unsigned long)(uintptr_t)argdata,
                  za_rtld_flag_cb, za_rtld_module_inits_cb, za_rtld_fini_cb);
            za_reinstall_signal_handlers();
            ZLOGI("里程碑 M6: nn::init::Start 返回");
            return 0;
        }
        ZLOGE("SDK 里找不到 nn::init::Start");
        return -1;
    }
}

// ════════════════════════════════════════════════════════════════
//  日志 / 采样子系统（其余几个 .c 都靠这些）
// ════════════════════════════════════════════════════════════════

// 日志**同时**写 logcat 与 files/za_log.txt。
// ⚠ 为什么必须落文件：logcat 缓冲会被系统日志刷掉（实测跑 18 秒我们的行就没了），
//   下一轮迭代就看不到上一轮遇到过什么。
static int za_log_fd = -1;
static pthread_mutex_t za_log_mtx = PTHREAD_MUTEX_INITIALIZER;

void za_log_print(int prio, const char *tag, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    __android_log_vprint(prio, tag, fmt, ap);
    va_end(ap);

    char buf[1024];
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n > (int)sizeof buf - 2) n = (int)sizeof buf - 2;
    buf[n] = '\n';
    buf[n + 1] = 0;
    pthread_mutex_lock(&za_log_mtx);
    if (za_log_fd < 0)
        za_log_fd = open("/data/data/org.pokelegza.android.port/files/za_log.txt",
                         O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (za_log_fd >= 0) { ssize_t w = write(za_log_fd, buf, (size_t)n + 1); (void)w; }
    pthread_mutex_unlock(&za_log_mtx);
}

// 崩溃日志文件（旧机制保留：现在现场主走 za_fatal_write，这里只建文件）
static int za_crash_fd = -1;
void za_open_crash_log(void)
{
    if (za_crash_fd >= 0) return;
    za_crash_fd = open("/data/data/org.pokelegza.android.port/files/za_crash.log",
                       O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (za_crash_fd < 0) ZLOGE("崩溃日志文件打不开: %s", strerror(errno));
}

// 详细日志开关：存在 files/verbose 就开（不用重装 APK，下次冷启动生效）。
// ⚠ 默认关：客机每秒几十万次 svc，逐条打印会把客机线程全耗在 liblog 里。
static int za_verbose_state = -1;
int za_verbose_is_on(void)
{
    if (za_verbose_state < 0)
    {
        za_verbose_state = 0;
        int fd = open("/data/data/org.pokelegza.android.port/files/verbose",
                      O_RDONLY | O_CLOEXEC);
        if (fd >= 0) { za_verbose_state = 1; close(fd); }
    }
    return za_verbose_state;
}
// ════════════════════════════════════════════════════════════════
//  PC 采样器（崩溃时知道客机卡在哪）
// ════════════════════════════════════════════════════════════════
//
// 用 POSIX 定时器按线程投递信号，处理器把当时的 PC 记下来。
// ⚠ 信号号必须挑 SDK **没屏蔽**的：
//   安卓的 SIGRTMIN == 42（bionic 自己占它做 POSIX 定时器），SIGRTMAX == 64；
//   SDK 初始化后把掩码设成 0xffffffffbaff（56 位）⇒ 只放行 bit56..63。
//   ⇒ 用 **63**（42 被 bionic 占，别抢）。
#define ZA_SAMPLER_SIG 63

static timer_t za_pc_timer;
static volatile int za_pc_timer_ready;
static volatile unsigned long long za_guest_last_guest_pc;
static pthread_t za_sampler_thread;

// 客机 PC 环形轨迹：崩溃前最后 ZA_PC_RING 次采样到的客机 PC。
// 这是唯一能回答「客机到底执行到哪条指令」的运行时证据。
volatile unsigned long za_pc_ring[ZA_PC_RING];
volatile unsigned long za_pc_ring_pos;

static void za_pc_sample_handler(int sig, siginfo_t *info, void *ctx)
{
    (void)sig; (void)info;
    static int probe;
    if (probe < 3)
    {
        probe++;
        unsigned long raw = ctx ? (unsigned long)((ucontext_t *)ctx)->uc_mcontext.pc : 0;
        ZLOGI("采样探针 %d：ctx=%p pc=%#lx", probe, ctx, raw);
    }
    if (!ctx) return;
    ucontext_t *uc = (ucontext_t *)ctx;
    unsigned long pc = (unsigned long)uc->uc_mcontext.pc;
    if ((za_guest_base && pc >= (unsigned long)za_guest_base &&
         pc < (unsigned long)za_guest_base + ZA_IMAGE_SIZE) ||
        (za_sdk_base && pc >= za_sdk_base && pc < za_sdk_base + za_sdk_size))
    {
        za_guest_last_guest_pc = pc;
        // 环形轨迹：崩溃前最后若干条客机 PC。
        // 采样间隔 20ms，崩前进度通常只剩几十毫秒 ⇒ 只要 16 格就能覆盖。
        unsigned long p = za_pc_ring_pos;
        za_pc_ring[p % ZA_PC_RING] = pc;
        za_pc_ring_pos = p + 1;
    }
}

// 每次 svc 之后重装采样信号（SDK 会把实时信号段全屏蔽掉）
void za_reinstall_sampler_handler(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = za_pc_sample_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaction(ZA_SAMPLER_SIG, &sa, NULL);
    sigset_t m;
    sigemptyset(&m);
    sigaddset(&m, ZA_SAMPLER_SIG);
    pthread_sigmask(SIG_UNBLOCK, &m, NULL);
}

static void *za_sampler_watchdog(void *arg)
{
    (void)arg;
    // ★ 卡死检测：同一 PC 连续 2 秒不变（且期间无新采样动作）⇒ 客机在原地
    //   自旋。打印一次 PC + 所属模块偏移 —— 这是不杀进程就能拿到「卡在哪」
    //   的唯一手段（2026-10-25：fsp-srv 后 100% CPU 自旋就是靠它定位的）。
    unsigned long long stuck_pc = 0;
    int stuck_n = 0;
    for (;;)
    {
        struct timespec ts = { 0, 50 * 100 * 1000 };   // 50ms
        nanosleep(&ts, NULL);
        /* 向客机线程投递采样信号（tgkill 按线程）：SIGEV_THREAD_ID 只能绑
         * 装载线程，绑不到客机线程 ⇒ 环形轨迹一直为空的根因。 */
        if (za_guest_tid > 0)
        {
            long r = syscall(SYS_tgkill, (int)getpid(), (int)za_guest_tid, ZA_SAMPLER_SIG);
            static long err_logged;
            if (r != 0 && err_logged++ < 3)
                ZLOGE("tgkill(%d, guest_tid=%ld, 63) = %ld errno=%d",
                      (int)getpid(), (long)za_guest_tid, r, errno);
        }
        /* ★ 卡死判据改为「svc 派发停止推进」：SDK 在 svc 之间会重新屏蔽实时
         *   信号 ⇒ 采样器送不进去（实测探针只在 boot 早期响过）⇒ 只能看
         *   派发计数。10 秒无推进 = 自旋在客机代码里 ⇒ 发 SIGSEGV 让致命
         *   处理器把当时的 PC/寄存器/栈整份倒出来（进程牺牲，答案到手）。 */
        static unsigned long last_count;
        static int no_progress;
        unsigned long cnt = za_disp_count;
        if (cnt == last_count)
        {
            if (++no_progress == 200)
                ZLOGE("★ 客机 1 秒无 svc 推进（count=%lu）", cnt);
            if (no_progress == 2000)
            {
                ZLOGE("★ 卡死 10 秒：向客机线程发 SIGSEGV 倒现场");
                syscall(SYS_tgkill, (int)getpid(), (int)za_guest_tid, 11);
            }
        }
        else { last_count = cnt; no_progress = 0; }
        unsigned long long pc = za_guest_last_guest_pc;
        if (pc && pc == stuck_pc) { if (++stuck_n == 40) ZLOGE("★ 客机 200ms 停在同一 PC=%#llx", pc); }
        else { stuck_pc = pc; stuck_n = 0; }
        // ★ hook 槽监视：0xc90600 应该一直是 za_host_tick_hook（宿主地址）。
        //   实测被改成 sdk+0x13d9a0（GetSystemTick 自己）⇒ 桩↔函数互跳死循环。
        //   这里每 2 秒打一次值 + 首个非 hook 值时把桩区头 0x60 字节也倒出来。
        {
            extern volatile unsigned long za_sdk_base;
            extern volatile int za_cnctp_ready;
            static unsigned long long first_bad;
            static int dumped;
            if (za_sdk_base && za_cnctp_ready)
            {
                unsigned long long slot = *(volatile unsigned long long *)(za_sdk_base + 0xc90600);
                unsigned long long hook = (unsigned long long)(uintptr_t)za_host_tick_hook;
                if (slot != hook && !first_bad)
                {
                    first_bad = slot;
                    ZLOGE("★ hook 槽被改！0xc90600 = %#llx（hook=%#llx）", slot, hook);
                }
                /* fs 分配器槽监视：初始 = base+0xdcb90（SDK 默认），
                 * main 调 SetAllocator 后**合法地**变成 main 映像内的函数。
                 * 只有既不是默认、也不在 main 映像内才算异常。 */
                {
                    static unsigned long long fs_bad;
                    unsigned long long fs = *(volatile unsigned long long *)(za_sdk_base + 0xb88898);
                    int ok = (fs == za_sdk_base + 0xdcb90ull) ||
                             (za_guest_base && fs >= (unsigned long long)(uintptr_t)za_guest_base &&
                              fs < (unsigned long long)(uintptr_t)za_guest_base + ZA_IMAGE_SIZE);
                    if (!ok && !fs_bad)
                    {
                        fs_bad = fs;
                        ZLOGE("★ fs 分配器槽异常！0xb88898 = %#llx（既非 SDK 默认也非 main 函数）", fs);
                    }
                }
                if (first_bad && !dumped && first_bad == slot)
                {
                    dumped = 1;
                    for (unsigned o = 0; o < 0x60; o += 4)
                        ZLOGE("  桩区[%#x] = %08x", 0xc90000u + o,
                              *(const volatile unsigned int *)(za_sdk_base + 0xc90000 + o));
                }
            }
        }
    }
    return NULL;
}

void za_guest_start_sampler(void)
{
    static int started;
    if (started) return;
    started = 1;
    if (getenv("ZA_NO_SAMPLER")) { ZLOGI("PC 采样器已禁用（ZA_NO_SAMPLER）"); return; }
    za_reinstall_sampler_handler();
    struct sigevent sev;
    memset(&sev, 0, sizeof sev);
    sev.sigev_notify = SIGEV_THREAD_ID;
    sev.sigev_signo = ZA_SAMPLER_SIG;
    sev.sigev_notify_thread_id = (pid_t)syscall(SYS_gettid);
    if (timer_create(CLOCK_MONOTONIC, &sev, &za_pc_timer) != 0)
    {
        ZLOGE("PC 采样定时器创建失败");
        return;
    }
    struct itimerspec its;
    its.it_value.tv_sec = 0;
    its.it_value.tv_nsec = 20 * 1000 * 1000;      // 20ms
    its.it_interval = its.it_value;
    if (timer_settime(za_pc_timer, 0, &its, NULL) != 0)
    {
        ZLOGE("PC 采样定时器启动失败");
        return;
    }
    za_pc_timer_ready = 1;
    pthread_create(&za_sampler_thread, NULL, za_sampler_watchdog, NULL);
    pthread_detach(za_sampler_thread);
    ZLOGI("PC 采样器已启动（20ms 采样 + 50ms 看门狗，信号 %d）", ZA_SAMPLER_SIG);
}

// 自检：打印本线程信号掩码（SDK 会改掉它，看看到底屏蔽了什么）
void za_dump_thread_mask(const char *tag)
{
    sigset_t cur;
    pthread_sigmask(SIG_BLOCK, NULL, &cur);
    char buf[320];
    char *p = buf;
    p = za_put_str(p, "ZaGuest: 信号掩码[");
    p = za_put_str(p, tag ? tag : "?");
    p = za_put_str(p, "] ");
    for (int s = 1; s <= 64; s++)
    {
        if (sigismember(&cur, s) == 1)
        {
            p = za_put_str(p, "挡:");
            p = za_put_hex(p, (unsigned long long)s);
            p = za_put_str(p, " ");
        }
    }
    p = za_put_str(p, "\n");
    za_fatal_write(buf, (size_t)(p - buf));
}
// ════════════════════════════════════════════════════════════════
//  SDK 模块装载（转接 za_sdk.c）
// ════════════════════════════════════════════════════════════════
// 装载分两步，因为两个模块互相依赖：
//   1) map main（导出表不依赖重定位）→ 2) 装 SDK（它的未定义符号查 main 导出表）
//   → 3) relocate main（它的未定义符号查 SDK 导出表）。顺序不能换。
// za_sdk_load 要的两个回调：查宿主 / 查 main 的导出表
static void *za_resolve_host_cb(const char *name, void *ctx)
{
    (void)ctx;
    return za_resolve_host(name);
}
static void *za_lookup_main_cb(const char *name, void *ctx)
{
    (void)ctx;
    return za_mod_lookup(&za_main_mod, name);
}

int za_guest_load_sdk(const unsigned char *text, size_t tsz,
                      const unsigned char *rodata, size_t rsz,
                      const unsigned char *data, size_t dsz, size_t bss,
                      const unsigned char *exp, size_t explen,
                      const unsigned char *rel, size_t rellen,
                      const unsigned char *gate, size_t gatelen)
{
    return za_sdk_load(&za_sdk_mod, text, tsz, rodata, rsz, data, dsz, bss,
                       exp, explen, rel, rellen, gate, gatelen,
                       (void *(*)(const char *, void *))za_resolve_host_cb,
                       za_lookup_main_cb, NULL);
}


// 跑 SDK 自己的 _init 与静态构造器（必须在 main 的 _init 之前）
int za_guest_run_sdk_init(void)
{
    return za_sdk_run_init(&za_sdk_mod);
}