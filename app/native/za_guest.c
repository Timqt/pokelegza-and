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
#include "za_mem.h"
#include "za_guest_info.h"
#include "za_imports.h"
#include "za_romfs_embed.h"
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
#include "za_nvn.h"
#include "za_sync.h"
#include "za_vi.h"

// ── 客机映像布局（来自 za_guest_info.h，实测值）────────────────────────
//   text   0x0000000 .. 0x2fc7250
//   rodata 0x2fc8000 .. 0x39e1000
//   data   0x39e1000 .. 0x3d7f1c0
//   bss    +0x21fae40        ⇒ 映像总计 0x5f7a000
#define ZA_GUEST_BASE_ADDR 0x100000000ul   // 客机代码里硬编码的基址，必须映射到这里

// 客机全局状态（其它 .c 通过 extern 访问）
unsigned char *za_guest_base = NULL;
volatile int za_stage_m5;                 /* M5 之后才允许「别名句柄」CMIF 应答 */
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
// svc 寄存器槽现在是每线程的（定义在 za_horizon.c）：
// 不能再声明成全局数组，否则会链接到另一个符号/读错线程。
extern unsigned long long *za_regs_get(void);
#define za_horizon_regs za_regs_get()

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
// 按服务号分桶的计数：卡住时能看出「只剩下哪几个 svc 在动」。
volatile unsigned long za_svc_nr_count[64];
void za_disp_count_bump(void) { za_disp_count++; }
void za_svc_nr_count_bump(unsigned nr) { if (nr < 64) __atomic_add_fetch(&za_svc_nr_count[nr], 1, __ATOMIC_RELAXED); }
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
// ★ 必须**每线程**一份：SDK 有多个 worker 线程，会同时崩；共用一份时
//   A 线程 sigsetjmp、B 线程 siglongjmp ⇒ libc 报 "setjmp cookie mismatch"
//   并在 longjmp 里 abort（实测调用链正好落在 libc 的 setjmp/longjmp 实现）。
// ⚠ 不用 __thread：本工程 .so 的 __thread 走 emutls（__emutls_get_address）。
//   实测有客机地址被喂进 emutls 控制块 ⇒ 它在内部 undef 指令上 SIGILL
//   （pc=libzaandroid.so+0xd6c98，x0=0xb400006f… 客机堆指针）。
//   ⇒ 改成按 tid 索引的静态池，彻底不依赖宿主 TLS。
#define ZA_FATAL_POOL 64
static volatile int za_fatal_owner;      // 0 = 没有线程在报告，1 = 已有
static sigjmp_buf za_fatal_jmp_pool[ZA_FATAL_POOL];
static volatile sig_atomic_t za_fatal_dump_pool[ZA_FATAL_POOL];
static int za_fatal_idx(void)
{
    long t = syscall(SYS_gettid);
    return (int)(((unsigned)t) % ZA_FATAL_POOL);
}

// 「像不像一个用户态地址」：dump 前的廉价检查（8 对齐 + 47 位内）
static int za_va_plausible(unsigned long v)
{
    return (v & 7) == 0 && v >= 0x10000ul && v < 0x800000000000ul;
}

// 本 .so 的映射范围与「被顶掉的别人的处理器」（定义在下面的信号安装处）
static unsigned long za_self_base, za_self_end;
// libart.so 的装载区间（见 za_fatal_handler 里 ART TrimMaps 的受控修复）
static unsigned long za_libart_base, za_libart_end;
static struct sigaction za_fatal_prev[64];
static volatile int za_fatal_prev_ok[64];
static void za_segv_handler(int sig, siginfo_t *info, void *ctx);

// 本线程是不是「客机线程」：看 [TP+0x40] → 描述符页 → [+0xA0] 的魔数。
// 客机线程上，宿主 libc 里的故障（abort/assert/memcpy…）也是我们的责任；
// ART/JNI 线程没有这个描述符 ⇒ 交回原处理器。
static int za_is_guest_thread(void)
{
    unsigned long tp = 0;
    __asm__ __volatile__("mrs %0, TPIDR_EL0" : "=r"(tp));
    if (!tp || tp < 0x10000ul) return 0;
    unsigned long long hdr = 0;
    memcpy(&hdr, (const void *)(uintptr_t)(tp + 0x40), 8);
    if (!hdr || hdr < 0x10000ull || (hdr & 0xfffull)) return 0;
    unsigned long long p = 0;
    memcpy(&p, (const void *)(uintptr_t)(hdr + 0xA0), 8);
    if (!p || p < 0x10000ull) return 0;
    unsigned long long magic = 0;
    memcpy(&magic, (const void *)(uintptr_t)(p + 31 * 8), 8);
    return magic == 0x5a5a524547535f31ull;
}

static void za_fatal_handler(int sig, siginfo_t *info, void *ctx)
{
    int zi = za_fatal_idx();
    if (za_fatal_dump_pool[zi]) siglongjmp(za_fatal_jmp_pool[zi], 1);   // dump 中二次 fault
    // ★★ 受控修复：ART 自己的一个已知缺陷。
    //   art::MemMapArenaPool::TrimMaps()+72（libart+0x795558）:
    //       ldr x20,[x19,#0x18]    ; arena 链表头
    //       ldr x8,[x20]           ; arena 的虚表指针
    //       ldr x8,[x8,#0x10]      ; ← 虚表为 0 时 fault addr = 0x10
    //   实测该链表里出现了一个**被清零过的 arena**（虚表=0），ART 没有判空直接虚调用，
    //   于是整个进程被打死。我们没法在这里替 ART 修好那个 arena，但可以把链表头摘掉
    //   （等价于"没有待裁剪的 arena"）并跳到解锁+返回处，让 JIT 继续工作。
    //   ⚠ 必须指令字节校验通过才动手；任何一条不匹配就不碰，交给原来的流程。
    if (ctx && za_libart_base && sig == SIGSEGV && info &&
        (unsigned long long)(uintptr_t)info->si_addr == 0x10ull)
    {
        ucontext_t *uc = (ucontext_t *)ctx;
        unsigned long pcv = (unsigned long)uc->uc_mcontext.pc;
        unsigned long fix = za_libart_base + 0x795558ul;
        if (pcv == fix && *(volatile unsigned int *)(uintptr_t)pcv == 0xf9400908u)
        {
            static int nfix;
            unsigned long pool = (unsigned long)uc->uc_mcontext.regs[19];
            unsigned long arena = (unsigned long)uc->uc_mcontext.regs[20];
            *(volatile unsigned long long *)(uintptr_t)(pool + 0x18) = 0;
            uc->uc_mcontext.pc = za_libart_base + 0x79553cul;   // → 解锁 + 返回
            if (nfix++ < 20)
            {
                char b[160];
                char *q = b;
                q = za_put_str(q, "ZaGuest: ★ 修复 ART TrimMaps 空虚表（第 ");
                q = za_put_dec(q, (unsigned long long)nfix);
                q = za_put_str(q, " 次）arena=");
                q = za_put_hex(q, (unsigned long long)arena);
                q = za_put_str(q, " pool=");
                q = za_put_hex(q, (unsigned long long)pool);
                q = za_put_str(q, "\n");
                za_fatal_write(b, (size_t)(q - b));
            }
            return;
        }
    }
    // ★★ 先判断这个故障是不是我们该管的：只有 **客机映像 / SDK 映像 / 本 .so**
    //   里的 PC 才是我们的责任。其余（ART 的隐式空指针检查、bionic 内部故障、
    //   JNI/UI 线程）一律交回**原来的处理器** —— 抢过来只会把宿主自己的
    //   信号机制（尤其 ART 的 null-check）搞坏，还会误杀整个进程。
    {
        unsigned long pc0 = ctx ? (unsigned long)((ucontext_t *)ctx)->uc_mcontext.pc : 0;
        int ours = 0;
        extern unsigned char *za_guest_base;
        extern volatile unsigned long za_sdk_base, za_sdk_size;
        if (pc0 && za_guest_base && pc0 >= (unsigned long)(uintptr_t)za_guest_base &&
            pc0 < (unsigned long)(uintptr_t)za_guest_base + ZA_IMAGE_SIZE) ours = 1;
        if (pc0 && za_sdk_base && pc0 >= za_sdk_base && pc0 < za_sdk_base + za_sdk_size) ours = 1;
        if (pc0 && za_self_base && pc0 >= za_self_base && pc0 < za_self_end) ours = 1;
        // ★ 返回地址也在映像里 ⇒ 是客机调进来的（例：客机 `blr` 到 NULL，
        //   pc=0 不在任何映像内，但 x30 指向客机代码）。不看 x30 的话这种
        //   最典型的空指针调用会被判成「非客机线程」，直接链给 SIG_DFL 把
        //   整个进程带走，连现场都留不下来（实测 tid 572 pc=0 addr=0）。
        if (!ours && ctx)
        {
            unsigned long x30 = (unsigned long)((ucontext_t *)ctx)->uc_mcontext.regs[30];
            if (x30 && za_guest_base && x30 >= (unsigned long)(uintptr_t)za_guest_base &&
                x30 < (unsigned long)(uintptr_t)za_guest_base + ZA_IMAGE_SIZE)
                ours = 1;
            if (x30 && za_sdk_base && x30 >= za_sdk_base && x30 < za_sdk_base + za_sdk_size)
                ours = 1;
        }
        // 客机线程上：即使 PC 在宿主 libc（客机 import 的 abort/assert/memcpy），
        // 也是我们的责任；非客机线程（ART/JNI）才交回原处理器。
        if (!ours && za_is_guest_thread()) ours = 1;
        if (!ours)
        {
            // ★ 诊断：交回原处理器前先留一行（异步信号安全）。以前这里静默
            //   链走，进程直接死掉、连崩在哪个线程都看不到（实测 tid 29814
            //   在 addr=0x0 上 SEGV_MAPERR，日志里没有任何痕迹）。
            {
                char b[160];
                char *q = b;
                q = za_put_str(q, "ZaGuest: 非客机线程故障 sig=");
                q = za_put_dec(q, (unsigned long long)sig);
                q = za_put_str(q, " pc=");
                q = za_put_hex(q, (unsigned long long)(ctx ? (unsigned long)((ucontext_t *)ctx)->uc_mcontext.pc : 0));
                q = za_put_str(q, " addr=");
                q = za_put_hex(q, (unsigned long long)(info ? (unsigned long long)(uintptr_t)info->si_addr : 0));
                q = za_put_str(q, " x30=");
                q = za_put_hex(q, (unsigned long long)(ctx ? (unsigned long)((ucontext_t *)ctx)->uc_mcontext.regs[30] : 0));
                q = za_put_str(q, " tid=");
                q = za_put_dec(q, (unsigned long long)syscall(SYS_gettid));
                q = za_put_str(q, "（交回原处理器）");
                {
                    // 这些 pc/x30 到底是哪个模块：自己的 .so 报 libza+offset，否则宿主
                    unsigned long pcv = ctx ? (unsigned long)((ucontext_t *)ctx)->uc_mcontext.pc : 0;
                    if (pcv && za_self_base && pcv >= za_self_base && pcv < za_self_end) {
                        q = za_put_str(q, " 模块=libza+");
                        q = za_put_hex(q, (unsigned long long)(pcv - za_self_base));
                    } else {
                        q = za_put_str(q, " 模块=宿主");
                    }
                }
                q = za_put_str(q, "\n");
                za_fatal_write(b, (size_t)(q - b));
            }
            // ★ 客机 -> 宿主库（libc++/libc）里崩的情况：pc 和 x30 都在宿主库，
            //   但**栈上**还留着客机的返回地址。扫一遍栈，找到就按客机故障处理
            //   （否则又是一例「进程被带走、连是谁调的都看不到」）。
            if (ctx)
            {
                unsigned long spx = (unsigned long)((ucontext_t *)ctx)->uc_mcontext.sp;
                extern unsigned char *za_guest_base;
                extern volatile unsigned long za_sdk_base, za_sdk_size;
                for (int k = 0; k < 64 && spx; k++)
                {
                    unsigned long long v = 0;
                    if (!za_read_bytes(spx + (unsigned long)k * 8, &v, 8)) break;
                    // ⚠ 只认**4 字节对齐、且落在 text 段内**的值：栈上经常躺着
                    //   0x100000001（= main+1）这种数据，会被误判成返回地址，
                    //   把 ART 自己的故障抢过来挂起（真机实测 libart+0x791558
                    //   addr=0x10 就是这么被误认的）。
                    unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
                    int in_main = mb && (v & 3) == 0 && v > mb && v < mb + ZA_TEXT_SIZE;
                    int in_sdk = za_sdk_base && (v & 3) == 0 && v > za_sdk_base &&
                                 v < za_sdk_base + 0x64e230ull;
                    if (in_main || in_sdk)
                    {
                        char b2[200];
                        char *q = b2;
                        q = za_put_str(q, "ZaGuest: 栈上有客机返回地址 sp+");
                        q = za_put_hex(q, (unsigned long long)(k * 8));
                        q = za_put_str(q, "=");
                        q = za_put_hex(q, v);
                        q = za_put_str(q, in_main ? " main+" : " sdk+");
                        q = za_put_hex(q, in_main
                                              ? v - (unsigned long long)(uintptr_t)za_guest_base
                                              : v - za_sdk_base);
                        q = za_put_str(q, " ⇒ 按客机故障处理\n");
                        za_fatal_write(b2, (size_t)(q - b2));
                        ours = 1;
                        break;
                    }
                }
            }
            // ★ 2026-10-27：pc=0 / x30=0 / addr=0 —— 这是一个**线程从地址 0 开始执行**
            //   的特征（线程入口为空），不是普通空指针调用。它没有客机描述符，
            //   以前直接交回 SIG_DFL 把整个进程带走，什么都看不到。
            //   这里补上 sp / TP / [TP+0x40]，然后**挂起**该线程而不是杀掉进程：
            //   其余线程还能继续跑，便于继续观察游戏走到哪一步。
            if (ctx)
            {
                unsigned long pcx = (unsigned long)((ucontext_t *)ctx)->uc_mcontext.pc;
                unsigned long spx = (unsigned long)((ucontext_t *)ctx)->uc_mcontext.sp;
                unsigned long lrx = (unsigned long)((ucontext_t *)ctx)->uc_mcontext.regs[30];
                if (pcx == 0 && lrx == 0)
                {
                    unsigned long tpx = 0;
                    unsigned long long slot = 0;
                    __asm__ __volatile__("mrs %0, TPIDR_EL0" : "=r"(tpx));
                    if (tpx > 0x10000) memcpy(&slot, (void *)(uintptr_t)(tpx + 0x40), 8);
                    {
                        char b[200];
                        char *q = b;
                        q = za_put_str(q, "ZaGuest: 线程从 0 开始执行 tid=");
                        q = za_put_dec(q, (unsigned long long)syscall(SYS_gettid));
                        q = za_put_str(q, " sp=");
                        q = za_put_hex(q, (unsigned long long)spx);
                        q = za_put_str(q, " tp=");
                        q = za_put_hex(q, (unsigned long long)tpx);
                        q = za_put_str(q, " desc=");
                        q = za_put_hex(q, slot);
                        q = za_put_str(q, " ⇒ 挂起该线程（不杀进程）\n");
                        za_fatal_write(b, (size_t)(q - b));
                    }
                    ZLOGE("★ 线程从 0 开始执行（tid=%ld sp=%#lx tp=%#lx desc=%#llx）"
                          " ⇒ 挂起，保住进程",
                          (long)syscall(SYS_gettid), spx, tpx, slot);
                    // 栈顶几格 + 各寄存器：判断它是「线程入口就是 0」还是
                    // 「跑到一半跳飞」——前者栈上没有返回地址，后者有。
                    for (int k = 0; k < 8 && spx; k++)
                    {
                        unsigned long long v = 0;
                        if (!za_read_bytes(spx + (unsigned long)k * 8, &v, 8)) break;
                        ZLOGE("    sp+%#x = %#llx", k * 8, v);
                    }
                    za_nvn_dump_recent();   /* 最后一次 NVN 调用的客机 LR 就在这里 */
                    for (int k = 0; k < 31; k++)
                        ZLOGE("    x%d = %#llx", k,
                              (unsigned long long)((ucontext_t *)ctx)->uc_mcontext.regs[k]);
                    for (;;) pause();
                }
            }
            // ★ 2026-10-27：致命信号（SEGV/BUS/ILL/FPE）在非客机线程上：
            //   · 空页访问（si_addr < 0x1000）= ART 的隐式空指针检查 ⇒ 交回 ART；
            //   · 其余（pc/x30 都在宿主库、栈上没有客机地址）⇒ 挂起该线程，
            //     其余线程继续跑（链给 ART 会让它当成自己的故障直接终止进程）。
            if ((sig == SIGSEGV || sig == SIGBUS || sig == SIGILL || sig == SIGFPE) &&
                !(info && (unsigned long long)(uintptr_t)info->si_addr < 0x1000ull))
            {
                char b2[120];
                char *q = b2;
                q = za_put_str(q, "ZaGuest: 致命信号无处理器 ⇒ 挂起该线程（不杀进程）\n");
                za_fatal_write(b2, (size_t)(q - b2));
                for (;;) pause();
            }
            // ★ 例外：**空页访问**（si_addr < 0x1000）必须交回 ART。
            //   libart 故意解引用空指针做「隐式空指针检查」来抛 NPE，靠它自己的
            //   处理器恢复；我们抢过来挂起会让 ART 的 NPE 永远不返回、JVM 状态
            //   坏掉（真机实测崩在 libart+0x791558、addr=0x10）。
            if (sig > 0 && sig < 64 && za_fatal_prev_ok[sig])
            {
                struct sigaction *o = &za_fatal_prev[sig];
                if (o->sa_flags & SA_SIGINFO)
                {
                    if (o->sa_sigaction && o->sa_sigaction != za_segv_handler)
                    {
                        // ★ 不要**直接调用**原处理器：ART 的处理器要经 libsigchain
                        //   的每线程状态（Self、implicit-check 标记）才能正确工作，
                        //   直接调会让它把状态搞坏（真机实测 ART 的 "Jit thread pool"
                        //   线程随后在 libart+0x791558 上解引用 null+0x10 崩掉）。
                        //   正确做法：把原处理器**装回去**再返回 —— 我们没改出错指令，
                        //   内核会立刻重新投递同一个信号，这次由 ART 自己按正常路径处理。
                        struct sigaction back = *o;
                        back.sa_flags &= ~SA_SIGINFO;
                        sigaction(sig, o, NULL);
                        return;
                    }
                }
                else if (o->sa_handler == SIG_IGN)
                {
                    return;
                }
                else if (o->sa_handler && o->sa_handler != SIG_DFL)
                {
                    sigaction(sig, o, NULL);
                    return;
                }
            }
            // 没有可转交的处理器。
            signal(sig, SIG_DFL);
            return;
        }
    }
    // ★★ 串行化：多线程同时崩时，只让**一个**线程做 dump。
    //   其它线程**挂起**而不是 _exit —— 以前一有第二个线程故障就把整个进程
    //   杀掉，日志里只剩最先那个线程的现场，其它线程的死因完全看不到。
    if (__atomic_exchange_n(&za_fatal_owner, 1, __ATOMIC_ACQ_REL) != 0)
    {
        for (;;) pause();
    }
    unsigned long pc = 0;
    if (ctx) { ucontext_t *uc = (ucontext_t *)ctx; pc = (unsigned long)uc->uc_mcontext.pc; }
    {
        static const char tag[] = "ZaGuest: FATAL-ENTER\n";
        za_fatal_write(tag, sizeof tag - 1);
    }
    // ★ NVN 调用历史：NVN 入口平时每种只记前两次，崩在 NVN 初始化中段时
    //   没有这份记录就只能靠猜最后走到哪一步。这里用宿主日志（非信号安全
    //   路径里已经这么干过），且只打一次。
    {
        static int nvn_dumped;
        if (!nvn_dumped) { nvn_dumped = 1; za_nvn_dump_recent(); }
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

    // ★ gate 现场：崩溃是否发生在 svc 门里（nr / guest sp / guest x30）。
    //   每线程 regs 里的 [10]=服务号、[9]=客机 sp、[11]=客机 x30。
    //   若 nr 非 0 ⇒ 崩在「宿主替客机执行 svc」的过程中；
    //   若 nr=0 且 guest_x30=0 ⇒ 客机自己 ret 到了 0。
    {
        extern unsigned long long *za_regs_get(void);
        unsigned long long *rr = za_regs_get();
        char buf[256];
        char *p = buf;
        p = za_put_str(p, "ZaGuest: gate nr=");
        p = za_put_dec(p, rr ? rr[10] : 0);
        p = za_put_str(p, " guest_sp=");
        p = za_put_hex(p, rr ? rr[9] : 0);
        p = za_put_str(p, " guest_x30=");
        p = za_put_hex(p, rr ? rr[11] : 0);
        p = za_put_str(p, " regs=");
        p = za_put_hex(p, (unsigned long long)(uintptr_t)rr);
        p = za_put_str(p, "\n");
        za_fatal_write(buf, (size_t)(p - buf));
    }

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
        // main 的单例缓存槽（0x3d99000+0x3e0/0x3e8，guard 0x3f0）：
        // 崩溃点 main+0x11ce34 是对 [obj+0x10] 的虚调用，obj 的 vtable 为 0。
        {
            extern unsigned char *za_guest_base;
            if (za_guest_base)
            {
                unsigned long long g = (unsigned long long)(uintptr_t)za_guest_base + 0x3d99000ull;
                unsigned long long a = 0, b = 0;
                unsigned char flag = 0;
                memcpy(&a, (const void *)(uintptr_t)(g + 0x3e0), 8);
                memcpy(&b, (const void *)(uintptr_t)(g + 0x3e8), 8);
                memcpy(&flag, (const void *)(uintptr_t)(g + 0x3f0), 1);
                {
                    unsigned long long m = (unsigned long long)(uintptr_t)za_guest_base;
                    unsigned int a0 = *(const unsigned int *)(uintptr_t)(m + 0x11cdf4);
                    unsigned int a1 = *(const unsigned int *)(uintptr_t)(m + 0x11cdf8);
                    unsigned int a2 = *(const unsigned int *)(uintptr_t)(m + 0x11cdfc);
                    char *q = buf;
                    q = za_put_str(q, "ZaGuest: PATCH 11cdf4=");
                    q = za_put_hex(q, a0);
                    q = za_put_str(q, " 11cdf8=");
                    q = za_put_hex(q, a1);
                    q = za_put_str(q, " 11cdfc=");
                    q = za_put_hex(q, a2);
                    {
                        const char nl[2] = { 10, 0 };
                        q = za_put_str(q, nl);
                    }
                    za_fatal_write(buf, (size_t)(q - buf));
                }
                char *p = buf;
                p = za_put_str(p, "ZaGuest: GUARD 0x3d99000: [+3e0]=");
                p = za_put_hex(p, a);
                p = za_put_str(p, " [+3e8]=");
                p = za_put_hex(p, b);
                p = za_put_str(p, " flag=");
                p = za_put_hex(p, flag);
                if (b)
                {
                    unsigned long long v0 = 0, v1 = 0;
                    memcpy(&v0, (const void *)(uintptr_t)b, 8);
                    memcpy(&v1, (const void *)(uintptr_t)(b + 8), 8);
                    p = za_put_str(p, " obj[0]=");
                    p = za_put_hex(p, v0);
                    p = za_put_str(p, " obj[8]=");
                    p = za_put_hex(p, v1);
                }
                {
                    const char nl[2] = { 10, 0 };
                    p = za_put_str(p, nl);
                }
                za_fatal_write(buf, (size_t)(p - buf));
            }
        }

        // 宿主 PC 附近的机器码：宿主库里崩了也能看出是哪条指令
        if (pc >= 0x10000)
        {
            unsigned int w[8];
            int ok = 1;
            for (int k = 0; k < 8; k++)
                if (!za_read_bytes(pc - 16 + (unsigned long)k * 4, &w[k], 4)) { ok = 0; break; }
            if (ok)
            {
                char *p = buf;
                p = za_put_str(p, "ZaGuest: FAULTCODE @pc-16:");
                for (int k = 0; k < 8; k++) { p = za_put_str(p, " "); p = za_put_hex(p, w[k]); }
                {
                    const char nl[2] = { 10, 0 };
                    p = za_put_str(p, nl);
                }
                za_fatal_write(buf, (size_t)(p - buf));
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
        // ★ 线程 StartThread 路径的跳板/GOT 回读。
        //   实测 boot 线程在 CreateThread(handle=7) 之后、svc#9 之前跳到
        //   pc=0x7fffffff00000000。这条路径只经过：
        //     ThreadManager::StartThread → Enter(type+0x1a8)
        //                                → GOT[0xb7ad18] = Impl::StartThread
        //                                → svc#9（门桩 @0x170044）
        //   把这几处现场打出来，就能立刻区分「GOT 坏」还是「门桩坏」。
        {
            extern volatile unsigned long za_sdk_base;
            if (za_sdk_base)
            {
                unsigned long long b = za_sdk_base;
                static const unsigned long long slots[] = {
                    0xb7ad18ull, 0xb7a880ull, 0xb7a888ull, 0xb7a890ull, 0xb79018ull,
                    0xb7af40ull, 0xb7af48ull, 0xb7af50ull, 0xb74078ull, 0xb74080ull
                };
                char *p = buf;
                p = za_put_str(p, "ZaGuest: GOTCHK");
                for (unsigned i = 0; i < sizeof slots / sizeof slots[0]; i++)
                {
                    unsigned long long v = 0;
                    memcpy(&v, (const void *)(uintptr_t)(b + slots[i]), 8);
                    p = za_put_str(p, " [");
                    p = za_put_hex(p, slots[i]);
                    p = za_put_str(p, "]=");
                    p = za_put_hex(p, v);
                }
                p = za_put_str(p, " gate9=");
                p = za_put_hex(p, (unsigned long long)*(const unsigned int *)(uintptr_t)(b + 0x170044));
                p = za_put_str(p, " trip9=");
                p = za_put_hex(p, (unsigned long long)*(const unsigned int *)(uintptr_t)(b + 0xc70040));
                p = za_put_str(p, "\n");
                za_fatal_write(buf, (size_t)(p - buf));
            }
        }
        // 从这里开始全是「解引用寄存器」的危险 dump：二次 fault 就放弃剩余部分。
        za_fatal_dump_pool[zi] = 1;
        if (sigsetjmp(za_fatal_jmp_pool[zi], 1) != 0)
        {
            static const char ab[] = "ZaGuest: (dump aborted: nested fault)\n";
            za_fatal_write(ab, sizeof ab - 1);
            za_fatal_dump_pool[zi] = 0;
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
        // ★ 最近一次 Break 的 info 块（前 0x40 字节 + 其中的字符串指针）
        {
            extern unsigned long long za_dbg_last_break_info, za_dbg_last_break_size;
            unsigned long long a = za_dbg_last_break_info;
            if (a && za_va_plausible(a))
            {
                ZLOGI("ZaGuest: BREAK-INFO @%#llx size=%llu", a, za_dbg_last_break_size);
                for (int i = 0; i < 0x40; i += 8)
                {
                    unsigned long long v = 0;
                    memcpy(&v, (const void *)(uintptr_t)(a + i), 8);
                    ZLOGI("  +%#02x: %016llx", i, v);
                    // 若像映像内地址，按 C 字符串打出来
                    extern unsigned char *za_guest_base;
                    if (za_sdk_base && v >= za_sdk_base && v < za_sdk_base + za_sdk_size)
                    {
                        const char *str = (const char *)(uintptr_t)v;
                        int ok = 0;
                        for (int k = 0; k < 96; k++) { if (!str[k]) { ok = 1; break; } if ((unsigned char)str[k] < 0x20) break; }
                        if (ok) ZLOGI("      ^ sdk 字符串: \"%s\"", str);
                    }
                    else if (za_guest_base && v >= (unsigned long long)(uintptr_t)za_guest_base &&
                             v < (unsigned long long)(uintptr_t)za_guest_base + ZA_IMAGE_SIZE)
                    {
                        const char *str = (const char *)(uintptr_t)v;
                        int ok = 0;
                        for (int k = 0; k < 96; k++) { if (!str[k]) { ok = 1; break; } if ((unsigned char)str[k] < 0x20) break; }
                        if (ok) ZLOGI("      ^ main 字符串: \"%s\"", str);
                    }
                }
            }
        }
        // ★ 最近一次 svc#44 映射的物理区（前 0x200 字节）
        {
            extern unsigned long long za_dbg_last_phys_addr, za_dbg_last_phys_size;
            unsigned long long a = za_dbg_last_phys_addr;
            if (a && za_va_plausible(a))
            {
                ZLOGI("ZaGuest: PHYSMAP last %#llx+%#llx 内容前 0x80：",
                      a, za_dbg_last_phys_size);
                for (int i = 0; i < 0x80; i += 0x20)
                {
                    unsigned long long w[4];
                    memcpy(w, (const void *)(uintptr_t)(a + i), 32);
                    ZLOGI("  +%#04x: %016llx %016llx %016llx %016llx",
                          i, w[0], w[1], w[2], w[3]);
                }
            }
        }
        // ★ 最近 16 次 svc 的返回值环形记录
        {
            extern void za_dump_ret_ring(void);
            za_dump_ret_ring();
        }
        // ★ 最近一次等待类 svc 的返回值
        {
            extern volatile long za_dbg_last_wait_nr, za_dbg_last_wait_ret;
            char *q = buf;
            q = za_put_str(q, "ZaGuest: LAST-WAIT nr=");
            q = za_put_dec(q, (unsigned long long)za_dbg_last_wait_nr);
            q = za_put_str(q, " ret=");
            q = za_put_hex(q, (unsigned long long)za_dbg_last_wait_ret);
            q[0] = 10; q++;
            za_fatal_write(buf, (size_t)(q - buf));
        }
        // ★ 最近一次 WaitForAddress 的锁字现场（活锁排查）
        {
            extern unsigned long long za_dbg_last_wait;
            unsigned long long a = za_dbg_last_wait;
            if (a && za_va_plausible(a))
            {
                for (int i = -2; i < 6; i++)
                {
                    char *q = buf;
                    q = za_put_str(q, "ZaGuest: WAITWORD[");
                    q = za_put_hex(q, (unsigned long long)(a + i * 8));
                    q = za_put_str(q, "]=");
                    q = za_put_hex(q, *(unsigned long long *)(uintptr_t)(a + i * 8));
                    q[0] = 10; q++;
                    za_fatal_write(buf, (size_t)(q - buf));
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
        za_fatal_dump_pool[zi] = 0;
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

// 本 .so 自己的映射范围：致命处理器要先判断「这个故障是不是我们该管的」
// （客机映像 / SDK 映像 / 本 .so）。不是就交回原来的处理器 ——
// 否则会把 ART 的隐式空指针检查、bionic 自己的故障处理全都抢掉。
void za_install_signal_handlers(void);
static void za_compute_self_range(void)
{
    Dl_info di;
    memset(&di, 0, sizeof di);
    if (!dladdr((void *)(uintptr_t)&za_install_signal_handlers, &di) || !di.dli_fbase)
        return;
    unsigned long bias = (unsigned long)di.dli_fbase;
    const unsigned char *p = (const unsigned char *)bias;
    unsigned long lo = 0, hi = 0;
    if (memcmp(p, "\177ELF", 4) == 0)
    {
        unsigned long phoff = *(const unsigned int *)(p + 0x20);
        unsigned int phentsize = *(const unsigned short *)(p + 0x36);
        unsigned int phnum = *(const unsigned short *)(p + 0x38);
        lo = ~0ul;
        for (unsigned i = 0; i < phnum && i < 32; i++)
        {
            const unsigned char *ph = p + phoff + (unsigned long)i * phentsize;
            if (*(const unsigned int *)ph != 1) continue;          /* PT_LOAD */
            unsigned long va = *(const unsigned long *)(ph + 0x10);
            unsigned long memsz = *(const unsigned long *)(ph + 0x28);
            if (va < lo) lo = va;
            if (va + memsz > hi) hi = va + memsz;
        }
    }
    if (hi == 0) { lo = 0; hi = 0x400000; }
    za_self_base = bias + lo;
    za_self_end = bias + hi;
}
// ── libart.so 装载基址（只用于识别一类 ART 自身缺陷，见 za_fatal_handler）──
// 在初始化时扫一次 /proc/self/maps（绝不能在信号处理器里扫）。
static void za_probe_libart(void)
{
    if (za_libart_base) return;
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return;
    static char mbuf[512 * 1024];
    ssize_t n = 0, r;
    while (n < (ssize_t)sizeof mbuf - 1 &&
           (r = read(fd, mbuf + n, sizeof mbuf - 1 - (size_t)n)) > 0)
        n += r;
    close(fd);
    mbuf[n] = 0;
    char *p = mbuf;
    while (p && *p && !za_libart_base)
    {
        char *nl = p;
        while (*nl && *nl != 10) nl++;
        int had_nl = (*nl == 10);
        if (had_nl) *nl = 0;
        if (strstr(p, "/libart.so"))
        {
            // 形如 "6e00000000-6e08000000 r-xp 00000000 fd:00 123 /apex/.../libart.so"
            unsigned long long a = 0, b = 0;
            const char *q = p;
            while (*q && *q != '-') { int c = *q++; if (c >= '0' && c <= '9') a = a * 16 + (unsigned)(c - '0'); else if (c >= 'a' && c <= 'f') a = a * 16 + (unsigned)(c - 'a' + 10); }
            if (*q == '-') q++;
            while (*q) { int c = *q; if (c >= '0' && c <= '9') { b = b * 16 + (unsigned)(c - '0'); q++; } else if (c >= 'a' && c <= 'f') { b = b * 16 + (unsigned)(c - 'a' + 10); q++; } else break; }
            if (a && b > a) { za_libart_base = (unsigned long)a; za_libart_end = (unsigned long)b; }
        }
        if (!had_nl) break;
        p = nl + 1;
    }
}


// ── nn::async 作业计数探针 ─────────────────────────────────────────────
// 在 ExecutionScheduler::Enqueue(sdk+0x8d2c0) 与 DequeueAndCall(sdk+0x8d550)
// 首指令处装计数探针：入口改成 b <桩>，桩做「计数 → 补执行原首指令 → 回入口+4」。
// 桩里的字面量存宿主函数地址，用 ldr/br 跳（blr 可跨任意距离，避开 b 的 ±128MB）。
volatile unsigned long za_async_enq, za_async_exec;
static void za_async_inc_enq(void) { __atomic_add_fetch(&za_async_enq, 1, __ATOMIC_RELAXED); }
static void za_async_inc_exec(void) { __atomic_add_fetch(&za_async_exec, 1, __ATOMIC_RELAXED); }
static int za_async_probe_done;

void za_install_async_probe(void)
{
    extern volatile unsigned long za_sdk_base, za_sdk_size;
    if (za_async_probe_done || !za_sdk_base) return;
    za_async_probe_done = 1;
    unsigned char *sb = (unsigned char *)(uintptr_t)za_sdk_base;
    // 桩区：sdk+16MB，b 偏移在 ±128MB 内（入口在 sdk+0x8d2c0 附近）
    unsigned char *stub = MAP_FAILED;
    // 依次尝试几个「SDK 映像之外、但离入口 <128MB」的位置
    static const unsigned long cands[] = { 0x4000000ul, 0x8000000ul, 0x2000000ul, 0x6000000ul };
    for (unsigned ci = 0; ci < 4 && stub == MAP_FAILED; ci++)
        stub = (unsigned char *)mmap((void *)(uintptr_t)(za_sdk_base + cands[ci]), 0x1000,
                                     PROT_READ | PROT_WRITE | PROT_EXEC,
                                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (stub == MAP_FAILED) { ZLOGE("async 探针桩区映射失败"); return; }
    static const unsigned long entries[2] = { 0x8d2c0, 0x8d550 };
    void (*fns[2])(void) = { za_async_inc_enq, za_async_inc_exec };
    for (int i = 0; i < 2; i++) {
        unsigned int *ep = (unsigned int *)(sb + entries[i]);
        unsigned int orig = *ep;
        unsigned int *st = (unsigned int *)(stub + i * 0x20);
        st[0] = 0x58000050u;                      // ldr x16,[pc,#8]
        st[1] = 0xD63F0200u;                      // blr x16
        *(void **)(st + 2) = (void *)fns[i];      // 字面量
        st[4] = orig;                             // 原首指令
        long off = ((long)(sb + entries[i] + 4) - (long)((unsigned char *)&st[5])) >> 2;
        st[5] = 0x14000000u | ((unsigned long)off & 0x3FFFFFFu);   // b 入口+4
        // 入口：b 桩
        long boff = ((long)((unsigned char *)st) - (long)(sb + entries[i])) >> 2;
        if (mprotect((void *)((uintptr_t)(sb + entries[i]) & ~0xfffull), 0x1000,
                     PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            ZLOGE("async 探针 mprotect 失败"); return;
        }
        *ep = 0x14000000u | ((unsigned long)boff & 0x3FFFFFFu);
        __builtin___clear_cache((char *)ep, (char *)ep + 4);
    }
    __builtin___clear_cache((char *)stub, (char *)stub + 0x40);
    ZLOGI("★ async 计数探针已装：enq@%#x exec@%#x（桩 %p）",
          entries[0], entries[1], (void *)stub);
}

// 装好致命信号的处理器（SIGSEGV/BUS/ILL/FPE/ABRT/SYS）。
// ⚠ 必须每次 svc 后重装：SDK 初始化会**替换**掉我们装的 SIGSEGV 处理器
//   ⇒ 客机崩了就没人接，直接被内核杀掉（连日志都没有）。
void za_install_async_probe(void);
void za_reinstall_signal_handlers(void)
{
    za_install_altstack();
    za_probe_libart();
    za_install_async_probe();
    if (!za_self_base) za_compute_self_range();
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = za_segv_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    static const int fatal[] = { SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT, SIGSYS };
    for (unsigned i = 0; i < sizeof fatal / sizeof fatal[0]; i++)
    {
        int s = fatal[i];
        struct sigaction old;
        memset(&old, 0, sizeof old);
        if (sigaction(s, &sa, &old) == 0 && old.sa_sigaction != za_segv_handler)
        {
            za_fatal_prev[s] = old;
            za_fatal_prev_ok[s] = 1;
        }
    }
}

// 接管 32..62（63 留给 PC 采样器；SIGRTMIN=42 是 bionic 内部定时器，不抢）
void za_install_rt_catch(void)
{
    // ★ sigaction 是**进程级**的，装一次就够；以前每次 svc 都重装一遍
    //   （每秒上千次），和 ART 自己装/查处理器抢，真机上 ART 的
    //   "Jit thread pool" 线程随后崩在 art::MemMapArenaPool::TrimMaps。
    //   需要每次 svc 重做的只有**线程级**的信号掩码（SDK 会把实时信号段全屏蔽）。
    static volatile int rt_installed;
    if (__atomic_exchange_n(&rt_installed, 1, __ATOMIC_ACQ_REL)) return;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = za_rt_catch;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    // ⚠ 只接 **40..62**。低位实时信号是宿主自己的：
    //   32 = SIGRTMIN（bionic debuggerd）、33 = BIONIC_SIGNAL_PROFILER（simpleperf）、
    //   34.. = ART 的线程挂起/检查点信号。
    //   以前从 32 开始一路装到 62，把 ART 的挂起信号处理器也抢了 ⇒
    //   ART 的 JIT/挂起机制坏掉，真机表现为 "Jit thread pool" 线程在
    //   libart+0x791558 上解引用 null+0x10 崩溃、进程被带走。
    for (int s = 40; s <= 62; s++)
        sigaction(s, &sa, NULL);
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
    unsigned long tp16;             // 仅作诊断保留（不再读写 bionic TLS！）
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

// ★ 2026-10-26：不再碰 bionic TLS 的 [tp16+0x98]。
//   客机的 TLS 基址已经全部走常数/每线程页，这一槽谁都不读了；
//   而 `tp16 = TPIDR & ~0x1FFF` 对新线程可能落在**未映射**区
//   （实测：新线程 install 里读 [b16+0x98] 直接 SIGSEGV，b16=0x70b147e000）。
void za_tls_enter(void)
{
    za_tls_state_t *st = za_tls_cur();
    if (st->depth < ZA_TLS_STACK) st->saved[st->depth] = za_get_tls();
    st->depth++;
}
void za_tls_leave(void)
{
    za_tls_state_t *st = za_tls_cur();
    if (st->depth > 0) st->depth--;
}

// 只读 TLS 页的绝对地址（za_horizon.c 的临界区按同一来源取 owner_id）
// za_ro_tls_page 由 za_sdk.c 定义并写入（SDK 装载时填真实页地址）
extern volatile unsigned long za_ro_tls_page;

void za_os_install_tls_descriptor(void)
{
    za_tls_state_t *st_chk = za_tls_cur();
    if (st_chk->area) return;            // 本线程已装过（幂等）
    void *b = za_get_tls();
    if (!b) { ZLOGE("读不到 TPIDR_EL0"); return; }
    unsigned long b16 = (unsigned long)b & ~0x1FFFul;
    // 客机算 `add x8, tp16, x9, lsl #3`，x9 是 **32 位有符号偏移**
    // ⇒ 变量区必须落在 tp16 + (int32 范围) 内，且越近越好；bionic 上方多半被占，
    //   所以逐页往上找空位（找不到就退回任意地址并明确报出来）。
    // ★ 每线程块 = [头页 D(4KB)] [TLS 变量区 A(4MB)] [RO 页 ...]
    //   [TP+0x40] = D；D+0x98 = (A-D)/8 ⇒ helper 的 `ldr; add` 自然算出 A。
    size_t area = 4 * 1024 * 1024 + 0x1000;
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
    st->tp16 = (unsigned long)b16;      // 仅诊断：不要拿它去读写内存
    st->tp = b;
    unsigned char *hdr = (unsigned char *)t;          // 头页 D
    unsigned char *area_p = hdr + 0x1000;             // TLS 变量区 A
    st->area = area_p;
    // D+0x98 = (A-D)/8 ⇒ 客机 helper 的 `ldr x9,[D,#0x98]; add D,x9,lsl#3` = A
    *(unsigned long long *)(hdr + 0x98) = (unsigned long long)((area_p - hdr) / 8);
    // 有些站点把「TPIDR & ~0x1FFF」当线程上下文对象用（ldr [ctx]; ldr [ctx+0x10]; blr）
    // ⇒ D[0] 放一个最小 vtable（槽 2/3 = 宿主 Allocate/Free）。
    {
        unsigned long long *vt = (unsigned long long *)(hdr + 0x100);
        vt[2] = (unsigned long long)(uintptr_t)&za_fs_vt_alloc;
        vt[3] = (unsigned long long)(uintptr_t)&za_fs_vt_free;
        *(unsigned long long *)(hdr) = (unsigned long long)(uintptr_t)vt;
    }
    // ★ 每线程的 svc 寄存器槽（gate trampoline 用 TPIDR_EL0 现取）。
    //   布局：hdr+0xA0 = 槽地址；槽本体在 hdr+0x200（32 个 u64，末槽放魔数）。
    //   以前这是一张全局数组，多线程并发 svc 会互相覆盖 nr / x1..x7。
    {
        unsigned long long *regs = (unsigned long long *)(hdr + 0x200);
        memset(regs, 0, 32 * sizeof(unsigned long long));
        regs[31] = 0x5a5a524547535f31ull;          /* "ZA_REGS_1" */
        *(unsigned long long *)(hdr + 0xA0) = (unsigned long long)(uintptr_t)regs;
    }
    // ★★ 每线程的 svc 门宿主栈（hdr+0xA8 = 栈顶）。
    //   以前门里 `mov sp, <全局栈顶>; sub sp,#0x80`：**所有线程共用同一条栈**，
    //   两个线程并发进 svc 时栈帧完全重叠 ⇒ C 局部变量/canary 互相踩烂
    //   （实测 libc 报 "stack corruption detected (-fstack-protector)" → abort）。
    //   512KB/线程足够深（C 调度链最深处几十 KB）。
    {
        size_t hsz = 512u << 10;
        void *hs = mmap(NULL, hsz, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (hs == MAP_FAILED)
        {
            ZLOGE("每线程宿主栈 mmap 失败（%zu 字节）⇒ svc 门会退回全局栈", hsz);
            *(unsigned long long *)(hdr + 0xA8) = 0;
        }
        else
        {
            *(unsigned long long *)(hdr + 0xA8) =
                ((unsigned long long)(uintptr_t)hs + hsz) & ~0xFull;   // 栈顶，16 对齐
        }
    }
    // ★ 把本线程的头页指针写进 bionic TLS 的空闲槽 [TP+0x40]。
    //   实测三个线程该位置都是已映射的 0（主程序静态 TLS 区为空）。
    //   不写 TPIDR_EL0（EL0 不可写），也不需要任何宿主调用。
    *(unsigned long long *)((unsigned long)b + 0x40) = (unsigned long long)(uintptr_t)hdr;

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
        // ★★ [ro+0x1f0] 是「本线程 TPIDR_EL0」。`msr TPIDR_EL0` 的站点已全部
        //   NOP 掉（见 za_tlsbase_patch.h），所以这个槽**只作为数据**被 SDK 读。
        //   关键是 fs 模块拿它算 `TP - 0x18` 当每线程链表头：
        //     sdk+0x98344: mrs x8,TPIDRRO_EL0 / ldr x8,[x8,#0x1f0]
        //                  sub x0,x8,#0x18 / bl 97940   ← 往链表插入
        //   以前这里放的是 bionic 的 TP ⇒ 链表头落进 bionic TCB，插入时把
        //   bionic TLS 写坏，崩在 libc（pc=syscall+0x28，x20=TP-0x18）。
        //   ⇒ 给客机一块**自己的** 0x200 字节零区，TP 指向它的 +0x18：
        //     TP-0x18 = 块基址（可写、每线程、与 bionic 无关）。
        {
            unsigned char *tpblk = (unsigned char *)hdr + 0x800;
            memset(tpblk, 0, 0x200);
            *(unsigned long long *)(ro + 0x1f0) =
                (unsigned long long)(uintptr_t)(tpblk + 0x18);
        }
        // owner_id 必须非 0，且要和 svc#37 GetThreadId 同源（用宿主 tid 目前自洽）
        *(unsigned int *)(ro2 + 0x1b0) = (unsigned int)syscall(SYS_gettid);
        st->ro = ro;
    }
    // 自检：写进去的 [TP+0x40] 是否真的读得回来，以及 helper 公式算出的地址
    {
        unsigned long long rd = 0;
        memcpy(&rd, (unsigned long long *)((unsigned long)b + 0x40), 8);
        unsigned long long slot = 0;
        if (rd) memcpy(&slot, (void *)(uintptr_t)(rd + 0x98), 8);
        ZLOGI("客机 TLS 自检: [TP+0x40]=%#llx（应=%p） slot=%#llx ⇒ A=%#llx（应=%p）",
              rd, (void *)hdr, slot, rd + slot * 8, (void *)area_p);
    }
    ZLOGI("客机 TLS: tp=%p 变量区=%p RO页=%p", b, t, st->ro);

    // ── 探针：[tp+0x40] 能否当「每线程 TLS 基址指针」槽 ──────────────
    // bionic 的 TCB 槽是 [tp+0..0x38]（8 个槽），之后是主可执行文件的静态
    // TLS 区。若它的 PT_TLS 很小/为 0，[tp+0x40..] 就是空闲且已映射的
    // ⇒ 客机的 TLS 访问可以用 **2 条指令**（mrs tp ; ldr Xt,[tp,#0x40]）
    //   拿到每线程基址，不用宿主调用。
    // 用 process_vm_readv 安全探测（未映射不会崩）。
    {
        static int n;
        if (n++ < 3)
        {
            unsigned long offs[] = { 0x40, 0x48, 0x80, 0xC0, 0x100, 0x200 };
            char line[256];
            char *p = line;
            p += snprintf(p, sizeof line - (size_t)(p - line), "tp+off 探针 tid=%ld:", (long)syscall(SYS_gettid));
            for (unsigned i = 0; i < sizeof offs / sizeof offs[0]; i++)
            {
                unsigned long q = 0;
                struct iovec l = { &q, 8 }, r2 = { (void *)((unsigned long)b + offs[i]), 8 };
                ssize_t got = process_vm_readv(getpid(), &l, 1, &r2, 1, 0);
                p += snprintf(p, sizeof line - (size_t)(p - line), " +%#lx=%s%#lx",
                              offs[i], got == 8 ? "" : "unmapped/", got == 8 ? q : 0ul);
            }
            ZLOGI("%s", line);
        }
    }
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

// NVN 图形入口：客机给它函数名，它回函数地址。
// 实现在 za_nvn.c：main 用 (device=NULL, 名字) 调 nvnDeviceGetProcAddress 批量解析 534 个
// 入口，所以这里和那条路径必须共用同一张表。
static void *za_nvn_bootstrap_loader(const char *name)
{
    return za_nvn_bootstrap(name);
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
// hid 初始化桩：返回 Result=0（u32 在 w0，不能用 void 函数 —— w0 会是野值）。
static unsigned int za_hid_init_ok(void) { return 0; }
// hid 的「设置」类 API 返回 void；内部会调 detail（需要真服务），
// 现阶段直接吞掉，避免它们把未初始化的服务错误当成致命错误 Abort。
static void za_hid_noop(void) { }

// ── 最小 fs 垫片（读路径）+ 内嵌 romfs 文件 ────────────────────────
// 静态构造函数里是 OpenFile → GetFileSize → (ReadFile) → CloseFile。
// 只接管 OpenFile 的话，GetFileSize 仍会走 CMIF 返回 0x177a02 ⇒ 重试后 Abort。
//
// 客机要读的默认配置 system/config/data/trinity_config.trowc 在 romfs 里
// 确实存在（729 字节），已经把它内嵌进 .so（za_romfs_embed.h）。
// 路径按「后缀」匹配，忽略 rom:/ 之类的挂载前缀。
// ⚠ 其余路径仍然返回「空文件」；接真正的 romfs 后端后整块撤掉。
typedef struct { const char *path; const unsigned char *data; unsigned long size; } za_embed_file_t;
// 未知的 .json（存档/用户配置）返回合法的空对象 "{}"。
// 空文件不是合法 JSON，解析器会直接失败；"{}" 至少能让它走默认值分支。
static const unsigned char za_embed_empty_json[2] = { '{', '}' };

static const za_embed_file_t za_embed_files[] = {
    { "system/config/data/trinity_config.trowc",
      za_romfs_trinity_config_trowc, ZA_ROMFS_TRINITY_CONFIG_SIZE },
    { ".json", za_embed_empty_json, 2 },
};
#define ZA_EMBED_N ((int)(sizeof za_embed_files / sizeof za_embed_files[0]))
#define ZA_EMBED_HANDLE_BIT 0x80000000u

static unsigned long za_guest_strnlen(const char *p, unsigned long max)
{
    unsigned long n = 0;
    if (!p) return 0;
    while (n < max && p[n]) n++;
    return n;
}
static int za_embed_lookup(const char *path)
{
    unsigned long pl = za_guest_strnlen(path, 512);
    if (!pl) return -1;
    for (int i = 0; i < ZA_EMBED_N; i++)
    {
        const char *suf = za_embed_files[i].path;
        unsigned long n = za_guest_strnlen(suf, 512);
        if (pl < n) continue;
        if (memcmp(path + (pl - n), suf, (size_t)n) == 0) return i;
    }
    return -1;
}
// 未知文件的句柄 → 路径（诊断用；后续接真实文件后端也用这张表）
#define ZA_FS_MAXH 32
static char za_fs_paths[ZA_FS_MAXH][192];
static int za_fs_hidx(unsigned int h) { return (h & 0x40000000u) ? (int)(h & 0x3FFFFFFFu) : -1; }
static const char *za_fs_path_of(unsigned int h)
{
    int i = za_fs_hidx(h);
    if (i < 0 || i >= ZA_FS_MAXH || !za_fs_paths[i][0]) return "?";
    return za_fs_paths[i];
}

// ── 真实文件后端 ───────────────────────────────────────────────
// 客机路径形如 "data:/arc/data.trpfs"、"data:/system/config/..."。
// 映射到平板上的应用私有目录（adb push 到这里，App 无需任何权限）：
//   /sdcard/Android/data/<pkg>/files/romfs/<去掉 scheme 的路径>
#define ZA_FS_ROOT "/sdcard/Android/data/org.pokelegza.android.port/files/romfs/"
#define ZA_FS_HANDLE_BIT 0x20000000u

static const char *za_fs_rel(const char *path)
{
    if (!path) return NULL;
    const char *p = path;
    for (int i = 0; i < 16 && p[i]; i++)
    {
        if (p[i] == ':') { p += i + 1; break; }
        if (p[i] == '/') break;          // 没有 scheme
    }
    while (*p == '/') p++;
    return p;
}
static int za_fs_handle_fd(unsigned int h)
{
    return (h & ZA_FS_HANDLE_BIT) ? (int)(h & 0x0FFFFFFFu) : -1;
}

static const unsigned char *za_embed_by_handle(unsigned int h, unsigned long *size)
{
    if (size) *size = 0;
    if ((h & ZA_EMBED_HANDLE_BIT) == 0) return NULL;
    unsigned i = h & ~ZA_EMBED_HANDLE_BIT;
    if (i >= (unsigned)ZA_EMBED_N) return NULL;
    if (size) *size = za_embed_files[i].size;
    return za_embed_files[i].data;
}
static unsigned int za_fs_getfilesize(long long *out, unsigned int h)
{
    unsigned long sz = 0;
    za_embed_by_handle(h, &sz);
    {
        int fd = za_fs_handle_fd(h);
        if (fd >= 0)
        {
            off_t end = lseek(fd, 0, SEEK_END);
            sz = (end > 0) ? (unsigned long)end : 0;
        }
    }
    if (out) *out = (long long)sz;
    {
        static int n;
        if (n++ < 24)
            ZLOGE("★ fs::GetFileSize(h=%#x \"%s\") => %lld", h, za_fs_path_of(h),
                  (long long)sz);
    }
    return 0;
}
static unsigned int za_fs_readfile_cnt(unsigned long *out_read, unsigned int h,
                                       long long off, void *buf, unsigned long size)
{
    unsigned long total = 0;
    const unsigned char *d = za_embed_by_handle(h, &total);
    if (out_read) *out_read = 0;
    {
        int fd = za_fs_handle_fd(h);
        if (fd >= 0)
        {
            if (off < 0) off = 0;
            if (!buf || !size) return 0;
            ssize_t n = pread(fd, buf, (size_t)size, (off_t)off);
            if (n < 0) n = 0;
            if (out_read) *out_read = (unsigned long)n;
            {
                static int lg2;
                if (lg2++ < 32)
                    ZLOGE("★ fs::ReadFile(fd=%d \"%s\" off=%lld size=%lu) => %zd",
                          fd, za_fs_path_of(h), off, size, n);
            }
            return 0;
        }
    }
    if (!d)
    {
        if (buf && size && size <= (4u << 20)) memset(buf, 0, (size_t)size);
        return 0;
    }
    {
        static int lg;
        if (lg++ < 32)
            ZLOGE("★ fs::ReadFile(h=%#x \"%s\" off=%lld size=%lu) => 0（空文件）",
                  h, za_fs_path_of(h), off, size);
    }
    if (off < 0) off = 0;
    if (!buf || (unsigned long long)off >= total) return 0;
    unsigned long n = (unsigned long)(total - (unsigned long long)off);
    if (n > size) n = size;
    memcpy(buf, d + (unsigned long)off, (size_t)n);
    if (out_read) *out_read = n;
    return 0;
}
static unsigned int za_fs_readfile(unsigned int h, long long off, void *buf, unsigned long size)
{
    return za_fs_readfile_cnt(NULL, h, off, buf, size);
}
static unsigned int za_fs_closefile(unsigned int h)
{
    int fd = za_fs_handle_fd(h);
    if (fd >= 0) close(fd);
    return 0;
}
static unsigned int za_fs_flushfile(unsigned int h) { (void)h; return 0; }
static unsigned int za_fs_setfilesize(unsigned int h, long long sz) { (void)h; (void)sz; return 0; }
static unsigned int za_fs_createfile(const char *p, int mode) { (void)p; (void)mode; return 0; }
static unsigned int za_fs_deletefile(const char *p) { (void)p; return 0; }
static unsigned int za_fs_createdir(const char *p) { (void)p; return 0; }
// ── mount / 目录：同样走“空 fs” ────────────────────────────────
// 这些调用以前要经过 CMIF 应答（我们知道那条路会返回 0x1a80a 一类错误），
// 静态构造函数在 mount 失败后也会 Abort。直接接管成成功/空目录。
// ⚠ 临时：真 fs 后端接入后撤掉。
static unsigned int za_fs_mount(const char *mount) { (void)mount; return 0; }
static unsigned int za_fs_mount2(const char *mount, int idx, void *cache, unsigned long sz)
{ (void)mount; (void)idx; (void)cache; (void)sz; return 0; }
static unsigned int za_fs_mount_rom(const char *mount, void *cache, unsigned long sz)
{ (void)mount; (void)cache; (void)sz; return 0; }
static unsigned int za_fs_unmount(const char *mount) { (void)mount; return 0; }
static unsigned int za_fs_commit(const char *mount) { (void)mount; return 0; }
static unsigned int za_fs_opendir(unsigned int *out, const char *path, int mode)
{
    (void)path; (void)mode;
    if (out) *out = 1;          // 假目录句柄
    return 0;
}
static unsigned int za_fs_readdir(long long *out_count, void *entries,
                                  unsigned int h, long long max)
{
    (void)entries; (void)h; (void)max;
    if (out_count) *out_count = 0;   // 空目录
    return 0;
}
static unsigned int za_fs_closedir(unsigned int h) { (void)h; return 0; }
static unsigned int za_fs_dircount(long long *out, unsigned int h)
{
    (void)h;
    if (out) *out = 0;
    return 0;
}

// DirectoryEntryType: 0=Directory, 1=File（这里一律当文件）
static unsigned int za_fs_getentrytype(unsigned int *out, const char *p)
{
    (void)p;
    if (out) *out = 1;
    return 0;
}

// nn::fs::OpenFile(FileHandle* out, const char* path, int mode)
// main 的静态构造函数里会开一个文件并用 16 次重试等它出现；失败就 Abort。
// 我们的 fs 服务还没有实现「指针缓冲」那一层（路径字符串走 PointerAndSize
// 描述符，宿主看不到），所以先在这里截住、把路径打出来，同时给出成功。
// TODO: 接真正的 romfs/save 后端后撤掉。
static unsigned int za_fs_openfile(void *out, const char *path, int mode)
{
    char tmp[256];
    unsigned i = 0;
    if (path)
    {
        for (; i < sizeof tmp - 1; i++)
        {
            char c = path[i];
            if (!c) break;
            tmp[i] = (c >= 0x20 && c < 0x7f) ? c : '?';
        }
    }
    tmp[i] = 0;
    int idx = za_embed_lookup(path);
    if (idx >= 0)
    {
        unsigned int h = ZA_EMBED_HANDLE_BIT | (unsigned)idx;
        ZLOGE("★ fs::OpenFile out=%p path=\"%s\" mode=%d ⇒ 内嵌文件（%lu 字节，句柄 %#x）",
              out, tmp, mode, za_embed_files[idx].size, h);
        if (out) *(unsigned int *)out = h;
        return 0;
    }
    {
        const char *rel = za_fs_rel(path);
        if (rel && *rel && za_guest_strnlen(rel, 200) < 200)
        {
            char hp[256];
            int hn = snprintf(hp, sizeof hp, "%s%s", ZA_FS_ROOT, rel);
            if (hn > 0 && hn < (int)sizeof hp)
            {
                static int nreal;
                int fd = open(hp, O_RDONLY | O_CLOEXEC);
                if (fd >= 0)
                {
                    if (nreal++ < 16)
                        ZLOGE("★ fs::OpenFile path=\"%s\" ⇒ 真实文件 %s（fd=%d）",
                              tmp, hp, fd);
                    if (out) *(unsigned int *)out = ZA_FS_HANDLE_BIT | (unsigned)fd;
                    return 0;
                }
                if (nreal++ < 16)
                    ZLOGE("★ fs::OpenFile path=\"%s\" ⇒ 宿主文件不存在：%s", tmp, hp);
            }
        }
    }
    {
        static unsigned gi;
        unsigned i = gi++ % ZA_FS_MAXH;
        unsigned n = 0;
        while (tmp[n] && n < sizeof za_fs_paths[i] - 1) { za_fs_paths[i][n] = tmp[n]; n++; }
        za_fs_paths[i][n] = 0;
        ZLOGE("★ fs::OpenFile out=%p path=\"%s\" mode=%d ⇒ 未知文件（句柄 %#x）",
              out, tmp, mode, 0x40000000u | i);
        if (out) *(unsigned int *)out = 0x40000000u | i;
    }
    return 0;
}

static const za_host_sym_t za_host_syms[] = {
    // loader 提供的「runtime object file」（真机由 nnrtld 提供）
    { "__nnDetailNintendoSdkRuntimeObjectFile", (void *)za_host_runtime_object_file },

    // ── hid 初始化：先接管成「成功」──────────────────────────────
    // nn::hid::InitializeNpad 会通过 CMIF 连 hid 服务、建共享内存；
    // 我们目前的伪造服务应答让它的内部解析返回 Result 0x1a80a，
    // 它在 main+0x19dca1c 处的 Result 检查里直接 Abort。
    // 现阶段的目标是进 nnMain，输入设备还没有接；先让它返回 0。
    // ⚠ 这是**临时**接管（可逆）：真正的 hid 服务/共享内存实现后要撤掉，
    //   否则 GetNpadState 之类的调用会读到未初始化的服务状态。
    { "_ZN2nn3hid14InitializeNpadEv", (void *)za_hid_init_ok },
    { "_ZN2nn3hid21InitializeTouchScreenEii", (void *)za_hid_init_ok },
    { "_ZN2nn3hid25InitializeVibrationDeviceERKNS0_21VibrationDeviceHandleE", (void *)za_hid_init_ok },
    { "_ZN2nn3hid22SetSupportedNpadIdTypeEPKjm", (void *)za_hid_noop },
    { "_ZN2nn2fs8OpenFileEPNS0_10FileHandleEPKci", (void *)za_fs_openfile },
    { "_ZN2nn2fs11GetFileSizeEPlNS0_10FileHandleE", (void *)za_fs_getfilesize },
    { "_ZN2nn2fs8ReadFileEPmNS0_10FileHandleElPvm", (void *)za_fs_readfile_cnt },
    { "_ZN2nn2fs8ReadFileENS0_10FileHandleElPvm", (void *)za_fs_readfile },
    { "_ZN2nn2fs9CloseFileENS0_10FileHandleE", (void *)za_fs_closefile },
    { "_ZN2nn2fs9FlushFileENS0_10FileHandleE", (void *)za_fs_flushfile },
    { "_ZN2nn2fs11SetFileSizeENS0_10FileHandleEl", (void *)za_fs_setfilesize },
    { "_ZN2nn2fs10CreateFileEPKcl", (void *)za_fs_createfile },
    { "_ZN2nn2fs10DeleteFileEPKc", (void *)za_fs_deletefile },
    { "_ZN2nn2fs15CreateDirectoryEPKc", (void *)za_fs_createdir },
    { "_ZN2nn2fs12GetEntryTypeEPNS0_18DirectoryEntryTypeEPKc", (void *)za_fs_getentrytype },
    { "_ZN2nn2fs13MountSaveDataEPKcRKNS_7account3UidE", (void *)za_fs_mount },
    { "_ZN2nn2fs21MountSaveDataReadOnlyEPKcNS_13ApplicationIdERKNS_7account3UidE", (void *)za_fs_mount2 },
    { "_ZN2nn2fs14EnsureSaveDataERKNS_7account3UidE", (void *)za_fs_mount },
    { "_ZN2nn2fs8MountRomEPKc", (void *)za_fs_mount },
    { "_ZN2nn2fs8MountRomEPKcPvm", (void *)za_fs_mount_rom },
    { "_ZN2nn2fs17MountAddOnContentEPKciPvm", (void *)za_fs_mount2 },
    { "_ZN2nn2fs7UnmountEPKc", (void *)za_fs_unmount },
    { "_ZN2nn2fs6CommitEPKc", (void *)za_fs_commit },
    { "_ZN2nn2fs13OpenDirectoryEPNS0_15DirectoryHandleEPKci", (void *)za_fs_opendir },
    { "_ZN2nn2fs13ReadDirectoryEPlPNS0_14DirectoryEntryENS0_15DirectoryHandleEl", (void *)za_fs_readdir },
    { "_ZN2nn2fs14CloseDirectoryENS0_15DirectoryHandleE", (void *)za_fs_closedir },
    { "_ZN2nn2fs22GetDirectoryEntryCountEPlNS0_15DirectoryHandleE", (void *)za_fs_dircount },
    { "_ZN2nn3hid18SetNpadJoyHoldTypeENS0_15NpadJoyHoldTypeE", (void *)za_hid_noop },
    { "_ZN2nn3hid24SetSupportedNpadStyleSetENS_4util10BitFlagSetILi32ENS0_12NpadStyleTagEEE", (void *)za_hid_noop },

    // NVN 图形入口（图形层未接：回陷阱桩，客机一调就知道缺哪个）
    { "nvnBootstrapLoader", (void *)za_nvn_bootstrap_loader },

    // vi 客户端 API（显示 / 图层 / 原生窗口）。只接 main 导入的这 5 个，
    // Initialize/Finalize 仍走 SDK：SDK 内部还有别的模块读它的 vi 状态。
    { "_ZN2nn2vi18OpenDefaultDisplayEPPNS0_7DisplayE", (void *)za_vi_open_default_display },
    { "_ZN2nn2vi11CreateLayerEPPNS0_5LayerEPNS0_7DisplayE", (void *)za_vi_create_layer },
    { "_ZN2nn2vi15GetNativeWindowEPPvPNS0_5LayerE", (void *)za_vi_get_native_window },
    { "_ZN2nn2vi12DestroyLayerEPNS0_5LayerE", (void *)za_vi_destroy_layer },
    { "_ZN2nn2vi12CloseDisplayEPNS0_7DisplayE", (void *)za_vi_close_display },

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
// 诊断：C++ 的 new/delete 解析到哪里（决定客机对象在哪个堆上）。
void za_log_cpp_alloc_syms(void)
{
    // ★ 2026-10-27：C++ 的 new/delete 落到哪里直接决定客机对象在**哪个堆**上。
    //   落到 libc++_shared ⇒ 宿主 Scudo 堆；落到 SDK/main 的导出 ⇒ 客机自己的
    //   musl 堆。宿主堆被客机写坏一个 chunk header 就会 SIGABRT（Scudo 报错），
    //   所以这里把三个关键符号的解析结果打出来。
    {
        static const char *sym[] = { "_Znwm", "_Znam", "_ZdlPv", "_ZnwmRKSt9nothrow_t" };
        for (int i = 0; i < 4; i++) {
            void *f = za_resolve_host(sym[i]);
            const char *where = "?";
            if (!f) where = "无";
            else if (za_sdk_base && (unsigned long long)(uintptr_t)f >= za_sdk_base &&
                     (unsigned long long)(uintptr_t)f < za_sdk_base + za_sdk_size) where = "SDK";
            else if (za_guest_base && (unsigned long long)(uintptr_t)f >=
                                           (unsigned long long)(uintptr_t)za_guest_base &&
                     (unsigned long long)(uintptr_t)f <
                         (unsigned long long)(uintptr_t)za_guest_base + ZA_IMAGE_SIZE)
                where = "main";
            else where = "宿主";
            ZLOGI("C++ 分配符号 %-24s -> %p（%s）", sym[i], f, where);
        }
    }
}

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
// main 模块探针（定义在后面）
#define ZA_MPROBE_STUB  0x6048000u
#define ZA_MPROBE_SLOT  0x6049000u
static void za_hook_m_poolinit(unsigned long long *r);
static void za_hook_m_poolloop(unsigned long long *r);
static void za_hook_m_w2(unsigned long long *r);
static void za_hook_m_w3(unsigned long long *r);
static void za_hook_m_openfile(unsigned long long *r);
static void za_install_main_probe(unsigned char *base, unsigned int func_off,
                                  unsigned int stub_off, unsigned int hook_off,
                                  void (*hook)(unsigned long long *));

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
            // ★ 跳过已被 helper 补丁处理过的站点：那里 mrs 保持原样、下一条被换成
            //   `ldr Xd,[Xsrc,#0x40]`。不跳过就会把 mrs 再改成 `b 桩` ⇒ 桩返回
            //   area（不是 tp）⇒ `ldr [area+0x40]` 读到 0 ⇒ 崩在 +0x98。
            {
                unsigned int nxt = *(unsigned int *)(base + e->off + 4);
                unsigned int rs = e->orig & 0x1F;
                if ((nxt & 0xFFC00000u) == 0xF9400000u &&
                    ((nxt >> 10) & 0xFFFu) == (0x40u >> 3) &&
                    ((nxt >> 5) & 0x1Fu) == rs)
                    continue;
            }
            long long delta = (long long)e->stub - (long long)e->off;
            if (delta < -(1LL << 27) || delta >= (1LL << 27)) continue;
            *at = 0x14000000u | (unsigned int)((delta >> 2) & 0x3FFFFFF);
            // ★ 紧跟的 `and Xt, Xt, #~0x1FFF` 必须一起 nop：
            //   桩返回的已经是**客机 TLS 变量区 A**；保留 and 会把 A 向 8KB
            //   对齐取整（A = D+0x1000，取整后落回描述符页 D）⇒ 客机从
            //   [D+0xa0] 读到我们放在那里的 regs 指针，当成对象解引用
            //   ⇒ vtable=0，崩在 `ldr x8,[x8,#0x10]`（实测 main+0x11ce34）。
            {
                unsigned int rt2 = e->orig & 0x1Fu;
                // ⚠ `and` 不一定紧跟随 mrs：实测 0x11cdf4 是
                //   mrs x8 ; mov x19,x1 ; and x8,x8,#~0x1FFF
                //   ⇒ 要同时看 off+4 和 off+8。
                for (unsigned k = 1; k <= 2; k++)
                {
                    unsigned int nxt = *(unsigned int *)(base + e->off + k * 4);
                    if ((nxt & 0xFF800000u) == 0x92000000u &&
                        (nxt & 0x1F) == rt2 && ((nxt >> 5) & 0x1F) == rt2 &&
                        ((nxt >> 22) & 1u) == 1u &&
                        ((nxt >> 16) & 0x3Fu) == 51u &&
                        ((nxt >> 10) & 0x3Fu) == 50u)
                    {
                        *(unsigned int *)(base + e->off + k * 4) = 0xD503201Fu;
                        break;
                    }
                }
            }
            patched++;
        }
        // ★ 2026-10-27：main+0x11ce04 把 [TP+0xa0] 当「每线程分配器对象」用：
        //     x22 = [TP+0xa0]；非 0 ⇒ ldr x8,[x22]; blr [x8+0x10]（虚调用）
        //   NULL ⇒ 回退到全局分配器 main+0x3d993e8（nn::init 已建好）。
        //   我们的 mrs 桩返回 TLS **变量区 A**，[A+0xa0] 是客机的一个普通 TLS
        //   变量（真机实测值 0x80000），当对象指针解引用 ⇒ 崩在 `ldr x8,[x22]`
        //   （pc=main+0x11ce24, addr=0x80000）。
        //   ⇒ 这条 load 直接换成 `movz x22,#0`，强制走「全局分配器」回退分支。
        //      （原指令 ldr x22,[x8,#0xa0] = 0xf9405116）
        *(unsigned int *)(base + 0x11ce04) = 0xD2800016u;   // movz x22, #0
        ZLOGI("TLS 自检 0x11cdf4=%08x 0x11cdf8=%08x 0x11cdfc=%08x 0x11ce00=%08x",
              *(const unsigned int *)(base + 0x11cdf4),
              *(const unsigned int *)(base + 0x11cdf8),
              *(const unsigned int *)(base + 0x11cdfc),
              *(const unsigned int *)(base + 0x11ce00));
        ZLOGI("TLS mrs 改写：%u / %u 条已替换（桩区 %#x..%#x）",
              patched, (unsigned)ZA_TLS_MRS_COUNT,
              (unsigned)ZA_TLS_STUB_OFF, (unsigned)(ZA_TLS_STUB_OFF + ZA_TLS_STUB_SIZE));
        // ★ 指令缓存维护：ARM64 上「写了指令再执行」必须显式 IC 维护，
        //   否则 I-cache 可能还是旧内容 ⇒ 补丁随机不生效（与 za_sdk.c 同理）。
        __builtin___clear_cache((char *)base, (char *)base + ZA_TEXT_SIZE);
        __builtin___clear_cache((char *)base + ZA_TLS_STUB_OFF,
                                (char *)base + ZA_TLS_STUB_OFF + ZA_TLS_STUB_SIZE);
    }

    // ★ main 模块入口探针：桩放 0x6048000（随后 RX），hook 槽放 0x6049000（保持 RW）
    {
        za_install_main_probe(base, 0x1653cc0, ZA_MPROBE_STUB,        ZA_MPROBE_SLOT,        za_hook_m_poolinit);
        za_install_main_probe(base, 0x1653d00, ZA_MPROBE_STUB + 0x80, ZA_MPROBE_SLOT + 0x08, za_hook_m_poolloop);
        za_install_main_probe(base, 0x1a0a204, ZA_MPROBE_STUB + 0x100, ZA_MPROBE_SLOT + 0x10, za_hook_m_w2);
        za_install_main_probe(base, 0x1bab754, ZA_MPROBE_STUB + 0x180, ZA_MPROBE_SLOT + 0x18, za_hook_m_w3);
        // ⚠ 试过在 main+0x19554c0（`bl nn::fs::OpenFile`）装探针来抓路径：
        //   这条指令是 **bl**，桩重放后 x30 指向桩内，实测把后续控制流带进了
        //   main 的 BSS（pc=main+0x76b732c）。call 类指令不适合这套探针，已移除。
        __builtin___clear_cache((char *)base + ZA_MPROBE_STUB, (char *)base + ZA_MPROBE_STUB + 0x100);
        mprotect(base + ZA_MPROBE_STUB, 0x1000, PROT_READ | PROT_EXEC);
        ZLOGI("main 入口探针已装：0x1653cc0 / 0x1653d00（桩 %#x，槽 %#x）",
              (unsigned)ZA_MPROBE_STUB, (unsigned)ZA_MPROBE_SLOT);
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
//
// ★ 2026-10-26：加「只释放自己分配过的指针」的登记表。
//   游戏的 fs 分配器被我们整体换成宿主 malloc 后，客机里**别的**分配器
//   （SDK 自己的堆 / 我们没接管的路径）分配出来的指针也可能流到我们的 Free。
//   直接 free() 非本堆指针 ⇒ bionic 堆元数据被写坏 ⇒ 之后在 libc 里 abort
//   （实测：pc=libc+0x9a688 ≈ longjmp 附近，多线程同时崩）。
//   ⇒ 用开放寻址表登记；Free 时查不到就**跳过并报一次**。
#define ZA_FS_SET_BITS 16
#define ZA_FS_SET_SIZE (1u << ZA_FS_SET_BITS)
static void *za_fs_set[ZA_FS_SET_SIZE];
static pthread_mutex_t za_fs_set_mtx = PTHREAD_MUTEX_INITIALIZER;
static int za_fs_set_full_logged;
static unsigned za_fs_foreign_free;

static void za_fs_set_add(void *p)
{
    unsigned h = (unsigned)(((uintptr_t)p >> 4) & (ZA_FS_SET_SIZE - 1));
    pthread_mutex_lock(&za_fs_set_mtx);
    for (unsigned i = 0; i < ZA_FS_SET_SIZE; i++)
    {
        unsigned k = (h + i) & (ZA_FS_SET_SIZE - 1);
        if (za_fs_set[k] == NULL) { za_fs_set[k] = p; break; }
    }
    pthread_mutex_unlock(&za_fs_set_mtx);
}
static int za_fs_set_take(void *p)
{
    unsigned h = (unsigned)(((uintptr_t)p >> 4) & (ZA_FS_SET_SIZE - 1));
    int found = 0;
    pthread_mutex_lock(&za_fs_set_mtx);
    for (unsigned i = 0; i < ZA_FS_SET_SIZE; i++)
    {
        unsigned k = (h + i) & (ZA_FS_SET_SIZE - 1);
        if (za_fs_set[k] == p) { za_fs_set[k] = NULL; found = 1; break; }
        if (za_fs_set[k] == NULL) break;
    }
    pthread_mutex_unlock(&za_fs_set_mtx);
    return found;
}
static void za_fs_guard_free(void *p, const char *who)
{
    if (!p) return;
    if (za_fs_set_take(p)) {
        if (za_mem_guest_owns(p)) za_mem_guest_free(p); else free(p);
        return;
    }
    if (za_fs_foreign_free++ < 6)
        ZLOGE("fs %s：%p 不是宿主分配器给的 ⇒ 跳过 free（防止写坏宿主堆）", who, p);
}

void *za_fs_alloc_host(unsigned long size)
{
    // ★ fs 读缓冲交给客机写 ⇒ 走客机共享区（宿主堆会被客机越界写坏）
    void *p = za_mem_guest_alloc(size ? (size_t)size : 1, 16);
    if (p) za_fs_set_add(p);
    return p;
}
void za_fs_free_host(void *p)
{
    za_fs_guard_free(p, "free");
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
    za_fs_set_add(p);
    return p;
}
void za_fs_vt_free(void *obj, void *ptr, unsigned long size, unsigned long align)
{
    (void)obj; (void)size; (void)align;
    za_fs_guard_free(ptr, "vt-free");
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

// ════════════════════════════════════════════════════════════════
//  main 模块的入口探针（桩必须在 main 的扩展区，分支才在 ±128MB 内）
// ════════════════════════════════════════════════════════════════
/* ZA_MPROBE_STUB / ZA_MPROBE_SLOT 见前面的声明区 */

// 空闲链表池初始化（main+0x1653cc0）：x0=desc, x1=stride, x2=base, w3=size
static void za_hook_m_poolinit(unsigned long long *r)
{
    static int n;
    if (n++ >= 6) return;
    ZLOGI("★ main 探针 pool-init: desc=%#llx stride=%#llx base=%#llx size=%#llx",
          r[0], r[1], r[2], r[3]);
}
// worker 线程实际执行的 main 函数（登录参数和调用者）
static void za_hook_m_w2(unsigned long long *r)
{
    static int n;
    if (n++ >= 8) return;
    ZLOGI("★ main 探针 w2(0x1a0a204): x0=%#llx x1=%#llx x2=%#llx x3=%#llx lr=%#llx",
          r[0], r[1], r[2], r[3], r[19]);
}
static void za_hook_m_openfile(unsigned long long *r)
{
    static int n;
    if (n++ >= 8) return;
    unsigned long p = (unsigned long)r[1];
    char txt[128];
    int ok = 0;
    unsigned long long gb = (unsigned long long)(uintptr_t)za_guest_base;
    if (p && ((p >= 0x400000000ull && p < 0xd00000000ull) ||
              (p >= 0xb400000000000000ull && p < 0xb400010000000000ull) ||
              (gb && p >= gb && p < gb + ZA_IMAGE_SIZE)))
    {
        for (int i = 0; i < 120; i++)
        {
            char c = *(const char *)(uintptr_t)(p + i);
            if (!c) { txt[i] = 0; ok = 1; break; }
            txt[i] = (c >= 0x20 && c < 0x7f) ? c : '?';
        }
    }
    if (ok) ZLOGE("★ main OpenFile: mode=%#llx path=\"%s\"", r[2], txt);
    else ZLOGE("★ main OpenFile: out=%#llx path=%#llx mode=%#llx（读不到字符串）", r[0], (unsigned long long)p, r[2]);
}

static void za_hook_m_w3(unsigned long long *r)
{
    static int n;
    if (n++ >= 8) return;
    ZLOGI("★ main 探针 w3(0x1bab754): x0=%#llx x1=%#llx x2=%#llx x3=%#llx lr=%#llx",
          r[0], r[1], r[2], r[3], r[19]);
}
// 循环入口（main+0x1653d00）：x0=desc(+0x18 stride,+0x1c count), x2=base, x8=stride/8
static void za_hook_m_poolloop(unsigned long long *r)
{
    static int n;
    if (n++ >= 6) return;
    unsigned long long desc = r[0], base = r[2], stride = r[8] << 3;
    unsigned int count = 0;
    if (desc) memcpy(&count, (const void *)(uintptr_t)(desc + 0x1c), 4);
    ZLOGI("★ main 探针 pool-loop: desc=%#llx base=%#llx stride=%#llx count=%u ⇒ 跨度=%#llx",
          desc, base, stride, count, stride * (unsigned long long)count);
}

static void za_install_main_probe(unsigned char *base, unsigned int func_off,
                                  unsigned int stub_off, unsigned int hook_off,
                                  void (*hook)(unsigned long long *))
{
    unsigned int *s = (unsigned int *)(base + stub_off);
    unsigned int orig = *(unsigned int *)(base + func_off);
    static const unsigned int seq[27] = {
        0xA9BD7BFD, 0xD10283FF, 0xA9097BFD,
        0xA90007E0, 0xA9010FE2, 0xA90217E4, 0xA9031FE6,
        0xA90427E8, 0xA9052FEA, 0xA90637EC, 0xA9073FEE, 0xA90847F0,
        0x910003E0, 0x90000010, 0xF9400000, 0xD63F0200,
        0xA94007E0, 0xA9410FE2, 0xA94217E4, 0xA9431FE6,
        0xA94427E8, 0xA9452FEA, 0xA94637EC, 0xA9473FEE, 0xA94847F0,
        0x910283FF, 0xA8C37BFD,
    };
    memcpy(s, seq, sizeof seq);
    long long pg = ((long long)(hook_off & ~0xFFFull) - (long long)(stub_off & ~0xFFFull)) >> 12;
    s[13] = 0x90000000u | ((unsigned)(pg & 3) << 29) | ((unsigned)((pg >> 2) & 0x7FFFF) << 5) | 16u;
    s[14] = 0xF9400000u | (((hook_off & 0xFFFull) >> 3) << 10) | (16u << 5) | 16u;
    s[27] = orig;
    {
        long long d = (long long)(func_off + 4) - (long long)(stub_off + 28 * 4);
        s[28] = 0x14000000u | (unsigned)((d >> 2) & 0x3FFFFFFu);
    }
    {
        long long d = (long long)stub_off - (long long)func_off;
        *(unsigned int *)(base + func_off) = 0x14000000u | (unsigned)((d >> 2) & 0x3FFFFFFu);
    }
    *(unsigned long long *)(base + hook_off) = (unsigned long long)(uintptr_t)hook;
    __builtin___clear_cache((char *)base + stub_off, (char *)base + stub_off + 29 * 4);
    __builtin___clear_cache((char *)base + func_off, (char *)base + func_off + 4);
}

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
    za_log_cpp_alloc_syms();
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
    extern volatile int za_stage_m5;
    za_stage_m5 = 1;
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
    // 同上：sigaction 只装一次（进程级），掩码每线程放行一次。
    static volatile int sampler_installed;
    static volatile unsigned char mask_done[128];
    if (!__atomic_exchange_n(&sampler_installed, 1, __ATOMIC_ACQ_REL))
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof sa);
        sa.sa_sigaction = za_pc_sample_handler;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        sigemptyset(&sa.sa_mask);
        sigaction(ZA_SAMPLER_SIG, &sa, NULL);
    }
    int mi = (int)((unsigned long)syscall(SYS_gettid) % 128u);
    if (mask_done[mi]) return;
    mask_done[mi] = 1;
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
        /* ★ 2026-10-28：真正有用的「停摆」判据 —— 客机整体睡在条件变量上时，
         *   svc 计数仍在缓慢增长（我们在 svc#28 里按 20ms 分片返回，客机每片
         *   都重新发一次），所以「计数没变」永远不成立。改成看**速率**：
         *   连续 30 秒每秒新增 svc 少于 100 次 ⇒ 主线程几乎不动 ⇒ 倒一次栈。 */
        {
            static unsigned long long win_ns;
            static unsigned long long win_cnt;
            static int slow_secs, dumped;
            struct timespec tsv;
            clock_gettime(CLOCK_MONOTONIC, &tsv);
            unsigned long long now = (unsigned long long)tsv.tv_sec * 1000000000ull +
                                     (unsigned long long)tsv.tv_nsec;
            if (now - win_ns >= 1000000000ull)
            {
                unsigned long rate = (unsigned long)(cnt - win_cnt);
                win_ns = now;
                win_cnt = cnt;
                if (rate < 100) {
                    if (++slow_secs == 30 && !dumped) {
                        dumped = 1;
                        ZLOGE("★ 客机 30 秒几乎不动（%lu svc/s）⇒ 倒客机栈（tid=%ld）",
                              rate, za_guest_tid);
                        if (za_guest_tid > 0)
                            syscall(SYS_tgkill, (int)getpid(), (int)za_guest_tid, 11);
                    }
                } else {
                    slow_secs = 0;
                }
            }
        }
        if (cnt == last_count)
        {
            if (++no_progress == 40)
            {
                // 只在每 10 秒（tick 2000）打一行：NVN 密集阶段本来就不发 svc，
                // 200ms 一条会把 logcat 环形缓冲刷爆，崩溃现场的头部就被挤掉了。
                if ((no_progress % 2000) == 40)
                    ZLOGE("★ 客机 200ms 无 svc 推进（count=%lu，已持续 %d 秒）", cnt,
                          no_progress / 40);
                // ★ 2026-10-27：全体线程可能都睡在条件变量上（真机实测 16 个）。
                //   ConditionVariable 允许伪唤醒，这里做一次**合法伪唤醒**：
                //   游戏若因此继续推进 ⇒ 卡住的原因就是丢了一次唤醒；
                //   若没反应 ⇒ 它在等真正的外部事件（vsync/GPU 完成等）。
                // ★ 先 dump 再 poke：poke 会把这些槽位的 kind 清 0，
                //   紧跟着 dump 就只会看到「0 个线程」（踩过一次）。
                if ((no_progress % 2000) == 40)
                {
                    {
                        extern volatile unsigned long za_thread_created, za_thread_started;
                        {
                            extern volatile unsigned long za_async_enq, za_async_exec;
                            ZLOGE("★ 停摆快照（%lu svc/s）：CreateThread=%lu StartThread=%lu "
                                  "async enq=%lu exec=%lu 差=%ld",
                                  cnt, za_thread_created, za_thread_started,
                                  za_async_enq, za_async_exec,
                                  (long)za_async_enq - (long)za_async_exec);
                        }
                    }
                    za_sync_dump();
                    // 主线程最近 24 次 svc：它才是「游戏卡在哪」的直接答案。
                    {
                        extern void za_dump_all_ret_rings(void);
                        extern void za_dump_ret_ring_for(long tid);
                        extern void za_sync_dump_chain_for(long tid);
                        ZLOGE("★ 主线程(tid=%ld)最近 svc：", za_guest_tid);
                        za_dump_ret_ring_for(za_guest_tid);
                        if (za_guest_tid > 0) za_sync_dump_chain_for(za_guest_tid);
                    }
                    za_nvn_dump_recent();   // 带客机 LR：最后几步 NVN 调用发生在哪
                }
                unsigned pk = za_sync_poke_all();
                if (pk && (no_progress % 2000) == 40)
                    ZLOGE("   已对 %u 个条件变量等待者做伪唤醒（累计 %d 次）", pk,
                          no_progress / 40);
            }
            // ★ 2026-10-27：阈值 2000 → 12000。客人有**合法的长 memset**
            //   （sdk+0x56e450 就是 memset 的内层循环，初始化几百 MB 内存池时
            //   要跑很久且不发 svc）⇒ 10 秒就开枪会把正常进度当卡死，
            //   SIGSEGV 打到正常线程上，整个进程被带走。
            if (no_progress == 12000)
            {
                ZLOGE("★ 卡死 60 秒：向客机线程发 SIGSEGV 倒现场");
                za_sync_dump();
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