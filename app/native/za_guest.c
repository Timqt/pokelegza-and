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
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
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
// E22：悬空读地址记录（信号处理器只裸写；归属由看门狗线程事后查 maps）。
volatile unsigned long long za_dangle_addr[8];
volatile unsigned int za_dangle_n;
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

// 在 /proc/self/maps 里找 addr 的「所属/前后」映射，写一行可读描述。
// 为什么需要：悬空指针只给出一个绝对地址，光看 0x6ee30dc1c8 无法判断它是
// 客机堆、我们 mmap 的栈、还是宿主 Scudo 大块（scudo:secondary）。真机上
// 这三个来源对应完全不同的修法，而 /proc/self/maps 一次就能分辨。
// 只用 open/read：这段可能在任意线程的致命路径上跑，尽量不碰 libc 的锁。
// Where does a dangling address live? /proc/self/maps answers it in one shot
// (guest heap vs. our mmap vs. the host's Scudo secondary arena).
static void za_maps_near(unsigned long long a, char *out, size_t cap)
{
    static char mbuf[384 * 1024];
    static int busy;
    int fd;
    ssize_t n;
    size_t used = 0;
    unsigned long long prev_lo = 0, prev_hi = 0;
    unsigned long long next_lo = 0;
    unsigned long long in_lo = 0, in_hi = 0;
    char prev_name[72] = "", next_name[72] = "", in_name[72] = "";
    char prev_perm[5] = "", next_perm[5] = "", in_perm[5] = "";
    if (!cap) return;
    if (busy) { out[0] = 0; return; }
    busy = 1;
    out[0] = 0;
    fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0) { busy = 0; return; }
    while (used < sizeof mbuf - 1) {
        n = read(fd, mbuf + used, sizeof mbuf - 1 - used);
        if (n <= 0) break;
        used += (size_t)n;
    }
    close(fd);
    mbuf[used] = 0;
    {
        char *p = mbuf;
        while (p && *p) {
            char *e = strchr(p, '\n');
            char *q;
            unsigned long long lo, hi;
            char perm[5] = "----";
            const char *nm;
            if (e) *e = 0;
            lo = strtoull(p, &q, 16);
            if (*q == '-') {
                hi = strtoull(q + 1, &q, 16);
                while (*q == ' ') q++;
                if (q[0] && q[1] && q[2] && q[3]) {
                    perm[0] = q[0]; perm[1] = q[1]; perm[2] = q[2]; perm[3] = q[3];
                    while (*q && *q != ' ') q++;              // perms
                    for (int k = 0; k < 3; k++) {             // offset / dev / inode
                        while (*q == ' ') q++;
                        while (*q && *q != ' ') q++;
                    }
                    while (*q == ' ') q++;
                }
                nm = q;
                if (lo <= a && a < hi) {          // ★ 必须单独处理「地址就在这条映射里」
                    in_lo = lo; in_hi = hi;
                    memcpy(in_perm, perm, 5);
                    snprintf(in_name, sizeof in_name, "%.71s", nm);
                } else if (hi <= a) {
                    prev_lo = lo; prev_hi = hi;
                    memcpy(prev_perm, perm, 5);
                    snprintf(prev_name, sizeof prev_name, "%.71s", nm);
                } else if (lo > a && !next_lo) {
                    next_lo = lo;
                    memcpy(next_perm, perm, 5);
                    snprintf(next_name, sizeof next_name, "%.71s", nm);
                }
            }
            p = e ? e + 1 : NULL;
        }
    }
    {
        char *q = out;
        char *end = out + cap - 1;
        if (in_lo) {
            q = za_put_str(q, "包含=[");
            q = za_put_hex(q, in_lo);
            q = za_put_str(q, "-");
            q = za_put_hex(q, in_hi);
            q = za_put_str(q, " ");
            q = za_put_str(q, in_perm);
            q = za_put_str(q, " ");
            q = za_put_str(q, in_name);
            q = za_put_str(q, "]");
        } else {
            q = za_put_str(q, "未映射（在空洞里）");
        }
        q = za_put_str(q, " 前一个=[");
        q = za_put_hex(q, prev_lo);
        q = za_put_str(q, "-");
        q = za_put_hex(q, prev_hi);
        q = za_put_str(q, " ");
        q = za_put_str(q, prev_perm);
        q = za_put_str(q, " ");
        q = za_put_str(q, prev_name);
        q = za_put_str(q, "]");
        if (next_lo) {
            q = za_put_str(q, " 后一个=[");
            q = za_put_hex(q, next_lo);
            q = za_put_str(q, " ");
            q = za_put_str(q, next_perm);
            q = za_put_str(q, " ");
            q = za_put_str(q, next_name);
            q = za_put_str(q, "]");
        }
        if (q > end) q = end;
        *q = 0;
    }
    busy = 0;
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
    // ★ 安卓应用进程的 fd 2 是 /dev/null，/data/local/tmp 又常常因 SELinux 写不进去
    //   ⇒ 致命现场曾经一条都没留下来（真机崩了但 logcat 里没有 FATAL-ENTER）。
    //   再往 logd 写一份：__android_log_write 只做一次 socket 写，信号处理器里可用。
    {
        char tmp[400];
        size_t n = len < sizeof tmp - 1 ? len : sizeof tmp - 1;
        memcpy(tmp, buf, n);
        tmp[n] = 0;
        __android_log_write(ANDROID_LOG_ERROR, "ZaFatal", tmp);
    }
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
static void za_rt_catch(int sig, siginfo_t *info, void *ctx);

// 读一个客机对象所属的类名（itanium ABI：vptr[-1] = typeinfo，typeinfo+8 = 名字）。
// 用途：整条 UAF 链的「第一个坏读」上把对象类型挖出来，否则只能看到一堆站点。
static void za_log_obj_rtti(unsigned long long obj_raw)
{
    unsigned long long o = obj_raw & 0x00FFFFFFFFFFFFFFull;
    if (o < 0x10000ull || o >= 0x800000000000ull) return;
    unsigned long long vptr = 0, ti = 0, nm = 0;
    struct iovec a = { &vptr, 8 }, b = { (void *)(uintptr_t)o, 8 };
    if (process_vm_readv(getpid(), &a, 1, &b, 1, 0) != 8 || !vptr) return;
    unsigned long long vp = vptr & 0x00FFFFFFFFFFFFFFull;
    struct iovec c2 = { &ti, 8 }, d2 = { (void *)(uintptr_t)(vp - 8), 8 };
    if (process_vm_readv(getpid(), &c2, 1, &d2, 1, 0) != 8 || !ti) return;
    unsigned long long tp = ti & 0x00FFFFFFFFFFFFFFull;
    struct iovec e2 = { &nm, 8 }, f2 = { (void *)(uintptr_t)(tp + 8), 8 };
    if (process_vm_readv(getpid(), &e2, 1, &f2, 1, 0) != 8 || !nm) return;
    char name[96];
    struct iovec g2 = { name, sizeof name - 1 }, h2 = { (void *)(uintptr_t)(nm & 0x00FFFFFFFFFFFFFFull), sizeof name - 1 };
    ssize_t got = process_vm_readv(getpid(), &g2, 1, &h2, 1, 0);
    name[got > 0 ? got : 0] = 0;
    char bb[220];
    char *qq = bb;
    qq = za_put_str(qq, "ZaGuest: ★ 坏读对象 obj=");
    qq = za_put_hex(qq, o);
    qq = za_put_str(qq, " vtable=");
    qq = za_put_hex(qq, vp);
    qq = za_put_str(qq, " rtti=");
    qq = za_put_str(qq, name);
    za_fatal_write(bb, (size_t)(qq - bb));
}


// 这个地址是不是「可执行代码」：客机映像 / SDK 映像 / 任何已加载模块。
// ⚠ 不能只用 dladdr：客机与 SDK 的映像是我们自己 mmap 进来的，动态链接器
//   不认识它们（实测客机地址 dladdr 返回 0）。
static int za_in_code(unsigned long a)
{
    extern unsigned char *za_guest_base;
    extern volatile unsigned long za_sdk_base, za_sdk_size;
    if (!a) return 0;
    if (za_guest_base && a >= (unsigned long)(uintptr_t)za_guest_base &&
        a < (unsigned long)(uintptr_t)za_guest_base + ZA_IMAGE_SIZE) return 1;
    if (za_sdk_base && a >= za_sdk_base && a < za_sdk_base + za_sdk_size) return 1;
    { Dl_info di; memset(&di, 0, sizeof di); if (dladdr((void *)(uintptr_t)a, &di) && di.dli_fbase) return 1; }
    return 0;
}

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
#define ZA_PC_RING 64
volatile unsigned long za_disp_count;   // svc 派发计数（看门狗判卡死用）
// 按服务号分桶的计数：卡住时能看出「只剩下哪几个 svc 在动」。
volatile unsigned long za_svc_nr_count[64];
void za_disp_count_bump(void) { za_disp_count++; }
void za_svc_nr_count_bump(unsigned nr) { if (nr < 64) __atomic_add_fetch(&za_svc_nr_count[nr], 1, __ATOMIC_RELAXED); }
volatile unsigned long za_pc_ring[ZA_PC_RING];
// 2026-10-28：同时记下「是哪条线程」—— 停摆时只有知道每条线程各自停在哪，
// 才能分清「谁在等」和「谁本该干活却没干活」。
volatile long za_pc_tid_ring[ZA_PC_RING];
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

// 崩在宿主库里时，pc 只有换算成「模块+偏移」才有意义。安卓上 shell 读不到
// app 的 /proc/<pid>/maps，所以让进程自己写一份。open/read/write 都是
// async-signal-safe，可以在信号处理器里直接做。
static void za_write_maps_file(void)
{
    int in = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (in < 0) return;
    int out = open("/data/data/org.pokelegza.android.port/files/za_maps.txt",
                   O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (out >= 0)
    {
        char b[4096];
        ssize_t r;
        while ((r = read(in, b, sizeof b)) > 0)
        {
            ssize_t w = write(out, b, (size_t)r);
            (void)w;
        }
        close(out);
    }
    close(in);
}
// 停摆时也存一份：宿主库是运行中才 dlopen 的，启动时的映射表不够用。
void za_write_maps_now(void) { za_write_maps_file(); }

static void za_fatal_dump_maps_once(void)
{
    static volatile int done;
    if (__atomic_exchange_n(&done, 1, __ATOMIC_ACQ_REL)) return;
    za_write_maps_file();
}

// ── 「名字表」假对象图 ────────────────────────────────────────────────
// 真实布局（反汇编 main+0x1757964 / main+0x173e6b4 / sdk+0x80fb8 确认）：
//   obj+0x1f8 → table
//   table+0x58 → registry（同一个对象同时被当 nn::util::BinaryFileHeader 用）
//   registry+0x28 → entry 数组；array[i] → entry；entry+0x60 → char*（访问器返回 +2）
//   registry+0x38 → 名字查找表（{@+0x08 计数, @+0x0c 桶数, @+0x10 字符串}）
//   BinaryFileHeader：u16@+0x14 bit0 = IsRelocated；u16@+0x16 = 首个 block 偏移；
//                     GetFirstBlock() = this + u16@+0x16（为 0 则返回 NULL）
// 目标：任何一次「查名字」都安全返回空名字，且 IsRelocated 为真（跳过重定位）。
#define ZA_FAKE_SLOTS 8192
static unsigned long long za_fake_array[ZA_FAKE_SLOTS];
static unsigned long long za_fake_entry[0x20];
static unsigned long long za_fake_registry[0x40];   // 0x200 字节，+0x80 处放一个 block
static unsigned long long za_fake_lookup[0x10];
static unsigned long long za_fake_table[0x20];
static char za_fake_name[8] __attribute__((aligned(8)));
// 悬空/不可读内存的「安全替身」：64KB 全零，可读写。
static unsigned char za_zero_page[65536] __attribute__((aligned(4096)));
static volatile int za_fake_ready;

// 「合法名字结构」：引擎解出来的名字是自相对偏移格式（反汇编 main+0x17389a0）：
//   P  = 返回的指针
//   base = P - (int32)[P]          ; 头部偏移
//   w10  = u16[base]     ; < 7 视为无效
//   off  = u16[base+6]   ; 为 0 视为无效
//   x8   = P + off
//   x8  += u32[x8]
//   data = x8 + 4        ; 交给调用方的字符串地址
// 下面构造 A：u16[A]=7、u16[A+6]=4、u32[A+8]=4、字符区 A+16 = "\0"，返回 P=A+4
// ⇒ data = A+16，指向空串。任何一次「取名字」都会得到一个合法但空的名字。
static unsigned char za_fake_name_entry[64] __attribute__((aligned(16)));
static unsigned long long za_fake_name_ptr;

static void za_build_fake_nametable(void)
{
    if (__atomic_exchange_n(&za_fake_ready, 1, __ATOMIC_ACQ_REL)) return;
    za_fake_name[0] = 0;
    {
        unsigned char *A = za_fake_name_entry;
        // 结构（自相对偏移）：
        //   P = A+8；base = P - (int32)[P] = A+8-8 = A
        //   u16[A]   = 7   （>=7 才不是「无效」）
        //   u16[A+6] = 8   （非 0 ⇒ x8 = P + 8 = A+16）
        //   u32[A+16]= 4   ⇒ x8 = A+20，+4 ⇒ data = A+24
        //   A+24     = 0   （空字符串）
        *(volatile unsigned short *)(A + 0) = 7;
        *(volatile unsigned short *)(A + 6) = 8;
        *(volatile unsigned int *)(A + 8) = 8;
        *(volatile unsigned int *)(A + 16) = 4;
        A[24] = 0;
        za_fake_name_ptr = (unsigned long long)(uintptr_t)(A + 8);
    }
    za_fake_entry[0x60 / 8] = (unsigned long long)(uintptr_t)za_fake_name;
    for (int i = 0; i < ZA_FAKE_SLOTS; i++)
        za_fake_array[i] = (unsigned long long)(uintptr_t)za_fake_entry;
    // BinaryFileHeader 语义：已迁移 + 首个 block 存在
    *(volatile unsigned short *)((char *)za_fake_registry + 0x14) = 1;      // IsRelocated = true
    *(volatile unsigned short *)((char *)za_fake_registry + 0x16) = 0x80;   // 首 block 偏移
    za_fake_registry[0x28 / 8] = (unsigned long long)(uintptr_t)za_fake_array;
    za_fake_registry[0x38 / 8] = (unsigned long long)(uintptr_t)za_fake_lookup;
    // 查找表：计数 1、桶数 0、唯一那条的字符串是空串 ⇒ 任何名字都只匹配到空名字
    za_fake_lookup[1] = 1;                                        // @+0x08 = 1
    za_fake_lookup[0x10 / 8] = (unsigned long long)(uintptr_t)za_fake_name;
    za_fake_table[0x28 / 8] = 0x40000000ull;                      // 引用计数永不归零
    za_fake_table[0x58 / 8] = (unsigned long long)(uintptr_t)za_fake_registry;
}

static void za_fatal_handler(int sig, siginfo_t *info, void *ctx)
{
    // ★ 2026-10-28：只处理**内核产生的**故障。si_code <= 0 表示这个信号是别的
    //   线程用 tgkill/kill 发来的（SI_USER=0 / SI_TKILL=-6 / SI_QUEUE=-1），
    //   不是真实的内存故障。看门狗本来用「给最忙的线程发 SIGSEGV」来倒现场，
    //   结果被这里当成致命故障，把被采样的线程（含主线程）永久 pause() 掉 ——
    //   等于自己制造全局停摆。真机实测：两次这样的信号之后主线程就再也不动了，
    //   NVN 永远 submit=0。现在一律忽略，采样改走专用信号 63。
    if (info && info->si_code <= 0) return;
    // ★★ 2026-10-29：**跳转到垃圾地址**（野 vptr / 被释放对象里的函数指针）。
    //   这类故障以前没有恢复路径：pc 不在我们的映像里，所有「解码故障指令」的
    //   降级都不匹配，只能交回致命流程 ⇒ 进程当场死。
    //   真机实测形态：`blr x8` 且 x8 = 0x74736e75007463（一段字符串字节）。
    //   语义上「这次间接调用没有目标」最接近的等价物是**让它立刻返回 0**：
    //   把 pc 设回 x30（调用方的返回地址），x0 = 0。
    //   用 dladdr 判断 pc 是否落在任何已加载模块里：落不进 ⇒ 一定不是可执行代码。
    if ((sig == SIGSEGV || sig == SIGBUS) && ctx)
    {
        ucontext_t *ucj = (ucontext_t *)ctx;
        unsigned long pcj = (unsigned long)ucj->uc_mcontext.pc;
        if (!za_in_code(pcj))
        {
            unsigned long lrj = (unsigned long)ucj->uc_mcontext.regs[30];
            // 返回地址必须是真代码，否则这次「返回」只会掉进下一个坑
            if (za_in_code(lrj))
            {
                static int nj;
                if (nj++ < 24) {
                    char b[200];
                    char *q = b;
                    q = za_put_str(q, "ZaGuest: ★ 野调用→按返回0处理 pc=");
                    q = za_put_hex(q, (unsigned long long)pcj);
                    q = za_put_str(q, " x30=");
                    q = za_put_hex(q, (unsigned long long)lrj);
                    za_fatal_write(b, (size_t)(q - b));
                }
                ucj->uc_mcontext.regs[0] = 0;
                ucj->uc_mcontext.pc = lrj;
                return;
            }
        }
    }
    // ★ 2026-10-28：「名字表缺失」修复（不受 ZA_NULLRECOVER 影响）。
    //   主映像里有一组「按序号取名字」的小访问器（main+0x1757a6c / 0x1757a98），
    //   形状都是
    //       ldr x8,[obj,#0x1f8]     ; 名字表容器（虚 setter main+0x1757680 写入）
    //       ldr x8,[x8,#0x58]       ; ← 容器为 0 时 fault addr = 0x58
    //       cbz x8, <返回空串/0>    ; 没有表就返回空
    //   容器由 vt[0x98] 那个虚 setter 建立；游戏这次运行里没人调它（资源没走到
    //   那一步）⇒ 容器一直是 0。**跳过读取**的实验证明不行：调用方随后会把
    //   读到的垃圾当指针`blr`（真机崩在 pc=0x250b0b4）。
    //   ⇒ 正确的最小修复是「给一个空表」，让整条路径自洽：
    //       容器 +0x58 == 0  ⇒ 访问器走 cbz，返回空串/0（=「没有名字」）
    //       容器 +0x28 = 极大值 ⇒ 析构时的引用计数递减永远不到 0，不会 free 它
    //   写回 [obj+0x1f8] 后**重执行**故障指令（pc 不变），后续每次访问都命中假表。
    // ★ 2026-10-29：SIGBUS 与 SIGSEGV 是同一类「解引用了不可用地址」的故障
    //   （真机同一个 `ldr w8,[x23,#0x30]` 站点前几次报 SIGSEGV、最后一次报 SIGBUS，
    //   而这里只放行 SIGSEGV ⇒ 最后一次没人接，进程当场死）。
    if (ctx && (sig == SIGSEGV || sig == SIGBUS) && info)
    {
        extern unsigned char *za_guest_base;
        ucontext_t *ucx = (ucontext_t *)ctx;
        unsigned long pcx = (unsigned long)ucx->uc_mcontext.pc;
        unsigned long gb0 = (unsigned long)(uintptr_t)za_guest_base;
        // ★★ 首选修复：**直接跳到该访问器自己的「没有名字」返回分支**，
        //   一个字节的游戏对象都不改。
        //   为什么不用「装假表 + 重执指令」：那条路会让游戏带着假数据继续跑，
        //   最后在消息处理里把假名字当对象解引用（真机崩在 main+0x250b0b8，
        //   x8 指向未映射的 0x...6ee36451a8）。返回空名字才是这条路径的本意。
        if (gb0) {
            // set_x0: -1 = 不动 x0，0 = 让函数返回 0，1 = 让函数返回 1
            struct { unsigned int fault, target; int set_x0; } fix[] = {
                // main+0x1757a6c: 失败分支在 0x1757a8c（返回静态空串）
                { 0x1757a70u, 0x1757a8cu, -1 },
                // main+0x1757a98: 失败分支在 0x1757ab0（mov w0,wzr; ret）
                { 0x1757a98u, 0x1757ab0u, 0 },
                // main+0x173e6b4: `ldr x0,[x8,#0x58]`，函数尾 0x173e6c4 (ret) → w0=0
                { 0x173e6b8u, 0x173e6c4u, 0 },
                // main+0x250b0e0: `cbz x0,ret0 ; ldr x8,[x0,#0x68] ; ldrb w8,[x8]`
                //   补零页让 [x0+0x68] 变成 0，而这里没有对 x8 判空 ⇒ 崩在 0x250b0e8。
                // ★ 2026-10-29 真机（两次实测，结论相反）：
                //   · 返回 0（「没准备好」）⇒ 调用方去**构建**：`ldr x0,[entry,#0x68]`
                //     拿到 NULL 去调构造器 ⇒ program = 0+0x10，空对象一路下传。
                //   · 返回 1（「已就绪」）⇒ 跳过构建，之后别处按「已初始化」用这些
                //     子对象 ⇒ 它们的 vptr 从没被写过（堆残留是字符串字节
                //     0x74736e75007463）⇒ blr 到数据，SIGBUS。
                //   ⇒ 两条路都不行，缺的是**这块 wrapper 的存储**。这里直接补给
                //   它：从静态池取一块 0x200 字节写进 [entry+0x68]，然后让查询照
                //   原样返回 false（读到 0），引擎就会**正常构建**进这块内存。
                //   ⚠ 静态池不归客机分配器管：如果引擎最终 free() 它们，会在
                //   销毁阶段炸；目前的优先级是先让首帧流程走通。
                { 0x250b0e8u, 0x250b0f4u, 1 },
            };
            // ★ 先补存储：main+0x250b0e8 `ldrb w8,[x8]` 且 x8==0，x0=entry。
            //   给 entry->0x68 塞一块零内存 → 重执该 ldrb（读 0 → 查询返回 false
            //   → 调用方走「构建」分支，把对象初始化进我们这块内存）。
            static int pool_on = -1;
            if (pool_on < 0)
                pool_on = access("/data/user/0/org.pokelegza.android.port/files/za-wrap-pool", F_OK) == 0;
            if (pool_on && pcx == gb0 + 0x250b0e8ul &&
                *(volatile unsigned int *)(uintptr_t)pcx == 0x39400108u &&
                ucx->uc_mcontext.regs[8] == 0 && ucx->uc_mcontext.regs[0] != 0)
            {
                static unsigned char pool[192][0x200] __attribute__((aligned(16)));
                static int used;
                if (used < 192) {
                    unsigned long long blk = (unsigned long long)(uintptr_t)pool[used++];
                    unsigned long long entry = (unsigned long long)ucx->uc_mcontext.regs[0];
                    struct iovec lo = { &blk, 8 }, ro = { (void *)(uintptr_t)(entry + 0x68), 8 };
                    if (process_vm_writev(getpid(), &lo, 1, &ro, 1, 0) == 8) {
                        ucx->uc_mcontext.regs[8] = blk;
                        static int nblk;
                        if (nblk++ < 6) {
                            char b[176];
                            char *q = b;
                            q = za_put_str(q, "ZaGuest: ★ 补 wrapper 存储 entry=");
                            q = za_put_hex(q, entry);
                            q = za_put_str(q, " blk=");
                            q = za_put_hex(q, blk);
                            za_fatal_write(b, (size_t)(q - b));
                        }
                        return;   // pc 不变，重执 ldrb
                    }
                }
            }
            for (unsigned i = 0; i < sizeof fix / sizeof fix[0]; i++) {
                if (pcx != gb0 + fix[i].fault) continue;
                static int nfix;
                if (fix[i].set_x0 >= 0)
                    ucx->uc_mcontext.regs[0] = (unsigned long)fix[i].set_x0;
                ucx->uc_mcontext.pc = gb0 + fix[i].target;
                if (nfix++ < 6) {
                    char b[160];
                    char *q = b;
                    q = za_put_str(q, "ZaGuest: ★ 名字表缺失→直接返回空 pc=+");
                    q = za_put_hex(q, (unsigned long long)fix[i].fault);
                    q = za_put_str(q, "\n");
                    za_fatal_write(b, (size_t)(q - b));
                }
                return;
            }
            // ★ 取虚函数指针时对象为空（main+0x2553d48 `ldr x0,[x0,x8]`，x8 来自
            //   一张函数表）。置 0 会让调用方 `blr 0`；给它「返回 0 的桩」最安全。
            if (pcx == gb0 + 0x2553d48ul && ucx->uc_mcontext.regs[0] == 0 &&
                *(volatile unsigned int *)(uintptr_t)pcx == 0xf8686800u)
            {
                static int nv;
                ucx->uc_mcontext.regs[0] = gb0 + 0x6048700ul;
                ucx->uc_mcontext.pc = pcx + 4;
                if (nv++ < 6) {
                    char b[160];
                    char *q = b;
                    q = za_put_str(q, "ZaGuest: ★ 空对象取虚函数→给返回0桩（第 ");
                    q = za_put_dec(q, (unsigned long long)nv);
                    q = za_put_str(q, " 次）");
                    za_fatal_write(b, (size_t)(q - b));
                }
                return;
            }
            //     ldr x8,[x0,#0x28] ; cbz ; ldr x8,[x8,#0x20] ; cbz ; ldrb w8,[x8,#0x110]
            //   字段指向未映射内存时，语义上等价于「没有这个对象」⇒ 返回 false 最温和。
            //   它只影响一个布尔查询，不改任何资源状态。
            // ★ 通用降级：**在客机/SDK 映像内的普通 load，目标地址不可读** ⇒ 读到 0 并跳过。
            //   这一族崩溃都是「某个对象字段指向已释放/未重定位的内存，代码直接解引用」，
            //   真机实测形如 `[obj+0x28] -> 0xb400006ee3xxxxxx`（宿主 malloc 区的悬空指针），
            //   崩在多个站点（main+0x250b0b8、main+0x2553b90 …）。
            //   保守条件：① pc 在 main/sdk 映像内；② 指令是 ldr/ldrb/ldrh/ldrsw；
            //             ③ 目标地址 >= 0x1000（近空指针另有专门恢复）；
            //             ④ 同一 pc 最多恢复 64 次（防止原地空转）。
            if (gb0 || za_sdk_base) {
                unsigned long pcv2 = pcx;
                int in_main2 = gb0 && pcv2 >= gb0 && pcv2 < gb0 + ZA_IMAGE_SIZE;
                extern volatile unsigned long za_sdk_base, za_sdk_size;
                int in_sdk2 = za_sdk_base && pcv2 >= za_sdk_base &&
                              pcv2 < za_sdk_base + za_sdk_size;
                unsigned long long saddr = (unsigned long long)(uintptr_t)info->si_addr;
                // 注意：store 的小地址（空指针写入）也要进来，所以这里不按 saddr 过滤。
                if (in_main2 || in_sdk2) {
                    unsigned int w = *(volatile unsigned int *)(uintptr_t)pcv2;
                    unsigned int rtn = w & 0x1fu, rnn = (w >> 5) & 0x1fu;
                    int is_ld = 0, is_st = 0, is_pair = 0;
                    // ★ 2026-10-29：引擎大量使用**配对读写**（ldp/stp）。以前只解码
                    //   单寄存器，配对指令一律落回致命流程 ⇒ 一条都救不回来
                    //   （真机 main+0x2554030 `ldp x8,x9,[x0]`）。
                    //   0xa9400000/0xa9000000 是 64 位、偏移为 imm7*8 的 ldp/stp。
                    if ((w & 0xffc00000u) == 0xa9400000u) { is_ld = 1; is_pair = 1; }
                    else if ((w & 0xffc00000u) == 0xa9000000u) { is_st = 1; is_pair = 1; }
                    else switch (w & 0xffc00000u) {
                    case 0xf9400000u: case 0xb9400000u: case 0x39400000u:
                    case 0x79400000u: case 0xb9800000u: is_ld = 1; break;
                    case 0xf9000000u: case 0xb9000000u: case 0x39000000u:
                    case 0x79000000u: case 0xb8000000u: is_st = 1; break;
                    default: break;
                    }
                    // store：把**基址**重定向到安全页，写落在我们自己的页里（无副作用）。
                    // ⚠ 空指针写入的 si_addr 很小（如 8），不能用「>= 0x1000」过滤，
                    //   否则整族漏掉（真机 main+0x2553ed8 `str x0,[x19,#8]`，x19=0）。
                    // ★ 2026-10-29 真机：store 的目标也可能是**远超用户空间**的野指针
                    //   （main+0x2553cb0 `str x8,[x0]`，x0=0x3c000000068d07），
                    //   那种地址 mmap 也补不了（超出 48 位 VA）。既然已经 fault，
                    //   这一页就一定不可写 —— 直接按「悬空写入」重定向到安全页。
                    // 地址范围：近空（< 256GB，含空指针 + 客机堆区）或**荒谬高位**
                    // （≥ 1PB，48 位 VA 之外的真野指针，mmap 也补不了）。中间那些
                    // 「看起来像真对象」的区间不动，避免把正常的越界写也一起盖掉。
                    if (is_st && rnn != 31 && rnn != 30 &&
                        (saddr < 0x4000000000ull || saddr >= 0x1000000000000ull)) {
                        static unsigned long stpc[16];
                        static unsigned stn[16];
                        int slot = 0;
                        {
                            int found = 0, empty = -1;
                            for (int i2 = 0; i2 < 16; i2++) {
                                if (stpc[i2] == pcv2) { slot = i2; found = 1; break; }
                                if (empty < 0 && stpc[i2] == 0) empty = i2;
                            }
                            if (!found) {
                                // ★ 换成另一个 PC 时必须清零计数：以前 8 个槽被挤满后，
                                //   新 PC 直接继承别人的计数（≥64）⇒ 一次都不救就放弃
                                //   （真机：main+0x2554d8c 的 `ldr w8,[x23,#0x30]` 没被救）。
                                slot = empty >= 0 ? empty : (int)((pcv2 >> 2) & 15u);
                                stpc[slot] = pcv2; stn[slot] = 0;
                            }
                        }
                        if (stn[slot] < 4096) {
                            stn[slot]++;
                            if (is_pair) {
                                ucx->uc_mcontext.pc = pcv2 + 4;   // 配对写：整条跳过
                                return;
                            }
                            ucx->uc_mcontext.regs[rnn] =
                                (unsigned long)(uintptr_t)za_zero_page;
                            if (stn[slot] <= 3) {
                                char b[176];
                                char *q = b;
                                q = za_put_str(q, "ZaGuest: ★ 悬空写入→安全页 pc=+");
                                q = za_put_hex(q, (unsigned long long)(pcv2 - (in_main2 ? gb0 : za_sdk_base)));
                                q = za_put_str(q, " addr=");
                                q = za_put_hex(q, saddr);
                                q = za_put_str(q, " (store)\n");
                                za_fatal_write(b, (size_t)(q - b));
                            }
                            return;      // pc 不变，重执这条 store
                        }
                    }
                    // 小的近空读交给后面的「近空读恢复」（它会置 0 并跳过，语义更准）
                    if (is_ld && saddr < 0x1000ull) { /* fallthrough */ }
                    else if (is_ld && rtn != 31 && rnn != 30) {
                        static unsigned long badpc[16];
                        static unsigned cnt[16];
                        int slot = 0, i;
                        {
                            int found = 0, empty = -1;
                            for (i = 0; i < 16; i++) {
                                if (badpc[i] == pcv2) { slot = i; found = 1; break; }
                                if (empty < 0 && badpc[i] == 0) empty = i;
                            }
                            if (!found) {
                                slot = empty >= 0 ? empty : (int)((pcv2 >> 2) & 15u);
                                badpc[slot] = pcv2; cnt[slot] = 0;   // 同 store：换 PC 清零
                            }
                        }
                        if (cnt[slot] < 4096) {   // 上限放大：引擎同一个站点可能反复解引用空/野对象
                            cnt[slot]++;
                            {
                                static int once;
                                if (once < 3 && in_main2 && (pcv2 - gb0) == 0x250b0b8ul) {
                                    once++;
                                    za_log_obj_rtti((unsigned long long)ucx->uc_mcontext.regs[0]);
                                }
                            }
                            // ★ 置 0 会被调用方原样往下传（真机：x21=0 → 崩在
                            //   main+0x254f4f8 的 `str x8,[x0]`）。改成指向一页全零的
                            //   安全内存：非空（过 cbz）、任何读取都得 0、写入也只是
                            //   落到我们自己的页里。
                            if (rtn != 31) {
                                // A/B（files/za-null-dangle）：把悬空读恢复成**真 0**。
                                // 给非空假指针会骗过引擎自己的 cbz 判空，可能正是下游
                                // 一连串垃圾的源头；0 至少会让它走「没有这个对象」的分支。
                                static int null_dangle = -1;
                                if (null_dangle < 0)
                                    null_dangle = access("/data/user/0/org.pokelegza.android.port/files/za-null-dangle", F_OK) == 0;
                                ucx->uc_mcontext.regs[rtn] = null_dangle
                                    ? 0ul : (unsigned long)(uintptr_t)za_zero_page;
                            }
                            // ★ 2026-10-29：main+0x2554d8c 是「按 0x6c 步长遍历一张列表」
                            //   的循环头（ldr w8,[x23,#0x30]），而列表基址与计数都可能是
                            //   垃圾（x23 = x8 + [x9+0x30]，x20 = [x9+0x2c]）。逐次恢复只会
                            //   把几万次迭代走完再放弃。把计数寄存器置 1，下一次
                            //   subs/b.eq 就正常退出循环——等价于「这张表里没有更多项」。
                            // ★ 首个坏读（main+0x250b0b8）处倒一次客机调用链：
                            //   这条链是整棵「半初始化对象树」的起点，先确认是哪个子系统在问。
                            if (in_main2 && (pcv2 - gb0) == 0x250b0b8ul) {
                                static int nchain;
                                if (nchain < 2) {
                                    // 这块就是 GetFirstBlock() 返回的资源块：把头部与那个
                                    // 悬空字段都倒出来，判断「被释放」还是「从没重定位」。
                                    unsigned long long blk = (unsigned long long)ucx->uc_mcontext.regs[0];
                                    unsigned long long b = blk & 0x00FFFFFFFFFFFFFFull;
                                    if (b >= 0x10000ull && b < 0x800000000000ull) {
                                        unsigned long long q[8] = {0};
                                        struct iovec lo3 = { q, sizeof q }, ro3 = { (void *)(uintptr_t)b, sizeof q };
                                        int okr = process_vm_readv(getpid(), &lo3, 1, &ro3, 1, 0) == (ssize_t)sizeof q;
                                        unsigned long long fld = 0; int fmapped = 0;
                                        if (okr) {
                                            struct iovec lo4 = { &fld, 8 }, ro4 = { (void *)(uintptr_t)(q[5]), 8 };
                                            fmapped = process_vm_readv(getpid(), &lo4, 1, &ro4, 1, 0) == 8;
                                        }
                                        ZLOGE("[nvn-diag] 首个坏读的块 blk=%#llx 可读=%d 头=%#llx %#llx %#llx %#llx | %#llx %#llx %#llx %#llx | [blk+0x28]=%#llx 可读=%d",
                                            b, okr, q[0], q[1], q[2], q[3], q[4], q[5], q[6], q[7], q[5], fmapped);
                                        // 块本身和悬空字段各查一次 /proc/self/maps：
                                        // 一眼看出它们在「客机堆 / 我们 mmap 的区域 / 宿主
                                        // Scudo 大块」中的哪一类 —— 三者的修法完全不同。
                                        {
                                            char mm[400];
                                            za_maps_near(b, mm, sizeof mm);
                                            ZLOGE("[nvn-diag] 块所在映射 %s", mm);
                                            za_maps_near(q[5] & 0x00FFFFFFFFFFFFFFull, mm, sizeof mm);
                                            ZLOGE("[nvn-diag] 悬空字段所在映射 %s", mm);
                                        }
                                    }
                                }
                                if (nchain++ < 2) {
                                    unsigned long long fp0 = (unsigned long long)ucx->uc_mcontext.regs[29];
                                    static unsigned long long seen[8];
                                    unsigned long long cur[8]; int nc = 0;
                                    unsigned long long fp = fp0;
                                    for (int i = 0; i < 8 && fp; i++) {
                                        if (fp & 7) break;
                                        unsigned long long nf = *(volatile unsigned long long *)(uintptr_t)fp;
                                        unsigned long long lr = *(volatile unsigned long long *)(uintptr_t)(fp + 8);
                                        if (!za_in_code((unsigned long)lr)) break;
                                        cur[nc++] = lr;
                                        if (nf <= fp || nf - fp > 0x100000ull) break;
                                        fp = nf;
                                    }
                                    int dup = 1;
                                    for (int i = 0; i < nc && dup; i++) if (cur[i] != seen[i]) dup = 0;
                                    if (!dup) {
                                        for (int i = 0; i < nc; i++) seen[i] = cur[i];
                                        char cb[300]; char *cq = cb;
                                        cq = za_put_str(cq, "ZaGuest: ★ 首个坏读调用链:");
                                        for (int i = 0; i < nc && i < 8; i++) {
                                            cq = za_put_str(cq, " ");
                                            if (cur[i] >= gb0 && cur[i] < gb0 + ZA_IMAGE_SIZE)
                                                cq = za_put_str(cq, "main+"), cq = za_put_hex(cq, cur[i] - gb0);
                                            else
                                                cq = za_put_hex(cq, cur[i]);
                                        }
                                        za_fatal_write(cb, (size_t)(cq - cb));
                                    }
                                }
                            }
                            if (in_main2 && (pcv2 - gb0) == 0x2554d8cul) {
                                static int nloop;
                                if (nloop++ < 8) {
                                    char lb[160]; char *lq = lb;
                                    lq = za_put_str(lq, "ZaGuest: ★ 垃圾列表遍历→提前结束 pc=+0x2554d8c");
                                    za_fatal_write(lb, (size_t)(lq - lb));
                                }
                                ucx->uc_mcontext.regs[20] = 1;
                            }
                            if (is_pair) {
                                int rt2 = (int)((w >> 10) & 0x1fu);
                                if (rt2 != 31) ucx->uc_mcontext.regs[rt2] = 0;
                            }
                            ucx->uc_mcontext.pc = pcv2 + 4;
                            if (cnt[slot] <= 3) {
                                // E22：只裸记地址（信号上下文不能扫 maps）
                                {
                                    unsigned int dn = __atomic_load_n(&za_dangle_n,
                                                                      __ATOMIC_RELAXED);
                                    if (dn < 8) {
                                        za_dangle_addr[dn] = saddr;
                                        __atomic_store_n(&za_dangle_n, dn + 1,
                                                         __ATOMIC_RELAXED);
                                    }
                                }
                                char b[176];
                                char *q = b;
                                q = za_put_str(q, "ZaGuest: ★ 悬空读取→置0 pc=+");
                                q = za_put_hex(q, (unsigned long long)(pcv2 - (in_main2 ? gb0 : za_sdk_base)));
                                q = za_put_str(q, " addr=");
                                q = za_put_hex(q, saddr);
                                q = za_put_str(q, "（第 ");
                                q = za_put_dec(q, cnt[slot]);
                                q = za_put_str(q, " 次）\n");
                                za_fatal_write(b, (size_t)(q - b));
                            }
                            return;
                        }
                    }
                }
            }
            if (pcx == gb0 + 0x250b0b8ul &&
                *(volatile unsigned int *)(uintptr_t)pcx == 0xf9401108u)   // ldr x8,[x8,#0x20]
            {
                static int nq;
                // ★ 2026-10-29：这是整条 UAF 链的**第一个**坏读（后面所有崩溃都是
                //   它的连锁反应）。先把「这个对象是什么类型」挖出来：读 vtable，
                //   顺着 RTTI 拿类名（itanium ABI：vptr[-1] = typeinfo，
                //   typeinfo+8 = 名字字符串）。
                {
                    unsigned long long obj = (unsigned long long)ucx->uc_mcontext.regs[0];
                    unsigned long long o = obj & 0x00FFFFFFFFFFFFFFull;
                    if (nq < 3 && o >= 0x10000ull && o < 0x800000000000ull) {
                        unsigned long long vptr = 0, ti = 0, nm = 0;
                        struct iovec a = { &vptr, 8 }, b = { (void *)(uintptr_t)o, 8 };
                        if (process_vm_readv(getpid(), &a, 1, &b, 1, 0) == 8 && vptr) {
                            unsigned long long vp = vptr & 0x00FFFFFFFFFFFFFFull;
                            struct iovec c2 = { &ti, 8 }, d2 = { (void *)(uintptr_t)(vp - 8), 8 };
                            if (process_vm_readv(getpid(), &c2, 1, &d2, 1, 0) == 8 && ti) {
                                unsigned long long tp = ti & 0x00FFFFFFFFFFFFFFull;
                                struct iovec e2 = { &nm, 8 }, f2 = { (void *)(uintptr_t)(tp + 8), 8 };
                                if (process_vm_readv(getpid(), &e2, 1, &f2, 1, 0) == 8 && nm) {
                                    char name[96];
                                    struct iovec g2 = { name, sizeof name - 1 }, h2 = { (void *)(uintptr_t)(nm & 0x00FFFFFFFFFFFFFFull), sizeof name - 1 };
                                    ssize_t got = process_vm_readv(getpid(), &g2, 1, &h2, 1, 0);
                                    if (got > 0) { name[got] = 0; }
                                    else name[0] = 0;
                                    char bb[200]; char *qq = bb;
                                    qq = za_put_str(qq, "ZaGuest: ★ 首个坏读对象 obj=");
                                    qq = za_put_hex(qq, o);
                                    qq = za_put_str(qq, " vtable=");
                                    qq = za_put_hex(qq, vp);
                                    qq = za_put_str(qq, " rtti=\"");
                                    qq = za_put_str(qq, name);
                                    qq = za_put_str(qq, "\"");
                                    za_fatal_write(bb, (size_t)(qq - bb));
                                }
                            }
                        }
                    }
                }
                ucx->uc_mcontext.regs[0] = 0;                    // w0 = false
                ucx->uc_mcontext.pc = gb0 + 0x250b0d0ul;         // mov w0,wzr; ret
                if (nq++ < 6) {
                    char b[160];
                    char *q = b;
                    q = za_put_str(q, "ZaGuest: ★ 悬空字段→布尔查询返回 false（第 ");
                    q = za_put_dec(q, (unsigned long long)nq);
                    q = za_put_str(q, " 次）\n");
                    za_fatal_write(b, (size_t)(q - b));
                }
                return;
            }
        }
        // ★★ 终极通用降级：客机/SDK 代码解引用了一个**未映射**的地址
        //   （悬空/use-after-free 指针，真机常见 0x6ee3_xxxx_xxxx 宿主堆残留）。
        //   与其逐条解码指令形态（ldr/ldp/寄存器偏移…），不如直接把那一页
        //   mmap 成全零页再重执：任何读都得 0、任何写都落在我们自己的页上。
        //   限制：只认客机/SDK 映像里的 PC；最多补 512 页；地址必须像个指针。
        {
            unsigned long long saddr2 = (unsigned long long)(uintptr_t)info->si_addr;
            int ours2 = 0;
            if (gb0 && pcx >= gb0 && pcx < gb0 + ZA_IMAGE_SIZE) ours2 = 1;
            extern volatile unsigned long za_sdk_base, za_sdk_size;
            if (!ours2 && za_sdk_base && pcx >= za_sdk_base && pcx < za_sdk_base + za_sdk_size)
                ours2 = 1;
            static int mapped_pages;
            {
                static int dbg;
                if (dbg < 8 && (gb0 || za_sdk_base)) {
                    dbg++;
                    char b[200]; char *q = b;
                    q = za_put_str(q, "ZaGuest: [dbg-mmap] ours=");
                    q = za_put_dec(q, (unsigned long long)ours2);
                    q = za_put_str(q, " pc=+");
                    q = za_put_hex(q, (unsigned long long)(pcx - (gb0 ? gb0 : za_sdk_base)));
                    q = za_put_str(q, " addr=");
                    q = za_put_hex(q, saddr2);
                    za_fatal_write(b, (size_t)(q - b));
                }
            }
            if (ours2 && saddr2 >= 0x10000ull && saddr2 >= 0x4000000000ull &&
                saddr2 < 0x800000000000ull && mapped_pages < 512)
            {
                unsigned long pg = (unsigned long)(saddr2 & ~0xFFFull);
                void *r = mmap((void *)pg, 0x1000, PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
                if (r == MAP_FAILED) {
                    static int dbg2;
                    if (dbg2++ < 8) {
                        char b2[160]; char *q2 = b2;
                        q2 = za_put_str(q2, "ZaGuest: [dbg-mmap] mmap 失败 errno=");
                        q2 = za_put_dec(q2, (unsigned long long)errno);
                        za_fatal_write(b2, (size_t)(q2 - b2));
                    }
                }
                if (r != MAP_FAILED) {
                    memset(r, 0, 0x1000);
                    mapped_pages++;
                    if (mapped_pages <= 6) {
                        char b[176];
                        char *q = b;
                        q = za_put_str(q, "ZaGuest: ★ 悬空地址补零页 addr=");
                        q = za_put_hex(q, saddr2);
                        q = za_put_str(q, " pc=+");
                        q = za_put_hex(q, (unsigned long long)(pcx - (gb0 ? gb0 : za_sdk_base)));
                        q = za_put_str(q, "（已补 ");
                        q = za_put_dec(q, (unsigned long long)mapped_pages);
                        q = za_put_str(q, " 页）\n");
                        za_fatal_write(b, (size_t)(q - b));
                    }
                    return;          // 重执这条指令，这次会读到全零
                }
            }
        }
        unsigned long prev = pcx >= 4 ? *(volatile unsigned int *)(uintptr_t)(pcx - 4) : 0;
        unsigned long fi = *(volatile unsigned int *)(uintptr_t)pcx;
        // 故障指令：`ldr Rt,[Xn,#0x58]`（imm12=0x58/8=0xB，任意 Rt）
        int fi_is_ld58 = ((fi & 0xffc00000u) == 0xf9400000u) && (((fi >> 10) & 0xfffu) == 0x0bu);
        // 前一条：`ldr xT,[Rm,#0x1f8]`（imm12=0x3F），且 T 就是故障指令的基址寄存器
        int prev_is_ld1f8 = ((prev & 0xffc00000u) == 0xf9400000u) && (((prev >> 10) & 0xfffu) == 0x3fu);
        int rn = (int)((fi >> 5) & 0x1fu);        // 故障指令的基址寄存器（值必须为 0）
        int rm = (int)((prev >> 5) & 0x1fu);      // 外层对象寄存器
        if (za_guest_base && fi_is_ld58 && prev_is_ld1f8 &&
            ((prev & 0x1fu) == (unsigned)rn) && rn < 31 && rm < 31 &&
            ucx->uc_mcontext.regs[rn] == 0)
        {
            unsigned long long self = ucx->uc_mcontext.regs[rm];
            static int nnm;
            za_build_fake_nametable();
            if (self && ZA_PTR_OK(self)) {
                *(volatile unsigned long long *)(uintptr_t)(self + 0x1f8) =
                    (unsigned long long)(uintptr_t)za_fake_table;
                // ★ 关键：重执行的是**故障那条** `ldr Rt,[Xn,#0x58]`，
                //   而 Xn 里还是旧的 0（它是上一条指令从 [obj+0x1f8] 装进寄存器的）。
                //   不把寄存器改成新表指针，就会「故障→恢复→再故障」死循环
                //   （真机实测：客机 100% CPU 卡在 main+0x173e6b8，一个 svc 都不发）。
                // 同时把「名字查询缓存」置成非零，短路另一条路径：
                //   main+0x17577d0 看到 [obj+0x1e8] 的 bit32..39 非零且
                //   [obj+0x1f0] 非零时，**跳过** main+0x1757810（那个函数会
                //   拿 [table+0x30] 当 nn::util::BinaryFileHeader 去解二进制）。
                // 缓存字段塞「合法名字指针」：两个懒建表入口看到缓存非零就早退，
                // 返回这个指针，下游按「无名字」处理而不是解引用垃圾。
                *(volatile unsigned long long *)(uintptr_t)(self + 0x1e8) = za_fake_name_ptr;
                *(volatile unsigned int *)(uintptr_t)(self + 0x1f0) = 1u;
                ucx->uc_mcontext.regs[rn] = (unsigned long)(uintptr_t)za_fake_table;
            }
            if (nnm < 8)
            {
                unsigned long long vt = 0;
                if (self) memcpy(&vt, (const void *)(uintptr_t)self, 8);
                char b[192];
                char *q = b;
                q = za_put_str(q, "ZaGuest: ★ 名字表缺失→装空表 pc=+");
                q = za_put_hex(q, (unsigned long long)(pcx - (unsigned long)(uintptr_t)za_guest_base));
                q = za_put_str(q, " obj=");
                q = za_put_hex(q, self);
                q = za_put_str(q, " vt=");
                q = za_put_hex(q, vt);
                q = za_put_str(q, "\n");
                za_fatal_write(b, (size_t)(q - b));
                nnm++;
            }
            // 不跳过：让它带着假表重新执行
            return;
        }
        // ★ 同一个「名字表懒建」函数的另一条入口（main+0x173def8）：
        //     x8 = [obj+0x1e0]        ; 一个已加载的二进制资源
        //     cbz x8 → 落到 `ldr w9,[x8]`（x8=0 ⇒ addr=0 崩溃）
        //     x8 = [x8+0x30] ; w9 = [x8] ; x8 += w9
        //     [obj+0x1f8] = x8        ; ← 名字表就是这么来的
        //   资源没加载 ⇒ [obj+0x1e0] == 0。函数开头本来有「缓存命中就早退」的
        //   判断（+0x1e8 的 bit32..39 与 +0x1f0 同时非零），我们直接置上缓存位
        //   并跳到函数返回处，等价于「这次查名字什么都不做」。
        if (za_guest_base && pcx == (unsigned long)(uintptr_t)za_guest_base + 0x173def8ul &&
            *(volatile unsigned int *)(uintptr_t)pcx == 0xb9400109u &&   // ldr w9,[x8]
            ucx->uc_mcontext.regs[8] == 0)
        {
            unsigned long long self = ucx->uc_mcontext.regs[0];
            static int nnm2;
            if (self && ZA_PTR_OK(self)) {
                *(volatile unsigned long long *)(uintptr_t)(self + 0x1e8) = za_fake_name_ptr;
                *(volatile unsigned int *)(uintptr_t)(self + 0x1f0) = 1u;
            }
            // 直接返回：x0 = 合法名字指针，x1 = 1（缓存非零）
            ucx->uc_mcontext.regs[0] = za_fake_name_ptr;
            ucx->uc_mcontext.regs[1] = 1;
            ucx->uc_mcontext.pc = (unsigned long)(uintptr_t)za_guest_base + 0x173df10ul;
            if (nnm2 < 4) {
                char b[160];
                char *q = b;
                q = za_put_str(q, "ZaGuest: ★ 名字表资源缺失→跳过建表 obj=");
                q = za_put_hex(q, self);
                q = za_put_str(q, "\n");
                za_fatal_write(b, (size_t)(q - b));
                nnm2++;
            }
            return;
        }
    }
    // ★ 2026-10-28：客机里的「近空指针读」受控恢复。
    //   实测有两处（sdk+0x3f70f4 `ldr x8,[x0]` 取未初始化的单例、
    //   main+0x1757a70 `ldr x8,[x8,#0x58]` 读 [obj+0x1f8] 为 0 的容器）
    //   都是「读到 0 再判空」的写法：真机上直接把进程打死，语义上等价于读到 0。
    //   严格条件：si_addr < 0x1000、pc 在 main/sdk 映像内、故障指令确实是
    //   `ldr Rt,[Xn,#imm]` 且 Xn+imm == si_addr。满足就把 Rt 置 0、pc += 4 继续；
    //   其余一律走原来的致命流程（不改判别的故障）。
    // ⚠ 早先实测它在「假表」时代会读出垃圾指针；现在配合补零页与定点跳转，
    //   近空读置 0 通常是这类代码的**本意**（读完立刻判空/比 0）。
    //   默认开启；files/za-no-nullrecover 或 ZA_NULLRECOVER=0 可关。
    static int nr_on = -1;
    if (nr_on < 0) {
        const char *e = getenv("ZA_NULLRECOVER");
        if (e && e[0] == '0') nr_on = 0;
        else if (access("/data/user/0/org.pokelegza.android.port/files/za-no-nullrecover",
                        F_OK) == 0) nr_on = 0;
        else nr_on = 1;
    }
    if (nr_on && ctx && sig == SIGSEGV && info &&
        (unsigned long long)(uintptr_t)info->si_addr < 0x1000ull)
    {
        ucontext_t *uc0 = (ucontext_t *)ctx;
        unsigned long pcv = (unsigned long)uc0->uc_mcontext.pc;
        unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
        int in_main = mb && pcv >= mb && pcv < mb + ZA_IMAGE_SIZE;
        int in_sdk = za_sdk_base && pcv >= za_sdk_base && pcv < za_sdk_base + za_sdk_size;
        if (in_main || in_sdk)
        {
            unsigned int w = *(volatile unsigned int *)(uintptr_t)pcv;
            unsigned int rt = w & 0x1fu, rn = (w >> 5) & 0x1fu;
            int is64 = ((w & 0xffc00000u) == 0xf9400000u);
            int is32 = ((w & 0xffc00000u) == 0xb9400000u);
            int is8  = ((w & 0xffc00000u) == 0x39400000u);
            int is16 = ((w & 0xffc00000u) == 0x79400000u);   // ldrh：实测崩在 sdk+0x80fb8
            int issw = ((w & 0xffc00000u) == 0xb9800000u);   // ldrsw
            if ((is64 || is32 || is8 || is16 || issw) && rn != 31)
            {
                unsigned long long base = (unsigned long long)uc0->uc_mcontext.regs[rn];
                unsigned long long scale = is8 ? 1ull : (is16 ? 2ull : (is64 ? 8ull : 4ull));
                unsigned long long imm = (unsigned long long)((w >> 10) & 0xfffu) * scale;
                if (base + imm == (unsigned long long)(uintptr_t)info->si_addr)
                {
                    // 同一个 pc 反复故障 ⇒ 这不是「读一次 0 就完了」的写法，
                    // 而是靠这次读的结果在循环。恢复下去只会空转，必须交回致命流程。
                    static unsigned long seen_pc[8];
                    static unsigned seen_n[8];
                    int slot = 0;
                    for (int i = 0; i < 8; i++) {
                        if (seen_pc[i] == 0) { slot = i; break; }
                        if (seen_pc[i] == pcv) { slot = i; break; }
                        if (i == 7) slot = (int)(pcv & 7u);
                    }
                    if (seen_pc[slot] != pcv) { seen_pc[slot] = pcv; seen_n[slot] = 0; }
                    // 上限从 3 提到 4096：真机上引擎会**成对地反复**解引用同一个空对象
                    // （0x2554b58 / 0x2554c18 交替出现，3 次就放弃 ⇒ 进程被打死）。
                    // 这两个站点都是「遍历 program 表、逐个读字段」，空对象在本作里是
                    // 常态（引擎的池槽位空着），所以允许它一直按「读到 0」走下去。
                    if (++seen_n[slot] > 4096) {
                        // 放弃恢复，走正常致命流程（下面会 dump 现场）
                    } else {
                    if (rt != 31) uc0->uc_mcontext.regs[rt] = 0;
                    uc0->uc_mcontext.pc = pcv + 4;
                    static int nrec;
                    if (nrec < 24)
                    {
                        char b[128];
                        char *q = b;
                        q = za_put_str(q, "ZaGuest: ★ 近空读恢复 pc=");
                        q = za_put_hex(q, (unsigned long long)pcv);
                        q = za_put_str(q, " rt=");
                        q = za_put_dec(q, rt);
                        q = za_put_str(q, " ← 0\n");
                        za_fatal_write(b, (size_t)(q - b));
                    }
                    nrec++;
                    return;
                    }
                }
            }
        }
    }
    // ★ 2026-10-29（A/B，默认关；files/za-kill-thread 打开）：
    //   走到这里说明所有定点/通用降级都没接住。若出错的不是客机主线程，
    //   只终结这一条线程、让进程继续跑——用来判断「主线程还能不能提交一帧」。
    //   Kill only the faulting thread (not the process) when it is not the guest main.
    if (ctx) {
        static int kill_on = -1;
        if (kill_on < 0)
            kill_on = access("/data/user/0/org.pokelegza.android.port/files/za-kill-thread", F_OK) == 0;
        if (kill_on) {
            long me = (long)syscall(SYS_gettid);
            if (za_guest_tid > 0 && me != za_guest_tid) {   // ⚠ za_guest_tid 未设置时别乱杀（会杀掉 UI 线程）
                static int nk;
                if (nk++ < 8)
                    ZLOGE("★ A/B：只终止出错线程 tid=%ld（pc=%#lx），进程继续", me,
                          (unsigned long)((ucontext_t *)ctx)->uc_mcontext.pc);
                syscall(SYS_exit, 0);
            }
        }
    }
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
                za_fatal_dump_maps_once();
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
            // ★ 2026-10-28：上面把 ours 置 1 之后必须真的**转去客机故障处理**。
            //   以前没有这条跳转：置了 1 却继续往下走到「致命信号无处理器 ⇒ 挂起」，
            //   日志写着「按客机故障处理」，线程实际被挂起了（主线程就是这样丢的）。
            if (ours) goto guest_fault;
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
guest_fault:
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
        za_fatal_dump_maps_once();
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

// ── 每线程 CPU 时间：找出「在自旋而不是在睡」的那条线程 ────────────────
// 停摆时 18 条线程全在等待表里，但持锁者可能压根没进 svc —— 它可能在
// sdk+0x13a630 的 `wfe` 自旋里。那种线程的 utime 会明显高于别人。
void za_dump_task_stats(void)
{
    DIR *d = opendir("/proc/self/task");
    if (!d) return;
    ZLOGE("★ 每线程 CPU 时间（utime/stime 单位=10ms；自旋者明显偏高）：");
    struct dirent *de;
    int n = 0;
    while ((de = readdir(d)) && n < 40) {
        long tid = atol(de->d_name);
        if (tid <= 0) continue;
        char path[64], buf[1024], comm[64] = "?";
        snprintf(path, sizeof path, "/proc/self/task/%ld/stat", tid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        ssize_t r = read(fd, buf, sizeof buf - 1);
        close(fd);
        if (r <= 0) continue;
        buf[r] = 0;
        char *lp = strchr(buf, '('), *rp = strrchr(buf, ')');
        if (lp && rp && rp > lp) {
            size_t cl = (size_t)(rp - lp - 1);
            if (cl >= sizeof comm) cl = sizeof comm - 1;
            memcpy(comm, lp + 1, cl);
            comm[cl] = 0;
        }
        // ')' 之后的字段：[0]=state [1]=ppid … [11]=utime [12]=stime
        char state = '?';
        unsigned long long ut = 0, st = 0;
        if (rp) {
            char *tok[16];
            int nt = 0;
            for (char *s = strtok(rp + 2, " "); s && nt < 16; s = strtok(NULL, " "))
                tok[nt++] = s;
            if (nt > 12) {
                state = tok[0][0];
                ut = strtoull(tok[11], NULL, 10);
                st = strtoull(tok[12], NULL, 10);
            }
        }
        ZLOGE("    tid=%ld %-16s state=%c utime=%llu stime=%llu", tid, comm, state, ut, st);
        n++;
    }
    closedir(d);
}

// 把信号打到「CPU 时间最高的那条线程」。
// 停摆时若某条线程在客机代码里自旋（例如 SDK 的 wfe 临界区循环），它根本
// 不发 svc ⇒ 等待表/探针都看不见它。SIGSEGV 会让致命处理器把它那一刻的
// pc/sp/x29 整份倒出来 —— 这是唯一能看到「自旋在哪」的办法。
// 采样信号（值在后面真正使用处也定义了一次，两处必须一致）。
#define ZA_SAMPLER_SIG 63

// 给**所有**线程投递一次采样信号，拿到「每条线程各自停在哪」的全景。
// 必须用专用信号 63（处理器只做纯存储）：以前用 SIGSEGV 采样，被自己的
// 致命处理器当成真故障，把被采样的线程（含主线程）永久挂起。
void za_sample_all_threads(void)
{
    DIR *d = opendir("/proc/self/task");
    if (!d) return;
    long self = (long)syscall(SYS_gettid);
    struct dirent *de;
    int n = 0;
    while ((de = readdir(d)) && n < 128) {
        long tid = atol(de->d_name);
        if (tid <= 0 || tid == self) continue;
        syscall(SYS_tgkill, (int)getpid(), (int)tid, ZA_SAMPLER_SIG);
        n++;
    }
    closedir(d);
}

long za_tgkill_hottest(int sig)
{
    DIR *d = opendir("/proc/self/task");
    if (!d) return -1;
    long self = (long)syscall(SYS_gettid);
    long best = -1;
    unsigned long long best_cpu = 0;
    struct dirent *de;
    int n = 0;
    while ((de = readdir(d)) && n < 80) {
        long tid = atol(de->d_name);
        if (tid <= 0 || tid == self) continue;
        char path[64], buf[1024];
        snprintf(path, sizeof path, "/proc/self/task/%ld/stat", tid);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        ssize_t r = read(fd, buf, sizeof buf - 1);
        close(fd);
        if (r <= 0) continue;
        buf[r] = 0;
        char *rp = strrchr(buf, ')');
        if (!rp) continue;
        char *tok[16];
        int nt = 0;
        for (char *s = strtok(rp + 2, " "); s && nt < 16; s = strtok(NULL, " "))
            tok[nt++] = s;
        if (nt <= 12) continue;
        unsigned long long cpu = strtoull(tok[11], NULL, 10) + strtoull(tok[12], NULL, 10);
        if (cpu > best_cpu) { best_cpu = cpu; best = tid; }
        n++;
    }
    closedir(d);
    if (best <= 0) return -1;
    ZLOGE("★ 取 CPU 最高的线程 tid=%ld（utime+stime=%llu）⇒ 投递信号 %d",
          best, best_cpu, sig);
    return syscall(SYS_tgkill, (int)getpid(), (int)best, sig);
}

// ── ptrace 自附加：读任意线程的真实寄存器现场 ────────────────────────
// 主线程的门不写 regs[]（实测 pc/sp/x29 全 0），所以从门的槽位拿不到它。
// ptrace(PTRACE_ATTACH) 同进程自附加可直接读内核保存的 pc/sp/x29 ——
// 这是「谁在跑、谁卡在哪条指令」最可靠的手段，其它线程也能一起看。
typedef struct {
    unsigned long long regs[31];
    unsigned long long sp;
    unsigned long long pc;
    unsigned long long pstate;
} za_pt_regs_t;

static int za_ptrace_regs(long tid, za_pt_regs_t *out)
{
    if (ptrace(PTRACE_ATTACH, tid, 0, 0) != 0) return -1;
    int st = 0;
    waitpid((pid_t)tid, &st, __WALL);
    struct iovec iov = { out, sizeof *out };
    int r = ptrace(PTRACE_GETREGSET, tid, (void *)(long)1 /* NT_PRSTATUS */, &iov);
    ptrace(PTRACE_DETACH, tid, 0, 0);
    return r;
}

void za_ptrace_dump_all(void)
{
    extern unsigned char *za_guest_base;
    extern volatile unsigned long za_sdk_base, za_sdk_size;
    unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
    DIR *d = opendir("/proc/self/task");
    if (!d) { ZLOGE("ptrace: 打不开 /proc/self/task (errno=%d)", errno); return; }
    ZLOGE("★ ptrace 全线程寄存器现场：");
    struct dirent *de;
    int n = 0, fails = 0;
    while ((de = readdir(d)) && n < 40) {
        long tid = atol(de->d_name);
        if (tid <= 0) continue;
        if (tid == (long)syscall(SYS_gettid)) continue;   // 不能附加自己
        za_pt_regs_t r;
        if (za_ptrace_regs(tid, &r) != 0) { fails++; continue; }
        const char *w;
        unsigned long long off = 0;
        if (r.pc >= mb && r.pc < mb + ZA_IMAGE_SIZE) { w = "main+"; off = r.pc - mb; }
        else if (za_sdk_base && r.pc >= za_sdk_base && r.pc < za_sdk_base + za_sdk_size)
        { w = "sdk+"; off = r.pc - za_sdk_base; }
        else { w = ""; off = r.pc; }
        ZLOGE("    tid=%ld pc=%s%#llx sp=%#llx fp=%#llx lr=%#llx",
              tid, w, off, r.sp, r.regs[29], r.regs[30]);
        n++;
    }
    closedir(d);
    ZLOGE("    （%d 条线程，%d 条 attach 失败）", n, fails);
}

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
    size_t area = 4 * 1024 * 1024 + 0x1000 + 0x100000;   // 多留 1MB 给下面的 id 偏移
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
    // ★★ 2026-10-28 根因修复：**每线程唯一 id**。
    //   客机用手写自旋锁，所有者判定是
    //       ubfx w24, TPIDR_EL0, #13, #7      ; id = (TLS >> 13) & 0x7f
    //       ldrb w8, [obj, #0xa] ; cmp w8, #0x5f ; cmp w8, w24
    //   见 main+0xd84490（真机反汇编）。也就是说线程 id 只能取 7 位，
    //   而 0x5f('_') 被占用作「已锁」哨兵。
    //   我们的 TLS 区域原来总是落在 b16+0x8000 附近、彼此又按 4MB 间隔
    //   （4MB/8KB = 0x200，&0x7f 后完全抵消）⇒ **多条线程算出同一个 id**，
    //   实测撞车：0x12/0x1a/0x4d 各出现两次，甚至有一条算出 0x5f。
    //   id 撞车 ⇒ 「这把锁是不是我持有的」判定错 ⇒ 锁永远解不开、全体停等。
    //   办法：把整块布局在 1MB 窗口内平移，强制 id 等于本线程的唯一槽号。
    {
        static volatile unsigned za_tls_slot;
        unsigned slot = __atomic_fetch_add(&za_tls_slot, 1, __ATOMIC_RELAXED);
        slot = slot % 0x7eu;                 // 1..=0x7e
        slot += 1;
        if (slot >= 0x5fu) slot += 1;        // 跳过 0x5f（'_' 哨兵）→ 最大 0x7f
        unsigned long id0 = ((unsigned long)(uintptr_t)t >> 13) & 0x7fu;
        unsigned long delta = ((slot - id0) & 0x7fu) * 0x2000ul;
        t = (void *)((char *)t + delta);
        ZLOGI("客机 TLS id 分配: tid=%ld slot=%#x（(A>>13)&0x7f 将等于该值）",
              (long)syscall(SYS_gettid), slot);
    }
    za_tls_state_t *st = za_tls_cur();
    st->tp16 = (unsigned long)b16;      // 仅诊断：不要拿它去读写内存
    st->tp = b;
    unsigned char *hdr = (unsigned char *)t;          // 头页 D
    unsigned char *area_p = hdr + 0x1000;             // TLS 变量区 A
    st->area = area_p;
    // D+0x98 = (A-D)/8 ⇒ 客机 helper 的 `ldr x9,[D,#0x98]; add D,x9,lsl#3` = A
    //
    // ★ 2026-10-31 E9：这个字段被引擎**同时**当两样用：
    //   ① scratch 槽深度（RAII：进作用域 +1 / 退 -1，槽地址 = D + 深度*8，
    //      值存 [槽+0x18]）——0xd7f2d0 / 0x194e3d0 两处同类习语；
    //   ② 我们当年以为的「变量区偏移」。
    //   若填 (A-D)/8，scratch 槽就**精确落在 A 上**，全引擎所有子系统共用
    //   A+0x18 这一个槽互相覆盖（E9 实测：派发/整备两个子系统 12 秒内
    //   在同一槽 0x74fef03018 互相踩）。
    //   ⇒ A/B 开关 files/za-tlsdepth0：填 0，scratch 落回头页自有区
    //   D+0x18..D+0x90（深度上限 16，正好塞进 0x98 之前）。
    {
        unsigned long long depth0 = (unsigned long long)((area_p - hdr) / 8);
        if (access("/data/user/0/org.pokelegza.android.port/files/za-tlsdepth0",
                   F_OK) == 0)
            depth0 = 0;
        *(unsigned long long *)(hdr + 0x98) = depth0;
    }
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
        // ★ 2026-10-28：主线程链里的 main+0xd84490 用
        //     ubfx w24, TPIDR_EL0, #13, #7   ⇒ 线程 id = (TP>>13)&0x7f
        //   做一把以 0x5f('_') 为哨兵的用户态自旋锁的**所有者判定**。
        //   两条线程算出同一个 id 就会互相把对方当成「自己」或永远等不到，
        //   所以这里把 id 打出来查重。
        ZLOGI("线程 id 采样: tid=%ld  id(b)=%#lx id(hdr)=%#lx id(A)=%#lx"
              "  (b=%#lx hdr=%#lx A=%#lx)",
              (long)syscall(SYS_gettid),
              (unsigned long)(((unsigned long)b >> 13) & 0x7f),
              (unsigned long)(((unsigned long)hdr >> 13) & 0x7f),
              (unsigned long)(((unsigned long)area_p >> 13) & 0x7f),
              (unsigned long)b, (unsigned long)hdr, (unsigned long)area_p);
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

// ── BinaryFileHeader 重定位诊断（2026-10-29 真机）────────────────────
// 首帧那块 BNSH 容器（magic `grsc`）的 [blk+0x28] 每次都比正确值**大
// 0x100000000（= main 装载基址，4GB）**，说明容器的内部指针被多重定位了一次。
// 这三个 API 是 main 从 SDK 导入的，我们能在导入表里接管成「透传 + 打日志」：
// 直接看到头指针、块指针、是否已重定位，以及容器头部的签名。
// Pass-through hooks around the SDK's BinaryFileHeader relocation API.
static za_mod_t za_sdk_mod;   // 前置声明（真正定义在后面，带初始化）
static int (*za_bin_hdr_isreloc)(const void *);
static void *(*za_bin_hdr_first)(const void *);
static void *(*za_bin_hdr_reltab)(const void *);
static void za_bfh_log(const char *what, const void *hdr, unsigned long long out)
{
    unsigned char q[0x30];
    struct iovec lo = { q, sizeof q }, ro = { (void *)(uintptr_t)hdr, sizeof q };
    int ok = hdr && process_vm_readv(getpid(), &lo, 1, &ro, 1, 0) == (ssize_t)sizeof q;
    ZLOGE("★ BFH %s hdr=%p out=%#llx 头=%08x %08x %08x %08x | %#llx %#llx",
          what, hdr, out,
          ok ? *(unsigned int *)(q + 0) : 0, ok ? *(unsigned int *)(q + 4) : 0,
          ok ? *(unsigned int *)(q + 8) : 0, ok ? *(unsigned int *)(q + 12) : 0,
          ok ? *(unsigned long long *)(q + 0x18) : 0ull,
          ok ? *(unsigned long long *)(q + 0x20) : 0ull);
}
static int za_bfh_isreloc(const void *hdr)
{
    if (!za_bin_hdr_isreloc)
        za_bin_hdr_isreloc = (int (*)(const void *))
            za_mod_lookup(&za_sdk_mod, "_ZNK2nn4util16BinaryFileHeader11IsRelocatedEv");
    int r = za_bin_hdr_isreloc ? za_bin_hdr_isreloc(hdr) : 0;
    static int n; if (n++ < 24) za_bfh_log("IsRelocated", hdr, (unsigned long long)r);
    return r;
}
static void *za_bfh_first(const void *hdr)
{
    if (!za_bin_hdr_first)
        za_bin_hdr_first = (void *(*)(const void *))
            za_mod_lookup(&za_sdk_mod, "_ZN2nn4util16BinaryFileHeader13GetFirstBlockEv");
    void *r = za_bin_hdr_first ? za_bin_hdr_first(hdr) : NULL;
    static int n; if (n++ < 24) za_bfh_log("GetFirstBlock", hdr, (unsigned long long)(uintptr_t)r);
    return r;
}
static void *za_bfh_reltab(const void *hdr)
{
    if (!za_bin_hdr_reltab)
        za_bin_hdr_reltab = (void *(*)(const void *))
            za_mod_lookup(&za_sdk_mod, "_ZN2nn4util16BinaryFileHeader18GetRelocationTableEv");
    void *r = za_bin_hdr_reltab ? za_bin_hdr_reltab(hdr) : NULL;
    static int n; if (n++ < 24) za_bfh_log("GetRelocationTable", hdr, (unsigned long long)(uintptr_t)r);
    return r;
}
// 重定位表本身：`Relocate()` 会按表的基址把容器内部指针改成绝对地址。
// 首帧那块 BNSH 的内部指针正好多出 0x100000000（main 基址），所以这里把
// 表头和调用前后的关键字段都打出来，看它用的基址是哪个。
static void (*za_reltab_reloc)(void *);
static void (*za_reltab_unreloc)(void *);
static void za_reltab_dump(const char *what, const void *t, const void *ret)
{
    unsigned char q[0x28];
    struct iovec lo = { q, sizeof q }, ro = { (void *)(uintptr_t)t, sizeof q };
    int ok = t && process_vm_readv(getpid(), &lo, 1, &ro, 1, 0) == (ssize_t)sizeof q;
    // 顺带看第一个块的 [+0x20]/[+0x28]：BFH 的 GetRelocationTable 返回 hdr+0x24028、
    // GetFirstBlock 返回 hdr+0x60，所以 blk = tbl - 0x23FC8。重定位前后各看一次，
    // 就能分清「文件里本来就是 pack 内偏移」还是「基址加错了」。
    unsigned long long b20 = 0, b28 = 0;
    {
        unsigned long long blk = (unsigned long long)(uintptr_t)t - 0x23FC8ull;
        unsigned long long v[2] = { 0, 0 };
        struct iovec l2 = { v, sizeof v }, r2 = { (void *)(uintptr_t)(blk + 0x20), sizeof v };
        if (process_vm_readv(getpid(), &l2, 1, &r2, 1, 0) == (ssize_t)sizeof v) { b20 = v[0]; b28 = v[1]; }
    }
    ZLOGE("★ RelTab %s tbl=%p ret=%p 表=%#llx %#llx %#llx %#llx %#llx | blk+0x20=%#llx blk+0x28=%#llx",
          what, t, ret,
          ok ? *(unsigned long long *)(q + 0x00) : 0ull,
          ok ? *(unsigned long long *)(q + 0x08) : 0ull,
          ok ? *(unsigned long long *)(q + 0x10) : 0ull,
          ok ? *(unsigned long long *)(q + 0x18) : 0ull,
          ok ? *(unsigned long long *)(q + 0x20) : 0ull, b20, b28);
}
static void za_reltab_reloc_h(void *tbl)
{
    if (!za_reltab_reloc)
        za_reltab_reloc = (void (*)(void *))
            za_mod_lookup(&za_sdk_mod, "_ZN2nn4util15RelocationTable8RelocateEv");
    za_reltab_dump("Relocate 前", tbl, NULL);
    if (za_reltab_reloc) za_reltab_reloc(tbl);
    za_reltab_dump("Relocate 后", tbl, NULL);
}
static void za_reltab_unreloc_h(void *tbl)
{
    if (!za_reltab_unreloc)
        za_reltab_unreloc = (void (*)(void *))
            za_mod_lookup(&za_sdk_mod, "_ZN2nn4util15RelocationTable10UnrelocateEv");
    za_reltab_dump("Unrelocate 前", tbl, NULL);
    if (za_reltab_unreloc) za_reltab_unreloc(tbl);
    za_reltab_dump("Unrelocate 后", tbl, NULL);
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
                // ★ 大块读一定要记下**目标缓冲地址**：资源容器就落在这些缓冲里，
                //   首帧那块 grsc 容器（0x6de3…）到底是哪个读填进去的，靠这一列对照。
                static int lg2;
                if (size >= 0x10000 || lg2 < 32)
                {
                    if (size >= 0x10000) { /* 大块每次都记，数量很少 */ }
                    else lg2++;
                    ZLOGE("★ fs::ReadFile(fd=%d \"%s\" off=%lld size=%lu buf=%p) => %zd",
                          fd, za_fs_path_of(h), off, size, buf, n);
                }
            }
            return 0;
        }
    }
    if (!d)
    {
        if (buf && size && size <= (4u << 20)) memset(buf, 0, (size_t)size);
        return 0;
    }
    if (off < 0) off = 0;
    if (!buf || (unsigned long long)off >= total) return 0;
    unsigned long n = (unsigned long)(total - (unsigned long long)off);
    if (n > size) n = size;
    memcpy(buf, d + (unsigned long)off, (size_t)n);
    if (out_read) *out_read = n;
    {
        static int lg;
        if (size >= 0x10000 || lg < 32)
        {
            if (size < 0x10000) lg++;
            ZLOGE("★ fs::ReadFile(内嵌 h=%#x \"%s\" off=%lld size=%lu buf=%p) => %lu/%lu",
                  h, za_fs_path_of(h), off, size, buf, n, total);
        }
    }
    return 0;
}
static unsigned int za_fs_readfile(unsigned int h, long long off, void *buf, unsigned long size)
{
    unsigned long lr0;
#if defined(__aarch64__)
    __asm__ __volatile__("mov %0, x30" : "=r"(lr0));
#else
    lr0 = 0;
#endif
    unsigned int r = za_fs_readfile_cnt(NULL, h, off, buf, size);
    // ★ 大块读：把**目标缓冲的归属**和调用者一起打出来。缓冲区落在
    //   scudo:secondary 还是客机自己的区，决定了它被谁释放、该在哪里挂钩子。
    if (size >= 0x10000) {
        static int once;
        if (once++ < 6) {
            char mm[320];
            za_maps_near((unsigned long long)(uintptr_t)buf & 0x00FFFFFFFFFFFFFFull,
                         mm, sizeof mm);
            {
                unsigned long gb = (unsigned long)za_guest_base;
                char who[40];
                if (gb && lr0 >= gb && lr0 < gb + ZA_IMAGE_SIZE)
                    snprintf(who, sizeof who, "main+%#lx", lr0 - gb);
                else if (za_sdk_base && lr0 >= za_sdk_base && lr0 < za_sdk_base + za_sdk_size)
                    snprintf(who, sizeof who, "sdk+%#lx", lr0 - za_sdk_base);
                else
                    snprintf(who, sizeof who, "%#lx", lr0);
                ZLOGE("★ 大块读 off=%lld size=%lu 调用者=%s 缓冲归属 %s",
                      off, size, who, mm);
            }
        }
    }
    return r;
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

// ── nn::oe（系统性能/运行模式服务）──────────────────────────────────────
// 真机上 `nn::oe::GetPerformanceMode()` 靠 `nn::oe::Initialize()` 建立的单例；
// 那个单例在 SDK 的 sdk+0xbacbb0，由 oe 的初始化路径创建。我们的 HLE 没有
// oe 服务，初始化没有真正完成 ⇒ GetPerformanceMode 里 `ldr x8,[x0]` 直接
// 解引用 NULL（真机实测 sdk+0x3f70f4，连跑几分钟后必崩）。
// oe 本来就是把「底座/掌机模式、焦点、语言」这些**固定答案**交给游戏的接口，
// 所以这里按 HLE 的方式直接给答案，不走 SDK 那条会解引用 NULL 的路径。
static unsigned za_oe_ok(void) { return 0; }                 // 各种 Set*/Enable*/Disable*
static unsigned za_oe_perf_mode(void) { return 1; }          // 1 = 掌机(Normal)
static unsigned za_oe_focus(void) { return 1; }              // 1 = 有焦点
static unsigned za_oe_lang(void) { return 1; }               // 1 = AmericanEnglish
static unsigned za_oe_no(void) { return 0; }                 // IsUserInactivity... = false
static unsigned za_oe_pop_message(unsigned *out) { if (out) *out = 0; return 0; }
static unsigned za_oe_pseudo_id(void *uuid) { if (uuid) memset(uuid, 0, 16); return 0; }

// ── nn::hid 输入（按参考实现 d2r-mobile 的做法）─────────────────────
// 真机上 hid 靠 InitializeNpad 建立的**共享内存**；我们把 InitializeNpad
// 接管成「成功」却没建共享内存，随后 SDK 的 GetNpadState 就会去读一块
// 从未映射/从未填充的状态 ⇒ 读到垃圾甚至卡住。参考实现（dm/host/hle_hid.c）
// 的做法是连查询接口一起接管，直接给「没有输入」。
// NpadFullKeyState / NpadHandheldState 都是 0x28 字节：
//   +0x00 sampling(u64) +0x08 buttons(u64) +0x10 lx,ly,rx,ry(i32×4)
//   +0x20 attributes(u32) +0x24 pad(u32)
static void za_hid_fill_npad(void *s)
{
    if (!s) return;
    memset(s, 0, 0x28);
    static unsigned long long seq;
    *(unsigned long long *)s = ++seq;          // sampling：每帧递增
}
static void za_hid_npad_fullkey(void *s, const unsigned *id) { (void)id; za_hid_fill_npad(s); }
static void za_hid_npad_handheld(void *s, const unsigned *id) { (void)id; za_hid_fill_npad(s); }
static unsigned za_hid_style_set(const unsigned *id) { (void)id; return 0; }   // 没有手柄
static unsigned za_hid_vib_handles(void *out, int max, const unsigned *id, unsigned style)
{ (void)out; (void)max; (void)id; (void)style; return 0; }                     // 0 个振动设备
static void za_hid_want_zero(unsigned v) { (void)v; }
static void za_hid_vib_zero(const void *a, const void *b) { (void)a; (void)b; }

// nn::err::ShowError：真机要连 err 服务弹错误框；宿主没有服务，直接吞掉
// （否则一条错误路径会把线程卡在 IPC 上）。参考实现同样接管。
static void za_err_show(unsigned long result) { (void)result; }

// ── nn::ngc::ProfanityFilter（玩家名敏感词过滤）──────────────────────
// 真机上词库放在**系统数据存档**里、经 IPC 挂载；宿主没有这个存档，
// SDK 自己的 Initialize 会失败并把内部表留成 NULL，之后
// CheckProfanityWords 在这张空表上查哈希就直接崩
// （真机实测 main+0x1757a70：ldr x8,[x8,#0x58]，[obj+0x1f8] == 0）。
// 参考实现（dm/host/hle_misc.c）的做法：整个类接管，恒判「无敏感词」。
static void za_ngc_ctor(void *self) { (void)self; }
static void za_ngc_dtor(void *self) { (void)self; }
static unsigned za_ngc_init(void *self, void *work, unsigned long long sz)
{ (void)self; (void)work; (void)sz; return 0; }
static unsigned za_ngc_version(void *self) { (void)self; return 0; }
static unsigned za_ngc_check(void *self, unsigned *masks, unsigned pat,
                             const char **words, unsigned long long n)
{
    (void)self; (void)pat; (void)words;
    for (unsigned long long i = 0; i < n; i++) masks[i] = 0;
    return 0;
}



// ★ 2026-10-29 实测：**不要**拦截 free 做诊断。客机的 malloc/free 解析到 main
//   自带的 musl 分配器（za_mod_lookup(&za_main_mod,...) 先命中），不是宿主 Scudo；
//   在 free 包装里调 malloc_usable_size 会对这些指针直接 abort（进程信号 6，
//   连致命处理器都来不及跑）。这条弯路已经试过，别再走。

// ── 分配器一致性垫片（2026-10-29，真机实测根因）────────────────────────
// 客机的 malloc/free/calloc/realloc/operator new/delete 由 **main 自带的 musl** 提供，
// 但下面这些 main 没导出、SDK 却导出了，于是被解析到 **SDK 自己的堆**：
//     memalign / posix_memalign / strdup / operator new[] / operator delete[]
// 于是同一块内存在 SDK 堆上分配、却由 musl 的 free 释放（或反过来）——
// 两套堆混用必然损坏。真机表现就是「一块二进制资源被释放后仍在被引用」。
// 这里把它们全部**改道到 main 的堆**，保证一套分配器。
// Allocator consistency: route these to main's own musl heap instead of the SDK's.
static za_mod_t za_main_mod;   // 前置声明（真正定义在下面，带初始化）
static void *za_main_malloc(size_t n)
{
    void *(*f)(size_t) = (void *(*)(size_t))za_mod_lookup(&za_main_mod, "malloc");
    return f ? f(n) : NULL;
}
static void *za_main_aligned_alloc(size_t align, size_t size)
{
    void *(*aa)(size_t, size_t) = (void *(*)(size_t, size_t))za_mod_lookup(&za_main_mod, "aligned_alloc");
    if (!aa) return NULL;
    if (align < sizeof(void *)) align = sizeof(void *);
    if (align & (align - 1)) return NULL;                  // 必须是 2 的幂
    size_t rounded = (size + align - 1) & ~(align - 1);    // aligned_alloc 要求 size 是 align 的倍数
    if (rounded < size) return NULL;
    return aa(align, rounded);
}
// 见下面「分配器接管」一节：这几个按模式（files/za-alloc-takeover）分派
static int za_alloc_mode(void);
static void *za_guest_aligned_impl(size_t al, size_t n);
static void *za_guest_malloc_impl(size_t n);
static void *za_guest_new_impl(size_t n);
static void *za_guest_new_aligned_impl(size_t n, size_t al);   // operator new(size, align_val_t)
static void za_guest_free_impl(void *p);
static void za_guest_delete_aligned_impl(void *p, size_t al);
static void *za_shim_memalign(size_t align, size_t size) { return za_guest_aligned_impl(align, size); }
static int za_shim_posix_memalign(void **out, size_t align, size_t size)
{
    if (!out) return 22;                                   // EINVAL
    if (align < sizeof(void *) || (align & (align - 1))) return 22;
    void *p = za_guest_aligned_impl(align, size);
    if (!p) return 12;                                     // ENOMEM
    *out = p;
    return 0;
}
static char *za_shim_strdup(const char *str)
{
    if (!str) return NULL;
    size_t n = strlen(str) + 1;
    char *p = (char *)za_guest_malloc_impl(n);
    if (p) memcpy(p, str, n);
    return p;
}
static void *za_shim_new_array(size_t n) { return za_guest_new_impl(n); }
static void za_shim_delete_array(void *p) { za_guest_free_impl(p); }
// malloc_usable_size：main 与 SDK 都没导出，落 dlsym 会用 bionic 的元数据去读
// musl 的指针。客机很少调；返回 0 比读坏元数据安全。
static size_t za_shim_usable_size(void *p) { (void)p; return 0; }


// C++17 对齐 / 不抛异常 / 数组变体：main 只导出了 _Znwm / _ZdlPv /
// _ZnwmSt11align_val_t，其余全由 SDK 的 operator new/delete 提供（SDK 自己的堆）。
// 全部改道到 main 的 musl，保证一套分配器。
static void za_shim_note(const char *n)
{
    static int c;
    if (c < 24) { c++; ZLOGE("★ 分配器垫片首次使用：%s", n); }
}
// ⚠ 对齐变体必须和对应的 delete 走**同一个堆**。接管模式下 delete 会落到
//   宿主 free（见 za_guest_delete_aligned_impl），这里如果继续用 main 的
//   `_ZnwmSt11align_val_t`（musl 堆），就是「musl 分配、宿主释放」的经典崩法。
static void *za_shim_new_array_aligned(size_t n, size_t al)
{
    za_shim_note("_ZnamSt11align_val_t");
    return za_guest_new_aligned_impl(n, al);
}
static void za_shim_delete_aligned(void *p, size_t al) { za_shim_note("_Zdl/_ZdaPvSt11align_val_t"); za_guest_delete_aligned_impl(p, al); }
static void *za_shim_new_nothrow(size_t n) { za_shim_note("_Znwm/_ZnamRKSt9nothrow_t"); return za_shim_new_array(n); }
static void za_shim_delete_nothrow(void *p) { za_shim_note("_ZdlPv/_ZdaPvRKSt9nothrow_t"); za_shim_delete_array(p); }


// ─────────── 分配器接管 + 释放隔离区（离线预置实验，2026-10-29）───────────
// 目标：首帧卡在一块**被提前释放的资源块**上（[blk+0x28] 指向的兄弟块已 munmap）。
// 只要能把「谁放掉的、什么时候放的」看清楚，或者干脆让大块永不真正归还，
// 就有机会让引擎走完一帧。开关（启动前建文件）：
//     files/za-alloc-takeover —— 客机的 C/C++ 分配器一律换成宿主堆，并记录大块释放
//     files/za-quarantine     —— 其中的**大块**（≥32KB）释放时只记账不归还
// 两者独立：只开 takeover 是「统一堆 + 记下释放者」，再加 quarantine 就是
// 「永不归还」的对照实验。
//
// ⚠ 为什么不用 bionic 的 malloc_usable_size 问大小：它对**不是本堆**的指针会
//   直接 abort（进程信号 6，见文件上方 2026-10-29 的实测记录）。所以接管模式
//   自带 16 字节头部（magic/size/base）：
//     · 头部 magic 对上 ⇒ 我们发的块，用 size 判断是否进隔离区，free(base) 归还；
//     · 对不上        ⇒ main 内部（不经导入表）用 musl 分配的指针，退回 musl free。
//   两条路都不碰 malloc_usable_size。
#define ZA_QN 512
#define ZA_HMAGIC 0x5a414c4cu
typedef struct za_hdr { unsigned int magic, size; void *base; } za_hdr_t;   // 16 字节

static void *za_q_ptr[ZA_QN];
static size_t za_q_sz[ZA_QN];
static int za_q_n;
static unsigned long za_free_total;

static int za_alloc_mode(void)
{
    static int m = -1;
    if (m < 0)
        m = access("/data/user/0/org.pokelegza.android.port/files/za-alloc-takeover",
                   F_OK) == 0;
    return m;
}
static int za_quar_mode(void)
{
    static int m = -1;
    if (m < 0)
        m = access("/data/user/0/org.pokelegza.android.port/files/za-quarantine",
                   F_OK) == 0;
    return m;
}
// ⚠ 必须**内联**在调用点取 x30：写成普通函数读到的是它自己的返回地址。
//   而且只能在函数**入口**取（任何一次调用都会覆盖 x30）。
#if defined(__aarch64__)
#define ZA_CALLER_LR() ({ unsigned long _l_; __asm__ __volatile__("mov %0, x30" : "=r"(_l_)); _l_; })
#else
#define ZA_CALLER_LR() 0ul
#endif
static void za_musl_free(void *p)
{
    void (*f)(void *) = (void (*)(void *))za_mod_lookup(&za_main_mod, "free");
    if (f) f(p);
}
static void *za_hdr_alloc(size_t n, size_t al)
{
    if (al < 16) al = 16;
    if (al & (al - 1)) return NULL;
    if (n > (size_t)-1 - al - sizeof(za_hdr_t)) return NULL;
    unsigned char *raw = (unsigned char *)malloc(n + al + sizeof(za_hdr_t));
    if (!raw) return NULL;
    uintptr_t u = ((uintptr_t)raw + sizeof(za_hdr_t) + al - 1) & ~(uintptr_t)(al - 1);
    za_hdr_t *h = (za_hdr_t *)(u - sizeof(za_hdr_t));
    h->magic = ZA_HMAGIC;
    h->size = (unsigned int)n;
    h->base = raw;
    return (void *)u;
}
static int za_hdr_get(void *p, za_hdr_t *out)
{
    if (!p) return 0;
    // 只读，不会因为「不是我们的块」而崩：musl 的 chunk 头同样在这个位置。
    za_hdr_t *h = (za_hdr_t *)((unsigned char *)p - sizeof(za_hdr_t));
    if (h->magic != ZA_HMAGIC || !h->base) return 0;
    out->magic = h->magic;
    out->size = h->size;
    out->base = h->base;
    return 1;
}
// ★ 2026-10-30：抓「等待期间对象被谁释放」。
//   真机实测：主线程阻塞在某个 job 对象的条件变量上（state 还是 1），几分钟后
//   再读那个对象已经**不可读** —— 等待者还睡着，对象已经被 free 了。
//   停摆快照会把「还没完成」的对象登记进来；此后任何落在
//   [addr-0x800, addr+0x800] 的 free 都记一条（释放者 lr + 线程），
//   用来找出「谁在等待期间把对象销毁了」。
#define ZA_WATCH_N 8
static volatile unsigned long long za_watch_base[ZA_WATCH_N];
static volatile int za_watch_used;
static __thread int za_watch_busy;      // 日志里不能再 malloc（会递归进 free）

void za_watch_free_register(unsigned long long a)
{
    if (!a) return;
    int n = __atomic_load_n(&za_watch_used, __ATOMIC_RELAXED);
    if (n > ZA_WATCH_N) n = ZA_WATCH_N;
    for (int i = 0; i < n; i++)
        if (za_watch_base[i] == a) return;          // 已登记
    int k = __atomic_fetch_add(&za_watch_used, 1, __ATOMIC_RELAXED);
    if (k < ZA_WATCH_N) za_watch_base[k] = a;
}
static int za_watch_hit(unsigned long long p)
{
    int n = __atomic_load_n(&za_watch_used, __ATOMIC_RELAXED);
    if (n > ZA_WATCH_N) n = ZA_WATCH_N;
    for (int i = 0; i < n; i++) {
        unsigned long long b = za_watch_base[i];
        if (!b) continue;
        if (p + 0x800 >= b && p <= b + 0x800) return i + 1;
    }
    return 0;
}
static void za_watch_log_free(void *p, unsigned long lr0, int which)
{
    if (za_watch_busy) return;
    za_watch_busy = 1;
    char b[192];
    int n = snprintf(b, sizeof b,
                     "★ 监视对象被释放 #%d：p=%p 基准=%#llx 差=%+lld tid=%ld 释放者 lr=%#lx",
                     which - 1, p, za_watch_base[which - 1],
                     (long long)((unsigned long long)(uintptr_t)p - za_watch_base[which - 1]),
                     (long)syscall(SYS_gettid), lr0);
    if (n > 0) ZLOGE("%s", b);
    za_watch_busy = 0;
}

// ★ 2026-10-30：释放环形缓冲。abort 现场里出现过「分配器对象 x21 已经不可读」
//   —— 对象在还被引用时就被释放了。而 fs/vtable 那条释放路径直接调宿主 free，
//   根本不进 za_guest_free_impl，所以光在导入表上打日志看不到它。
//   这里把所有释放（两条路径都记）压进定长环，abort/停摆时倒出来对照地址。
#define ZA_FR_N 256
// vt = 块首 8 字节（C++ 对象的 vtable）。有了它才能回答「被释放的是哪一类对象」，
// 也才能在 abort 现场的 x21/x19 与释放记录之间对上号。
typedef struct { unsigned long long p, sz, vt; unsigned long lr; long tid; } za_fr_t;
static za_fr_t za_fr[ZA_FR_N];
static volatile unsigned za_fr_pos;

void za_free_ring_add(void *p, unsigned long long sz, unsigned long lr)
{
    unsigned i = __atomic_fetch_add(&za_fr_pos, 1, __ATOMIC_RELAXED);
    za_fr_t *e = &za_fr[i % ZA_FR_N];
    e->p = (unsigned long long)(uintptr_t)p;
    e->sz = sz;
    e->lr = lr;
    e->tid = (long)syscall(SYS_gettid);
    e->vt = 0;
    // 只读对齐的、看起来是客机堆/映像内的地址；读坏了最多丢一条记录，
    // 但把 free 路径搞崩就不值得了，所以先做形态过滤。
    if (p) {
        unsigned long long a = (unsigned long long)(uintptr_t)p;
        if (!(a & 7) && a >= 0x10000ull && a < 0x0001000000000000ull)
            e->vt = *(volatile unsigned long long *)(uintptr_t)p;
    }
}

void za_free_ring_dump(const char *why, int n)
{
    unsigned pos = __atomic_load_n(&za_fr_pos, __ATOMIC_RELAXED);
    unsigned have = pos < ZA_FR_N ? pos : ZA_FR_N;
    if (n > (int)have) n = (int)have;
    unsigned long long gb = (unsigned long long)(uintptr_t)za_guest_base;
    unsigned long long sb = za_sdk_base;
    ZLOGE("★ 释放环（最近 %d 次，新→旧）%s：", n, why ? why : "");
    for (int i = 1; i <= n; i++) {
        const za_fr_t *e = &za_fr[(pos - i) % ZA_FR_N];
        const char *lrs;
        unsigned long loff = e->lr;
        if (gb && e->lr >= gb && e->lr < gb + ZA_IMAGE_SIZE) { lrs = "main+"; loff = e->lr - gb; }
        else if (sb && e->lr >= sb && e->lr < sb + za_sdk_size) { lrs = "sdk+"; loff = e->lr - sb; }
        else { lrs = ""; }
        // vt 也换算成 main+偏移 —— 同一个 vtable 的地址重复出现，就能认类别
        if (gb && e->vt >= gb && e->vt < gb + ZA_IMAGE_SIZE)
            ZLOGE("   p=%#llx sz=%llu vt=main+%#llx lr=%s%#lx tid=%ld",
                  e->p, e->sz, e->vt - gb, lrs, loff, e->tid);
        else
            ZLOGE("   p=%#llx sz=%llu vt=%#llx lr=%s%#lx tid=%ld",
                  e->p, e->sz, e->vt, lrs, loff, e->tid);
    }
}

// 在释放环里找某个地址（abort 现场的 x21/x19 是否刚被谁释放过）。
// 返回 0 = 没找到；非 0 = 找到（age = 距现在多少次释放之前）。
int za_free_ring_find(unsigned long long p, unsigned long *lr, long *tid, unsigned *age)
{
    if (!p) return 0;
    unsigned pos = __atomic_load_n(&za_fr_pos, __ATOMIC_RELAXED);
    unsigned have = pos < ZA_FR_N ? pos : ZA_FR_N;
    for (unsigned i = 0; i < have; i++) {
        const za_fr_t *e = &za_fr[(pos - 1 - i) % ZA_FR_N];
        if (e->p == p) {
            if (lr) *lr = e->lr;
            if (tid) *tid = e->tid;
            if (age) *age = i;
            return 1;
        }
    }
    return 0;
}

// ── E1b：按调用点拦截的释放隔离区（files/za-quar-free）──────────────
// 待裁决假设：abort 前那串「拆容器」释放（6 个固定调用点）、以及
// main+0x17042f4 释放监视对象（2026-10-30 watch 命中），到底是致命原因，
// 还是「操作失败后的清理」？只保留这几个调用点 free 的块不真归还，其余
// 释放完全不受影响 ⇒ 一轮对照就能看出 abort/停摆 消不消失。
// 调用点来源：2026-10-30 释放环（main+0x…，两轮 abort 现场顺序几乎一致）。
#define ZA_QFR_N 256
static const unsigned long za_quar_free_lrs[] = {
    0x1bafe78, 0x16e9964, 0xd97084, 0x176fc14, 0xf94688, 0x16c06d8, // 拆容器序列
    0x17042f4,                                                       // 监视对象被释放现场
};
static void *za_qfr_ptr[ZA_QFR_N];
static unsigned long za_qfr_lr[ZA_QFR_N];
static int za_qfr_n, za_qfr_full;
static __thread int za_qfr_busy;   // 隔离区里不能再打日志（logcat 自己会 malloc）
static int za_quar_free_mode(void)
{
    static int m = -1;
    if (m < 0)
        m = access("/data/user/0/org.pokelegza.android.port/files/za-quar-free",
                   F_OK) == 0;
    return m;
}
// lr 是否落在关注调用点集合里。返回 main+偏移；0 = 不在（或不在 main 里）。
static unsigned long za_quar_free_lr_off(unsigned long lr)
{
    unsigned long long gb = (unsigned long long)(uintptr_t)za_guest_base;
    if (!gb || lr < gb || lr >= gb + ZA_IMAGE_SIZE) return 0;
    unsigned long off = (unsigned long)(lr - gb);
    for (size_t i = 0; i < sizeof(za_quar_free_lrs) / sizeof(za_quar_free_lrs[0]); i++)
        if (off == za_quar_free_lrs[i]) return off;
    return 0;
}

// ★ E23：引擎 NVN wrapper 区（main+0x2500000..0x2560000）发起的释放
//   「只记账不归还」——验证「wrapper 对象被提前释放 ⇒ 悬空读 ⇒ NVN 静默」。
//   E22 实测静默点前该区连续悬空读宿主堆地址，随后垃圾 NVN 调用。
static int za_nvnleak_mode(void)
{
    static int m = -1;
    if (m < 0)
        m = access("/data/user/0/org.pokelegza.android.port/files/za-nvnleak",
                   F_OK) == 0;
    return m;
}

static void za_guest_free_impl(void *p)
{
    unsigned long lr0 = ZA_CALLER_LR();
    if (!p) return;
    za_free_ring_add(p, 0, lr0);
    {
        int w = za_watch_hit((unsigned long long)(uintptr_t)p);
        if (w) za_watch_log_free(p, lr0, w);
    }
    if (za_nvnleak_mode()) {
        unsigned long gb = (unsigned long)za_guest_base;
        if (gb && lr0 >= gb + 0x2500000ul && lr0 < gb + 0x2560000ul) {
            static int n;
            if (n++ < 8)
                ZLOGE("★ E23 NVN wrapper 释放被扣留 p=%p lr=main+%#lx（累计 %d）",
                      p, lr0 - gb, n);
            return;                      // 不归还
        }
    }
    if (za_quar_free_mode()) {
        unsigned long off = za_quar_free_lr_off(lr0);
        if (off) {
            if (za_qfr_n < ZA_QFR_N) {
                za_qfr_ptr[za_qfr_n] = p;
                za_qfr_lr[za_qfr_n] = lr0;
                za_qfr_n++;
                if (!za_qfr_busy && (za_qfr_n <= 16 || (za_qfr_n & 63) == 0)) {
                    za_qfr_busy = 1;
                    ZLOGE("★ [quar-free] 保留 %p（main+%#lx，第 %d 块）",
                          p, off, za_qfr_n);
                    za_qfr_busy = 0;
                }
                return;          // 不归还：裁决「释放是原因还是清理」
            }
            if (!za_qfr_full) {
                za_qfr_full = 1;
                if (!za_qfr_busy) {
                    za_qfr_busy = 1;
                    ZLOGE("★ [quar-free] 隔离区满（%d 块），关注释放改为照常归还",
                          ZA_QFR_N);
                    za_qfr_busy = 0;
                }
            }
        }
    }
    if (!za_alloc_mode()) { za_musl_free(p); return; }
    za_hdr_t h;
    if (!za_hdr_get(p, &h)) { za_musl_free(p); return; }
    za_free_total++;
    if (za_quar_mode() && h.size >= 32768 && za_q_n < ZA_QN) {
        za_q_ptr[za_q_n] = p;
        za_q_sz[za_q_n] = h.size;
        za_q_n++;
        if (za_q_n <= 16 || (za_q_n & 63) == 0)
            ZLOGE("★ [quarantine] 保留 %u 字节块 %p（第 %d 块，释放者 lr=%#lx）",
                  h.size, p, za_q_n, lr0);
        return;                       // 不归还：让悬空指针继续可读
    }
    if (za_free_total <= 32 || h.size >= 32768)
        ZLOGE("★ [free] %u 字节块 %p（累计 %lu 次，释放者 lr=%#lx）",
              h.size, p, za_free_total, lr0);
    free(h.base);
}
// 分配器里**不能直接打日志**：__android_log_print 自己会 malloc，再进来就
// 无限递归（真机实测：启动 0.2 秒就崩在宿主里，纹理 0）。用线程局部标志挡一层。
static __thread int za_alloc_log_busy;
static void za_alloc_log(const char *fmt, ...)
{
    char b[160];
    va_list ap;
    if (za_alloc_log_busy) return;
    za_alloc_log_busy = 1;
    va_start(ap, fmt);
    vsnprintf(b, sizeof b, fmt, ap);
    va_end(ap);
    ZLOGE("%s", b);
    za_alloc_log_busy = 0;
}
static void *za_guest_malloc_impl(size_t n)
{
    unsigned long lr0 = ZA_CALLER_LR();
    void *p;
    if (!za_alloc_mode()) p = za_main_malloc(n);
    else p = za_hdr_alloc(n ? n : 1, 16);
    if (p && n >= 0x10000) {
        static int na;
        if (na++ < 40) za_alloc_log("★ 大块分配 %zu 字节 -> %p（lr=%#lx）", n, p, lr0);
    }
    return p;
}
static void *za_guest_calloc_impl(size_t a, size_t b)
{
    if (!za_alloc_mode()) {
        void *(*f)(size_t, size_t) =
            (void *(*)(size_t, size_t))za_mod_lookup(&za_main_mod, "calloc");
        return f ? f(a, b) : NULL;
    }
    if (b && a > (size_t)-1 / b) return NULL;
    size_t n = a * b;
    void *p = za_hdr_alloc(n ? n : 1, 16);
    if (p) memset(p, 0, n);
    return p;
}
static void *za_guest_realloc_impl(void *p, size_t n)
{
    if (!za_alloc_mode()) {
        void *(*f)(void *, size_t) =
            (void *(*)(void *, size_t))za_mod_lookup(&za_main_mod, "realloc");
        return f ? f(p, n) : NULL;
    }
    if (!p) return za_hdr_alloc(n ? n : 1, 16);
    za_hdr_t h;
    if (!za_hdr_get(p, &h)) {          // 不是我们的块：交给 musl 原样处理
        void *(*f)(void *, size_t) =
            (void *(*)(void *, size_t))za_mod_lookup(&za_main_mod, "realloc");
        return f ? f(p, n) : NULL;
    }
    void *q = za_hdr_alloc(n ? n : 1, 16);
    if (!q) return NULL;
    size_t cpy = h.size < n ? h.size : n;
    if (cpy) memcpy(q, p, cpy);
    free(h.base);                      // 旧块直接归还：调用方已经放弃它
    return q;
}
static void *za_guest_aligned_impl(size_t al, size_t n)
{
    unsigned long lr0 = ZA_CALLER_LR();
    void *p;
    if (!za_alloc_mode()) p = za_main_aligned_alloc(al, n);
    else p = za_hdr_alloc(n ? n : 1, al);
    if (p && n >= 0x10000) {
        static int na;
        if (na++ < 40) za_alloc_log("★ 大块对齐分配 %zu 字节 (align %zu) -> %p（lr=%#lx）", n, al, p, lr0);
    }
    return p;
}
static void *za_guest_new_impl(size_t n) { return za_guest_malloc_impl(n ? n : 1); }
static void *za_guest_new_aligned_impl(size_t n, size_t al) { return za_guest_aligned_impl(al, n); }
static void za_guest_delete_aligned_impl(void *p, size_t al) { (void)al; za_guest_free_impl(p); }

static const za_host_sym_t za_host_syms[] = {
    // loader 提供的「runtime object file」（真机由 nnrtld 提供）
    { "__nnDetailNintendoSdkRuntimeObjectFile", (void *)za_host_runtime_object_file },
    // BinaryFileHeader 重定位诊断（透传 SDK 实现，只加日志）
    { "_ZN2nn4util16BinaryFileHeader13GetFirstBlockEv", (void *)za_bfh_first },
    { "_ZNK2nn4util16BinaryFileHeader13GetFirstBlockEv", (void *)za_bfh_first },
    { "_ZN2nn4util16BinaryFileHeader18GetRelocationTableEv", (void *)za_bfh_reltab },
    { "_ZNK2nn4util16BinaryFileHeader11IsRelocatedEv", (void *)za_bfh_isreloc },
    { "_ZN2nn4util15RelocationTable8RelocateEv", (void *)za_reltab_reloc_h },
    { "_ZN2nn4util15RelocationTable10UnrelocateEv", (void *)za_reltab_unreloc_h },
    // 分配器接管/隔离实验（files/za-alloc-takeover、files/za-quarantine 控制行为）
    { "malloc", (void *)za_guest_malloc_impl },
    { "free", (void *)za_guest_free_impl },
    { "calloc", (void *)za_guest_calloc_impl },
    { "realloc", (void *)za_guest_realloc_impl },
    { "aligned_alloc", (void *)za_guest_aligned_impl },
    { "_Znwm", (void *)za_guest_new_impl },
    { "_Znam", (void *)za_guest_new_impl },
    { "_ZdlPv", (void *)za_guest_free_impl },
    { "_ZdaPv", (void *)za_guest_free_impl },
    // 对齐变体必须**成对**改道：只改 delete 不改 new，就是「musl 分配、宿主释放」。
    { "_ZnwmSt11align_val_t", (void *)za_guest_new_aligned_impl },
    { "_ZnamSt11align_val_t", (void *)za_guest_new_aligned_impl },
    { "_ZdlPvSt11align_val_t", (void *)za_guest_delete_aligned_impl },
    { "_ZdaPvSt11align_val_t", (void *)za_guest_delete_aligned_impl },
    // nothrow 变体没有对齐参数，直接走同一套 impl
    { "_ZnwmRKSt9nothrow_t", (void *)za_shim_new_nothrow },
    { "_ZnamRKSt9nothrow_t", (void *)za_shim_new_nothrow },
    { "_ZdlPvRKSt9nothrow_t", (void *)za_shim_delete_nothrow },
    { "_ZdaPvRKSt9nothrow_t", (void *)za_shim_delete_nothrow },
    // 分配器一致性（见上面 za_shim_* 的注释）：一律走同一套堆
    { "memalign", (void *)za_shim_memalign },
    { "posix_memalign", (void *)za_shim_posix_memalign },
    { "strdup", (void *)za_shim_strdup },
    { "malloc_usable_size", (void *)za_shim_usable_size },

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

    // ── nn::oe：系统运行模式服务（HLE 直接给固定答案）─────────────────
    { "_ZN2nn2oe10InitializeEv",                       (void *)za_oe_ok },
    { "_ZN2nn2oe18GetPerformanceModeEv",               (void *)za_oe_perf_mode },
    { "_ZN2nn2oe20GetCurrentFocusStateEv",             (void *)za_oe_focus },
    { "_ZN2nn2oe18GetDesiredLanguageEv",               (void *)za_oe_lang },
    { "_ZN2nn2oe37IsUserInactivityDetectionTimeExtendedEv", (void *)za_oe_no },
    { "_ZN2nn2oe25TryPopNotificationMessageEPj",       (void *)za_oe_pop_message },
    { "_ZN2nn2oe17GetPseudoDeviceIdEPNS_4util4UuidE",  (void *)za_oe_pseudo_id },
    { "_ZN2nn2oe27SetPerformanceConfigurationENS0_15PerformanceModeEi", (void *)za_oe_ok },
    { "_ZN2nn2oe44SetPerformanceModeChangedNotificationEnabledEb", (void *)za_oe_ok },
    { "_ZN2nn2oe20SetFocusHandlingModeENS0_17FocusHandlingModeE", (void *)za_oe_ok },
    { "_ZN2nn2oe38SetUserInactivityDetectionTimeExtendedEb", (void *)za_oe_ok },
    { "_ZN2nn2oe15SetCpuBoostModeENS0_12CpuBoostModeE", (void *)za_oe_ok },
    { "_ZN2nn2oe15EnableRecordingEv",                    (void *)za_oe_ok },
    { "_ZN2nn2oe16DisableRecordingEv",                   (void *)za_oe_ok },
    { "_ZN2nn2oe16EnableScreenShotEv",                   (void *)za_oe_ok },
    { "_ZN2nn2oe17DisableScreenShotEv",                  (void *)za_oe_ok },
    { "_ZN2nn2oe17FinishStartupLogoEv",                  (void *)za_oe_ok },
    { "_ZN2nn2oe31EnterExitRequestHandlingSectionEv",    (void *)za_oe_ok },
    { "_ZN2nn2oe31LeaveExitRequestHandlingSectionEv",    (void *)za_oe_ok },

    // ── hid 查询侧（必须一起接管，见上面的注释）───────────────────────
    { "_ZN2nn3hid12GetNpadStateEPNS0_16NpadFullKeyStateERKj",  (void *)za_hid_npad_fullkey },
    { "_ZN2nn3hid12GetNpadStateEPNS0_17NpadHandheldStateERKj",  (void *)za_hid_npad_handheld },
    { "_ZN2nn3hid15GetNpadStyleSetERKj",                        (void *)za_hid_style_set },
    { "_ZN2nn3hid25GetVibrationDeviceHandlesEPNS0_21VibrationDeviceHandleEiRKjNS_4util10BitFlagSetILi32ENS0_12NpadStyleTagEEE", (void *)za_hid_vib_handles },
    { "_ZN2nn3hid18SendVibrationValueERKNS0_21VibrationDeviceHandleERKNS0_14VibrationValueE", (void *)za_hid_vib_zero },
    { "_ZN2nn3hid29SetNpadHandheldActivationModeENS0_26NpadHandheldActivationModeE", (void *)za_hid_want_zero },
    { "_ZN2nn3err9ShowErrorENS_6ResultE",                       (void *)za_err_show },

    // ── ngc 敏感词过滤（整类接管，见上面注释）─────────────────────────
    { "_ZN2nn3ngc15ProfanityFilterC1Ev",                       (void *)za_ngc_ctor },
    { "_ZN2nn3ngc15ProfanityFilterD1Ev",                       (void *)za_ngc_dtor },
    { "_ZN2nn3ngc15ProfanityFilter10InitializeEPvm",           (void *)za_ngc_init },
    { "_ZN2nn3ngc15ProfanityFilter17GetContentVersionEv",      (void *)za_ngc_version },
    { "_ZN2nn3ngc15ProfanityFilter19CheckProfanityWordsEPjjPPKcm", (void *)za_ngc_check },

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

// ★ 一次性探针：哪些「分配器」符号真的由 main / SDK 导出。
// 两套堆是隐患：客机 malloc/free 在 main 自带的 musl 里，若某个分配入口 main
// 没导出就会落到 dlsym → bionic 堆，之后被 musl 的 free 处理 ⇒ 堆损坏
// （真机表现为「资源块释放后仍被引用」）。这里把归属打出来。
void za_log_alloc_syms(void)
{
    static const char *names[] = {
        "malloc", "free", "calloc", "realloc", "memalign", "aligned_alloc",
        "posix_memalign", "strdup", "malloc_usable_size",
        "_Znwm", "_Znam", "_ZdlPv", "_ZdaPv",
        // C++17 对齐/不抛异常变体：这些如果落到 dlsym，就是 bionic 堆
        "_ZnwmSt11align_val_t", "_ZnamSt11align_val_t",
        "_ZdlPvSt11align_val_t", "_ZdaPvSt11align_val_t",
        "_ZnwmRKSt9nothrow_t", "_ZnamRKSt9nothrow_t",
        "_ZdlPvRKSt9nothrow_t", "_ZdaPvRKSt9nothrow_t", NULL
    };
    for (int k = 0; names[k]; k++) {
        void *m = za_mod_lookup(&za_main_mod, names[k]);
        void *d = za_mod_lookup(&za_sdk_mod, names[k]);
        ZLOGI("分配器符号 %-16s main=%p sdk=%p", names[k], m, d);
    }
}
static unsigned char *za_guest_main_base;

// 解析客机导入的符号。顺序与上游 d2r-mobile 的 guest_sym 一致：
//   ① 宿主自己的 nn::* 实现  ② 图形层接管表  ③ 模块导出表（SDK→main）  ④ 系统 libc/libc++
// ⚠ **模块导出表优先于 dlsym**：裸 malloc/free 是 main NSO 导出的**客机自己的 musl 分配器**，
//   落到 dlsym 会变成 bionic 的分配器 ⇒ SDK 与客机不是同一套堆。
void *za_gfx_hle_lookup(const char *name);
void *za_gfx_force_lookup(const char *name);
void *za_resolve_host(const char *name)
{
    if (name)
    {
        size_t n = strlen(name);
        if (n >= sizeof za_last_sym) n = sizeof za_last_sym - 1;
        memcpy(za_last_sym, name, n);
        za_last_sym[n] = 0;
    }
    // 参考工程图形层的**强制接管**表（dm 的 HLE_FORCE 条目，ELF 段 swforce）。
    // ⚠ 必须排在我们的 za_host_syms 之前：`nvnBootstrapLoader` 两边都有，
    //   先查我们那张表就会用影子层把图形层整体遮掉 —— 真机实测 Vulkan 设备
    //   建成功、窗口也有，但每个 NVN 入口都在影子层里假成功，submit 永远 0。
    {
        void *f = za_gfx_force_lookup(name);
        if (f) return f;
    }
    for (const za_host_sym_t *h = za_host_syms; h->name; h++)
        if (!strcmp(h->name, name)) return h->fn;
    // 参考工程图形层的普通 HLE 表（放在 ELF 段 swhle）。
    // ⚠ 必须排在模块导出表之前：nvnBootstrapLoader 是 SDK 里也有定义的，
    //   落回 SDK 就会执行真机 NS 的 NVN 驱动（桌面 GPU 命令，安卓上必崩）。
    void *p = za_gfx_hle_lookup(name);
    if (p) return p;
    p = za_mod_lookup(&za_sdk_mod, name);
    if (p) return p;
    p = za_mod_lookup(&za_main_mod, name);
    if (p) return p;
    p = dlsym(RTLD_DEFAULT, name);
    if (p) {
        // ★ 2026-10-29 真机：落在这条兜底的符号会解析到 **bionic**（Scudo 堆）。
        //   首帧那块资源容器就在 scudo:secondary 里，说明它的分配/释放走的是
        //   bionic 而不是 main 的 musl —— 而我们的分配器钩子只看得到导入表。
        //   把「谁走了兜底」逐个记下来，才知道该补哪几个名字。
        static char seen[64][64];
        static int nseen;
        int known = 0;
        for (int i = 0; i < nseen; i++) if (!strcmp(seen[i], name)) { known = 1; break; }
        if (!known && nseen < 64) {
            snprintf(seen[nseen], sizeof seen[0], "%s", name);
            nseen++;
            ZLOGE("★ 导入走 bionic 兜底：%s -> %p", name, p);
        }
    }
    return p;
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
#define ZA_MPROBE_STUB2 0x604A000u   // E2b 第二桩页（bss 区，装上后补 RX）
#define ZA_MPROBE_STUB3 0x604B000u   // E12 第三桩页
static void za_hook_m_poolinit(unsigned long long *r);
static void za_dump_mpsc_lanes(unsigned long long q, const char *when);   // E6
static void za_hook_m_poolloop(unsigned long long *r);
static void za_hook_m_w2(unsigned long long *r);
static void za_hook_m_w3(unsigned long long *r);
static void za_hook_m_jobwait(unsigned long long *r);
static void za_hook_m_jobsubmit(unsigned long long *r);
static void za_hook_m_jobdispatch(unsigned long long *r);
static void za_hook_m_jobpost(unsigned long long *r);
static void za_hook_m_dequeue(unsigned long long *r);static void za_hook_m_enq2(unsigned long long *r);
static void za_hook_m_enq3(unsigned long long *r);
static void za_hook_m_jobenqueue(unsigned long long *r);
static void za_hook_m_jobctor(unsigned long long *r);   // E2: 0x17395d0
static void za_hook_m_push(unsigned long long *r);      // E2: 0x16ffd70
static void za_hook_m_brancha(unsigned long long *r);   // E2: 0xa6a2e0
static void za_hook_m_f2d0(unsigned long long *r);      // E2b: 0xd7f2d0 入口
static void za_hook_m_reach940(unsigned long long *r);  // E2b: 0xd7f940 构造前
static void za_hook_m_allocbail(unsigned long long *r); // E2b: 0xd7fa98 分配弃单
static void za_hook_m_fwd(unsigned long long *r);       // E3: 0x255ae70 命令转发器
static void za_hook_m_qdtor(unsigned long long *r);     // E3: 0x1703390 队列析构
static void za_hook_m_picker(unsigned long long *r);    // E7: 0x194e850 派发侧选命令
static void za_hook_m_stash_disp(unsigned long long *r);   // E9: 0xd7f30c 派发路径 stash
static void za_hook_m_stash_intake(unsigned long long *r); // E9: 0x194e458 整备路径 stash
static void za_hook_m_mover(unsigned long long *r);        // E10: 0x194e3d0 搬运族入口
static void za_hook_m_sub0(unsigned long long *r);         // E11
static void za_hook_m_sub1(unsigned long long *r);
static void za_hook_m_sub2(unsigned long long *r);
static void za_hook_m_sub3(unsigned long long *r);
static void za_hook_m_sub4(unsigned long long *r);
static void za_hook_m_rb_enter(unsigned long long *r);     // E12: 0xd7fa3c
static void za_hook_m_rb_fdb0(unsigned long long *r);      // E12: 0xd7fa64
static void za_hook_m_rb_d81f60(unsigned long long *r);    // E12: 0xd81f60
static void za_hook_m_find(unsigned long long *r);         // E14: 0x1706640
static void za_hook_m_vt0(unsigned long long *r);          // E16
static void za_hook_m_vt1(unsigned long long *r);
static void za_hook_m_vt2(unsigned long long *r);
static void za_hook_m_vt3(unsigned long long *r);
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
        // ★ 2026-10-31 E9（同 per-thread 页）：这格同时被引擎当 scratch 深度
        //   计数用（进 +1/退 -1，槽 = P + 深度*8，值存 [槽+0x18]）。填 (V-P)/8
        //   会把 scratch 槽精确压到变量区头部，各子系统互相覆盖。
        //   A/B：files/za-tlsdepth0 时填 0，scratch 回到头页 P+0x18 起的自有区。
        {
            unsigned long long depth0 =
                (unsigned long long)((ZA_TLS_VAR_OFF - ZA_TLS_DESC_OFF) / 8);
            if (access("/data/user/0/org.pokelegza.android.port/files/za-tlsdepth0",
                       F_OK) == 0)
                depth0 = 0;
            *(unsigned long long *)(base + ZA_TLS_DESC_OFF + 0x98) = depth0;
        }
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

    // ── 「名字查询懒建表」两个入口的说明（不改指令）───────────────────
    //   main+0x173ded0 与 main+0x17577d0 在资源（obj+0x1e0）缺失时都会解引用空指针。
    //   两个函数开头都有「缓存命中就早退」的分支（要求 obj+0x1e8 非零），所以
    //   由崩溃恢复统一给它们塞一个**合法的名字结构指针**（见 za_fake_name_ptr），
    //   而不是改指令让它们返回 0 —— 实测返回 0 会被下游当指针解引用
    //   （真机崩在 main+0x17389a4，addr=0）。
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
        // 任务系统：等待入口 + 提交入口（回答「任务排上了没有」）
        za_install_main_probe(base, 0x1938e30, ZA_MPROBE_STUB + 0x200, ZA_MPROBE_SLOT + 0x20, za_hook_m_jobwait);
        za_install_main_probe(base, 0xd26b90, ZA_MPROBE_STUB + 0x280, ZA_MPROBE_SLOT + 0x28, za_hook_m_jobsubmit);
        // 提交函数内部的调用点 + worker 出队侧
        za_install_main_probe(base, 0xd270d8, ZA_MPROBE_STUB + 0x300, ZA_MPROBE_SLOT + 0x30, za_hook_m_jobdispatch);
        za_install_main_probe(base, 0xd270ec, ZA_MPROBE_STUB + 0x380, ZA_MPROBE_SLOT + 0x38, za_hook_m_jobpost);
        za_install_main_probe(base, 0x1bab3a0, ZA_MPROBE_STUB + 0x400, ZA_MPROBE_SLOT + 0x40, za_hook_m_dequeue);
        za_install_main_probe(base, 0xd848fc, ZA_MPROBE_STUB + 0x480, ZA_MPROBE_SLOT + 0x48, za_hook_m_jobenqueue);
        za_install_main_probe(base, 0xd82644, ZA_MPROBE_STUB + 0x500, ZA_MPROBE_SLOT + 0x50, za_hook_m_enq2);
        za_install_main_probe(base, 0x16ffeb0, ZA_MPROBE_STUB + 0x580, ZA_MPROBE_SLOT + 0x58, za_hook_m_enq3);
        // E2 派发链中间三环（桩区 0x600/0x680/0x780 空闲；0x700 是「返回0」桩）
        za_install_main_probe(base, 0x17395d0, ZA_MPROBE_STUB + 0x600, ZA_MPROBE_SLOT + 0x60, za_hook_m_jobctor);
        za_install_main_probe(base, 0x16ffd70, ZA_MPROBE_STUB + 0x680, ZA_MPROBE_SLOT + 0x68, za_hook_m_push);
        za_install_main_probe(base, 0xa6a2e0,  ZA_MPROBE_STUB + 0x780, ZA_MPROBE_SLOT + 0x78, za_hook_m_brancha);
        // E2b 二分：桩页 2（0x604A000，bss 区现成 RW，下面补 mprotect RX）
        za_install_main_probe(base, 0xd7f2d0,  ZA_MPROBE_STUB2,        ZA_MPROBE_SLOT + 0x80, za_hook_m_f2d0);
        za_install_main_probe(base, 0xd7f940,  ZA_MPROBE_STUB2 + 0x80, ZA_MPROBE_SLOT + 0x88, za_hook_m_reach940);
        za_install_main_probe(base, 0xd7fa98,  ZA_MPROBE_STUB2 + 0x100, ZA_MPROBE_SLOT + 0x90, za_hook_m_allocbail);
        // E3：消费侧（命令转发器）+ 拆证据（队列析构）
        za_install_main_probe(base, 0x255ae70, ZA_MPROBE_STUB2 + 0x180, ZA_MPROBE_SLOT + 0x98, za_hook_m_fwd);
        za_install_main_probe(base, 0x1703390, ZA_MPROBE_STUB2 + 0x200, ZA_MPROBE_SLOT + 0xA0, za_hook_m_qdtor);
        // E7：派发侧选命令入口——x0=派发器查询的容器，与被 push 的容器对账
        za_install_main_probe(base, 0x194e850, ZA_MPROBE_STUB2 + 0x280, ZA_MPROBE_SLOT + 0xA8, za_hook_m_picker);
        // E9：TLS scratch 覆盖证明——两处 stash 点（探针在 str 前触发，读槽旧值）
        za_install_main_probe(base, 0xd7f30c,  ZA_MPROBE_STUB2 + 0x300, ZA_MPROBE_SLOT + 0xB0, za_hook_m_stash_disp);
        za_install_main_probe(base, 0x194e458, ZA_MPROBE_STUB2 + 0x380, ZA_MPROBE_SLOT + 0xB8, za_hook_m_stash_intake);
        // E10：搬运族入口——x0 与 P（被 push）/ D（派发器）三方对账
        za_install_main_probe(base, 0x194e3d0, ZA_MPROBE_STUB2 + 0x400, ZA_MPROBE_SLOT + 0xC0, za_hook_m_mover);
        // E11：dispatch 的其余五个子调用（谁该把 P 里的活领走/推进状态机）
        za_install_main_probe(base, 0xd7cd10,  ZA_MPROBE_STUB2 + 0x480, ZA_MPROBE_SLOT + 0xC8, za_hook_m_sub0);
        za_install_main_probe(base, 0xd7e820,  ZA_MPROBE_STUB2 + 0x500, ZA_MPROBE_SLOT + 0xD0, za_hook_m_sub1);
        za_install_main_probe(base, 0xd7eb10,  ZA_MPROBE_STUB2 + 0x580, ZA_MPROBE_SLOT + 0xD8, za_hook_m_sub2);
        za_install_main_probe(base, 0x1700c40, ZA_MPROBE_STUB2 + 0x600, ZA_MPROBE_SLOT + 0xE0, za_hook_m_sub3);
        za_install_main_probe(base, 0xd7f040,  ZA_MPROBE_STUB2 + 0x680, ZA_MPROBE_SLOT + 0xE8, za_hook_m_sub4);
        // E12：B 的回滚路径（refcount==-1 → 销毁+清理）三针
        za_install_main_probe(base, 0xd7fa3c,  ZA_MPROBE_STUB2 + 0x700, ZA_MPROBE_SLOT + 0xF0, za_hook_m_rb_enter);
        za_install_main_probe(base, 0xd7fa64,  ZA_MPROBE_STUB2 + 0x780, ZA_MPROBE_SLOT + 0xF8, za_hook_m_rb_fdb0);
        za_install_main_probe(base, 0xd81f60,  ZA_MPROBE_STUB3,         ZA_MPROBE_SLOT + 0x100, za_hook_m_rb_d81f60);
        // E14：P 的哈希 find（只读遍历，不改变 count）
        za_install_main_probe(base, 0x1706640, ZA_MPROBE_STUB3 + 0x80,  ZA_MPROBE_SLOT + 0x108, za_hook_m_find);
        // E16：P 类 vtable 剩余槽位 + 同族 0x16ffb40
        za_install_main_probe(base, 0x255aec0, ZA_MPROBE_STUB3 + 0x100, ZA_MPROBE_SLOT + 0x110, za_hook_m_vt0);
        za_install_main_probe(base, 0x255af80, ZA_MPROBE_STUB3 + 0x180, ZA_MPROBE_SLOT + 0x118, za_hook_m_vt1);
        za_install_main_probe(base, 0x255af04, ZA_MPROBE_STUB3 + 0x200, ZA_MPROBE_SLOT + 0x120, za_hook_m_vt2);
        za_install_main_probe(base, 0x16ffb40, ZA_MPROBE_STUB3 + 0x280, ZA_MPROBE_SLOT + 0x128, za_hook_m_vt3);
        // ⚠ 试过在 main+0x102d180 / 0x102d3c8 / 0x102d020 装分配器探针，已全部撤掉：
        //   这三个点都在「对象+8 取分配器 → blr [vt+0x10]」的失败路径上，x21 可能是
        //   空/野值，桩里重放的 `ldr x8,[x21]` 会异常；而桩地址 0x6048xxx 落在
        //   ZA_IMAGE_SIZE(0x5f7a000) 之外，故障处理器认不出，按「野调用→返回 0」
        //   把 PC 设成 x30 —— 等于让 0x102cf70 提前返回，调用方拿着垃圾 x20 继续跑，
        //   真机实测 5 秒内 23 次野调用后崩在宿主堆地址 0x6f5b0ec550。
        //   结论：这条路径只能靠 abort 帧链（za_sdk.c 的 abort-entry）读，不能改代码。
        (void)0;
        // ⚠ 试过在 main+0x19554c0（`bl nn::fs::OpenFile`）装探针来抓路径：
        //   这条指令是 **bl**，桩重放后 x30 指向桩内，实测把后续控制流带进了
        //   main 的 BSS（pc=main+0x76b732c）。call 类指令不适合这套探针，已移除。
        // 「返回 0」桩：虚函数指针为空时的替身（mov x0,#0; ret）。
        // 真机 main+0x2553d48 `ldr x0,[x0,x8]` 在 obj=null 时取不到虚函数；
        // 置 0 会让调用方 `blr 0`，给一个真能调、返回 0 的桩更安全。
        {
            unsigned int *st = (unsigned int *)(base + 0x6048700u);
            st[0] = 0xd2800000u;   // mov x0, #0
            st[1] = 0xd65f03c0u;   // ret
        }
        // ★ 2026-10-29（A/B，默认关；files/za-nop-fill 打开）：
        //   首个坏读的调用链是 main+0x251f814 ← 0xed91d4 ← 0xecafd0 ← 0xa6a6d8
        //   ← 任务线程，中间 main+0x251f810 的 `bl 0x24fa77c` 会把一堆
        //   **半初始化的 program wrapper** 填进表里（entry+0x68 是空/野），
        //   之后整棵对象图带着垃圾往下走。把这个填充调用跳过，看引擎能否
        //   继续到下一趟绘制——用来判断这一步是不是「可选的一趟」。
        if (access("/data/user/0/org.pokelegza.android.port/files/za-nop-fill", F_OK) == 0) {
            unsigned int *w = (unsigned int *)(base + 0x251f810u);
            if (*w == 0x97ff6bdbu) {          // bl 0x24fa77c（原字节校验后才改）
                *w = 0xd503201fu;             // nop
                __builtin___clear_cache((char *)w, (char *)w + 4);
                ZLOGE("★ A/B：已跳过 main+0x251f810 的 program wrapper 填充（bl→nop）");
            } else {
                ZLOGE("★ A/B：main+0x251f810 指令字不符（%#x），未打补丁", *w);
            }
        }
        __builtin___clear_cache((char *)base + ZA_MPROBE_STUB, (char *)base + ZA_MPROBE_STUB + 0x800);
        mprotect(base + ZA_MPROBE_STUB, 0x1000, PROT_READ | PROT_EXEC);
        // E2b 第二桩页：同法清缓存 + RX（0x6049000 槽页保持 RW）
        __builtin___clear_cache((char *)base + ZA_MPROBE_STUB2, (char *)base + ZA_MPROBE_STUB2 + 0x800);
        mprotect(base + ZA_MPROBE_STUB2, 0x1000, PROT_READ | PROT_EXEC);
        // E12 第三桩页
        __builtin___clear_cache((char *)base + ZA_MPROBE_STUB3, (char *)base + ZA_MPROBE_STUB3 + 0x800);
        mprotect(base + ZA_MPROBE_STUB3, 0x1000, PROT_READ | PROT_EXEC);
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
static size_t za_fs_set_sz[ZA_FS_SET_SIZE];
static pthread_mutex_t za_fs_set_mtx = PTHREAD_MUTEX_INITIALIZER;
static int za_fs_set_full_logged;
static unsigned za_fs_foreign_free;

static void za_fs_set_add(void *p, size_t sz)
{
    unsigned h = (unsigned)(((uintptr_t)p >> 4) & (ZA_FS_SET_SIZE - 1));
    pthread_mutex_lock(&za_fs_set_mtx);
    for (unsigned i = 0; i < ZA_FS_SET_SIZE; i++)
    {
        unsigned k = (h + i) & (ZA_FS_SET_SIZE - 1);
        if (za_fs_set[k] == NULL) { za_fs_set[k] = p; za_fs_set_sz[k] = sz; break; }
    }
    pthread_mutex_unlock(&za_fs_set_mtx);
}
static int za_fs_set_take(void *p, size_t *sz_out)
{
    unsigned h = (unsigned)(((uintptr_t)p >> 4) & (ZA_FS_SET_SIZE - 1));
    int found = 0;
    pthread_mutex_lock(&za_fs_set_mtx);
    for (unsigned i = 0; i < ZA_FS_SET_SIZE; i++)
    {
        unsigned k = (h + i) & (ZA_FS_SET_SIZE - 1);
        if (za_fs_set[k] == p) {
            if (sz_out) *sz_out = za_fs_set_sz[k];
            za_fs_set[k] = NULL; za_fs_set_sz[k] = 0; found = 1; break;
        }
        if (za_fs_set[k] == NULL) break;
    }
    pthread_mutex_unlock(&za_fs_set_mtx);
    return found;
}
// fs/vtable 路径的隔离区：**不依赖全局接管**。
// 大块资源缓冲（BNSH 容器）就是这条路上 posix_memalign 出来的（真机实测落在
// scudo:secondary），所以只要这条路的释放被保留，就能验证「提前 free 是不是首帧墙」。
#define ZA_FQN 256
static void *za_fq_ptr[ZA_FQN];
static size_t za_fq_sz[ZA_FQN];
static int za_fq_n;
static int za_fq_mode(void)
{
    static int m = -1;
    if (m < 0)
        m = access("/data/user/0/org.pokelegza.android.port/files/za-quarantine", F_OK) == 0;
    return m;
}
static void za_fs_guard_free(void *p, const char *who)
{
    size_t sz = 0;
    if (!p) return;
    int owned = za_fs_set_take(p, &sz);
    {
        extern void za_free_ring_add(void *p, unsigned long long sz, unsigned long lr);
        // ⚠ 不能用内联 asm 读 x30：函数中途 x30 已被调用者约定的临时用途改掉，
        //   实测记下来的是记录函数自己的地址（0x11cce8 = za_free_ring_add）。
        unsigned long lr0 = (unsigned long)(uintptr_t)__builtin_return_address(0);
        za_free_ring_add(p, (unsigned long long)sz, lr0);
        int w = za_watch_hit((unsigned long long)(uintptr_t)p);
        if (w) za_watch_log_free(p, lr0, w);
    }
    if (owned) {
        if (za_fq_mode() && sz >= 32768 && za_fq_n < ZA_FQN) {
            za_fq_ptr[za_fq_n] = p;
            za_fq_sz[za_fq_n] = sz;
            za_fq_n++;
            if (za_fq_n <= 8 || (za_fq_n & 63) == 0)
                ZLOGE("★ [fs-quarantine] 保留 %zu 字节块 %p（第 %d 块）", sz, p, za_fq_n);
            return;                    // 不归还：验证悬空引用能否被救活
        }
        if (za_mem_guest_owns(p)) za_mem_guest_free(p);
        else free(p);
        return;
    }
    if (za_fs_foreign_free++ < 6)
        ZLOGE("fs %s：%p 不是宿主分配器给的 ⇒ 跳过 free（防止写坏宿主堆）", who, p);
}

void *za_fs_alloc_host(unsigned long size)
{
    // ★ fs 读缓冲交给客机写 ⇒ 走客机共享区（宿主堆会被客机越界写坏）
    void *p = za_mem_guest_alloc(size ? (size_t)size : 1, 16);
    if (p) za_fs_set_add(p, (size_t)size);
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
    unsigned long lr0 = ZA_CALLER_LR();
    (void)obj;
    void *p = NULL;
    if (align < sizeof(void *)) align = sizeof(void *);
    if ((align & (align - 1)) != 0) align = 16;      // 非 2 的幂：退回 16
    // 接管模式下走同一套自带头部堆（接管模式本身有问题，默认不用）
    if (za_alloc_mode()) p = za_guest_aligned_impl((size_t)align, size ? (size_t)size : 1);
    else if (posix_memalign(&p, (size_t)align, size ? (size_t)size : 1) != 0) return NULL;
    if (p) {
        za_fs_set_add(p, size ? (size_t)size : 1);
        // ★ 大块分配记一笔：首帧那块 grsc 资源容器到底是不是从这里出去的，
        //   和大块读的 buf 地址一对照就知道。
        if (size >= 0x10000) {
            static int nv;
            if (nv++ < 40) ZLOGE("★ fs vt 大块分配 %lu 字节 -> %p（lr=%#lx）", size, p, lr0);
        }
    }
    return p;
}
void za_fs_vt_free(void *obj, void *ptr, unsigned long size, unsigned long align)
{
    (void)obj; (void)size; (void)align;
    za_fs_guard_free(ptr, "vt-free");
}

// 看门狗的「伪唤醒」默认关闭：SDK 的条件变量等待者环（cap=100）会被
// 每次伪唤醒多塞一条记录，且没有真实信号可消耗 ⇒ 几轮就写满。
// 需要区分「我们丢了唤醒 / 对方确实没生产」时，手动放标记文件打开。
static int za_fakewake_on(void)
{
    static int cached = -1;
    if (cached < 0) {
        cached = access("/data/local/tmp/za-fakewake", F_OK) == 0 ||
                 access("/data/user/0/org.pokelegza.android.port/files/za-fakewake", F_OK) == 0;
        ZLOGI("看门狗伪唤醒：%s", cached ? "开" : "关");
    }
    return cached;
}

// ── 基址重定位 ──────────────────────────────────────────────────// NSO 里**一条 RELATIVE 重定位都没有**：.data 里的模块内指针要自己加基址。
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
// ★ 2026-10-28：以前只打前 6 次，看不出「同一个池被重建了几次」。现在一直计数，
//   并把 x30（调用者返回地址）也打出来 —— 谁在反复初始化这个池就是它。
static void za_hook_m_poolinit(unsigned long long *r)
{
    static volatile unsigned long long calls;
    static unsigned long long seen[16];
    static int nseen;
    unsigned long long n = __atomic_add_fetch(&calls, 1, __ATOMIC_RELAXED);
    unsigned long long lr = r[19];
    int found = 0, fresh = 0;
    for (int i = 0; i < nseen; i++) if (seen[i] == lr) { found = 1; break; }
    if (!found && nseen < 16) { seen[nseen++] = lr; fresh = 1; }
    if (n <= 8 || fresh || (n & 0xfffull) == 0)
    {
        char who[64];
        unsigned long sb = za_sdk_base, gb = (unsigned long)za_guest_base;
        if (sb && lr >= sb && lr < sb + za_sdk_size) snprintf(who, sizeof who, "sdk+%#lx", lr - sb);
        else if (gb && lr >= gb && lr < gb + ZA_IMAGE_SIZE) snprintf(who, sizeof who, "main+%#lx", lr - gb);
        else snprintf(who, sizeof who, "%#llx", lr);
        ZLOGI("★ main 探针 pool-init: 累计第%llu次 desc=%#llx stride=%#llx base=%#llx "
              "size=%#llx 调用者=%s%s",
              n, r[0], r[1], r[2], r[3], who, fresh ? "（新的调用点）" : "");
    }
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
    if (p && ((ZA_PTR_OK(p)) ||
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
// 任务等待入口（main+0x1938e30）：x0 = 任务对象；[x0+0x158] = 状态（5 = 完成）。
// 这条探针回答「任务到底排上了没有」：状态是 0/1 ⇒ 没人取走；是 3/4 ⇒ 被取走后在跑。
#define ZA_JOBRING 16
static volatile unsigned long long za_job_objs[ZA_JOBRING];
static volatile unsigned long long za_job_caller[ZA_JOBRING];
static volatile unsigned za_job_pos;
// 按线程记「正在等哪个任务对象」（共享环形会被别的线程覆盖）。
volatile unsigned long long za_job_by_tid[64];
// 入队探针（main+0x16ffeb0）记录的「被入队的队列对象」与累计次数，
// 以及 worker 侧最近一次出队轮询的对象 —— 停摆时两者对照即可区分
// 「任务没进这个队列」和「进了但没人取」。
volatile unsigned long long za_enq_queue;
volatile unsigned long long za_enq_count;
volatile unsigned long long za_worker_obj;
volatile unsigned long long za_worker_polls;
// ── E2 派发链中间环节计数（2026-10-30）──────────────────────────────
// 已知两端矛盾：job-dispatch(0xd270d8) 早期停摆发过 1 次、真 push(0x16ffeb0)
// 0 次 —— 中间三环谁断了？构造(0x17395d0) / push 入口(0x16ffd70，[x0+0x120]
// 是字节开关：0 → cbz 走 0x16ffe10 内部分支) / 另一条路(0xa6a2e0)。
volatile unsigned long long za_n_ctor, za_n_push, za_n_brancha;
volatile unsigned long long za_n_push_sw0;      // push 入口里开关字节==0 的次数
// E2b 二分：0xd7f2d0 入口 → 0xd7f940（构造前）→ ctor/push / 0xd7fa98（分配弃单）
volatile unsigned long long za_n_f2d0, za_n_reach940, za_n_allocbail;
// E9：TLS scratch 两处 stash 的累计次数（覆盖事件见日志明细）
volatile unsigned long long za_n_stash_disp, za_n_stash_intake;
// E10：三方容器对账——P（被 push，za_enq_queue）/ D（派发器 picker）/ 搬运族入口
volatile unsigned long long za_picker_container;
volatile unsigned long long za_n_mover;
// E11：dispatch(0xd7bdb8) 的五个子调用（除首个子调用 0xd7be10 已由 B 路径覆盖）
volatile unsigned long long za_n_sub[5];
// E12：B 里 refcount==-1 的回滚路径三针（进回滚 / d7fdb0 返回 / d81f60 入口）
volatile unsigned long long za_n_rb[3];
// E14：P 的哈希 find（0x1706640）调用次数——count 不变只证明没 remove，
// find 不改变 count，必须单独数：0=真没人读，>0=有人查
volatile unsigned long long za_n_find, za_n_find_p;
// E16：P 类 vtable 其余槽位（0x255aec0/0x255af80/0x255af04）+ 同族 0x16ffb40
volatile unsigned long long za_n_vt[4];
// E3：命令转发器 0x255ae70（消费侧证据）+ 队列析构 0x1703390（拆证据）
volatile unsigned long long za_n_fwd, za_n_qdtor;

// 停摆时做一次（仅一次）：在客机堆里搜主线程等的那个任务对象。
//   找得到 ⇒ 它确实被挂进了某个队列（该队列的 worker 才是该被唤醒的人）；
//   找不到 ⇒ 任务从未入队，问题在提交侧，不在等待原语。
void za_scan_job_in_heap(void)
{
    // 只扫一次（256MB 的 process_vm_readv 很贵），但结论要每次停摆都打出来：
    // 以前是 done 后直接 return，唯一那次输出随 logcat 环形缓冲滚掉，等于没有。
    static int scanned;
    static char verdict[320] = "（还没有结果）";
    unsigned long long o;
    const unsigned long long lo = 0x452000000ull, len = 0x10000000ull;
    static unsigned char buf[1 << 20];
    int hits = 0;
    if (!scanned) {
        scanned = 1;
        o = za_job_by_tid[(long)za_guest_tid & 63];
        if (!o) {
            snprintf(verdict, sizeof verdict, "主线程没有记录到任务对象（探针没触发？）");
        } else {
            char *w = verdict;
            size_t cap = sizeof verdict;
            int n = snprintf(w, cap, "找 %#llx：", o);
            w += n; cap -= (size_t)n;
            for (unsigned long long a = lo; a < lo + len && hits < 8; a += sizeof buf) {
                struct iovec l = { buf, sizeof buf }, r = { (void *)(uintptr_t)a, sizeof buf };
                ssize_t got = process_vm_readv(getpid(), &l, 1, &r, 1, 0);
                if (got <= 0) continue;
                for (ssize_t i = 0; i + 8 <= got; i += 8) {
                    unsigned long long v;
                    memcpy(&v, buf + i, 8);
                    if (v == o) {
                        int k = snprintf(w, cap, " @%#llx", a + (unsigned long long)i);
                        if (k > 0) { w += k; cap -= (size_t)k; }
                        if (++hits >= 8) break;
                    }
                }
            }
            if (!hits) snprintf(verdict, sizeof verdict,
                                "找 %#llx：没有任何结构引用它 ⇒ 它从未入队（问题在提交侧）", o);
        }
    }
    ZLOGE("★ 堆扫描：%s", verdict);
}

// 强制完成任务实验的开关：files/za-forcejob 或 ZA_FORCEJOB。
int za_forcejob_on(void)
{
    static int on = -1;
    if (on < 0)
        on = getenv("ZA_FORCEJOB") ? 1 :
             (access("/data/user/0/org.pokelegza.android.port/files/za-forcejob", F_OK) == 0);
    return on;
}

// 把卡住的任务强制标成「完成（5）」。
// 只动 JobWait 探针真实记录过的对象（环形里最多 16 个），且当前 state != 5。
static void za_force_stuck_jobs(void)
{
    static int first;
    if (!za_forcejob_on()) return;
    if (!first) {
        first = 1;
        ZLOGE("★ 强制任务：开关=开，环内记录 %u 条", (unsigned)za_job_pos);
    }
    static unsigned long long forced[ZA_JOBRING];
    static int forced_n;
    unsigned pos = za_job_pos;
    unsigned n = pos < ZA_JOBRING ? pos : ZA_JOBRING;
    int changed = 0;
    for (unsigned i = 0; i < n; i++) {
        unsigned long long o = za_job_objs[(pos - 1 - i) % ZA_JOBRING];
        if (!ZA_PTR_OK(o)) continue;
        int skip = 0;
        for (unsigned k = 0; k < forced_n; k++)
            if (forced[k] == o) { skip = 1; break; }
        if (skip) continue;
        unsigned int st = 0;
        struct iovec li = { &st, 4 }, ri = { (void *)(uintptr_t)(o + 0x158), 4 };
        if (process_vm_readv(getpid(), &li, 1, &ri, 1, 0) != 4) continue;
        if (st == 5) continue;
        unsigned int done = 5;
        struct iovec lo = { &done, 4 }, ro = { (void *)(uintptr_t)(o + 0x158), 4 };
        if (process_vm_writev(getpid(), &lo, 1, &ro, 1, 0) != 4) continue;
        if (forced_n < ZA_JOBRING) forced[forced_n++] = o;
        ZLOGE("★ 强制完成任务 obj=%#llx：state %#x → 5（让同步 submit 返回）", o, st);
        changed++;
    }
    if (changed) {
        extern unsigned za_sync_poke_all(void);
        za_sync_poke_all();
    }
}

// 取「主线程」此刻的寄存器快照（发一次采样信号给它，等 handler 落盘）。
// 用于定位它自旋在哪个循环、手里拿的是哪个对象。
extern volatile unsigned long za_samp_pc;
extern volatile unsigned long za_samp_regs[32];
extern volatile long za_samp_tid;
static int za_snap_main_regs(unsigned long *pc, unsigned long *regs)
{
    extern volatile long za_guest_tid;
    if (za_guest_tid <= 0) return 0;
    za_samp_tid = 0;
    syscall(SYS_tgkill, (int)getpid(), (int)za_guest_tid, ZA_SAMPLER_SIG);
    for (int i = 0; i < 300; i++) {
        if (za_samp_tid == za_guest_tid) {
            if (pc) *pc = za_samp_pc;
            if (regs) for (int k = 0; k < 31; k++) regs[k] = za_samp_regs[k];
            return 1;
        }
        struct timespec t = { 0, 100 * 1000 };
        nanosleep(&t, NULL);
    }
    return 0;
}

typedef struct { volatile long tid; volatile unsigned long pc; volatile unsigned long regs[31]; } za_samp_slot_t;
extern za_samp_slot_t za_samp_tab[32];

// 主线程「等任务完成」的自旋（main+0xcc080：`ldrb w8,[x20,#3]` /
// `ldr w8,[x19,#0x158]`；x19 = 任务对象，state 要等于 5）。
// 任务永远没人执行 ⇒ 它自旋 100% CPU 且一个 svc 都不发。
// 这里把它的任务对象直接标成完成，让它走出这个循环（实验性恢复）。
// ⚠ 自旋的**不一定是主线程**（实测常常是某个 worker 线程），所以扫
//   所有线程的寄存器快照，谁在那个 PC 区间里就修谁。
static void za_unstick_main_job_spin(void)
{
    unsigned long gb = (unsigned long)(uintptr_t)za_guest_base;
    if (!gb) return;
    static int n;
    for (int i = 0; i < 32; i++) {
        za_samp_slot_t *sl = &za_samp_tab[i];
        long tid = sl->tid;
        if (tid <= 0) continue;
        unsigned long pc = sl->pc;
        if (pc < gb) continue;
        unsigned long off = pc - gb;
        // 这个自旋回路从 0xcc040（自旋锁）到 0xcc0dc（判 state）、0xcc0f4（重试）
        // 都算；真机采样点实测落在 0xcc080 与 0xcc0d0 两处。
        if (off < 0xcc030 || off > 0xcc140) continue;
        // 这段循环里还有一个**字节自旋锁**：`add x8,x20,#2; ldxrb/stlxrb 0x5f`。
        // 锁被一个永远不回来的线程持有时，这里会空转到死。把锁字节清 0 放行。
        {
            unsigned long long lk = sl->regs[20];
            if (ZA_PTR_OK(lk)) {
                unsigned char b2 = 0xff, b3 = 0xff;
                memcpy(&b2, (const void *)(uintptr_t)(lk + 2), 1);
                memcpy(&b3, (const void *)(uintptr_t)(lk + 3), 1);
                if (b2 != 0 || b3 != 0) {
                    unsigned char z = 0;
                    memcpy((void *)(uintptr_t)(lk + 2), &z, 1);
                    memcpy((void *)(uintptr_t)(lk + 3), &z, 1);
                    if (n++ < 12)
                        ZLOGE("★ tid=%ld 自旋在字节锁 %#llx（%02x/%02x）→ 清 0 放行",
                              tid, lk, b2, b3);
                }
            }
        }
        unsigned long long job = sl->regs[19];
        if (!ZA_PTR_OK(job)) continue;
        unsigned int st = 0xffffffffu;
        {
            struct iovec li = { &st, 4 }, ri = { (void *)(uintptr_t)(job + 0x158), 4 };
            process_vm_readv(getpid(), &li, 1, &ri, 1, 0);
        }
        if (st == 5) continue;
        {
            unsigned int done = 5;
            struct iovec lo = { &done, 4 }, ro = { (void *)(uintptr_t)(job + 0x158), 4 };
            process_vm_writev(getpid(), &lo, 1, &ro, 1, 0);
        }
        if (n++ < 12)
            ZLOGE("★ tid=%ld 自旋在 main+%#lx 等任务：强制 job=%#llx state %#x → 5",
                  tid, off, job, st);
    }
}

// ★ 2026-10-30：Havok 反射注册表成环 —— 主线程 100% CPU 空转的真因。
//   main+0xa8d470 是「把对象 x0 移到链表尾」（move-to-tail）：
//     x9 = head = *(main+0x5f39498)；沿 [node+0x20] 往下走；
//     找到 x0 先摘下来，走到 NULL 再把 x0 接到尾部。
//   真机实测（进程活着时直接 dump BSS）：0x105f54e90 → … → 0x103d7f470 → 回到
//   0x105f54e90，是**14 个节点的环**，而 x0（0x103d7f498）不在环里 ⇒ `cmp/b.eq`
//   永不成立，主线程在 main+0xa8d484 烧满一个核，帧再也提交不出去。
//   节点名字是 `$hkReflect::Version::PatchRegistry` / `$ReflectStrings` /
//   `$AfterReflectNewLock` —— Havok 的类型注册表（多线程 move-to-tail 未串行化
//   时正是环的典型成因）。
//   这里做「有界遍历 + 重复检测」：发现回到走过的节点，就把那一跳改成 NULL，
//   链表恢复线性，自旋线程走到表尾把 x0 接上、继续干活。
//   默认开启；files/za-no-lrufix 可关（A/B 用）。
#define ZA_LRU_HEAD_OFF 0x5f39498ul     // main+0x5f39498 = 链表头
#define ZA_LRU_FN_LO    0xa8d470ul      // move-to-tail 函数体范围
#define ZA_LRU_FN_HI    0xa8d4bcul

static int za_lru_fix_mode(void)
{
    static int m = -1;
    if (m < 0)
        m = access("/data/user/0/org.pokelegza.android.port/files/za-no-lrufix",
                   F_OK) != 0;
    return m;
}

static int za_grd(unsigned long a, void *dst, size_t n)
{
    struct iovec lo = { dst, n }, ro = { (void *)(uintptr_t)a, n };
    return process_vm_readv(getpid(), &lo, 1, &ro, 1, 0) == (ssize_t)n;
}
static int za_gwr(unsigned long a, const void *src, size_t n)
{
    struct iovec lo = { (void *)(uintptr_t)src, n }, ro = { (void *)(uintptr_t)a, n };
    return process_vm_writev(getpid(), &lo, 1, &ro, 1, 0) == (ssize_t)n;
}

static void za_unstick_lru_cycle(void)
{
    if (!za_lru_fix_mode()) return;
    unsigned long gb = (unsigned long)(uintptr_t)za_guest_base;
    if (!gb) return;
    // 只有真的采到「某条线程在 move-to-tail 里」才动链表，避免误伤。
    int stuck = 0;
    for (int i = 0; i < 32; i++) {
        long tid = za_samp_tab[i].tid;
        unsigned long pc = za_samp_tab[i].pc;
        if (tid <= 0 || pc < gb) continue;
        unsigned long off = pc - gb;
        if (off >= ZA_LRU_FN_LO && off < ZA_LRU_FN_HI) { stuck = 1; break; }
    }
    if (!stuck) return;

    unsigned long head = 0;
    if (!za_grd(gb + ZA_LRU_HEAD_OFF, &head, 8) || !head) return;

    enum { ZA_LRU_MAX = 8192 };
    static unsigned long path[ZA_LRU_MAX];
    static int fixed_n;
    if (fixed_n >= 8) return;
    int n = 0;
    unsigned long cur = head, prev = 0;
    while (cur && n < ZA_LRU_MAX) {
        int dup = 0;
        for (int k = 0; k < n; k++)
            if (path[k] == cur) { dup = k + 1; break; }
        if (dup) {
            unsigned long zero = 0;
            char nm[48] = "";
            unsigned long name = 0;
            if (za_grd(cur, &name, 8)) {
                const unsigned char *p = (const unsigned char *)(uintptr_t)name;
                (void)p;
                // 名字是客机 rodata 里的字符串，只用来点名人/不追求完整
                for (int k = 0; k < 40; k++) {
                    unsigned char c = 0;
                    if (!za_grd((unsigned long)name + (unsigned long)k, &c, 1) || !c) break;
                    if (c < 0x20 || c > 0x7e) break;
                    nm[k] = (char)c;
                }
            }
            int cut = prev && za_gwr(prev + 0x20, &zero, 8);
            fixed_n++;
            ZLOGE("★ Havok 注册表成环：head=%#lx，第 %d 个节点 %#lx（%s）与第 %d 个重复"
                  "（环长 %d）⇒ %s", head, n, cur, nm[0] ? nm : "?", dup - 1, n - (dup - 1),
                  cut ? "已切断上一跳的 next，放自旋线程继续" : "切断失败");
            return;
        }
        path[n++] = cur;
        prev = cur;
        unsigned long nx = 0;
        if (!za_grd(cur + 0x20, &nx, 8)) {
            ZLOGE("★ Havok 注册表：第 %d 个节点 %#lx 的 next 读不到，停止扫描", n, cur);
            return;
        }
        cur = nx;
    }
    ZLOGE("★ Havok 注册表：扫了 %d 个节点没发现环（可能是超长链表，不动它）", n);
}

// ★ 线程级「两次采样」对照表。
//   停摆表只列「在 svc 里睡着」的线程；**纯用户态自旋**的线程根本不进那张表
//   （它不发 svc），而它往往就是真正卡住整条流水线的那一条（真机实测主线程
//   6.3 秒墙钟烧掉 6.2 秒 CPU，同时排队/等待表全是静止的）。
//   两次采样 PC 相同 ⇒ 卡在该 PC；PC 变化 ⇒ 它在正常跑。
//   一起打印 x19/x20：任务对象 / 锁对象，能把「在等谁/持着什么」直接读出来。
static void za_pc_str(char *out, size_t cap, unsigned long pc)
{
    unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
    unsigned long long sb = (unsigned long long)za_sdk_base;
    unsigned long long ss = (unsigned long long)za_sdk_size;
    if (mb && pc >= mb && pc < mb + ZA_IMAGE_SIZE)
        snprintf(out, cap, "main+%#llx", (unsigned long long)(pc - mb));
    else if (sb && ss && pc >= sb && pc < sb + ss)
        snprintf(out, cap, "sdk+%#llx", (unsigned long long)(pc - sb));
    else
        snprintf(out, cap, "%#lx", pc);
}

void za_dump_thread_pcs2(void)
{
    long tid[32];
    unsigned long pc1[32], x19[32], x20[32], fp1[32];
    int n = 0;
    for (int i = 0; i < 32; i++) {
        if (!za_samp_tab[i].tid) continue;
        tid[n] = za_samp_tab[i].tid;
        pc1[n] = za_samp_tab[i].pc;
        x19[n] = za_samp_tab[i].regs[19];
        x20[n] = za_samp_tab[i].regs[20];
        fp1[n] = za_samp_tab[i].regs[29];
        n++;
    }
    za_sample_all_threads();
    { struct timespec t = { 0, 30 * 1000 * 1000 }; nanosleep(&t, NULL); }
    ZLOGE("★ 线程 PC 对照（两次采样；同 PC = 卡在该处，CPU 在涨即用户态自旋）：");
    for (int k = 0; k < n; k++) {
        unsigned long p2 = 0;
        int found = 0;
        for (int i = 0; i < 32; i++)
            if (za_samp_tab[i].tid == tid[k]) { p2 = za_samp_tab[i].pc; found = 1; break; }
        char a[40], b[40];
        za_pc_str(a, sizeof a, pc1[k]);
        if (found) za_pc_str(b, sizeof b, p2);
        else snprintf(b, sizeof b, "(未采到)");
        int same = found && p2 == pc1[k];
        ZLOGE("    tid=%ld %s (%#lx) → %s  x19=%#lx x20=%#lx%s",
              tid[k], a, pc1[k], b, x19[k], x20[k], same ? "  ← 同 PC" : "");
        // 同 PC 且落在客机映像里 ⇒ 用户态自旋，倒 5 帧调用链（fp 链）
        if (same && za_guest_base && pc1[k] >= (unsigned long)(uintptr_t)za_guest_base &&
            pc1[k] < (unsigned long)(uintptr_t)za_guest_base + ZA_IMAGE_SIZE) {
            unsigned long long fp = fp1[k];
            for (int f = 0; f < 5 && fp; f++) {
                if (fp & 7) break;
                unsigned long long nf = *(volatile unsigned long long *)(uintptr_t)fp;
                unsigned long long lr = *(volatile unsigned long long *)(uintptr_t)(fp + 8);
                char s[40];
                za_pc_str(s, sizeof s, (unsigned long)lr);
                ZLOGE("        [%d] lr=%s", f, s);
                if (nf <= fp || nf - fp > 0x100000ull) break;
                fp = nf;
            }
            // 这个对象的头 4 个 qword：vector 的 begin/end/cap 一看就知道计数是不是
            // 「被一个垃圾字段撑大」的（真机实测 resize 计数到了 4.2e9）。
            {
                za_samp_slot_t *sl = NULL;
                for (int i = 0; i < 32; i++)
                    if (za_samp_tab[i].tid == tid[k]) { sl = &za_samp_tab[i]; break; }
                if (sl && x19[k] >= 0x10000ul &&
                    (x19[k] & 0x00FFFFFFFFFFFFFFull) < 0x800000000000ull) {
                    unsigned long long a = x19[k] & 0x00FFFFFFFFFFFFFFull;
                    unsigned long long q[4] = {0, 0, 0, 0};
                    struct iovec lo = { q, sizeof q }, ro = { (void *)(uintptr_t)a, sizeof q };
                    if (process_vm_readv(getpid(), &lo, 1, &ro, 1, 0) == (ssize_t)sizeof q)
                        ZLOGE("        x19 头 4 项: %#llx %#llx %#llx %#llx  (end-begin)/8=%lld",
                              q[0], q[1], q[2], q[3], (long long)((q[1] - q[0]) / 8));
                }
                if (sl)
                    ZLOGE("        regs x0=%#lx x1=%#lx x2=%#lx x3=%#lx x8=%#lx x9=%#lx"
                          " x10=%#lx x21=%#lx x22=%#lx x23=%#lx",
                          sl->regs[0], sl->regs[1], sl->regs[2], sl->regs[3],
                          sl->regs[8], sl->regs[9], sl->regs[10],
                          sl->regs[21], sl->regs[22], sl->regs[23]);
            }
        }
    }
}


// 自旋型停摆的快照。客机自旋时 svc 计数一直在涨，旧的 no_progress 判定
// 永远不会触发；但 NVN 一个提交都没有，说明它其实没前进。
// 由 NVN 帧驱动每 10 秒调一次，倒出「每条线程此刻停在哪」。
void za_dump_progress_stall(void)
{
    extern void za_sample_all_threads(void);
    // ★ 先采样（拿到每条线程此刻的 PC + 寄存器快照），再做恢复：
    //   「谁在等任务完成的自旋里」只能从抽样寄存器里看出来，用上一轮的旧样本
    //   会打偏（真机实测：卡在 main+0xcc080，但恢复没触发）。
    za_sample_all_threads();
    { struct timespec t = { 0, 40 * 1000 * 1000 }; nanosleep(&t, NULL); }
    // 实验性恢复（不依赖「主线程是否在 svc 等待里」这个条件——
    // 自旋的线程根本不在等待表里）。
    za_force_stuck_jobs();
    za_unstick_main_job_spin();
    // 反射注册表成环（主线程 100% CPU 于 main+0xa8d484）：切断闭环那一跳。
    za_unstick_lru_cycle();
    // 停摆现场也倒一次释放环：主线程在 main+0x5d7128 位图池找空槽自旋时，
    // 只有「最近释放了什么」能解释槽位/链为什么变成这样。只倒前两轮。
    {
        // ⚠ 头两轮快照在启动 0.2 秒时就触发了，那时还没有任何释放；
        //   取第 3/8 轮（真的停摆之后）才有内容。
        static int fr;
        fr++;
        if (fr == 3 || fr == 8) {
            extern void za_free_ring_dump(const char *why, int n);
            za_free_ring_dump("停摆现场", 18);
        }
    }
    {
        // 实验开关：files/za-lqgrow —— 把塞满的消息队列扩容，破「队满→生产者全堵」。
        static int lg = -1;
        if (lg < 0)
            lg = access("/data/user/0/org.pokelegza.android.port/files/za-lqgrow", F_OK) == 0;
        if (lg) {
            extern int za_sync_grow_full_lq(void);
            static int n;
            // 每轮停摆都试：只要还有发送方被「队满」堵着，就继续扩。
            // 真机实测：扩到 400 后纹理立刻从 10 涨到 21，说明这一环确实是死锁点。
            if (n < 64) {
                int g = za_sync_grow_full_lq();
                if (g) { n++; ZLOGE("   ↳ 队列扩容累计 %d 次", n); }
            }
        }
    }
    {
        extern int za_sync_force_signal_stuck(void);
        static int fsn;
        if (fsn < 20) {
            int fs = za_sync_force_signal_stuck();
            if (fs) ZLOGE("   ↳ 强制交接：动了 %d 个等待字（第 %d 轮）", fs, ++fsn);
        }
    }
    za_sample_all_threads();
    { struct timespec t = { 0, 40 * 1000 * 1000 }; nanosleep(&t, NULL); }
    // ★ SIMD 空转诊断：main+0x1a08440..0x1a084c0 是一个字节扫描内层循环，
    //   界在 [x25+8] 与 [x25+0x30]。把采样到的寄存器与这两个界打出来，
    //   立刻能分辨「界是垃圾值（死循环）」还是「真的在跑一段长数据」。
    {
        unsigned long gb = (unsigned long)(uintptr_t)za_guest_base;
        for (int i = 0; i < 32; i++) {
            za_samp_slot_t *sl = &za_samp_tab[i];
            if (sl->tid <= 0 || sl->pc < gb) continue;
            unsigned long off = sl->pc - gb;
            if (off < 0x1a08400 || off > 0x1a08500) continue;
            unsigned long long x25 = sl->regs[25], x10 = sl->regs[10], x12 = sl->regs[12];
            unsigned long long b0 = 0, b1 = 0;
            if (ZA_PTR_OK(x25)) {
                memcpy(&b0, (const void *)(uintptr_t)(x25 + 8), 8);
                memcpy(&b1, (const void *)(uintptr_t)(x25 + 0x30), 8);
            }
            ZLOGE("★ SIMD 空转 tid=%ld main+%#lx: x10=%llu x12=%llu x25=%#llx 界[+8]=%#llx 界[+30]=%#llx",
                  sl->tid, off, x10, x12, x25, b0, b1);
            // 这是一个哈希表探针循环：`cmp x10(=[x25+8]), x12(=[x25+0x30]); b.hs 退出`。
            // 上界是垃圾值时会空转到天荒地老。把上界改成游标 ⇒ 下一轮立刻按
            // 「未命中」退出（等价于这次查找没找到，是可接受的降级）。
            // 只在上界明显大于游标、且两者都像正常计数（< 1<<24）时动手。
            if (b1 > b0 && b1 < (1ull << 24) && b0 < (1ull << 24)) {
                unsigned long long nb = b0;
                memcpy((void *)(uintptr_t)(x25 + 0x30), &nb, 8);
                ZLOGE("   ↳ 已把哈希表上界 [%#llx+0x30] 从 %#llx 改成 %#llx（令探针循环退出）",
                      x25, b1, nb);
            } else if (b1 >= (1ull << 24)) {
                ZLOGE("   ↳ 上界 %#llx 像垃圾值（不动它，等寄存器采样确认）", b1);
            }
        }
    }
    ZLOGE("★ 10 秒无 NVN 进展快照（svc 在涨 ⇒ 客机在自旋）：");
    {
        extern volatile unsigned long long za_enq_queue, za_enq_count;
        extern volatile unsigned long long za_worker_obj, za_worker_polls;
        extern volatile unsigned long long za_n_ctor, za_n_push, za_n_brancha, za_n_push_sw0;
        extern volatile unsigned long long za_n_f2d0, za_n_reach940, za_n_allocbail;
        unsigned long long q = za_enq_queue;
        unsigned long long w = za_worker_obj;
        ZLOGE("★ 任务队列 %#llx（累计入队 %llu 次）；worker 轮询对象 %#llx（轮询 %llu 次）：",
              q, (unsigned long long)za_enq_count, w, (unsigned long long)za_worker_polls);
        // E2 派发链：构造 → push 入口（开关字=0 的次数单列）→ 另一分支 → 真 push。
        // 哪一环是 0，断点就在它和上一环之间。
        ZLOGE("★ E2 派发链: 构造=%llu push入口=%llu(开关0:%llu) 另一分支=%llu 真push=%llu",
              (unsigned long long)za_n_ctor, (unsigned long long)za_n_push,
              (unsigned long long)za_n_push_sw0, (unsigned long long)za_n_brancha,
              (unsigned long long)za_enq_count);
        // E2b 二分：0xd7f2d0 入口 → 0xd7f940 → ctor/push / 0xd7fa98 弃单。
        // 入口>0 且 940=0 ⇒ 提前出口；940>0 且 ctor=0 ⇒ 分配器虚调用弃单/崩。
        ZLOGE("★ E2b 二分: f2d0入口=%llu 构造前=%llu 分配弃单=%llu",
              (unsigned long long)za_n_f2d0, (unsigned long long)za_n_reach940,
              (unsigned long long)za_n_allocbail);
        // E3 消费侧：转发器=0 且队列析构>0 ⇒ 命令进了队列但消费者从未跑、队列被拆。
        {
            extern volatile unsigned long long za_n_fwd, za_n_qdtor;
            ZLOGE("★ E3 消费侧: 命令转发器=%llu 队列析构=%llu",
                  (unsigned long long)za_n_fwd, (unsigned long long)za_n_qdtor);
        }
        // E9：TLS scratch 两次 stash 的累计次数（同槽覆盖次数见 E9 明细行）
        {
            extern volatile unsigned long long za_n_stash_disp, za_n_stash_intake;
            ZLOGE("★ E9 TLS scratch: 派发stash=%llu 整备stash=%llu",
                  (unsigned long long)za_n_stash_disp, (unsigned long long)za_n_stash_intake);
        }
        // E10：搬运族次数 + 三方容器快照（P/D/搬运）
        {
            extern volatile unsigned long long za_n_mover, za_picker_container, za_enq_queue;
            ZLOGE("★ E10 三方容器: 搬运族=%llu P=%#llx D=%#llx",
                  (unsigned long long)za_n_mover,
                  (unsigned long long)za_enq_queue,
                  (unsigned long long)za_picker_container);
        }
        // E11：dispatch 五个子调用的执行次数
        {
            extern volatile unsigned long long za_n_sub[5];
            ZLOGE("★ E11 dispatch子调用: cd10=%llu e820=%llu eb10=%llu 00c40=%llu f040=%llu",
                  (unsigned long long)za_n_sub[0], (unsigned long long)za_n_sub[1],
                  (unsigned long long)za_n_sub[2], (unsigned long long)za_n_sub[3],
                  (unsigned long long)za_n_sub[4]);
        }
        // E12：B 回滚路径三针（进回滚 / d7fdb0 返回 / d81f60 入口）
        {
            extern volatile unsigned long long za_n_rb[3];
            ZLOGE("★ E12 回滚: 进回滚=%llu d7fdb0返回=%llu d81f60=%llu",
                  (unsigned long long)za_n_rb[0], (unsigned long long)za_n_rb[1],
                  (unsigned long long)za_n_rb[2]);
        }
        // E22：悬空读地址的所属区域（看门狗线程里查 maps，安全）
        {
            unsigned int dn = __atomic_load_n(&za_dangle_n, __ATOMIC_RELAXED);
            if (dn > 8) dn = 8;
            for (unsigned int i = 0; i < dn; i++) {
                char m[220];
                unsigned long long a = za_dangle_addr[i];
                za_maps_near(a, m, sizeof m);
                ZLOGE("★ E22 悬空读#%u addr=%#llx 归属：%s", i, a, m);
            }
        }
        // E14：哈希 find 总次数 + 其中落在 P+0x70 的次数
        {
            extern volatile unsigned long long za_n_find, za_n_find_p;
            ZLOGE("★ E14 哈希find: 总=%llu 查P的=%llu",
                  (unsigned long long)za_n_find, (unsigned long long)za_n_find_p);
        }
        // E16：P 类 vtable 剩余槽位 + 同族 0x16ffb40 的执行次数
        {
            extern volatile unsigned long long za_n_vt[4];
            ZLOGE("★ E16 槽位: aec0=%llu af80=%llu af04=%llu ffb40=%llu",
                  (unsigned long long)za_n_vt[0], (unsigned long long)za_n_vt[1],
                  (unsigned long long)za_n_vt[2], (unsigned long long)za_n_vt[3]);
        }
        // worker 真正在等的那个池对象：把 +0x2c0..+0x360 的关键字段全倒出来。
        //   前 4 个 64 位字就是「队列数组/数量/索引/停止标志」这几个；
        //   只要和入队对象的字段对不上，就说明两头用的不是同一个池。
        if (ZA_PTR_OK(w)) {
            unsigned long long v[8];
            memcpy(v, (const void *)(uintptr_t)w, 16);
            ZLOGE("   pool[0]=%#llx pool[8]=%#llx vt=%#llx", v[0], v[1], v[0]);
            for (unsigned long long off = 0x2c0; off <= 0x360; off += 0x10) {
                memcpy(v, (const void *)(uintptr_t)(w + off), 16);
                ZLOGE("   pool+%#llx: %#llx %#llx", off, v[0], v[1]);
            }
        }
        if (ZA_PTR_OK(q)) {
            ZLOGE("   enq vt=%#llx", *(volatile unsigned long long *)(uintptr_t)q);
            for (unsigned long long off = 0x2c0; off <= 0x360; off += 0x10) {
                unsigned long long a = *(volatile unsigned long long *)(uintptr_t)(q + off);
                unsigned long long b = *(volatile unsigned long long *)(uintptr_t)(q + off + 8);
                ZLOGE("   enq+%#llx: %#llx %#llx", off, a, b);
            }
            // E5：MPSC 容器是「每 lane 0x80」布局（0x194e850/0x194e94c 反汇编）：
            //   lane+0x08 = 哈希桶表指针、+0x10 = 取模基数、+0x40 = 环计数区
            //   （16 字节一对 [begin,end]，门闩值 = end-begin）。
            // 停摆时把前 8 条 lane 的环计数倒出来：哈希有命令但环计数为 0
            // ⇒ 87 个未消费命令的下落（入哈希没入环 / 或在无人认领的 lane）。
            {
                unsigned long long vt2 = *(volatile unsigned long long *)(uintptr_t)q;
                if (vt2 == 0x103a29f48ull)   // push 时记录的这个类才按 lane 布局倒
                    za_dump_mpsc_lanes(q, "停摆时");
            }
            // E13：P 哈希条目计数（停摆时）。等于累计入队数 ⇒ 只进不出。
            // 地址被复用（vt 不符）就跳过，避免假数据。
            {
                unsigned long long vt2 = 0, cnt = 0, lf = 0;
                za_read_bytes((unsigned long)q, &vt2, 8);
                if (vt2 == 0x103a29f48ull) {
                    za_read_bytes((unsigned long)(q + 0x98), &cnt, 8);
                    za_read_bytes((unsigned long)(q + 0xA0), &lf, 8);
                    ZLOGE("★ E13 停摆时P哈希: 条目=%llu 装载因子=%#llx（累计入队 %llu）",
                          cnt, lf, (unsigned long long)za_enq_count);
                } else {
                    ZLOGE("★ E13 停摆时P哈希: 地址已复用（vt=%#llx），计数不可读", vt2);
                }
            }
        }
        // 「谁认识这个池对象」：扫全线程栈找出持有它的线程。
        //   只被 worker 认识 ⇒ 生产方从来没拿到过这个池（问题在池的分发侧）；
        //   主线程栈上也有 ⇒ 主线程就是该 push 的人，顺着它的 fp 链就能定位代码。
        if (ZA_PTR_OK(w)) {
            extern void za_sync_scan_for_addr(unsigned long long val);
            ZLOGE("★ 扫线程栈找池对象 %#llx 的持有者：", w);
            za_sync_scan_for_addr(w);
        }
    }
    za_dump_task_stats();
    {
        extern void za_sync_dump_top_spinner(void);
        za_sync_dump_top_spinner();
    }
    za_sync_dump();
    {
        // 「队满/队空 + 谁在等哪个方向」——闸门 A 的直接证据。
        extern void za_sync_dump_lq_pairs(void);
        za_sync_dump_lq_pairs();
    }
    {
        // 「worker 睡在键 K 上，有没有人 SignalProcessWideKey(K)」——
        // 这是区分「没人发信号」与「发到了别的键」的唯一直接证据。
        extern void za_sync_dump_key_stats(void);
        za_sync_dump_key_stats();
    }
    {
        unsigned long pos = za_pc_ring_pos;
        unsigned long n = pos < ZA_PC_RING ? pos : ZA_PC_RING;
        unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
        ZLOGE("★ PC 采样环（最近 %lu 条）：", n);
        for (unsigned long i = 0; i < n; i++) {
            unsigned long k = (pos - n + i) % ZA_PC_RING;
            unsigned long pc = za_pc_ring[k];
            const char *w = "@";
            unsigned long long off = pc;
            if (mb && pc >= mb && pc < mb + ZA_IMAGE_SIZE) { w = "main+"; off = pc - mb; }
            else if (za_sdk_base && pc >= za_sdk_base && pc < za_sdk_base + za_sdk_size) {
                w = "sdk+"; off = pc - za_sdk_base;
            }
            ZLOGE("    tid=%ld %s%#llx", za_pc_tid_ring[k], w, off);
        }
    }
    // 主线程卡在哪个等待字上 ⇒ 以「等待字」和「对象基址」两个值扫全线程栈。
    // 等待字只能找到别的等待者；**持有者**栈上留的是对象基址（互斥字通常在
    // obj+0x20），所以必须再扫一次 val-0x20。
    {
        extern unsigned long long za_last_blocked_addr(long tid);
        extern unsigned long long za_sync_top_spin_addr(void);
        extern void za_sync_scan_for_addr(unsigned long long val);
        unsigned long long lb = za_last_blocked_addr(za_guest_tid);
        unsigned long long sp = za_sync_top_spin_addr();
        if (sp && sp != lb) {
            ZLOGE("★ 自旋线程等待字 %#llx ⇒ 扫线程栈找持有者（对象基址 %#llx）：", sp, sp - 0x20);
            za_sync_scan_for_addr(sp);
            za_sync_scan_for_addr(sp - 0x20);
        }
        if (lb) {
            ZLOGE("★ 主线程等待字 %#llx ⇒ 扫线程栈找持有者（对象基址 %#llx）：", lb, lb - 0x20);
            za_sync_scan_for_addr(lb);
            za_sync_scan_for_addr(lb - 0x20);
            {
                extern void za_dump_mtx_hist(unsigned long long addr);
                za_dump_mtx_hist(lb);
            }
            // 伪唤醒一次：语义合法，用来区分「我们丢了唤醒」和「对方没释放」。
            {
                extern int za_sync_poke_addr_waiters(void);
                extern int za_sync_repair_full_wait_ring(void);
                static int poke_n;
                int rp = za_sync_repair_full_wait_ring();
                if (rp) ZLOGE("   ↳ 本轮修好 %d 个写满的等待环", rp);
                // 条件变量侧的伪唤醒：svc#29 一次都不发的时候，worker 会永远
                // 睡在自己的 CV 上。伪唤醒合法（调用方必须重判谓词），
                // 用它区分「我们漏了唤醒」和「确实没活可干」。
                // ⚠ 2026-10-28 真机实测：**伪唤醒对这个 SDK 并不无害**。
                //   SDK 的 cv.Wait（sdk+0x13a5d0）每次被唤醒都会重新登记一条
                //   「等待者」记录进 cv 的固定环（容量 100、从不主动收缩），
                //   而伪唤醒不消耗任何真实信号 ⇒ 每轮伪唤醒给环里塞 19 条
                //   陈旧记录，5 轮就把环写满（真机看到 100/100），之后新等待者
                //   登记失败，唤醒路径找不到人。所以默认**关闭**，需要时用
                //   标记文件 /data/local/tmp/za-fakewake 打开。
                {
                    extern unsigned za_sync_poke_all(void);
                    if (za_fakewake_on()) {
                        unsigned cv = za_sync_poke_all();
                        if (cv) ZLOGE("   ↳ 伪唤醒 %u 个条件变量等待者", cv);
                    }
                }
                // （强制交接已经挪到 za_dump_progress_stall 开头：主线程常常
                //  是纯自旋、`lb` 为 0，放在这个条件块里根本执行不到。）
                // ★ 2026-10-28 实验：把卡住的任务强制标成完成（5）。调度器的
                //   submit 是**同步**的（提交后就在这里等这个任务跑完），而 worker
                //   从来没被唤醒过、任务也没真正入队 ⇒ 主线程永远等不到。
                //   强制完成后 submit 才会返回，我们才能看到「下一段」。
                //   只动 JobWait 探针真实记录过的对象。用标记文件打开。
                za_force_stuck_jobs();
                int pk = za_fakewake_on() ? za_sync_poke_addr_waiters() : 0;
                if (pk) ZLOGE("   ↳ 伪唤醒了 %d 个地址等待者（第 %d 次）", pk, ++poke_n);
                // 伪唤醒三次都没让系统动 ⇒ 等待的字确实没人写。做一次限定范围的
                // 强制解锁，把「锁泄漏」和「锁还在保护数据」区分开。
                if (poke_n >= 3 && (poke_n % 3) == 0) {
                    extern int za_sync_force_release_stuck(void);
                    int fr = za_sync_force_release_stuck();
                    ZLOGE("   ↳ 强制解锁：动了 %d 个锁字（第 %d 轮）", fr, poke_n / 3);
                }
            }
        }
    }
}

static void za_hook_m_jobwait(unsigned long long *r)
{
    static int n;
    unsigned long long o = r[0];
    {
        unsigned p = za_job_pos;
        za_job_objs[p % ZA_JOBRING] = o;
        za_job_caller[p % ZA_JOBRING] = r[19];
        za_job_pos = p + 1;
    }
    // 按线程记一份：停摆时要精确知道「主线程在等的那个任务对象是哪个」，
    // 共享环形会被别的 worker 覆盖掉。
    {
        extern volatile unsigned long long za_job_by_tid[64];
        za_job_by_tid[syscall(SYS_gettid) & 63] = o;
    }
    if (n++ >= 24) return;
    unsigned long long st = 0, a = 0, b = 0, p = 0;
    if (ZA_PTR_OK(o)) {
        memcpy(&st, (const void *)(uintptr_t)(o + 0x158), 8);
        memcpy(&a,  (const void *)(uintptr_t)(o + 0x168), 8);
        memcpy(&b,  (const void *)(uintptr_t)(o + 0x170), 8);
        memcpy(&p,  (const void *)(uintptr_t)(o + 0x38), 8);
        // ★ 实验记录（保留结论，不启用）：「在 job-wait 那一刻就把 state 写成 5」
        //   太粗暴——任务体没跑，结果字段是空的，调用方随后空指针解引用
        //   （真机 main+0x193bd0c 崩在 addr=0）。只有 state>=2（已经有人在跑）
        //   的任务强制完成才勉强安全，且要留到停摆快照里做。
    }
    {
        unsigned long lr = (unsigned long)r[19];
        unsigned long sb = za_sdk_base, gb = (unsigned long)za_guest_base;
        char who[48];
        if (sb && lr >= sb) snprintf(who, sizeof who, "sdk+%#lx", lr - sb);
        else if (gb && lr >= gb) snprintf(who, sizeof who, "main+%#lx", lr - gb);
        else snprintf(who, sizeof who, "%#lx", lr);
        ZLOGI("★ job-wait: obj=%#llx state=%#llx(+0x158) x168=%#llx x170=%#llx payload=%#llx 调用者=%s",
              o, st, a, b, p, who);
    }
}

// 任务提交入口（main+0xd26b90）：x0 = 描述符。用来看「提交了几次」。
static void za_hook_m_jobsubmit(unsigned long long *r)
{
    static int n;
    if (n++ >= 6) return;
    unsigned long lr = (unsigned long)r[19];
    unsigned long sb = za_sdk_base, gb = (unsigned long)za_guest_base;
    char who[48];
    if (sb && lr >= sb) snprintf(who, sizeof who, "sdk+%#lx", lr - sb);
    else if (gb && lr >= gb) snprintf(who, sizeof who, "main+%#lx", lr - gb);
    else snprintf(who, sizeof who, "%#lx", lr);
    ZLOGI("★ job-submit: desc=%#llx arg1=%#llx arg2=%#llx 调用者=%s",
          r[0], r[1], r[2], who);
}
// 停摆快照用：把最近等过的任务对象的**当前**状态读出来。
void za_dump_job_states(void)
{
    unsigned pos = za_job_pos;
    unsigned n = pos < ZA_JOBRING ? pos : ZA_JOBRING;
    ZLOGE("★ 任务对象状态（最近 %u 次 job-wait；state: 0=新建 5=完成）：", n);
    for (unsigned i = 0; i < n; i++)
    {
        unsigned k = (pos - n + i) % ZA_JOBRING;
        unsigned long long o = za_job_objs[k];
        unsigned long lr = (unsigned long)za_job_caller[k];
        unsigned long long st = 0, m = 0, cv = 0;
        if (ZA_PTR_OK(o))
        {
            memcpy(&st, (const void *)(uintptr_t)(o + 0x158), 8);
            memcpy(&m, (const void *)(uintptr_t)(o + 0x118), 8);
            memcpy(&cv, (const void *)(uintptr_t)(o + 0x138), 8);
        }
        unsigned long sb = za_sdk_base, gb = (unsigned long)za_guest_base;
        unsigned long off = lr;
        const char *w = "";
        if (sb && lr >= sb) { w = "sdk+"; off = lr - sb; }
        else if (gb && lr >= gb) { w = "main+"; off = lr - gb; }
        ZLOGE("    obj=%#llx state=%#llx mutex(+118)=%#llx cv(+138)=%#llx 调用者=%s%#lx",
              o, st, m, cv, w, off);
        // 还没完成 ⇒ 盯住它的释放（真机实测：等待者睡着时对象被 free 掉）
        if (o && st != 5) {
            extern void za_watch_free_register(unsigned long long a);
            za_watch_free_register(o);
        }
    }
}

// 把地址格式化成 main+0x… / sdk+0x… / 裸地址（探针日志用）
static void za_fmt_addr(char *out, unsigned long n, unsigned long long a)
{
    unsigned long sb = za_sdk_base, gb = (unsigned long)za_guest_base;
    if (sb && a >= sb && a < sb + za_sdk_size) snprintf(out, n, "sdk+%#llx", a - sb);
    else if (gb && a >= gb && a < gb + ZA_IMAGE_SIZE) snprintf(out, n, "main+%#llx", a - gb);
    else snprintf(out, n, "%#llx", a);
}

// 提交点（main+0xd270d8，紧跟 adrp x8,0x3d8000 之后）：
//   此处 x8 = main+0x3d8000（页基址），单例指针在 [x8+0x800]；
//   随后 `ldr x0,[x8,#0x800]; ldr x8,[x0]; ldr x8,[x8,#0x10]; blr x8`
//   就是「取单例 → 取 vtable → 调 +0x10」。把这条链解出来就知道提交函数是谁。
static void za_hook_m_jobdispatch(unsigned long long *r)
{
    static int n;
    if (n++ >= 4) return;
    unsigned long long g = 0, vt = 0, fn = 0;
    unsigned long gb = (unsigned long)za_guest_base;
    unsigned long long page = r[8];
    if (!(gb && page >= gb && page < gb + ZA_IMAGE_SIZE)) page = (unsigned long long)gb + 0x3d80000ull;
    if (gb)
    {
        memcpy(&g, (const void *)(uintptr_t)(page + 0x800), 8);
        if (ZA_PTR_OK(g))
        {
            memcpy(&vt, (const void *)(uintptr_t)g, 8);
            if (vt) memcpy(&fn, (const void *)(uintptr_t)(vt + 0x10), 8);
        }
    }
    char a[48], b[48], c[48];
    za_fmt_addr(a, sizeof a, g);
    za_fmt_addr(b, sizeof b, vt);
    za_fmt_addr(c, sizeof c, fn);
    ZLOGI("★ job-dispatch: 单例=%s vtable=%s 提交函数=%s", a, b, c);
}

// 提交之后（main+0xd270ec）：虚调用返回点。能走到这里 ⇒ 提交确实执行完了。
static void za_hook_m_jobpost(unsigned long long *r)
{
    (void)r;
    static int n;
    if (n++ >= 4) return;
    ZLOGI("★ job-post: 虚提交调用已返回（第 %d 次）", n);
}

// worker 出队入口（main+0x1bab3a0）：x0 = 队列对象。
// [obj+0x2f8] = 待取数量、[obj+0x330] = 另一个计数。数量为 0 还能进来 = 空转。
// 入队函数 main+0xd80bf0 的内层：0xd80210（先调）与 0xd80ce0（后调）。
// worker 在 main+0x1bac828 里等的是 `[[x+0x400]+0x308]` 这个队列对象；
// 只要把这里收到的对象打出来，就能判断「提交到底推给了哪个队列」，
// 以及它是不是 worker 在等的那个。
static void za_hook_m_enq2(unsigned long long *r)
{
    static int n;
    if (n++ >= 8) return;
    // 0xd82644 = `ldr x8,[x8,#0x50]` 之前：x0 刚被赋成 x21（调度器），x8 = vtable。
    // 桩只保存 x0..x17 ⇒ 这两个都能读。
    unsigned long long disp = r[0], vt = r[8], tgt = 0;
    if (ZA_PTR_OK(vt)) memcpy(&tgt, (const void *)(uintptr_t)(vt + 0x50), 8);
    ZLOGI("★ 提交虚调用: 调度器=%#llx vtable=%#llx [vt+0x50]=%#llx tid=%ld",
          disp, vt, tgt, (long)syscall(SYS_gettid));
}

// 最近一次真正入队的队列对象（停摆时装它的内部状态用）。
// 主线程把 16 个任务「入队」后，worker 却一直报队列数 0 —— 到底是
// ① 任务没进这个队列，还是 ② 进了但没人取，看这几个字段就能分辨。
// （变量本体定义在 za_job_by_tid 旁边，供停摆快照跨函数读取。）

// E6：倒 MPSC 容器（vt 0x3a29f48）8 条 lane 的状态。push 时与停摆时各倒一次：
// push 时就缺 ⇒ 构造缺口；push 时全有、停摆时缺 ⇒ 事后被改坏/拆掉。
// 环指针做 /proc/self/maps 归属（E5 实测 lane5 的环 begin=136>end=5 待=-131，
// 需要判「野指针 vs 上一代结构残骸」）。
static void za_dump_mpsc_lanes(unsigned long long q, const char *when)
{
    for (int lane = 0; lane < 8; lane++) {
        unsigned long long base = q + (unsigned long long)lane * 0x80;
        unsigned long long tbl = 0, mod = 0, cb = 0, ce = 0, rp = 0;
        // ⚠ 全部探读：lane 字段可能是垃圾值（E5 实测 lane5 的环指针能过
        //   ZA_PTR_OK 但指向未映射页，裸 memcpy 把进程打死过一轮）。
        za_read_bytes((unsigned long)(base + 0x08), &tbl, 8);
        za_read_bytes((unsigned long)(base + 0x10), &mod, 8);
        za_read_bytes((unsigned long)(base + 0x40), &rp, 8);
        if (ZA_PTR_OK(rp)) {
            za_read_bytes((unsigned long)rp, &cb, 8);
            za_read_bytes((unsigned long)(rp + 8), &ce, 8);
        }
        ZLOGE("   [%s]lane%d: 桶表=%#llx 取模=%#llx 环[%#llx]=%llu,%llu 待=%lld",
              when, lane, tbl, mod, rp, cb, ce, (long long)(ce - cb));
        if (ZA_PTR_OK(rp)) {
            char m[220];
            za_maps_near(rp, m, sizeof m);
            ZLOGE("      环归属：%s", m);
        }
    }
}

static void za_hook_m_enq3(unsigned long long *r)
{
    // E3：第一次 push 时倒队列类的**真字段**。停摆快照那份会被地址复用污染
    // （实测 push 时 vt=main+0x3a29f48，5 分钟后同地址已是 vt=main+0x3a3e140 的
    // 别的对象）。这里读的才是这个队列类自己的布局。
    {
        static int nq;
        if (nq++ == 0 && ZA_PTR_OK(r[0])) {
            unsigned long long vt = 0, l0 = 0, l1 = 0;
            unsigned long long a110 = 0, af0 = 0, a8 = 0;
            unsigned char sw = 0;
            memcpy(&vt, (const void *)(uintptr_t)r[0], 8);
            memcpy(&l0, (const void *)(uintptr_t)(r[0] + 0xe0), 8);
            memcpy(&l1, (const void *)(uintptr_t)(r[0] + 0xe8), 8);
            memcpy(&sw, (const void *)(uintptr_t)(r[0] + 0x120), 1);
            memcpy(&a110, (const void *)(uintptr_t)(r[0] + 0x110), 8);
            memcpy(&af0, (const void *)(uintptr_t)(r[0] + 0xf0), 8);
            memcpy(&a8, (const void *)(uintptr_t)(r[0] + 0xa8), 8);
            ZLOGE("★ E3 push时队列真字段: q=%#llx vt=%#llx 锁头[+e0]=%#llx,%#llx "
                  "开关[+120]=%u +110=%#llx +f0=%#llx +a8=%#llx 项=%#llx",
                  r[0], vt, l0, l1, (unsigned)sw, a110, af0, a8, r[1]);
            if (ZA_PTR_OK(r[1])) {
                unsigned long long e8 = 0, e10 = 0;
                unsigned short e18 = 0, e1a = 0;
                memcpy(&e8,  (const void *)(uintptr_t)(r[1] + 8), 8);
                memcpy(&e10, (const void *)(uintptr_t)(r[1] + 0x10), 8);
                memcpy(&e18, (const void *)(uintptr_t)(r[1] + 0x18), 2);
                memcpy(&e1a, (const void *)(uintptr_t)(r[1] + 0x1a), 2);
                ZLOGE("★ E3 项字段: +8=%#llx +10=%#llx +18=%u +1a=%u",
                      e8, e10, (unsigned)e18, (unsigned)e1a);
            }
            // E6：push 时刻的 lane 全景（与停摆时对照 ⇒ 判「构造缺口」还是「事后改坏」）
            za_dump_mpsc_lanes(r[0], "push时");
        }
        // E13：P 的哈希条目计数时间线（map=P+0x70，count=[map+0x28]=P+0x98）。
        // 计数在 push 过程中应单调涨；停摆时若仍等于总 push 数 ⇒ 从未有人取过。
        if (ZA_PTR_OK(r[0])) {
            unsigned long long cnt = 0, lf = 0;
            za_read_bytes((unsigned long)(r[0] + 0x98), &cnt, 8);
            za_read_bytes((unsigned long)(r[0] + 0xA0), &lf, 8);
            unsigned long long n = __atomic_load_n(&za_enq_count, __ATOMIC_RELAXED);
            if (n == 1 || (n % 25) == 0)
                ZLOGE("★ E13 P哈希计数: push#%llu 条目=%llu 装载因子=%#llx", n, cnt, lf);
        }
    }
    za_enq_queue = r[0];
    __atomic_add_fetch(&za_enq_count, 1, __ATOMIC_RELAXED);
    static int n;
    if (n++ >= 8) return;
    unsigned long long vt = 0, cnt = 0, idx = 0;
    if (ZA_PTR_OK(r[0])) {
        memcpy(&vt, (const void *)(uintptr_t)r[0], 8);
        memcpy(&cnt, (const void *)(uintptr_t)(r[0] + 0x2f8), 8);
        memcpy(&idx, (const void *)(uintptr_t)(r[0] + 0x2f0), 8);
    }
    ZLOGI("★ 真正入队 0x16ffeb0: x0=%#llx x1=%#llx x2=%#llx vt=%#llx 数量=%llu idx=%#llx lr=%#llx",
          r[0], r[1], r[2], vt, cnt, idx, r[19]);
    // 入队目标事后被释放过（停摆时已不可读）⇒ 同样盯住它
    {
        extern void za_watch_free_register(unsigned long long a);
        za_watch_free_register(r[0]);
        za_watch_free_register(r[1]);
    }
    // ★ 2026-10-30：停摆后这个队列对象在 /proc/self/maps 里已经**不可读**。
    //   到底是「入队当时就已是死对象」还是「之后才释放」，只能在入队点看一次。
    {
        char m[220];
        za_maps_near(r[0], m, sizeof m);
        ZLOGI("★ 入队目标归属：%s", m);
    }
}

// ── E2：派发链中间三环（2026-10-30）─────────────────────────────────
// 链路：job-dispatch(0xd270d8，虚提交) → job 构造 0x17395d0 → push 入口
// 0x16ffd70（[x0+0x120] 字节开关：0 → cbz 走 0x16ffe10）→ … → 真 push
// 0x16ffeb0 / 另一条路 0xa6a2e0。早期停摆 dispatch=1、真 push=0，断点必在
// 中间。反汇编（text.bin 静态核对过首指令都非 PC 相对）：
//   0x16ffd70: x0=队列 x1=项 x2=链节点；ldrb w8,[x0,#0x120]; cbz w8,0x16ffe10
//   0xa6a2e0 : x0/x1=参数、x8 存进 x20（三个有效入参）
//   0x17395d0: x0/x1/x2=构造参数，adrp x8,0x3cc4000 取全局
static void za_hook_m_jobctor(unsigned long long *r)
{
    __atomic_add_fetch(&za_n_ctor, 1, __ATOMIC_RELAXED);
    static int n;
    if (n++ >= 8) return;
    ZLOGI("★ E2 job构造 0x17395d0: x0=%#llx x1=%#llx x2=%#llx lr=main+%#llx",
          r[0], r[1], r[2],
          za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19]);
}

static void za_hook_m_push(unsigned long long *r)
{
    __atomic_add_fetch(&za_n_push, 1, __ATOMIC_RELAXED);
    unsigned char sw = 0;
    unsigned long long vt = 0;
    if (ZA_PTR_OK(r[0])) {
        memcpy(&sw, (const void *)(uintptr_t)(r[0] + 0x120), 1);
        memcpy(&vt, (const void *)(uintptr_t)r[0], 8);
    }
    if (sw == 0) __atomic_add_fetch(&za_n_push_sw0, 1, __ATOMIC_RELAXED);
    // push 目标队列也可能「等的人还在就被拆」——一并盯住
    {
        extern void za_watch_free_register(unsigned long long a);
        if (ZA_PTR_OK(r[0])) za_watch_free_register(r[0]);
    }
    static int n;
    if (n++ >= 8) return;
    ZLOGI("★ E2 push入口 0x16ffd70: 队列=%#llx vt=%#llx 项=%#llx 开关[+0x120]=%u lr=main+%#llx",
          r[0], vt, r[1], (unsigned)sw,
          za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19]);
}

static void za_hook_m_brancha(unsigned long long *r)
{
    __atomic_add_fetch(&za_n_brancha, 1, __ATOMIC_RELAXED);
    static int n;
    if (n++ >= 8) return;
    ZLOGI("★ E2 另一分支 0xa6a2e0: x0=%#llx x1=%#llx x8=%#llx lr=main+%#llx",
          r[0], r[1], r[8],
          za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19]);
}

// ── E2b：0xd7f2d0 函数（dispatch 尾跳，含构造+push 调用点）内部二分 ──
// 已知：ctor=0、push=0、alloc弃单=0（未崩）。函数要么没进、要么提前出口。
// 三探针：入口 0xd7f2d0 / 构造前 0xd7f940 / 分配弃单 0xd7fa98（会 udf #0）。
static void za_hook_m_f2d0(unsigned long long *r)
{
    __atomic_add_fetch(&za_n_f2d0, 1, __ATOMIC_RELAXED);
    static int n;
    if (n++ >= 8) return;
    ZLOGI("★ E2b 进 0xd7f2d0: x0=%#llx x1=%#llx lr=main+%#llx",
          r[0], r[1],
          za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19]);
}

static void za_hook_m_reach940(unsigned long long *r)
{
    __atomic_add_fetch(&za_n_reach940, 1, __ATOMIC_RELAXED);
    static int n;
    if (n++ >= 8) return;
    ZLOGI("★ E2b 到构造前 0xd7f940: x20=%#llx lr=main+%#llx",
          r[16],  // 桩只存 x0-x8；x20 不在内，用占位（实际值在调用方栈上）
          za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19]);
}

static void za_hook_m_allocbail(unsigned long long *r)
{
    __atomic_add_fetch(&za_n_allocbail, 1, __ATOMIC_RELAXED);
    // 弃单之后是 udf #0 硬崩，这条日志通常是此生最后一条
    ZLOGE("★ E2b 分配弃单 0xd7fa98！x22=%#llx lr=main+%#llx",
          r[16],
          za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19]);
}

// ── E3：消费侧证据 ─────────────────────────────────────────────
// 队列类 vt[+0x10]=0x255ae70 是「执行一条命令」的转发器（读命令对象 +8/+0x10/
// +0x18/+0x1a，转发到 [目标+0x18]）。106 个命令推给了它所属的队列；如果这里
// 从不触发 ⇒ 消费者线程/派发循环根本不存在，队列饿死。
static void za_hook_m_fwd(unsigned long long *r)
{
    __atomic_add_fetch(&za_n_fwd, 1, __ATOMIC_RELAXED);
    static int n;
    if (n++ >= 4) return;
    unsigned long long vt = 0, p8 = 0, p10 = 0;
    unsigned short w18 = 0, w1a = 0;
    if (ZA_PTR_OK(r[0])) {
        memcpy(&vt, (const void *)(uintptr_t)r[0], 8);
        memcpy(&p8, (const void *)(uintptr_t)(r[0] + 8), 8);
        memcpy(&p10, (const void *)(uintptr_t)(r[0] + 0x10), 8);
        memcpy(&w18, (const void *)(uintptr_t)(r[0] + 0x18), 2);
        memcpy(&w1a, (const void *)(uintptr_t)(r[0] + 0x1a), 2);
    }
    ZLOGI("★ E3 命令转发器 0x255ae70: 命令=%#llx vt=%#llx +8=%#llx +10=%#llx +18=%u +1a=%u lr=main+%#llx",
          r[0], vt, p8, p10, (unsigned)w18, (unsigned)w1a,
          za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19]);
}

// 队列析构（vt[0]/[8]）：它的存在 = 引擎主动拆掉这个队列类对象（+0x110/+0xf0
// 成员销毁、+0xa8 缓冲释放）。若它在 push 后不久触发，说明「结构被拆」是引擎行为。
static void za_hook_m_qdtor(unsigned long long *r)
{
    __atomic_add_fetch(&za_n_qdtor, 1, __ATOMIC_RELAXED);
    static int n;
    if (n++ >= 4) return;
    unsigned long long vt = 0;
    if (ZA_PTR_OK(r[0])) memcpy(&vt, (const void *)(uintptr_t)r[0], 8);
    ZLOGI("★ E3 队列析构 0x1703390: obj=%#llx vt=%#llx lr=main+%#llx tid=%ld",
          r[0], vt,
          za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19],
          (long)syscall(SYS_gettid));
}

// ── E9-①：TLS scratch 覆盖证明 ──────────────────────────────────────
// 两处 stash 都是 `str x21,[slot,#0x18]`，slot = ctx + [ctx+0x98]*8。
// 我们令 [D+0x98]=0x2000 ⇒ slot 恒 = V+0x18。探针装在 str 之前：
// 槽旧值非 0 = 有人已经在这个槽存过东西 ⇒ 现在这次会把它覆盖掉。
// 派发路径存 [x0+8]（job 上下文），整备路径存分配器对象——
// 同一个槽上的两次事件 = 互相覆盖的直接证据。
static void za_tls_stash_check(unsigned long long *r, unsigned long long slot,
                               const char *who, volatile unsigned long long *counter)
{
    __atomic_add_fetch(counter, 1, __ATOMIC_RELAXED);
    if (!slot || !ZA_PTR_OK(slot)) return;
    unsigned long long old = 0;
    if (!za_read_bytes((unsigned long)slot, &old, 8) || old == 0) return;
    static int n;
    if (n++ >= 24) return;
    ZLOGE("★ E9 TLS scratch 覆盖[%s]: 槽=%#llx 旧值=%#llx tid=%ld lr=main+%#llx",
          who, slot, old, (long)syscall(SYS_gettid),
          za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19]);
}

static void za_hook_m_stash_disp(unsigned long long *r)
{
    // 0xd7f30c: str x21,[x8,#0x18]
    za_tls_stash_check(r, r[8] + 0x18, "派发", &za_n_stash_disp);
}

static void za_hook_m_stash_intake(unsigned long long *r)
{
    // 0x194e458: str x21,[x9,#0x18]
    za_tls_stash_check(r, r[9] + 0x18, "整备", &za_n_stash_intake);
}

// E7：0x194e850（派发侧「按 lane 哈希桶选命令」）入口。
// x0 = 派发器查询的容器、x1 = worker 描述（[desc+0x28]=lane）。
// 与 enq3 记录的「被 push 容器」对账：两个地址不同 ⇒ 106 个命令推进了
// 一个派发器从不读的容器（推错队列的精确形态）。
static void za_hook_m_picker(unsigned long long *r)
{
    za_picker_container = r[0];                    // E10：记住 D
    static int n;
    if (n++ >= 8) return;
    unsigned char lane = 0xFF;
    unsigned long long vt = 0;
    if (ZA_PTR_OK(r[1]))
        za_read_bytes((unsigned long)(r[1] + 0x28), &lane, 1);   // ldrb w8,[desc+0x28]
    if (ZA_PTR_OK(r[0]))
        za_read_bytes((unsigned long)r[0], &vt, 8);
    extern volatile unsigned long long za_enq_queue;
    ZLOGE("★ E7 派发侧选命令: 容器=%#llx（被push容器=%#llx %s）lane=%u vt=%#llx lr=main+%#llx",
          r[0], za_enq_queue,
          r[0] == za_enq_queue ? "同一个" : "★不同★",
          (unsigned)lane, vt,
          za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19]);
}

// E10：搬运族入口 0x194e3d0（含环槽拷贝 0x1955724 的两个调用点）。
// 三方对账：P（被 push 的容器 za_enq_queue）、D（派发器 picker 看到的容器）、
// 这里收到的 x0。x0==D ⇒ 搬运只在 D 内部；x0==P ⇒ 搬运读的是 P（桥存在）；
// 都不是 ⇒ 第三容器。
// ── E11：dispatch 的五个子调用 ──────────────────────────────────
// 0xd7bdb8 的调用序列：0xd7be10(→B，已覆盖) → 0xd7cd10 → 0xd7e820 →
// 0xd7eb10 → 0x1700c40 → 0xd7f040 → 尾跳 A。P 里的 106 个活要有人领走，
// 候选就在这五个里。谁 0 次 = 没跑；谁跑了但 P 没动 = 不是它。
static void za_sub_log(unsigned long long *r, int idx, const char *name)
{
    __atomic_add_fetch(&za_n_sub[idx], 1, __ATOMIC_RELAXED);
    static int n[5];
    if (n[idx]++ >= 3) return;
    ZLOGI("★ E11 子调用 %s: x0=%#llx x1=%#llx lr=main+%#llx",
          name, r[0], r[1],
          za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19]);
}
static void za_hook_m_sub0(unsigned long long *r) { za_sub_log(r, 0, "0xd7cd10"); }
static void za_hook_m_sub1(unsigned long long *r) { za_sub_log(r, 1, "0xd7e820"); }
static void za_hook_m_sub2(unsigned long long *r) { za_sub_log(r, 2, "0xd7eb10"); }
static void za_hook_m_sub3(unsigned long long *r) { za_sub_log(r, 3, "0x1700c40"); }
static void za_hook_m_sub4(unsigned long long *r) { za_sub_log(r, 4, "0xd7f040"); }

// ── E12：B 的回滚路径三针 ───────────────────────────────────────
// B(0xd7f560) 构造完 job 后若引用计数读到 -1（0xffffffff）就跳 0xd7fa38：
// 销毁 job → bl 0xd7fdb0 → bl 0xd81f60 → ret。E11 显示五个子调用全 0 ⇒
// B 没返回。三针定位：进回滚(fa3c) / d7fdb0 返回后(fa64) / d81f60 入口。
static void za_rb_log(unsigned long long *r, int idx, const char *name)
{
    __atomic_add_fetch(&za_n_rb[idx], 1, __ATOMIC_RELAXED);
    static int n[3];
    if (n[idx]++ >= 3) return;
    // 桩只保存 x0-x17 与 lr（x21 等不可见），命中本身即判据
    ZLOGE("★ E12 回滚 %s: 命中 lr=main+%#llx x0=%#llx",
          name, za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19], r[0]);
}
static void za_hook_m_rb_enter(unsigned long long *r) { za_rb_log(r, 0, "进回滚@fa3c"); }
static void za_hook_m_rb_fdb0(unsigned long long *r)  { za_rb_log(r, 1, "d7fdb0已返回@fa64"); }
static void za_hook_m_rb_d81f60(unsigned long long *r) { za_rb_log(r, 2, "d81f60入口"); }

// E14：哈希 find（0x1706640）入口。x0 = map 基址。
// 如果 map == P+0x70 ⇒ 有人在查 P 的条目（「106 不降」不等于没人读）。
// ── E16：P 类 vtable 剩余槽位 + 同族函数 ───────────────────────
// 槽位表（main+0x3a29f48）：[0]=0x1703390 析构、[8]=0x17034c0 调整器、
// [0x10]=0x255ae70 转发器（已知 19 次）、[0x18]=0x255aec0、[0x20]=0x255aef0
// （尾跳 0x255af80）、[0x38]/[0x40] 调整器、[0x48]=0x255af04。
// 若某个槽位 0 次 ⇒ 引擎本该调的排水/派发方法从未被调（或它就被设计成
// 由别的路径调）。同族 0x16ffb40（与 0x16ffd70 同构、带 [queue+0x120] 开关）
// 也一并数：它是「另一条 push 路径」，若 0 次 ⇒ 从未走过。
static void za_vt_log(unsigned long long *r, int idx, const char *name)
{
    __atomic_add_fetch(&za_n_vt[idx], 1, __ATOMIC_RELAXED);
    static int n[4];
    if (n[idx]++ >= 2) return;
    ZLOGI("★ E16 槽位 %s: x0=%#llx x1=%#llx lr=main+%#llx",
          name, r[0], r[1],
          za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19]);
}
static void za_hook_m_vt0(unsigned long long *r) { za_vt_log(r, 0, "vt[0x18]=0x255aec0"); }
static void za_hook_m_vt1(unsigned long long *r) { za_vt_log(r, 1, "vt[0x20]→0x255af80"); }
static void za_hook_m_vt2(unsigned long long *r) { za_vt_log(r, 2, "vt[0x48]=0x255af04"); }
static void za_hook_m_vt3(unsigned long long *r) { za_vt_log(r, 3, "同族0x16ffb40"); }

static void za_hook_m_find(unsigned long long *r)
{
    __atomic_add_fetch(&za_n_find, 1, __ATOMIC_RELAXED);
    extern volatile unsigned long long za_enq_queue;
    unsigned long long p = za_enq_queue;
    if (p && r[0] == p + 0x70) {
        __atomic_add_fetch(&za_n_find_p, 1, __ATOMIC_RELAXED);
        static int n;
        if (n++ < 6)
            ZLOGE("★ E14 P的find被调用: map=%#llx(=P+0x70) 总计P查找=%llu lr=main+%#llx",
                  r[0], (unsigned long long)za_n_find_p,
                  za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19]);
    }
}

static void za_hook_m_mover(unsigned long long *r)
{
    __atomic_add_fetch(&za_n_mover, 1, __ATOMIC_RELAXED);
    static int n;
    if (n++ >= 8) return;
    extern volatile unsigned long long za_enq_queue;
    unsigned char lane = 0xFF;
    unsigned long long f0 = 0;
    if (ZA_PTR_OK(r[1])) za_read_bytes((unsigned long)(r[1] + 0x28), &lane, 1);
    if (ZA_PTR_OK(r[0])) za_read_bytes((unsigned long)r[0], &f0, 8);
    ZLOGE("★ E10 搬运族 0x194e3d0: 容器=%#llx（P=%#llx %s / D=%#llx %s）[x0]=%#llx lane=%u lr=main+%#llx",
          r[0],
          za_enq_queue, r[0] == za_enq_queue ? "=P" : "≠P",
          za_picker_container, r[0] == za_picker_container ? "=D" : "≠D",
          f0, (unsigned)lane,
          za_guest_base ? r[19] - (unsigned long long)(uintptr_t)za_guest_base : r[19]);
}

// 真正的提交点（main+0xd848fc）：`ldr x8,[x22] ; ldr x8,[x8,#0x50] ; blr x8`。
// 紧随其后 main 就 `bl 0x413b8` 等这个任务 —— 这里就是「任务交给谁」的唯一入口。
static void za_hook_m_jobsubmit2(unsigned long long *r)
{
    static int n;
    if (n++ >= 6) return;
    unsigned long long o = r[0];            // x0 = x22
    unsigned long long vt = 0, fn = 0, g = 0;
    if (ZA_PTR_OK(o)) memcpy(&vt, (const void *)(uintptr_t)o, 8);
    if (ZA_PTR_OK(vt)) memcpy(&fn, (const void *)(uintptr_t)(vt + 0x50), 8);
    {
        unsigned long gb = (unsigned long)za_guest_base;
        if (gb) memcpy(&g, (const void *)(uintptr_t)(gb + 0x3d80800), 8);
    }
    ZLOGI("★ 提交点 x22=%#llx vtable=%#llx [vt+0x50]=%#llx（调度器单例=%#llx）",
          o, vt, fn, g);
}

static void za_hook_m_dequeue(unsigned long long *r)
{
    static volatile unsigned long long n;
    unsigned long long k = __atomic_add_fetch(&n, 1, __ATOMIC_RELAXED);
    unsigned long long o = r[0];
    unsigned int cnt = 0, cnt2 = 0;
    za_worker_obj = o;
    __atomic_store_n(&za_worker_polls, k, __ATOMIC_RELAXED);
    if (ZA_PTR_OK(o)) {
        memcpy(&cnt, (const void *)(uintptr_t)(o + 0x2f8), 4);
        memcpy(&cnt2, (const void *)(uintptr_t)(o + 0x330), 4);
    }
    if (k <= 8 || cnt || (k % 500ull) == 0)
        ZLOGI("★ worker 出队: 第%llu次 obj=%#llx 队列数(+0x2f8)=%u +0x330=%u",
              k, o, cnt, cnt2);
}
// 入队点（main+0xd848fc）：`ldr x8,[x22] ; ldr x8,[x8,#0x50] ; blr x8`
//   ⇒ x22 是调度器对象，vtable+0x50 是「把任务交出去」的虚函数。
//   把这条链解出来，就能定位任务到底交给了谁、有没有真的入队。
static void za_hook_m_jobenqueue(unsigned long long *r)
{
    static int n;
    if (n++ >= 4) return;
    unsigned long long vt = r[8], fn = 0;
    if (ZA_PTR_OK(vt))
        memcpy(&fn, (const void *)(uintptr_t)(vt + 0x50), 8);
    {
        char a[48], b[48];
        za_fmt_addr(a, sizeof a, vt);
        za_fmt_addr(b, sizeof b, fn);
        ZLOGI("★ job-enqueue: 调度器 vtable=%s 入队函数=%s", a, b);
    }
}

// 停摆快照用：读调度器单例（main+0x3d80800）的 vtable 与两个虚函数目标。
// 探针里读到的可能是 0（对象尚未构造完），停摆时刻再读一次。
void za_dump_dispatch_state(void)
{
    unsigned long gb = (unsigned long)za_guest_base;
    unsigned long long g = 0, vt = 0, f10 = 0, f50 = 0;
    if (gb) {
        memcpy(&g, (const void *)(uintptr_t)(gb + 0x3d80800), 8);
        if (ZA_PTR_OK(g)) {
            memcpy(&vt, (const void *)(uintptr_t)g, 8);
            if (ZA_PTR_OK(vt)) {
                memcpy(&f10, (const void *)(uintptr_t)(vt + 0x10), 8);
                memcpy(&f50, (const void *)(uintptr_t)(vt + 0x50), 8);
            }
        }
    }
    {
        char a[40], b[40], c[40], d[40];
        za_fmt_addr(a, sizeof a, g);
        za_fmt_addr(b, sizeof b, vt);
        za_fmt_addr(c, sizeof c, f10);
        za_fmt_addr(d, sizeof d, f50);
        ZLOGE("★ 调度器单例=%s vtable=%s [+0x10]=%s [+0x50]=%s", a, b, c, d);
    }
    // E15：单例字段全景——P（被 push 容器）和 D（派发器容器）是不是同一个
    // 单例的两个字段？打印时把命中标出来（P/D 来自 enq3/picker 的实时记录）。
    if (ZA_PTR_OK(g)) {
        extern volatile unsigned long long za_enq_queue, za_picker_container;
        for (unsigned long long off = 0; off < 0x200; off += 8) {
            unsigned long long v = 0;
            za_read_bytes((unsigned long)(g + off), &v, 8);
            if (!v) continue;
            const char *tag = "";
            if (v == za_enq_queue) tag = " ← P(被push)";
            else if (v == za_picker_container) tag = " ← D(派发器)";
            else if (za_enq_queue && v == za_enq_queue + 0x70) tag = " ← P的map";
            // v 指向堆对象时顺手读它的首字段（vtable/分配器），找同族对象
            if (!tag[0] && ZA_PTR_OK(v)) {
                unsigned long long vv = 0;
                za_read_bytes((unsigned long)v, &vv, 8);
                if (vv == 0x103a29f48ull) tag = " → 同为P类容器";
            }
            ZLOGE("   单例+%#llx = %#llx%s", off, v, tag);
        }
    }
}

// 循环入口（main+0x1653d00）：x0=desc(+0x18 stride,+0x1c count), x2=base, x8=stride/8
// ★ 2026-10-28：装在循环头，每迭代一次就进来一次 ⇒ 累计迭代数 ÷ count = 完整建表了几轮。
static void za_hook_m_poolloop(unsigned long long *r)
{
    static volatile unsigned long long iters;
    unsigned long long n = __atomic_add_fetch(&iters, 1, __ATOMIC_RELAXED);
    if (n > 6 && (n % 4681ull) != 0) return;
    unsigned long long desc = r[0], base = r[2], stride = r[8] << 3;
    unsigned int count = 0;
    if (desc) memcpy(&count, (const void *)(uintptr_t)(desc + 0x1c), 4);
    ZLOGI("★ main 探针 pool-loop: 累计第%llu次迭代 desc=%#llx base=%#llx stride=%#llx "
          "count=%u ⇒ 跨度=%#llx（约 %llu 轮完整建表）",
          n, desc, base, stride, count, stride * (unsigned long long)count,
          count ? n / count : 0);
}

static void za_install_main_probe(unsigned char *base, unsigned int func_off,
                                  unsigned int stub_off, unsigned int hook_off,
                                  void (*hook)(unsigned long long *))
{
    unsigned int *s = (unsigned int *)(base + stub_off);
    unsigned int orig = *(unsigned int *)(base + func_off);
    // ★ 2026-10-28：**PC 相对指令不能重放**。桩在 0x6048000，原指令在 main 映像里，
    //   重放 ADR/ADRP/B/BL/CBZ/TBZ/LDR-literal 时会按**桩的 PC** 重新计算目标。
    //   真机实测：探针装在 main+0xd270d4 的 `adrp x8, 0x3d8000` 上，重放后
    //   x8 变成 main+0x90a1000，随后 ldr x8,[x8,#0x800] 崩在 main+0x90a1800
    //   —— 等于我们自己把游戏打断了（而且看起来像「游戏死锁」）。
    //   检测到这类指令就拒绝安装并在日志里点名，换一条安全指令。
    {
        int pcrel = 0;
        if ((orig & 0x9F000000u) == 0x90000000u) pcrel = 1;      // ADR/ADRP
        if ((orig & 0x7C000000u) == 0x14000000u) pcrel = 1;      // B/BL
        if ((orig & 0x7E000000u) == 0x34000000u) pcrel = 1;      // CBZ/CBNZ
        if ((orig & 0x7E000000u) == 0x36000000u) pcrel = 1;      // TBZ/TBNZ
        if ((orig & 0x3B000000u) == 0x18000000u) pcrel = 1;      // LDR literal
        if (pcrel) {
            ZLOGE("★ 探针拒绝安装在 main+%#x：首指令 %#x 是 PC 相对指令，"
                  "重放到桩里会算错目标（换一条安全指令）", func_off, orig);
            return;
        }
    }
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
            // ★ 2026-10-28：nn::mem 的几个符号解析到哪个地址 —— 用来确认
            //   `StandardAllocator::Initialize` 拿到的是 SDK 真实现（而非桩），
            //   以便下一步直接在它的入口装探针。
            if (name && strstr(name, "nn3mem"))
                ZLOGI("mem 导入 %s -> %p（base=%p）", name, p, (void *)base);
            // 桩 0x2fc5a20 读 GOT 槽 0x3cea090，调用点 main+0x1a0495c 崩在里面
            // ⇒ 把槽号一起打出来，才能确定那到底是谁（名字表的两列都有偏移，不能靠猜）。
            if (name && (r->slot == 0x3cea090u || r->slot == 0x3cea098u ||
                         r->slot == 0x3cea088u || r->slot == 0x3ce9b40u ||
                         r->slot == 0x3ceab68u || r->slot == 0x3ceab60u))
                ZLOGE("★ GOT 槽 %#x = %s -> %p", r->slot, name, p);
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
// 落文件的上限：这个文件是**跨进程追加**的，反复重启会把平板写满
// （实测累积到 514 MB，直接拖慢整机）。超过上限就只写 logcat。
#define ZA_LOG_FILE_CAP (64ull << 20)
static unsigned long long za_log_bytes;

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
    if (za_log_fd < 0) {
        za_log_fd = open("/data/data/org.pokelegza.android.port/files/za_log.txt",
                         O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
        struct stat st;
        if (za_log_fd >= 0 && fstat(za_log_fd, &st) == 0) {
            za_log_bytes = (unsigned long long)st.st_size;
            if (za_log_bytes > ZA_LOG_FILE_CAP) {      // 旧文件太大：清掉重新记
                close(za_log_fd);
                za_log_fd = open("/data/data/org.pokelegza.android.port/files/za_log.txt",
                                 O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
                za_log_bytes = 0;
            }
        }
    }
    if (za_log_fd >= 0 && za_log_bytes < ZA_LOG_FILE_CAP) {
        ssize_t w = write(za_log_fd, buf, (size_t)n + 1);
        if (w > 0) za_log_bytes += (unsigned long long)w;
        if (za_log_bytes >= ZA_LOG_FILE_CAP)
            __android_log_print(ANDROID_LOG_WARN, "ZaGuest",
                                "日志文件到 64MB 上限，之后只写 logcat");
    }
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

// 采样到的寄存器快照：主线程在「等任务完成」的死循环里自旋时，唯一能拿到
// 它寄存器（x19 = 那个任务对象）的办法就是采样信号。（2026-10-28）
volatile unsigned long za_samp_pc;
volatile unsigned long za_samp_regs[32];
volatile long za_samp_tid;
// 按线程分槽（tid & 31）——停摆时要找的是「正在那个自旋回路里的线程」，
// 它不一定是主线程（实测常常是某个 worker）。类型定义在文件前部。
za_samp_slot_t za_samp_tab[32];

static void za_pc_sample_handler(int sig, siginfo_t *info, void *ctx)
{
    (void)sig; (void)info;
    // ★ 2026-10-28：这里**绝不能调 ZLOGI**。日志函数要拿互斥、走 malloc，
    //   不是 async-signal-safe：信号恰好打断正在写日志的线程时会自锁/踩堆，
    //   真机上就表现为「宿主崩溃 pc=libzaandroid.so+0xd77fc」，崩溃点落在
    //   本函数里。信号处理器只做纯存储。
    if (!ctx) return;
    ucontext_t *uc = (ucontext_t *)ctx;
    unsigned long pc = (unsigned long)uc->uc_mcontext.pc;
    static volatile unsigned long raw_last;
    raw_last = pc;
    // 寄存器快照（只给主线程自旋诊断用；每次都覆盖）
    za_samp_pc = pc;
    za_samp_tid = (long)syscall(SYS_gettid);
    for (int i = 0; i < 31; i++) za_samp_regs[i] = (unsigned long)uc->uc_mcontext.regs[i];
    {
        long t = za_samp_tid;
        za_samp_slot_t *sl = &za_samp_tab[t & 31];
        sl->tid = t;
        sl->pc = pc;
        for (int i = 0; i < 31; i++) sl->regs[i] = (unsigned long)uc->uc_mcontext.regs[i];
    }
    // ★ 2026-10-28：**所有**样本都记（不再只记客机映像内的）。停摆时真正要回答的
    //   是「每条线程此刻停在哪」；把落在 libc/驱动里的样本丢掉，等于把
    //   正在 futex/驱动里等的那十几条线程全滤掉，只剩一堆旧样本。
    if ((za_guest_base && pc >= (unsigned long)za_guest_base &&
         pc < (unsigned long)za_guest_base + ZA_IMAGE_SIZE) ||
        (za_sdk_base && pc >= za_sdk_base && pc < za_sdk_base + za_sdk_size))
        za_guest_last_guest_pc = pc;
    // 环形轨迹：崩溃前最后若干条 PC（含线程号）。
    unsigned long p = za_pc_ring_pos;
    za_pc_ring[p % ZA_PC_RING] = pc;
    za_pc_tid_ring[p % ZA_PC_RING] = (long)syscall(SYS_gettid);
    za_pc_ring_pos = p + 1;
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
        sa.sa_flags = SA_SIGINFO | SA_RESTART | SA_ONSTACK;
        sigemptyset(&sa.sa_mask);
        sigaction(ZA_SAMPLER_SIG, &sa, NULL);
    }
    int mi = (int)((unsigned long)syscall(SYS_gettid) % 128u);
    if (mask_done[mi]) return;
    mask_done[mi] = 1;
    // 备用信号栈：采样信号可能正好落在客机很深的调用栈上（或被 svc 门切到
    // 宿主栈的深处），在快溢出的栈上跑处理器会二次 fault。SA_ONSTACK + 每线程
    // 64KB 备用栈可以避免这一类崩溃。
    {
        static stack_t alt[128];
        static int alt_done[128];
        if (!alt_done[mi]) {
            alt_done[mi] = 1;
            size_t sz = 64 * 1024;
            void *p = mmap(NULL, sz, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (p != MAP_FAILED) {
                alt[mi].ss_sp = p;
                alt[mi].ss_size = sz;
                alt[mi].ss_flags = 0;
                sigaltstack(&alt[mi], NULL);
            }
        }
    }
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
        // ★ 2026-10-28：常开的 10 秒快照。以前所有倒出都挂在「svc 没推进」
        //   或「NVN 有调用」这类条件上：客机自旋时 svc 一直在涨、还没进 NVN 时
        //   帧驱动又没起来 ⇒ 两种情况下都一行诊断都没有，等于没有观测。
        {
            static unsigned long long last_dump_ns;
            struct timespec tp;
            clock_gettime(CLOCK_MONOTONIC, &tp);
            unsigned long long now = (unsigned long long)tp.tv_sec * 1000000000ull +
                                     (unsigned long long)tp.tv_nsec;
            if (now - last_dump_ns >= 10ull * 1000000000ull) {
                last_dump_ns = now;
                za_dump_progress_stall();
            }
        }
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
                        {
                            extern long za_tgkill_hottest(int sig);
                            if (za_tgkill_hottest(ZA_SAMPLER_SIG) < 0 && za_guest_tid > 0)
                                syscall(SYS_tgkill, (int)getpid(), (int)za_guest_tid, ZA_SAMPLER_SIG);
                        }
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
                        {
                            extern void za_ptrace_dump_all(void);
                            extern void za_dump_task_stats(void);
                            za_dump_task_stats();
                            // 采样器环形轨迹（现在是纯存储、async-signal-safe）
                            {
                                extern void za_sample_all_threads(void);
                                extern void za_dump_thread_pcs2(void);
                                extern void za_write_maps_now(void);
                                za_write_maps_now();
                                // ★ 先做两次采样对照：谁在用户态自旋（不发 svc）只能这样看见。
                                za_dump_thread_pcs2();
                                za_sample_all_threads();
                                struct timespec samp = { 0, 40 * 1000 * 1000 };
                                nanosleep(&samp, NULL);
                                unsigned long pos = za_pc_ring_pos;
                                unsigned long n = pos < ZA_PC_RING ? pos : ZA_PC_RING;
                                extern unsigned char *za_guest_base;
                                unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
                                ZLOGE("★ PC 采样环（最近 %lu 条，signal=%d）：", n, ZA_SAMPLER_SIG);
                                for (unsigned long i = 0; i < n; i++) {
                                    unsigned long k = (pos - n + i) % ZA_PC_RING;
                                    unsigned long pc = za_pc_ring[k];
                                    unsigned long long off = pc;
                                    const char *w = "@";
                                    if (pc >= mb && pc < mb + ZA_IMAGE_SIZE) { w = "main+"; off = pc - mb; }
                                    else if (za_sdk_base && pc >= za_sdk_base &&
                                             pc < za_sdk_base + za_sdk_size) { w = "sdk+"; off = pc - za_sdk_base; }
                                    ZLOGE("    tid=%ld %s%#llx", za_pc_tid_ring[k], w, off);
                                }
                            }
                            za_ptrace_dump_all();
                            {
                                extern void za_dump_mutex_trace(void);
                                za_dump_mutex_trace();
                            }
                        }
                        if (za_guest_tid > 0) za_sync_dump_chain_for(za_guest_tid);
                        {
                            extern void za_dump_job_states(void);
                            extern void za_dump_hle_stuck(void);
                            extern void za_dump_dispatch_state(void);
                            extern void za_scan_job_in_heap(void);
                            za_dump_job_states();
                            za_scan_job_in_heap();
                            za_dump_dispatch_state();
                            za_dump_hle_stuck();
                        }
                        // 主线程阻塞在哪个锁上 ⇒ 扫所有线程栈找持有者
                        {
                            extern unsigned long long za_last_blocked_addr(long tid);
                            extern void za_sync_scan_for_addr(unsigned long long val);
                            unsigned long long lb = za_last_blocked_addr(za_guest_tid);
                            if (lb) {
                                ZLOGE("★ 主线程阻塞地址 %#llx ⇒ 扫全线程栈找持有者：", lb);
                                za_sync_scan_for_addr(lb);
                                {
                                    extern void za_dump_mtx_hist(unsigned long long addr);
                                    za_dump_mtx_hist(lb);
                                }
                                // ★ 2026-10-28：慢路径（sdk+0x13a5d0）探针实测，
                                //   锁字经常停在 **2（交接态）**；解锁路径的动作就是
                                //   `cmp #2 ; stlxr wzr` 把它清回 0。对所有被探针记录过
                                //   且在等待态卡住的对象做同一动作。
                                {
                                    extern int za_mutex_clear_handoff(void);
                                    int ncl = za_mutex_clear_handoff();
                                    if (ncl) ZLOGE("   ↳ 本轮清了 %d 个交接态锁字", ncl);
                                }
                            }
                        }
                    }
                    za_nvn_dump_recent();   // 带客机 LR：最后几步 NVN 调用发生在哪
                }
                unsigned pk = za_fakewake_on() ? za_sync_poke_all() : 0;
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
                ZLOGE("★ 卡死 60 秒：采样客机线程 PC（信号 %d，不再用 SIGSEGV）", ZA_SAMPLER_SIG);
                za_sync_dump();
                syscall(SYS_tgkill, (int)getpid(), (int)za_guest_tid, ZA_SAMPLER_SIG);
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