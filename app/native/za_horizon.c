// Horizon 内核服务（svc）宿主实现。
//
// 客机（SDK NSO）用 `svc #N` 调 Horizon 内核服务。在 Linux/arm64 上 `svc` 就是系统调用
// ⇒ 未知号 ⇒ SIGSYS ⇒ 客机直接死。所以把 SDK text 里的 58 处 `svc #N` 全部改写成
// `b 门_N`，门区在映像末尾扩展区（见 tools/patch_svc.py）。
//
// ── 调用约定（权威来源：SDK 自己那 58 个包装函数，tools/dump_svc_wrappers.py 可 dump）──
//   包装函数长这样（以 svc #2 为例）：
//       16ffec: svc #2
//       16fff0: ret
//   ⇒ 纯 B 形式的服务：入参 x0..x7，**结果在 W0**（0 = 成功）。
//
//   带出参的服务（以 svc #1 SetHeapSize 为例）：
//       str x0, [sp, #-0x10]!     ; x0 = 出参指针，先存起来
//       svc  #1                   ; W1 = 出参值
//       ldr x2, [sp]
//       str x1, [x2]              ; 把 W1 写进 *x0
//       add sp, sp, #0x10
//       ret
//   ⇒ **结果在 W0，出参在 W1**（部分服务还有 W2）。
//
//   服务 #47(0x2F) 特殊：出参在 x1..x6（包装器把它们分别写进 3 个指针）。
//
// ── 为什么 trampoline 要回写 x1..x7 ──
//   我们的 C 函数只能返回一个值（x0）。但 Horizon 的出参在 W1/W2 里，
//   包装器 `svc` 返回后立刻读 W1。所以 C 侧把要回写的 x1..x7 放进
//   `za_horizon_regs[]`，由 trampoline 在 blr 之后从固定槽读回来。
//
// ── 服务号表 ──
//   1..0x2E 的名字与参数来自 switchbrew 的 Horizon 系统调用表；
//   0x2F 以上（47/50/51/53/54/64/65/67/68/69/75/80/81/82/112/114）
//   switchbrew 没列全，语义按「有出参就写 0，无出参就返回 0」处理。

#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "za_common.h"
#include "za_svc_patch.h"
#include "za_guest_api.h"
#include "za_guest_info.h"
#include "za_mem.h"
#include "za_os.h"
#include "za_nvn.h"
#include "za_sync.h"

static void za_spcache_put(long tid, unsigned long long sp);
static unsigned long long za_spcache_get(long tid);
// ── svc#52 陈旧持锁兜底（按地址记时间戳）────────────────────────────
// 该等待会被 20ms 分片反复重新进入，函数内计数器每次都从 0 开始，
// 所以原先 slices >= 50 的兜底永远达不到、从未生效（真机确认）。
#define ZA_STALE_N 32
static struct { unsigned long long addr; unsigned long long since; } za_stale[ZA_STALE_N];
static unsigned long long za_stale_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}
static int za_stale_check(unsigned long long addr)
{
    unsigned long long now = za_stale_now();
    int slot = -1, free_slot = -1;
    for (int i = 0; i < ZA_STALE_N; i++) {
        if (za_stale[i].addr == addr) { slot = i; break; }
        if (!za_stale[i].addr && free_slot < 0) free_slot = i;
    }
    if (slot < 0) {
        if (free_slot < 0) return 0;
        za_stale[free_slot].addr = addr;
        za_stale[free_slot].since = now;
        return 0;
    }
    if (now - za_stale[slot].since > 1000000000ull) { za_stale[slot].addr = 0; return 1; }
    return 0;
}
static void za_stale_clear(unsigned long long addr)
{
    for (int i = 0; i < ZA_STALE_N; i++)
        if (za_stale[i].addr == addr) { za_stale[i].addr = 0; return; }
}

// SDK 映像基址/大小（定义在 za_guest.c）：崩溃与断言回溯时用来把地址换算成模块偏移
extern volatile unsigned long za_sdk_base;
extern volatile unsigned long za_sdk_size;
// 主 NSO 映像基址（定义在 za_guest.c）
extern unsigned char *za_guest_base;

// trampoline 回写用的寄存器数组：index 0 = 结果(x0)，1..7 = x1..x7，
// index 9 = 客机 sp，10 = 服务号，11 = 客机 x30（svc 调用点的返回地址，
// 日志里用来定位是哪个函数调的服务）。
//
// ★★★ 2026-10-26：必须**每线程一份**。
//   以前是全局数组，trampoline 把服务号写进 regs[10] 再读回来当第 9 个 C 参数，
//   x1..x7 也从这张表回写 —— 两个线程同时进 svc 时：
//     · A 的 nr 被 B 覆盖（实测：svc#28 被记成 svc#44，参数却是 Wait 的 cs/cv）；
//     · A 的 x1..x7 被写成 B 留下的陈旧值（Horizon 约定 svc 只改 x0，SDK 依赖这点）
//   ⇒ 客机随机跳野地址（实测 pc=0x7fffffff00000000）。
//   现在 regs 放在**每线程描述符页**里（hdr+0x200），描述符 +0xa0 存它的地址；
//   trampoline 用 `mrs TPIDR_EL0 → [tp+0x40] → [+0xa0]` 现取，不再共享。
#define ZA_REGS_MAGIC 0x5a5a524547535f31ull   /* "ZA_REGS_1" */
static unsigned long long za_regs_fallback[32];
unsigned long long *za_regs_get(void)
{
    unsigned long tp = 0;
    __asm__ __volatile__("mrs %0, TPIDR_EL0" : "=r"(tp));
    if (tp)
    {
        unsigned long long hdr = 0;
        __builtin_memcpy(&hdr, (const void *)(uintptr_t)(tp + 0x40), 8);
        if (hdr)
        {
            unsigned long long p = 0;
            __builtin_memcpy(&p, (const void *)(uintptr_t)(hdr + 0xA0), 8);
            if (p && *(unsigned long long *)(uintptr_t)(p + 31 * 8) == ZA_REGS_MAGIC)
                return (unsigned long long *)(uintptr_t)p;
            // ★ 2026-10-28：魔数不符时**仍然返回同一个地址**。
            //   门桩是照 `[TP+0x40] → [+0xA0]` 取的，C 侧若在这里退到全局兜底槽，
            //   两侧读写的就不是同一块内存 ⇒ 该线程的 sp/x30/x29 在 C 侧永远是 0
            //   （真机实测：主线程 pc=sp=fp=0，而所有工作线程正常）。
            //   一致性比「安全」重要：至少能读到门桩真正写下的值。
            if (p && !(p & 7)) {
                static volatile int warned2;
                if (!warned2) {
                    warned2 = 1;
                    ZLOGI("svc 寄存器槽：tid=%ld 的槽没有魔数（p=%#llx，读到 %#llx）"
                          "⇒ 门桩与 C 侧地址不一致，改按门桩的地址读写",
                          (long)syscall(SYS_gettid), (unsigned long long)p,
                          *(unsigned long long *)(uintptr_t)(p + 31 * 8));
                }
                return (unsigned long long *)(uintptr_t)p;
            }
        }
    }
    // 一发式诊断：谁落到了全局兜底槽。**主线程**如果出现在这里，说明门桩
    // 没把 sp/x30/x29 写进它自己的槽 ⇒ 它的调用链拿不到 fp（实测正是如此：
    // 主线程 svc 的 pc=sp=fp=0）。
    {
        static volatile int warned;
        if (!warned) {
            warned = 1;
            ZLOGI("svc 寄存器槽：tid=%ld 落到全局兜底槽（TP=%#lx）⇒ 该线程的 "
                  "sp/x30/x29 不可用，调用链需靠反向 x29 重建",
                  (long)syscall(SYS_gettid), (unsigned long)tp);
        }
    }
    return za_regs_fallback;   // 非客机线程（诊断路径）兜底
}
#define za_horizon_regs za_regs_get()

// ── 帧快照探针（2026-10-25 夜）──────────────────────────────────────
// 目的：把 0x14457c 的 x30 槽「何时变 0」一刀切开。
//   帧底 sp0 = 客机 svc 时的 sp + 0x10（包装函数先 str x?,[sp,#-0x10]!）。
//   stp x29,x30,[sp,#0x40] ⇒ x29 槽 = sp0+0x40、x30 槽 = sp0+0x48。
// 18 words = 0x90 字节：比 0x14457c 的 0x70 帧多留 0x20 余量，
// 这样无论「包装函数 prologue 有没有跑」，x29/x30 槽都一定在窗口内，
// 可以直接用「x30 == 0x20013ed84」的出现位置反推真实帧底。
#define ZA_SNAP_N 18
volatile unsigned long za_frame_snap[4][ZA_SNAP_N];
volatile unsigned long za_frame_snap_pc[4];
volatile unsigned long za_frame_snap_sp[4];
volatile int za_frame_snap_n;

static void za_frame_snapshot(unsigned long guest_pc, unsigned long guest_sp)
{
    // 只对 0x14457c 里那三条 svc 拍快照
    if (guest_pc != 0x2001445a8ul && guest_pc != 0x2001445ccul &&
        guest_pc != 0x200144608ul)
        return;
    int k = za_frame_snap_n;
    if (k >= 4) return;
    // 从 guest_sp 原样起算（不加 0x10）：由 dump 里 x30 的位置反推。
    unsigned long sp0 = guest_sp;
    za_frame_snap_pc[k] = guest_pc;
    za_frame_snap_sp[k] = sp0;
    for (int i = 0; i < ZA_SNAP_N; i++)
    {
        unsigned long v = 0;
        // 直接读客机栈；越界读由客机影像/栈映射保证可读（同一条线程栈）
        v = *(volatile unsigned long *)(uintptr_t)(sp0 + (unsigned long)i * 8);
        za_frame_snap[k][i] = v;
    }
    za_frame_snap_n = k + 1;
}


// svc 逐次轨迹：客人的 x19/x29/x30 —— 用来定位「客人的 callee-saved 何时变坏」
#define ZA_SVC_REGTRACE 16
volatile unsigned long za_horizon_regtrace[ZA_SVC_REGTRACE][4];  // [nr, pc, x19, x29]
volatile unsigned long za_horizon_regtrace_pos;

// svc 调用序号（用来限频「装回信号处理器」）。
static volatile unsigned long za_svc_seq;

#define ZA_REG_X0 0
#define ZA_REG_X1 1
#define ZA_REG_X2 2
#define ZA_REG_X3 3
#define ZA_REG_X4 4
#define ZA_REG_X5 5
#define ZA_REG_X6 6
#define ZA_REG_X7 7
#define ZA_REG_PC 11     // 客机 x30（svc 调用点的返回地址，日志里用来定位是哪个函数调的服务）
// 客机 sp：门区 `str x17,[x16,#0x48]` ⇒ 下标 9。
//   ⚠ 下标 10（+0x50）是**服务号**，11（+0x58）才是客机 x30。
#define ZA_REG_SP 9
// 客机 x29：门区 `str x29,[x16,#136]` ⇒ 下标 17。
//   svc 包装函数不改 x29（它是 callee-saved），所以这就是**调用 svc 的那个
//   函数自己的帧指针**：[fp] = 上一帧 fp，[fp+8] = 该函数的返回地址。
//   调用链回溯必须走这条链；扫栈是启发式，会把映像内的数据指针当帧。
#define ZA_REG_FP 17
// 取客机在 svc 那一刻的 sp。用它可以直接量出「sp 漂移」——
// 若两条 svc 之间客机代码没有动 sp，值必须完全一致；不一致就说明门区写坏了 sp。
unsigned long za_horizon_guest_sp(void)
{
    return za_horizon_regs[ZA_REG_SP];
}
                         // ★ 2026-10-25：新 trampoline 把栈切到宿主栈再调 C，
                         //   布局变成 [9]=客机 sp [10]=服务号 [11]=客机 x30。
#define ZA_REG_SP 9      // 客机栈指针（进入 trampoline 时的 sp）
#define ZA_REG_NR 10     // 服务号

// ───────────────────────── 句柄表 ─────────────────────────
// Horizon 的句柄是 u32。客机把它当不透明整数到处传，我们必须能查回来。
enum {
    ZA_H_FREE = 0,
    ZA_H_THREAD,
    ZA_H_EVENT,
    ZA_H_MEMORY,
};

typedef struct
{
    int used;
    int type;
    // 线程
    void (*entry)(void *);
    void *arg;
    pthread_t tid;
    int started;
    int exited;
    unsigned char *stack;
    size_t stack_size;
    // 事件（SignalEvent / ClearEvent / ResetSignal / WaitSynchronization）
    int signaled;
} za_handle_t;

#define ZA_MAX_HANDLES 512
static za_handle_t g_handles[ZA_MAX_HANDLES];
volatile unsigned long za_thread_created, za_thread_started;
static pthread_mutex_t g_handles_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_handle_cond = PTHREAD_COND_INITIALIZER;

// 句柄**从 1 开始**：0 是「无效句柄」。
// ⚠ 主线程的句柄要交给 nnosInitialize，SDK 会把它的低 32 位当**临界区 owner_id**
//   （owner_id=0 时「空闲锁字」和「我持有的锁」分不清 ⇒ 客机一进临界区就 Abort）。
static int za_handle_alloc(int type)
{
    int id = -1;
    pthread_mutex_lock(&g_handles_mtx);
    for (int i = 0; i < ZA_MAX_HANDLES; i++)
    {
        if (!g_handles[i].used) { id = i; break; }
    }
    if (id >= 0)
    {
        memset(&g_handles[id], 0, sizeof g_handles[id]);
        g_handles[id].used = 1;
        g_handles[id].type = type;
        id += 1;                    // 客机看到的句柄从 1 开始
    }
    pthread_mutex_unlock(&g_handles_mtx);
    return id;
}

// ★ 实验/兜底：把所有「事件」句柄置为已触发并唤醒所有 svc#24 等待者。
//   用途：客机整个睡在条件变量/事件上时，用来判定它是不是在等一个**外部事件**
//   （典型就是 display 的 vsync）。真机上如果这一步让帧循环跑起来，说明缺的就是
//   周期性 vsync；如果没反应，说明等待点在客机自己的逻辑里。
int za_horizon_signal_all_events(void)
{
    int n = 0;
    pthread_mutex_lock(&g_handles_mtx);
    for (int i = 0; i < ZA_MAX_HANDLES; i++)
    {
        if (!g_handles[i].used || g_handles[i].type != ZA_H_EVENT) continue;
        if (!g_handles[i].signaled) { g_handles[i].signaled = 1; n++; }
    }
    if (n) pthread_cond_broadcast(&g_handle_cond);
    pthread_mutex_unlock(&g_handles_mtx);
    return n;
}

static za_handle_t *za_handle_get(int h)
{
    if (h <= 0 || h > ZA_MAX_HANDLES) return NULL;
    int id = h - 1;
    if (!g_handles[id].used) return NULL;
    return &g_handles[id];
}

static void za_handle_free(int h)
{
    int id = h - 1;
    pthread_mutex_lock(&g_handles_mtx);
    if (id >= 0 && id < ZA_MAX_HANDLES) g_handles[id].used = 0;
    pthread_mutex_unlock(&g_handles_mtx);
}

// ───────────────────────── 工具 ─────────────────────────

static unsigned long long za_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000000000ull + (unsigned long long)ts.tv_nsec;
}

// Switch 的系统计数器（19.2 MHz）。
//
// ⚠ **不能**用 `mrs x0, cntpct_el0` —— 安卓内核不向 EL0 开放这个计数器，
//   这条指令在 Android 上是**非法指令** ⇒ SIGILL（实测崩在 svc #37 里）。
//   改用 CLOCK_MONOTONIC 换算成 19.2 MHz 的刻度，和真机语义保持一致
//   （客机会用 nnosConvertTickToNanoSeconds 按 19200000 的频率换算）。
#define ZA_TICK_HZ 19200000ull
static unsigned long long za_cntpct(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned long long ns = (unsigned long long)ts.tv_sec * 1000000000ull +
                            (unsigned long long)ts.tv_nsec;
    return (ns / 1000000000ull) * ZA_TICK_HZ + (ns % 1000000000ull) * ZA_TICK_HZ / 1000000000ull;
}

// ★ 客机 CNTPCT_EL0 读取的宿主替身：这台设备的内核在 EL0 挡了 CNTPCT
//   （实测 SIGILL，pc=sdk+0x13d9a0 GetSystemTick），za_sdk.c 把 40 处
//   `mrs Xt,CNTPCT_EL0` 换成门区桩经这里取 tick。与 svc#30 同源。
unsigned long long za_host_tick_hook(void)
{
    return za_cntpct();
}

// ───────────────────────── 服务名 ─────────────────────────
static const char *za_svc_name(long nr)
{
    switch (nr)
    {
    case 1:  return "SetHeapSize";
    case 2:  return "SetMemoryPermission";
    case 3:  return "SetMemoryAttribute";
    case 4:  return "MapMemory";
    case 5:  return "UnmapMemory";
    case 6:  return "QueryMemory";
    case 7:  return "ExitProcess";
    case 8:  return "CreateThread";
    case 9:  return "StartThread";
    case 10: return "ExitThread";
    case 11: return "SleepThread";
    case 12: return "GetThreadPriority";
    case 13: return "SetThreadPriority";
    case 14: return "GetThreadCoreMask";
    case 15: return "SetThreadCoreMask";
    case 16: return "GetCurrentProcessorNumber";
    case 17: return "SignalEvent";
    case 18: return "ClearEvent";
    case 19: return "MapSharedMemory";
    case 20: return "UnmapSharedMemory";
    case 21: return "CreateTransferMemory";
    case 22: return "CloseHandle";
    case 23: return "ResetSignal";
    case 24: return "WaitSynchronization";
    case 25: return "CancelSynchronization";
    case 26: return "ArbitrateLock";
    case 27: return "ArbitrateUnlock";
    case 28: return "WaitProcessWideKeyAtomic";
    case 29: return "SignalProcessWideKey";
    case 30: return "GetSystemTick";
    case 31: return "ConnectToNamedPort";
    case 33: return "SendSyncRequest";
    case 34: return "SendSyncRequestWithUserBuffer";
    case 35: return "SendAsyncRequestWithUserBuffer";
    case 37: return "GetThreadId";
    case 38: return "Break";
    case 39: return "OutputDebugString";
    case 41: return "GetInfo";
    case 42: return "FlushEntireDataCache";
    case 44: return "MapPhysicalMemory";
    case 45: return "UnmapPhysicalMemory";
    case 47: return "GetSystemInfo-ish";
    case 52: return "WaitForAddress";
    case 53: return "SignalToAddress";
    case 54: return "SyncToAddress";
    case 75: return "Unknown75";
    case 80: return "Unknown80";
    case 81: return "Unknown81";
    case 82: return "Unknown82";
    default: return NULL;
    }
}

// ───────────────────────── 线程 ─────────────────────────

typedef struct
{
    za_handle_t *h;
    void (*entry)(void *);
    void *arg;
} za_thread_start_t;

static void *za_thread_trampoline(void *p)
{
    // 栈溢出时也要能报出来 ⇒ 给这条线程装备用信号栈
    za_install_altstack();
    za_stack_register_current((long)syscall(SYS_gettid), "svc");
    // ★ 每个客机线程都要有自己的影子 TLS 描述符：mrs 桩内联读 [tp16+0x98]
    //   来算客机 TLS 区；不装的话读到的是 bionic 的 DTV 指针 ⇒ 野地址。
    za_os_install_tls_descriptor();
    // ★★ 2026-10-27：这里原来每线程把**自己的 bionic TP** 写进 [ro+0x1f0]
    //   （当时 RO 页还是全局一张，靠这招防止线程用别人的 TLS）。现在：
    //     · RO 页已经是每线程一份（za_os_install_tls_descriptor 里建）；
    //     · `msr TPIDR_EL0` 的站点全部 NOP 了（za_tlsbase_patch.h），
    //       这个槽不再需要承载真 TP；
    //     · SDK 的 fs 模块反而把它当「本线程 TPIDR」算 `TP-0x18` 做每线程链表头
    //       （sdk+0x98344 → bl 97940）。写回 bionic TP 会让链表头落进 bionic
    //       TCB ⇒ 插入时写坏 TLS/只读页 ⇒ 崩在 libc。
    //   ⇒ 保留 install 时写入的自备 TP 块，这里不再覆盖。
    za_thread_start_t *ts = (za_thread_start_t *)p;
    void (*entry)(void *) = ts->entry;
    ZLOGI("客机线程启动 tid=%ld entry=%p arg=%p", (long)syscall(SYS_gettid),
          (void *)entry, ts->arg);
    void *arg = ts->arg;
    za_handle_t *h = ts->h;
    free(ts);
    if (entry) entry(arg);
    pthread_mutex_lock(&g_handles_mtx);
    if (h) h->exited = 1;
    pthread_cond_broadcast(&g_handle_cond);
    pthread_mutex_unlock(&g_handles_mtx);
    return NULL;
}

// ───────────────────────── 堆 ─────────────────────────
// 堆本体在 za_mem.c（主堆落在「堆区」里，GetInfo 要报同一块）。

// 分配一个「线程句柄」（真机上是 OS 给线程的整数句柄）。
// 主线程的句柄要交给 nnosInitialize —— SDK 把它存进 0xb740128 槽，
// 之后 ThreadManagerImplByHorizon 读它的低 32 位当**临界区 owner_id**。
// ⇒ 必须是**稳定的小整数**（随机堆地址会让 owner_id 的位 29-31 不为 0，
//   临界区的加锁/自旋逻辑会走错分支）。
int za_horizon_alloc_thread_handle(void)
{
    int id = za_handle_alloc(ZA_H_THREAD);
    return id;
}

// ───────────────────────── 主分派 ─────────────────────────
//
// 返回值 = W0（结果码，0 = 成功）。
// 需要回写 x1..x7 的，写进 za_horizon_regs[]，由 trampoline 回写寄存器。
//
long za_horizon_svc(long a0, long a1, long a2, long a3,
                    long a4, long a5, long a6, long a7, long nr);

// 真正的分派体（原来就叫 za_horizon_svc）。出参写回由外层做。
// 当前的「线程 owner id」：SDK 的临界区拿 [只读TLS页 + 0x1f8] + 0x1b0 与之比较，
// 所以我们这里必须用同一个来源（不能另编一个值，否则锁字和判定永远对不上）。
// 只读 TLS 页地址由 za_sdk.c 在装载时填好，这里通过导出变量取。
extern volatile unsigned long za_ro_tls_page;
unsigned long long za_dbg_last_wait;   // 最近一次 WaitForAddress 的地址
// ── 锁字「谁拿走了」的线索 ──────────────────────────────────────────
// 客机侧的 0/1/2 互斥字是纯用户态 CAS，我们看不到谁把它置成 1。
// 唯一能观察到的窗口是 svc#52 的**返回**：返回时锁字非 0 ⇒ 本次调用之后
// 这个线程很可能成了持有者。停摆时据此把「最后几个摸过这把锁的线程」倒出来。
#define ZA_MTX_HIST 32
typedef struct {
    unsigned long long addr;
    long tid;
    unsigned int word;
    unsigned long long ns;
} za_mtx_hist_t;
static za_mtx_hist_t za_mtx_hist[ZA_MTX_HIST];
static volatile unsigned za_mtx_hist_pos;

static void za_mtx_hint(unsigned long long addr)
{
    if (!addr || (addr & 3)) return;
    unsigned int w = __atomic_load_n((const unsigned int *)(uintptr_t)addr, __ATOMIC_RELAXED);
    unsigned p = za_mtx_hist_pos;
    za_mtx_hist_t *h = &za_mtx_hist[p % ZA_MTX_HIST];
    h->addr = addr;
    h->tid = (long)syscall(SYS_gettid);
    h->word = w;
    h->ns = za_now_ns();
    za_mtx_hist_pos = p + 1;
}

// 停摆：把最近摸过 addr 的线程按时间倒序列出。
void za_dump_mtx_hist(unsigned long long addr)
{
    unsigned pos = za_mtx_hist_pos;
    unsigned n = pos < ZA_MTX_HIST ? pos : ZA_MTX_HIST;
    int hit = 0;
    for (unsigned i = 1; i <= n; i++) {
        za_mtx_hist_t *h = &za_mtx_hist[(pos - i) % ZA_MTX_HIST];
        if (h->addr != addr) continue;
        if (hit == 0) ZLOGE("    ↑ svc#52 返回时摸过这把锁的线程（新→旧）：");
        if (hit++ >= 6) break;
        ZLOGE("      tid=%ld word=%#x (+%llums)", h->tid, h->word,
              h->ns ? (za_now_ns() - h->ns) / 1000000ull : 0);
    }
    if (!hit) ZLOGE("    ↑ 近期没有线程在 svc#52 上摸过这把锁");
}
unsigned long long za_dbg_last_phys_addr, za_dbg_last_phys_size;
unsigned long long za_dbg_last_break_info, za_dbg_last_break_size;
static unsigned int za_current_owner_id(void)
{
    unsigned long ro = za_os_tls_ro_area();   // ★ 每线程页（不是全局页）
    // 兜底也必须是「真实 tid」：owner_id 的唯一权威来源就是 svc#37 GetThreadId，
    // 客机加锁时把它的返回值写进锁字，解锁时用 [self+0x1b0] 比。
    unsigned int fallback = (unsigned int)syscall(SYS_gettid);
    if (!fallback) fallback = 1;
    if (!ro) return fallback;
    unsigned long self = 0;
    __builtin_memcpy(&self, (void *)(ro + 0x1f8), 8);
    if (!self) return fallback;
    unsigned int oid = 0;
    __builtin_memcpy(&oid, (void *)(self + 0x1b0), 4);
    return oid ? oid : fallback;
}
// ══════════════════════════════════════════════════════════════════
//
// 客机的 IPC 缓冲区就是它自己的**线程 IPC 缓冲**（TPIDRRO_EL0）。
// 我们把客机里全部 123 处 `mrs Xt,TPIDRRO_EL0` 改写成 `adrp` 指向自建页
// `za_ro_tls_page` ⇒ **这一页就是内核的应答缓冲区**，内核应答必须写回这里。
//
// 客机有两套 IPC 协议：
//  ① 服务管理器 `sm:` / `sm:m` 走 **TIPC**（请求号在 Header0Tag 低 16 位）。
//     实测反汇编（SDK text）：
//       0x153ee0 nn::sm::Initialize  : TLS[0..8]=0x8000_0000_0000_0000,
//                                     TLS[8]=1（SpecialHeader），svc#33 之后
//                                     SDK 读 TLS[8] 要求 == 0（0x153f14/0x153f18）
//       0x154014 nn::sm::GetServiceHandle: TLS[0..8]={0x11,0x02}，
//                                     TLS[8..16]=服务名（8 字节小端打包），
//                                     svc#33 之后 SDK 读
//                                     TLS[0xc]=服务句柄、TLS[0x10]=返回码
//                                     （0x154058 `ldp w8,w0,[x20,#0xc]`）
//  ② 普通服务（fs/bsd/…）走 **CMIF**。请求头 "SFCI"(0x49434653) 写在 TLS+0
//     （0x14eae4），应答头 "SFCO"(0x4F434653) 必须落在**某个 16 字节对齐的槽**
//     上，且该槽 +0x8 的 u32 Result 必须为 0 —— 客机在 0x14eb60 校验：
//         ldr w9,[x8] ; cmp w9,#0x4F434653 ; b.ne → 返回 0x1a80a
//     不匹配 ⇒ 客机 nn::diag::detail::Abort(Result{0x1a80a}) ⇒ 崩溃。
//
//  ⚠ 槽位索引 idx 由客机自己从应答头解出来（0xc4b68 + 0x9a8f0），宿主无法
//    静态预知 ⇒ 把同样的 16 字节 CmifOutHeader 模式填满前 0xf0 字节，
//    无论客机挑哪个槽都能命中。0x1f8 是 SDK 的 `self` 槽，不能碰。

// 我们伪造的服务「句柄」。
// ⚠ 句柄是 **u32**（SDK 读 `ldp w8,w0,[x20,#0xc]`）。
// ★★ 但 SDK 会把它**当成地址**用！实测：句柄 0x7000 时 SDK 直接去读 0x7000
//   ⇒ SIGSEGV(addr=0x7000)。所以它必须是一块**我们自己映射的**可写内存。
// ⚠ 地址必须 ≥ 0x10000：Linux 的 vm.mmap_min_addr 默认 65536，
//   低于它的地址 mmap 会被内核拒绝（实测 0x7000 映射失败）。
// ★ 真机上这个地址是内核按 session 分配的 IPC 共享内存；
//   这里用 SDK 扩展区之外的一块独立映射，每服务 0x400 字节。
#define ZA_FAKE_SVC_BASE 0x10000u   /* 我们伪造的服务句柄基址（应答缓冲） */

typedef struct
{
    const char *name;
    int tipc;   /* 1 = 走 TIPC（sm:m），0 = 走 CMIF */
} za_fake_svc_t;

static const za_fake_svc_t g_fake_svcs[] = {
    { "fs",      0 },
    { "bsd",     0 },
    { "sm:m",    1 },
    { "nwm",     0 },
    { "fssrv",   0 },
    { "sfdnsres",0 },
    { "diag",    0 },
    { "pc",      0 },
    { "wctl",    0 },
    { "lm",      0 },
};
#define ZA_FAKE_SVC_N ((int)(sizeof(g_fake_svcs) / sizeof(g_fake_svcs[0])))

// 名字 → 句柄；不认识的名字也返回一个「通用 CMIF 句柄」，
// 免得 SDK 因为拿到 0 而直接失败。
//
// ⚠ 每个服务名必须给**独立句柄**：SDK 会按句柄缓存每个服务的客户端状态，
//   像 "pctl" / "pctl:s" / "pctl:a" / "pctl:r" 是四个不同的服务，
//   共用一个句柄会让 SDK 把它们当成同一个 ⇒ 内部对象错乱。
static char g_fake_names[64][9];
static unsigned int g_fake_handles[64];
static int g_fake_tipc[64];
static int g_fake_count;

// 名字 → 协议属性（静态表只提供属性，不再隐含句柄索引）
static int za_fake_svc_tipc_by_name(const char *name)
{
    for (int i = 0; i < ZA_FAKE_SVC_N; i++)
        if (strcmp(g_fake_svcs[i].name, name) == 0)
            return g_fake_svcs[i].tipc;
    return 0;   /* 未知服务一律按 CMIF */
}

static unsigned int za_fake_svc_handle(const char *name)
{
    for (int i = 0; i < g_fake_count; i++)
        if (strcmp(g_fake_names[i], name) == 0)
            return g_fake_handles[i];
    if (g_fake_count >= 64)
        return ZA_FAKE_SVC_BASE + 0x100u;
    int idx = g_fake_count++;
    snprintf(g_fake_names[idx], 9, "%s", name);
    /* ★ 每个服务 0x400 字节：SDK 读应答的槽位最大到 +0x3f0，
     *   服务之间不能重叠（否则应答会互相踩）。 */
    g_fake_handles[idx] = ZA_FAKE_SVC_BASE + (unsigned int)idx * 0x400u;
    g_fake_tipc[idx] = za_fake_svc_tipc_by_name(name);
    return g_fake_handles[idx];
}

// 句柄 → 服务名（只用于日志；未知句柄返回 "??"）
static const char *za_fake_svc_name(unsigned int h)
{
    unsigned int i = (h - ZA_FAKE_SVC_BASE) / 0x400u;   /* 每服务 0x400 步进 */
    if (i >= (unsigned int)g_fake_count) return "??";
    return g_fake_names[i];
}

// 句柄 → 是否 TIPC（-1 = 未知句柄）
//
// ⚠ 必须按**名字**查协议，不能拿句柄数值去索引静态表：句柄是按调用顺序动态
//   分配的，数值和 g_fake_svcs 的下标毫无关系。
//   实测踩坑：ectx:aw 拿到 0x7002，静态表 g_fake_svcs[2] 恰好是 "sm:m"（TIPC）
//   ⇒ ectx:aw 被误判成 TIPC ⇒ 没写 "SFCO" 应答头 ⇒ SDK Abort(0x1a80a)。
static int za_fake_svc_is_tipc(unsigned int h)
{
    if (h < ZA_FAKE_SVC_BASE) return -1;
    unsigned int i = (h - ZA_FAKE_SVC_BASE) / 0x400u;   /* 每服务 0x400 步进 */
    if (i == 0x100u) return 0;
    if (i >= (unsigned int)g_fake_count) return -1;
    return g_fake_tipc[i];
}

// 独立（非 applet）标题**根本不存在**的系统服务。
// 我们若给它们返回假句柄，SDK 会以为服务可用，接着解引用一个永远为 NULL 的
// 接口对象 ⇒ SIGSEGV（实测：nn::am = applet manager，服务名 "apm"，
// nn::am::InitializeApplicationInterfaces 在 SDK+0x1c99d4 崩）。
// 正确做法是让 GetServiceHandle **失败**：SDK 会走「服务不存在」的正常分支。
//
// ⚠⚠ 2026-10-25 修正：**"apm" 不能拒**！
//   真机上**每个标题都有 apm（applet manager）服务**，只有 applet 专有的
//   "appletOE" / "ae" 才对独立标题不存在。
//   我们拒掉 apm ⇒ nn::am::GetApplicationFunctions()（SDK+0x1c61c0）返回 NULL
//   ⇒ nn::diag::InitializeApplicationAbortObserver（SDK+0x349e40）在
//      `ldr x8,[x0]` 处解引用 NULL ⇒ SIGSEGV（真机实测 pc=SDK+0x349e64）。
static const char *g_svc_deny[] = {
    "appletOE",   /* applet operation environment（只有 applet 才有） */
    "ae",         /* applet extra（只有 applet 才有） */
};
#define ZA_SVC_DENY_N ((int)(sizeof(g_svc_deny) / sizeof(g_svc_deny[0])))
#define ZA_SVC_NOT_FOUND 0x202u     /* Horizon: 服务名找不到 */

static int za_svc_is_denied(const char *name)
{
    for (int i = 0; i < ZA_SVC_DENY_N; i++)
        if (strcmp(name, g_svc_deny[i]) == 0)
            return 1;
    return 0;
}

// 写 CMIF 应答。
//
// 实测（2026-10-25 真机）得到的客机请求布局（TLS 页，命令缓冲区）：
//     +0x00 Header0Tag  {tag, 0,0,0,0}          例：0x00000007
//     +0x04 Header1Tag  {RawCount, …, bit31=有 SpecialHeader}  例：0x00000008 / 0x8000000e
//     +0x08 …            8 字节（SpecialHeader / ProcessId / 句柄）
//     +0x10 CmifInHeader "SFCI"(0x49434653) / ver=1,resv=0 / MethodId / token
//     +0x20 …            入参
// ⇒ **应答的 CmifOutHeader 必须落在与请求 CmifInHeader 相同的偏移**（16 对齐），
//   客机读应答时 x8 = align_down_16(TLS + idx*4)，idx 由应答头解出。
//
// ⚠ 不能把 "SFCO" 铺满整页：客机 0x14eb3c 有 `ldrh w8,[sp,#0xb2]; cmp w8,#0x41;
//   b.hs trap` 的描述符合法性校验，头写错会直接 trap（第一版就是这么炸的）。
//   所以这里：沿用请求的头，只把 "SFCI" 换成 "SFCO"。
// 安全读一个客机地址（定义在下方）
static int za_h_read_word(unsigned long addr, unsigned long *out);

/* ══════════════════════════════════════════════════════════════════
 *  复刻 SDK 的 CMIF 应答槽位解码（SDK text 0xc4b68 + 0x9a8f0）
 * ══════════════════════════════════════════════════════════════════
 *
 * SDK 读应答（SDK+0x14eb28 起）：
 *   bl 0xc4b68(out, buffer)        ; buffer = TPIDRRO_EL0 = 我们的 ro 页
 *   ldr x8, out[0x00]               ; = ro
 *   ldrb w9, out[0x1f]              ; idx
 *   add x8, x8, x9, lsl #2
 *   add x8, x8, #0xf
 *   and x8, x8, #~0xf               ; 槽位 = align_down_16(ro + idx*4 + 15)
 *   ldr w9, [x8] ; cmp w9, #"SFCO"  ; 不等 → Abort(0x1a80a)
 *
 * 0x9a8f0 的输入是 out[8..0x17]，而 out[8..0x17] 由 0xc4b68 从
 * buffer[0]/buffer[4]/buffer[8] 算出。下面把两段 1:1 复刻，只为拿 idx。
 *
 * ★ 实测校验（真机请求数据）：
 *   请求 A   buffer=07 00 00 00 08 00 00 00 20 00 ⇒ idx=10 ⇒ 槽位 ro+0x30
 *   请求 R3  buffer=06 00 00 00 0e 80 00 00 01 00 ⇒ idx=19 ⇒ 槽位 ro+0x50
 *   （lm::CreateLogServiceByHipc 用的正是 R3 ⇒ 我们以前写 ro+0x10 永远读不到
 *     ⇒ Abort(0x1a80a)。）
 */
static unsigned int za_cmif_slot_offset(const unsigned char *b)
{
    unsigned long long w9 = (unsigned long long)b[0] | ((unsigned long long)b[1] << 8) |
                            ((unsigned long long)b[2] << 16) | ((unsigned long long)b[3] << 24);
    unsigned long long w8 = (unsigned long long)b[4] | ((unsigned long long)b[5] << 8) |
                            ((unsigned long long)b[6] << 16) | ((unsigned long long)b[7] << 24);

    /* --- 0xc4b68 --- */
    unsigned long long x11 = (w9 & 0xffffull) << 32;
    x11 |= (w8 & 0x3fcull) << 2;
    unsigned int w10 = (unsigned int)((w8 >> 10) & 0xf);
    unsigned long long x13 = ((unsigned long long)w10 << 16) + 0xfe0000ull;
    unsigned long long x14 = x11 | 0x1000000ull;
    unsigned long long x12 = x11 | 0x2010000ull;
    x13 = (x11 | x13) | 0x3000000ull;
    x13 = (w10 != 1) ? x13 : x14;
    x12 = (w10 == 2) ? x12 : x13;
    unsigned long long x10 = (w10 == 0) ? x11 : x12;

    unsigned long long x13b = 0, x14b = 0, x11b = 0, x12b = 0;
    if (w8 & 0x80000000ull)
    {
        unsigned long long b8 = (unsigned long long)b[8] | ((unsigned long long)b[9] << 8) |
                               ((unsigned long long)b[10] << 16) | ((unsigned long long)b[11] << 24);
        x12b = b8 & 1ull;
        x13b = ((b8 << 11) & 0xf0000ull) | x12b;
        x14b = (b8 << 7) & 0xf00ull;
        x11b = 0x1000000000000ull;
    }
    unsigned long long x15 = (w9 << 20) & 0xf000000000000ull;
    x15 |= (unsigned long long)((w9 >> 24) & 0xf) << 40;
    unsigned int w17 = ((unsigned int)((w9 >> 8) & 0xf)) & 0xf000000u;
    unsigned long long x9 = x15 | (((w9 >> 20) & 0xf) << 32);
    x13b |= (unsigned long long)w17;
    x13b |= x14b;
    x12b |= x13b;
    x9 |= x12b;

    /* out[8..0x17] —— 0x9a8f0 的输入 */
    unsigned char d[16];
    for (int i = 0; i < 8; i++) d[i] = (unsigned char)(x9 >> (i * 8));
    unsigned long long xm = x11b | x10;
    d[8]  = (unsigned char)(xm);
    d[9]  = (unsigned char)(xm >> 8);
    d[10] = (unsigned char)(xm >> 16);
    d[11] = (unsigned char)(xm >> 24);
    d[12] = (unsigned char)(xm >> 32);
    d[13] = (unsigned char)(xm >> 40);
    d[14] = (unsigned char)(x11b >> 48);
    d[15] = 0;

    /* --- 0x9a8f0 --- */
    unsigned int u8 = (unsigned int)d[8] | ((unsigned int)d[9] << 8);
    if (u8 & 3) return 0x10;               /* 解码失败：退回 ro+0x10 */
    unsigned int w9b = d[0];
    unsigned int w10b = 2 + (unsigned int)((w8 >> 31) & 1);
    w9b = (w9b == 0) ? w10b : (w10b + 2);
    w9b += d[1];
    w9b += d[2];
    unsigned int w11 = (d[3] == 0) ? w9b : (w9b + 2u * d[3]);
    w11 = (d[4] == 0) ? w11 : (w11 + 3u * d[4]);
    w11 = (d[5] == 0) ? w11 : (w11 + 3u * d[5]);
    w11 = (d[6] == 0) ? w11 : (w11 + 3u * d[6]);
    unsigned int idx = (w11 + (u8 >> 2)) & 0xff;
    return (idx * 4u + 0xfu) & ~0xfu;      /* align_down_16(idx*4 + 15) */
}

/* 把「假句柄」那块地址映射出来。
 * ★ SDK 把我们给的假句柄（0x7000+）当作**应答缓冲地址**传回 svc#33 的 a2，
 *   内核（我们）必须能把应答写进那里。
 * ★ 客机与宿主是同一个进程、同一个地址空间 ⇒ 只要 mmap 出来就能写。
 */
static void za_ensure_reply_buf(unsigned long long addr)
{
    static unsigned long long lo = 1, hi = 0;
    if (addr < 0x1000) return;
    if (addr >= lo && addr < hi) return;
    size_t sz = 0x20000;
    void *p = mmap((void *)(uintptr_t)addr, sz, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p == MAP_FAILED)
    {
        ZLOGE("假句柄应答缓冲 %#llx 映射失败", addr);
        return;
    }
    lo = addr; hi = addr + sz;
    ZLOGI("假句柄应答缓冲已映射：%#llx..%#llx", lo, hi);
}

static void za_write_cmif_reply(unsigned long long ro, unsigned long long reply_buf,
                                 unsigned long long out_ptr, unsigned int hdr0, unsigned int hdr1)
{
    /* 取证：把请求的前 0x40 字节打出来 */
    {
        unsigned int w[16];
        for (int i = 0; i < 16; i++)
            memcpy(&w[i], (const void *)(uintptr_t)(ro + (unsigned long long)(i * 4)), 4);
        ZLOGI("    req[0..0x40]=%08x %08x %08x %08x | %08x %08x %08x %08x | %08x %08x %08x %08x | %08x %08x %08x %08x",
              w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7],
              w[8], w[9], w[10], w[11], w[12], w[13], w[14], w[15]);
    }

    /* 取证（首次）：把整页前 0x100 字节 dump 出来，确定
     *   ① SDK 把请求写在哪些槽位
     *   ② SDK 从哪个槽位读应答（槽位 = align_down_16(buffer + idx*4 + 0xf)，
     *      idx 由 0x9a8f0 从 buffer[0..0xa] 解出，不是固定 +0x10）
     */
    static int dumped = 0;
    if (!dumped)
    {
        dumped = 1;
        for (unsigned int base = 0; base < 0x100; base += 0x20)
        {
            unsigned int w[8];
            for (int i = 0; i < 8; i++)
                memcpy(&w[i], (const void *)(uintptr_t)(ro + base + (unsigned long long)(i * 4)), 4);
            ZLOGI("    PAGE[%#05x]=%08x %08x %08x %08x %08x %08x %08x %08x",
                  base, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
        }

        /* 取证（首次）：ro2 页 = SDK基址 + 0xf01000。
         * ★ 请求里反复出现 {0x00f01000, 0x00000002}，这就是 Horizon CMIF 的
         *   「间接传参」对：(数据区偏移, 长度) ⇒ 真正的数据交换发生在这一页。
         */
        if (za_sdk_base)
        {
            unsigned long long ro2 = (unsigned long long)za_sdk_base + 0xf01000ul;
            for (unsigned int base = 0; base < 0x100; base += 0x20)
            {
                unsigned int w[8];
                for (int i = 0; i < 8; i++)
                    memcpy(&w[i], (const void *)(uintptr_t)(ro2 + base + (unsigned long long)(i * 4)), 4);
                ZLOGI("    RO2  [%#05x]=%08x %08x %08x %08x %08x %08x %08x %08x",
                      base, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
            }
        }

        /* 探测「出参/间接数据区」的真实地址。
         * ★ 请求入参 = {0x00f01000, 2} ⇒ 服务端应从「某基址 + 0xf01000」读 2 个 u32，
         *   而 SDK 已经把入参写在那儿了 ⇒ 哪个候选能读到非零，就是它。
         * 全部用 process_vm_readv 安全读，未映射页不会崩。
         */
        {
            struct { unsigned long long base; const char *what; } cand[] = {
                { (unsigned long long)za_sdk_base + 0x0f00000ull, "SDK基址+0xf00000 (=TPIDRRO页/ro)" },
                { (unsigned long long)za_sdk_base + 0x0f01000ull, "SDK基址+0xf01000 (RO2页)" },
                { (unsigned long long)za_sdk_base + 0x1ef01000ull, "SDK基址+0x1ef01000 (ro+0xf01000)" },
                { (unsigned long long)za_sdk_base + 0x1ef00000ull, "SDK基址+0x1ef00000 (ro)" },
            };
            for (unsigned i = 0; i < sizeof cand / sizeof cand[0]; i++)
            {
                unsigned long w[16];
                int ok = 1;
                for (int k = 0; k < 16; k++)
                    if (!za_h_read_word(cand[i].base + (unsigned long)(k * 4), &w[k])) { ok = 0; break; }
                if (!ok) { ZLOGI("    CAND %s: 不可读", cand[i].what); continue; }
                ZLOGI("    CAND %s:", cand[i].what);
                for (int k = 0; k < 16; k += 4)
                    ZLOGI("        +%#04x: %08lx %08lx %08lx %08lx",
                          k * 4, w[k], w[k + 1], w[k + 2], w[k + 3]);
            }
        }
    }

    /* ── 找应答槽位 ────────────────────────────────────────────────
     *
     * ★ 协议（静态逆向 SDK+0x10be2c 路径 B / SDK+0x14eb28 路径 A 确认）：
     *   应答槽 = align16(应答缓冲 + idx*4 + 15)，idx 由**应答头**算出。
     *   槽内字段：
     *     路径 B（魔数在槽+0x10）：槽+0x10="SFCO"、槽+0x18=Result(必须0)、槽+0x20=token
     *     路径 A（魔数在槽+0x00）：槽+0x00="SFCO"、槽+0x08=Result(必须0)、槽+0x10=u16 返回值
     *   统一律：**SFCO 魔数的落点 == 请求侧 SFCI 魔数的落点**
     *   ⇒ 两条路径都写成「SFCI 位置 + 0x00 = "SFCO"、+0x08 = 0、+0x10 = token」。
     */
    unsigned int cmif_off = 0;
    for (unsigned int off = 0; off < 0x100; off += 4)
    {
        unsigned int w;
        memcpy(&w, (const void *)(uintptr_t)(ro + (unsigned long long)off), 4);
        if (w == 0x49434653u) { cmif_off = off; break; }
    }
    if (!cmif_off)
    {
        /* 没找到 SFCI ⇒ SDK 这次**没有重写魔数**（实测：time:u 的 cmd=0x2 那次，
         * 请求里 [0x20] 还是我们上次写的 "SFCO"）⇒ 沿用上次应答的 "SFCO" 位置。 */
        for (unsigned int off = 0; off < 0x100; off += 4)
        {
            unsigned int w;
            memcpy(&w, (const void *)(uintptr_t)(ro + (unsigned long long)off), 4);
            if (w == 0x4f434653u) { cmif_off = off; break; }
        }
        if (cmif_off)
            ZLOGI("    请求里没有 SFCI（SDK 未重写魔数），沿用上次应答槽位 TLS+%#x", cmif_off);
    }
    ZLOGI("    请求里 SFCI @TLS+%#x（应答就写在这里）", cmif_off);

    /* ★★★ 应答写到「服务自己的共享内存」★★★
     *
     * svc#33 的原始参数（实测 2026-10-25 真机）：
     *   TIPC(sm:) : a0=0x1 a1=0x200b9c59c(请求缓冲) a2=0x200b3b2b8(**应答缓冲**) a3=0x200bebdb0
     *   CMIF(lm)  : a0=0x7000 a1=0x200f00000(ro,请求缓冲) a2=0x7000(**应答缓冲**) a3=0x7000
     *
     * ★★ a2 在真机上就是这个服务的**共享内存地址**（内核按 session 分配），
     *   SDK 把它当「应答缓冲区」用。我们返回的假句柄被 SDK 直接当成地址传下来了
     *   ⇒ 只要让**句柄本身是一个真实可写的地址**，SDK 就会从那里读我们的应答！
     *
     * ⇒ 做法：句柄 = SDK基址 + 0x1100000（扩展区里一块专用页），
     *   应答写到 SDK基址 + 0x1100000 + 槽位偏移。
     */
    {
        /* ★★★ 应答写回 **IPC 缓冲（请求缓冲本身）** ★★★
         *
         * SDK 的 SFCO 校验（SDK+0x14eb28 / +0x10be2c，真机实测）：
         *     bl 0xc4b68(out, buffer)     ; out[0x00] = buffer（= ro 页），out[0x1f] = idx
         *     ldr  x8, [out[0x00]]        ; base = buffer
         *     ldrb w9, [out[0x1f]]       ; idx
         *     add  x8, x8, x9, lsl #2
         *     add  x8, x8, #0xf
         *     and  x8, x8, #0xfffffffffffffff0   ; 槽位 = align16(buffer + idx*4 + 15)
         *     ldr  w9, [x8]               ; ★ 槽位+0 必须 == "SFCO"
         *     cmp  w9, #"SFCO" ; b.ne → Abort(0x1a80a)
         *     ldr  w0, [x8, #0x8]         ; 槽位+8 = IPC 结果码（必须 0）
         *     ldrh w8, [x8, #0x10]        ; 槽位+0x10 = 命令返回（u16）
         *
         * ⇒ 请求与应答**共用同一块 IPC 缓冲、同一个槽位**：SDK 把请求头
         *   （"SFCI"）写在槽位上，内核把应答头（"SFCO"）写回**同一位置**。
         *   两条校验路径都印证这一点：
         *     路径 A（SDK+0x14eb28）：查 槽位+0            ⇒ 槽位 = SFCI 位置
         *     路径 B（SDK+0x10be2c）：查 槽位+0x10         ⇒ 槽位 = SFCI 位置 − 0x10
         *   ⇒ 结论：**SFCO 必须写在 "SFCI" 所在的位置**。
         *   我们以前固定写 +0x10 ⇒ 请求位置一变就错位 ⇒ Abort(0x1a80a)。
         *
         * 实测：请求头 = 07 00 00 00 08 00 00 00 20 00 时 SFCI 在 ro+0x10；
         *       另一个请求（06 00 00 00 0e 80 00 00 01 00）SFCI 在 ro+0x30。
         */
        unsigned int slot = cmif_off;   /* ★ SFCO 必须与 SFCI 同槽位 */
        if (slot == 0 || slot > 0x100) slot = za_cmif_slot_offset((const unsigned char *)(uintptr_t)ro);
        if (slot < 0x10 || slot > 0x800) slot = 0x10;   /* 解码异常时退回旧位置 */

        /* ★★★ a4：**绝对不能写** ★★★
         *
         * 2026-10-25 真机实测（反汇编 SDK+0x10be2c，nn::hipc 的派发函数）：
         *     mov  x19, x4            ; a4 = 一个 Object** 槽（不是出参缓冲）
         *     ldr  x0, [x19]          ; x0 = *a4 ← SDK 刚建好的 IPC 对象指针
         *     cbz  w23, <无出参分支> ; w23 = SFCO 槽 +0x20 的类型码
         *     str  xzr, [x19]        ; ← SDK **自己**把 *a4 清零
         *
         * ⇒ 内核（我们）**从不**往 a4 写任何东西；a4 是 SDK 调用方的局部变量。
         *   我们以前往这里塞占位 {0x0000000100000001, 0}，正好把 SDK 刚建好的
         *   IPC 对象指针顶掉 ⇒ SDK 拿 0x100000001 当对象解引用：
         *     ldr x8,[0x100000001] → 读到 main 映像头部（+1 处 8 字节）
         *                          → 0x7c02fc8048000000
         *     ldr x8,[x8,#8]       → 野指针 ⇒ SIGSEGV（pc=sdk+0x3c46a8）
         *
         * 出参**不在** a4，也不在应答缓冲里的一段数据：
         * SDK 在发请求**之前**就预建好 56 字节的 CmifProxy 出参代理对象
         * （SDK+0x3fcf58），应答里只用「SFCO 槽 +0x18 = Result」和
         * 「+0x20 = token」两个字段决定它是否被激活。
         *   token == 0 ⇒ SDK 走「无出参」分支，自己把出参指针清 0
         *              ⇒ 全局 SDK+0xc024b8 = NULL ⇒ 下次 SDK+0x3fcbf4 崩
         *   token != 0 ⇒ 出参代理被激活并交付出参指针
         * 所以这里必须写一个非 0 的 token（见下面）。
         */
        ZLOGI("    a4=%#llx（不写：这是 SDK 的 Object** 槽，内核不碰它）", out_ptr);

        /* 应答内容（写在 SFCI 的位置）：
         *   +0x00 "SFCO"    +0x04 保留     +0x08 IPC Result（必须 0）
         *   +0x0c 保留       +0x10 token（路径 B）/ 命令返回 u16（路径 A）
         * ★ 路径 A（SDK+0x14eb28）读 槽位+0 / +0x8 / +0x10；
         *   路径 B（SDK+0x10be2c）读 槽位+0x10 / +0x18 / +0x20，
         *   而路径 B 的槽位 = SFCI 位置 − 0x10 ⇒ 两条路径要求的字段完全一致。
         *
         * ★★ token（+0x10）必须非 0（SDK+0x10bf98 `cbz w23, <无出参分支>`）：
         *   token == 0 ⇒ SDK 走「无出参」分支 ⇒ 它自己把出参指针清 0
         *   ⇒ SDK+0x3fcaac 把 NULL 写进全局 SDK+0xc024b8
         *   ⇒ 下一次 SDK+0x3fcbf4 对 NULL 解引用 ⇒ SIGSEGV（真机实测）。
         *   SDK 不校验 token 的值，只把它原样回填进下一次请求的 SFCI+0x04，
         *   所以我们自己编一个递增的就行。
         */
        unsigned char hdr[0x20];
        memset(hdr, 0, sizeof hdr);
        memcpy(hdr + 0x00, "SFCO", 4);

        /* ── 路径判定 ────────────────────────────────────────────────
         * 路径 B（普通命令 / 取子对象）的请求描述符在 **SFCI 位置前 0x10**：
         *   描述符 slot+0x00 = 0x00180001（取子对象）或 0x00100001（普通命令），
         *   描述符 slot+0x10 = "SFCI"。
         * 路径 A 的描述符在 **SFCI 位置后 0x10**（slot+0x00 = SFCO、slot+0x08 = Result、
         *   slot+0x10 = u16 命令返回）。
         *
         * 实测对照（真机日志）：
         *   cmd=0x7 hdr0=7 hdr1=8  ⇒ SFCI@0x10、[0x00]=7      ⇒ 路径 A
         *   cmd=0x6 hdr0=6 hdr1=0xc ⇒ SFCI@0x20、[0x10]=0x00100001 ⇒ 路径 B
         */
        int path_b = 0;
        if (cmif_off >= 0x10)
        {
            unsigned int w = 0;
            memcpy(&w, (const void *)(uintptr_t)(ro + (unsigned long long)cmif_off - 0x10), 4);
            if (w == 0x00180001u || w == 0x00100001u) path_b = 1;
        }

        /* token（路径 B 的槽+0x20 = SFCI 位置 + 0x10）必须非 0；
         * 路径 A 的同一位置是「u16 命令返回」，应当是 0。 */
        if (path_b)
        {
            static unsigned int g_cmif_token = 1;
            unsigned int token = ++g_cmif_token;
            if (!token) token = ++g_cmif_token;     /* 0 是保留值，绕开 */
            memcpy(hdr + 0x10, &token, 4);
        }

        /* ★ 写回 IPC 缓冲的槽位（SDK 校验的就是这里）*/
        memcpy((void *)(uintptr_t)((unsigned long long)ro + slot), hdr, sizeof hdr);

        /* 共享内存（svc#33 的 a2 = 假句柄当地址用）里也放一份：
         *   - 同一相对偏移（rb 的头被清零 ⇒ 那边的 idx 恒为 2 ⇒ 落在 rb+0x10）
         *   - 两个位置都写，成本为零，纯保险 */
        {
            unsigned long long rb = reply_buf ? reply_buf : ro;
            if (rb < 0x1000) rb = ro;          /* 明显不是有效地址时退回 ro */
            za_ensure_reply_buf(rb);
            memcpy((void *)(uintptr_t)(rb + slot), hdr, sizeof hdr);
            memcpy((void *)(uintptr_t)(rb + 0x10), hdr, sizeof hdr);
            ZLOGI("    应答: ro=%#llx 槽位=%#x（\"SFCO\" @ro+槽位），共享内存 rb=%#llx",
                  ro, slot, rb);
        }
    }
}

// 安全读一个客机地址（客机地址空间我们自己映射的，直接读也可能踩未映射页，
// 所以走 process_vm_readv，失败就返回 0）
static int za_h_read_word(unsigned long addr, unsigned long *out)
{
    struct iovec local, remote;
    local.iov_base = out;
    local.iov_len = sizeof *out;
    remote.iov_base = (void *)(uintptr_t)addr;
    remote.iov_len = sizeof *out;
    ssize_t n = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    return n == (ssize_t)sizeof *out;
}

// 把客机地址换算成 "sdk+0x…" / "main+0x…"
static const char *za_h_addrstr(unsigned long a)
{
    static char buf[4][64];
    static int turn;
    char *p = buf[turn = (turn + 1) & 3];
    unsigned long sb = za_sdk_base, ss = za_sdk_size;
    if (sb && a >= sb && a < sb + ss)
    {
        snprintf(p, 64, "sdk+%#lx", a - sb);
        return p;
    }
    if (za_guest_base && a >= (unsigned long)za_guest_base &&
        a < (unsigned long)za_guest_base + ZA_IMAGE_SIZE)
    {
        snprintf(p, 64, "main+%#lx", a - (unsigned long)za_guest_base);
        return p;
    }
    snprintf(p, 64, "%#lx", a);
    return p;
}

static long za_horizon_dispatch(long a0, long a1, long a2, long a3,
                                long a4, long a5, long a6, long a7, long nr)
{
    // 先把入参原样放进回写数组（不改的话也要保持原值）
    za_horizon_regs[ZA_REG_X1] = (unsigned long)a1;
    za_horizon_regs[ZA_REG_X2] = (unsigned long)a2;
    za_horizon_regs[ZA_REG_X3] = (unsigned long)a3;
    za_horizon_regs[ZA_REG_X4] = (unsigned long)a4;
    za_horizon_regs[ZA_REG_X5] = (unsigned long)a5;
    za_horizon_regs[ZA_REG_X6] = (unsigned long)a6;
    za_horizon_regs[ZA_REG_X7] = (unsigned long)a7;

    const char *nm = za_svc_name(nr);
    unsigned long pc = za_horizon_regs[ZA_REG_PC];
    (void)nm;   // 详细日志关着时用不到
    (void)pc;
    // 计数总是做（代价 = 一次加法），供看门狗汇总。
    za_svc_count(nr);
    // ⚠ 逐条打印只在「详细日志」打开时做。客机每秒几十万次 svc，
    //   逐条打会瞬间刷爆 logcat，客机线程全耗在 liblog 里（还把 liblog 搞崩）。
    if (za_verbose_is_on())
    {
        ZLOGI("Horizon svc #%ld %s（调用点=%#lx a0=%#lx a1=%#lx a2=%#lx a3=%#lx）",
              nr, nm ? nm : "?", pc, (unsigned long)a0, (unsigned long)a1,
              (unsigned long)a2, (unsigned long)a3);
        // 把「调用点」附近的实际机器码打出来（运行中的映像，可能和我们改写过的不一样）
        if (za_sdk_base && pc >= za_sdk_base && pc < za_sdk_base + za_sdk_size)
        {
            unsigned long off = pc - za_sdk_base;
            const unsigned int *w = (const unsigned int *)(uintptr_t)(za_sdk_base + off - 4);
            ZLOGI("  调用点机器码（sdk+%#lx）：%08x %08x %08x %08x",
                  off - 4, w[0], w[1], w[2], w[3]);
        }
    }
    // SDK 初始化会抢走我们的 SIGSEGV 处理器 ⇒ 定期装回来，
    // 不然客机崩了没人接（进程被内核静默杀掉，连日志都没有）。
    // 限频：每 128 次装一次就够（抢处理器只发生在 SDK 初始化阶段）。
    if ((++za_svc_seq & 127u) == 0) za_reinstall_signal_handlers();

    switch (nr)
    {
    // ── 内存 ──
    case 1: // SetHeapSize(out_base=x0, size=x1) → W1 = 堆基址
    {
        unsigned char *b = za_mem_heap_ensure((size_t)a1);
        ZLOGI("svc#1 SetHeapSize size=%#lx -> base=%p%s", a1, (void *)b,
              b ? "" : "（失败！ CentralHeap::Init 会 abort）");
        if (!b) return 1;
        if (a0) *(unsigned long long *)(uintptr_t)a0 = (unsigned long long)(uintptr_t)b;
        za_horizon_regs[ZA_REG_X1] = (unsigned long)(uintptr_t)b;
        return 0;
    }
    case 2: // SetMemoryPermission(addr=x0, size=x1, perm=w2)
    {
        // ⚠ 不真的 mprotect：Switch 上这里是把 .data.rel.ro / GOT 变成只读，
        // 但我们宿主这边 .data 是整段 RW，客机后面还会往里写全局变量。
        // 真收紧权限会造成「客机写全局变量 ⇒ SIGSEGV」的假崩溃。
        // 先只记录，等确认客机不再写这块再考虑收紧。
        return 0;
    }
    case 3: // SetMemoryAttribute(addr=x0, size=x1, mask=w2, attr=w3)
        return 0;
    case 4: // MapMemory(dst=x0, src=x1, size=x2)
    {
        // 客机建线程时用它把「堆上的栈」搬进栈区 —— 不实现的话栈还是留在堆上，
        // 客机的线程栈分配器会一直找不到合适的地方。
        return (long)za_mem_map_memory((unsigned long long)a0,
                                       (unsigned long long)a1,
                                       (unsigned long long)a2);
    }
    case 5: // UnmapMemory(dst=x0, src=x1, size=x2)
    {
        return (long)za_mem_unmap_memory((unsigned long long)a0,
                                         (unsigned long long)a1,
                                         (unsigned long long)a2);
    }
    case 6: // QueryMemory(MemoryInfo* out=x0, PageInfo* pout=x1, addr=x2)
    {
        // ⚠ *x0 是 **MemoryInfo 结构**（base/size/state/attr/perm），
        //   客机的包装函数只把 W1 写进 *x1（PageInfo），MemoryInfo 得我们自己填。
        //   以前这里把 *x0 全写 0 ⇒ SDK 看到的自由区大小永远是 0 ⇒
        //   它的地址空间分配器找不到空位，空转 100 万次 ⇒ 客机线程栈溢出。
        //
        // ⚠⚠ 结构只有 0x24 字节（照 d2r-and 的口径：base@0 size@8
        //   state@0x10 attr@0x14 perm@0x18 再加两个 u32）。
        //   我们之前 memcpy 了 72 字节 ⇒ **把客机栈上紧跟着的 PageInfo
        //   和其它局部变量全踩烂了** ⇒ 客机跳空。
        unsigned long long mi[5];
        mi[0] = mi[1] = 0;
        unsigned long long pageinfo = za_mem_query_memory((unsigned long long)a2, mi);
        if (a0) memcpy((void *)(uintptr_t)a0, mi, 0x24);
        // 记录每次 QueryMemory 的查询地址与结果 —— 客机拿到的 MemoryInfo 一旦不对，
        // 后面用它的 base/size 去建对象就会跳空（pc=0），这里是最直接的证据。
        {
            static unsigned qn;
            if (qn < 40)
            {
                qn++;
                ZLOGI("svc#6 QueryMemory addr=%#llx -> base=%#llx size=%#llx state=%#x perm=%#x "
                      "(out=%p)",
                      (unsigned long long)a2, mi[0], mi[1],
                      ((unsigned int *)mi)[4], ((unsigned int *)mi)[6], (void *)(uintptr_t)a0);
            }
        }
        za_horizon_regs[ZA_REG_X1] = (unsigned long)pageinfo;
        // ★ 2026-10-25：SDK 的 os 上下文构造（sdk+0x145af8）这样用 svc#6：
        //     sub  x0, x29, #0x28      ← MemoryInfo（栈上）
        //     bl   svc#6
        //     cbnz w0, <abort>          ← **返回值必须为 0**
        //     ldur w8, [x29, #-0x10]    ← MemoryInfo+0x18 = **perm**
        //     cmp  w8, #0x3             ← **perm 必须是 3（读写）**
        //     b.ne <abort>
        //   abort 路径是 `mov x0..x3,xzr; bl AbortImpl` ⇒ 崩在 pc=0。
        //   我们的 svc 门只写回 x1..x7，**x0 直接用 C 返回值** ⇒ 必须显式清 0。
        za_horizon_regs[ZA_REG_X0] = 0;
        if (za_verbose_is_on())
            ZLOGI("svc#6 返回：x0=0 perm=%#x state=%#x size=%#llx",
                  ((unsigned int *)mi)[6], ((unsigned int *)mi)[4], mi[1]);
        return 0;
    }
    case 44: // MapPhysicalMemory(addr=x0, size=x1)
    case 45: // UnmapPhysicalMemory(addr=x0, size=x1)
        if (nr == 44) { za_dbg_last_phys_addr = (unsigned long long)a0;
                        za_dbg_last_phys_size = (unsigned long long)a1; }
        ZLOGI("svc#%ld MapPhys addr=%#lx size=%#lx (pc=sdk+%#lx)", nr,
              (unsigned long)a0, (unsigned long)a1,
              (unsigned long)(za_horizon_regs[ZA_REG_PC] - (unsigned long)za_sdk_base));
    {
        // ★ 必须真映射（2026-10-25 实测）：客机在 nn::os::detail::VammManager /
        //   TransferMemoryImplByHorizon::MapImpl 里要 svc#44 把 0x410000000 这类
        //   「alias 区」页面映射出来（调用点 SDK+0x14242c：`mov x0,x1; mov w1,#0x1000;
        //   bl svc#44`），然后往里写图案（SDK+0x10ff78 `str x10,[x20]`）。
        //   我们以前直接 return 0（假成功）⇒ 客机随后写未映射地址 ⇒ SIGSEGV。
        //   参考成品 d2r-android 同样只允许 alias 区并真做 mprotect。
        unsigned long addr = (unsigned long)a0;
        unsigned long size = (unsigned long)a1;
        if (!addr || !size)
        {
            ZLOGI("svc#%ld Map/Unmap 参数为空 addr=%#lx size=%#lx", nr, addr, size);
            return 0;
        }
        // ★ 只允许动**我们预留区**里的地址。客机偶尔会给出区外的地址
        //   （野指针 / 我们报给它的地址空间与实际预留不一致），那时 mprotect
        //   会打到 ART/libc 的映射上 —— 宿主随后必崩，而且现场完全指不到我们。
        if (!za_mem_owns(addr, size))
        {
            static int nbad;
            if (nbad++ < 12)
                ZLOGE("svc#%ld 拒绝：addr=%#lx size=%#lx 不在预留区内（不动宿主映射）",
                      nr, addr, size);
            return (long)0xD401;
        }
        if (nr == 44)
        {
            /* 已映射就只改权限；没映射就真 mmap 到这个地址。
             * ★ 12GB 的系统资源块会落在声明 ASLR 区里实际预留之外的地方，
             *   mmap 必须带 MAP_NORESERVE（否则 12GB commit 直接 ENOMEM），
             *   页面按需落地。 */
            void *p = mmap((void *)addr, size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
            if (p == MAP_FAILED)
            {
                /* 已经有人占了这段地址（EEXIST）⇒ 只放开权限 */
                if (mprotect((void *)addr, size, PROT_READ | PROT_WRITE) != 0)
                {
                    ZLOGI("svc#44 映射 %#lx+%#lx 失败 errno=%d", addr, size, errno);
                    return (long)0xD401;   /* 越界/失败码 */
                }
            }
            za_mem_note_mapping(addr, size, 1);
            ZLOGI("svc#44 MapPhysicalMemory %#lx+%#lx -> ok", addr, size);
        }
        else
        {
            /* 只收回权限，不 munmap（这段可能与宿主其它映射共享） */
            if (mprotect((void *)addr, size, PROT_NONE) != 0)
                ZLOGI("svc#45 解除权限 %#lx+%#lx 失败 errno=%d", addr, size, errno);
            za_mem_note_mapping(addr, size, 0);
            ZLOGI("svc#45 UnmapPhysicalMemory %#lx+%#lx -> ok", addr, size);
        }
        return 0;
    }
    case 42: // FlushEntireDataCache
    case 43: // FlushDataCache(addr=x0, size=x1)
        return 0;

    // ── 进程 ──
    case 7: // ExitProcess
        ZLOGI("Horizon: ExitProcess —— 客机要退出");
        return 0;

    // ── 线程 ──
    case 8: // CreateThread(out_handle=x0, entry=x1, arg=x2, stack_bottom=x3, prio=w4, core=w5)
    {
        int id = za_handle_alloc(ZA_H_THREAD);
        __atomic_add_fetch(&za_thread_created, 1, __ATOMIC_RELAXED);
        ZLOGI("svc#8 CreateThread: out=%#lx entry=%#lx arg=%#lx stack=%#lx prio=%ld core=%ld -> handle=%d",
              (unsigned long)a0, (unsigned long)a1, (unsigned long)a2, (unsigned long)a3,
              (long)a4, (long)a5, id);
        if (id <= 0) return 1;
        za_handle_t *h = za_handle_get(id);
        h->entry = (void (*)(void *))(uintptr_t)a1;
        h->arg = (void *)(uintptr_t)a2;
        // 栈：客机只给了 stack_bottom（栈底），没给大小。
        // ⚠ 必须给够大：SDK 的异步工作线程（nn::async::ExecutionScheduler）会在这上面
        //   跑 C++ 代码，1MB 直接栈溢出 ⇒ 进程被 SIGSEGV 静默杀掉（连处理器都跑不起来）。
        // 栈要落在**栈区**里（GetInfo 的 I_StackAddr/I_StackSize 报的就是它），
        // 否则 SDK 的 AddressSpaceAllocator 和我们的分配器口径不一致。
        size_t ssz = 16u << 20;
        h->stack_size = ssz;
        h->stack = za_mem_stack_alloc(ssz);
        if (!h->stack)
        {
            h->stack = (unsigned char *)mmap(NULL, ssz, PROT_READ | PROT_WRITE,
                                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (h->stack == MAP_FAILED) h->stack = NULL;
        }
        if (a0) *(unsigned int *)(uintptr_t)a0 = (unsigned int)id;
        za_horizon_regs[ZA_REG_X1] = (unsigned long)(unsigned int)id;
        // ★ 不再在这里 pthread_create：Horizon 的 svcCreateThread 只创建、不启动，
        //   SDK 的 nn::os::StartThread 之后才调 svcStartThread。
        //   （以前在这里直接启动 ⇒ SDK 的 ThreadType 状态机没跑，看起来「能跑」，
        //     但 SDK 自己的线程入口/临界区读到的 ThreadType 是未初始化的，
        //     实测会在新线程里走 nn::diag abort（无消息）然后自旋。）
        ZLOGI("Horizon: CreateThread handle=%d entry=%#lx arg=%#lx（栈 %zu 字节，待 StartThread）",
              id, (unsigned long)a1, (unsigned long)a2, ssz);
        return 0;
    }
    case 9: // StartThread(handle=x0)
    {
        za_handle_t *h = za_handle_get((int)a0);
        if (!h || h->type != ZA_H_THREAD) return 1;
        if (h->started) return 0;
        h->started = 1;
        __atomic_add_fetch(&za_thread_started, 1, __ATOMIC_RELAXED);
        za_thread_start_t *ts = (za_thread_start_t *)malloc(sizeof *ts);
        if (!ts) return 1;
        ts->h = h;
        ts->entry = h->entry;
        ts->arg = h->arg;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        if (h->stack) pthread_attr_setstack(&attr, h->stack, h->stack_size);
        pthread_t tid;
        int rc = pthread_create(&tid, &attr, za_thread_trampoline, ts);
        pthread_attr_destroy(&attr);
        if (rc != 0) { free(ts); return 1; }
        h->tid = tid;
        ZLOGI("Horizon: StartThread handle=%d tid=%lu", (int)a0, (unsigned long)tid);
        return 0;
    }
    case 10: // ExitThread
    {
        za_handle_t *h = NULL;
        pthread_mutex_lock(&g_handles_mtx);
        for (int i = 0; i < ZA_MAX_HANDLES; i++)
            if (g_handles[i].used && g_handles[i].type == ZA_H_THREAD &&
                g_handles[i].started && pthread_equal(g_handles[i].tid, pthread_self()))
            { h = &g_handles[i]; break; }
        if (h) h->exited = 1;
        pthread_cond_broadcast(&g_handle_cond);
        pthread_mutex_unlock(&g_handles_mtx);
        return 0;   // 真正退出由 trampoline 的 return 处理
    }
    case 11: // SleepThread(ns=x0)
    {
        struct timespec ts;
        ts.tv_sec = (time_t)(a0 / 1000000000L);
        ts.tv_nsec = (long)(a0 % 1000000000L);
        nanosleep(&ts, NULL);
        return 0;
    }
    case 12: // GetThreadPriority(out_prio=x0, handle=x1) → W1
    {
        unsigned int prio = 0x1000;   // Horizon 默认优先级
        za_horizon_regs[ZA_REG_X1] = prio;
        if (a0) *(unsigned int *)(uintptr_t)a0 = prio;
        return 0;
    }
    case 13: // SetThreadPriority(handle=x0, prio=w1)
        return 0;
    case 14: // GetThreadCoreMask(out_core=x0, out_mask=x1, handle=w2) → W1,W2
    {
        za_horizon_regs[ZA_REG_X1] = 0;
        za_horizon_regs[ZA_REG_X2] = 1;
        if (a0) *(unsigned int *)(uintptr_t)a0 = 0;
        if (a1) *(unsigned long long *)(uintptr_t)a1 = 1;
        return 0;
    }
    case 15: // SetThreadCoreMask(handle=x0, mask=x1)
    case 16: // GetCurrentProcessorNumber
    {
        za_horizon_regs[ZA_REG_X0] = 0;
        return 0;
    }
    case 37: // GetThreadId(out_id=x0, handle=x1) → x1（64 位）
    {
        // ⚠ 必须返回**稳定**的线程 id：客机把它存进线程对象，
        //   之后每次进临界区都比对 (锁字 & 0xbfffffff) == owner_id。
        //   之前这里返回的是「每次都变的计数器」⇒ 客机永远对不上 ⇒ 死循环。
        //   用真实的 Linux tid：一条线程一个值，跨调用不变。
        unsigned long long tid = (unsigned long long)syscall(SYS_gettid);
        za_horizon_regs[ZA_REG_X1] = (unsigned long)tid;
        if (a0) *(unsigned long long *)(uintptr_t)a0 = tid;
        return 0;
    }

    // ── 事件 / 同步 ──
    case 17: // SignalEvent(handle=x0)
    {
        pthread_mutex_lock(&g_handles_mtx);
        za_handle_t *h = za_handle_get((int)a0);
        if (h) { h->signaled = 1; pthread_cond_broadcast(&g_handle_cond); }
        pthread_mutex_unlock(&g_handles_mtx);
        return 0;
    }
    case 18: // ClearEvent(handle=x0)
    {
        pthread_mutex_lock(&g_handles_mtx);
        za_handle_t *h = za_handle_get((int)a0);
        if (h) h->signaled = 0;
        pthread_mutex_unlock(&g_handles_mtx);
        return 0;
    }
    case 23: // ResetSignal(handle=x0)
        return 0;
    case 24: // WaitSynchronization(out_index=x0, handles=x1, num=w2, timeout=x3) → W1
    {
        int num = (int)a2;
        const unsigned int *hs = (const unsigned int *)(uintptr_t)a1;
        long long timeout = a3;      // 纳秒，-1 = 无限
        unsigned long long deadline = timeout >= 0 ? za_now_ns() + (unsigned long long)timeout : 0;
        int idx = -1;
        unsigned long long last_log = 0;
        pthread_mutex_lock(&g_handles_mtx);
        for (;;)
        {
            for (int i = 0; i < num; i++)
            {
                za_handle_t *h = za_handle_get((int)hs[i]);
                if (!h) continue;
                if (h->type == ZA_H_EVENT ? h->signaled : h->exited) { idx = i; break; }
            }
            if (idx >= 0) break;
            if (timeout == 0) break;              // 不等待
            // ★ 诊断：无限等待时每 2 秒把「到底在等谁」打出来。
            //   客机整体停摆的第一手证据就在这里 —— 等的事件没人 signal，
            //   整个进程就会静默（所有线程 futex 睡眠、svc 计数不涨）。
            if (timeout < 0)
            {
                unsigned long long now = za_now_ns();
                if (now - last_log > 2000000000ull)
                {
                    last_log = now;
                    char lb[256];
                    int n = snprintf(lb, sizeof lb, "svc#24 无限等待 %d 个句柄:", num);
                    for (int i = 0; i < num && n > 0 && n < (int)sizeof lb - 48; i++)
                    {
                        za_handle_t *h = za_handle_get((int)hs[i]);
                        const char *ty = !h ? "无效" : h->type == ZA_H_EVENT ? "事件"
                                         : h->type == ZA_H_THREAD ? "线程" : "其他";
                        const char *st2 = "";
                        if (h && h->type == ZA_H_EVENT) st2 = h->signaled ? "·已信号" : "·未信号";
                        else if (h && h->type == ZA_H_THREAD) st2 = h->exited ? "·已退出" : "·在跑";
                        n += snprintf(lb + n, sizeof lb - (size_t)n, " #%u(%s%s)", hs[i], ty, st2);
                    }
                    ZLOGE("%s", lb);
                }
            }
            if (timeout >= 0)
            {
                unsigned long long now = za_now_ns();
                if (now >= deadline) break;       // 超时
                struct timespec ts;
                unsigned long long remain = deadline - now;
                ts.tv_sec = (time_t)(remain / 1000000000ull);
                ts.tv_nsec = (long)(remain % 1000000000ull);
                pthread_cond_timedwait(&g_handle_cond, &g_handles_mtx, &ts);
            }
            else
            {
                pthread_cond_wait(&g_handle_cond, &g_handles_mtx);
            }
        }
        pthread_mutex_unlock(&g_handles_mtx);
        za_horizon_regs[ZA_REG_X1] = (unsigned long)idx;
        if (a0) *(unsigned int *)(uintptr_t)a0 = (unsigned int)idx;
        return (idx >= 0) ? 0 : 1;   // 超时/无信号 ⇒ 非 0
    }
    case 25: // CancelSynchronization(handle=x0)
    {
        pthread_mutex_lock(&g_handles_mtx);
        pthread_cond_broadcast(&g_handle_cond);
        pthread_mutex_unlock(&g_handles_mtx);
        return 0;
    }
    case 26: // ArbitrateLock(owner=x0, lockaddr=x1, tag=w2)
        // 语义见 za_sync.c：锁字仍是 `owner|等待者位` 就睡眠等交接，否则立刻返回。
        // 以前这里是「阻塞 CAS + 陈旧锁强制夺取」，会让两个线程同时「持有」同一把
        // 锁 ⇒ SDK 的 owner 记账被破坏 ⇒ WaitConditionVariable 断言失败后 Panic。
        return (long)za_sync_arbitrate_lock((unsigned int)a0, (unsigned long long)a1,
                                            (unsigned int)a2);
    case 27: // ArbitrateUnlock(lockaddr=x0)
        return (long)za_sync_arbitrate_unlock((unsigned long long)a0);
    case 28: // WaitProcessWideKeyAtomic(lockaddr=x0, condkey=x1, tag=w2, timeout=x3)
        za_sync_note_guest((unsigned long long)za_horizon_regs[ZA_REG_SP],
                           (unsigned long long)za_horizon_regs[ZA_REG_PC],
                           (unsigned long long)za_horizon_regs[ZA_REG_FP]);
        // 诊断：高频重复等待时把参数打出来（每秒最多 8 行），
        // 用来区分「timeout=0 的空转」和「真的在睡」。
        {
            static unsigned long long win_start, nl;
            unsigned long long now = za_now_ns();
            if (now - win_start > 1000000000ull) { win_start = now; nl = 0; }
            if (nl < 8) {
                nl++;
                ZLOGI("svc#28 lock=%#llx key=%#llx tag=%#x timeout=%lld",
                      (unsigned long long)a0, (unsigned long long)a1,
                      (unsigned)a2, (long long)a3);
            }
        }
        return (long)za_sync_wait_key((unsigned long long)a0, (unsigned long long)a1,
                                      (unsigned int)a2, (long long)a3);
    case 29: // SignalProcessWideKey(condkey=x0, count=w1)
    {
        static unsigned long long win; static unsigned nl;
        struct timespec tsv; clock_gettime(CLOCK_MONOTONIC, &tsv);
        unsigned long long now = (unsigned long long)tsv.tv_sec * 1000000000ull + tsv.tv_nsec;
        if (now - win > 1000000000ull) { win = now; nl = 0; }
        if (nl++ < 10)
            ZLOGI("svc#29 key=%#llx n=%d pc=sdk+%#lx", (unsigned long long)a0, (int)a1,
                  (unsigned long)za_horizon_regs[ZA_REG_PC] - (unsigned long)za_sdk_base);
        return (long)za_sync_signal_key((unsigned long long)a0, (int)a1);
    }

    // ── 地址等待/唤醒（nn::os 的用户态 futex 算法）──────────────────
    // 实测（SDK+0x13b2xx，nn::os 的 mutex/条件变量实现）：
    //     13b2d4: ldar w8,[x21] ; cmp w8,#2 ; b.eq 重等      （2 = contended）
    //     13b320: mov x0,x21 ; mov w1,#2 ; mov w2,#1 ; x3=-1 ; svc#52
    //   ⇒ svc#52 = WaitForAddress(addr, type, value, timeout)。
    //   type 语义（与内核一致）：仅当条件成立才阻塞，否则立刻返回 0xFA01(InvalidState)：
    //     0 = Equal(==)  1 = LessThan(<)  2 = GreaterThan(>)  3 = NotEqual(!=)
    //   实测 w1=2、w2=1、字值=2 ⇒ 等待 "word > 1"，与调用方的循环完全吻合。
    //   svc#53 = SignalToAddress(addr, type, value)：唤醒该地址上的等待者。
    case 52: // WaitForAddress(addr=x0, type=w1, value=w2, timeout=x3)
    {
        za_dbg_last_wait = (unsigned long long)a0;   // 崩溃 dump 用
        // 每条返回路径都留一条「此刻锁字是多少」的记录（谁在摸这把锁）。
#define ZA_W52_RET(v) do { za_mtx_hint((unsigned long long)a0); return (long)(v); } while (0)
        if (!a0) ZA_W52_RET(0xFA01u);
        // 登记等待点（诊断用）：看门狗伪唤醒 / 栈回溯都靠这条记录。
        {
            unsigned long long spv = (unsigned long long)za_horizon_regs[ZA_REG_SP];
            if (!spv) spv = za_spcache_get((long)syscall(SYS_gettid));
            za_sync_note_addr_wait((unsigned long long)a0, (unsigned int)a2, (int)a1, spv,
                                   (unsigned long long)za_horizon_regs[ZA_REG_PC],
                                   (unsigned long long)za_horizon_regs[ZA_REG_FP]);
        }
        // ★ 2026-10-28：整条等待语义改为**参考版**（d2r hle_thread.c svc 0x34）：
        //   type 2 ⇒ 值等于 value 才等；0/1 ⇒ 值小于 value 才等；1 ⇒ 先减一再等。
        //   条件不成立立刻返回 0xFA01（SDK 的锁慢路径把它当「重判」）。
        //   等待由 za_sync 的等待表统一管，不再直接 futex 等客机地址。
        ZA_W52_RET(za_sync_wait_addr((unsigned long long)a0, (int)a1, (int)a2,
                                     (long long)a3));
    }
    case 54: // SynchronizeToAddress / 慢路径让出 CPU（SDK 临界区忙等里调）
    {
        // 实测调用点 sdk+0x1385cc：InternalCriticalSection 的慢路径，参数沿用
        // 外层（没有单独的 addr/type/value）⇒ 语义是「让出/短睡」，不是等待。
        // 这里按让出 CPU 处理，避免多线程忙等把核跑满。
        sched_yield();
        return 0;
    }
    case 53: // SignalToAddress(addr=x0, type=w1, value=w2, count=w3)
    {
        // ★ 2026-10-28：整条语义改为**参考版**（d2r hle_thread.c svc 0x35）：
        //     type 0 ⇒ 只唤醒 count 个；
        //     type 1 ⇒ 若 *addr == value 则 **+1** 并唤醒（CAS 失败返回 0xFA01）；
        //     type 2 ⇒ 按等待者数量改值再唤醒。
        //   这才是客机 0/1/2 互斥字状态机需要的动作：解锁方把 1 推成 2（交接），
        //   等待方才可能被唤醒。以前我们无条件 `+= value`，既不看原值也不改
        //   等待表，锁字与等待者彻底脱节。
        unsigned int *p = (unsigned int *)(uintptr_t)a0;
        {
            static unsigned long long win;
            static unsigned nl;
            struct timespec tsv;
            clock_gettime(CLOCK_MONOTONIC, &tsv);
            unsigned long long now = (unsigned long long)tsv.tv_sec * 1000000000ull + tsv.tv_nsec;
            if (now - win > 1000000000ull) { win = now; nl = 0; }
            if (nl < 12) {
                nl++;
                unsigned int cur = p ? __atomic_load_n(p, __ATOMIC_RELAXED) : 0xdeadbeef;
                ZLOGI("svc#53 addr=%#llx type=%ld value=%u cur=%#x pc=sdk+%#lx", (unsigned long long)a0,
                      (long)a1, (unsigned)a2, cur,
                      (unsigned long)za_horizon_regs[ZA_REG_PC] - (unsigned long)za_sdk_base);
            }
        }
        return (long)za_sync_signal_addr((unsigned long long)a0, (int)a1, (int)a2, (int)a3);
    }

    // ── 句柄 / 共享内存 ──
    case 19: // MapSharedMemory(handle=x0, addr=x1, size=x2, perm=w3)
    {
        // ★ 以前这里是**空实现**（直接 return 0），害得 SDK 随后读未映射地址崩：
        //   真机实测 pc=SDK+0x42ff34 addr=0x404b60038（seqlock 读共享内存）
        // 客机流程（SDK+0x143c44 反汇编）：
        //   ① SDK 自己的分配器在 ASLR 区挑空位（0x404b60000）
        //   ② svc#19(handle, addr, size, perm) ← 内核要在这儿真的映射出来
        //   ③ SDK+0x636f30 登记进自己的页表
        //   ④ SDK 之后直接当这块内存存在
        if (!za_mem_map_shared((unsigned long long)a1, (unsigned long long)a2))
            return 0xDC01;
        ZLOGI("svc#19 MapSharedMemory：%#llx 映射 %llu 字节（handle=%#lx）",
              (unsigned long long)a1, (unsigned long long)a2, (unsigned long)a0);
        return 0;
    }
    case 20: // UnmapSharedMemory(handle=x0, addr=x1, size=x2)
    {
        ZLOGI("svc#20 UnmapSharedMemory handle=%#lx addr=%#lx size=%#lx (pc=sdk+%#lx)",
              (unsigned long)a0, (unsigned long)a1, (unsigned long)a2,
              (unsigned long)(za_horizon_regs[ZA_REG_PC] - (unsigned long)za_sdk_base));
        za_mem_unmap_shared((unsigned long long)a1, (unsigned long long)a2);
        return 0;
    }
    case 21: // CreateTransferMemory(out_handle=x0, addr=x1, size=x2, perm=w3) → W1
    {
        if (nr == 21)
        {
            int id = za_handle_alloc(ZA_H_MEMORY);
            if (id < 0) return 1;
            if (a0) *(unsigned int *)(uintptr_t)a0 = (unsigned int)id;
            za_horizon_regs[ZA_REG_X1] = (unsigned long)(unsigned int)id;
        }
        return 0;
    }
    case 22: // CloseHandle(handle=x0)
    {
        za_handle_free((int)a0);
        return 0;
    }
    case 31: // ConnectToNamedPort(out_handle=x0, name=x1) → W1
    {
        // 取证：客机连的是哪个服务（无结尾 NUL，按 8 字节打印）
        {
            const char *nm = (const char *)(uintptr_t)a1;
            if (nm)
            {
                unsigned long long w0v = 0, w1v = 0;
                memcpy(&w0v, nm, 8);
                memcpy(&w1v, nm + 8, 8);
                ZLOGI("svc#31 ConnectToNamedPort name=%.8s%s (raw %016llx %016llx) out=%p",
                      nm, (w0v >> 56) ? "" : "...", w0v, w1v, (void *)(uintptr_t)a0);
            }
        }
        int id = za_handle_alloc(ZA_H_MEMORY);
        if (id < 0) return 1;
        if (a0) *(unsigned int *)(uintptr_t)a0 = (unsigned int)id;
        za_horizon_regs[ZA_REG_X1] = (unsigned long)(unsigned int)id;
        return 0;
    }

// ══════════════════════════════════════════════════════════════════
//  IPC（svc#33 SendSyncRequest）应答生成

    // ── IPC（svc#33）：生成真正的应答 ──
    case 33: // SendSyncRequest(session=x0)
    {
        // ★★ 取证：svc#33 的全部原始参数。真机上普通服务（CMIF）的请求/应答
        //   缓冲区**不是** TPIDRRO_EL0，而是「按 session 分配的 IPC 共享内存」，
        //   它的地址应当出现在 svc 参数里 —— 打印出来才能定位。
        ZLOGI("  svc#33 RAW a0=%#lx a1=%#lx a2=%#lx a3=%#lx a4=%#lx a5=%#lx a6=%#lx a7=%#lx",
              (unsigned long)a0, (unsigned long)a1, (unsigned long)a2, (unsigned long)a3,
              (unsigned long)a4, (unsigned long)a5, (unsigned long)a6, (unsigned long)a7);
        // ★ 见上面「IPC 应答生成」注释块：这一页（za_ro_tls_page）就是内核
        //   的应答缓冲区，请求也在这里。
        unsigned long long ro = za_os_tls_ro_area();   // ★ 本线程的只读 TLS 页
        unsigned int hdr0 = 0, hdr1 = 0;
        unsigned int sm_cnt = 0, sm_sess = 0;
        if (ro)
        {
            memcpy(&hdr0, (void *)(uintptr_t)(ro + 0), 4);
            memcpy(&hdr1, (void *)(uintptr_t)(ro + 4), 4);
        }
        if (za_sdk_base)
        {
            memcpy(&sm_cnt, (void *)(uintptr_t)(za_sdk_base + 0xb9c598), 4);
            memcpy(&sm_sess, (void *)(uintptr_t)(za_sdk_base + 0xb9c59c), 4);
        }
        unsigned int sess = (unsigned int)a0;
        unsigned int cmd = hdr0 & 0xffff;
        unsigned int zero = 0;

        if (ro && sm_sess && sess == sm_sess)
        {
            // ── TIPC：服务管理器 ──
            if (cmd == 0x11)                                  // GetServiceHandle
            {
                // ★ 必须**先读名字**再写结果：服务名就在 TLS+8（8 字节小端打包），
                //   写结果会把同一个 4 字节覆盖掉（上一版就是在这儿把名字读成空的）。
                char nm[9];
                memset(nm, 0, sizeof nm);
                memcpy(nm, (void *)(uintptr_t)(ro + 8), 8);
                if (za_svc_is_denied(nm))
                {
                    /* 服务不存在：句柄给 0、服务级返回码给「找不到」⇒ SDK 走正常分支 */
                    unsigned int nf = ZA_SVC_NOT_FOUND;
                    memcpy((void *)(uintptr_t)(ro + 8), &zero, 4);
                    memcpy((void *)(uintptr_t)(ro + 0xc), &zero, 4);
                    memcpy((void *)(uintptr_t)(ro + 0x10), &nf, 4);
                    ZLOGI("  IPC TIPC GetServiceHandle(\"%s\") -> 不存在（返回 %#x）", nm, nf);
                }
                else
                {
                    unsigned int h = za_fake_svc_handle(nm);
                    memcpy((void *)(uintptr_t)(ro + 8), &zero, 4);      // result
                    memcpy((void *)(uintptr_t)(ro + 0xc), &h, 4);      // 服务句柄 (u32!)
                    memcpy((void *)(uintptr_t)(ro + 0x10), &zero, 4);   // 返回码
                    /* ★★ 实验：在应答里**额外**带一个 u64 的「共享内存地址」。
                     *   真机上 CMIF 服务的应答缓冲区地址不是句柄（句柄是 u32），
                     *   而是服务管理器通过 IPC 内存偏移表下发的另一个 u64。
                     *   这里试把它放在 ro+0x14，看 SDK 后续 svc#33 的 a2 会不会变。 */
                    unsigned long long shared = (unsigned long long)za_sdk_base + 0x1100000ull;
                    memcpy((void *)(uintptr_t)(ro + 0x14), &shared, 8);
                    ZLOGI("  IPC TIPC GetServiceHandle(\"%s\") -> handle %#x (+u64 shared=%#llx @ro+0x14)",
                          nm, h, shared);
                }
            }
            else
            {
                memcpy((void *)(uintptr_t)(ro + 8), &zero, 4);   // result
                memcpy((void *)(uintptr_t)(ro + 0xc), &zero, 4);
                memcpy((void *)(uintptr_t)(ro + 0x10), &zero, 4);
                ZLOGI("  IPC TIPC cmd=%#x hdr0=%#x hdr1=%#x -> ok", cmd, hdr0, hdr1);
            }
        }
        else if (ro && sess >= ZA_FAKE_SVC_BASE)
        {
            // ── CMIF：普通服务（fs 等）──
            int tipc = za_fake_svc_is_tipc(sess);
            if (tipc == 1)
            {
                // sm:m 也是 TIPC
                memcpy((void *)(uintptr_t)(ro + 8), &zero, 4);
                memcpy((void *)(uintptr_t)(ro + 0xc), &zero, 4);
                memcpy((void *)(uintptr_t)(ro + 0x10), &zero, 4);
                ZLOGI("  IPC TIPC(sm:m) cmd=%#x -> ok", cmd);
            }
            else
            {
                // 取证：hid 的请求/应答布局（每个 hid 调用前 8 次）
                if (strcmp(za_fake_svc_name(sess), "hid") == 0)
                {
                    static int hid_dumps;
                    if (hid_dumps++ < 8)
                    {
                        unsigned int w[20];
                        for (int i = 0; i < 20; i++)
                            memcpy(&w[i], (void *)(uintptr_t)(ro + (unsigned long long)(i * 4)), 4);
                        ZLOGI("  HID req[0..0x50]=%08x %08x %08x %08x | %08x %08x %08x %08x | "
                              "%08x %08x %08x %08x | %08x %08x %08x %08x | %08x %08x %08x %08x",
                              w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7],
                              w[8], w[9], w[10], w[11], w[12], w[13], w[14], w[15],
                              w[16], w[17], w[18], w[19]);
                    }
                }
                // 取证：把请求缓冲里的可打印字符串（文件路径等）打出来。
                // 实测 main 的 OpenFile 失败会让它在重试后 Abort，
                // 所以必须知道它到底在开哪个文件。
                {
                    static int strdumps;
                    const char *nm2 = za_fake_svc_name(sess);
                    if (strdumps < 24 && nm2 && (strcmp(nm2, "fsp-srv") == 0 || strcmp(nm2, "fs") == 0))
                    {
                        for (unsigned off = 0; off < 0x200 && strdumps < 24; off++)
                        {
                            const unsigned char *q = (const unsigned char *)(uintptr_t)(ro + off);
                            unsigned n = 0;
                            while (n < 120 && q[n] >= 0x20 && q[n] < 0x7f) n++;
                            if (n >= 4 && (off == 0 || q[-1] == 0))
                            {
                                strdumps++;
                                // ⚠ 必须拷到本地再 NUL 结尾：客机的字符串可能在
                                //   页尾没有终止符，直接把 q 交给 vsnprintf("%s")
                                //   会让 libc 走过映射边界 ⇒ SIGSEGV（实测）。
                                char tmp[72];
                                unsigned m = n < 64 ? n : 64;
                                memcpy(tmp, q, m);
                                tmp[m] = 0;
                                ZLOGI("    fs 字符串 @TLS+%#x: \"%s\"", off, tmp);
                                off += n;
                            }
                        }
                    }
                }
                za_write_cmif_reply(ro, (unsigned long long)a2, (unsigned long long)a4, hdr0, hdr1);
                {
                    // 把 CMIF 头里的**命令号**打出来（hdr0 只是类型）。
                    unsigned cmdid = 0;
                    if (ro)
                    {
                        for (unsigned off = 0; off < 0x100; off += 4)
                        {
                            unsigned int w = 0;
                            memcpy(&w, (void *)(uintptr_t)(ro + off), 4);
                            if (w == 0x49434653u)
                            {
                                memcpy(&cmdid, (void *)(uintptr_t)(ro + off + 8), 4);
                                break;
                            }
                        }
                    }
                    ZLOGI("  IPC CMIF 服务=\"%s\" session=%#x type=%#x cmd=%#x hdr1=%#x -> reply written",
                          za_fake_svc_name(sess), sess, cmd, cmdid, hdr1);
                }
            }
        }
        else
        {
            // 未知会话：维持旧行为（清挂起位 + result 0）。
            // ⚠ 试过「未知会话也按 CMIF 写 SFCO（带 SFCI 判据）」——连 M5 都到不了，
            //   说明早期仍有 TIPC/控制会话会被误判。先只记录，不改行为。
            if (ro)
            {
                static int nunk;
                if (nunk++ < 16)
                {
                    unsigned int w[8];
                    for (int i = 0; i < 8; i++)
                        memcpy(&w[i], (void *)(uintptr_t)(ro + (unsigned long long)(i * 4)), 4);
                    ZLOGI("  未知会话 session=%#x cmd=%#x hdr0=%#x hdr1=%#x 前 8 字=%08x %08x %08x %08x %08x %08x %08x %08x",
                          sess, cmd, hdr0, hdr1, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7]);
                }
                // ★ 克隆出来的小句柄（session 0x6/0x7）：SDK 的
                //   CloneCurrentObject 控制请求拿到的「新句柄」其实是我们
                //   应答里的 token，随后它就在这些小句柄上发 CMIF 请求。
                //   限定条件（避免误伤 TIPC/早期控制会话）：
                //     type ∈ {6,7}、SFCI 落在 16 字节对齐处、version == 1。
                extern volatile int za_stage_m5;
                int alias_cmif = 0;
                if (za_stage_m5 && sess < 0x1000)
                {
                    unsigned int w0v = 0;
                    memcpy(&w0v, (void *)(uintptr_t)ro, 4);
                    unsigned int ty = w0v & 0xffffu;
                    if (ty == 6 || ty == 7)
                    {
                        for (unsigned off = 0; off < 0x100 && !alias_cmif; off += 16)
                        {
                            unsigned int w = 0, ver = 0;
                            memcpy(&w, (void *)(uintptr_t)(ro + off), 4);
                            if (w != 0x49434653u) continue;
                            memcpy(&ver, (void *)(uintptr_t)(ro + off + 4), 4);
                            if (ver == 1) alias_cmif = 1;
                        }
                    }
                }
                if (alias_cmif)
                {
                    za_write_cmif_reply(ro, (unsigned long long)a2, (unsigned long long)a4,
                                        hdr0, hdr1);
                    ZLOGI("  IPC CMIF(别名句柄) session=%#x type=%#x -> reply written",
                          sess, cmd);
                }
                else
                {
                    memcpy((void *)(uintptr_t)(ro + 8), &zero, 4);
                    memcpy((void *)(uintptr_t)(ro + 0xc), &zero, 4);
                }
            }
        }
        ZLOGI("svc#33 SendSyncRequest session=%#x sm.cnt=%u sm.sess=%#x hdr0=%#x hdr1=%#x",
              sess, sm_cnt, sm_sess, hdr0, hdr1);
        return 0;
    }
    case 34: // SendSyncRequestWithUserBuffer(buf=x0, size=x1, session=x2)
    case 35: // SendAsyncRequestWithUserBuffer(out_handle=x0, buf=x1, size=x2, session=x3) → W1
        if (nr == 35)
        {
            int id = za_handle_alloc(ZA_H_MEMORY);
            if (id < 0) return 1;
            if (a0) *(unsigned int *)(uintptr_t)a0 = (unsigned int)id;
            za_horizon_regs[ZA_REG_X1] = (unsigned long)(unsigned int)id;
        }
        return 0;

    // ── 调试 ──
    case 38: // Break(reason=x0, info=x1, size=x2)
    {
        za_dbg_last_break_info = (unsigned long long)a1;
        za_dbg_last_break_size = (unsigned long long)a2;
        // 客机的断言/致命错误：reason 是 BreakReason，info 指向一个 size 字节的值。
        // 把这个值读出来 —— 它能直接指出是哪个断言（模块号/行号）。
        unsigned long long v = 0;
        if (a1 && a2 > 0 && a2 <= 8)
            memcpy(&v, (const void *)(uintptr_t)a1, (size_t)a2);
        ZLOGI("Horizon: Break reason=%#lx info=%#lx size=%ld 值=%#llx",
              (unsigned long)a0, (unsigned long)a1, a2, v);
        // ★ 新增：把 panic 前最后 64 次 NVN 调用打出来。
        //   NVN 入口只在每个函数前两次调用时打日志，后面全是静默的；
        //   客机 panic 时没有这份记录就只能靠猜最后走到哪一步。
        za_nvn_dump_recent();
        // ① info 附近原始字节：断言文本/结构体常紧邻它
        if (a1)
        {
            unsigned long long w0v = 0, w1v = 0, w2v = 0;
            memcpy(&w0v, (const void *)(uintptr_t)a1, 8);
            memcpy(&w1v, (const void *)(uintptr_t)((unsigned long)a1 + 8), 8);
            memcpy(&w2v, (const void *)(uintptr_t)((unsigned long)a1 + 16), 8);
            ZLOGI("  info[0..0x18]=%016llx %016llx %016llx", w0v, w1v, w2v);
            // ★ 立即把断言元数据（表达式/文件/函数）解析成字符串 —— 不等进程崩
            {
                extern unsigned char *za_guest_base;
                for (int i = 0; i < 8; i++)
                {
                    unsigned long long v = 0;
                    memcpy(&v, (const void *)(uintptr_t)((unsigned long)a1 + i * 8), 8);
                    if (!v) continue;
                    int in_sdk = (za_sdk_base && v >= za_sdk_base && v < za_sdk_base + za_sdk_size);
                    int in_main = (za_guest_base && v >= (unsigned long long)(uintptr_t)za_guest_base &&
                                   v < (unsigned long long)(uintptr_t)za_guest_base + ZA_IMAGE_SIZE);
                    if (!in_sdk && !in_main) continue;
                    const char *str = (const char *)(uintptr_t)v;
                    int ok = 0;
                    for (int k = 0; k < 128; k++) { if (!str[k]) { ok = 1; break; }
                                                    if ((unsigned char)str[k] < 0x20) break; }
                    if (ok) ZLOGI("    info[+%#x] → %s 字符串: \"%s\"",
                                  i * 8, in_sdk ? "sdk" : "main", str);
                }
            }
        }
        // ② GetInfo 关键 id 的当前值：0x148f80 的 bics 掩码校验依赖它
        {
            extern unsigned long long za_mem_getinfo(long id);
            ZLOGI("  GetInfo: id0(CpuMask)=%#llx id23(IsApplication)=%#llx",
                  za_mem_getinfo(0), za_mem_getinfo(23));
        }
        // ③ 临界区实况：self / owner_id / 本线程 tid
        //   ⚠ 不要读 Break 的 a0 当锁字 —— a0 是 reason（恒为 0），
        //     上一版据此报「lockword=0 match=NO」是自己造的假结论。
        {
            unsigned long ro = za_os_tls_ro_area();
            unsigned long self = 0;
            if (ro)
                memcpy(&self, (void *)(uintptr_t)(ro + 0x1f8), 8);
            unsigned int oid = 0;
            if (self)
                memcpy(&oid, (void *)(uintptr_t)(self + 0x1b0), 4);
            unsigned int mine = za_current_owner_id();
            unsigned int tid = (unsigned)syscall(SYS_gettid);
            ZLOGI("  cs: ro=%p self=%p [self+0x1b0]=%u cur_owner_id=%u host_tid=%u "
                  "consistent=%s",
                  (void *)(uintptr_t)ro, (void *)(uintptr_t)self, oid, mine, tid,
                  (oid && oid == tid) ? "YES" : "NO(以 [self+0x1b0] 为准)");
        }
        // 顺便把客机栈里的返回地址扫出来 ⇒ 能看出是哪条调用链走到这个断言
        // 指针值若是 rodata 里的字符串（断言文本 file/func/expr），一并打出来
        {
            unsigned long sp = za_horizon_regs[ZA_REG_SP];
            unsigned long sb = za_sdk_base;
            unsigned long sz = za_sdk_size;
            for (int i = 0; i < 96 && sp; i++)
            {
                unsigned long w = *(const unsigned long *)(uintptr_t)(sp + i * 8);
                if (sb && w >= sb && w < sb + sz)
                {
                    char buf[97];
                    long n = 0;
                    for (; n < 96; n++)
                    {
                        char c = *(const volatile char *)(uintptr_t)(w + n);
                        if (c == 0) break;
                        if (c < 0x20 || c > 0x7e) break;
                        buf[n] = c;
                    }
                    buf[n] = 0;
                    if (n >= 4)
                        ZLOGI("  客机栈[%d] = sdk+%#lx 「%s」", i, w - sb, buf);
                    else
                        ZLOGI("  客机栈[%d] = sdk+%#lx", i, w - sb);
                }
            }
        }
        // ★★ 断言调用者（决定性证据）★★
        // 客机断言走 nn::diag::detail::Abort(const nn::Result*)，它的 prologue 是
        //     0x9c560: stp x29, x30, [sp, #-0x10]!
        //     0x9c564: mov x29, sp
        //     0x9c568: mov x1, x0        ; info = &Result
        //     0x9c56c: mov w0, wzr       ; reason = 0
        //     0x9c570: mov w2, #4        ; size = 4
        //     0x9c574: bl  0x17018c      ; svc #0x26 (Break)
        // ⇒ Break 现场 sp 就是 Abort 的栈帧：
        //     [sp+0] = Abort 保存的 x29（调用者的帧指针）
        //     [sp+8] = Abort 的返回地址 = **调用 Abort 的那个 SDK 函数里的指令**
        // 再从 x29 链往上走，就能拿到整条调用栈。
        {
            unsigned long sp = za_horizon_regs[ZA_REG_SP];
            unsigned long caller_ret = 0, caller_fp = 0;
            if (sp && za_h_read_word(sp + 8, &caller_ret))
            {
                ZLOGI("  ★ Abort 调用者 = %s", za_h_addrstr(caller_ret));
            }
            if (sp && za_h_read_word(sp, &caller_fp) && caller_fp)
            {
                unsigned long fp = caller_fp;
                for (int i = 0; i < 12 && fp; i++)
                {
                    unsigned long nfp = 0, ret = 0;
                    if (!za_h_read_word(fp, &nfp) || !za_h_read_word(fp + 8, &ret)) break;
                    ZLOGI("  ★ frame[%d] ret=%s", i, za_h_addrstr(ret));
                    if (!nfp || (nfp & 0xF) || nfp <= fp) break;
                    fp = nfp;
                }
            }
        }
        // ★ 断言文本：VAbortImpl(file, func, ...) 的参数指针在被调寄存器里，
        //   断言发生时（Break 现场）它们还没被覆盖 —— 当字符串打出来。
        //   （nn::diag 的日志管理器此刻往往还没初始化 ⇒ OutputDebugString 走不到。）
        {
            unsigned long sb = za_sdk_base, sz = za_sdk_size;
            unsigned long mb = 0x100000000ull;
            for (int r = 19; r <= 28; r++)
            {
                unsigned long p = za_horizon_regs[ZA_REG_X0 + r];
                if (!p) continue;
                int in_sdk = sb && p >= sb && p < sb + sz;
                int in_main = p >= mb && p < mb + 0x4000000ull;
                if (!in_sdk && !in_main) continue;
                char buf[121];
                long n = 0;
                for (; n < 120; n++)
                {
                    /* 指针已框进映像内，直接逐字节读是安全的 */
                    char c = *(const volatile char *)(uintptr_t)(p + n);
                    if (c == 0) break;
                    if (c < 0x20 || c > 0x7e) { break; }
                    buf[n] = c;
                }
                buf[n] = 0;
                if (n >= 3)
                    ZLOGI("  ★ 文本 x%d = %s「%s」", r, in_sdk ? "sdk" : "main", buf);
            }
        }
        // ★ VammManager 现场：ctx+0x428 是 SystemResource 的内存管理器。
        //   它的区域分配器 [mgr+0x40] 的空闲链表决定 12GB 能不能放下。
        {
            unsigned long sb = za_sdk_base;
            if (sb)
            {
                unsigned long long ctx = 0, alloc = 0;
                memcpy(&ctx, (void *)(uintptr_t)(sb + 0xb74078), 8);
                /* VammAllocate 桩诊断：GOT 槽是否还指桩、步进指针是否动过 */
                {
                    unsigned long long got = 0, bump = 0;
                    memcpy(&got, (void *)(uintptr_t)(sb + 0xb7af08), 8);
                    memcpy(&bump, (void *)(uintptr_t)(sb + 0xF01E00), 8);
                    ZLOGI("  Vamm: got(0xb7af08)=%#llx bump(0xF01E00)=%#llx", got, bump);
                }
                if (ctx)
                {
                    /* AllocateAddressRegion(this=ctx+0x428): x23 = [this+0x40] = [ctx+0x468] */
                    memcpy(&alloc, (void *)(uintptr_t)(ctx + 0x468), 8);
                    ZLOGI("  Vamm: ctx=%#llx alloc(ctx+0x468)=%#llx", ctx, alloc);
                    if (alloc)
                    {
                        unsigned long long node = 0;
                        memcpy(&node, (void *)(uintptr_t)(alloc + 0x10), 8);
                        for (int i = 0; i < 24 && node; i++)
                        {
                            unsigned long long nx = 0, b = 0, s = 0;
                            memcpy(&nx, (void *)(uintptr_t)(node + 0x00), 8);
                            memcpy(&b, (void *)(uintptr_t)(node + 0x20), 8);
                            memcpy(&s, (void *)(uintptr_t)(node + 0x28), 8);
                            ZLOGI("  Vamm region[%d] @%#llx: base=%#llx size=%#llx", i, node, b, s);
                            node = nx;
                            if (nx == node) break;
                        }
                    }
                }
            }
        }
        return 0;
    }
    case 39: // OutputDebugString(str=x0, len=x1) —— 客机的调试输出，很有用
    {
        const char *s = (const char *)(uintptr_t)a0;
        long n = a1;
        if (s && n > 0)
        {
            if (n > 512) n = 512;
            char buf[520];
            memcpy(buf, s, (size_t)n);
            buf[n] = 0;
            for (long i = 0; i < n; i++) if (buf[i] == '\n' || buf[i] == '\r') buf[i] = ' ';
            ZLOGI("客机日志: %s", buf);
        }
        return 0;
    }

    // ── 其它 ──
    case 30: // GetSystemTick
    {
        unsigned long long t = za_cntpct();
        za_horizon_regs[ZA_REG_X1] = (unsigned long)(t >> 32);
        return (long)(unsigned int)t;
    }
    case 36: // GetProcessId(out=x0, handle=x1) → W1
    {
        unsigned long long pid = (unsigned long long)getpid();
        za_horizon_regs[ZA_REG_X1] = (unsigned long)pid;
        if (a0) *(unsigned long long *)(uintptr_t)a0 = pid;
        return 0;
    }
    case 41: // GetInfo(out=x0, type=w1, handle=x2, subtype=x3) → W1（64 位值）
    {
        // ⚠ 这里以前一直返回 0 ⇒ SDK 拿到「空地址空间」⇒ 它的
        //   AddressSpaceAllocator 在空区间上空转 100 万次 ⇒ 客机线程栈溢出 256MB。
        //   语义（id 枚举）见 za_mem.c 文件头；值必须自洽。
        unsigned long long v = za_mem_getinfo((long)a1);
        ZLOGI("svc#41 GetInfo id=%#lx -> %#llx (pc=sdk+%#lx)",
              (unsigned long)a1, v,
              (unsigned long)(za_horizon_regs[ZA_REG_PC] - (unsigned long)za_sdk_base));
        za_svc41_count((long)a1);
        za_svc41_trace(za_horizon_regs[ZA_REG_PC], (long)a1);
        za_horizon_regs[ZA_REG_X1] = (unsigned long)v;
        if (a0) *(unsigned long long *)(uintptr_t)a0 = v;
        return 0;
    }
    case 47: // 出参在 x1..x6
    {
        za_horizon_regs[ZA_REG_X1] = 0;
        za_horizon_regs[ZA_REG_X2] = 0;
        za_horizon_regs[ZA_REG_X3] = 0;
        za_horizon_regs[ZA_REG_X4] = 0;
        za_horizon_regs[ZA_REG_X5] = 0;
        za_horizon_regs[ZA_REG_X6] = 0;
        return 0;
    }
    case 75: case 80: case 81: case 82:
    case 64: case 65: case 67: case 68: case 69:
    case 112: case 114:
    {
        // 这几个的包装器都有出参：写 0 即可（结构体清零）
        if (a0) *(unsigned long long *)(uintptr_t)a0 = 0;
        za_horizon_regs[ZA_REG_X1] = 0;
        return 0;
    }
    default:
        break;
    }

    // 未实现的服务：返回 0（成功）。**不能返回非 0**——
    // 客机会把结果码当错误处理（ProtectRelro 里 `cbnz w0` 直接跳错误分支崩掉）。
    return 0;
}

// ── 外层：真正被 trampoline 调用的入口 ──
//
// 出参怎么落地：**由客机自己的包装函数负责**，我们不写。
//   包装函数长这样（svc #41 GetInfo）：
//       str  x0, [sp, #-0x10]!
//       svc  #0x29
//       ldr  x2, [sp]
//       str  x1, [x2]        ← 64 位出参，值在 x1
//   而 svc #6 QueryMemory 的包装函数存的是 **x1**：
//       str  x1, [sp, #-0x10]!
//       svc  #0x6
//       ldr  x2, [sp]
//       str  w1, [x2]        ← 32 位出参，值在 w1，写进 *x1
//
// ⚠ 以前这里按「形状表」替客机写出一参（W1→*x0 等），有两个害处：
//   1) 写的是 32 位 ⇒ 64 位的地址值（GetInfo 返回的就是地址）高位被截断；
//   2) 会**覆盖我们自己在 C 里填的结构体**（#6 的 MemoryInfo 就被写成了 4 字节）。
//   ⇒ 现在只负责把值放进 x1/x2，落地交给客机的包装函数。
// ★ 最近一次「等待类」svc 的返回值（崩溃 dump 用）：
//   SDK 的等待路径对非 0 返回值会直接 throw/abort，必须知道是哪一条返回了什么。
volatile long za_dbg_last_wait_nr;
volatile long za_dbg_last_wait_ret;

// ── 每线程「最近一次有效的客机 sp」缓存 ────────────────────────────────
// 主线程的 svc 走的是另一条门桩路径，slot 9 常为 0（实测），
// 于是它进 svc#52 时我们拿不到栈指针、倒不出调用链。
// 这里在**任何** svc 上把非 0 的 sp 记下来，缺的时候用它兜底。
static struct { long tid; unsigned long long sp; } za_spcache[64];
static void za_spcache_put(long tid, unsigned long long sp)
{
    if (!tid || !sp) return;
    int free_slot = -1;
    for (int i = 0; i < 64; i++) {
        if (za_spcache[i].tid == tid) { za_spcache[i].sp = sp; return; }
        if (!za_spcache[i].tid && free_slot < 0) free_slot = i;
    }
    if (free_slot >= 0) { za_spcache[free_slot].tid = tid; za_spcache[free_slot].sp = sp; }
}
static unsigned long long za_spcache_get(long tid)
{
    for (int i = 0; i < 64; i++) if (za_spcache[i].tid == tid) return za_spcache[i].sp;
    return 0;
}
static long za_horizon_svc_impl(long a0, long a1, long a2, long a3,
                                long a4, long a5, long a6, long a7, long nr);

// ★ 2026-10-28：「谁正卡在我们的 HLE 里」。
//   停摆时如果所有客机线程都睡在 futex，那是正常的等待；但如果某条线程其实
//   卡在宿主实现里（IPC / NVN / fs），它就还占着客机侧的锁，而等待表里看不到它
//   —— 这次死锁的锁持有者就是这么藏起来的。这里给每次 svc 派发记一条出入记录，
//   看门狗据此倒出「超过 1 秒还没返回」的线程。
#define ZA_HLE_SLOTS 64
typedef struct {
    long tid;
    long nr;
    unsigned long long since;
    unsigned long long pc;
} za_hle_rec_t;
static za_hle_rec_t za_hle_rec[ZA_HLE_SLOTS];

static za_hle_rec_t *za_hle_find(long tid)
{
    unsigned h = (unsigned)tid;
    h ^= h >> 16; h *= 0x7feb352du; h ^= h >> 15;
    for (unsigned k = 0; k < ZA_HLE_SLOTS; k++)
    {
        za_hle_rec_t *r = &za_hle_rec[(h + k) & (ZA_HLE_SLOTS - 1)];
        long cur = __atomic_load_n(&r->tid, __ATOMIC_ACQUIRE);
        if (cur == tid) return r;
        if (cur == 0)
        {
            long expect = 0;
            if (__atomic_compare_exchange_n(&r->tid, &expect, tid, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE) || expect == tid)
                return r;
        }
    }
    return NULL;
}

static void za_hle_enter(long nr)
{
    long tid = (long)syscall(SYS_gettid);
    za_hle_rec_t *r = za_hle_find(tid);
    if (!r) return;
    r->nr = nr;
    r->pc = (unsigned long long)za_horizon_regs[ZA_REG_PC];
    r->since = (unsigned long long)za_now_ns();
}

static void za_hle_leave(void)
{
    long tid = (long)syscall(SYS_gettid);
    za_hle_rec_t *r = za_hle_find(tid);
    if (r) r->nr = 0;
}

// 看门狗用：倒出卡在 HLE 里超过 1 秒的线程。
void za_dump_hle_stuck(void)
{
    unsigned long long now = (unsigned long long)za_now_ns();
    int n = 0;
    for (int i = 0; i < ZA_HLE_SLOTS; i++)
    {
        za_hle_rec_t *r = &za_hle_rec[i];
        if (!__atomic_load_n(&r->tid, __ATOMIC_ACQUIRE)) continue;
        long nr = __atomic_load_n(&r->nr, __ATOMIC_ACQUIRE);
        if (!nr) continue;
        unsigned long long age_ms = r->since ? (now - r->since) / 1000000ull : 0;
        if (age_ms < 1000) continue;
        if (n == 0) ZLOGE("★ 卡在 HLE 里的线程（>1s 未返回）：");
        n++;
        ZLOGE("    tid=%ld svc#%ld 已 %llums pc=%s", r->tid, nr, age_ms,
              za_h_addrstr((unsigned long)r->pc));
    }
    if (!n) ZLOGI("    （没有线程卡在 HLE 里）");
}

// ★ 每线程的 svc 环形记录（服务号 + 返回值 + 参数 + 调用点 PC）。
//   之前是全局一份：多线程并发写会互相覆盖，dump 出来的「最后几条 svc」
//   来自不同线程，据此推断谁返回了非 0 会漂移。
//   现在每个 tid 独占一个槽（CAS 认领），槽内字段不会被别的线程混写。
#define ZA_RR 24
#define ZA_RR_SLOTS 256
typedef struct {
    long nr, ret;
    unsigned long long a0, a1, a2, a3, pc;
} za_rr_t;
typedef struct {
    int tid;
    unsigned head;
    za_rr_t e[ZA_RR];
} za_rr_slot_t;
static za_rr_slot_t za_rr_slots[ZA_RR_SLOTS];
static za_rr_slot_t *za_rr_cur(void)
{
    int t = (int)syscall(SYS_gettid);
    unsigned h = (unsigned)t;
    h ^= h >> 16; h *= 0x7feb352du; h ^= h >> 15;
    for (unsigned k = 0; k < ZA_RR_SLOTS; k++)
    {
        za_rr_slot_t *s = &za_rr_slots[(h + k) & (ZA_RR_SLOTS - 1)];
        int cur = __atomic_load_n(&s->tid, __ATOMIC_ACQUIRE);
        if (cur == t) return s;
        if (cur == 0)
        {
            int expect = 0;
            if (__atomic_compare_exchange_n(&s->tid, &expect, t, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                return s;
            if (expect == t) return s;
        }
    }
    return &za_rr_slots[h & (ZA_RR_SLOTS - 1)];   // 表满：退化（诊断用，可接受）
}
// 按 tid 倒出某个线程的 svc 环形记录（看门狗在等待表里用）。
// ret == 0xdead 表示这条 svc **还没返回**（线程正阻塞在里面）。
// 某线程当前阻塞在哪个地址（环形记录里最新一条 ret=0xdead 的 a0）。
unsigned long long za_last_blocked_addr(long tid)
{
    for (unsigned i = 0; i < ZA_RR_SLOTS; i++) {
        za_rr_slot_t *s = &za_rr_slots[i];
        if (__atomic_load_n(&s->tid, __ATOMIC_ACQUIRE) != tid) continue;
        unsigned h = __atomic_load_n(&s->head, __ATOMIC_RELAXED);
        for (int k = 0; k < 4; k++) {
            int j = (int)((h - 1 - k + ZA_RR * 2) % ZA_RR);
            za_rr_t *e = &s->e[j];
            if (e->ret != 0xdeadL) break;
            if (e->a0 && (e->nr == 52 || e->nr == 28 || e->nr == 26)) return e->a0;
        }
    }
    return 0;
}

void za_dump_ret_ring_for(long tid)
{
    za_rr_slot_t *s = NULL;
    for (unsigned i = 0; i < ZA_RR_SLOTS; i++)
        if (__atomic_load_n(&za_rr_slots[i].tid, __ATOMIC_ACQUIRE) == tid) { s = &za_rr_slots[i]; break; }
    if (!s) { ZLOGI("    (tid=%ld 没有 svc 记录)", tid); return; }
    unsigned h = __atomic_load_n(&s->head, __ATOMIC_RELAXED);
    for (int k = 0; k < 4; k++)
    {
        int i = (int)((h - 1 - k + ZA_RR * 2) % ZA_RR);
        za_rr_t *e = &s->e[i];
        if (!e->pc && !e->nr) continue;
        ZLOGI("      svc#%ld ret=%s%#lx pc=%#llx a0=%#llx a1=%#llx",
              e->nr, e->ret == 0xdeadL ? "(未返回)" : "", (unsigned long)e->ret,
              e->pc, e->a0, e->a1);
        // 阻塞中的那条：把**等待字当前的值**读出来。这决定死锁判断方向：
        //   0/1  ⇒ 锁其实是空的，是我们把线程按住了（等待逻辑错）
        //   >1   ⇒ 真有人在持有，要找持有者
        if (k == 0 && e->ret == 0xdeadL && e->a0 &&
            (e->nr == 52 || e->nr == 28 || e->nr == 26)) {
            // ★ 必须走 process_vm_readv：环形记录里的地址可能已经失效
            //   （实测直接解引用会把看门狗线程打死，整个进程跟着崩）。
            unsigned int w = 0, c = 0;
            struct iovec li = { &w, 4 };
            struct iovec ri = { (void *)(uintptr_t)e->a0, 4 };
            int okw = process_vm_readv((pid_t)syscall(SYS_getpid), &li, 1, &ri, 1, 0) == 4;
            if (e->a1) {
                struct iovec li2 = { &c, 4 };
                struct iovec ri2 = { (void *)(uintptr_t)e->a1, 4 };
                if (process_vm_readv((pid_t)syscall(SYS_getpid), &li2, 1, &ri2, 1, 0) != 4)
                    c = 0;
            }
            if (!okw) {
                ZLOGI("        ↳ 等待字[%#llx] 不可读（地址已失效）", e->a0);
            } else {
                ZLOGI("        ↳ 等待字[%#llx]=%#x  cv[%#llx]=%#x  ⇒ %s",
                      e->a0, w, e->a1, c,
                      w <= 1u ? "锁字是 0/1：实际无人持有，问题在我们这边"
                              : "锁字 >1：有人持有，需找持有者");
            }
        }
    }
}

// ★ 把所有线程的 svc 环形记录都倒出来（停摆诊断用）。
//   za_dump_ret_ring_for(tid) 需要先知道 tid，而停摆时我们只知道「哪个 tag 在等」，
//   所以直接遍历槽位：每个线程最近 4 条 svc 连着打，主线程一眼能认出来。
void za_dump_all_ret_rings(void)
{
    int shown = 0;
    for (unsigned i = 0; i < ZA_RR_SLOTS; i++)
    {
        za_rr_slot_t *s = &za_rr_slots[i];
        long t = __atomic_load_n(&s->tid, __ATOMIC_ACQUIRE);
        if (!t) continue;
        unsigned h = __atomic_load_n(&s->head, __ATOMIC_RELAXED);
        if (!h) continue;
        int any = 0;
        for (int k = 0; k < 4; k++)
        {
            int j = (int)((h - 1 - k + ZA_RR * 2) % ZA_RR);
            if (s->e[j].nr || s->e[j].pc) { any = 1; break; }
        }
        if (!any) continue;
        if (shown++ >= 24) break;
        for (int k = 0; k < 4; k++)
        {
            int j = (int)((h - 1 - k + ZA_RR * 2) % ZA_RR);
            za_rr_t *e = &s->e[j];
            if (!e->pc && !e->nr) continue;
            ZLOGI("    tid=%ld svc#%ld ret=%s%#lx pc=%#llx a0=%#llx a1=%#llx", t, e->nr,
                  e->ret == 0xdeadL ? "(未返回)" : "", (unsigned long)e->ret, e->pc, e->a0,
                  e->a1);
        }
    }
    if (!shown) ZLOGI("    （没有任何线程的 svc 记录）");
}

void za_dump_ret_ring(void)
{
    za_rr_slot_t *s = za_rr_cur();
    unsigned h = __atomic_load_n(&s->head, __ATOMIC_RELAXED);
    ZLOGI("  ret-ring（本线程 tid=%d，最近 %d 条）", s->tid, ZA_RR);
    for (int k = 0; k < ZA_RR; k++)
    {
        int i = (int)((h - 1 - k + ZA_RR * 2) % ZA_RR);
        za_rr_t *e = &s->e[i];
        if (!e->pc) continue;
        ZLOGI("  ret-ring[%d] svc#%ld ret=%#lx a0=%#llx a1=%#llx a2=%#llx pc=%#llx", k,
              e->nr, (unsigned long)e->ret, e->a0, e->a1, e->a2, e->pc);
    }
}
long za_horizon_svc(long a0, long a1, long a2, long a3,
                    long a4, long a5, long a6, long a7, long nr)
{
    // ★ 2026-10-27：**入口就记一条**（ret = 哨兵 0xdead）。
    //   以前只在 svc 返回后记录 ⇒ 阻塞在 svc#28 里的线程在环形记录里
    //   完全不可见，看门狗倒现场时根本不知道它在等什么。
    za_rr_slot_t *rr = za_rr_cur();
    int rri = (int)(__atomic_fetch_add(&rr->head, 1, __ATOMIC_RELAXED) % ZA_RR);
    rr->e[rri].nr  = nr;
    rr->e[rri].ret = 0xdeadL;
    rr->e[rri].a0  = (unsigned long long)a0;
    rr->e[rri].a1  = (unsigned long long)a1;
    rr->e[rri].a2  = (unsigned long long)a2;
    rr->e[rri].a3  = (unsigned long long)a3;
    rr->e[rri].pc  = (unsigned long long)za_horizon_regs[ZA_REG_PC];
    long r = za_horizon_svc_impl(a0, a1, a2, a3, a4, a5, a6, a7, nr);
    rr->e[rri].ret = r;
    if (nr == 24 || nr == 28 || nr == 52 || nr == 53 || nr == 54)
    {
        za_dbg_last_wait_nr = nr;
        za_dbg_last_wait_ret = r;
    }
    return r;
}
static long za_horizon_svc_impl(long a0, long a1, long a2, long a3,
                                long a4, long a5, long a6, long a7, long nr)
{
    // 服务号只有 16 位有效（svc #N）。上位是防御性清零。
    nr &= 0xFFFF;
    // 轨迹：最近 32 次 svc 的（服务号 + 调用点 PC）⇒ 崩溃时直接定位卡在哪一步
    za_svc_trace_rich(nr, za_horizon_regs[ZA_REG_PC], (unsigned long)a0,
                      (unsigned long)a2, za_horizon_regs[19]);
    // 帧快照：0x14457c 的三条 svc 各拍一张（见 za_frame_snapshot 注释）
    za_frame_snapshot(za_horizon_regs[ZA_REG_PC], za_horizon_guest_sp());
    // 轨迹：客人的 callee-saved（x19/x29）—— 用来定位它们何时变坏
    {
        unsigned long p = za_horizon_regtrace_pos % ZA_SVC_REGTRACE;
        za_horizon_regtrace[p][0] = (unsigned long)nr;
        za_horizon_regtrace[p][1] = za_horizon_regs[ZA_REG_PC];
        za_horizon_regtrace[p][2] = za_horizon_regs[16];
        za_horizon_regtrace[p][3] = za_horizon_regs[17];
        za_horizon_regtrace_pos = p + 1;
    }
    // ★ 客机初始化期间 SDK 会把线程的信号掩码设成「几乎全屏蔽」⇒ 我们的 PC 采样器
    //   （SIGALRM 定时器）会被挡掉 ⇒ 崩溃时拿不到客机真正的 PC。
    //   ⇒ 每次 svc 调用时把采样信号重新放行（一次 sigprocmask，代价可忽略）。
    {
        // ⚠ 不用 `__thread`（emutls 的每线程块要靠 realloc，真机上被写坏过
        //   ⇒ scudo realloc 报 chunk header 损坏）。按 tid 取模记一个布尔。
        static volatile unsigned char last_mask_done[128];
        int lm_idx = (int)((unsigned long)syscall(SYS_gettid) % 128u);
        if (!last_mask_done[lm_idx])
        {
            sigset_t m;
            sigemptyset(&m);
            sigaddset(&m, SIGALRM);
            sigaddset(&m, SIGUSR1); sigaddset(&m, SIGRTMIN);
            sigaddset(&m, SIGTERM); sigaddset(&m, 63);
            pthread_sigmask(SIG_UNBLOCK, &m, NULL);
            last_mask_done[lm_idx] = 1;
        }
        // ★ SDK 初始时会把自己的信号拜码设成「忇以换捉」
        //   ⇒ 每次 svc 都重新装一遍 32..62 的捕获器，并把整个实时信号段放行。
        za_install_rt_catch();
        za_reinstall_sampler_handler();
        {
            sigset_t rt;
            sigemptyset(&rt);
            for (int s = 32; s <= 63; s++) sigaddset(&rt, s);
            pthread_sigmask(SIG_UNBLOCK, &rt, NULL);
        }
    }
    za_disp_count_bump();
    za_svc_nr_count_bump((unsigned)nr);
    za_spcache_put((long)syscall(SYS_gettid), (unsigned long long)za_horizon_regs[ZA_REG_SP]);
    za_hle_enter(nr);
    long res = za_horizon_dispatch(a0, a1, a2, a3, a4, a5, a6, a7, nr);
    za_hle_leave();
    // 返回值也记进轨迹：客机多数 svc 包装函数是
    //   svc #N ; <收尾> ; ret     —— 返回值直接进 x0/w0
    // 而 0x14457c 收尾前有 cbnz w0, <abort>；把 w0 记下来才能判定
    // 崩点究竟是「走了 abort 分支」还是「ret 取到 0」。
    za_svc_trace_ret(res);
    (void)a0; (void)a1; (void)a2; (void)a3;
    (void)a4; (void)a5; (void)a6; (void)a7;
    return res;
}
