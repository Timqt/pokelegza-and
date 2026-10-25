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

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "za_common.h"
#include "za_svc_patch.h"
#include "za_guest_api.h"
#include "za_mem.h"

// SDK 映像基址/大小（定义在 za_guest.c）：崩溃与断言回溯时用来把地址换算成模块偏移
extern volatile unsigned long za_sdk_base;
extern volatile unsigned long za_sdk_size;

// trampoline 回写用的寄存器数组：index 0 = 结果(x0)，1..7 = x1..x7，
// index 9 = 客机 sp，10 = 服务号，11 = 客机 x30（svc 调用点的返回地址，
// 日志里用来定位是哪个函数调的服务）。
__attribute__((visibility("default"))) volatile unsigned long za_horizon_regs[32];

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
    za_thread_start_t *ts = (za_thread_start_t *)p;
    void (*entry)(void *) = ts->entry;
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
static unsigned int za_current_owner_id(void)
{
    unsigned long ro = (unsigned long)za_ro_tls_page;
    if (!ro) return 1;                       // 兜底：与 za_sdk.c 里写入的 owner_id 一致
    unsigned long self = 0;
    __builtin_memcpy(&self, (void *)(ro + 0x1f8), 8);
    if (!self) return 1;
    unsigned int oid = 0;
    __builtin_memcpy(&oid, (void *)(self + 0x1b0), 4);
    return oid ? oid : 1;
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
        return 0;
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
        ZLOGI("Horizon: CreateThread handle=%d entry=%#lx arg=%#lx（栈 %zu 字节）",
              id, (unsigned long)a1, (unsigned long)a2, ssz);
        return 0;
    }
    case 9: // StartThread(handle=x0)
    {
        za_handle_t *h = za_handle_get((int)a0);
        if (!h || h->type != ZA_H_THREAD) return 1;
        if (h->started) return 0;
        h->started = 1;
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
    case 26: // ArbitrateLock(cur_handle=x0, ptr=x1, req_handle=w2) → 返回 0 表示拿到锁
    case 27: // ArbitrateUnlock(ptr=x0)
        // ★★ 2026-10-25：这里原来直接 `return 0`，**从不操作锁字** —— 这是错的。
        //
        //   SDK 的临界区（sdk+0x145fe0）自己实现了 futex 快路径：
        //       ldxr w9,[x0]        ; 读锁字
        //       cmp  w9, w8         ; 和 owner_id 比
        //       b.eq 快速解锁（stlxr w9,wzr,[x0]）
        //       b.ne → svc #0x1b（ArbitrateUnlock）  ← **期望内核真的解锁**
        //   我们返回 0 却不改锁字 ⇒ 锁永远是「别人持有」
        //   ⇒ 后续每次进入临界区都走慢路径、越积越多 ⇒ 最终走到 abort（实测 pc=0）。
        //
        //   正确语义（照 Horizon 内核）：
        //     ArbitrateLock  : 锁字是 0（空闲）⇒ 写成本线程 owner_id，返回 0（拿到）
        //                      否则 ⇒ 返回 1（没拿到，调用方去 WaitProcessWideKey）
        //     ArbitrateUnlock: 把锁字清零（无论当前是谁持有）
        //   owner_id 取自 [TPIDRRO_EL0 + 0x1f8] + 0x1b0（我们已填成 1）。
        if (nr == 27)
        {
            // ArbitrateUnlock(ptr = x0)
            if (a0) __atomic_store_n((unsigned int *)(uintptr_t)a0, 0u, __ATOMIC_RELEASE);
            return 0;
        }
        {
            // ArbitrateLock(cur_handle = x0, ptr = x1, req_handle = w2)
            unsigned int *lock = (unsigned int *)(uintptr_t)a1;
            if (!lock) return 0;
            unsigned int owner = za_current_owner_id();
            unsigned int expect = 0;
            if (__atomic_compare_exchange_n(lock, &expect, owner, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                return 0;           // 拿到
            if (expect == owner) return 0;   // 已经是自己持有（可重入视作拿到）
            return 1;               // 别人持有 ⇒ 让调用方去等
        }
    case 28: // WaitProcessWideKeyAtomic(addr=x0, key=x1, tag=w2, timeout=x3)
    case 29: // SignalProcessWideKey(key=x0, count=w1)
        return 0;

    // ── 句柄 / 共享内存 ──
    case 19: // MapSharedMemory(shmem=x0, addr=x1, size=x2, perm=w3)
    case 20: // UnmapSharedMemory(shmem=x0, addr=x1)
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

    // ── IPC（客机用不上真 IPC，给个空实现让它别崩）──
    case 33: // SendSyncRequest(session=x0)
    {
        // ★ 取证 + 关键修复（见本次补丁头部注释）
        //
        // 客机在 sdk+0x153edc 这样用 svc#33（反汇编实测）：
        //     str  w8,[tp16+8]      ; = 1
        //     ldr  w0,[0xb9c59c]    ; session
        //     bl   svc#33
        //     cbnz w0, error        ; 必须返回 0
        //     ldr  w8,[tp16+8]
        //     cbnz w8, error        ; ★ 必须变回 0
        // 也就是说，**SendSyncRequest 的实现必须把 [tp16+8] 清 0**
        // （真机上这由内核在完成 IPC 时写回「无挂起中断」）。
        // 我们以前只 return 0，[tp16+8] 永远是 1 ⇒ 必走 error ⇒ abort("stdio")。
        // ⚠ 不能用 `mrs TPIDRRO_EL0` 探测：客机里 123 处 `mrs` 已全部改写成
        //   `adrp` 指向我们的只读 TLS 页；真实 TPIDRRO_EL0 在这个进程里本来就是 0
        //   （安卓 bionic 不设置它）⇒ 用 mrs 探到 0 是「探针错」而不是「客机错」。
        //   要看客机看到的内容，必须读**我们自己那一页**。
        unsigned long long ro = za_ro_tls_page;   // 由 za_sdk.c 在装载时填
        unsigned int pre0 = 0, pre8 = 0, post8 = 0;
        if (ro)
        {
            memcpy(&pre0, (void *)(uintptr_t)(ro + 0), 4);
            memcpy(&pre8, (void *)(uintptr_t)(ro + 8), 4);
            // 真机上 IPC 完成后内核会把这个「挂起」位置 0；我们替它清，
            // 否则客机在 sdk+0x153f18 的 `cbnz w8` 必然走 abort("stdio")。
            unsigned int zero = 0;
            memcpy((void *)(uintptr_t)(ro + 8), &zero, 4);
            memcpy(&post8, (void *)(uintptr_t)(ro + 8), 4);
        }
        // SDK bss 里的 sm 计数/会话句柄（反汇编 0x153e54 / 0x153efc 得来）
        unsigned int sm_cnt = 0, sm_sess = 0;
        if (za_sdk_base)
        {
            memcpy(&sm_cnt, (void *)(uintptr_t)(za_sdk_base + 0xb9c598), 4);
            memcpy(&sm_sess, (void *)(uintptr_t)(za_sdk_base + 0xb9c59c), 4);
        }
        ZLOGI("svc#33 SendSyncRequest session=%#llx  ro=%p [ro+0]=%#x [ro+8] %#x->%#x  "
              "sm.cnt=%u sm.sess=%u",
              (unsigned long long)(unsigned int)a0, (void *)(uintptr_t)ro,
              pre0, pre8, post8, sm_cnt, sm_sess);
        // IPC 应答：sm 的 GetService 之类需要往缓冲区写回复。
        // 目前最小实现：只保证结果码 0 + 清挂起位，让初始化流程能继续。
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
        // 客机的断言/致命错误：reason 是 BreakReason，info 指向一个 size 字节的值。
        // 把这个值读出来 —— 它能直接指出是哪个断言（模块号/行号）。
        unsigned long long v = 0;
        if (a1 && a2 > 0 && a2 <= 8)
            memcpy(&v, (const void *)(uintptr_t)a1, (size_t)a2);
        ZLOGI("Horizon: Break reason=%#lx info=%#lx size=%ld 值=%#llx",
              (unsigned long)a0, (unsigned long)a1, a2, v);
        // ① info 附近原始字节：断言文本/结构体常紧邻它
        if (a1)
        {
            unsigned long long w0v = 0, w1v = 0, w2v = 0;
            memcpy(&w0v, (const void *)(uintptr_t)a1, 8);
            memcpy(&w1v, (const void *)(uintptr_t)((unsigned long)a1 + 8), 8);
            memcpy(&w2v, (const void *)(uintptr_t)((unsigned long)a1 + 16), 8);
            ZLOGI("  info[0..0x18]=%016llx %016llx %016llx", w0v, w1v, w2v);
        }
        // ② GetInfo 关键 id 的当前值：0x148f80 的 bics 掩码校验依赖它
        {
            extern unsigned long long za_mem_getinfo(long id);
            ZLOGI("  GetInfo: id0(CpuMask)=%#llx id23(IsApplication)=%#llx",
                  za_mem_getinfo(0), za_mem_getinfo(23));
        }
        // 顺便把客机栈里的返回地址扫出来 ⇒ 能看出是哪条调用链走到这个断言
        {
            unsigned long sp = za_horizon_regs[ZA_REG_SP];
            unsigned long sb = za_sdk_base;
            unsigned long sz = za_sdk_size;
            for (int i = 0; i < 96 && sp; i++)
            {
                unsigned long w = *(const unsigned long *)(uintptr_t)(sp + i * 8);
                if (sb && w >= sb && w < sb + sz)
                    ZLOGI("  客机栈[%d] = sdk+%#lx", i, w - sb);
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
long za_horizon_svc(long a0, long a1, long a2, long a3,
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
        static __thread int last_mask = -1;
        if (last_mask != 1)
        {
            sigset_t m;
            sigemptyset(&m);
            sigaddset(&m, SIGALRM);
            sigaddset(&m, SIGUSR1); sigaddset(&m, SIGRTMIN);
            sigaddset(&m, SIGTERM); sigaddset(&m, 63);
            pthread_sigmask(SIG_UNBLOCK, &m, NULL);
            last_mask = 1;
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
    long res = za_horizon_dispatch(a0, a1, a2, a3, a4, a5, a6, a7, nr);
    // 返回值也记进轨迹：客机多数 svc 包装函数是
    //   svc #N ; <收尾> ; ret     —— 返回值直接进 x0/w0
    // 而 0x14457c 收尾前有 cbnz w0, <abort>；把 w0 记下来才能判定
    // 崩点究竟是「走了 abort 分支」还是「ret 取到 0」。
    za_svc_trace_ret(res);
    (void)a0; (void)a1; (void)a2; (void)a3;
    (void)a4; (void)a5; (void)a6; (void)a7;
    return res;
}
