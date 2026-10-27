// NVN 图形接口层（第一阶段：影子对象 + 语义桩）
//
// 事实依据（真机日志 + 静态分析）：
//   · main 只导入 nvnBootstrapLoader 一个符号（GOT 槽 0x3ce9b70）。
//   · main+0x1779834 是懒加载入口：它先取 nvnBootstrapLoader("nvnDeviceInitialize") 和
//     nvnBootstrapLoader("nvnDeviceGetProcAddress")，然后把 procaddr 当函数指针用，
//     以 (device=NULL, 名字) 的形式一次性解析 534 个 nvn* 入口，存进自己的全局表。
//     所以本文件必须让**任意名字**都能拿到一个可调用的地址（拿到 NULL 客机会直接跳空）。
//
// 本阶段的定位：所有入口都「可调用、返回合理值、对象字段自洽」，但不产生任何 GPU 工作。
//   · 对象是我们自己的影子结构：客机传进来的内存指针就是对象本体，字段偏移由本文件定义
//     （客机只会把对象指针再传回来，从不读内部，所以布局可以自定）；
//   · 内存池/缓冲/贴图的「GPU 地址」= 客机给的真实内存地址（后续接真 GPU 时可直接零拷贝）；
//   · 每个入口首次调用打一行日志（带参数），方便按真实调用序继续往下实现；
//   · 未单独实现语义的入口统一走 za_nvn_unknown，只报一次名字。
//
// 已确认的 NVN 对象尺寸（d2r-and 参考头 nvn.h）：device 0x3000 / queue 0x2000 /
// window 0x180 / texture 0xC0 / commandBuffer 0xA0 / memoryPool 0x100 / program 0xC0 /
// sync 0x40 / event 0x40 / buffer 0x30 / sampler 0x30 / 各种 builder 0x40~0x80。
// 我们的字段一律放在对象前 0x80 字节内，绝不会越过最小对象尺寸。
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#include "za_common.h"
#include "za_guest_info.h"
#include "za_nvn.h"
#include "za_nvn_names.h"

extern unsigned char *za_guest_base;
extern volatile unsigned long za_sdk_base, za_sdk_size;

typedef uint64_t u64;
typedef uint32_t u32;

// ── 名字表 / id ────────────────────────────────────────────────────────
#define ZA_NVN_ID_ITEM(n) ZA_NVN_ID_##n,
enum { ZA_NVN_ENUM(ZA_NVN_ID_ITEM) };
#undef ZA_NVN_ID_ITEM

#define ZA_NVN_NAME_ITEM(n) [ZA_NVN_ID_##n] = #n,
static const char *const za_nvn_name[ZA_NVN_COUNT] = { ZA_NVN_ENUM(ZA_NVN_NAME_ITEM) };
#undef ZA_NVN_NAME_ITEM

static u64 za_nvn_calls[ZA_NVN_COUNT];
static u32 za_nvn_logged[ZA_NVN_COUNT];

// ── 影子对象字段（我们自己定义布局）────────────────────────────────────
//  建在客机给的对象内存上；偏移都 < 0x80。
enum {
    // 通用
    F_MAGIC = 0x00,
    F_FLAGS = 0x08,
    F_DEVICE = 0x10,
    F_MEMORY = 0x18,
    F_SIZE = 0x20,
    F_OFFSET = 0x28,
    F_FLAGS2 = 0x30,      // 第二组标志 / 计数
    F_W = 0x38,
    F_H = 0x3c,
    F_D = 0x40,
    F_LEVELS = 0x44,
    F_FORMAT = 0x48,
    F_SAMPLES = 0x4c,
    F_TARGET = 0x50,
    F_SWIZZLE = 0x54,
    F_DSM = 0x58,
    F_STRIDE = 0x5c,
    F_POOL = 0x60,
    F_POOLOFF = 0x68,
    F_ADDR = 0x70,
    F_EXTRA = 0x78,
};

#define M_MAGIC 0x4e564e31u /* "NVN1"（已不再写进客机内存，仅作历史标记保留） */

// ════════════════════════════════════════════════════════════════════════
// 影子状态表：**NVN 对象的所有字段都存在宿主内存里，一个字节都不写客机对象**
// ════════════════════════════════════════════════════════════════════════
// 真机证据链（2026-10-28）：
//   ① 崩溃地址 0x4e564e39 = 我们在对象偏移 0 写的魔数 0x4e564e31+8 ——
//      客机的哈希表把对象第一个字当链指针走，魔数被当地址解引用。
//   ② /proc/self/maps 显示客机传进来的 NVN 对象（0x6f3b11ebc8 /
//      0x6e2b11b290 / 0x6f1b1024e0 …）**全部落在 [anon:scudo:primary]**：
//      客机的分配器和宿主共用一个堆。
//   ③ 这套 SDK 的 NVN 对象比参考头文件小（已证实 sampler builder 是 0x40）。
//      init_obj 以前无条件 memset 0x100 字节 ⇒ 越过对象尾部写坏相邻块：
//      实测把 ART 的 JIT arena（同一 Scudo 区，只差 0x90 字节）虚表清零
//      ⇒ "Jit thread pool" 崩在 MemMapArenaPool::TrimMaps；也见过
//      'Scudo ERROR: corrupted chunk header'。
//   ⇒ 对象状态全放这里，客机对象**一个字节都不写**（builder 同样：以前
//     memset 0x40 踩过栈上保存的 x29/x30）。
#define ZA_NVN_SHADOW_N 8192
#define ZA_NVN_SHADOW_SZ 0x100
static unsigned char za_nvn_shadow_mem[ZA_NVN_SHADOW_N][ZA_NVN_SHADOW_SZ];
static uintptr_t za_nvn_shadow_key[ZA_NVN_SHADOW_N];   // 0 = 空槽

static int za_nvn_shadow_idx(const void *p)
{
    uintptr_t v = (uintptr_t)p;
    if (!v) return -1;
    unsigned h = (unsigned)((v >> 4) * 2654435761u) & (ZA_NVN_SHADOW_N - 1);
    for (unsigned i = 0; i < ZA_NVN_SHADOW_N; i++) {
        unsigned k = (h + i) & (ZA_NVN_SHADOW_N - 1);
        uintptr_t cur = __atomic_load_n(&za_nvn_shadow_key[k], __ATOMIC_ACQUIRE);
        if (cur == v) return (int)k;
        if (!cur) return -1;
    }
    return -1;
}

static unsigned char *za_nvn_shadow_mut(const void *p)
{
    uintptr_t v = (uintptr_t)p;
    if (!v) return NULL;
    unsigned h = (unsigned)((v >> 4) * 2654435761u) & (ZA_NVN_SHADOW_N - 1);
    for (unsigned i = 0; i < ZA_NVN_SHADOW_N; i++) {
        unsigned k = (h + i) & (ZA_NVN_SHADOW_N - 1);
        uintptr_t cur = __atomic_load_n(&za_nvn_shadow_key[k], __ATOMIC_ACQUIRE);
        if (cur == v) return za_nvn_shadow_mem[k];
        if (!cur) {
            if (__atomic_compare_exchange_n(&za_nvn_shadow_key[k], &cur, v, 0,
                                            __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE))
                return za_nvn_shadow_mem[k];
            if (cur == v) return za_nvn_shadow_mem[k];
        }
    }
    static int warned;
    if (!warned++) ZLOGE("★ NVN 影子表已满（%d 个对象）", ZA_NVN_SHADOW_N);
    return NULL;
}

static inline u64 ld64(const void *p, u32 off)
{
    int k = za_nvn_shadow_idx(p);
    u64 v;
    if (k >= 0) memcpy(&v, za_nvn_shadow_mem[k] + off, 8);
    else memcpy(&v, (const char *)p + off, 8);
    return v;
}
static inline u32 ld32(const void *p, u32 off)
{
    int k = za_nvn_shadow_idx(p);
    u32 v;
    if (k >= 0) memcpy(&v, za_nvn_shadow_mem[k] + off, 4);
    else memcpy(&v, (const char *)p + off, 4);
    return v;
}
// 写：只写影子。没有影子的指针（没 init 过的）直接忽略 —— 往一个来路不明
// 的地址写字节以前把宿主堆写坏过，宁可什么也不做。
static inline void st64(void *p, u32 off, u64 v)
{
    int k = za_nvn_shadow_idx(p);
    if (k >= 0) memcpy(za_nvn_shadow_mem[k] + off, &v, 8);
}
static inline void st32(void *p, u32 off, u32 v)
{
    int k = za_nvn_shadow_idx(p);
    if (k >= 0) memcpy(za_nvn_shadow_mem[k] + off, &v, 4);
}
static inline int is_obj(const void *p) { return za_nvn_shadow_idx(p) >= 0; }
static void init_obj(void *p, u64 size)
{
    unsigned char *s2 = za_nvn_shadow_mut(p);
    if (!s2) return;
    if (size > ZA_NVN_SHADOW_SZ) size = ZA_NVN_SHADOW_SZ;
    memset(s2, 0, (size_t)size);
}

// 贴图行跨度：客机 SetStride(0) 表示「自动」，真 NVN 会按格式算出来。
// 我们以前一律返回 0 ⇒ 客机拿 0 去算上传大小/循环条件会卡住。
// 常见格式按 4 字节/纹素算（0x25 = RGBA8），行对齐 64 字节（Tegra 的要求）。
static u64 za_nvn_tex_stride(const void *o)
{
    u32 w = ld32(o, F_W);
    u32 stride = ld32(o, F_STRIDE);
    if (stride) return stride;
    if (!w) return 64;
    return ((u64)w * 4 + 63) & ~63ull;
}

// 贴图存储量估算：客机拿它给自己的内存池定尺寸，稍微给大一点是安全的。
static u64 za_nvn_tex_bytes(const void *b)
{
    u64 w = ld32(b, F_W) ? ld32(b, F_W) : 1;
    u64 h = ld32(b, F_H) ? ld32(b, F_H) : 1;
    u64 d = ld32(b, F_D) ? ld32(b, F_D) : 1;
    u64 lv = ld32(b, F_LEVELS) ? ld32(b, F_LEVELS) : 1;
    u64 sm = ld32(b, F_SAMPLES) ? ld32(b, F_SAMPLES) : 1;
    u64 bytes = (u64)(((w * 4 + 63) & ~63ull)) * h * d * sm;
    if (lv > 1) bytes *= 2;
    return (bytes + 0xfff) & ~0xfffull;
}

static u64 za_nvn_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000000ull + (u64)ts.tv_nsec;
}

// 设备属性表：Tegra X1 实测值。
// 出处：d2r-and 的 dm/gfx/nvn/hle_nvn.c（那边在 SMO 上逐项调 nvnDeviceGetInteger 量出来的，
// 与 nnheaders nvn_DeviceConstantsNX.h 一致）。0x00/0x01 是 API 版本，游戏只读不比较。
// ⚠ 原型是 `void nvnDeviceGetInteger(dev, what, int *out)` —— 结果**写指针**，
//   不是返回值。之前这里把值当返回值给、没写 out，客机读到的就是栈上的垃圾。
static const int za_nvn_devinfo[] = {
    [0x00] = 53, [0x01] = 311, [0x02] = 14, [0x03] = 65536, [0x04] = 256, [0x05] = 8,
    [0x06] = 16, [0x07] = 4, [0x08] = 16, [0x09] = 32, [0x0A] = 16, [0x0B] = 4,
    [0x0C] = 4, [0x0D] = 4, [0x0E] = 16, [0x0F] = 32, [0x10] = 32, [0x11] = 256,
    [0x12] = 256, [0x13] = 4, [0x14] = 8, [0x15] = 512, [0x16] = 256, [0x17] = 2,
    [0x18] = 256, [0x19] = 4096, [0x1A] = 131072, [0x1B] = 16, [0x1C] = 1536,
    [0x1D] = 1024, [0x1E] = 64, [0x1F] = 1536, [0x20] = 65535, [0x21] = 65535,
    [0x22] = 65535, [0x23] = 8, [0x24] = 1048576, [0x25] = 4096, [0x26] = 16,
    [0x27] = 4096, [0x28] = 1, [0x29] = 1, [0x2A] = 1, [0x2B] = 262144, [0x2C] = 15,
    [0x2D] = 2048, [0x2E] = 1, [0x2F] = 1, [0x30] = 14, [0x31] = 5, [0x32] = 1,
    [0x33] = 8, [0x34] = 8, [0x35] = 4, [0x36] = 32, [0x37] = 128, [0x38] = 32,
    [0x39] = 128, [0x3A] = 65536, [0x3B] = 1, [0x3C] = 4, [0x3D] = 16384,
    [0x3E] = 134217728, [0x3F] = 2048, [0x40] = 16384, [0x41] = 16384, [0x42] = 1,
    [0x43] = 1, [0x44] = 1, [0x45] = 1, [0x46] = 5, [0x47] = 1, [0x48] = 1, [0x49] = 1,
    [0x4A] = 1, [0x4B] = 1, [0x4C] = 1, [0x4D] = 16, [0x4E] = 1024, [0x4F] = 32,
    [0x50] = 4096, [0x51] = 65536, [0x52] = 65536, [0x53] = 256, [0x54] = 16384,
    [0x55] = 262144, [0x56] = 4096, [0x57] = 1, [0x58] = 4, [0x59] = 2, [0x5A] = 0,
    [0x5B] = 4096, [0x5C] = 16384, [0x5D] = 4096, [0x5E] = 128, [0x5F] = 4096,
};

// 状态对象（blend/color/depth…）没有 CPU 可见结果，只需要默认值 + get/set 自洽：
// 我们把第一个参数当作对象，按 (id, 字段序号) 存在对象前 0x80 字节里。
// 约定：*Set*(obj, a, v) 存 a 字段；*Get* 读回。字段地址由 id 高位区分。
static void za_nvn_state_set(void *obj, int field, u64 v) { st64(obj, (u32)(8 + field * 8), v); }
static u64 za_nvn_state_get(const void *obj, int field) { return ld64(obj, (u32)(8 + field * 8)); }

// ── 未实现入口 ────────────────────────────────────────────────────────
static u64 za_nvn_unknown_impl(u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6,
                               u64 a7);

// ── 名字解析 ──────────────────────────────────────────────────────────
static void *za_nvn_fn_ptr[ZA_NVN_COUNT];

void *za_nvn_lookup(const char *name)
{
    int i;
    if (!name) return NULL;
    for (i = 0; i < ZA_NVN_COUNT; i++) {
        if (strcmp(name, za_nvn_name[i]) == 0) return za_nvn_fn_ptr[i];
    }
    return NULL;
}

// ── 派发 ──────────────────────────────────────────────────────────────
// ⚠ 带 guest_lr：客机调我们时 x30 就是「它下一步要执行的地方」。崩溃发生在
//   某个 NVN 调用**返回之后**时，仅凭调用名看不出客机在做什么；有了 LR 就能
//   直接反汇编那条 `blr` 后面的几条指令。
static u64 za_nvn_call(int id, unsigned long guest_lr, u64 guest_fp, u64 a0, u64 a1, u64 a2,
                       u64 a3, u64 a4, u64 a5, u64 a6, u64 a7);

// 每个入口一个函数：地址稳定、名字可查（客机只会拿指针调用）。
#define ZA_NVN_FN_DEF(n)                                                                 \
    static u64 za_nvn_fn_##n(u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6,      \
                             u64 a7)                                                       \
    {                                                                                      \
        unsigned long lr, fp;                                                               \
        __asm__ __volatile__("mov %0, x30" : "=r"(lr));                                     \
        __asm__ __volatile__("mov %0, x29" : "=r"(fp));                                     \
        return za_nvn_call(ZA_NVN_ID_##n, lr, fp, a0, a1, a2, a3, a4, a5, a6, a7);          \
    }
ZA_NVN_ENUM(ZA_NVN_FN_DEF)
#undef ZA_NVN_FN_DEF

static void za_nvn_init_ptr_table(void)
{
    static int done;
    if (done) return;
    done = 1;
#define ZA_NVN_PTR_ITEM(n) za_nvn_fn_ptr[ZA_NVN_ID_##n] = (void *)&za_nvn_fn_##n;
    ZA_NVN_ENUM(ZA_NVN_PTR_ITEM)
#undef ZA_NVN_PTR_ITEM
}

static u64 za_nvn_unknown_impl(u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6,
                               u64 a7)
{
    (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5; (void)a6; (void)a7;
    return 0;
}

// ── 最近调用环形缓冲（客机 Panic/断言时由崩溃处理器打印）────────────
// 只记「谁、前两个参数、返回值」——足够定位 panic 前最后几步 NVN 调用。
#define ZA_NVN_HIST 64
typedef struct {
    unsigned id;
    unsigned long lr;     /* 客机侧返回地址（= 客机那条 blr 的下一条） */
    u64 a0, a1, ret;
} za_nvn_hist_t;
static za_nvn_hist_t za_nvn_hist[ZA_NVN_HIST];
static unsigned za_nvn_hist_n;

void za_nvn_dump_recent(void)
{
    unsigned n = za_nvn_hist_n < ZA_NVN_HIST ? za_nvn_hist_n : ZA_NVN_HIST;
    ZLOGI("NVN 最近 %u 次调用（旧 → 新）：", n);
    for (unsigned k = 0; k < n; k++) {
        unsigned i = (za_nvn_hist_n - n + k) % ZA_NVN_HIST;
        const za_nvn_hist_t *h = &za_nvn_hist[i];
        ZLOGI("    %s(a0=%#llx a1=%#llx) -> %#llx  lr=%#lx", za_nvn_name[h->id],
              (unsigned long long)h->a0, (unsigned long long)h->a1,
              (unsigned long long)h->ret, h->lr);
    }
}

// ── 60Hz 帧驱动 + 帧循环计数 ─────────────────────────────────────────
// 目的：① 给「GPU 侧会完成」一个真实的时间轴（同步对象/呈现计数随时间推进）；
//       ② 用 submit/acquire/present 的计数直接判断游戏有没有进入帧循环。
// ⚠ tick 线程**只碰宿主计数器**，不解引用任何客机对象 —— 那些对象可能已经被
//   客机释放，从另一个线程解引用会随机炸（之前就吃过这种亏）。
static volatile u64 za_nvn_submits, za_nvn_acquires, za_nvn_presents;
static volatile u64 za_nvn_ticks;
static volatile int za_nvn_tick_run;
static pthread_t za_nvn_tick_th;
static int za_nvn_tick_started;

static void *za_nvn_tick_main(void *p)
{
    (void)p;
    while (za_nvn_tick_run) {
        struct timespec ts = { 0, 16666667 };
        nanosleep(&ts, NULL);
        za_nvn_ticks++;
        // ★ 停摆侦测：NVN 进展（贴图/命令缓冲/提交/呈现）20 秒没变 ⇒ 主动给客机
        //   主线程发 SIGSEGV 让致命处理器把客机调用栈倒进 files/za_fatal.log。
        //   客机整体睡死时 svc 计数还在缓慢增长（条件变量分片返回），按 svc 判卡死
        //   永远不会触发，只能按「真正有用的进展」判。
        {
            static u64 last_prog;
            static unsigned long long last_change;
            u64 prog = za_nvn_calls[ZA_NVN_ID_nvnTextureInitialize] +
                       za_nvn_calls[ZA_NVN_ID_nvnCommandBufferBeginRecording] +
                       za_nvn_calls[ZA_NVN_ID_nvnQueueSubmitCommands] + za_nvn_presents;
            if (prog != last_prog) { last_prog = prog; last_change = za_nvn_ticks; }
            else if (za_nvn_ticks - last_change == 1800) {   // 30 秒
                extern volatile long za_guest_tid;
                ZLOGE("★ NVN 30 秒无进展 ⇒ 倒客机栈（tid=%ld）", za_guest_tid);
                if (za_guest_tid > 0)
                    syscall(SYS_tgkill, (int)getpid(), (int)za_guest_tid, 11);
            }
        }
        if ((za_nvn_ticks % 300) == 0)
            ZLOGI("★ NVN 帧驱动：%llu tick，submit=%llu acquire=%llu present=%llu"
                  " tex=%llu buf=%llu cmd=%llu",
                  (unsigned long long)za_nvn_ticks, (unsigned long long)za_nvn_submits,
                  (unsigned long long)za_nvn_acquires, (unsigned long long)za_nvn_presents,
                  (unsigned long long)za_nvn_calls[ZA_NVN_ID_nvnTextureInitialize],
                  (unsigned long long)za_nvn_calls[ZA_NVN_ID_nvnBufferInitialize],
                  (unsigned long long)za_nvn_calls[ZA_NVN_ID_nvnCommandBufferBeginRecording]);
        {
            extern volatile unsigned long za_svc_nr_count[64];
            static unsigned long prev[64];
            char lb[256];
            int n = snprintf(lb, sizeof lb, "   svc 增量:");
            int changed = 0;
            for (int i = 0; i < 64; i++) {
                unsigned long c = za_svc_nr_count[i];
                if (c != prev[i]) {
                    if (n > 0 && n < (int)sizeof lb - 24) {
                        n += snprintf(lb + n, sizeof lb - (size_t)n, " #%d+%lu", i, c - prev[i]);
                        changed = 1;
                    }
                    prev[i] = c;
                }
            }
            if (changed) ZLOGI("%s", lb);
        }
    }
    return NULL;
}

static void za_nvn_tick_start(void)
{
    if (za_nvn_tick_started) return;
    za_nvn_tick_started = 1;
    za_nvn_tick_run = 1;
    if (pthread_create(&za_nvn_tick_th, NULL, za_nvn_tick_main, NULL) != 0) {
        za_nvn_tick_run = 0;
        ZLOGE("NVN 帧驱动线程创建失败");
    } else {
        ZLOGI("★ NVN 帧驱动线程已启动（60Hz）");
    }
}

static u64 za_nvn_dispatch(int id, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6,
                           u64 a7);

// 沿着客机的 x29 链倒出调用栈。用途：某个 NVN 入口被反复调用时（例如贴图
// 占位资源被无限重建），直接看是哪段客机代码在循环，而不是靠参数猜。
// 只跟随「严格向高地址、且跨度合理」的帧，避免把野指针当帧指针解引用。
static void za_nvn_dump_guest_stack(u64 fp0, const char *why)
{
    unsigned long long mb = (unsigned long long)(uintptr_t)za_guest_base;
    unsigned long long sb = (unsigned long long)za_sdk_base;
    unsigned long long ss = (unsigned long long)za_sdk_size;
    unsigned long long fp = fp0;
    ZLOGI("★ NVN 循环诊断（%s）：客机调用栈", why);
    for (int i = 0; i < 40; i++) {
        if (!fp || (fp & 7u)) break;
        unsigned long long nf = *(volatile unsigned long long *)(uintptr_t)fp;
        unsigned long long lr = *(volatile unsigned long long *)(uintptr_t)(fp + 8);
        if (lr >= mb && lr < mb + ZA_IMAGE_SIZE)
            ZLOGI("    [%d] fp=%#llx lr=main+%#llx", i, fp, lr - mb);
        else if (lr >= sb && lr < sb + ss)
            ZLOGI("    [%d] fp=%#llx lr=sdk+%#llx", i, fp, lr - sb);
        else
            ZLOGI("    [%d] fp=%#llx lr=%#llx", i, fp, lr);
        if (nf <= fp || nf - fp > 0x100000ull) break;
        fp = nf;
    }
}

static u64 za_nvn_call(int id, unsigned long guest_lr, u64 guest_fp, u64 a0, u64 a1, u64 a2,
                       u64 a3, u64 a4, u64 a5, u64 a6, u64 a7)
{
    u64 r = za_nvn_dispatch(id, a0, a1, a2, a3, a4, a5, a6, a7);
    // 只对「被海量重复调用」的入口做栈诊断：第 400 次一次，之后每 4000 次一次，
    // 避免刷爆日志。
    if ((id == ZA_NVN_ID_nvnTextureInitialize || id == ZA_NVN_ID_nvnTexturePoolRegisterTexture ||
         id == ZA_NVN_ID_nvnBufferInitialize) &&
        (za_nvn_calls[id] == 60 || (za_nvn_calls[id] % 2000) == 0))
        za_nvn_dump_guest_stack(guest_fp, za_nvn_name[id]);
    za_nvn_hist_t *h = &za_nvn_hist[za_nvn_hist_n % ZA_NVN_HIST];
    h->id = (unsigned)id;
    h->lr = guest_lr;
    h->a0 = a0;
    h->a1 = a1;
    h->ret = r;
    za_nvn_hist_n++;
    return r;
}

static u64 za_nvn_dispatch(int id, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6,
                           u64 a7)
{
    void *o = (void *)(uintptr_t)a0;

    if (za_nvn_logged[id] < 2) {
        ZLOGI("★ NVN %s(a0=%#llx a1=%#llx a2=%#llx a3=%#llx a4=%#llx)", za_nvn_name[id],
              (unsigned long long)a0, (unsigned long long)a1, (unsigned long long)a2,
              (unsigned long long)a3, (unsigned long long)a4);
        za_nvn_logged[id]++;
    }
    za_nvn_calls[id]++;

    switch (id) {
    // ── 设备 ──────────────────────────────────────────────────────────
    case ZA_NVN_ID_nvnDeviceBuilderSetDefaults:
        init_obj(o, 0x40);
        return 0;
    case ZA_NVN_ID_nvnDeviceBuilderSetFlags:
        if (is_obj(o)) st32(o, F_FLAGS, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnDeviceBuilderGetFlags:
        return is_obj(o) ? ld32(o, F_FLAGS) : 0;
    case ZA_NVN_ID_nvnDeviceInitialize: {
        const void *b = (const void *)(uintptr_t)a1;
        init_obj(o, 0x3000);
        if (is_obj(b)) st32(o, F_FLAGS, ld32(b, F_FLAGS));
        ZLOGI("★ NVN 设备已建立（flags=%#x）", is_obj(b) ? ld32(b, F_FLAGS) : 0);
        return 1;
    }
    case ZA_NVN_ID_nvnDeviceFinalize:
        return 0;
    case ZA_NVN_ID_nvnDeviceGetProcAddress: {
        void *fn = za_nvn_lookup((const char *)(uintptr_t)a1);
        if (!fn) {
            ZLOGI("★ NVN 客机要的入口不在表里：%s（给通用桩）", (const char *)(uintptr_t)a1);
            fn = (void *)&za_nvn_unknown_impl;
        }
        // ⚠ 不要往 device 里写任何东西：main 解析整张表时传的 device 是 NULL
        //   （nvnDeviceGetProcAddress(NULL, 名字) 取「全局函数」），写影子字段
        //   会直接落到 0x0+0x78 ⇒ SIGSEGV @ addr=0x78（真机实测）。
        return (u64)(uintptr_t)fn;
    }
    case ZA_NVN_ID_nvnDeviceGetInteger: {
        // 原型：void nvnDeviceGetInteger(const NVNdevice*, NVNdeviceInfo, int*)
        int *out = (int *)(uintptr_t)a2;
        unsigned what = (unsigned)a1;
        int v = 0;
        if (what < sizeof za_nvn_devinfo / sizeof za_nvn_devinfo[0])
            v = za_nvn_devinfo[what];
        else
            ZLOGI("★ NVN DeviceGetInteger 未知项 %#x（给 0）", what);
        if (out) *out = v;
        return 0;
    }
    case ZA_NVN_ID_nvnDeviceGetCurrentTimestampInNanoseconds:
    case ZA_NVN_ID_nvnDeviceGetTimestampInNanoseconds:
        if (a1) st64((void *)(uintptr_t)a1, 0, za_nvn_now_ns());
        return za_nvn_now_ns();
    case ZA_NVN_ID_nvnDeviceGenerateDebugDomainId:
        st32(o, F_EXTRA, ld32(o, F_EXTRA) + 1);
        return ld32(o, F_EXTRA);
    case ZA_NVN_ID_nvnDeviceIsExternalDebuggerAttached:
        return 0;
    // 贴图句柄：低 20 位是贴图描述符号，高位是采样器号（与 NVN 的位布局一致）
    case ZA_NVN_ID_nvnDeviceGetTextureHandle:
        return (u64)(u32)a1 | ((u64)(u32)a2 << 20);
    case ZA_NVN_ID_nvnDeviceGetTexelFetchHandle:
    case ZA_NVN_ID_nvnDeviceGetImageHandle:
        return (u64)(u32)a1;
    case ZA_NVN_ID_nvnDeviceGetSeparateTextureHandle:
        return (u64)(u32)a1;
    case ZA_NVN_ID_nvnDeviceGetSeparateSamplerHandle:
        return (u64)(u32)a1 << 20;
    case ZA_NVN_ID_nvnDeviceGetWindowOriginMode:
        return 0;
    case ZA_NVN_ID_nvnDeviceGetDepthMode:
        return 0;

    // ── 内存池 ────────────────────────────────────────────────────────
    case ZA_NVN_ID_nvnMemoryPoolBuilderSetDefaults:
        init_obj(o, 0x40);
        return 0;
    case ZA_NVN_ID_nvnMemoryPoolBuilderSetDevice:
        if (is_obj(o)) st64(o, F_DEVICE, a1);
        return 0;
    case ZA_NVN_ID_nvnMemoryPoolBuilderSetStorage:
        if (is_obj(o)) {
            st64(o, F_MEMORY, a1);
            st64(o, F_SIZE, a2);
        }
        return 0;
    case ZA_NVN_ID_nvnMemoryPoolBuilderSetFlags:
        if (is_obj(o)) st32(o, F_FLAGS2, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnMemoryPoolBuilderGetDevice:
        return is_obj(o) ? ld64(o, F_DEVICE) : 0;
    case ZA_NVN_ID_nvnMemoryPoolBuilderGetMemory:
        return is_obj(o) ? ld64(o, F_MEMORY) : 0;
    case ZA_NVN_ID_nvnMemoryPoolBuilderGetSize:
        return is_obj(o) ? ld64(o, F_SIZE) : 0;
    case ZA_NVN_ID_nvnMemoryPoolBuilderGetFlags:
        return is_obj(o) ? ld32(o, F_FLAGS2) : 0;
    case ZA_NVN_ID_nvnMemoryPoolInitialize: {
        const void *b = (const void *)(uintptr_t)a1;
        init_obj(o, 0x100);
        if (is_obj(b)) {
            st64(o, F_MEMORY, ld64(b, F_MEMORY));
            st64(o, F_SIZE, ld64(b, F_SIZE));
            st32(o, F_FLAGS2, ld32(b, F_FLAGS2));
            st64(o, F_ADDR, ld64(b, F_MEMORY));
        }
        return 1;
    }
    case ZA_NVN_ID_nvnMemoryPoolFinalize:
        return 0;
    case ZA_NVN_ID_nvnMemoryPoolMap:
    case ZA_NVN_ID_nvnMemoryPoolGetBufferAddress:
        return is_obj(o) ? ld64(o, F_ADDR) : 0;
    case ZA_NVN_ID_nvnMemoryPoolGetSize:
        return is_obj(o) ? ld64(o, F_SIZE) : 0;
    case ZA_NVN_ID_nvnMemoryPoolGetFlags:
        return is_obj(o) ? ld32(o, F_FLAGS2) : 0;
    case ZA_NVN_ID_nvnMemoryPoolMapVirtual:
        return 0;

    // ── 队列 ──────────────────────────────────────────────────────────
    case ZA_NVN_ID_nvnQueueBuilderSetDefaults:
        init_obj(o, 0x40);
        st32(o, F_FLAGS2, 1); // priority 默认 1
        return 0;
    case ZA_NVN_ID_nvnQueueBuilderSetDevice:
    case ZA_NVN_ID_nvnQueueBuilderSetQueueMemory:
        if (is_obj(o)) st64(o, F_DEVICE, a1);
        return 0;
    case ZA_NVN_ID_nvnQueueBuilderSetFlags:
    case ZA_NVN_ID_nvnQueueBuilderSetQueuePriority:
        if (is_obj(o)) st32(o, F_FLAGS, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnQueueBuilderSetCommandMemorySize:
        if (is_obj(o)) st64(o, F_MEMORY, a1);
        return 0;
    case ZA_NVN_ID_nvnQueueBuilderSetComputeMemorySize:
        if (is_obj(o)) st64(o, F_SIZE, a1);
        return 0;
    case ZA_NVN_ID_nvnQueueBuilderSetControlMemorySize:
        if (is_obj(o)) st64(o, F_POOL, a1);
        return 0;
    case ZA_NVN_ID_nvnQueueBuilderSetCommandFlushThreshold:
        if (is_obj(o)) st64(o, F_POOLOFF, a1);
        return 0;
    case ZA_NVN_ID_nvnQueueBuilderGetDevice:
        return is_obj(o) ? ld64(o, F_DEVICE) : 0;
    case ZA_NVN_ID_nvnQueueBuilderGetFlags:
        return is_obj(o) ? ld32(o, F_FLAGS) : 0;
    case ZA_NVN_ID_nvnQueueBuilderGetQueuePriority:
        return is_obj(o) ? ld32(o, F_FLAGS2) : 1;
    case ZA_NVN_ID_nvnQueueBuilderGetCommandMemorySize:
        return is_obj(o) ? ld64(o, F_MEMORY) : 0;
    case ZA_NVN_ID_nvnQueueBuilderGetComputeMemorySize:
        return is_obj(o) ? ld64(o, F_SIZE) : 0;
    case ZA_NVN_ID_nvnQueueBuilderGetControlMemorySize:
        return is_obj(o) ? ld64(o, F_POOL) : 0;
    case ZA_NVN_ID_nvnQueueBuilderGetCommandFlushThreshold:
        return is_obj(o) ? ld64(o, F_POOLOFF) : 0;
    case ZA_NVN_ID_nvnQueueBuilderGetQueueMemorySize:
    case ZA_NVN_ID_nvnQueueBuilderGetMemorySize:
        if (!is_obj(o)) return 0;
        return ld64(o, F_MEMORY) + ld64(o, F_SIZE) + ld64(o, F_POOL);
    case ZA_NVN_ID_nvnQueueBuilderGetMemory:
        return is_obj(o) ? ld64(o, F_DEVICE) : 0;
    case ZA_NVN_ID_nvnQueueInitialize: {
        za_nvn_tick_start();
        const void *b = (const void *)(uintptr_t)a1;
        init_obj(o, 0x2000);
        if (is_obj(b)) {
            st64(o, F_DEVICE, ld64(b, F_DEVICE));
            st64(o, F_MEMORY, ld64(b, F_MEMORY));
            st64(o, F_SIZE, ld64(b, F_SIZE));
            st64(o, F_POOL, ld64(b, F_POOL));
        }
        return 1;
    }
    case ZA_NVN_ID_nvnQueuePresentTexture:
        za_nvn_presents++;
        if (za_nvn_presents <= 4 || (za_nvn_presents % 120) == 0)
            ZLOGI("★ NVN 呈现 #%llu", (unsigned long long)za_nvn_presents);
        return 0;
    case ZA_NVN_ID_nvnQueueFinalize:
    case ZA_NVN_ID_nvnQueueFlush:
    case ZA_NVN_ID_nvnQueueFinish:
    case ZA_NVN_ID_nvnQueueGetError:
    case ZA_NVN_ID_nvnQueueResetMemoryUsageCounts:
        return 0;
    case ZA_NVN_ID_nvnQueueSubmitCommands:
        za_nvn_submits++;
        if (za_nvn_submits <= 4 || (za_nvn_submits % 120) == 0)
            ZLOGI("★ NVN 提交命令缓冲 #%llu（本次 %llu 个）",
                  (unsigned long long)za_nvn_submits, (unsigned long long)a1);
        return 0;
    case ZA_NVN_ID_nvnQueueGetTotalCommandMemoryUsed:
        return is_obj(o) ? ld64(o, F_MEMORY) : 0;
    case ZA_NVN_ID_nvnQueueGetTotalComputeMemoryUsed:
        return is_obj(o) ? ld64(o, F_SIZE) : 0;
    case ZA_NVN_ID_nvnQueueGetTotalControlMemoryUsed:
        return is_obj(o) ? ld64(o, F_POOL) : 0;
    case ZA_NVN_ID_nvnQueueFenceSync: {
        void *sync = (void *)(uintptr_t)a1;
        u64 fence = is_obj(o) ? ld64(o, F_EXTRA) + 1 : 1;
        if (is_obj(o)) st64(o, F_EXTRA, fence);
        if (is_obj(sync)) {
            st64(sync, F_SIZE, fence);
            st32(sync, F_FLAGS, 1);
        }
        return 1;
    }

    // ── 窗口 ──────────────────────────────────────────────────────────
    // ⚠ NVNwindowBuilder 也是 0x40 字节、且客机常放在栈上（与 sampler builder
    //   同一类风险：写超过 0x40 会改掉保存的 x29/x30 ⇒ ret 跳飞）。
    //   紧凑布局：0x00 magic / 0x08 device / 0x10 nativeWindow / 0x18 textures
    //             0x20 numTextures / 0x24 presentInterval / 0x28 numActive
    case ZA_NVN_ID_nvnWindowBuilderSetDefaults:
        init_obj(o, 0x40);
        st32(o, 0x24, 1);   // presentInterval
        st32(o, 0x28, 1);   // numActiveTextures
        return 0;
    case ZA_NVN_ID_nvnWindowBuilderSetDevice:
        if (is_obj(o)) st64(o, 0x08, a1);
        return 0;
    case ZA_NVN_ID_nvnWindowBuilderSetNativeWindow:
        if (is_obj(o)) st64(o, 0x10, a1);
        return 0;
    case ZA_NVN_ID_nvnWindowBuilderSetTextures:
        if (is_obj(o)) {
            st64(o, 0x18, a1);
            st32(o, 0x20, (u32)a2);
        }
        return 0;
    case ZA_NVN_ID_nvnWindowBuilderSetPresentInterval:
        if (is_obj(o)) st32(o, 0x24, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnWindowBuilderSetNumActiveTextures:
        if (is_obj(o)) st32(o, 0x28, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnWindowBuilderGetDevice:
        return is_obj(o) ? ld64(o, 0x08) : 0;
    case ZA_NVN_ID_nvnWindowBuilderGetNumTextures:
        return is_obj(o) ? ld32(o, 0x20) : 0;
    case ZA_NVN_ID_nvnWindowBuilderGetTexture: {
        u64 base;
        if (!is_obj(o)) return 0;
        base = ld64(o, 0x18);
        return base ? ld64((const void *)(uintptr_t)base, (u32)(a1 * 8)) : 0;
    }
    case ZA_NVN_ID_nvnWindowBuilderGetNativeWindow:
        return is_obj(o) ? ld64(o, 0x10) : 0;
    case ZA_NVN_ID_nvnWindowBuilderGetPresentInterval:
        return is_obj(o) ? ld32(o, 0x24) : 1;
    case ZA_NVN_ID_nvnWindowBuilderGetNumActiveTextures:
        return is_obj(o) ? ld32(o, 0x28) : 1;
    case ZA_NVN_ID_nvnWindowInitialize: {
        const void *b = (const void *)(uintptr_t)a1;
        init_obj(o, 0x180);
        if (is_obj(b)) {
            st64(o, 0x08, ld64(b, 0x08));          // device
            st64(o, 0x10, ld64(b, 0x10));          // nativeWindow
            st64(o, 0x18, ld64(b, 0x18));          // textures
            st32(o, 0x20, ld32(b, 0x20));          // numTextures
            st32(o, 0x24, ld32(b, 0x24));          // presentInterval
            st32(o, 0x28, ld32(b, 0x28));          // numActiveTextures
        }
        return 1;
    }
    case ZA_NVN_ID_nvnWindowFinalize:
        return 0;
    case ZA_NVN_ID_nvnWindowAcquireTexture: {
        // 结果 0 = SUCCESS（原实现返回 1 = NATIVE_ERROR，客机会当成失败）
        za_nvn_acquires++;
        if (za_nvn_acquires <= 4 || (za_nvn_acquires % 120) == 0)
            ZLOGI("★ NVN 取帧贴图 #%llu", (unsigned long long)za_nvn_acquires);
        void *idx = (void *)(uintptr_t)a2;
        u32 ntex = is_obj(o) ? ld32(o, 0x20) : 0;
        u32 cur = is_obj(o) ? ld32(o, 0x2c) : 0;
        if (idx) st32(idx, 0, ntex ? (cur % ntex) : 0);
        if (is_obj(o)) st32(o, 0x2c, cur + 1);
        return 0;
    }
    case ZA_NVN_ID_nvnWindowGetNativeWindow:
        return is_obj(o) ? ld64(o, 0x10) : 0;
    case ZA_NVN_ID_nvnWindowGetPresentInterval:
        return is_obj(o) ? ld32(o, 0x24) : 1;
    case ZA_NVN_ID_nvnWindowSetPresentInterval:
        if (is_obj(o)) st32(o, 0x24, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnWindowSetCrop:
        if (is_obj(o)) {
            st32(o, 0x30, (u32)a1);
            st32(o, 0x34, (u32)a2);
            st32(o, 0x38, (u32)a3);
            st32(o, 0x3c, (u32)a4);
        }
        return 0;
    case ZA_NVN_ID_nvnWindowGetCrop: {
        void *r = (void *)(uintptr_t)a1;
        if (is_obj(o) && r) {
            st32(r, 0, ld32(o, 0x30));
            st32(r, 4, ld32(o, 0x34));
            st32(r, 8, ld32(o, 0x38));
            st32(r, 12, ld32(o, 0x3c));
        }
        return 0;
    }
    case ZA_NVN_ID_nvnWindowSetNumActiveTextures:
        if (is_obj(o)) st32(o, 0x28, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnWindowGetNumActiveTextures:
        return is_obj(o) ? ld32(o, 0x28) : 1;
    case ZA_NVN_ID_nvnWindowGetNumTextures:
        return is_obj(o) ? ld32(o, 0x20) : 0;

    // ── 纹理 ──────────────────────────────────────────────────────────
    case ZA_NVN_ID_nvnTextureBuilderSetDefaults:
        init_obj(o, 0x80);
        st32(o, F_TARGET, 1);  // 2D
        st32(o, F_LEVELS, 1);
        st32(o, F_SAMPLES, 1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetDevice:
        if (is_obj(o)) st64(o, F_DEVICE, a1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetFlags:
        if (is_obj(o)) st32(o, F_FLAGS, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetTarget:
        if (is_obj(o)) st32(o, F_TARGET, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetWidth:
        if (is_obj(o)) st32(o, F_W, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetHeight:
        if (is_obj(o)) st32(o, F_H, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetDepth:
        if (is_obj(o)) st32(o, F_D, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetSize2D:
        if (is_obj(o)) {
            st32(o, F_W, (u32)a1);
            st32(o, F_H, (u32)a2);
        }
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetSize3D:
    case ZA_NVN_ID_nvnTextureBuilderSetSize1D:
        if (is_obj(o)) {
            st32(o, F_W, (u32)a1);
            st32(o, F_H, (u32)a2);
            st32(o, F_D, (u32)a3);
        }
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetLevels:
        if (is_obj(o)) st32(o, F_LEVELS, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetFormat:
        if (is_obj(o)) st32(o, F_FORMAT, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetSamples:
        if (is_obj(o)) st32(o, F_SAMPLES, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetSwizzle:
        if (is_obj(o)) st32(o, F_SWIZZLE, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetDepthStencilMode:
        if (is_obj(o)) st32(o, F_DSM, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetStride:
        if (is_obj(o)) st32(o, F_STRIDE, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetStorage:
        if (is_obj(o)) {
            st64(o, F_POOL, a1);
            st64(o, F_POOLOFF, a2);
        }
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderSetPackagedTextureData:
        if (is_obj(o)) st64(o, F_MEMORY, a1);
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderGetStorageSize:
        return is_obj(o) ? za_nvn_tex_bytes(o) : 0x1000;
    case ZA_NVN_ID_nvnTextureBuilderGetStorageAlignment:
        return 0x1000;
    case ZA_NVN_ID_nvnTextureBuilderGetViewOffset:
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderGetStorageClass:
    case ZA_NVN_ID_nvnTextureBuilderGetRawStorageClass:
        return 0;
    case ZA_NVN_ID_nvnTextureBuilderGetDevice:
        return is_obj(o) ? ld64(o, F_DEVICE) : 0;
    case ZA_NVN_ID_nvnTextureBuilderGetFlags:
        return is_obj(o) ? ld32(o, F_FLAGS) : 0;
    case ZA_NVN_ID_nvnTextureBuilderGetTarget:
        return is_obj(o) ? ld32(o, F_TARGET) : 1;
    case ZA_NVN_ID_nvnTextureBuilderGetWidth:
        return is_obj(o) ? ld32(o, F_W) : 0;
    case ZA_NVN_ID_nvnTextureBuilderGetHeight:
        return is_obj(o) ? ld32(o, F_H) : 0;
    case ZA_NVN_ID_nvnTextureBuilderGetDepth:
        return is_obj(o) ? ld32(o, F_D) : 1;
    case ZA_NVN_ID_nvnTextureBuilderGetLevels:
        return is_obj(o) ? ld32(o, F_LEVELS) : 1;
    case ZA_NVN_ID_nvnTextureBuilderGetFormat:
        return is_obj(o) ? ld32(o, F_FORMAT) : 0;
    case ZA_NVN_ID_nvnTextureBuilderGetSamples:
        return is_obj(o) ? ld32(o, F_SAMPLES) : 1;
    case ZA_NVN_ID_nvnTextureBuilderGetSwizzle:
        return is_obj(o) ? ld32(o, F_SWIZZLE) : 0;
    case ZA_NVN_ID_nvnTextureBuilderGetDepthStencilMode:
        return is_obj(o) ? ld32(o, F_DSM) : 0;
    case ZA_NVN_ID_nvnTextureBuilderGetStride:
        return is_obj(o) ? za_nvn_tex_stride(o) : 0;
    case ZA_NVN_ID_nvnTextureBuilderGetPackagedTextureData:
        return is_obj(o) ? ld64(o, F_MEMORY) : 0;
    case ZA_NVN_ID_nvnTextureBuilderGetMemoryPool:
        return is_obj(o) ? ld64(o, F_POOL) : 0;
    case ZA_NVN_ID_nvnTextureBuilderGetMemoryOffset:
        return is_obj(o) ? ld64(o, F_POOLOFF) : 0;
    case ZA_NVN_ID_nvnTextureInitialize: {
        const void *b = (const void *)(uintptr_t)a1;
        u64 pool, off;
        init_obj(o, 0xc0);
        if (!is_obj(b)) return 1;
        st32(o, F_W, ld32(b, F_W));
        st32(o, F_H, ld32(b, F_H));
        st32(o, F_D, ld32(b, F_D));
        st32(o, F_LEVELS, ld32(b, F_LEVELS));
        st32(o, F_FORMAT, ld32(b, F_FORMAT));
        st32(o, F_SAMPLES, ld32(b, F_SAMPLES));
        st32(o, F_TARGET, ld32(b, F_TARGET));
        st32(o, F_SWIZZLE, ld32(b, F_SWIZZLE));
        st32(o, F_DSM, ld32(b, F_DSM));
        st32(o, F_STRIDE, ld32(b, F_STRIDE));
        pool = ld64(b, F_POOL);
        off = ld64(b, F_POOLOFF);
        st64(o, F_POOL, pool);
        st64(o, F_POOLOFF, off);
        st64(o, F_ADDR, is_obj((const void *)(uintptr_t)pool) ? ld64((const void *)(uintptr_t)pool, F_ADDR) + off : off);
        st64(o, F_EXTRA, za_nvn_tex_bytes(b));
        return 1;
    }
    case ZA_NVN_ID_nvnTextureFinalize:
        return 0;
    case ZA_NVN_ID_nvnTextureGetTextureAddress:
        return is_obj(o) ? ld64(o, F_ADDR) : 0;
    case ZA_NVN_ID_nvnTextureGetWidth:
        return is_obj(o) ? ld32(o, F_W) : 0;
    case ZA_NVN_ID_nvnTextureGetHeight:
        return is_obj(o) ? ld32(o, F_H) : 0;
    case ZA_NVN_ID_nvnTextureGetDepth:
        return is_obj(o) ? ld32(o, F_D) : 1;
    case ZA_NVN_ID_nvnTextureGetLevels:
        return is_obj(o) ? ld32(o, F_LEVELS) : 1;
    case ZA_NVN_ID_nvnTextureGetFormat:
        return is_obj(o) ? ld32(o, F_FORMAT) : 0;
    case ZA_NVN_ID_nvnTextureGetSamples:
        return is_obj(o) ? ld32(o, F_SAMPLES) : 1;
    case ZA_NVN_ID_nvnTextureGetTarget:
        return is_obj(o) ? ld32(o, F_TARGET) : 1;
    case ZA_NVN_ID_nvnTextureGetSwizzle:
        return is_obj(o) ? ld32(o, F_SWIZZLE) : 0;
    case ZA_NVN_ID_nvnTextureGetDepthStencilMode:
        return is_obj(o) ? ld32(o, F_DSM) : 0;
    case ZA_NVN_ID_nvnTextureGetStride:
        return is_obj(o) ? za_nvn_tex_stride(o) : 0;
    case ZA_NVN_ID_nvnTextureGetFlags:
        return is_obj(o) ? ld32(o, F_FLAGS) : 0;
    case ZA_NVN_ID_nvnTextureGetStorageSize:
        return is_obj(o) ? ld64(o, F_EXTRA) : 0;
    case ZA_NVN_ID_nvnTextureGetMemoryPool:
        return is_obj(o) ? ld64(o, F_POOL) : 0;
    case ZA_NVN_ID_nvnTextureGetMemoryOffset:
        return is_obj(o) ? ld64(o, F_POOLOFF) : 0;
    case ZA_NVN_ID_nvnTextureGetZCullStorageSize:
        return 0;
    case ZA_NVN_ID_nvnTextureCompare: {
        const void *x = (const void *)(uintptr_t)a1;
        if (!is_obj(o) || !is_obj(x)) return 0;
        return ld32(o, F_FORMAT) == ld32(x, F_FORMAT) && ld32(o, F_W) == ld32(x, F_W) &&
               ld32(o, F_H) == ld32(x, F_H) && ld32(o, F_LEVELS) == ld32(x, F_LEVELS);
    }

    // ── 采样器 ────────────────────────────────────────────────────────
    // ★★ NVNsamplerBuilder 在这套 SDK 里只有 **0x40 字节**，而且客机把它放在
    //    栈上：`sub sp,#0x90; stp x29,x30,[sp,#0x50]; ... add x0,sp,#0x10`
    //    ⇒ builder 占 sp+0x10..sp+0x4f，往 0x40 之外写会直接改掉保存的
    //    x29/x30/x24/x23（真机实测：写 0x60 字节后 ret 跳到 pc=0）。
    //    所以这里**只保留 magic + device**，其余 setter 一律不落盘：
    //    Initialize 只认这两个字段，Get 系返回 0（客机只拿来回填 builder）。
    case ZA_NVN_ID_nvnSamplerBuilderSetDefaults:
        init_obj(o, 0x40);
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderSetDevice:
        if (is_obj(o)) st64(o, F_DEVICE, a1);
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderSetMinMagFilter:
    case ZA_NVN_ID_nvnSamplerBuilderSetWrapMode:
    case ZA_NVN_ID_nvnSamplerBuilderSetLodClamp:
    case ZA_NVN_ID_nvnSamplerBuilderSetLodBias:
    case ZA_NVN_ID_nvnSamplerBuilderSetCompare:
    case ZA_NVN_ID_nvnSamplerBuilderSetBorderColor:
    case ZA_NVN_ID_nvnSamplerBuilderSetBorderColori:
    case ZA_NVN_ID_nvnSamplerBuilderSetBorderColorui:
    case ZA_NVN_ID_nvnSamplerBuilderSetMaxAnisotropy:
    case ZA_NVN_ID_nvnSamplerBuilderSetReductionFilter:
    case ZA_NVN_ID_nvnSamplerBuilderSetLodSnap:
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderGetDevice:
    case ZA_NVN_ID_nvnSamplerBuilderGetMinMagFilter:
    case ZA_NVN_ID_nvnSamplerBuilderGetWrapMode:
    case ZA_NVN_ID_nvnSamplerBuilderGetLodClamp:
    case ZA_NVN_ID_nvnSamplerBuilderGetLodBias:
    case ZA_NVN_ID_nvnSamplerBuilderGetCompare:
    case ZA_NVN_ID_nvnSamplerBuilderGetBorderColor:
    case ZA_NVN_ID_nvnSamplerBuilderGetBorderColori:
    case ZA_NVN_ID_nvnSamplerBuilderGetBorderColorui:
    case ZA_NVN_ID_nvnSamplerBuilderGetMaxAnisotropy:
    case ZA_NVN_ID_nvnSamplerBuilderGetReductionFilter:
    case ZA_NVN_ID_nvnSamplerBuilderGetLodSnap:
        return is_obj(o) ? ld64(o, F_DEVICE) : 0;
    case ZA_NVN_ID_nvnSamplerInitialize:
        // NVNsampler = 0x30 字节（客机给的是堆对象，尺寸够）
        init_obj(o, 0x30);
        if (is_obj((const void *)(uintptr_t)a1)) {
            st64(o, F_DEVICE, ld64((const void *)(uintptr_t)a1, F_DEVICE));
        }
        return 1;
    case ZA_NVN_ID_nvnSamplerFinalize:
        return 0;

    // ── 缓冲 ──────────────────────────────────────────────────────────
    case ZA_NVN_ID_nvnBufferBuilderSetDefaults:
        init_obj(o, 0x40);
        return 0;
    case ZA_NVN_ID_nvnBufferBuilderSetDevice:
        if (is_obj(o)) st64(o, F_DEVICE, a1);
        return 0;
    case ZA_NVN_ID_nvnBufferBuilderSetStorage:
        // 紧凑布局（NVNbufferBuilder = 0x40，同样可能是栈对象）
        if (is_obj(o)) {
            st64(o, 0x10, a1);   // memoryPool
            st64(o, 0x18, a2);   // offset
            st64(o, 0x20, a3);   // size
        }
        return 0;
    case ZA_NVN_ID_nvnBufferBuilderGetDevice:
        return is_obj(o) ? ld64(o, F_DEVICE) : 0;
    case ZA_NVN_ID_nvnBufferBuilderGetMemoryPool:
        return is_obj(o) ? ld64(o, 0x10) : 0;
    case ZA_NVN_ID_nvnBufferBuilderGetMemoryOffset:
        return is_obj(o) ? ld64(o, 0x18) : 0;
    case ZA_NVN_ID_nvnBufferBuilderGetSize:
        return is_obj(o) ? ld64(o, 0x20) : 0;
    case ZA_NVN_ID_nvnBufferInitialize: {
        const void *b = (const void *)(uintptr_t)a1;
        u64 pool, off;
        init_obj(o, 0x30);
        if (!is_obj(b)) return 1;
        pool = ld64(b, 0x10);
        off = ld64(b, 0x18);
        st64(o, F_POOL, pool);
        st64(o, F_POOLOFF, off);
        st64(o, F_SIZE, ld64(b, 0x20));
        st32(o, F_FLAGS, ld32(b, F_FLAGS));
        st64(o, F_ADDR, is_obj((const void *)(uintptr_t)pool)
                            ? ld64((const void *)(uintptr_t)pool, F_ADDR) + off
                            : off);
        return 1;
    }
    case ZA_NVN_ID_nvnBufferFinalize:
        return 0;
    case ZA_NVN_ID_nvnBufferMap:
    case ZA_NVN_ID_nvnBufferGetAddress:
        return is_obj(o) ? ld64(o, F_ADDR) : 0;
    case ZA_NVN_ID_nvnBufferGetSize:
        return is_obj(o) ? ld64(o, F_SIZE) : 0;
    case ZA_NVN_ID_nvnBufferGetMemoryPool:
        return is_obj(o) ? ld64(o, F_POOL) : 0;
    case ZA_NVN_ID_nvnBufferGetMemoryOffset:
        return is_obj(o) ? ld64(o, F_POOLOFF) : 0;
    case ZA_NVN_ID_nvnBufferGetDebugID:
        return 0;

    // ── 纹理池 / 采样器池 ─────────────────────────────────────────────
    // 原型：NVNboolean nvnXxxPoolInitialize(pool, const NVNmemoryPool*, ptrdiff_t off, int n)
    // ⚠ 第二个参数是**内存池对象**，不是 builder；n 是描述符个数（贴图 0x7000 / 采样器 0x200）。
    case ZA_NVN_ID_nvnTexturePoolInitialize:
    case ZA_NVN_ID_nvnSamplerPoolInitialize:
        init_obj(o, 0x20);
        st64(o, F_POOL, a1);
        st64(o, F_POOLOFF, a2);
        st64(o, F_SIZE, a3);
        ZLOGI("★ NVN %s(size=%llu)", za_nvn_name[id], (unsigned long long)a3);
        return 1;
    case ZA_NVN_ID_nvnTexturePoolGetSize:
    case ZA_NVN_ID_nvnSamplerPoolGetSize:
        return is_obj(o) ? ld64(o, F_SIZE) : 0;
    case ZA_NVN_ID_nvnTexturePoolFinalize:
    case ZA_NVN_ID_nvnSamplerPoolFinalize:
    case ZA_NVN_ID_nvnTexturePoolRegisterTexture:
    case ZA_NVN_ID_nvnTexturePoolRegisterImage:
    case ZA_NVN_ID_nvnSamplerPoolRegisterSampler:
    case ZA_NVN_ID_nvnSamplerPoolRegisterSamplerBuilder:
        return 0;
    case ZA_NVN_ID_nvnTexturePoolGetMemoryPool:
    case ZA_NVN_ID_nvnSamplerPoolGetMemoryPool:
        return is_obj(o) ? ld64(o, F_POOL) : 0;
    case ZA_NVN_ID_nvnTexturePoolGetMemoryOffset:
    case ZA_NVN_ID_nvnSamplerPoolGetMemoryOffset:
        return is_obj(o) ? ld64(o, F_POOLOFF) : 0;

    // ── 命令缓冲 ──────────────────────────────────────────────────────
    case ZA_NVN_ID_nvnCommandBufferInitialize:
        init_obj(o, 0xa0);
        return 1;
    case ZA_NVN_ID_nvnCommandBufferFinalize:
        return 0;
    case ZA_NVN_ID_nvnCommandBufferAddCommandMemory:
        if (is_obj(o)) {
            st64(o, F_MEMORY, a1);
            st64(o, F_SIZE, a2);
        }
        return 0;
    case ZA_NVN_ID_nvnCommandBufferAddControlMemory:
        if (is_obj(o)) {
            st64(o, F_POOL, a1);
            st64(o, F_POOLOFF, a2);
        }
        return 0;
    case ZA_NVN_ID_nvnCommandBufferGetCommandMemorySize:
        return is_obj(o) ? ld64(o, F_SIZE) : 0;
    case ZA_NVN_ID_nvnCommandBufferGetCommandMemoryFree:
        return is_obj(o) ? ld64(o, F_SIZE) : 0;
    case ZA_NVN_ID_nvnCommandBufferGetControlMemorySize:
        return is_obj(o) ? ld64(o, F_POOLOFF) : 0;
    case ZA_NVN_ID_nvnCommandBufferGetControlMemoryFree:
        return is_obj(o) ? ld64(o, F_POOLOFF) : 0;
    case ZA_NVN_ID_nvnCommandBufferGetCommandMemoryUsed:
    case ZA_NVN_ID_nvnCommandBufferGetControlMemoryUsed:
        return 0;
    case ZA_NVN_ID_nvnCommandBufferBeginRecording:
        if (is_obj(o)) st32(o, F_FLAGS, 1);
        return 0;
    case ZA_NVN_ID_nvnCommandBufferEndRecording:
        if (is_obj(o)) st32(o, F_FLAGS, 0);
        return 0;
    case ZA_NVN_ID_nvnCommandBufferIsRecording:
        return is_obj(o) ? ld32(o, F_FLAGS) : 0;
    case ZA_NVN_ID_nvnCommandBufferGetMemoryCallback:
        return is_obj(o) ? ld64(o, F_EXTRA) : 0;
    case ZA_NVN_ID_nvnCommandBufferGetMemoryCallbackData:
        return is_obj(o) ? ld64(o, F_EXTRA + 8) : 0;
    case ZA_NVN_ID_nvnCommandBufferCallCommands:
        ZLOGI("★ NVN CallCommands(%llu 个)", (unsigned long long)a1);
        return 0;

    // ── 同步对象 / 事件 / 程序 ────────────────────────────────────────
    case ZA_NVN_ID_nvnSyncInitialize:
        init_obj(o, 0x40);
        st32(o, F_FLAGS, 1); // 已经「已触发」，任何等待都立刻放行
        return 1;
    case ZA_NVN_ID_nvnSyncFinalize:
        return 0;
    case ZA_NVN_ID_nvnSyncWait:
        return 1; // 立刻视为已触发：本阶段不产生 GPU 工作，不能让客机卡死
    case ZA_NVN_ID_nvnSyncInitializeFromFencedGLSync:
    case ZA_NVN_ID_nvnSyncCreateGLSync:
        return 0;
    case ZA_NVN_ID_nvnEventBuilderSetDefaults:
        init_obj(o, 0x40);
        return 0;
    case ZA_NVN_ID_nvnEventBuilderSetStorage:
        if (is_obj(o)) {
            st64(o, F_POOL, a1);
            st64(o, F_POOLOFF, a2);
        }
        return 0;
    case ZA_NVN_ID_nvnEventBuilderGetStorage:
        if (a1) st64((void *)(uintptr_t)a1, 0, is_obj(o) ? ld64(o, F_POOL) : 0);
        if (a2) st64((void *)(uintptr_t)a2, 0, is_obj(o) ? ld64(o, F_POOLOFF) : 0);
        return 0;
    case ZA_NVN_ID_nvnEventBuilderGetMemoryPool:
        return is_obj(o) ? ld64(o, F_POOL) : 0;
    case ZA_NVN_ID_nvnEventBuilderGetMemoryOffset:
        return is_obj(o) ? ld64(o, F_POOLOFF) : 0;
    case ZA_NVN_ID_nvnEventInitialize:
        init_obj(o, 0x40);
        return 1;
    case ZA_NVN_ID_nvnEventFinalize:
        return 0;
    case ZA_NVN_ID_nvnEventGetValue:
        return is_obj(o) ? ld64(o, F_SIZE) : 0;
    case ZA_NVN_ID_nvnEventSignal:
        // 原型：void nvnEventSignal(NVNevent*, NVNeventSignalMode, uint32_t)
        // 0 = ADD，1 = SET
        if (!is_obj(o)) return 0;
        if ((u32)a1 == 0) st64(o, F_SIZE, ld64(o, F_SIZE) + (u32)a2);
        else st64(o, F_SIZE, (u32)a2);
        return 0;
    case ZA_NVN_ID_nvnEventGetMemoryPool:
        return is_obj(o) ? ld64(o, F_POOL) : 0;
    case ZA_NVN_ID_nvnEventGetMemoryOffset:
        return is_obj(o) ? ld64(o, F_POOLOFF) : 0;
    case ZA_NVN_ID_nvnProgramInitialize:
        init_obj(o, 0xc0);
        return 1;
    case ZA_NVN_ID_nvnProgramFinalize:
        return 0;
    case ZA_NVN_ID_nvnProgramGetSubtileSize:
        return 0x1000;

    default:
        return 0;
    }
}

// ── 对外接口 ──────────────────────────────────────────────────────────
void za_nvn_init(void) { za_nvn_init_ptr_table(); }

void *za_nvn_bootstrap(const char *name)
{
    void *fn;
    za_nvn_init();
    fn = za_nvn_lookup(name);
    if (fn) {
        ZLOGI("★ NVN bootstrap \"%s\" -> %p", name ? name : "(null)", fn);
        return fn;
    }
    ZLOGI("★ NVN bootstrap \"%s\" 不在表里（给通用桩）", name ? name : "(null)");
    return (void *)&za_nvn_unknown_impl;
}
