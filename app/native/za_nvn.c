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
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "za_common.h"
#include "za_nvn.h"
#include "za_nvn_names.h"

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

#define M_MAGIC 0x4e564e31u /* "NVN1" */

static inline u64 ld64(const void *p, u32 off)
{
    u64 v;
    memcpy(&v, (const char *)p + off, 8);
    return v;
}
static inline void st64(void *p, u32 off, u64 v) { memcpy((char *)p + off, &v, 8); }
static inline u32 ld32(const void *p, u32 off)
{
    u32 v;
    memcpy(&v, (const char *)p + off, 4);
    return v;
}
static inline void st32(void *p, u32 off, u32 v) { memcpy((char *)p + off, &v, 4); }
static inline int is_obj(const void *p) { return p && ld32(p, F_MAGIC) == M_MAGIC; }
static void init_obj(void *p, u64 size)
{
    memset(p, 0, size);
    st32(p, F_MAGIC, M_MAGIC);
}

// 贴图存储量估算：客机拿它给自己的内存池定尺寸，稍微给大一点是安全的。
static u64 za_nvn_tex_bytes(const void *b)
{
    u64 w = ld32(b, F_W) ? ld32(b, F_W) : 1;
    u64 h = ld32(b, F_H) ? ld32(b, F_H) : 1;
    u64 d = ld32(b, F_D) ? ld32(b, F_D) : 1;
    u64 lv = ld32(b, F_LEVELS) ? ld32(b, F_LEVELS) : 1;
    u64 sm = ld32(b, F_SAMPLES) ? ld32(b, F_SAMPLES) : 1;
    u64 bytes = w * h * d * 4 * sm;
    if (lv > 1) bytes *= 2;
    return (bytes + 0xfff) & ~0xfffull;
}

static u64 za_nvn_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u64)ts.tv_sec * 1000000000ull + (u64)ts.tv_nsec;
}

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
static u64 za_nvn_call(int id, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7);

// 每个入口一个函数：地址稳定、名字可查（客机只会拿指针调用）。
#define ZA_NVN_FN_DEF(n)                                                                 \
    static u64 za_nvn_fn_##n(u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6,      \
                             u64 a7)                                                       \
    {                                                                                      \
        return za_nvn_call(ZA_NVN_ID_##n, a0, a1, a2, a3, a4, a5, a6, a7);                 \
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

static u64 za_nvn_call(int id, u64 a0, u64 a1, u64 a2, u64 a3, u64 a4, u64 a5, u64 a6, u64 a7)
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
        st64(o, F_EXTRA, (u64)(uintptr_t)fn);
        return (u64)(uintptr_t)fn;
    }
    case ZA_NVN_ID_nvnDeviceGetInteger:
        ZLOGI("★ NVN nvnDeviceGetInteger(id=%#llx)", (unsigned long long)a1);
        return 0;
    case ZA_NVN_ID_nvnDeviceGetCurrentTimestampInNanoseconds:
    case ZA_NVN_ID_nvnDeviceGetTimestampInNanoseconds:
        if (a1) st64((void *)(uintptr_t)a1, 0, za_nvn_now_ns());
        return za_nvn_now_ns();
    case ZA_NVN_ID_nvnDeviceGenerateDebugDomainId:
        st32(o, F_EXTRA, ld32(o, F_EXTRA) + 1);
        return ld32(o, F_EXTRA);
    case ZA_NVN_ID_nvnDeviceIsExternalDebuggerAttached:
        return 0;
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
    case ZA_NVN_ID_nvnQueueFinalize:
    case ZA_NVN_ID_nvnQueueFlush:
    case ZA_NVN_ID_nvnQueueFinish:
    case ZA_NVN_ID_nvnQueuePresentTexture:
    case ZA_NVN_ID_nvnQueueGetError:
    case ZA_NVN_ID_nvnQueueResetMemoryUsageCounts:
        return 0;
    case ZA_NVN_ID_nvnQueueSubmitCommands:
        ZLOGI("★ NVN 提交命令缓冲：%llu 个", (unsigned long long)a1);
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
    case ZA_NVN_ID_nvnWindowBuilderSetDefaults:
        init_obj(o, 0x40);
        st32(o, F_LEVELS, 1);  // numActiveTextures 默认 1
        st32(o, F_SAMPLES, 1); // presentInterval 默认 1
        return 0;
    case ZA_NVN_ID_nvnWindowBuilderSetDevice:
        if (is_obj(o)) st64(o, F_DEVICE, a1);
        return 0;
    case ZA_NVN_ID_nvnWindowBuilderSetNativeWindow:
        if (is_obj(o)) st64(o, F_MEMORY, a1);
        return 0;
    case ZA_NVN_ID_nvnWindowBuilderSetTextures:
        if (is_obj(o)) {
            st64(o, F_POOL, a1);
            st32(o, F_FLAGS2, (u32)a2);
        }
        return 0;
    case ZA_NVN_ID_nvnWindowBuilderSetPresentInterval:
        if (is_obj(o)) st32(o, F_SAMPLES, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnWindowBuilderSetNumActiveTextures:
        if (is_obj(o)) st32(o, F_LEVELS, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnWindowBuilderGetDevice:
        return is_obj(o) ? ld64(o, F_DEVICE) : 0;
    case ZA_NVN_ID_nvnWindowBuilderGetNumTextures:
        return is_obj(o) ? ld32(o, F_FLAGS2) : 0;
    case ZA_NVN_ID_nvnWindowBuilderGetTexture: {
        u64 base;
        if (!is_obj(o)) return 0;
        base = ld64(o, F_POOL);
        return base ? ld64((const void *)(uintptr_t)base, (u32)(a1 * 8)) : 0;
    }
    case ZA_NVN_ID_nvnWindowBuilderGetNativeWindow:
        return is_obj(o) ? ld64(o, F_MEMORY) : 0;
    case ZA_NVN_ID_nvnWindowBuilderGetPresentInterval:
        return is_obj(o) ? ld32(o, F_SAMPLES) : 1;
    case ZA_NVN_ID_nvnWindowBuilderGetNumActiveTextures:
        return is_obj(o) ? ld32(o, F_LEVELS) : 1;
    case ZA_NVN_ID_nvnWindowInitialize: {
        const void *b = (const void *)(uintptr_t)a1;
        init_obj(o, 0x180);
        if (is_obj(b)) {
            st64(o, F_DEVICE, ld64(b, F_DEVICE));
            st64(o, F_MEMORY, ld64(b, F_MEMORY));
            st64(o, F_POOL, ld64(b, F_POOL));
            st32(o, F_FLAGS2, ld32(b, F_FLAGS2));
            st32(o, F_LEVELS, ld32(b, F_LEVELS));
            st32(o, F_SAMPLES, ld32(b, F_SAMPLES));
        }
        return 1;
    }
    case ZA_NVN_ID_nvnWindowFinalize:
        return 0;
    case ZA_NVN_ID_nvnWindowAcquireTexture: {
        void *idx = (void *)(uintptr_t)a2;
        if (idx) st32(idx, 0, 0);
        return 1;
    }
    case ZA_NVN_ID_nvnWindowGetNativeWindow:
        return is_obj(o) ? ld64(o, F_MEMORY) : 0;
    case ZA_NVN_ID_nvnWindowGetPresentInterval:
        return is_obj(o) ? ld32(o, F_SAMPLES) : 1;
    case ZA_NVN_ID_nvnWindowSetPresentInterval:
        if (is_obj(o)) st32(o, F_SAMPLES, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnWindowSetCrop:
        if (is_obj(o)) {
            st32(o, F_H, (u32)a1);
            st32(o, F_D, (u32)a2);
            st32(o, F_W, (u32)a3);
            st32(o, F_FORMAT, (u32)a4);
        }
        return 0;
    case ZA_NVN_ID_nvnWindowGetCrop: {
        void *r = (void *)(uintptr_t)a1;
        if (is_obj(o) && r) {
            st32(r, 0, ld32(o, F_H));
            st32(r, 4, ld32(o, F_D));
            st32(r, 8, ld32(o, F_W));
            st32(r, 12, ld32(o, F_FORMAT));
        }
        return 0;
    }
    case ZA_NVN_ID_nvnWindowSetNumActiveTextures:
        if (is_obj(o)) st32(o, F_LEVELS, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnWindowGetNumActiveTextures:
        return is_obj(o) ? ld32(o, F_LEVELS) : 1;
    case ZA_NVN_ID_nvnWindowGetNumTextures:
        return is_obj(o) ? ld32(o, F_FLAGS2) : 0;

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
        return is_obj(o) ? ld32(o, F_STRIDE) : 0;
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
        return is_obj(o) ? ld32(o, F_STRIDE) : 0;
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
    case ZA_NVN_ID_nvnSamplerBuilderSetDefaults:
        init_obj(o, 0x60);
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderSetDevice:
        if (is_obj(o)) st64(o, F_DEVICE, a1);
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderSetMinMagFilter:
        if (is_obj(o)) st32(o, F_FLAGS, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderSetWrapMode:
        if (is_obj(o)) {
            st32(o, F_FLAGS2, (u32)a1);
            st32(o, F_W, (u32)a2);
            st32(o, F_H, (u32)a3);
        }
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderSetLodClamp:
        if (is_obj(o)) {
            st32(o, F_D, (u32)a1);
            st32(o, F_LEVELS, (u32)a2);
        }
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderSetLodBias:
        st64(o, F_OFFSET, a1); // float 位模式，原样存
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderSetCompare:
        if (is_obj(o)) st32(o, F_FORMAT, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderSetBorderColor:
        if (is_obj(o)) memcpy((char *)o + F_SAMPLES, (const void *)(uintptr_t)a1, 16);
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderSetBorderColori:
    case ZA_NVN_ID_nvnSamplerBuilderSetBorderColorui:
        if (is_obj(o)) {
            st32(o, F_SAMPLES, (u32)a1);
            st32(o, F_SAMPLES + 4, (u32)a2);
            st32(o, F_SAMPLES + 8, (u32)a3);
            st32(o, F_SAMPLES + 12, (u32)a4);
        }
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderSetMaxAnisotropy:
        st64(o, F_ADDR, a1);
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderSetReductionFilter:
        if (is_obj(o)) st32(o, F_TARGET, (u32)a1);
        return 0;
    case ZA_NVN_ID_nvnSamplerBuilderSetLodSnap:
        st64(o, F_EXTRA, a1);
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
        // 采样器 getter 用不到，返回 0 即可（客机只会拿它回填另一个 builder）。
        return 0;
    case ZA_NVN_ID_nvnSamplerInitialize:
        init_obj(o, 0x30);
        if (is_obj((const void *)(uintptr_t)a1))
            memcpy(o, (const void *)(uintptr_t)a1, 0x30);
        st32(o, F_MAGIC, M_MAGIC);
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
        if (is_obj(o)) {
            st64(o, F_POOL, a1);
            st64(o, F_POOLOFF, a2);
            st64(o, F_SIZE, a3);
        }
        return 0;
    case ZA_NVN_ID_nvnBufferBuilderGetDevice:
        return is_obj(o) ? ld64(o, F_DEVICE) : 0;
    case ZA_NVN_ID_nvnBufferBuilderGetMemoryPool:
        return is_obj(o) ? ld64(o, F_POOL) : 0;
    case ZA_NVN_ID_nvnBufferBuilderGetMemoryOffset:
        return is_obj(o) ? ld64(o, F_POOLOFF) : 0;
    case ZA_NVN_ID_nvnBufferBuilderGetSize:
        return is_obj(o) ? ld64(o, F_SIZE) : 0;
    case ZA_NVN_ID_nvnBufferInitialize: {
        const void *b = (const void *)(uintptr_t)a1;
        u64 pool, off;
        init_obj(o, 0x30);
        if (!is_obj(b)) return 1;
        pool = ld64(b, F_POOL);
        off = ld64(b, F_POOLOFF);
        st64(o, F_POOL, pool);
        st64(o, F_POOLOFF, off);
        st64(o, F_SIZE, ld64(b, F_SIZE));
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
    case ZA_NVN_ID_nvnTexturePoolInitialize:
    case ZA_NVN_ID_nvnSamplerPoolInitialize:
        init_obj(o, 0x20);
        if (is_obj((const void *)(uintptr_t)a1)) {
            st64(o, F_POOL, ld64((const void *)(uintptr_t)a1, 0));
            st64(o, F_POOLOFF, ld64((const void *)(uintptr_t)a1, 8));
            st64(o, F_SIZE, ld64((const void *)(uintptr_t)a1, 16));
        }
        return 0;
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
    case ZA_NVN_ID_nvnTexturePoolGetSize:
    case ZA_NVN_ID_nvnSamplerPoolGetSize:
        return is_obj(o) ? ld64(o, F_SIZE) : 0;

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
        if (is_obj(o)) st64(o, F_SIZE, ld64(o, F_SIZE) + 1);
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
