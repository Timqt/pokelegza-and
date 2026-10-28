// 图形层接线：把 app/native/dm 里的**参考工程图形层**（NVN→Vulkan 翻译器）接到我们的内核上。
//
// 这里的三个职责：
//   1) 补参考内核（dm/host）的宿主 API —— 时钟、性能计数、缺页钩子登记、刷新率。
//      这些在参考工程里由 hle_os.c / crash.c / front_mac.m 提供，我们没有那套内核，只能自己垫。
//   2) 符号接管表：dm 的 HLE_FORCE/HLE 条目被 DM_SECT 放进 ELF 段 swforce / swhle，
//      链接器给 __start_/__stop_ 边界符号；我们的导入解析先查这张表，
//      于是 main 导入的 nvnBootstrapLoader 直接落到 hle_nvn.c 的实现上。
//   3) 安卓窗口与 Vulkan 初始化：窗口回调把 ANativeWindow 交给 dm_android_vk_set_window，
//      初始化在独立线程里跑（它会阻塞等窗口，绝不能占住客机线程或 UI 线程）。
#include <android/native_window.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "za_common.h"

// 我们自己内核里的系统刻度（19.2 MHz），见 za_os.c
unsigned long long za_os_get_system_tick(void);

// 参考工程的安卓呈现层
void dm_android_vk_set_window(ANativeWindow *window);
int dm_android_vk_initialize(const char *shader_directory, char *error, size_t bytes);
int dm_android_vk_has_window(void);

// ───────────────────────── 参考内核的宿主 API 垫片 ─────────────────────────
// 声明见 dm/host/dm.h；图形层用到的这些必须由我们给出，否则 .so 装载时就缺符号。

uint64_t g_t0_ns;                       // 宿主启动时刻（now_ns 时基），日志相对时间用

uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

// 客体时钟：直接取 svc 的 19.2 MHz 刻度换算，保证与客机自己算出来的时间一致。
uint64_t guest_ns(void)
{
    return za_os_get_system_tick() * 1000000000ull / 19200000ull;
}

int dm_detclock_enabled(void) { return 0; }   // 确定性时钟：不用
void dm_guest_frame_tick(void) {}             // 只在确定性时钟下有效
void dm_prof_add(int id, uint64_t ns, uint64_t bytes) { (void)id; (void)ns; (void)bytes; }

// 缺页 / 宿主写客体内存钩子：参考工程在安卓上也不用（docs 明确「禁 SIGSEGV/mprotect 脏页追踪」），
// 这里只登记不使用 —— 引擎据此关掉自己的信号处理，走保守路径。
static int (*za_gfx_fault_hook)(void *addr, int is_write, void *uc);
static void (*za_gfx_write_prep)(void *addr, size_t len);
void dm_fault_hook_register(int (*fn)(void *addr, int is_write, void *uc)) { za_gfx_fault_hook = fn; }
void dm_guest_write_prep_register(void (*fn)(void *addr, size_t len)) { za_gfx_write_prep = fn; }

double front_display_refresh(char *name, size_t n)
{
    if (name && n) snprintf(name, n, "%s", "display");
    return 60.0;   // 引擎只用它做首帧节奏估计；真实刷新率由交换链决定
}

// ───────────────────────── 符号接管表（swforce / swhle） ─────────────────────────
// 与 dm/host/hle.h 的结构逐字对应；不直接包含那个头 —— 它会引入参考内核的整套声明。
typedef struct { const char *name; void *fn; const char *why; } za_force_ent;
typedef struct { const char *name; void *fn; } za_hle_ent;

extern const char __start_swforce[] __attribute__((weak, visibility("hidden")));
extern const char __stop_swforce[] __attribute__((weak, visibility("hidden")));
extern const char __start_swhle[] __attribute__((weak, visibility("hidden")));
extern const char __stop_swhle[] __attribute__((weak, visibility("hidden")));

static int za_gfx_ready_scan;

// 按改编名查参考图形层的实现；没有返回 NULL。
// 顺序：强制接管表（nvnBootstrapLoader 等）在前，普通 HLE 表在后。
void *za_gfx_hle_lookup(const char *name)
{
    if (!name || !*name) return NULL;
    if (!za_gfx_ready_scan)
    {
        za_gfx_ready_scan = 1;
        size_t nf = (size_t)(__stop_swforce - __start_swforce) / sizeof(za_force_ent);
        size_t nh = (size_t)(__stop_swhle - __start_swhle) / sizeof(za_hle_ent);
        ZLOGI("图形层符号表: 强制接管 %zu 条，HLE %zu 条", nf, nh);
    }
    if (__start_swforce)
    {
        const za_force_ent *e = (const za_force_ent *)__start_swforce;
        size_t n = (size_t)(__stop_swforce - __start_swforce) / sizeof(*e);
        for (size_t i = 0; i < n; i++)
            if (e[i].name && !strcmp(e[i].name, name)) return e[i].fn;
    }
    if (__start_swhle)
    {
        const za_hle_ent *e = (const za_hle_ent *)__start_swhle;
        size_t n = (size_t)(__stop_swhle - __start_swhle) / sizeof(*e);
        for (size_t i = 0; i < n; i++)
            if (e[i].name && !strcmp(e[i].name, name)) return e[i].fn;
    }
    return NULL;
}

// ───────────────────────── 开关与窗口 ─────────────────────────
// 开关用文件而不是环境变量：NativeActivity 起进程时给不了自定义环境变量，
// adb shell 建文件最容易（/data/local/tmp 对 app 可读）。
static int za_marker(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

// 图形层是否接管显示。默认接管；/data/local/tmp/za-demo-vk 存在时退回旧的三角形演示。
int za_gfx_active(void)
{
    static int cached = -1;
    if (cached < 0) cached = !za_marker("/data/local/tmp/za-demo-vk");
    return cached;
}

static char g_shader_dir[512];
static char g_init_err[512];
static volatile int g_init_state;   // 0 未开始 1 进行中 2 成功 3 失败

// 前端（NativeActivity 回调）在窗口来了/走了时调。只更新快照，不做 Vulkan 调用。
void za_gfx_set_window(ANativeWindow *window)
{
    dm_android_vk_set_window(window);
    ZLOGI("图形层窗口 -> %p", (void *)window);
}

static void *za_gfx_init_thread(void *arg)
{
    (void)arg;
    ZLOGI("图形层初始化线程开始（着色器目录 %s）", g_shader_dir);
    int r = dm_android_vk_initialize(g_shader_dir, g_init_err, sizeof g_init_err);
    if (r == 0)
    {
        g_init_state = 2;
        ZLOGI("图形层初始化完成");
    }
    else
    {
        g_init_state = 3;
        ZLOGE("图形层初始化失败 (%d): %s", r, g_init_err);
    }
    return NULL;
}

// 客机线程起跑前调：准备着色器目录并起初始化线程。
// shader_root 传 activity->internalDataPath（可写目录），着色器放在 <root>/shaders。
void za_gfx_start(const char *shader_root)
{
    if (!za_gfx_active()) { ZLOGI("图形层未接管（演示模式）"); return; }
    if (g_init_state) return;
    g_init_state = 1;
    snprintf(g_shader_dir, sizeof g_shader_dir, "%s/shaders", shader_root ? shader_root : "/data/local/tmp");
    g_t0_ns = now_ns();
    pthread_t th;
    if (pthread_create(&th, NULL, za_gfx_init_thread, NULL) != 0)
    {
        g_init_state = 3;
        ZLOGE("图形层初始化线程起不来");
        return;
    }
    pthread_detach(th);
}

int za_gfx_init_state(void) { return g_init_state; }
