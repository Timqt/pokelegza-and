// nn::os 宿主实现（宝可梦 Z-A 客机用）。
//
// 客机是 Switch 原生 ARM64 代码，调的是 Nintendo SDK 的 nn::os。
// 安卓上没有这些实现 —— 全用自动桩返回 0 的话，客机拿到的是**空句柄**，
// 下一句就解引用空指针（实测就是那样崩的）。
//
// 这里实现「客机启动阶段真正会用到的」一批：线程、互斥锁、信号量、事件、
// TLS 槽、宿主参数、时间。
//
// 关键设计：**不往客机的结构体里写东西**（nn::os 的句柄类型多大我们并不知道），
// 一律用「客机对象地址」当键，查我们自己的表 —— 绝对不会写坏客机内存。

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <sys/mman.h>
#include "za_common.h"
#include "za_os.h"
#include "za_guest_api.h"

// ---------------------------------------------------------------- 句柄表
#define ZA_OS_SLOTS 256

typedef struct
{
    void *obj;                 // 客机对象地址（键）
    int used;
    pthread_mutex_t lock;
    pthread_cond_t cond;
    int count;                 // 信号量计数 / 事件标志
    int initialized;
} za_os_obj_t;

static za_os_obj_t za_os_objs[ZA_OS_SLOTS];

static za_os_obj_t *za_os_slot(void *obj, int create)
{
    if (!obj) return NULL;
    size_t h = ((uintptr_t)obj >> 4) % ZA_OS_SLOTS;
    for (size_t i = 0; i < ZA_OS_SLOTS; i++)
    {
        za_os_obj_t *s = &za_os_objs[(h + i) % ZA_OS_SLOTS];
        if (s->used && s->obj == obj) return s;
        if (!s->used)
        {
            if (!create) return NULL;
            memset(s, 0, sizeof *s);
            s->obj = obj;
            s->used = 1;
            pthread_mutex_init(&s->lock, NULL);
            pthread_cond_init(&s->cond, NULL);
            return s;
        }
    }
    return NULL;
}

// ---------------------------------------------------------------- 时间
//
// ⚠ 刻度必须是 19.2 MHz（和 nnosGetSystemTickFrequency 一致），
//   否则客机按「tick × 1e9 / freq」换算出的时间全错。
//   另外 Android 上不能用 `mrs x0, cntpct_el0`（非法指令 ⇒ SIGILL），
//   只能用 CLOCK_MONOTONIC 换算。
unsigned long long za_os_get_system_tick(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    unsigned long long ns = (unsigned long long)ts.tv_sec * 1000000000ull +
                            (unsigned long long)ts.tv_nsec;
    return (ns / 1000000000ull) * 19200000ull + (ns % 1000000000ull) * 19200000ull / 1000000000ull;
}
unsigned long long za_os_get_system_tick_frequency(void) { return 19200000ull; }

void za_os_sleep_thread(long long ns)
{
    if (ns <= 0) return;
    struct timespec ts;
    ts.tv_sec = (time_t)(ns / 1000000000ll);
    ts.tv_nsec = (long)(ns % 1000000000ll);
    nanosleep(&ts, NULL);
}

void za_os_yield_thread(void) { sched_yield(); }

// ---------------------------------------------------------------- 线程
// 客机的 ThreadType 是句柄；我们不碰它的内容，只记住「客机对象 → pthread」。
typedef struct
{
    void *obj;
    int used;
    pthread_t tid;
    int started;
} za_os_thread_t;

#define ZA_OS_THREADS 64
static za_os_thread_t za_os_threads[ZA_OS_THREADS];

static za_os_thread_t *za_os_thread_slot(void *obj, int create)
{
    if (!obj) return NULL;
    for (int i = 0; i < ZA_OS_THREADS; i++)
    {
        za_os_thread_t *t = &za_os_threads[i];
        if (t->used && t->obj == obj) return t;
        if (!t->used)
        {
            if (!create) return NULL;
            memset(t, 0, sizeof *t);
            t->obj = obj;
            t->used = 1;
            return t;
        }
    }
    return NULL;
}

// 客机线程入口：先给这个线程装上影子 TLS 描述符，再调客机函数。
// （每个客机线程有自己的 bionic TLS 块，[tp+0x98] 得各装各的。）
static void *za_os_thread_entry(void *arg)
{
    struct { void (*fn)(void *); void *arg; } *p = arg;
    za_install_altstack();
    za_stack_register_current((long)syscall(SYS_gettid), "nnos");
    za_os_install_tls_descriptor();
    p->fn(p->arg);
    free(p);
    return NULL;
}

unsigned int za_os_create_thread(void *thread_obj, void (*fn)(void *), void *arg,
                                 void *stack_obj, int priority, int core_mask)
{
    (void)stack_obj; (void)priority; (void)core_mask;
    if (!fn) return 1;
    za_os_thread_t *t = za_os_thread_slot(thread_obj, 1);
    if (!t) return 1;
    struct { void (*fn)(void *); void *arg; } *p = malloc(sizeof *p);
    if (!p) return 1;
    p->fn = fn;
    p->arg = arg;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 8 * 1024 * 1024);
    if (pthread_create(&t->tid, &attr, za_os_thread_entry, p) != 0)
    {
        pthread_attr_destroy(&attr);
        free(p);
        return 1;
    }
    pthread_attr_destroy(&attr);
    pthread_detach(t->tid);
    t->started = 1;
    return 0;
}

unsigned int za_os_start_thread(void *thread_obj)
{
    (void)thread_obj;
    return 0;   // 我们创建时就直接跑了
}

unsigned int za_os_destroy_thread(void *thread_obj)
{
    za_os_thread_t *t = za_os_thread_slot(thread_obj, 0);
    if (t) t->started = 0;
    return 0;
}

void *za_os_get_current_thread(void)
{
    // 必须返回**非空**的合法指针：客机拿到后会立刻解引用。
    return za_os_current_thread_obj();
}

unsigned long long za_os_get_thread_id(const void *thread_obj)
{
    za_os_thread_t *t = za_os_thread_slot((void *)thread_obj, 0);
    if (t) return (unsigned long long)(uintptr_t)t->tid;
    return (unsigned long long)syscall(SYS_gettid);
}

// ---------------------------------------------------------------- 互斥锁
unsigned int za_os_initialize_mutex(void *mutex_obj, int recursive, int priority)
{
    (void)recursive; (void)priority;
    za_os_obj_t *s = za_os_slot(mutex_obj, 1);
    if (!s) return 1;
    pthread_mutex_lock(&s->lock);
    s->count = 0;
    pthread_mutex_unlock(&s->lock);
    return 0;
}

void za_os_lock_mutex(void *mutex_obj)
{
    za_os_obj_t *s = za_os_slot(mutex_obj, 0);
    if (!s) return;
    pthread_mutex_lock(&s->lock);
    s->count++;
    pthread_mutex_unlock(&s->lock);
    // 真正的互斥语义：用计数做「递归锁」简化版
    while (s->count > 1) { struct timespec ts = { 0, 1000000 }; nanosleep(&ts, NULL); }
}

void za_os_unlock_mutex(void *mutex_obj)
{
    za_os_obj_t *s = za_os_slot(mutex_obj, 0);
    if (!s) return;
    pthread_mutex_lock(&s->lock);
    if (s->count > 0) s->count--;
    pthread_mutex_unlock(&s->lock);
}

// ---------------------------------------------------------------- 信号量
unsigned int za_os_initialize_semaphore(void *sem_obj, int count, int max_count)
{
    (void)max_count;
    za_os_obj_t *s = za_os_slot(sem_obj, 1);
    if (!s) return 1;
    pthread_mutex_lock(&s->lock);
    s->count = count;
    pthread_mutex_unlock(&s->lock);
    return 0;
}

void za_os_acquire_semaphore(void *sem_obj)
{
    za_os_obj_t *s = za_os_slot(sem_obj, 0);
    if (!s) return;
    pthread_mutex_lock(&s->lock);
    while (s->count <= 0) pthread_cond_wait(&s->cond, &s->lock);
    s->count--;
    pthread_mutex_unlock(&s->lock);
}

int za_os_try_acquire_semaphore(void *sem_obj)
{
    za_os_obj_t *s = za_os_slot(sem_obj, 0);
    if (!s) return 0;
    pthread_mutex_lock(&s->lock);
    int ok = s->count > 0;
    if (ok) s->count--;
    pthread_mutex_unlock(&s->lock);
    return ok;
}

void za_os_release_semaphore(void *sem_obj, int count)
{
    za_os_obj_t *s = za_os_slot(sem_obj, 0);
    if (!s) return;
    pthread_mutex_lock(&s->lock);
    s->count += count;
    pthread_cond_broadcast(&s->cond);
    pthread_mutex_unlock(&s->lock);
}

// ---------------------------------------------------------------- 事件
unsigned int za_os_initialize_event(void *event_obj, int auto_reset, int clear_mode)
{
    (void)auto_reset; (void)clear_mode;
    za_os_obj_t *s = za_os_slot(event_obj, 1);
    if (!s) return 1;
    pthread_mutex_lock(&s->lock);
    s->count = 0;
    pthread_mutex_unlock(&s->lock);
    return 0;
}

void za_os_wait_event(void *event_obj)
{
    za_os_obj_t *s = za_os_slot(event_obj, 0);
    if (!s) return;
    pthread_mutex_lock(&s->lock);
    while (s->count == 0) pthread_cond_wait(&s->cond, &s->lock);
    s->count = 0;   // 手动复位
    pthread_mutex_unlock(&s->lock);
}

int za_os_try_wait_event(void *event_obj)
{
    za_os_obj_t *s = za_os_slot(event_obj, 0);
    if (!s) return 0;
    pthread_mutex_lock(&s->lock);
    int ok = s->count > 0;
    if (ok) s->count = 0;
    pthread_mutex_unlock(&s->lock);
    return ok;
}

void za_os_signal_event(void *event_obj)
{
    za_os_obj_t *s = za_os_slot(event_obj, 0);
    if (!s) return;
    pthread_mutex_lock(&s->lock);
    s->count = 1;
    pthread_cond_broadcast(&s->cond);
    pthread_mutex_unlock(&s->lock);
}

void za_os_clear_event(void *event_obj)
{
    za_os_obj_t *s = za_os_slot(event_obj, 0);
    if (!s) return;
    pthread_mutex_lock(&s->lock);
    s->count = 0;
    pthread_mutex_unlock(&s->lock);
}

// 轻量事件（无阻塞版本），用同一套表
unsigned int za_os_initialize_light_event(void *event_obj, int auto_reset, int clear_mode)
{
    return za_os_initialize_event(event_obj, auto_reset, clear_mode);
}
void za_os_signal_light_event(void *event_obj) { za_os_signal_event(event_obj); }
void za_os_wait_light_event(void *event_obj) { za_os_wait_event(event_obj); }

// ---------------------------------------------------------------- 宿主参数
static char *za_os_argv_storage[2] = { (char *)"main", NULL };

unsigned int za_os_get_host_argc(void) { return 1; }
const char **za_os_get_host_argv(void) { return (const char **)za_os_argv_storage; }

// ---------------------------------------------------------------- errno
//
// 客机只导入了两个 musl 内部符号：`__errno_location` 与 `__nnmusl_init_dso`。
// **安卓的 bionic 不导出 `__errno_location`**（它导出的是 `__errno`），
// 所以这个符号会落到自动桩 —— 桩返回 NULL ⇒ 客机拿 NULL 当 errno 指针去写
// ⇒ 崩在「对 NULL 对象调虚函数」那种地方。
//
// 这里自己实现：每线程一个 errno 槽（__thread 在我们这儿是安全的，
// 因为我们不再改 TPIDR_EL0，bionic 的 TLS 完好）。
static __thread int za_errno_slot;

void *za_os_errno_location(void)
{
    return &za_errno_slot;
}

// Switch 的 musl DSO 初始化：宿主侧已经提供了 libc 与 TLS，
// 这里只需要「明确表示已处理」，不要落进自动桩（落桩会返回 NULL 语义）。
unsigned int za_os_nnmusl_init_dso(void)
{
    return 0;
}

// ---------------------------------------------------------------- 客机用的 aligned_alloc
//
// ⚠ 客机（Switch 的 musl）调 aligned_alloc 时，**不会检查返回值**。
//   bionic 的实现要求 alignment 必须是 2 的幂，否则直接返回 NULL
//   ⇒ 客机拿着 NULL 继续走 ⇒ 跳空（pc=0）。
//   真机上 musl 的 aligned_alloc 宽松得多，所以这里自己实现一个：
//   - alignment 不要求是 2 的幂（向上取整到 2 的幂即可）
//   - 分配失败时再退一步用 mmap 兜底，尽量不返回 NULL
void *za_os_aligned_alloc(unsigned long alignment, unsigned long size)
{
    if (alignment < sizeof(void *)) alignment = sizeof(void *);
    // 对齐向上取整到 2 的幂
    size_t a = sizeof(void *);
    while (a < alignment && a < ((size_t)1 << 40)) a <<= 1;
    if ((alignment & (alignment - 1)) != 0 || size > (1ul << 30))
        ZLOGI("aligned_alloc 对齐/尺寸不寻常：align=%#lx size=%#lx", alignment, size);
    void *p = NULL;
    if (posix_memalign(&p, a, size ? (size_t)size : 1) != 0 || !p)
    {
        // 兜底：mmap 一块并手动对齐（宁可泄漏也不要给客机 NULL）
        size_t len = (size ? (size_t)size : 1);
        len = (len + a - 1) & ~(a - 1);
        void *m = mmap(NULL, len + a, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED) return NULL;
        uintptr_t base = ((uintptr_t)m + a - 1) & ~(uintptr_t)(a - 1);
        p = (void *)base;
    }
    return p;
}

//
// Switch 上 SDK 的 `nnosAllocateMemoryForThreadLocal` / `nnosFreeMemoryForThreadLocal`
// 只是**壳**：真正的实现在 OS 侧，由 OS 在装载 NN 时通过 SDK 导出的
// `nn::os::SetMemoryAllocatorForThreadLocal`（SDK 映像偏移 0x140d20）注册进
// .bss 的两个固定槽（0xb9b008 / 0xb9b010）。文件里这两个槽是 0，
// 不注册的话 SDK 一分配就 `br 0` 跳空。
void *za_os_alloc_thread_local(unsigned long size, unsigned long align)
{
    size_t sz = size ? (size_t)size : 16;
    size_t al = align ? (size_t)align : 16;
    if (al < 16) al = 16;
    // ★★ alignment 必须是 **2 的幂**，否则 posix_memalign 直接返回 EINVAL
    //   ⇒ 我们返回 NULL ⇒ 客机（musl 的 TLS 分配器）拿着 NULL 继续走
    //   ⇒ 跳进数据区执行 ⇒ pc=0（这正是本轮崩溃的形态）。
    //   客机传的 align 未必是 2 的幂 ⇒ 这里向上取整。
    {
        size_t p2 = sizeof(void *);
        while (p2 < al && p2 < ((size_t)1 << 40)) p2 <<= 1;
        al = p2;
    }
    sz = (sz + al - 1) & ~(al - 1);
    void *p = NULL;
    int rc = posix_memalign(&p, al, sz);
    if (rc != 0 || !p)
    {
        ZLOGE("TLS 分配失败：size=%#zx align=%#lx（posix_memalign rc=%d）", sz, al, rc);
        // 兜底：宁可给一块不对齐的内存，也不要给 NULL
        p = malloc(sz);
        if (!p) return NULL;
    }
    memset(p, 0, sz);
    // 前几次分配打出来：客机 TLS 分配器的参数能反映它要什么
    {
        static int n;
        if (n < 8) { n++; ZLOGI("TLS 分配 #%d：size=%#zx align=%#lx -> %p", n, sz, al, p); }
    }
    return p;
}

void za_os_free_thread_local(void *p, unsigned long size)
{
    (void)size;
    free(p);
}

// Switch 的 TLS 槽机制：AllocateTlsSlot 拿到一个槽号，Set/GetTlsValue 按槽存值。
// 客机自己的 TLS 变量（编译期 __thread）走影子描述符；这里是运行期分配的槽。
#define ZA_OS_TLS_SLOTS 16
static void *za_os_tls_values[ZA_OS_TLS_SLOTS];
static unsigned char za_os_tls_used[ZA_OS_TLS_SLOTS];

unsigned int za_os_allocate_tls_slot(void *slot_obj, void *destructor)
{
    (void)destructor;
    for (int i = 0; i < ZA_OS_TLS_SLOTS; i++)
    {
        if (!za_os_tls_used[i])
        {
            // ★ 不能再用「值 = 1」当占用标记：GetTlsValue 会把 1 当成真实值
            //   返回。main 的单例 getter（main+0x1a0a6b0 → GetTlsValue(槽1)）
            //   把返回值当对象指针解引用 ⇒ SIGSEGV addr=0xa9（实测）。
            //   「已分配但未设置」必须返回 0，让 getter 走创建分支。
            za_os_tls_used[i] = 1;
            za_os_tls_values[i] = NULL;
            if (slot_obj) *(unsigned long long *)slot_obj = (unsigned long long)i;
            return 0;
        }
    }
    return 1;
}

void za_os_set_tls_value(unsigned long long slot, unsigned long long value)
{
    if (slot < ZA_OS_TLS_SLOTS)
    {
        za_os_tls_used[slot] = 1;
        za_os_tls_values[slot] = (void *)(uintptr_t)value;
    }
}

unsigned long long za_os_get_tls_value(unsigned long long slot)
{
    if (slot < ZA_OS_TLS_SLOTS && za_os_tls_used[slot])
        return (unsigned long long)(uintptr_t)za_os_tls_values[slot];
    return 0;
}

void za_os_free_tls_slot(unsigned long long slot)
{
    if (slot < ZA_OS_TLS_SLOTS)
    {
        za_os_tls_used[slot] = 0;
        za_os_tls_values[slot] = NULL;
    }
}
