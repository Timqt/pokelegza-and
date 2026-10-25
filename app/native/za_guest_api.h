// 客机装载器的对外接口（za_activity.c 编排用）。
#ifndef ZA_GUEST_API_H
#define ZA_GUEST_API_H

#include <stddef.h>

typedef struct
{
    unsigned char *base;       // 映像基址
    size_t size;
    int resolved;             // 解析成功的符号数
    int stubbed;              // 落到自动桩的符号数
    int missing;              // 完全没解析出来的符号数
} za_guest_t;

// 1) 映射 main 映像（固定基址 0x100000000）+ 改写 TLS helper + 放描述符区
int za_guest_map(const unsigned char *text, const unsigned char *rodata,
                 const unsigned char *data_seg, size_t bss, unsigned char **out_base);

// 2) 建立 main 的导出符号视图（SDK 查 nnMain/nninitStartup 用）
int za_guest_mod_init(unsigned char *base, const unsigned char *exp_bin, size_t exp_len);

// 3) main 的重定位（基址重定位 + 导入解析，导入会查到 SDK 的导出表）
int za_guest_relocate(unsigned char *base, za_guest_t *out);

// 跑 main 的 _init / 静态构造器 / nninitStartup / nnMain
int za_guest_boot(za_guest_t *g);

// 解析客机导入的符号：宿主 nn::* 实现 → 模块导出表（SDK→main）→ dlsym。
// ⚠ 模块导出表**优先于 dlsym**（与上游 d2r-mobile 的 guest_sym 一致）：
//   客机的 malloc/free 是 main NSO 导出的**客机自己的 musl 分配器**，
//   落到 dlsym 会变成 bionic 的分配器 ⇒ SDK 与客机不是同一套堆 ⇒ 野指针。
// 只读 TLS 页 +0x1f0 = SDK init 结尾要恢复回 TPIDR_EL0 的值 = 本线程真实的 TPIDR_EL0。
// 必须在客机线程里、调 SDK init 之前调用。
void za_sdk_set_ro_tls_tpidr(unsigned long tp);
// 只读 TLS 页 +0x1f8 = 「当前线程对象指针」（SDK 会在 sdk+0x13edb4 写它，再取回来当对象用）。
// 指向**可写的客机 TLS 区**，不能指我们自造的只读结构。
void za_sdk_set_ro_tls_self(unsigned long self);

// 把 main / SDK 登记进 SDK 的模块链表（扮演 nnrtld）。
// 必须在 SDK 加载完成后、调 nnosInitialize 之前调用。
int za_sdk_register_modules(unsigned char *main_base, unsigned long long main_size);

// 造启动参数区（SDK 在 sdk+0x145b1c 处按 musl 格式解析它）。
// 返回的块里 argv[0]="main"；必须传给 nnosInitialize/Start 的第 2 个参数，别传 NULL。
void *za_build_startup_info(void);

void *za_resolve_host(const char *name);

void za_install_altstack(void);
void za_reinstall_signal_handlers(void);

void za_guest_start_sampler(void);

// ── 详细日志开关 ───────────────────────────────────────────────
// ⚠ 默认**关**。客机每秒能发起几十万次 svc，逐条打印会在 30 秒内刷出
//   40 万行 logcat：客机线程全耗在 liblog 里（这正是之前 liblog 崩溃的嫌疑），
//   而且日志本身会把我们真正的进度淹掉。
// 打开方式（不用重装 APK，下次冷启动生效）：
//   adb shell run-as org.pokelegza.android.port touch files/verbose
// 关闭：删掉那个文件。
int za_verbose_is_on(void);

// svc 调用计数：按服务号累加，用来在不开详细日志时也知道客机在调什么。
void za_svc_count(long nr);

// 分配一个线程句柄（主线程的句柄要交给 nnosInitialize 当 owner_id 源）。
int za_horizon_alloc_thread_handle(void);

// SDK 的「os 上下文」对象（za_sdk.c 建、za_guest_boot 用）。
extern void *za_sdk_ctx;
// 取计数并清零（看门狗线程定期调用）。
unsigned long za_svc_count_take(long nr);
// 只读不改（崩溃处理器用）
unsigned long za_svc_count_peek(long nr);
// svc #41 GetInfo 的按 id 计数（哪个 id 被狂问 = 死循环入口）
void za_svc41_count(long id);
unsigned long za_svc41_peek(long id);
// #41 调用点轨迹（最近 32 次的 调用点PC + id）
void za_svc41_trace(unsigned long pc, long id);
extern unsigned long za_svc41_trace_pc[32];
extern unsigned long za_svc41_trace_id[32];
extern unsigned long za_svc41_trace_pos;
// 通用 svc 轨迹（最近 32 次的 服务号 + 调用点PC）
void za_svc_trace(long nr, unsigned long pc);
// 富轨迹：额外记 x0 / x2 / x19 —— 「svc 返回了什么」和「客机拿它干了什么」
// 只有都记下来才能对上：崩溃点几乎总是紧跟某条 svc。
void za_svc_trace_rich(long nr, unsigned long pc,
                       unsigned long a0, unsigned long a2, unsigned long x19);
extern unsigned long za_svc_trace_nr[32];
extern unsigned long za_svc_trace_pc[32];
extern unsigned long za_svc_trace_arg0[32];
extern unsigned long za_svc_trace_arg2[32];
extern unsigned long za_svc_trace_x19[32];
extern unsigned long za_svc_trace_sp[32];
extern unsigned long za_svc_trace_retv[32];
// 回填最近一次 svc 的返回值（客机 w0）
void za_svc_trace_ret(long r);
extern unsigned long za_svc_trace_pos;
// 客机在 svc 那一刻的 sp（由 za_horizon.c 提供）
unsigned long za_horizon_guest_sp(void);
unsigned long za_svc_total_take(void);

// ── 线程栈边界登记 ─────────────────────────────────────────────
// 栈溢出是当前的头号故障：光看「崩在哪」不够，必须知道**哪条线程**、
// 它的栈有多大、用了多少。
typedef struct
{
    long tid;
    unsigned long lo;     // 栈低地址（增长方向的一端）
    unsigned long hi;     // 栈高地址
    const char *who;      // 哪来的线程：guest / svc / nnos
} za_stack_region_t;

void za_stack_register(long tid, unsigned long lo, unsigned long hi, const char *who);
const za_stack_region_t *za_stack_find(long tid);
// 在线程入口调用：自动从 /proc/self/maps 找出本线程栈的真实边界。
void za_stack_register_current(long tid, const char *who);

void za_install_rt_catch(void);
void za_dump_thread_mask(const char *tag);
void za_reinstall_sampler_handler(void);
#endif
