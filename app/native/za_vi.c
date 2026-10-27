// nn::vi 客户端 API 的宿主实现（显示 / 图层 / 原生窗口）。
//
// 为什么在客户端这一层接管，而不是继续补 vi:m 的 IPC 应答：
//   · 真机实测：SDK 的 nn::vi::CreateLayer → vi:m/vi:u 的 CMIF 请求，我们回了
//     Result=0 但没有出参 ⇒ CreateLayer 没写出 Layer*（保持 NULL），随后客机
//     调 nn::vi::GetNativeWindow(&out, NULL)，SDK 里 `ldr x8,[x0,#8]`（x0=0x10）
//     直接 SIGSEGV @ sdk+0x442a04。栈回溯已确认。
//   · vi 的 IPC 协议面很大（display/layer/scaling mode/vsync event/indirect layer…），
//     而我们最终要交给 NVN 的只是一个「原生窗口」指针。与其猜协议，不如在客户端
//     这一层给出语义正确的假对象：显示、图层、原生窗口都是我们自己的结构。
//   · 分层上没有损失：SDK 的 vi 本来就是一层 IPC 客户端壳；我们接管的就是这层壳。
//
// ⚠ 只接管 main 真正导入的 5 个入口（CreateLayer / GetNativeWindow / DestroyLayer /
//   OpenDefaultDisplay / CloseDisplay）。nn::vi::Initialize / Finalize 仍走 SDK 原实现
//   —— 它们要维护 SDK 内部的 vi 状态（其它 SDK 模块也会读），接掉反而会让 SDK
//   自认为没初始化。
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "za_common.h"
#include "za_vi.h"

typedef unsigned int u32;
typedef unsigned long long u64;

enum { ZA_VI_MAX_LAYERS = 8 };

typedef struct {
    u32 magic;
    u32 kind;          // 1 = display, 2 = layer, 3 = native window
    u64 display;       // 图层所属的显示对象指针
    u64 native_window; // 图层对应的原生窗口指针
    u32 width;
    u32 height;
} za_vi_obj;

static za_vi_obj za_vi_display;
static za_vi_obj za_vi_native_window;
static za_vi_obj za_vi_layers[ZA_VI_MAX_LAYERS];
static int za_vi_layer_next;
static int za_vi_created;

#define ZA_VI_MAGIC 0x5a415649u /* "ZAVI" */

// 默认分辨率：客机不会读这两个数（NVN 层只用窗口指针），但给个真实值便于日志核对。
#define ZA_VI_DEFAULT_W 1280u
#define ZA_VI_DEFAULT_H 720u

static void za_vi_obj_init(za_vi_obj *o, u32 kind)
{
    memset(o, 0, sizeof *o);
    o->magic = ZA_VI_MAGIC;
    o->kind = kind;
    o->width = ZA_VI_DEFAULT_W;
    o->height = ZA_VI_DEFAULT_H;
}

static int za_vi_ok(const void *p, u32 kind)
{
    const za_vi_obj *o = (const za_vi_obj *)p;
    return o && o->magic == ZA_VI_MAGIC && o->kind == kind;
}

u32 za_vi_open_default_display(void **out)
{
    if (!za_vi_created) {
        za_vi_obj_init(&za_vi_display, 1);
        za_vi_obj_init(&za_vi_native_window, 3);
        za_vi_created = 1;
    }
    if (out) *out = &za_vi_display;
    ZLOGI("★ vi: OpenDefaultDisplay -> %p（默认显示 %ux%u）", (void *)&za_vi_display,
          ZA_VI_DEFAULT_W, ZA_VI_DEFAULT_H);
    return 0;
}

u32 za_vi_create_layer(void **out, void *display, u64 a2, u64 a3)
{
    za_vi_obj *l;
    if (za_vi_layer_next >= ZA_VI_MAX_LAYERS) {
        ZLOGE("★ vi: CreateLayer 超过 %d 个图层（客机在泄漏？）", ZA_VI_MAX_LAYERS);
        return 1;
    }
    l = &za_vi_layers[za_vi_layer_next++];
    za_vi_obj_init(l, 2);
    l->display = (u64)(uintptr_t)(za_vi_ok(display, 1) ? display : &za_vi_display);
    l->native_window = (u64)(uintptr_t)&za_vi_native_window;
    if (out) *out = l;
    ZLOGI("★ vi: CreateLayer(display=%p, a2=%#llx, a3=%#llx) -> %p", display,
          (unsigned long long)a2, (unsigned long long)a3, (void *)l);
    return 0;
}

u32 za_vi_get_native_window(void **out, void *layer)
{
    const za_vi_obj *l = (const za_vi_obj *)layer;
    if (!za_vi_ok(l, 2)) {
        // 真机上这里原本是「Layer* == NULL ⇒ SDK 内部空指针崩」。给一个兜底，
        // 免得某个 SDK 内部分支再传空进来时把进程带走。
        ZLOGE("★ vi: GetNativeWindow 收到非法 Layer(%p) —— 用默认原生窗口兜底", layer);
        if (out) *out = &za_vi_native_window;
        return 0;
    }
    if (out) *out = (void *)(uintptr_t)l->native_window;
    ZLOGI("★ vi: GetNativeWindow(layer=%p) -> %p", layer,
          (void *)(uintptr_t)l->native_window);
    return 0;
}

u32 za_vi_destroy_layer(void *layer)
{
    ZLOGI("★ vi: DestroyLayer(%p)", layer);
    return 0;
}

u32 za_vi_close_display(void *display)
{
    ZLOGI("★ vi: CloseDisplay(%p)", display);
    return 0;
}

// 供 NVN 层查询「当前原生窗口的默认尺寸」（后续接真 GPU 时用）。
void *za_vi_native_window_ptr(void)
{
    if (!za_vi_created) return NULL;
    return &za_vi_native_window;
}
