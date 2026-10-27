// nn::vi 客户端 API 的宿主实现（显示 / 图层 / 原生窗口）。
// 依据见 za_vi.c 顶部：真机上 SDK 的 CreateLayer 拿不到我们假 IPC 的出参，
// 导致 Layer* 保持 NULL，随后 nn::vi::GetNativeWindow 在 SDK 内空指针崩溃。
#ifndef ZA_VI_H
#define ZA_VI_H

unsigned int za_vi_open_default_display(void **out);
unsigned int za_vi_create_layer(void **out, void *display, unsigned long long a2,
                                unsigned long long a3);
unsigned int za_vi_get_native_window(void **out, void *layer);
unsigned int za_vi_destroy_layer(void *layer);
unsigned int za_vi_close_display(void *display);

// 当前假原生窗口指针（未创建时为 NULL）。
void *za_vi_native_window_ptr(void);

#endif
