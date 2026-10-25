// 客机加载器的共享日志宏。
//
// ⚠ 信号处理里**不能**用这些宏（__android_log_print 不可重入）——
// 那条路径见 za_guest.c 里的 za_log_raw（手写格式化 + write(2)）。
#ifndef ZA_COMMON_H
#define ZA_COMMON_H

#include <android/log.h>

// 我们的日志**同时**写到 logcat 和设备上的 files/za_log.txt。
// ⚠ 为什么必须落文件：logcat 缓冲会被系统日志刷掉（实测跑 18 秒后
//   我们的行就没了）⇒ 下一轮迭代根本看不到上一轮遇到过什么。
//   落文件后，app/tools/smoke_test.py 每次都能把上一轮的完整现场拉回来。
void za_log_print(int prio, const char *tag, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

#define ZLOGI(...) za_log_print(ANDROID_LOG_INFO, "ZaGuest", __VA_ARGS__)
#define ZLOGE(...) za_log_print(ANDROID_LOG_ERROR, "ZaGuest", __VA_ARGS__)

#endif
