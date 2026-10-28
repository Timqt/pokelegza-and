// Android 上没有 mach/mach_time.h。这份垫片只为让参考实现的 nvn_dirty.c 编译：
// 它只是用 mach_absolute_time 给 mprotect 计时（脏页追踪，安卓路径本就不启用）。
// mach 时基按 1:1 返回纳秒，mach_timebase_info 给 numer=denom=1。
#pragma once
#include <stdint.h>
typedef int kern_return_t;
typedef struct { uint32_t numer, denom; } mach_timebase_info_data_t;
uint64_t mach_absolute_time(void);
kern_return_t mach_timebase_info(mach_timebase_info_data_t *info);
// Apple 的便捷接口：直接返回指定时钟的纳秒数。安卓用 clock_gettime 顶替。
uint64_t clock_gettime_nsec_np(int clock_id);
void mach_wait_until(uint64_t deadline);
