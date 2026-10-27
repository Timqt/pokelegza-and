// NVN 图形接口层对外接口。
//
// 客机只导入 nvnBootstrapLoader 一个符号；它拿名字来换函数地址，
// 之后再通过 nvnDeviceGetProcAddress 把所有入口解析出来（见 za_nvn.c 顶部注释）。
#ifndef ZA_NVN_H
#define ZA_NVN_H

// 初始化入口指针表（幂等，可重复调用）。
void za_nvn_init(void);

// nvnBootstrapLoader 的实现：返回该名字对应的实现地址（永不为 NULL）。
void *za_nvn_bootstrap(const char *name);

// 名字 -> 实现地址；不在表里返回 NULL。
void *za_nvn_lookup(const char *name);

#endif
