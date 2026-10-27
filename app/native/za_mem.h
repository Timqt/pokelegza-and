// 客机地址空间（Horizon GetInfo 语义 + 堆/栈/映射管理）。
#ifndef ZA_MEM_H
#define ZA_MEM_H

#include <stddef.h>

// 预留四块区域（ASLR / alias / stack / heap）。
void za_mem_init(void);

// GetInfo 的取值（id 语义见 za_mem.c 文件头）。
unsigned long long za_mem_getinfo(long id);

// 主堆：按客机要的尺寸开放（RW），返回堆基址；失败返回 NULL。
unsigned char *za_mem_heap_ensure(size_t size);

// 客机线程栈：从栈区分配。
unsigned char *za_mem_stack_alloc(size_t size);

// MapMemory / UnmapMemory / QueryMemory
int za_mem_map_memory(unsigned long long dst, unsigned long long src, unsigned long long size);
int za_mem_unmap_memory(unsigned long long dst, unsigned long long src, unsigned long long size);
// MapSharedMemory / UnmapSharedMemory（svc#19 / #20）：
// 客机先在 ASLR 区内挑一块空位，再让内核把共享内存映射到那个地址上。
int za_mem_map_shared(unsigned long long addr, unsigned long long size);
int za_mem_unmap_shared(unsigned long long addr, unsigned long long size);
// svc#44/#45 Map/UnmapPhysicalMemory 的登记：QueryMemory 据此把这块报成已映射/空闲。
void za_mem_note_mapping(unsigned long long addr, unsigned long long size, int on);

// 这段地址是否落在我们自己的预留区内（svc#44/#45 改权限前必须先问）
int za_mem_owns(unsigned long long addr, unsigned long long size);
// QueryMemory：填 MemoryInfo（base/size/state/attr/perm 六个字段），返回页信息（W1）。
unsigned long long za_mem_query_memory(unsigned long long addr, unsigned long long *mi);

#endif
