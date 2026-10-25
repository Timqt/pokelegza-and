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
// QueryMemory：填 MemoryInfo（base/size/state/attr/perm 六个字段），返回页信息（W1）。
unsigned long long za_mem_query_memory(unsigned long long addr, unsigned long long *mi);

#endif
