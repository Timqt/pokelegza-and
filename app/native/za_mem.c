// 客机地址空间（我们扮演 Switch OS，必须提供的那四块区域）。
//
// 真机上这四块由 OS 提供；语义是 Horizon 服务 0x29「GetInfo」的 id 枚举：
//   2  I_AliasAddr   3  I_AliasSize    物理内存别名区（VammManager 的 MapPhysicalMemory 用）
//   4  I_HeapAddr    5  I_HeapSize     主堆
//   12 I_AslrAddr   13  I_AslrSize     程序自身（ASLR 区）
//   14 I_StackAddr  15 I_StackSize    线程栈区
//   6  I_TotalMem   21  I_TotalNonSys  应用内存池总量
//   7  I_UsedMem    22  I_UsedNonSys   已用（堆 + 映像）
//   0  I_CoreMask   1  I_PriorityMask 8  I_DebuggerAttached 11 I_RandomEntropy
//   16 I_SysResTotal 17 I_SysResUsed  18 I_ProgramId  23 I_IsApplication
//
// ⚠⚠ 这些值**绝对不能全 0** —— 这是本轮最贵的坑：
//   SDK 的 nnosInitialize 会拿 Heap/Alias/Aslr/Stack 的 (基址, 大小) 构造
//   nn::os::detail::AddressSpaceAllocator（范围 + 16KB 粒度 + 禁止区表）。
//   全 0 ⇒ 分配器拿到一个**空区间** ⇒ 它在里面反复找空位，
//   实测空转 104 万次、#41 被调 1150 万次 ⇒ 客机线程把 256MB 栈跑爆。
//
// 布局照 d2r-and 的 hle_svc.c（那边是已上线的成品）：
//   预留一整块 PROT_NONE 大区（ASLR），里面切出 alias / stack / heap。
//   **heap 和 alias 必须在 ASLR 区内** —— SDK 的禁止区表按「相对 ASLR 基址的偏移」算，
//   区外的话偏移会算成负数。
//   主 NSO 仍然固定在 0x100000000（客机代码里写死了那个基址），它不在 ASLR 区内，
//   与 d2r 的做法一致。

// process_vm_readv 要 _GNU_SOURCE（bionic 的 <sys/uio.h> 才声明它）
// ⚠ 必须在任何系统头文件之前定义
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>

#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "za_common.h"
#include "za_guest_api.h"
#include "za_mem.h"
#include "za_sdk.h"


// 整块预留大小（PROT_NONE，只占地址空间不占内存）
// ★ 2026-10-25：5GB ⇒ 16GB。游戏的 nn::init::Start 要 0x300000000（12GB）的堆
//   （main+0x19f84b4 硬编码），CentralHeap::Init(ptr=0) 会向地址空间分配器
//   申请这么大一整块；5GB 的预留永远凑不出来 ⇒ 申请失败 ⇒ nn::diag abort
//   （实测：StandardAllocator::Initialize 断言、Break 调用者 sdk+0x9ab48）。
// ★ 必须带 MAP_NORESERVE：heap_ensure/svc#44 会把 12GB 转 RW，
//   没有 NORESERVE 时内核要一次性预留 12GB commit ⇒ 8GB 设备直接 ENOMEM。
#define ZA_MEM_RESERVE (16ull << 30)
// ★ 报给客机的 ASLR 区大小（GetInfo 12/13、QueryMemory 的空闲上界）。
//   真机 Switch 上这个值约 512GB；客机的地址空间分配器要在「四块区域之外的
//   空闲」里放下一整个 12GB 的系统资源块，16GB 实际预留扣掉 alias/stack/heap
//   后凑不出来。声明区可以远大于实际预留：超出部分 QueryMemory 照报空闲，
//   客机真要用时 svc#44 会现场 mmap（也要 NORESERVE）。
#define ZA_MEM_ASLR_DECL (64ull << 30)
// 四块区域的划分（相对预留块基址），与 d2r-and 保持一致
#define ZA_MEM_ALIAS_OFF 0x10000000ull
#define ZA_MEM_ALIAS_CAP 0x20000000ull   // 512MB
#define ZA_MEM_STACK_OFF 0x30000000ull
#define ZA_MEM_STACK_CAP 0x10000000ull   // 256MB
#define ZA_MEM_HEAP_OFF  0x40000000ull
#define ZA_MEM_HEAP_CAP  0x300000000ull  // 12GB —— ≥ nn::init::Start 要的 0x300000000

// 报给游戏的「应用内存池」：Switch 上是 3285MB，这里多给一点（d2r 加 512MB）
#define ZA_MEM_APP_POOL (0xED500000ull)

static unsigned char *g_as;          // 预留块基址（= ASLR 区基址）
static unsigned char *g_alias;
static unsigned char *g_stack;
static unsigned char *g_heap;
static size_t g_heap_cur;            // 堆已开放（RW）的字节数
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

// ── 已映射区间登记（QueryMemory 据此回报；SDK 靠它找空位）──
// state: 0x0B = MappedMemory
#define ZA_MEM_MAX_MAP 4096
typedef struct { unsigned long long base, size, src; unsigned int state; } za_mem_map_t;
static za_mem_map_t g_map[ZA_MEM_MAX_MAP];
static int g_nmap;

static void za_mem_map_add(unsigned long long base, unsigned long long size,
                            unsigned long long src, unsigned int state)
{
    if (size == 0) return;
    for (int i = 0; i < g_nmap; i++)
        if (g_map[i].base == base) { g_map[i].size = size; g_map[i].src = src; g_map[i].state = state; return; }
    if (g_nmap >= ZA_MEM_MAX_MAP) return;
    g_map[g_nmap].base = base;
    g_map[g_nmap].size = size;
    g_map[g_nmap].src = src;
    g_map[g_nmap].state = state;
    g_nmap++;
}

// 找包含 addr 的区间（1 基下标，0 = 没有）
static int za_mem_map_find(unsigned long long addr)
{
    for (int i = 0; i < g_nmap; i++)
        if (g_map[i].size && addr >= g_map[i].base && addr < g_map[i].base + g_map[i].size)
            return i + 1;
    return 0;
}

// 预留整块地址空间 + 切分四块区域。
// 只做一次；重复调用安全。
void za_mem_init(void)
{
    if (g_as) return;
    pthread_mutex_lock(&g_lock);
    if (!g_as)
    {
        void *p = mmap((void *)(uintptr_t)ZA_MEM_BASE_ADDR, (size_t)ZA_MEM_RESERVE,
                       PROT_NONE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
        if (p == MAP_FAILED)
        {
            ZLOGE("客机地址空间固定基址 %#lx 被占：%s", (unsigned long long)ZA_MEM_BASE_ADDR,
                  strerror(errno));
            p = mmap(NULL, (size_t)ZA_MEM_RESERVE, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
        }
        if (p == MAP_FAILED)
        {
            ZLOGE("客机地址空间预留失败（%llu 字节）：%s",
                  (unsigned long long)ZA_MEM_RESERVE, strerror(errno));
            pthread_mutex_unlock(&g_lock);
            return;
        }
        g_as = (unsigned char *)p;
        g_alias = g_as + ZA_MEM_ALIAS_OFF;
        g_stack = g_as + ZA_MEM_STACK_OFF;
        g_heap = g_as + ZA_MEM_HEAP_OFF;
        ZLOGI("客机地址空间：ASLR=%p+%#llx alias=%p+%#llx stack=%p+%#llx heap=%p+%#llx",
              (void *)g_as, (unsigned long long)ZA_MEM_RESERVE,
              (void *)g_alias, (unsigned long long)ZA_MEM_ALIAS_CAP,
              (void *)g_stack, (unsigned long long)ZA_MEM_STACK_CAP,
              (void *)g_heap, (unsigned long long)ZA_MEM_HEAP_CAP);
    }
    pthread_mutex_unlock(&g_lock);
}

static unsigned long long za_mem_random64(void)
{
    // ⚠ 不能每次都 open("/dev/urandom")：svc #41(id=11) 会被问几十万次，
    //   每次开一次文件会把系统调用打爆（而且实测崩在 libc 的 open 里）。
    // 改成静态 xorshift：一次性取种子，之后纯算。
    static unsigned long long s = 0;
    if (!s)
    {
        unsigned long long v = 0;
        int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) { ssize_t n = read(fd, &v, sizeof v); (void)n; close(fd); }
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        s = v ^ ((unsigned long long)ts.tv_sec << 32) ^ (unsigned long long)ts.tv_nsec;
        if (!s) s = 0x9E3779B97F4A7C15ull;
    }
    s ^= s << 13;
    s ^= s >> 7;
    s ^= s << 17;
    return s;
}


// ── 真实映射查询（/proc/self/maps）────────────────────────────────────────
//
// 为什么需要：svc #6 QueryMemory 的地址可能落在**宿主进程的任何一个映射**里
// （客机的栈、线程栈、mmap 出来的匿名区…）。以前对「不认识地址」一律回报
// 「它所在的 4 KiB 页 + Code 权限」⇒ SDK 把**主线程栈记成一页**，
// 之后 nn::os::GetCurrentStackInfo 断言 sp 仍在该区间里就失败。
// d2r-and（已上线成品）hle_svc.c case 0x06 的注释写得很清楚：
//   「原先对客体地址空间之外的地址一律回报『它所在的 4 KiB 页』，
//     主线程栈于是被记成一页……换个环境偶发启动即中止。」
//
// 这里改成：**如实报告该地址所在的真实映射**（base/size/权限），
// 并且优先识别出「宿主线程栈」⇒ 报整段栈 + state 0x0B。
#define ZA_MAPS_MAX 512
typedef struct
{
    unsigned long long lo, hi;
    unsigned int perm;     // 1=只读 3=读写 5=读+执行 0=不可访问
    int is_stack;
} za_map_t;

static za_map_t g_maps[ZA_MAPS_MAX];
static int g_nmaps;
static long long g_maps_at;

static void za_mem_refresh_maps(void)
{
    int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    g_nmaps = 0;
    if (fd < 0) { g_maps_at = 0; return; }
    char buf[16384];
    ssize_t n = read(fd, buf, sizeof buf - 1);
    close(fd);
    if (n <= 0) { g_maps_at = 0; return; }
    buf[n] = 0;
    const char *line = buf;
    while (line && *line && g_nmaps < ZA_MAPS_MAX)
    {
        unsigned long long lo = 0, hi = 0;
        char perms[8] = {0};
        int a = 0, b = 0;
        // 解析 "lo-hi perms ..."
        const char *p1 = line;
        while (*p1 && *p1 != '-') p1++;
        if (*p1 != '-') break;
        char tmp[64];
        size_t tl = (size_t)(p1 - line);
        if (tl >= sizeof tmp) break;
        memcpy(tmp, line, tl); tmp[tl] = 0;
        if (sscanf(tmp, "%llx", &lo) != 1) break;
        const char *p2 = p1 + 1;
        while (*p2 && *p2 != ' ' && *p2 != '\n') p2++;
        tl = (size_t)(p2 - (p1 + 1));
        if (tl >= sizeof tmp) break;
        memcpy(tmp, p1 + 1, tl); tmp[tl] = 0;
        if (sscanf(tmp, "%llx", &hi) != 1) break;
        while (*p2 == ' ') p2++;
        memcpy(perms, p2, 4); perms[4] = 0;
        // 名字里带 stack 的当栈
        int is_stack = (strstr(line, "stack") != NULL);
        za_map_t *m2 = &g_maps[g_nmaps++];
        m2->lo = lo; m2->hi = hi;
        m2->is_stack = is_stack;
        m2->perm = (perms[0] == 'r')
                 ? ((perms[2] == 'x') ? 5u : ((perms[1] == 'w') ? 3u : 1u))
                 : 0u;
        const char *eol = strchr(line, '\n');
        line = eol ? eol + 1 : NULL;
    }
    g_maps_at = 1;
}

static const za_map_t *za_mem_find_mapping(unsigned long long addr)
{
    if (!g_maps_at) za_mem_refresh_maps();
    for (int i = 0; i < g_nmaps; i++)
        if (addr >= g_maps[i].lo && addr < g_maps[i].hi) return &g_maps[i];
    return NULL;
}
// GetInfo 的取值。id 见文件头的枚举。
unsigned long long za_mem_getinfo(long id)
{
    if (!g_as) za_mem_init();
    switch (id)
    {
    case 0:  return 7;                                   // CoreMask：4 核可用
    case 1:  return 0;                                   // PriorityMask
    case 2:  return (unsigned long long)(uintptr_t)g_alias;   // AliasAddr
    case 3:  return ZA_MEM_ALIAS_CAP;                    // AliasSize
    case 4:  return (unsigned long long)(uintptr_t)g_heap;    // HeapAddr
    case 5:  return ZA_MEM_HEAP_CAP;                     // HeapSize
    case 6:  return ZA_MEM_APP_POOL;                     // TotalMem
    case 7:  return g_heap_cur;                          // UsedMem
    case 8:  return 0;                                   // DebuggerAttached
    case 9:  return 0;                                   // ResourceLimit
    case 10: return 0;                                   // IdleTick
    case 11: return za_mem_random64();                   // RandomEntropy
    case 12: return (unsigned long long)(uintptr_t)g_as;      // AslrAddr
    case 13: return ZA_MEM_ASLR_DECL;                         // AslrSize（声明值，见文件头注释）
    case 14: return (unsigned long long)(uintptr_t)g_stack;   // StackAddr
    case 15: return ZA_MEM_STACK_CAP;                    // StackSize
    case 16: return 0x2000000;                           // SysResTotal
    case 17: return 0x400000;                            // SysResUsed
    case 18: return 0x0100726014352000ull;                // ProgramId
    case 19: return 0;                                   // InitProcIdRange
    case 20: return 0;                                   // UserExcAddr
    case 21: return ZA_MEM_APP_POOL;                     // TotalNonSys
    case 22: return g_heap_cur;                          // UsedNonSys
    case 23: return 1;                                   // IsApplication ★
    default: return 0;
    }
}

// 主堆：按客机要的尺寸开放（RW）。可以多次调用来扩大。
unsigned char *za_mem_heap_ensure(size_t size)
{
    if (!g_as) za_mem_init();
    if (!g_heap) return NULL;
    if (size > ZA_MEM_HEAP_CAP) return NULL;
    pthread_mutex_lock(&g_lock);
    if (size > g_heap_cur)
    {
        if (mprotect(g_heap + g_heap_cur, size - g_heap_cur, PROT_READ | PROT_WRITE) != 0)
        {
            ZLOGE("主堆开放失败（%zu 字节 @%p）：%s", size - g_heap_cur,
                  (void *)(g_heap + g_heap_cur), strerror(errno));
            pthread_mutex_unlock(&g_lock);
            return NULL;
        }
        g_heap_cur = size;
        za_mem_map_add((unsigned long long)(uintptr_t)g_heap, size, 0, 5);   // state 5 = Heap
    }
    unsigned char *b = g_heap;
    pthread_mutex_unlock(&g_lock);
    return b;
}

// 客机线程栈：从栈区里分配（SDK 的 MapMemory 会把栈搬到这儿）。
unsigned char *za_mem_stack_alloc(size_t size)
{
    if (!g_as) za_mem_init();
    if (!g_stack) return NULL;
    size = (size + 0xFFF) & ~(size_t)0xFFF;
    if (size == 0) size = 0x1000;
    pthread_mutex_lock(&g_lock);
    static size_t used;
    if (used + size > ZA_MEM_STACK_CAP) { pthread_mutex_unlock(&g_lock); return NULL; }
    unsigned char *p = g_stack + used;
    used += size;
    pthread_mutex_unlock(&g_lock);
    if (mprotect(p, size, PROT_READ | PROT_WRITE) != 0)
    {
        ZLOGE("栈区分配失败（%zu 字节 @%p）：%s", size, (void *)p, strerror(errno));
        return NULL;
    }
    za_mem_map_add((unsigned long long)(uintptr_t)p, size, 0, 0x0B);
    return p;
}

// MapSharedMemory / UnmapSharedMemory（svc#19 / #20）
//
// 客机流程（实测反汇编 SDK+0x143c44）：
//   ① SDK 自己的地址空间分配器（SDK+0x636f20）在 ASLR 区内挑一块空位
//      ⇒ 例如 0x404b60000
//   ② svc#19 MapSharedMemory(handle, 0x404b60000, 0x1000, perm)
//   ③ SDK+0x636f30 把它登记进自己的页表
//   ④ 之后 SDK 就当这块内存存在（seqlock 读它）
//
// 以前 svc#19 是**空实现** ⇒ ②什么都没做 ⇒ ④读 0x404b60038 ⇒ SIGSEGV
// （真机实测：pc=SDK+0x42ff34 addr=0x404b60038，x9=0x404b60000）。
//
// ⚠ ASLR 区是整块 PROT_NONE 预留的（mmap PROT_NONE + 5GB），
//   所以**不能用 mmap**（那段地址已经被预留映射占了），
//   只能用 mprotect 在预留块里开口子。
int za_mem_map_shared(unsigned long long addr, unsigned long long size)
{
    if (!g_as) za_mem_init();
    if (!g_as || !addr || !size) return 0;
    size = (size + 0xFFF) & ~0xFFFull;
    unsigned long long lo = (unsigned long long)(uintptr_t)g_as;
    // 越界判定按**声明区**（64GB）：QueryMemory 报给客机的空闲就是这么大，
    // 客机分配器会把共享内存挑在实际预留之外的地方（实测 0x103866f000）。
    if (addr < lo || addr + size > lo + ZA_MEM_ASLR_DECL)
    {
        ZLOGE("MapSharedMemory：%#llx 不在客机声明地址空间内，拒绝", addr);
        return 0;
    }
    if (addr < lo + ZA_MEM_RESERVE)
    {
        // 实际预留内：ASLR 区是整块 PROT_NONE，用 mprotect 开口子
        if (mprotect((void *)(uintptr_t)addr, (size_t)size, PROT_READ | PROT_WRITE) != 0)
        {
            ZLOGE("MapSharedMemory 开放失败（%#llx+%#llx）：%s", addr, size, strerror(errno));
            return 0;
        }
    }
    else
    {
        // 声明区内、实际预留外：现场映射（NORESERVE，页面按需落地）
        void *p = mmap((void *)(uintptr_t)addr, (size_t)size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
        if (p == MAP_FAILED &&
            mprotect((void *)(uintptr_t)addr, (size_t)size, PROT_READ | PROT_WRITE) != 0)
        {
            ZLOGE("MapSharedMemory 现场映射失败（%#llx+%#llx）：%s", addr, size, strerror(errno));
            return 0;
        }
    }
    za_mem_map_add(addr, size, 0, 0x0B);
    return 1;
}

int za_mem_unmap_shared(unsigned long long addr, unsigned long long size)
{
    if (!g_as || !addr || !size) return 0;
    size = (size + 0xFFF) & ~0xFFFull;
    unsigned long long lo = (unsigned long long)(uintptr_t)g_as;
    if (addr < lo || addr + size > lo + ZA_MEM_ASLR_DECL)
        return 0;
    if (addr < lo + ZA_MEM_RESERVE)
        mprotect((void *)(uintptr_t)addr, (size_t)size, PROT_NONE);  // 收回成预留态
    else
        munmap((void *)(uintptr_t)addr, (size_t)size);               // 现场映射的直接摘除
    za_mem_map_add(addr, 0, 0, 0);      /* size=0 ⇒ za_mem_map_find 当成没占用 */
    return 1;
}

// svc#44/#45 的登记：让 QueryMemory 把这块报成已映射（0x0B），
// 否则客机分配器可能把同一段地址再分给别人。
void za_mem_note_mapping(unsigned long long addr, unsigned long long size, int on)
{
    if (!g_as || !addr || !size) return;
    pthread_mutex_lock(&g_lock);
    if (on)
        za_mem_map_add(addr, size, 0, 0x0B);
    else
        za_mem_map_add(addr, 0, 0, 0);  /* size=0 ⇒ 当成没占用 */
    pthread_mutex_unlock(&g_lock);
}

// MapMemory(dst, src, size)：把 src 的内容搬到 dst（src=0 就只是占位）。
// 客机建线程时用它把堆上的栈搬进栈区。
// 语义照 d2r-and 的 hle_svc.c（那边是已上线的成品）：
//   - 目标必须在**栈区**内且不能已被占用
//   - 搬移语义：内容从 src 复制到 dst
int za_mem_map_memory(unsigned long long dst, unsigned long long src, unsigned long long size)
{
    if (!dst || size == 0) return 0;
    if (dst & 0xFFF) return 0xDC01;       // 目标没对齐
    size = (size + 0xFFF) & ~0xFFFull;
    if (!g_as) za_mem_init();
    // 目标必须落在栈区里（SDK 建线程只把栈搬进栈区）
    if (!g_stack || dst < (unsigned long long)(uintptr_t)g_stack ||
        dst + size > (unsigned long long)(uintptr_t)g_stack + ZA_MEM_STACK_CAP)
        return 0xDC01;
    if (za_mem_map_find(dst)) return 0xDC01;    // 已占用
    if (mprotect((void *)(uintptr_t)dst, (size_t)size, PROT_READ | PROT_WRITE) != 0)
    {
        ZLOGE("MapMemory 开放失败（%#llx+%#llx）：%s", dst, size, strerror(errno));
        return 0xD401;
    }
    if (src)
    {
        // 源没全映射时只拷读得到的部分；剩下的是零页（匿名映射本来就是零）。
        size_t chunk = 1u << 20;
        for (unsigned long long off = 0; off < size; off += chunk)
        {
            size_t n = (size_t)((size - off < chunk) ? (size - off) : chunk);
            struct iovec l, r;
            l.iov_base = (void *)(uintptr_t)(dst + off);
            l.iov_len = n;
            r.iov_base = (void *)(uintptr_t)(src + off);
            r.iov_len = n;
            if (process_vm_readv(getpid(), &l, 1, &r, 1, 0) != (ssize_t)n)
                break;
        }
    }
    za_mem_map_add(dst, size, src, 0x0B);
    return 0;
}

int za_mem_unmap_memory(unsigned long long dst, unsigned long long src, unsigned long long size)
{
    if (!dst || size == 0) return 0;
    size = (size + 0xFFF) & ~0xFFFull;
    int k = za_mem_map_find(dst);
    if (!k || g_map[k - 1].base != dst || g_map[k - 1].size != size)
        return 0xD401;
    if (src)
    {
        // 搬回源区
        size_t chunk = 1u << 20;
        for (unsigned long long off = 0; off < size; off += chunk)
        {
            size_t n = (size_t)((size - off < chunk) ? (size - off) : chunk);
            struct iovec l, r;
            l.iov_base = (void *)(uintptr_t)(src + off);
            l.iov_len = n;
            r.iov_base = (void *)(uintptr_t)(dst + off);
            r.iov_len = n;
            if (process_vm_readv(getpid(), &l, 1, &r, 1, 0) != (ssize_t)n)
                break;
        }
    }
    g_map[k - 1].size = 0;
    // 不收回权限（16K 页可能与相邻映射共用）
    return 0;
}

// QueryMemory(MemoryInfo* out, PageInfo* pout, addr)
//   MemoryInfo 布局：base(0x00) size(0x08) state(0x10) attr(0x14) perm(0x18)
//   state: 0=空闲 3=Code 5=Heap 0x0B=已映射 0x0B=Stack
//   perm : 0=无 3=读写 5=读+执行
//
// ⚠ 这一段是本轮最关键的修复：以前我们把 *out 全写 0、
//   自由区间的大小永远是 0 ⇒ SDK 的地址空间分配器找不到任何空位，
//   在那儿空转 100 万次（#41 被问 1150 万次）⇒ 客机线程栈溢出 256MB。
//   语义照 d2r-and 的 hle_svc.c（已上线成品）。
unsigned long long za_mem_query_memory(unsigned long long addr, unsigned long long *mi)
{
    unsigned long long base = 0, size = 0, state = 0, perm = 0;
    int k;
    pthread_mutex_lock(&g_lock);
    if (g_heap && addr >= (unsigned long long)(uintptr_t)g_heap &&
        addr < (unsigned long long)(uintptr_t)g_heap + g_heap_cur)
    {
        base = (unsigned long long)(uintptr_t)g_heap;
        size = g_heap_cur;
        state = 5;      // Heap
        perm = 3;
    }
    else if ((k = za_mem_map_find(addr)))
    {
        base = g_map[k - 1].base;
        size = g_map[k - 1].size;
        state = g_map[k - 1].state;
        perm = 3;
    }
    else if (g_as && addr >= (unsigned long long)(uintptr_t)g_as &&
             addr < (unsigned long long)(uintptr_t)g_as + ZA_MEM_ASLR_DECL)
    {
        // 空闲：报到「相邻映射/堆边界」为止。上界用**声明区**（64GB）而不是
        // 实际预留（16GB）—— 客机分配器要在四块区域之外放下 12GB 的系统资源，
        // 超出实际预留的部分 svc#44 会现场 mmap。
        unsigned long long lo = (unsigned long long)(uintptr_t)g_as;
        unsigned long long hi = (unsigned long long)(uintptr_t)g_as + ZA_MEM_ASLR_DECL;
        if (addr >= (unsigned long long)(uintptr_t)g_heap)
            lo = (unsigned long long)(uintptr_t)g_heap + g_heap_cur;
        else if (hi > (unsigned long long)(uintptr_t)g_heap)
            hi = (unsigned long long)(uintptr_t)g_heap;
        for (int i = 0; i < g_nmap; i++)
        {
            if (!g_map[i].size) continue;
            unsigned long long e = g_map[i].base + g_map[i].size;
            if (e <= addr && e > lo) lo = e;
            if (g_map[i].base > addr && g_map[i].base < hi) hi = g_map[i].base;
        }
        base = lo;
        size = hi - lo;
        state = 0;      // 空闲
        perm = 0;
    }
    else
    {
        // 地址落在「当前宿主线程的栈」里：回报整段栈（state 0x0B）。
        //
        // ★ 2026-10-25：这一段是照 d2r-and（已上线成品）hle_svc.c case 0x06 改的。
        //   d2r 用的是 pthread_get_stackaddr_np / pthread_get_stacksize_np，
        //   我们原来用 pthread_getattr_np —— 取不到时就谎报成「Code 4KB」，
        //   结果 **SDK 把主线程栈记成一页**（真机上是整段栈），
        //   之后 nn::os::GetCurrentStackInfo 断言 sp 仍在该区间里 ⇒ 失败/跳空。
        //   d2r 的原注释：
        //     「原先对客体地址空间之外的地址一律回报『它所在的 4 KiB 页』，
        //       主线程栈于是被记成一页——初始化时的 sp 与后来的 sp 是否同页，
        //       取决于宿主栈顶的绝对位置，而它随环境变量/启动参数总长移动
        //       （换个环境偶发启动即中止）。」
        // ① 宿主线程栈 ⇒ 报整段栈（state 0x0B）
        //
        // ★ 2026-10-25（小米平板 25079RPDCC 实机定位）：这段以前**永远判不中**。
        //   原因：**POSIX 规定 pthread_attr_getstack 返回的是「最低地址」（栈底）**，
        //   而代码把它当「栈顶」用（base = t - ssz、判定 addr < t）——
        //   判据整段错位 ⇒ 落到下面的「一页 Code」分支。
        //   实测数字：客机线程栈底 0x6d584a5000 / 栈顶 0x6d684a9000（256 MB），
        //   SDK 用自己的 sp（0x6d684a5100）来问，我们却回报「一页 4 KiB / Code」
        //   ⇒ SDK 把主线程栈记成一页 ⇒ 后续 nn::os::GetCurrentStackInfo
        //   断言 sp 仍在该区间里就失败 ⇒ 客机走进坏区间 ⇒ pc=0 跳空。
        //   （d2r-and 的 hle_svc.c 用 bionic 私有 API pthread_get_stackaddr_np，
        //     它返回的是**栈顶**；安卓上这符号不导出，只能用 pthread_attr_getstack。）
        //
        // ① 先用宿主登记的栈区间（za_stack_find）：它是从 /proc/self/maps 读出来的
        //    真实映射，最权威，也不依赖任何 libc 的栈语义。
        const za_stack_region_t *sr = za_stack_find((long)syscall(SYS_gettid));
        if (sr && sr->hi > sr->lo && addr >= sr->lo && addr < sr->hi)
        {
            base = sr->lo;
            size = sr->hi - sr->lo;
            state = 0x0B;   // Stack
            perm = 3;
        }
        else
        {
            // ② 兜底：pthread 查询。⚠ pthread_attr_getstack 给的是**栈底**，
            //    栈顶 = 栈底 + 栈大小（栈向下生长）。
            void *lo = NULL;
            size_t ssz = 0;
            pthread_attr_t attr;
            if (pthread_getattr_np(pthread_self(), &attr) == 0)
            {
                pthread_attr_getstack(&attr, &lo, &ssz);
                pthread_attr_destroy(&attr);
            }
            unsigned long long t = (unsigned long long)(uintptr_t)lo + ssz;   // 栈顶
            if (ssz && addr < t && addr >= t - ssz)
            {
                base = t - ssz;
                size = ssz;
                state = 0x0B;   // Stack
                perm = 3;
            }
            else
            {
            // ② 如实报告该地址所在的真实映射（别再谎报成「一页 Code」）
            const za_map_t *mp2 = za_mem_find_mapping(addr);
            if (mp2)
            {
                base = mp2->lo;
                size = mp2->hi - mp2->lo;
                perm = mp2->perm;
                state = mp2->is_stack ? 0x0B : (mp2->perm == 5 ? 3 : 0x0B);
                if (perm == 0) { state = 0; }
            }
            else
            {
                base = addr & ~0xFFFull;
                size = 0x1000;
                state = 3;     // Code
                perm = 5;
            }
            }   // ② 兜底（pthread 查询）结束
        }
    }
    pthread_mutex_unlock(&g_lock);

    if (mi)
    {
        mi[0] = base;
        mi[1] = size;
        ((unsigned int *)mi)[4] = (unsigned int)state;
        ((unsigned int *)mi)[5] = 0;          // attr
        ((unsigned int *)mi)[6] = (unsigned int)perm;
        ((unsigned int *)mi)[7] = 0;
        ((unsigned int *)mi)[8] = 0;
    }
    // 页信息：客机的包装函数会把这个值写进 *PageInfo。
    return 0;
}
