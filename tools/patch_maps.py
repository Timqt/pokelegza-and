# -*- coding: utf-8 -*-
"""① 去掉非导出的 bionic 私有 API（导致 dlopen 失败）
   ② QueryMemory 对「未知地址」改成**如实报告它所在的真实映射**（读 /proc/self/maps），
      不再谎报成「Code 4KB」——照 d2r-and hle_svc.c case 0x06 的口径：
      落在宿主线程栈里就报整段栈（state 0x0B），否则报真实区间的 base/size。
"""
import re, sys

ROOT = r"D:\feiniukexinhome\Code\pokeLegza-and\app\native"
def rd(p):
    with open(p, "rb") as f: return f.read()
def wr(p, b):
    with open(p, "wb") as f: f.write(b)
def enc(s): return s.encode("utf-8")

# ---------------------------------------------------------------- ① 去掉私有 API 声明
for name in ("za_mem.c", "za_guest.c"):
    p = ROOT + "\\" + name
    b = rd(p)
    b2 = re.sub(rb"\n// bionic [^\n]*\n//[^\n]*\nextern void \*pthread_get_stackaddr_np[^\n]*\n"
                rb"extern size_t pthread_get_stacksize_np[^\n]*\n", b"\n", b)
    if b2 != b:
        wr(p, b2)
        print("[%s] 去掉 bionic 私有 API 声明" % name)

# ---------------------------------------------------------------- ② za_mem.c 真实映射查询
mp = ROOT + r"\za_mem.c"
m = rd(mp)

HELPER = enc("""
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
        while (*p2 && *p2 != ' ' && *p2 != '\\n') p2++;
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
        const char *eol = strchr(line, '\\n');
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
""")

if b"za_mem_find_mapping" not in m:
    anchor = enc("// GetInfo 的取值。id 见文件头的枚举。")
    assert anchor in m, "za_mem.c 锚点没找到"
    m = m.replace(anchor, HELPER + anchor, 1)
    print("[mem] 加 /proc/self/maps 映射查询")

old = enc("""        unsigned long long t = (unsigned long long)(uintptr_t)pthread_get_stackaddr_np(pthread_self());
        unsigned long long ssz = (unsigned long long)pthread_get_stacksize_np(pthread_self());
        if (ssz && addr < t && addr >= t - ssz)
        {
            base = t - ssz;
            size = ssz;
            state = 0x0B;   // Stack
            perm = 3;
        }
        else
        {
            base = addr & ~0xFFFull;
            size = 0x1000;
            state = 3;     // Code
            perm = 5;
        }
""")
new = enc("""        // ① 宿主线程栈 ⇒ 报整段栈（state 0x0B）
        void *top = NULL;
        size_t ssz = 0;
        pthread_attr_t attr;
        if (pthread_getattr_np(pthread_self(), &attr) == 0)
        {
            pthread_attr_getstack(&attr, &top, &ssz);
            pthread_attr_destroy(&attr);
        }
        unsigned long long t = (unsigned long long)(uintptr_t)top;
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
        }
""")
if b"pthread_get_stackaddr_np" in m:
    assert old in m, "za_mem.c 栈判定块没找到"
    m = m.replace(old, new, 1)
    wr(mp, m)
    print("[mem] 栈判定改用 pthread_getattr_np + 真实映射")

# 需要 open/read/strstr/sscanf
if b"#include <fcntl.h>" not in m:
    m = rd(mp)
    m = m.replace(b"#include", b"#include <fcntl.h>\n#include <stdio.h>\n#include <string.h>\n#include", 1)
    wr(mp, m)
    print("[mem] 加 fcntl/stdio/string 头")

# ---------------------------------------------------------------- za_guest.c：去掉私有 API
gp = ROOT + r"\za_guest.c"
g = rd(gp)
old3 = enc("""            q = za_put_str(q, "ZaGuest: 真实栈边界 top=");
            q = za_put_hex(q, (unsigned long long)(uintptr_t)pthread_get_stackaddr_np(pthread_self()));
            q = za_put_str(q, " size=");
            q = za_put_hex(q, (unsigned long long)pthread_get_stacksize_np(pthread_self()));
""")
new3 = enc("""            void *tp = NULL; size_t tsz = 0; pthread_attr_t at2;
            if (pthread_getattr_np(pthread_self(), &at2) == 0)
            {
                pthread_attr_getstack(&at2, &tp, &tsz);
                pthread_attr_destroy(&at2);
            }
            q = za_put_str(q, "ZaGuest: 真实栈边界 top=");
            q = za_put_hex(q, (unsigned long long)(uintptr_t)tp);
            q = za_put_str(q, " size=");
            q = za_put_hex(q, (unsigned long long)tsz);
""")
if b"pthread_get_stackaddr_np" in g:
    assert old3 in g, "za_guest.c 真实栈边界块没找到"
    g = g.replace(old3, new3, 1)
    wr(gp, g)
    print("[guest] 真实栈边界改用 pthread_getattr_np")

print("done")
