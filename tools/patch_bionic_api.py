# -*- coding: utf-8 -*-
"""bionic 专有 API 声明：pthread_get_stackaddr_np / pthread_get_stacksize_np
   （NDK 的 pthread.h 只在 __USE_BIONIC 下暴露它们，这里显式声明）"""
import sys

ROOT = r"D:\feiniukexinhome\Code\pokeLegza-and\app\native"
def rd(p):
    with open(p, "rb") as f: return f.read()
def wr(p, b):
    with open(p, "wb") as f: f.write(b)
def enc(s): return s.encode("utf-8")

DECL = enc("""
// bionic 专有 API（NDK 的 <pthread.h> 只在 __USE_BIONIC 下暴露）：
//   线程的栈顶地址 / 栈大小。d2r-and 的 hle_svc.c 用它判定「地址是否落在宿主线程栈里」。
extern void *pthread_get_stackaddr_np(pthread_t __pthread);
extern size_t pthread_get_stacksize_np(pthread_t __pthread);
""")

for name in ("za_mem.c", "za_guest.c"):
    p = ROOT + "\\" + name
    b = rd(p)
    if b"pthread_get_stackaddr_np(pthread_t" in b:
        print("[%s] 已声明" % name)
        continue
    # 插在**最后一个** #include 之后（pthread_t 要先有声明）
    last = -1
    i = 0
    while True:
        i = b.find(b"#include", i)
        if i == -1:
            break
        j = b.find(b"\n", i)
        if j == -1:
            break
        last = j + 1
        i = j + 1
    if last == -1:
        print("[%s] 找不到 #include" % name)
        continue
    b = b[:last] + DECL + b[last:]
    wr(p, b)
    print("[%s] 加上 bionic API 声明" % name)
