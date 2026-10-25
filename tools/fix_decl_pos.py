# -*- coding: utf-8 -*-
"""把 bionic API 声明移到「最后一个 #include 之后」（pthread_t 要先可见）"""
import re

ROOT = r"D:\feiniukexinhome\Code\pokeLegza-and\app\native"
DECL = (b"\n// bionic \xe4\xb8\x93\xe6\x9c\x89 API\xef\xbc\x88NDK \xe7\x9a\x84 <pthread.h> \xe5\x8f\xaa\xe5\x9c\xa8 "
        b"__USE_BIONIC \xe4\xb8\x8b\xe6\x8a\xab\xe9\x9c\xb2\xe9\x9c\xb2\xef\xbc\x89\xef\xbc\x9a\n"
        b"//   \xe7\xba\xbf\xe7\xa8\x8b\xe7\x9a\x84\xe6\xa0\x88\xe9\xa1\xb6\xe5\x9c\xb0\xe5\x9d\x80 / \xe6\xa0\x88\xe5\xa4\xa7\xe5\xb0\x8f\xe3\x80\x82"
        b"d2r-and \xe7\x9a\x84 hle_svc.c \xe7\x94\xa8\xe5\xae\x83\xe5\x88\xa4\xe5\xae\x9a\xe3\x80\x8c"
        b"\xe5\x9c\xb0\xe5\x9d\x80\xe6\x98\xaf\xe5\x90\xa6\xe8\x90\xbd\xe5\x9c\xa8\xe5\xae\xbf\xe4\xb8\xbb\xe7\xba\xbf\xe7\xa8\x8b\xe6\xa0\x88\xe9\x87\x8c\xe3\x80\x82\n"
        b"extern void *pthread_get_stackaddr_np(pthread_t __pthread);\n"
        b"extern size_t pthread_get_stacksize_np(pthread_t __pthread);\n")

for name in ("za_mem.c", "za_guest.c"):
    p = ROOT + "\\" + name
    b = open(p, "rb").read()
    # 去掉已有的声明块
    b = re.sub(rb"\n// bionic [^\n]*\n//[^\n]*\nextern void \*pthread_get_stackaddr_np[^\n]*\n"
               rb"extern size_t pthread_get_stacksize_np[^\n]*\n", b"\n", b)
    # 找到最后一个 #include 行
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
    assert last != -1, name
    b = b[:last] + DECL + b[last:]
    open(p, "wb").write(b)
    print("[%s] 声明已移到最后一个 #include 之后" % name)
