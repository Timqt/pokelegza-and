# -*- coding: utf-8 -*-
"""把 za_reinstall_sampler_handler 挪到 za_pc_sampler / za_pc_timer_ready 定义之后"""
import sys

ROOT = r"D:\feiniukexinhome\Code\pokeLegza-and\app\native"
def rd(p):
    with open(p, "rb") as f: return f.read()
def wr(p, b):
    with open(p, "wb") as f: f.write(b)
def enc(s): return s.encode("utf-8")

gp = ROOT + r"\za_guest.c"
g = rd(gp)

start = g.find(b"// SDK \xe5\x88\x9d\xe5\xa7\x8b\xe6\x97\xb6\xe4\xbc\x9a\xe8\xa6\x86\xe7\x9b\x96")
if start == -1:
    print("!! 找不到 za_reinstall_sampler_handler 块"); sys.exit(1)
end_marker = b"// \xe6\x8e\xa5\xe7\xae\xa1 32..62\xef\xbc\x8863 \xe6\x98\xaf PC \xe9\x87\x87\xe6\xa0\xb7\xe5\x99\xa8\xe7\x9a\x84\xef\xbc\x8c\xe4\xb8\x8d\xe8\x83\xbd\xe6\x8a\xa2\xef\xbc\x89"
end = g.find(end_marker, start)
if end == -1:
    print("!! 找不到块尾"); sys.exit(1)
block = g[start:end]
g = g[:start] + g[end:]
print("[guest] 摘下旧位置（%d 字节）" % len(block))

# 重新插到 za_guest_start_sampler 之前
anchor = enc("// 启动 PC 采样器（幂等）。")
i = g.find(anchor)
if i == -1:
    print("!! 找不到 za_guest_start_sampler 注释"); sys.exit(1)
g = g[:i] + block + g[i:]
print("[guest] 插到 za_guest_start_sampler 之前")

wr(gp, g)
print("done")
