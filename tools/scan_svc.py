#!/usr/bin/env python3
"""扫描客机 text 段里的 SVC（Horizon 服务调用）指令。

为什么重要：Switch 的 `svc #n` 在 Linux/arm64 上会被当成系统调用执行 ——
x8 若是 exit/exit_group 之类的号，进程会**静默退出**（没有 tombstone）。
移植的做法跟 D2R 一样：把 svc 改成跳到宿主门。

AArch64 编码：SVC #imm16 = 0xD4000001 | (imm16 << 5)
"""
import collections
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT = os.path.join(ROOT, "work", "nso", "text.bin")

d = open(TEXT, "rb").read()
print("text %d 字节" % len(d))

hits = []
for off in range(0, len(d) - 3, 4):
    w = struct.unpack_from("<I", d, off)[0]
    if (w & 0xFFE0001F) == 0xD4000001:
        hits.append((off, (w >> 5) & 0xFFFF))

print("SVC 指令 %d 条" % len(hits))
c = collections.Counter(imm for _, imm in hits)
print("立即数分布（前 20）:")
for imm, n in c.most_common(20):
    print("   svc #%d (0x%x)  ×%d" % (imm, imm, n))
print("\n前 20 条位置:")
for off, imm in hits[:20]:
    print("   text+%#x  svc #%d" % (off, imm))

# Linux 危险 syscall 号对照（x8 值）：这些号一旦被 svc 用上就会静默退进程
danger = {93: "exit", 94: "exit_group", 60: "exit", 57: "fork", 221: "execve",
          134: "rt_sigaction", 135: "rt_sigprocmask", 129: "kill", 160: "uname",
          222: "mmap", 226: "mprotect", 215: "munmap"}
print("\n注：svc 的 x8 由客机自己设置，扫描无法直接看到；但下面的立即数是 Horizon 服务号。")
