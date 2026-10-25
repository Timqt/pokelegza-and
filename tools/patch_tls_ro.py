#!/usr/bin/env python3
"""生成 SDK 里 `mrs Xt,TPIDRRO_EL0` 的改写补丁。

背景（2026-10-25 实测）：
  客机 SDK 有 123 处直接读「只读 TLS 寄存器」TPIDRRO_EL0（main NSO 里 0 处）。
  安卓/bionic **从不设置 TPIDRRO_EL0** ⇒ 它一直是 0 ⇒
  `mrs x8,TPIDRRO_EL0 ; ldr x8,[x8,#0x1f8]` 读到地址 0x1f8 ⇒ pc=0 崩溃。

做法（和已有的 TPIDR_EL0 改写同一思路）：
  `mrs Xt, TPIDRRO_EL0`  →  `adrp Xt, <我们自备的只读 TLS 页>`
  —— **1 条换 1 条**，后面的指令与偏移全部保持不变，
  于是「相对偏移」语义完全一致；那一页的内容由我们填。

只读 TLS 页放在 SDK 映像末尾的扩展区（RW），偏移见输出。
"""
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SDK_TEXT = os.path.join(ROOT, "work", "nso_32848007", "text.bin")
OUT_H = os.path.join(ROOT, "app", "native", "za_tlsro_patch.h")

# SDK 映像末尾扩展区（必须 > 映像大小 0xC5E000，且在门区之外）
RO_TLS_OFF = 0xF00000        # 只读 TLS 页（RW，客机会往里写）
RO_TLS_SIZE = 0x1000
RO_TLS2_OFF = 0xF01000        # 只读 TLS 里那些指针指向的「小结构体」页
RO_TLS2_SIZE = 0x1000

MRS_TPIDRRO = 0xD53BD060     # mrs Xt, TPIDRRO_EL0


def adrp_x(rd, page_delta):
    """编码 adrp Xd, <page>：imm21 = (目标页 - 本指令所在页) >> 12。

    ADRP 的立即数布局：immlo 在 bit30:29，immhi 在 bit23:5，21 位整体算出来后
    左移 12 位当页偏移 —— 不能简单地把 imm 塞进 bit23:5（会放大 4 倍）。
    """
    imm = page_delta >> 12
    if imm < 0:
        imm += (1 << 21)
    if not (0 <= imm <= 0x1FFFFF):
        raise ValueError("adrp 立即数越界: %d" % imm)
    immlo = imm & 3
    immhi = (imm >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | rd


def main():
    d = open(SDK_TEXT, "rb").read()
    n = len(d) // 4
    words = list(struct.unpack_from("<%dI" % n, d, 0))

    patches = []
    usage = {}
    for i in range(n):
        w = words[i]
        if (w & 0xFFFFFFE0) != MRS_TPIDRRO:
            continue
        rt = w & 31
        off = i * 4
        page_delta = RO_TLS_OFF - (off & ~0xFFF)
        patches.append((off, adrp_x(rt, page_delta)))
        # 统计后续对这个寄存器的用法（粗略：看后 4 条指令里有没有以它为基址的访存）
        for j in range(i + 1, min(i + 5, n)):
            w2 = words[j]
            # LDR/STR (unsigned imm) 且基址是该寄存器
            if (w2 & 0x3B200000) == 0x39000000 and ((w2 >> 5) & 31) == rt:
                size = (w2 >> 30) & 3
                imm = ((w2 >> 10) & 0xFFF) << size
                key = (imm, size)
                usage[key] = usage.get(key, 0) + 1

    print("TPIDRRO_EL0 改写点：%d 处" % len(patches))
    print("以该寄存器为基址的访存（偏移, 宽度）分布：")
    for k in sorted(usage):
        kind = {0: "字节", 1: "半字", 2: "字", 3: "双字"}[k[1]]
        print("    +%#x (%s) : %d 处" % (k[0], kind, usage[k]))

    with open(OUT_H, "w", encoding="utf-8", newline="\n") as o:
        o.write("// 自动生成：tools/patch_tls_ro.py —— 别手改\n")
        o.write("// 把 SDK 里 `mrs Xt,TPIDRRO_EL0` 换成 `adrp Xt,<我们自备的只读 TLS 页>`。\n")
        o.write("// 安卓/bionic 从不设置 TPIDRRO_EL0（一直是 0），客机读它就会取到空指针。\n")
        o.write("// 1 条换 1 条，后面的指令与相对偏移全部不变 ⇒ 语义等价。\n")
        o.write("#ifndef ZA_TLSRO_PATCH_H\n#define ZA_TLSRO_PATCH_H\n\n")
        o.write("#define ZA_TLSRO_OFF      0x%xul   /* 只读 TLS 页（基址 + 该偏移） */\n" % RO_TLS_OFF)
        o.write("#define ZA_TLSRO_SIZE    0x%xul\n" % RO_TLS_SIZE)
        o.write("#define ZA_TLSRO2_OFF    0x%xul   /* 那些指针指向的小结构体页 */\n" % RO_TLS2_OFF)
        o.write("#define ZA_TLSRO2_SIZE  0x%xul\n" % RO_TLS2_SIZE)
        o.write("#define ZA_TLSRO_PATCH_COUNT %d\n\n" % len(patches))
        o.write("typedef struct { unsigned int off; unsigned int w; } za_tlsro_patch_t;\n\n")
        o.write("static const za_tlsro_patch_t za_tlsro_patches[] = {\n")
        for off, w in patches:
            o.write("    {0x%xu, 0x%08xu},\n" % (off, w))
        o.write("};\n\n#endif\n")
    print("补丁表 -> %s" % OUT_H)


if __name__ == "__main__":
    main()
