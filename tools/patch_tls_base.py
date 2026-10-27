#!/usr/bin/env python3
"""生成「客机不许动 bionic 的 TLS 指针」+「SDK 自己的 TLS 上下文」两组补丁。

背景（2026-10-25 实测）：
1) 客机（SDK NSO）里有 `msr TPIDR_EL0, xN`（**写** TPIDR_EL0）。
   TPIDR_EL0 在安卓上就是 **bionic 的 TLS 指针** ⇒ 客机一写，bionic 的 TLS 就废了
   ⇒ 后续任何 libc 调用（malloc/pthread/logcat…）必崩，而且崩在 libc 内部，
   症状是「进程被 SIGSEGV 静默杀掉」。
   ⇒ 把这些写指令一律 NOP 掉（我们的客机 TLS 用影子描述符，不依赖这个寄存器）。

2) SDK NSO 里有 2 处 `mrs xN, TPIDR_EL0`（真·TLS 基址访问，musl 的
   `__tls_get_addr` 快速路径）。main 里的 9496 处「裸读」其实取的是
   **线程 ID**（`ubfx wN,wM,#13,#7`），不是 TLS 基址，不用动。
   ⇒ SDK 的这 2 处改成读「SDK 自己的一页 TLS 上下文」。

SDK 的 TLS 上下文页布局（我们自建，偏移 0xF10000）：
   +0x08  动态 TLS 表指针（表项非 0 ⇒ 走快速路径，不进 musl 的慢路径）
   +0x13  本模块的 TLS 描述符（照 Switch 的线程上下文布局）
   +0x18  动态 TLS 表本体（每项 0x200 ⇒ 落在上下文页内，不会跑飞）
"""
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SDK_TEXT = os.path.join(ROOT, "work", "nso_32848007", "text.bin")
MAIN_TEXT = os.path.join(ROOT, "work", "nso", "text.bin")
OUT_H = os.path.join(ROOT, "app", "native", "za_tlsbase_patch.h")

# SDK 映像末尾扩展区
SDK_TLSCTX_OFF = 0xF10000        # SDK 的 TLS 上下文页（16KB 对齐）
SDK_TLSCTX_SIZE = 0x1000
SDK_TLSTAB_OFF = 0xF11000         # 动态 TLS 表
SDK_TLSTAB_SIZE = 0x1000

MRS_TPIDR_EL0 = 0xD53BD040       # mrs Xt, TPIDR_EL0
MSR_TPIDR_EL0 = 0xD51BD040       # msr TPIDR_EL0, Xt
# ⚠ 掩码必须只清掉 Rt（bit4..0）和 op2（bit7..5），
#   o0 是 **2 位**（bit21..20），op1 是 4 位 —— 用 0xFFE0001F 会把 op1/op2 也比成 0 ⇒ 匹配不到。
MASK = 0xFFFFFFE0
NOP = 0xD503201F


def adrp_x(rd, page_delta):
    """编码 adrp Xd, <page>：imm21 = (目标页 - 本指令所在页) >> 12。

    ADRP 的立即数布局：immlo 在 bit30:29，immhi 在 bit23:5，
    21 位整体算出后左移 12 位当页偏移（不是简单塞进 bit23:5，会放大 4 倍）。
    """
    imm = page_delta >> 12
    if imm < 0:
        imm += (1 << 21)
    if not (0 <= imm <= 0x1FFFFF):
        raise ValueError("adrp 立即数越界: %d" % imm)
    immlo = imm & 3
    immhi = (imm >> 2) & 0x7FFFF
    return 0x90000000 | (immlo << 29) | (immhi << 5) | rd


def scan(path, text_end):
    d = open(path, "rb").read()
    n = min(len(d) // 4, text_end // 4)
    W = struct.unpack_from("<%dI" % n, d, 0)
    reads, writes = [], []
    for i in range(n):
        x = W[i]
        if (x & MASK) == MRS_TPIDR_EL0:
            reads.append((i * 4, x & 31))
        elif (x & MASK) == MSR_TPIDR_EL0:
            writes.append((i * 4, x & 31))
    return reads, writes


def main():
    sdk_reads, sdk_writes = scan(SDK_TEXT, 0x64E230)
    main_reads, main_writes = scan(MAIN_TEXT, 0x2FC7250)
    print("SDK: mrs TPIDR_EL0 %d 处，msr TPIDR_EL0 %d 处" % (len(sdk_reads), len(sdk_writes)))
    print("main: mrs TPIDR_EL0 %d 处，msr TPIDR_EL0 %d 处" % (len(main_reads), len(main_writes)))

    # SDK 的 2 处真 TLS 基址读 → 读我们自建的 TLS 上下文页
    sdk_reads_patch = []
    sub_fix = []          # 快速路径末尾那句 `sub x0, x0, x3` —— NOP 掉
    SUB_X0_X0_X3 = 0xCB030000     # sub x0, x0, x3（SUBS 移位寄存器：Rd=0,Rn=0,Rm=3,imm6=0）
    for off, rt in sdk_reads:
        page_delta = SDK_TLSCTX_OFF - (off & ~0xFFF)
        sdk_reads_patch.append((off, adrp_x(rt, page_delta)))
    # 单独扫一遍：找所有 `sub x0, x0, x3`（快速路径末尾那句）
    d = open(SDK_TEXT, "rb").read()
    n = len(d) // 4
    W = struct.unpack_from("<%dI" % n, d, 0)
    for i in range(n):
        if W[i] == SUB_X0_X0_X3:
            sub_fix.append((i * 4, NOP))
    print("  快速路径的 `sub x0,x0,x3` %d 处 → NOP" % len(sub_fix))
    # 所有写 TPIDR_EL0 的地方一律 NOP（SDK 与 main 分开成两张表，方便各自应用）
    sdk_write_patch = sorted((off, NOP) for off, _ in sdk_writes)
    main_write_patch = sorted((off, NOP) for off, _ in main_writes)
    # ★ 2026-10-27：nn::os::SetThreadLocalStoragePointer（sdk+0x99218）除了写寄存器，
    #   还把参数存进 [TPIDRRO+0x1f0]。那个槽我们当成「本线程 TPIDR_EL0」，由宿主
    #   写成自备零区（TP-0x18 是 fs 模块的每线程链表头）。客机把它改回 bionic 的 TP
    #   后，链表头就落进 bionic TCB ⇒ 插入时写坏 TLS/只读页 ⇒ 崩在 libc
    #   （真机实测 addr=0x70abea8fe0）。⇒ 这条 store（str x22,[x8,#0x1f0]）也 NOP。
    sdk_write_patch = sorted(sdk_write_patch + [(0x99220, NOP)])

    with open(OUT_H, "w", encoding="utf-8", newline="\n") as o:
        o.write("// 自动生成：tools/patch_tls_base.py —— 别手改\n")
        o.write("// 1) 客机写 TPIDR_EL0 ⇒ 会把 bionic 的 TLS 指针冲掉 ⇒ 后续 libc 调用必崩。\n")
        o.write("//    全部 NOP 掉（客机 TLS 走影子描述符，不依赖这个寄存器）。\n")
        o.write("// 2) SDK 的 2 处真·TLS 基址读（musl __tls_get_addr 快速路径）\n")
        o.write("//    改读「SDK 自己的一页 TLS 上下文」。\n")
        o.write("#ifndef ZA_TLSBASE_PATCH_H\n#define ZA_TLSBASE_PATCH_H\n\n")
        o.write("#define ZA_SDK_TLSCTX_OFF   0x%xul   /* SDK 的 TLS 上下文页 */\n" % SDK_TLSCTX_OFF)
        o.write("#define ZA_SDK_TLSCTX_SIZE 0x%xul\n" % SDK_TLSCTX_SIZE)
        o.write("#define ZA_SDK_TLSTAB_OFF   0x%xul   /* 动态 TLS 表 */\n" % SDK_TLSTAB_OFF)
        o.write("#define ZA_SDK_TLSTAB_SIZE 0x%xul\n" % SDK_TLSTAB_SIZE)
        o.write("#define ZA_TLSBASE_READ_COUNT  %d\n" % len(sdk_reads_patch))
        o.write("#define ZA_TLSBASE_SDK_WRITE_COUNT  %d\n" % len(sdk_write_patch))
        o.write("#define ZA_TLSBASE_MAIN_WRITE_COUNT %d\n\n" % len(main_write_patch))
        o.write("typedef struct { unsigned int off; unsigned int w; } za_tlsbase_patch_t;\n\n")
        o.write("static const za_tlsbase_patch_t za_tlsbase_reads[] = {\n")
        for off, w in sdk_reads_patch:
            o.write("    {0x%xu, 0x%08xu},\n" % (off, w))
        o.write("};\n\n")
        o.write("static const za_tlsbase_patch_t za_tlsbase_sdk_writes[] = {\n")
        for off, w in sdk_write_patch:
            o.write("    {0x%xu, 0x%08xu},\n" % (off, w))
        o.write("};\n\n")
        o.write("static const za_tlsbase_patch_t za_tlsbase_main_writes[] = {\n")
        for off, w in main_write_patch:
            o.write("    {0x%xu, 0x%08xu},\n" % (off, w))
        o.write("};\n\n")
        o.write("// musl __tls_get_addr 快速路径末尾的 `sub x0,x0,x3`：\n")
        o.write("// 它把「变量绝对地址」变成「相对 TLS 基址的偏移」，但调用方要的是地址\n")
        o.write("// （SDK 里已经没有别的 mrs TPIDR_EL0 了）⇒ 客机拿野偏移当地址用 ⇒ 跳飞。\n")
        o.write("static const za_tlsbase_patch_t za_tlsbase_subfix[] = {\n")
        for off, w in sub_fix:
            o.write("    {0x%xu, 0x%08xu},\n" % (off, w))
        o.write("};\n\n#endif\n")
    print("补丁：SDK TLS 基址读 %d 处，TPIDR_EL0 写 SDK %d 处 / main %d 处 → %s"
          % (len(sdk_reads_patch), len(sdk_write_patch), len(main_write_patch), OUT_H))


if __name__ == "__main__":
    main()
