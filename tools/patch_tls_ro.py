#!/usr/bin/env python3
"""生成 SDK 里 123 处 `mrs Xt,TPIDRRO_EL0` 的改写补丁（**每线程**只读 TLS）。

背景（2026-10-26 实测）：
  * 安卓/bionic 从不设置 TPIDRRO_EL0（一直是 0），而 SDK 拿它当 Horizon 的
    线程只读区（ThreadLocalRegion）：
        +0x100/+0x102/+0x104  本线程 busy 标记（InternalCriticalSection 忙等）
        +0x1e0/+0x20/+0x70…   指向本线程结构的指针
        +0x1f0                本线程 TPIDR_EL0（SDK 线程入口会 msr tpidr_el0,[ro+0x1f0]）
        +0x1f8                本线程对象（SDK 线程入口写 ThreadType*）
    这一页还是 **CMIF IPC 的应答缓冲区**（内核应答写回 [ro+槽位]）。
  * 以前用**一张全局页** + `adrp Xt,<全局页>` 代替 ⇒ 多线程互相踩
    （彼此看到对方的 busy 标记 ⇒ 活锁；IPC 缓冲互相覆盖）。
  * TPIDRRO_EL0 在 EL0 **不可写**（实测 `msr` 直接 SIGILL），所以只能改代码。

做法（每站点一个桩，因为原 mrs 后面紧跟的是真代码，不能占用 2 条槽位）：
    mrs Xt, TPIDRRO_EL0   →   b <站点桩>
  桩（28 条指令）：
    sub sp,sp,#0xa0 ; stp x0..x17 ; str x30
    adrp/ldr x16,<全局 hook 槽> ; blr x16        ← 宿主 za_os_tls_ro_area()
    str x0,[sp,#0x98]
    ldp x0..x17 ; ldr x30
    ldr Xt,[sp,#0x98]                            ← 本线程 RO 页写回原寄存器
    add sp,sp,#0xa0 ; b site+4

输出：app/native/za_tlsro_patch.h（补丁表 + 桩机器码）
"""
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SDK_TEXT = os.path.join(ROOT, "work", "nso_32848007", "text.bin")
OUT_H = os.path.join(ROOT, "app", "native", "za_tlsro_patch.h")

STUB_BASE = 0xC92000      # 每站点桩区（SDK 映像内偏移，扩展区）
STUB_STRIDE = 0x70        # 28 条指令 = 112 字节
HOOK_SLOT = 0xC96000      # 全局 hook 槽（运行时填 &za_os_tls_ro_area）
STUB_INSNS = 28

MRS_TPIDRRO = 0xD53BD060


def enc_b(frm, to):
    off = to - frm
    assert -(1 << 27) <= off < (1 << 27) and off % 4 == 0, "b 越界 %#x -> %#x" % (frm, to)
    return 0x14000000 | ((off >> 2) & 0x3FFFFFF)


def enc_adrp(rd, pc, target):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    assert -(1 << 20) <= imm < (1 << 20), "adrp 越界"
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def enc_ldr(rt, rn, imm12):
    return 0xF9400000 | (imm12 << 10) | (rn << 5) | rt


def build_stub(site, stub_off, rt):
    s = [0xD10283FF]                                    # sub sp,sp,#0xa0
    s += [0xA90007E0, 0xA9010FE2, 0xA90217E4, 0xA9031FE6,
          0xA90427E8, 0xA9052FEA, 0xA90637EC, 0xA9073FEE, 0xA90847F0]   # stp x0..x17
    s.append(0xF9004BFE)                                # str x30,[sp,#0x90]
    s.append(enc_adrp(16, stub_off + len(s) * 4, HOOK_SLOT))
    s.append(enc_ldr(16, 16, (HOOK_SLOT & 0xFFF) // 8))
    s.append(0xD63F0200)                                # blr x16
    s.append(0xF9004FE0)                                # str x0,[sp,#0x98]
    s += [0xA94007E0, 0xA9410FE2, 0xA94217E4, 0xA9431FE6,
          0xA94427E8, 0xA9452FEA, 0xA94637EC, 0xA9473FEE, 0xA94847F0]   # ldp x0..x17
    s.append(0xF9404BFE)                                # ldr x30,[sp,#0x90]
    s.append(enc_ldr(rt, 31, 0x98 // 8))                # ldr Xt,[sp,#0x98]
    s.append(0x910283FF)                                # add sp,sp,#0xa0
    s.append(enc_b(stub_off + len(s) * 4, site + 4))    # b site+4
    return s


def main():
    d = open(SDK_TEXT, "rb").read()
    n = len(d) // 4
    words = list(struct.unpack_from("<%dI" % n, d, 0))
    sites = [(i * 4, words[i] & 31) for i in range(n)
             if (words[i] & 0xFFFFFFE0) == MRS_TPIDRRO]
    print("TPIDRRO_EL0 站点：%d 处" % len(sites))

    patches = []
    for k, (off, rt) in enumerate(sites):
        stub = STUB_BASE + k * STUB_STRIDE
        seq = build_stub(off, stub, rt)
        assert len(seq) == STUB_INSNS
        patches.append((off, stub, seq))

    with open(OUT_H, "w", encoding="utf-8", newline="\n") as o:
        o.write("// 自动生成：tools/patch_tls_ro.py —— 别手改\n")
        o.write("// SDK 的 123 处 `mrs Xt,TPIDRRO_EL0` → `b <每站点桩>`；\n")
        o.write("// 桩调用宿主取**本线程**的只读 TLS 页（TPIDRRO 语义 + CMIF 应答缓冲）。\n")
        o.write("#ifndef ZA_TLSRO_PATCH_H\n#define ZA_TLSRO_PATCH_H\n\n")
        o.write("#define ZA_TLSRO_STUB_BASE  0x%xul\n" % STUB_BASE)
        o.write("#define ZA_TLSRO_HOOK_SLOT  0x%xul\n" % HOOK_SLOT)
        o.write("/* 旧全局页常量：现在只用于诊断（页本身已被每线程页取代） */\n")
        o.write("#define ZA_TLSRO_OFF      0xf00000ul\n")
        o.write("#define ZA_TLSRO_SIZE     0x1000ul\n")
        o.write("#define ZA_TLSRO2_OFF     0xf01000ul\n")
        o.write("#define ZA_TLSRO2_SIZE    0x1000ul\n")
        o.write("#define ZA_TLSRO_PATCH_COUNT %d\n\n" % len(patches))
        o.write("typedef struct { unsigned int off; unsigned int stub; const unsigned int *seq; }"
                " za_tlsro_patch_t;\n\n")
        o.write("static const unsigned int za_tlsro_stubs[%d][%d] = {\n"
                % (len(patches), STUB_INSNS))
        for off, stub, seq in patches:
            o.write("  { /* site %#x */ %s },\n"
                    % (off, ", ".join("0x%08xu" % w for w in seq)))
        o.write("};\n\n")
        o.write("static const za_tlsro_patch_t za_tlsro_patches[] = {\n")
        for i, (off, stub, seq) in enumerate(patches):
            o.write("  {0x%xu, 0x%xu, za_tlsro_stubs[%d]},\n" % (off, stub, i))
        o.write("};\n\n#endif\n")
    print("补丁表 -> %s（%d 个站点桩）" % (OUT_H, len(patches)))


if __name__ == "__main__":
    main()
