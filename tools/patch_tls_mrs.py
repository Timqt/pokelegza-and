#!/usr/bin/env python3
"""把 main NSO 里每一条 `mrs Xt, TPIDR_EL0` 换成「回调宿主取线程基址」。

为什么要这样改（而不是按后续形态分类）
------------------------------------
客机用 TPIDR_EL0 取「Horizon 线程上下文」有两种以上写法：
    mrs x8,TPIDR_EL0 ; and  x23,x8,#~0x1FFF ; ldr x9,[x23,#0x98] ...
    mrs x8,TPIDR_EL0 ; ubfm x8,x8,#51,#14   ; ldr x9,[x8,#0x13] ...
    mrs x8,TPIDR_EL0 ; add  x20,x8,x0       ; ldr x0,[x20] ...
实测 main 里共 10,193 处，按形态改写要覆盖 5 种以上、且容易漏（本轮已踩过：
只认 ubfm/and 两种时覆盖率仅 47%）。

⇒ 换个层次：**只换 `mrs` 这一条指令**，让它给出「我们控制的指针」。
   后续无论 and/ubfm/add/lsr/mov 怎么算，结果都自然正确，覆盖率 100%。

替换序列（返回**进程级**的客机 TLS 变量区 V = base + 0x5F90000）：
    stur x16, [sp, #-8]
    adrp x16, <V 所在页>
    mov  xN, x16                 ; ★ 结果
    ldur x16, [sp, #-8]

为什么是「进程级常数」而不是每线程区域：
  * 4756 个 helper 已经被 patch_tls_helpers.py 改写成 `adrp Xt,<描述符区 P>`，
    它们算出来的永远是 P + [P+0x98]*8 = V（**同一个块**）。
    两种机制必须给出同一个地址，否则同一个 __thread 变量经不同站点读到不同内存。
  * 曾经试过「每线程 area = tp16 + [tp16+0x98]*8」：那个槽在 bionic 的
    pthread 结构里，宿主代码/其它线程会改它。实测静态构造器跑到一半时它从
    我们写入的 0xfffffffffb8b9600 变成了 0x1FFFFF80FFFFFFD8，
    ⇒ x8 算成 0xfffffc756969dec0 ⇒ 崩在 main+0x165272c。
  * 也试过桩里 blr 宿主 C：C 按 AAPCS 改 x0–x17，而 mrs 只该写目标寄存器。
    实测 main+0x1a44fc 是 `movz/movk x0,#0x1000 ; mrs x8 ; add x8,x8,x0`，
    x0 被改成 area ⇒ x8 = area*2 ⇒ 崩在 0xda8ef48000。
  ⇒ 常数最稳：不读任何共享状态、不调用任何函数，只借 x16 并原样恢复。

⚠ 为什么不用 thread_base 那套（d2r-android 的 `sub sp + 键页`）：
   那一套是**离线改写 + 宿主可 dlopen 的 .so** 场景，需要键页与 fixups。
   我们是**运行时内存改写**，桩区地址在映射时就知道，用固定桩区更简单。

输出：app/native/za_tls_mrs.h（每条：偏移、原 4 字节、新指令序列的索引）
     以及 app/native/za_tls_mrs_blob.h（所有替换序列拼成的机器码块）
"""
import os
import struct
import sys

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_TEXT = os.path.join(ROOT, "work", "nso", "text.bin")
OUT_H = os.path.join(ROOT, "app", "native", "za_tls_mrs.h")
OUT_BLOB = os.path.join(ROOT, "app", "native", "za_tls_mrs_blob.h")

STUB_OFF = 0x6000000        # 桩区（在映像 0x5f7a000 之后、必须纳入映射范围）
TLS_VAR_OFF = 0x5F90000     # 客机 TLS 变量区（必须与 patch_tls_helpers.py 一致！）

MRS_TPIDR_EL0 = 0xD53BD040


def enc_adrp(rd, pc, target):
    imm = ((target & ~0xFFF) - (pc & ~0xFFF)) >> 12
    assert -(1 << 20) <= imm < (1 << 20), "adrp 越界"
    return 0x90000000 | ((imm & 3) << 29) | (((imm >> 2) & 0x7FFFF) << 5) | rd


def enc_ldr(rt, rn, imm12=0):
    return 0xF9400000 | (imm12 << 10) | (rn << 5) | rt


def enc_stur(rt, rn, off):
    return 0xF8000000 | ((off & 0x1FF) << 12) | (rn << 5) | rt


def enc_ldur(rt, rn, off):
    return 0xF8400000 | ((off & 0x1FF) << 12) | (rn << 5) | rt


def enc_mov(rd, rm):
    # ORR Xd, XZR, Xm
    return 0xAA0003E0 | (rm << 16) | rd


def enc_blr(rn):
    return 0xD63F0000 | (rn << 5)


def enc_mrs_tpidr(rt):
    return 0xD53BD040 | rt


def enc_and_not1fff(rd, rn):
    # AND (imm) 64-bit，N=1 immr=51 imms=50 ⇒ 掩掉低 13 位（同 patch_tls_helpers 的 AND_MASK_13）
    return 0x92000000 | (1 << 22) | (51 << 16) | (50 << 10) | (rn << 5) | rd


def enc_add_lsl3(rd, rn, rm):
    # ADD (shifted reg) Xd, Xn, Xm, LSL #3
    return 0x8B000000 | (rm << 16) | (3 << 10) | (rn << 5) | rd


NOP = 0xD503201F


def enc_b(frm, to):
    off = to - frm
    assert -(1 << 27) <= off < (1 << 27) and off % 4 == 0, "b 越界"
    return 0x14000000 | ((off >> 2) & 0x3FFFFFF)


def main():
    text = open(MAIN_TEXT, "rb").read()
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    md.detail = True

    # 用 capstone 逐**字**反汇编找 mrs Xt, TPIDR_EL0。
    # ⚠ 不能整段 `md.disasm(text, 0)`：它会顺着控制流跳、遇到数据/非法字就停，
    #   实测整段扫出来 0 处。必须按 4 字节网格逐字解码（数据字解不出来就跳过）。
    sites = []
    for off in range(0, len(text) - 3, 4):
        w = struct.unpack_from("<I", text, off)[0]
        # 先用编码预筛（mrs Xt, TPIDR_EL0 = 0xD53BD040 | Rt），再用 capstone 复核
        if (w & 0xFFFFFFE0) != MRS_TPIDR_EL0:
            continue
        got = list(md.disasm(text[off:off + 4], off))
        if not got or got[0].mnemonic != "mrs" or "tpidr_el0" not in got[0].op_str:
            continue
        n = w & 0x1F
        sites.append((off, n, w))
    print("main 里 mrs Xt, TPIDR_EL0 共 %d 处" % len(sites))

    # 生成替换序列：每条 = 5 条指令（固定步长），原位置写 b <桩>
    STRIDE_INSNS = 5
    V_ADDR = TLS_VAR_OFF            # 客机 TLS 变量区（与 helper 改写同一块）
    blob = bytearray()
    entries = []
    for off, n, orig in sites:
        stub_pc = STUB_OFF + len(blob)
        seq = []
        if n == 16:
            # 目标就是 x16：mrs 本来就会覆盖它，不必保存
            seq += [NOP, 0, NOP, NOP]
        else:
            seq += [enc_stur(16, 31, -8), 0, enc_mov(n, 16), enc_ldur(16, 31, -8)]
        seq.append(0)                    # b 回原址+4，下面统一回填
        assert len(seq) == STRIDE_INSNS
        entries.append([off, orig, stub_pc, seq])
        for w in seq:
            blob.extend(struct.pack("<I", w))

    # 回填每条序列的 adrp + 末尾 b
    for off, orig, stub_pc, seq in entries:
        idx = (stub_pc - STUB_OFF) // 4
        adrp = enc_adrp(16, stub_pc + 4, V_ADDR)
        struct.pack_into("<I", blob, (idx + 1) * 4, adrp)
        b_insn = enc_b(stub_pc + (STRIDE_INSNS - 1) * 4, off + 4)
        struct.pack_into("<I", blob, (idx + STRIDE_INSNS - 1) * 4, b_insn)

    # 桩区末尾留一格（映射/mprotect 的上界；本版桩不再需要宿主回调）
    hook_slot = (STUB_OFF + len(blob) + 7) & ~7
    entries = [(off, orig, stub_pc) for off, orig, stub_pc, _ in entries]

    print("替换序列 %d 条，桩区 %#x 字节（%#x .. %#x）"
          % (len(entries), len(blob), STUB_OFF, STUB_OFF + len(blob)))

    with open(OUT_BLOB, "w", encoding="utf-8", newline="\n") as o:
        o.write("// 自动生成：tools/patch_tls_mrs.py —— 别手改\n")
        o.write("// 每条 mrs TPIDR_EL0 的替换序列（机器码），运行时拷到 ZA_TLS_STUB_OFF。\n")
        o.write("#ifndef ZA_TLS_MRS_BLOB_H\n#define ZA_TLS_MRS_BLOB_H\n\n")
        o.write("#include <stdint.h>\n\n")
        o.write("#define ZA_TLS_STUB_OFF  0x%xul\n" % STUB_OFF)
        o.write("#define ZA_TLS_STUB_SIZE %d\n" % len(blob))
        o.write("#define ZA_TLS_HOOK_SLOT 0x%xul   /* 桩区末尾（映射上界） */\n" % hook_slot)
        o.write("static const unsigned int za_tls_mrs_blob[%d] = {\n" % (len(blob) // 4))
        for i in range(0, len(blob), 4):
            w = struct.unpack_from("<I", blob, i)[0]
            o.write("    0x%08xu,   // +%#x\n" % (w, i))
        o.write("};\n\n#endif\n")

    with open(OUT_H, "w", encoding="utf-8", newline="\n") as o:
        o.write("// 自动生成：tools/patch_tls_mrs.py —— 别手改\n")
        o.write("// 每条 mrs TPIDR_EL0 → `b <桩>`，桩里内联算客机 TLS 基址。\n")
        o.write("#ifndef ZA_TLS_MRS_H\n#define ZA_TLS_MRS_H\n\n")
        o.write("#define ZA_TLS_MRS_COUNT %d\n\n" % len(entries))
        o.write("typedef struct { unsigned int off; unsigned int orig; unsigned int stub; } za_tls_mrs_t;\n\n")
        o.write("static const za_tls_mrs_t za_tls_mrs[] = {\n")
        for off, orig, stub in entries:
            o.write("    {0x%xu, 0x%08xu, 0x%xu},\n" % (off, orig, stub))
        o.write("};\n\n#endif\n")
    print("已写 %s / %s" % (os.path.basename(OUT_H), os.path.basename(OUT_BLOB)))


if __name__ == "__main__":
    main()
