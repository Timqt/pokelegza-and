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

替换序列（借红区存临时寄存器，不破坏 callee-saved）：
    stur x16, [sp, #-16]        ; 临时保存（xN != 16 时用 16）
    adrp x16, <桩区>            ; 桩区 = 宿主写进来的函数指针表
    ldr  x16, [x16, #0]         ; x16 = 宿主回调地址
    blr  x16                    ; 回调宿主 → 宿主返回本线程的客机 TLS 基址
    mov  xN, x0                 ; ★ 结果
    ldur x16, [sp, #-16]

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

    # 生成替换序列：每条 = 6 条指令，放在桩区里，原位置写 b <桩>
    blob = bytearray()
    entries = []
    for off, n, orig in sites:
        tmp = 17 if n == 17 else 16      # 临时寄存器（不用目标寄存器自己）
        stub_pc = STUB_OFF + len(blob)
        seq = []
        # ★ 必须同时保存 x30：被替换的 mrs 站点可能是**叶子函数**，x30 就是
        #   调用者的返回地址（没有 prologue 保护）。桩里的 blr 会覆盖 x30，
        #   之后 `b 回原址` 落到函数末尾的 ret ⇒ ret 跳回桩里 ⇒ 桩↔ret 无限
        #   乒乓（实测：pc 恒在 main+0x603447c 桩区、100% CPU 无 svc）。
        #   x16 用红区 [sp-16]，x30 用 [sp-32]（同样是红区，安全）。
        seq.append(enc_stur(tmp, 31, -16))
        seq.append(enc_stur(30, 31, -32))
        # 回调地址放在**整个桩区末尾之后**的一格（运行时装进去），
        # 用 adrp+ldr 取：adrp 给页基址，ldr 的 imm12 按 8 字节缩放给页内偏移。
        seq_adrp_pc = stub_pc + 4
        seq.append(0)                    # 先占位，循环结束后统一回填
        seq.append(0)                    # ldr
        seq.append(enc_blr(tmp))
        seq.append(enc_mov(n, 0))
        seq.append(enc_ldur(30, 31, -32))
        seq.append(enc_ldur(tmp, 31, -16))
        # 回原位置的下一条
        seq.append(enc_b(stub_pc + len(seq) * 4, off + 4))
        entries.append((off, orig, stub_pc, seq, seq_adrp_pc))
        for w in seq:
            blob.extend(struct.pack("<I", w))

    # 回调地址那格 = 桩区末尾（8 字节对齐）
    hook_slot = (STUB_OFF + len(blob) + 7) & ~7
    print("回调地址格：%#x（桩区末尾）" % hook_slot)
    # 回填每条序列里的 adrp/ldr
    for off, orig, stub_pc, seq, adrp_pc in entries:
        adrp = enc_adrp(16, adrp_pc, hook_slot)
        page = hook_slot & ~0xFFF
        imm12 = (hook_slot - page) // 8          # LDR 的 imm12 按 8 缩放
        assert 0 <= imm12 < 0x1000, "ldr imm12 越界"
        ldr = enc_ldr(16, 16, imm12)
        base_idx = (stub_pc - STUB_OFF) // 4
        # 序列：stur x16 / stur x30 / adrp / ldr / blr / mov / ldur x30 / ldur x16 / b
        #               [0]      [1]     [2]   [3]   [4]   [5]     [6]       [7]    [8]
        struct.pack_into("<I", blob, (base_idx + 2) * 4, adrp)
        struct.pack_into("<I", blob, (base_idx + 3) * 4, ldr)

    # 重新写 entries（此时 stub 地址不变）
    entries = [(off, orig, stub_pc) for off, orig, stub_pc, _, _ in entries]

    print("替换序列 %d 条，桩区 %#x 字节（%#x .. %#x）"
          % (len(entries), len(blob), STUB_OFF, STUB_OFF + len(blob)))

    with open(OUT_BLOB, "w", encoding="utf-8", newline="\n") as o:
        o.write("// 自动生成：tools/patch_tls_mrs.py —— 别手改\n")
        o.write("// 每条 mrs TPIDR_EL0 的替换序列（机器码），运行时拷到 ZA_TLS_STUB_OFF。\n")
        o.write("#ifndef ZA_TLS_MRS_BLOB_H\n#define ZA_TLS_MRS_BLOB_H\n\n")
        o.write("#include <stdint.h>\n\n")
        o.write("#define ZA_TLS_STUB_OFF  0x%xul\n" % STUB_OFF)
        o.write("#define ZA_TLS_STUB_SIZE %d\n" % len(blob))
        o.write("#define ZA_TLS_HOOK_SLOT 0x%xul\n" % hook_slot)
        o.write("#define ZA_TLS_HOOK_SLOT 0x%xul\n" % hook_slot)
        o.write("static const unsigned int za_tls_mrs_blob[%d] = {\n" % (len(blob) // 4))
        for i in range(0, len(blob), 4):
            w = struct.unpack_from("<I", blob, i)[0]
            o.write("    0x%08xu,   // +%#x\n" % (w, i))
        o.write("};\n\n#endif\n")

    with open(OUT_H, "w", encoding="utf-8", newline="\n") as o:
        o.write("// 自动生成：tools/patch_tls_mrs.py —— 别手改\n")
        o.write("// 每条 mrs TPIDR_EL0 → `b <桩>`，桩里回调宿主取线程基址。\n")
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
