#!/usr/bin/env python3
"""生成 Horizon `svc` 宿主门的补丁表与门区机器码（SDK NSO）。

背景：客机/SDK 用 `svc #N` 调 Horizon 内核服务（线程/事件/内存/文件…）。
在 Linux/arm64 上 `svc` 就是系统调用 ⇒ 未知号 ⇒ SIGSYS，客机直接死。

实测：main 的 text 里 0 处 svc；SDK 的 text 里 58 处，全在 0x16FFD8–0x1700xx
（服务号 1…58 连续 ⇒ Horizon 服务调用封装表），形态极简 `svc #N ; ret`。

改写链（每处 svc 只改 4 字节）：
    svc #N  →  b 门_N
门_N（映像内固定地址）：  mov w9, #N ; b tramp_N
tramp_N（映像内固定地址）：
    sub sp, sp, #0x70 / stp x29,x30,[sp,#0x60] / mov x29,sp
    str w9, [sp, #0x00]        ← 服务号 → C 的第 9 个参数（栈上传参）
    adrp x16, <C指针槽页> / ldr x17, [x16, #off]   ← 从固定槽取 C 函数地址
    blr x17
    ldp x29,x30,[sp,#0x60] / add sp,sp,#0x70 / ret

为什么要绕这一圈：我们的 .so 里那个 C 函数的**运行时地址不固定**，
所以不能直接 bl 它；改成从映像内一个固定槽读地址（装载时填好）✓

输出：app/native/za_svc_patch.h
"""
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SDK_TEXT = os.path.join(ROOT, "work", "nso_32848007", "text.bin")
OUT_H = os.path.join(ROOT, "app", "native", "za_svc_patch.h")

SDK_IMG_SIZE = 0xC5E000
GATE_BASE = 0xC70000          # 门区起点（映像末尾扩展区）
GATE_SIZE = 0x20000
GATE_COUNT = 256              # 服务号最大 114 ⇒ 门按 (N-1) 排
TRAMP_BASE = GATE_BASE + 0x10000  # trampoline 区
TRAMP_SIZE = 96               # 每条 trampoline 的字节数（自检用，实际长度由编译结果决定）
SLOT_OFF = GATE_BASE + 0x1F000    # C 函数指针槽（8 字节）


# ---------------- aarch64 指令编码 ----------------
def enc_sub_sp(imm):
    return 0xD1000000 | ((imm & 0xFFF) << 10) | (31 << 5) | 31


def enc_add_sp(imm):
    return 0x91000000 | ((imm & 0xFFF) << 10) | (31 << 5) | 31


def enc_stp_x29x30_sp_pre(imm):
    imm7 = (imm // 8) & 0x7F
    # STP pre-index: 1010 1000 10 imm7(22:16) Rt2(15:10) Rn(9:5) Rt(4:0)
    return 0xA8000000 | (imm7 << 16) | (30 << 10) | (31 << 5) | 29


def enc_ldp_x29x30_sp_post(imm):
    imm7 = (imm // 8) & 0x7F
    # LDP post-index: 1010 1000 11 imm7(22:16) Rt2(15:10) Rn(9:5) Rt(4:0)
    return 0xA8C00000 | (imm7 << 16) | (30 << 10) | (31 << 5) | 29


def enc_mov_x29_sp():
    return 0x910003FD


def enc_str_w9_sp0():
    return 0xB9000000 | (31 << 5) | 9


def enc_adrp(rd, from_off, target_page):
    imm = (target_page - (from_off & ~0xFFF)) >> 12
    if not (-(1 << 20) <= imm < (1 << 20)):
        raise ValueError("adrp 越界")
    return 0x90000000 | ((imm & 0x1FFFFF) << 5) | rd


def enc_ldr_x_off(xn, rt, byte_off):
    imm12 = byte_off // 8
    if not (0 <= imm12 <= 0xFFF):
        raise ValueError("ldr 偏移越界: %d" % byte_off)
    return 0xF9400000 | (imm12 << 10) | (xn << 5) | rt


def enc_blr(rt):
    # BLR: 1101 0111 0011 1111 0000 00 Rn
    return 0xD63F0000 | (rt << 5) | rt


def enc_ret():
    return 0xD65F03C0


def enc_mov_w_imm(rd, imm16):
    return 0x52800000 | ((imm16 & 0xFFFF) << 5) | rd


def enc_b(from_off, to_off):
    delta = to_off - from_off
    if delta & 3:
        raise ValueError("b 目标未对齐")
    imm = delta >> 2
    if not (-(1 << 25) <= imm < (1 << 25)):
        raise ValueError("b 越界: %d" % imm)
    return 0x14000000 | (imm & 0x03FFFFFF)


def compile_trampoline():
    """用 clang 把 app/native/za_horizon_tramp.S 编译成机器码（避免手写编码出错）。

    trampoline 自带一个 8 字节的 .quad 槽（末尾），装载时填入宿主 C 函数地址。
    """
    import subprocess
    ndk = os.environ.get("ZA_NDK", r"D:\feiniukexinhome\Code\d2r-and\build-tools-win\ndk28\android-ndk-r28c")
    cc = os.path.join(ndk, "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin",
                      "aarch64-linux-android26-clang.cmd")
    oc = os.path.join(ndk, "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin", "llvm-objcopy.exe")
    src = os.path.join(ROOT, "app", "native", "za_horizon_tramp.S")
    out_o = os.path.join(ROOT, "work", "za_horizon_tramp.o")
    out_bin = os.path.join(ROOT, "work", "za_horizon_tramp.bin")
    subprocess.run([cc, "-c", src, "-o", out_o], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    subprocess.run([oc, "-O", "binary", "--only-section=.text", out_o, out_bin], check=True)
    return open(out_bin, "rb").read()


def main():
    d = open(SDK_TEXT, "rb").read()
    n = len(d) // 4
    words = struct.unpack_from("<%dI" % n, d, 0)
    hits = []
    for i in range(n):
        w = words[i]
        if (w & 0xFFE0001F) == 0xD4000001:
            hits.append((i * 4, (w >> 5) & 0xFFFF))
    print("SDK svc 指令 %d 处" % len(hits))
    if not hits:
        raise SystemExit("没扫到 svc")
    maxnr = max(nr for _, nr in hits)
    if maxnr > GATE_COUNT:
        raise SystemExit("服务号 %d 超过门区容量 %d" % (maxnr, GATE_COUNT))

    # ── 找出每个 svc 所属的「包装函数入口」和「出参形状」 ──
    #
    # 带出参的包装函数长这样（svc 前面有 prologue）：
    #     str  x0, [sp, #-0x10]!      ← 保存出参指针
    #     svc  #N
    #     ldr  x2, [sp]               ← 取回
    #     str  w1, [x2]               ← W1 → *x0
    #     add  sp, sp, #0x10
    #     ret
    # 另有一种同时有两个出参（stp x0,x1），还有 svc #47 的三槽特例。
    #
    # ⚠ 必须改写**包装函数的入口**而不是 svc 那条指令：
    #   改 svc 的话 prologue 仍会执行（sp 被压低 16、保存了 x0），
    #   trampoline 的 ret 就会把保存的 x0 当返回地址弹出去 ⇒ 跳到野地址。
    STR_PRE = 0xF81F0FE0     # str x0,[sp,#-0x10]!
    STP_PRE = 0xA9BF07E0     # stp x0,x1,[sp,#-0x10]!
    shapes = {}
    entries = {}
    for off, nr in hits:
        shape = 1
        entry = off
        if off >= 4 and words[off // 4 - 1] == STR_PRE:
            shape = 2
            entry = off - 4
        elif off >= 4 and words[off // 4 - 1] == STP_PRE:
            if off >= 8 and words[off // 4 - 2] == (STR_PRE | 2):
                shape = 4       # svc #47：str x2 + stp x0,x1
                entry = off - 8
            else:
                shape = 3       # stp x0,x1：两个出参
                entry = off - 4
        shapes[nr] = shape
        entries[nr] = entry
    from collections import Counter
    print("出参形状分布: %s（1=无 2=W1→*x0 3=W1→*x0,W2→*x1 4=#47 三槽）"
          % dict(sorted(Counter(shapes.values()).items())))

    # trampoline 机器码（clang 编的，所有服务号共用一份；服务号在 x9）
    tramp = compile_trampoline()
    TRAMP_LEN = len(tramp)
    # 末尾三个 .quad 槽：1: C 函数地址  2: za_horizon_regs[] 地址  3: 宿主栈顶
    slot_fn_off = TRAMP_BASE + TRAMP_LEN - 24
    slot_regs_off = TRAMP_BASE + TRAMP_LEN - 16
    slot_stack_off = TRAMP_BASE + TRAMP_LEN - 8
    print("trampoline 机器码 %d 字节，C 指针槽 %#x，寄存器回写槽 %#x，宿主栈槽 %#x"
          % (TRAMP_LEN, slot_fn_off, slot_regs_off, slot_stack_off))

    # 门区机器码
    gate = bytearray(GATE_SIZE)
    struct.pack_into("<I", gate, TRAMP_BASE - GATE_BASE, struct.unpack_from("<I", tramp, 0)[0])
    for i in range(1, TRAMP_LEN // 4):
        struct.pack_into("<I", gate, TRAMP_BASE - GATE_BASE + i * 4, struct.unpack_from("<I", tramp, i * 4)[0])
    for nr in range(1, maxnr + 1):
        g = GATE_BASE + (nr - 1) * 8
        struct.pack_into("<II", gate, g - GATE_BASE, enc_mov_w_imm(9, nr), enc_b(g + 4, TRAMP_BASE))

    # 补丁表：改写**包装函数入口**
    patches = []
    for off, nr in hits:
        g = GATE_BASE + (nr - 1) * 8
        e = entries[nr]
        patches.append((e, enc_b(e, g)))
    patches.sort()

    with open(OUT_H, "w", encoding="utf-8", newline="\n") as o:
        o.write("// 自动生成：tools/patch_svc.py —— 别手改\n")
        o.write("// 把 SDK 的 Horizon `svc #N` 包装函数**入口**改写成 `b <门_N>`，\n")
        o.write("// 门区在映像末尾扩展区。出参形状表告诉宿主怎么把 W1/W2 写回去。\n")
        o.write("#ifndef ZA_SVC_PATCH_H\n#define ZA_SVC_PATCH_H\n\n")
        o.write("#define ZA_SVC_GATE_BASE   0x%xul   /* 门区（基址 + 该偏移） */\n" % GATE_BASE)
        o.write("#define ZA_SVC_GATE_SIZE   0x%xul\n" % GATE_SIZE)
        o.write("#define ZA_SVC_SLOT_OFF    0x%xul   /* C 函数指针槽（装载时填） */\n" % slot_fn_off)
        o.write("#define ZA_SVC_REGS_OFF    0x%xul   /* za_horizon_regs[] 槽（装载时填） */\n" % slot_regs_off)
        o.write("#define ZA_SVC_STACK_OFF  0x%xul   /* 宿主栈顶槽（装载时填） */\n" % slot_stack_off)
        o.write("#define ZA_SVC_PATCH_COUNT %d\n\n" % len(patches))
        o.write("// 出参形状：1=无  2=W1→*x0  3=W1→*x0 且 W2→*x1  4=#47 三槽特例\n")
        o.write("#define ZA_SVC_SHAPE_NONE  1\n")
        o.write("#define ZA_SVC_SHAPE_W1    2\n")
        o.write("#define ZA_SVC_SHAPE_W1W2  3\n")
        o.write("#define ZA_SVC_SHAPE_S47   4\n\n")
        o.write("typedef struct { unsigned int off; unsigned int w; } za_svc_patch_t;\n\n")
        o.write("static const za_svc_patch_t za_svc_patches[] = {\n")
        for off, w in patches:
            o.write("    {0x%xu, 0x%08xu},\n" % (off, w))
        o.write("};\n\n")
        o.write("// 每个服务号的出参形状（按服务号索引）\n")
        o.write("static const unsigned char za_svc_shapes[%d] = {\n" % (maxnr + 1))
        row = []
        for nr in range(0, maxnr + 1):
            row.append("%d" % shapes.get(nr, 0))
            if len(row) == 16:
                o.write("    " + ", ".join(row) + ",\n")
                row = []
        if row:
            o.write("    " + ", ".join(row) + ",\n")
        o.write("};\n\n#endif\n")
    # 门区机器码写成二进制资产（0x20000 的 C 数组太大）
    gate_bin = os.path.join(ROOT, "work", "nso_sdk", "sdk_gate.bin")
    os.makedirs(os.path.dirname(gate_bin), exist_ok=True)
    with open(gate_bin, "wb") as f:
        f.write(bytes(gate))
    print("门区机器码 -> %s（%d 字节）" % (gate_bin, len(gate)))
    print("补丁 %d 条；门区基址 %#x，trampoline 区 %#x，C 指针槽 %#x" %
          (len(patches), GATE_BASE, TRAMP_BASE, slot_fn_off))

    # 自检：把第一条 trampoline 打成二进制，交给 objdump 反汇编核对
    chk = os.path.join(ROOT, "work", "tramp_check.bin")
    with open(chk, "wb") as f:
        f.write(bytes(gate[TRAMP_BASE - GATE_BASE:TRAMP_BASE - GATE_BASE + TRAMP_SIZE]))
    print("自检文件: %s" % chk)


if __name__ == "__main__":
    main()
