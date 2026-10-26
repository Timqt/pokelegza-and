#!/usr/bin/env python3
"""生成「客机 TLS helper」改写补丁。

原理（见 客机装载.md §3）：
客机取 TLS 变量的 helper 长这样：

    mrs  x8, TPIDR_EL0
    ubfm x8, x8, #51, #14      ; x8 = TPIDR & ~0x1FFF（16KB 对齐的线程上下文基址）
    ldr  x9, [x8, #0x13]       ; x9 = [x8+0x98] = 模块 TLS 块偏移
    add  x8, x8, x9, lsl #3    ; x8 = 基址 + 偏移*8 = TLS 变量区
    ldr  x0, [x8, #imm]        ; 取变量值

我们**不动 TPIDR_EL0**（动了会把 bionic 自己的 TLS 弄坏），
而是把 helper 里的 x8 来源从「TPIDR & ~0x1FFF」换成「我们自备的描述符块 P」：
    mrs  x8, TPIDR_EL0   →  adrp x8, <P 所在页>
    ubfm x8, x8, #51,#14 →  nop
于是 `ldr x9, [x8, #0x13]` 读到的就是我们放在 P+0x98 的描述符，
`add x8, x8, x9, lsl #3` 得到的 x8 = P + (V-P)/8*8 = V（我们自备的 TLS 变量区）。

adrp 是 **PC 相对**的 ⇒ 每个位置的立即数都要单独算。

输出：一个 C 头文件（补丁表），C 端在 mprotect 收紧权限之前应用。
"""
import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT = os.path.join(ROOT, "work", "nso", "text.bin")
OUT_H = os.path.join(ROOT, "app", "native", "za_tls_patch.h")

# 映像末尾之外扩展一块「描述符区」：基址 + 该偏移。
# 必须是 4KB 对齐（adrp 只给页基址，低 12 位用 add 补；这里低 12 位是 0，省一条 add）。
TLS_DESC_OFF = 0x5F80000
TLS_VAR_OFF = 0x5F90000      # 客机 TLS 变量区（1MB）
TLS_VAR_SIZE = 0x100000

MRS_TPIDR = 0xD53BD040        # mrs Xt, TPIDR_EL0
UBFM_MASK = 0xF273C800        # ubfm Xd, Xn, #51, #14（掩掉寄存器位后）
# ★ 2026-10-25 追加：同样的「TPIDR & ~0x1FFF」还有第二种写法 —— **AND (立即数)**：
#     31bc8: and x23, x8, #0xffffffffffffe000    (= 0x9273C917，sf=1 N=1 immr=51 imms=50)
#   语义与 ubfm #51,#14 完全一样，只是编码不同。原补丁器只认 ubfm ⇒
#   这类 helper **一处都没被改写** ⇒ 客机拿到 bionic 的 tp、按 [tp+0x98] 读到 bionic 元数据
#   ⇒ 算出的模块 TLS 块偏移是垃圾 ⇒ 之后 blr 到野地址（实测 pc=0）。
#   这里把 AND 形态一起匹配。
AND_MASK_13 = 0x9273C800      # AND (imm) 64-bit，immr=51 imms=50 ⇒ 掩掉低 13 位（实测编码 0x9273C917）


def is_tls_mask(w):
    """判断这条指令是不是「TPIDR 与 ~0x1FFF」的那一步（ubfm 或 and 两种写法）。"""
    if (w & 0xFFFFFC00) == UBFM_MASK:
        return True
    if (w & 0xFFFFFC00) == AND_MASK_13:
        return True
    return False


def adrp_x(rd, page_delta):
    """编码 adrp Xd, <page>：imm21 = (目标页 - 本指令所在页) >> 12。

    ADRP 的立即数布局：**immlo 在 bit30:29，immhi 在 bit23:5**，
    21 位整体算出来后再左移 12 位当页偏移 —— 不是简单地把 imm 塞进 bit23:5。
    （写错的话立即数会放大 4 倍，客机就会读到野地址。）
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
    d = open(TEXT, "rb").read()
    n = len(d) // 4
    words = list(struct.unpack_from("<%dI" % n, d, 0))

    patches = []
    for i in range(n - 1):
        w1 = words[i]
        w2 = words[i + 1]
        if (w1 & 0xFFFFFFE0) != MRS_TPIDR:
            continue
        if not is_tls_mask(w2):
            continue
        src1 = w1 & 31          # mrs 的目标（= 读到 TPIDR 的寄存器）
        src2 = (w2 >> 5) & 31   # 掩码指令的源寄存器
        dst2 = w2 & 31          # 掩码指令的目标寄存器
        if src2 != src1:
            continue            # 源必须是刚读到 TPIDR 的那个寄存器
        # ⚠ 两种形态：
        #   ubfm x8, x8, #51,#14  → dst2 == src2（原地掩码）
        #   and  x23,x8, #~0x1FFF → dst2 != src2（掩到另一个寄存器）
        # 改写要作用在**掩码指令的目标寄存器**上（客机后续用它当 tp16）：
        #   adrp dst2, <描述符区页>  ; nop
        # 原代码只允许 dst2 == src2 ⇒ and 形态（main 里那种）一处都匹配不到。
        off = i * 4
        # ★ 2026-10-26：改成**每线程**取基址。
        #   mrs 保持原样（x_src = TPIDR_EL0），掩码位置改成
        #       ldr  dst2, [src1, #0x40]
        #   [TP+0x40] 是 bionic 8 个 TCB 槽之后的第一个空闲位（实测三个线程
        #   都是已映射的 0），宿主在每线程 install 时写进该线程的「头页 D」。
        #   后续原代码仍做 `ldr x9,[dst2,#0x98]` / `add dst2,dst2,x9,lsl#3`：
        #   D+0x98 = (area-D)/8 ⇒ 结果正好是该线程的 TLS 变量区。
        patches.append((off, 0xD53BD040 | src1,
                        0xF9400000 | ((0x40 // 8) << 10) | (src1 << 5) | dst2))

    print("TLS helper 改写点：%d 处" % len(patches))
    with open(OUT_H, "w", encoding="utf-8", newline="\n") as o:
        o.write("// 自动生成：tools/patch_tls_helpers.py —— 别手改\n")
        o.write("// 把客机 TLS helper 里的 `mrs Xt,TPIDR_EL0 / ubfm` 换成\n")
        o.write("// `adrp Xt,<我们自备描述符区> / nop`，这样不必动 TPIDR_EL0（动了会破坏 bionic 的 TLS）。\n")
        o.write("#ifndef ZA_TLS_PATCH_H\n#define ZA_TLS_PATCH_H\n\n")
        o.write("#define ZA_TLS_DESC_OFF  0x%xul   /* 描述符区：基址 + 该偏移 */\n" % TLS_DESC_OFF)
        o.write("#define ZA_TLS_VAR_OFF   0x%xul   /* 客机 TLS 变量区 */\n" % TLS_VAR_OFF)
        o.write("#define ZA_TLS_VAR_SIZE  0x%xul\n" % TLS_VAR_SIZE)
        o.write("#define ZA_TLS_PATCH_COUNT %d\n\n" % len(patches))
        o.write("typedef struct { unsigned int off; unsigned int w0; unsigned int w1; } za_tls_patch_t;\n\n")
        o.write("static const za_tls_patch_t za_tls_patches[] = {\n")
        for off, w0, w1 in patches:
            o.write("    {0x%xu, 0x%08xu, 0x%08xu},\n" % (off, w0, w1))
        o.write("};\n\n#endif\n")
    print("已写 %s" % OUT_H)
    print("  描述符区 = 基址 + %#x，变量区 = 基址 + %#x（%d 字节）" % (TLS_DESC_OFF, TLS_VAR_OFF, TLS_VAR_SIZE))


if __name__ == "__main__":
    main()
