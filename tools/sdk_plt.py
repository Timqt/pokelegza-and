# -*- coding: utf-8 -*-
"""把 SDK 的 PLT 跳板解析成「跳板地址 → 导入符号名」。

用法:
    python tools/sdk_plt.py 0x635020 0x635030 ...
    python tools/sdk_plt.py --all        # 列出全部跳板
"""
import os
import struct
import sys

import lz4.block

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NSO = os.path.join(ROOT, "work", "base", "exefs2", "entry_32848007")
RELS = os.path.join(ROOT, "work", "nso_sdk", "sdk_relocs.bin")
TEXT_SZ = 0x64E230

d = open(NSO, "rb").read()
flags = struct.unpack_from("<I", d, 0x0C)[0]
segs = [struct.unpack_from("<III", d, 0x10 + i * 0x10) for i in range(3)]
csz = struct.unpack_from("<III", d, 0x60)
segd = []
for i, (fo, mo, sz) in enumerate(segs):
    raw = d[fo:fo + csz[i]]
    if flags >> i & 1:
        raw = lz4.block.decompress(raw, uncompressed_size=sz)
    segd.append((mo, sz, raw))
dmo, dsz, _x = segd[2]
bss = struct.unpack_from("<I", d, 0x3C)[0]
IMG = bytearray(dmo + dsz + bss)
for mo, sz, raw in segd:
    IMG[mo:mo + sz] = raw
TEXT = bytes(IMG[:TEXT_SZ])


def rd(off, n):
    if off < 0 or off + n > len(IMG):
        return None
    return bytes(IMG[off:off + n])


# ── dynsym ──
mod0 = struct.unpack_from("<I", bytes(IMG[4:8]), 0)[0]
disp = struct.unpack_from("<i", rd(mod0, 28), 4)[0]
dyn = mod0 + disp
vals = {}
for i in range(512):
    b = rd(dyn + i * 16, 16)
    if b is None:
        break
    tag, val = struct.unpack_from("<qQ", b, 0)
    if tag == 0:
        break
    vals[tag] = val
symtab, strtab, strsz = vals[6], vals[5], vals[10]
nsym = (strtab - symtab) // 24
strs = rd(strtab, strsz)
names = []
for i in range(nsym):
    b = rd(symtab + i * 24, 24)
    if not b:
        break
    name = struct.unpack_from("<I", b, 0)[0]
    e = strs.find(b"\0", name)
    names.append(strs[name:e].decode("ascii", "replace"))

# ── relocs ──
rel = open(RELS, "rb").read()
nrel = struct.unpack_from("<I", rel, 0)[0]
rmap = {}
for i in range(nrel):
    slot, kind, sym, add = struct.unpack_from("<IIII", rel, 4 + i * 16)
    rmap[slot] = (kind, sym, add)


BASE = 0x140000000


def adrp_t(pc, w):
    immlo = (w >> 29) & 3
    immhi = (w >> 5) & 0x7FFFF
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= 1 << 21
    return (pc & ~0xFFF) + (imm << 12)


def br_reg(w):
    """BR Xn 的寄存器号在 bits 9:5（不是 4:0）。"""
    return (w >> 5) & 0x1F


def thunk_at(a):
    """识别 adrp(+ldr)(+add) br 形态，返回 (slot候选列表, 指令数) 或 None。

    SDK 实际形态是 4 条：
        adrp x16, page ; ldr x17,[x16,#off] ; add x16,x16,#off ; br x17

    slot 的绝对化有两种基准（NSO 链接基址可能是 0 或 0x140000000），
    这里两种都算出来，由调用方去重定位表里挑能命中的那个。
    """
    if a + 16 > len(TEXT):
        return None
    w = struct.unpack_from("<4I", TEXT, a)
    if w[0] & 0x9F000000 != 0x90000000:
        return None
    page = adrp_t(a, w[0])
    adrp_rd = w[0] & 0x1F
    if w[1] & 0xFFC00000 != 0xF9400000:
        return None
    if (w[1] >> 5) & 0x1F != adrp_rd:
        return None
    ldr_rd = w[1] & 0x1F
    loff = ((w[1] >> 10) & 0xFFF) * 8
    if w[2] == 0xD61F0000 | (ldr_rd << 5):          # adrp/ldr/br
        extra = None
    elif w[2] & 0xFF800000 == 0x91000000 and w[3] == 0xD61F0000 | (ldr_rd << 5):
        extra = (w[2] >> 10) & 0xFFF
    else:
        return None
    # GOT 地址 = adrp 页 + ldr 偏移；后面的 add 只是把同一地址再算一遍，
    # 真正被 br 的是 ldr 出来的值，所以槽 = page + loff（loff 为 0 时才用 add 的偏移）。
    off = loff if loff else (extra or 0)
    cands = [page + off, page - BASE + off]
    return cands, 3 + (1 if extra is not None else 0)


def describe(slot):
    r = rmap.get(slot)
    if r is None:
        return "无重定位条目"
    kind, sym, add = r
    nm = names[sym] if 0 <= sym < len(names) else "?%d" % sym
    if kind == 0:
        return "导入 %s (sym=%d add=%#x)" % (nm, sym, add)
    return "内部 base+%#x (%s)" % (add, nm)


if __name__ == "__main__":
    def show(a):
        r = thunk_at(a)
        if not r:
            print("thunk %#x: shape unknown" % a)
            return
        cands, ln = r
        hits = [(s, describe(s)) for s in cands if s in rmap]
        if hits:
            for s, ds in hits:
                print("thunk text+%#x (%d insn) -> slot %#x : %s" % (a, ln, s, ds))
        else:
            print("thunk text+%#x (%d insn) -> cands %s : no reloc hit"
                  % (a, ln, ", ".join("%#x" % c for c in cands)))

    def bl_target(off):
        w = struct.unpack_from("<I", TEXT, off)[0]
        if (w & 0xFC000000) != 0x94000000:
            return None
        imm = w & 0x3FFFFFF
        if imm & (1 << 25):
            imm -= 1 << 26
        return off + imm * 4

    if len(sys.argv) > 2 and sys.argv[1] == "--target":
        # 找出 GOT 槽最终指向 target 的跳板，并列出调用它的地方
        target = int(sys.argv[2], 0)
        stubs = []
        for a in range(0, len(TEXT) - 16, 4):
            r = thunk_at(a)
            if not r:
                continue
            for s in r[0]:
                rr = rmap.get(s)
                if rr and rr[2] == target:
                    stubs.append((a, s, rr))
                    break
        print("跳板指向 %#x 的有 %d 个:" % (target, len(stubs)))
        for a, s, rr in stubs:
            print("   text+%#08x  slot=%#x kind=%d sym=%d add=%#x"
                  % (a, s, rr[0], rr[1], rr[2]))
            callers = [o for o in range(0, len(TEXT) - 4, 4) if bl_target(o) == a]
            for c in callers:
                print("        <- bl @ text+%#08x" % c)
    elif len(sys.argv) > 1 and sys.argv[1] == "--all":
        seen = {}
        for a in range(0, len(TEXT) - 16, 4):
            r = thunk_at(a)
            if r:
                for s in r[0]:
                    if s not in seen:
                        seen[s] = (a, r[1])
        print("distinct slots %d" % len(seen))
        for slot in sorted(seen, key=lambda s: seen[s][0]):
            a, ln = seen[slot]
            print("   text+%#08x  -> %s" % (a, describe(slot)))
    else:
        for x in sys.argv[1:]:
            show(int(x, 0))
