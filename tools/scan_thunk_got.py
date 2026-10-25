#!/usr/bin/env python3
"""扫出 SDK 里所有「导入跳板」的 GOT 槽 + 每个槽应该装的符号。
   （用 llvm-objdump 的反汇编文本解析，不手搓指令掩码。）

   运行时若某槽为 0 ⇒ `br x17` 跳到 0 ⇒ 客机 pc=0 跳空。
"""
import os, re, struct, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import sdk_thunk as ST

OBJDUMP = os.path.join(ROOT, "..", "d2r-and", "build-tools-win", "ndk28", "android-ndk-r28c",
                       "toolchains", "llvm", "prebuilt", "windows-x86_64", "bin", "llvm-objdump.exe")
TEXT_SZ = 0x64E230
TEXT = os.path.join(ROOT, "work", "nso_32848007", "text.bin")


def disassemble_all():
    """把整个 text 段包成临时 ELF 后交给 llvm-objdump，返回 {地址: 指令文本}"""
    blob = open(TEXT, "rb").read()
    with tempfile.NamedTemporaryFile(suffix=".elf", delete=False) as f:
        f.write(ST.__dict__.get("_wrap", None) or wrap_elf(blob, 0))
        tmp = f.name
    try:
        r = subprocess.run([OBJDUMP, "-d", "--no-show-raw-insn", tmp],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
    finally:
        os.unlink(tmp)
    out = {}
    for line in r.stdout.splitlines():
        m = re.match(r"^\s*([0-9a-f]+):\s+(.*)$", line)
        if m:
            out[int(m.group(1), 16)] = m.group(2).strip()
    return out


def wrap_elf(text, vaddr):
    shstr = b"\0.shstrtab\0.text\0"
    ehsize, phentsize = 64, 56
    phoff = ehsize
    dataoff = (phoff + phentsize + 15) & ~15
    shstr_off = dataoff + len(text)
    shoff = (shstr_off + len(shstr) + 15) & ~15
    e = bytearray()
    e += b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8)
    e += struct.pack("<HHIQQQIHHHHHH", 2, 0xB7, 1, vaddr, phoff, shoff, 0,
                     ehsize, phentsize, 56, 64, 3, 2)
    e += struct.pack("<IIQQQQQQ", 1, 5, dataoff, vaddr, vaddr, len(text), len(text), 0x1000)
    e += b"\0" * (dataoff - len(e))
    e += text
    e += shstr
    e += b"\0" * (shoff - len(e))
    e += bytes(64)
    e += struct.pack("<IIQQQQIIQQ", 1, 1, 6, vaddr, dataoff, len(text), 0, 0, 8, 0)
    e += struct.pack("<IIQQQQIIQQ", 2, 3, 0, 0, shstr_off, len(shstr), 0, 0, 1, 0)
    return bytes(e)


def reloc_map():
    IMG = ST.load()
    mod0 = struct.unpack_from("<I", bytes(IMG[4:8]), 0)[0]
    disp = struct.unpack_from("<i", bytes(IMG[mod0:mod0 + 28]), 4)[0]
    dyn = mod0 + disp
    vals = {}
    for i in range(512):
        b = bytes(IMG[dyn + i * 16:dyn + i * 16 + 16])
        if len(b) < 16:
            break
        tag, val = struct.unpack_from("<qQ", b, 0)
        if tag == 0:
            break
        vals[tag] = val
    symtab, strtab, strsz = vals[6], vals[5], vals[10]
    strs = bytes(IMG[strtab:strtab + strsz])

    def sym(i):
        b = bytes(IMG[symtab + i * 24:symtab + i * 24 + 24])
        if len(b) < 24:
            return None
        name, info, other, shndx = struct.unpack_from("<IBBH", b, 0)
        value, size = struct.unpack_from("<QQ", b, 8)
        e = strs.find(b"\0", name)
        return strs[name:e].decode("ascii", "replace"), value

    relmap = {}
    for off, size in ((vals.get(7), vals.get(8)), (vals.get(23), vals.get(2))):
        if not off or not size:
            continue
        for i in range(size // 24):
            b = bytes(IMG[off + i * 24:off + i * 24 + 24])
            if len(b) < 24:
                break
            r_off, r_info, r_add = struct.unpack_from("<QQq", b, 0)
            si, typ = r_info >> 32, r_info & 0xFFFFFFFF
            s = sym(si)
            if s:
                relmap.setdefault(r_off, []).append((typ, s[0], s[1]))
    return relmap


def main():
    print("反汇编整个 text 段（%d 字节）…" % TEXT_SZ)
    ins = disassemble_all()
    print("指令 %d 条" % len(ins))

    slots = {}
    addrs = sorted(ins)
    for a in addrs:
        t = ins[a]
        m = re.match(r"^adrp\s+x(\d+),\s*0x([0-9a-f]+)(\s|$)", t)
        if not m:
            continue
        rd = int(m.group(1))
        page = int(m.group(2), 16)
        t1 = ins.get(a + 4, "")
        m1 = re.match(r"^ldr\s+x(\d+),\s*\[x(\d+),\s*#0x([0-9a-f]+)\](\s|$)", t1)
        if not m1 or int(m1.group(2)) != rd:
            continue
        rt = int(m1.group(1))
        off = int(m1.group(3), 16)
        t2 = ins.get(a + 8, "")
        m2 = re.match(r"^add\s+x(\d+),\s*x(\d+),\s*#0x([0-9a-f]+)(\s|$)", t2)
        if not m2 or int(m2.group(1)) != rd or int(m2.group(2)) != rd:
            continue
        if int(m2.group(3), 16) != off:
            continue
        t3 = ins.get(a + 12, "")
        m3 = re.match(r"^br\s+x(\d+)(\s|$)", t3)
        if not m3 or int(m3.group(1)) != rt:
            continue
        slots.setdefault(page + off, []).append(a)

    rel = reloc_map()
    out = sorted(slots.items())
    print("跳板 %d 个，GOT 槽 %d 个\n" % (sum(len(v) for v in slots.values()), len(out)))
    nosym = []
    for slot, callers in out:
        r = rel.get(slot)
        nm = ",".join(x[1] for x in r) if r else "(无重定位)"
        if not r:
            nosym.append((slot, callers))
            nm += "   ★无重定位"
        print("  GOT[%#010x] <- %-46s 跳板 %s" % (slot, nm[:46], " ".join("%#x" % c for c in callers[:3])))
    print("\n无重定位的槽 %d 个（文件里原值可能是 0 ⇒ br 0）:" % len(nosym))
    for slot, callers in nosym[:60]:
        print("  GOT[%#010x] 跳板 %s" % (slot, " ".join("%#x" % c for c in callers[:3])))

    OUT = os.path.join(ROOT, "app", "native", "za_thunk_got.h")
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write("// 自动生成：tools/scan_thunk_got.py —— 别手改\n")
        f.write("// SDK text 里所有「导入跳板」(adrp/ldr [GOT]/br x17) 的 GOT 槽。\n")
        f.write("// 槽值为 0 ⇒ `br x17` 跳到 0 ⇒ 客机 pc=0 跳空。\n")
        f.write("#ifndef ZA_THUNK_GOT_H\n#define ZA_THUNK_GOT_H\n\n")
        f.write("#define ZA_THUNK_GOT_COUNT %d\n\n" % len(out))
        f.write("static const unsigned int za_thunk_got[] = {\n")
        for slot, _ in out:
            f.write("    0x%xu,\n" % slot)
        f.write("};\n\n#endif\n")
    print("\n-> %s" % OUT)


if __name__ == "__main__":
    main()
