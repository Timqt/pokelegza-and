"""挖控制段 / SPH 头 / c1 常数段的实际布局。

目的：
 1) 打印一个控制段 0x880 字节，找其中描述 c1 常数段位置/长度的字段；
 2) 打印 SPH 头（代码段起点）附近的字节；
 3) 打印控制段前后 0x100 字节，看 c1 是否紧贴控制段。
"""
import os, struct, collections

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BN = os.path.join(ROOT, "work", "bnsh_all")
TSV = os.path.join(ROOT, "work", "spv_map_all.tsv")

CTL = bytes.fromhex("34127698")
SPH = bytes.fromhex("78563412")

def hexdump(b, base=0, width=16):
    out = []
    for i in range(0, len(b), width):
        chunk = b[i:i + width]
        hexs = " ".join("%02x" % x for x in chunk)
        txt = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        out.append("%08x  %-*s |%s|" % (base + i, width * 3, hexs, txt))
    return "\n".join(out)

def main():
    rows = []
    with open(TSV, "r", encoding="utf-8", errors="replace") as f:
        f.readline()
        for line in f:
            p = line.rstrip("\r\n").split("\t")
            if len(p) >= 5:
                rows.append(p)

    # 选一个样本容器
    target = None
    for r in rows:
        if r[2].endswith(".bnsh"):
            target = r
            break
    if not target:
        print("no sample")
        return

    name = target[2]
    data = open(os.path.join(BN, name), "rb").read()
    c = int(target[3])
    print("样本容器: %s (%d 字节)" % (name, len(data)))
    print("控制段偏移(BNSH) = %d (0x%X)" % (c, c))

    print("\n--- 控制段 0x00..0x40 ---")
    print(hexdump(data[c:c + 0x40], c))
    print("\n--- 控制段 0x40..0x90 ---")
    print(hexdump(data[c + 0x40:c + 0x90], c + 0x40))

    # 控制段内所有看起来像偏移/长度的 u32（相对 BNSH 起点）
    print("\n--- 控制段内 u32 值落在 BNSH 范围内的字段 ---")
    hits = []
    for off in range(0, 0x880, 4):
        v = struct.unpack_from("<I", data, c + off)[0]
        if 0 < v < len(data):
            hits.append((off, v))
    for off, v in hits[:40]:
        # 该值指向的地方是什么魔数？
        magic = data[v:v + 4]
        tag = ""
        if magic == CTL: tag = "<CTL>"
        elif magic == SPH: tag = "<SPH>"
        elif magic[:3] == b"BNS": tag = "<BNSH>"
        print("  ctl+0x%03X = %d (0x%X)  %s" % (off, v, v, tag))

    print("\n--- 控制段前 0x120 字节 ---")
    print(hexdump(data[c - 0x120:c], c - 0x120))

    # 找第一个 SPH
    sph = data.find(SPH)
    print("\n--- SPH 头 @0x%X ---" % sph)
    print(hexdump(data[sph:sph + 0x100], sph))

    # 统计：所有容器里 SPH 头之后 0x50 字节（Ryujinx 说的 0x50 字节 SPH 头）长什么样
    print("\n--- 第二个 SPH 头 ---")
    sph2 = data.find(SPH, sph + 4)
    if sph2 > 0:
        print(hexdump(data[sph2:sph2 + 0x100], sph2))

if __name__ == "__main__":
    main()
