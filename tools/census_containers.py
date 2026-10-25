"""在**容器原始文件**（work/shaders_all）上普查 SPH，统计真/假。

判真伪：SPH+0x30 的阶段字 bits10..13 ∈ {1,5}（与 bnsh_all 上的普查口径一致，
因为真 SPH 的阶段字只有这两种取值，杂散字节落在这个范围的概率约 1/8）。
"""
import os, struct, collections, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "work", "shaders_all")
SPH = bytes.fromhex("78563412")

def main():
    tot = 0
    good = 0
    bad = 0
    badfiles = []
    stage = collections.Counter()
    files = sorted(f for f in os.listdir(SRC) if os.path.getsize(os.path.join(SRC, f)) > 64)
    for i, name in enumerate(files):
        p = os.path.join(SRC, name)
        data = open(p, "rb").read()
        pos = 0
        nb = 0
        while True:
            j = data.find(SPH, pos)
            if j < 0:
                break
            pos = j + 1
            tot += 1
            if j + 0x34 <= len(data):
                w = struct.unpack_from("<I", data, j + 0x30)[0]
                st = (w >> 10) & 0xF
            else:
                st = -1
            if st in (1, 5):
                good += 1
                stage[st] += 1
            else:
                bad += 1
                nb += 1
        if nb:
            badfiles.append((nb, name))
    print("容器文件 %d 个" % len(files))
    print("0x12345678 命中总数 : %d" % tot)
    print("  像 SPH（阶段∈{1,5}）: %d   其中 vs=%d ps=%d" % (good, stage[1], stage[5]))
    print("  不像 SPH（杂散字节）  : %d" % bad)
    badfiles.sort(reverse=True)
    if badfiles:
        print("  假 SPH 最多的容器：")
        for n, nm in badfiles[:12]:
            print("     %4d 个  %s" % (n, nm[:80]))

if __name__ == "__main__":
    main()
