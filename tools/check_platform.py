#!/usr/bin/env python3
"""判定任意 Switch / Switch 2 游戏包的运行平台（NX=Switch 1 / Ounce=Switch 2）。

依据：Program/Control NCA 头里的 SDK Version（= 游戏的 nnSdk 版本）。
  · SDK 19.x 及以下  -> Nintendo Switch (Tegra X1 / Maxwell)，着色器是 Maxwell 机器码
  · SDK 20.x 及以上  -> Nintendo Switch 2 (T239 / Ounce)，着色器是 Ounce ISA

用法：
  python check_platform.py <file.nsz|file.nsp|file.nca> [...]
只读，不改动任何游戏文件；不打印密钥值。
"""
import re
import struct
import subprocess
import sys
from pathlib import Path

D2R = Path(r"D:\feiniukexinhome\Code\d2r-and")
sys.path.insert(0, str(D2R / "d2r-android" / "dm" / "android" / "tools"))
import extract_packages as ep  # noqa: E402

HACTOOL = D2R / "tools" / "hactool" / "bin" / "hactool.exe"
KEYS = D2R / "switch key" / "prod.keys"
WORK = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work\platform-probe")

# nnSdk 20 起是 Switch 2（Ounce）世代
SWITCH2_SDK_MAJOR = 20


def hactool(keys, args, titlekey=None):
    cmd = [str(HACTOOL), "-k", str(keys), "--disablekeywarns", "--suppresskeys"]
    if titlekey:
        cmd.append("--titlekey=" + titlekey.hex())
    p = subprocess.run(cmd + [str(a) for a in args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.stdout.decode(errors="replace")


def pfs0_entries(path, outdir):
    outdir.mkdir(parents=True, exist_ok=True)
    txt = hactool(keys, ["-t", "pfs0", "--outdir=" + str(outdir), path])
    return list(outdir.iterdir()), txt


def report(path):
    print("=" * 78)
    print(f"文件: {path.name}")
    print(f"大小: {path.stat().st_size / 2**30:.2f} GiB")
    global keys
    work = WORK / re.sub(r"[^A-Za-z0-9._-]", "_", path.stem)[:60]
    keys = ep.minimal_keyset(KEYS, work / "keys")

    if path.suffix.lower() == ".nca":
        ncas = [path]
        tk = None
    else:
        entries, _ = pfs0_entries(path, work / "pfs0")
        ncas = [e for e in entries if e.suffix.lower() == ".nca"]
        tk = ep.ticket_key(work / "pfs0", keys)
        print(f"票据标题密钥: {'已取到' if tk else '未取到'}")
        print(f"NCA 条目: {len(ncas)} 个")

    found = False
    for nca in sorted(ncas):
        out = hactool(keys, ["-t", "nca", nca], tk)
        ctype = re.search(r"Content Type:\s*(\S+)", out)
        tid = re.search(r"Title ID:\s*([0-9a-fA-F]+)", out)
        sdk = re.search(r"SDK Version:\s*([\d.]+)", out)
        mkr = re.search(r"Master Key Revision:\s*(\S+)\s*\(([^)]*)\)", out)
        if not sdk:
            print(f"  [{nca.name}] 读取失败（可能需要该标题的密钥）")
            continue
        major = int(sdk.group(1).split(".")[0])
        plat = "Nintendo Switch 2 (T239/Ounce)" if major >= SWITCH2_SDK_MAJOR else "Nintendo Switch (Tegra X1/Maxwell)"
        kind = ctype.group(1) if ctype else "?"
        if kind == "Meta":
            # Meta NCA 的 SDK 字段是「打包工具」的 SDK 版本，不是游戏本体的。
            # 本机实测：D2R(Switch 1 游戏) 的 Meta NCA 同样是 22.2.0.0，而它的 Control NCA 是 11.4.4.0。
            print(f"  [Meta]  Title ID={tid.group(1) if tid else '?'}  SDK={sdk.group(1)}"
                  f"  MasterKeyRev={mkr.group(1) if mkr else '?'}")
            print(f"        -> Meta 的 SDK 是打包工具版本，**不作平台依据**（只认 Program/Control）")
        elif kind in ("Program", "Control"):
            print(f"  [{kind}] Title ID={tid.group(1) if tid else '?'}  SDK={sdk.group(1)}"
                  f"  MasterKeyRev={mkr.group(1) if mkr else '?'}")
            print(f"        -> 平台判定: {plat}")
            found = True
        elif kind == "Manual":
            # LegalInformation。更新包里的这一份通常沿用基础程序打包时的内容，
            # 所以它的 SDK = 「这个程序最初是拿哪个 nnSdk 打的」，可用来反推原平台。
            print(f"  [Manual/LegalInfo] Title ID={tid.group(1) if tid else '?'}  SDK={sdk.group(1)}")
            print(f"        -> 该内容通常沿用基础程序打包时的版本 => 原程序最初是 {plat} 构建")
        else:
            print(f"  [{kind}] Title ID={tid.group(1) if tid else '?'}  SDK={sdk.group(1)}")
    if not found:
        print("  !! 没读到 Program/Control NCA 的 SDK 版本")


def main():
    for a in sys.argv[1:]:
        p = Path(a)
        if not p.exists():
            print(f"!! 不存在: {p}")
            continue
        report(p)


if __name__ == "__main__":
    main()
