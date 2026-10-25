#!/usr/bin/env python3
"""把 NSZ 里的 Program NCA 解出来并取出 ExeFS。

NSZ = PFS0(NCZ*)；NCZ 的 NCA 头仍是加密的，必须带票据里的 titlekey 才能读节表。
不打印任何密钥值。
"""
import re
import subprocess
import sys
from pathlib import Path

D2R = Path(r"D:\feiniukexinhome\Code\d2r-and")
sys.path.insert(0, str(D2R / "d2r-android" / "dm" / "android" / "tools"))
import extract_packages as ep  # noqa: E402

HACTOOL = D2R / "tools" / "hactool" / "bin" / "hactool.exe"
WORK = Path(r"D:\feiniukexinhome\Code\pokeLegza-and\work")
NCAS = WORK / "ncas"
KEYS = WORK / "keys" / "private" / "hactool.keys"


def raw(args, titlekey=None):
    cmd = [str(HACTOOL), "-k", str(KEYS), "--disablekeywarns", "--suppresskeys"]
    if titlekey:
        cmd.append("--titlekey=" + titlekey.hex())
    p = subprocess.run(cmd + [str(a) for a in args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode(errors="replace")


def step(m):
    print(m, flush=True)


def main():
    tk = ep.ticket_key(NCAS, KEYS)
    step(f"titlekey: {'OK' if tk else 'NONE'}")
    ncz = NCAS / "4a70b3ff963bfe412681185cea68bf55.ncz"

    nca = NCAS / "4a70b3ff963bfe412681185cea68bf55.nca"
    if not nca.exists():
        step("NCZ -> NCA ...")
        rc, out = raw(["-t", "ncz", "--outdir=" + str(NCAS)], tk)
        step(f"rc={rc}")
        for line in out.splitlines():
            if "Error" in line or "Failed" in line or "Invalid" in line:
                step("  ! " + line)
    step(f"nca exists: {nca.exists()}  size={nca.stat().st_size if nca.exists() else 0}")

    rc, out = raw(["-t", "nca", nca], tk)
    for line in out.splitlines():
        if re.search(r"(Title ID|Content Type|Version|Size|Required|NCA Size|Fragment|Hash|Key)", line):
            step("  " + line.strip())

    exefs = WORK / "exefs"
    exefs.mkdir(parents=True, exist_ok=True)
    step("ExeFS ...")
    rc, out = raw(["-t", "nca", "--exefsdir=" + str(exefs), nca], tk)
    for line in out.splitlines():
        if "Error" in line or "Failed" in line:
            step("  ! " + line)
    for p in sorted(exefs.rglob("*")):
        if p.is_file():
            step(f"  ExeFS {p.name}  {p.stat().st_size} 字节")


if __name__ == "__main__":
    main()
