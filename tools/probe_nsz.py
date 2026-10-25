#!/usr/bin/env python3
"""探测一个 NSZ 更新包：列出 NCA、定位 Program、取出 ExeFS。

不打印任何密钥值（复用 d2r-and 的 extract_packages.run()，它会吞掉底层输出）。
用法: probe_nsz.py <nsz> <workdir>
"""
import re
import sys
from pathlib import Path

D2R = Path(r"D:\feiniukexinhome\Code\d2r-and")
sys.path.insert(0, str(D2R / "d2r-android" / "dm" / "android" / "tools"))
import extract_packages as ep  # noqa: E402

HACTOOL = D2R / "tools" / "hactool" / "bin" / "hactool.exe"
KEYS = D2R / "switch key" / "prod.keys"


def step(msg):
    print(msg, flush=True)


def main():
    nsz = Path(sys.argv[1])
    work = Path(sys.argv[2])
    work.mkdir(parents=True, exist_ok=True)

    keys = ep.minimal_keyset(KEYS, work / "keys")
    step(f"最小化密钥集: {keys}")

    ncas_dir = work / "ncas"
    ncas_dir.mkdir(parents=True, exist_ok=True)
    if not (ncas_dir / ".done").exists():
        step(f"解 NSZ（{nsz.stat().st_size/2**30:.2f} GiB）…")
        ep.run(HACTOOL, keys, ["-t", "nsz", "--outdir=" + str(ncas_dir)])
        (ncas_dir / ".done").touch()
    files = sorted(ncas_dir.glob("*"))
    step(f"NSZ 内 {len(files)} 个条目")
    for f in files:
        step(f"  {f.name}  {f.stat().st_size} 字节")

    tickets = list(ncas_dir.glob("*.tik"))
    step(f"票据: {[t.name for t in tickets] or '无'}")
    titlekey = ep.ticket_key(ncas_dir, keys)
    step(f"票据内标题密钥: {'取到' if titlekey else '无'}")

    step("逐个 NCA 读信息…")
    programs = []
    for f in ncas_dir.glob("*.nca"):
        try:
            info = ep.run(HACTOOL, keys, ["-t", "nca", f], titlekey)
        except RuntimeError as e:
            step(f"  {f.name}: 读取失败 ({e})")
            continue
        ctype = re.search(r"Content Type:\s*(.+)", info)
        tid = re.search(r"Title ID:\s*([0-9a-fA-F]+)", info)
        ver = re.search(r"Version:\s*(\d+)", info)
        size = re.search(r"Size:\s*(\d+)", info)
        step("  {n}: type={t} title={i} ver={v} size={s}".format(
            n=f.name, t=ctype.group(1).strip() if ctype else "?",
            i=tid.group(1) if tid else "?", v=ver.group(1) if ver else "?",
            s=size.group(1) if size else "?"))
        if ctype and "Program" in ctype.group(1):
            programs.append(f)

    step(f"Program NCA: {[p.name for p in programs]}")
    if not programs:
        step("没有 Program NCA")
        return

    out = work / "exefs"
    out.mkdir(parents=True, exist_ok=True)
    prog = programs[0]
    step(f"取 Program 的 ExeFS: {prog.name}")
    ep.run(HACTOOL, keys, ["-t", "nca", "--exefsdir=" + str(out)], prog, titlekey)
    for p in sorted(out.rglob("*")):
        if p.is_file():
            step(f"  ExeFS: {p.relative_to(out)}  {p.stat().st_size} 字节")


if __name__ == "__main__":
    main()
