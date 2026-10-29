#!/usr/bin/env python3
"""把运行时转储的「内建着色器」（<键>.code + <键>.ctl）翻译并打成 <键>.xgs。

为什么需要它：main NSO 里内嵌了一批图形着色器（各查询核、调试/后处理），它们不在
任何 bnsh 容器里，所以 tools/build_spv_map_all.py 的「容器 → 控制段键」索引覆盖不到。
引擎仍然会用它们的键来要包（真机实测 24 个），缺一个就是
`Missing genuine shader bundle`。

转储由 hle_nvn.c 的自检在「键缺失」时做：<键>.ctl 是引擎给的控制段（0x880 字节，
键就是它的 sha256 前 16 位），<键>.code 是从 NVNshaderData.data 读出的代码块，
里面**第一个** SPH 就是引擎要的那一份（后面的是同块里的其它着色器）。

用法：
    python tools/za_pack_builtin.py <转储目录> <输出目录> [--xlate <bnsh_xlate.dll>]
"""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
DOTNET_ROOT = ROOT / "work" / "dotnet" / "sdk"


def run_xlate(dll: Path, src_dir: Path, out_dir: Path) -> None:
    env = dict(os.environ)
    env.setdefault("DOTNET_ROOT", str(DOTNET_ROOT))
    subprocess.run([str(DOTNET_ROOT / "dotnet.exe"), str(dll), str(src_dir), str(out_dir)],
                   check=False, env=env, capture_output=True, text=True)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("dump_dir", type=Path)
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("--xlate", type=Path,
                    default=TOOLS / "bnsh_xlate" / "bin" / "Release" / "net10.0" / "bnsh_xlate.dll")
    args = ap.parse_args()

    keys = sorted(p.stem for p in args.dump_dir.glob("*.code"))
    if not keys:
        sys.exit("转储目录里没有 <键>.code")

    work = args.out_dir / "_work"
    pick = args.out_dir / "_pick"
    xout = args.out_dir / "_xlate"
    for d in (work, pick, xout):
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, exist_ok=True)

    ok = 0
    for key in keys:
        one = work / key
        one.mkdir(exist_ok=True)
        shutil.copyfile(args.dump_dir / (key + ".code"), one / (key + ".code"))
        run_xlate(args.xlate, one, xout)

    # 只取每个键的 SPH@0（引擎给 data 指向的那一份）
    picked = 0
    for key in keys:
        # 取**最小偏移**那个 SPH：引擎给的 data 指向代码块起点，起点上的那个 SPH
        # 才是它要的；有些块起点不是 0x0（实测 0a1eac07 的第一个 SPH 就不在 0）。
        # Take the SPH with the smallest offset.
        cands = []
        for spv in xout.rglob(key + "_*_*.spv"):
            parts = spv.stem.rsplit("_", 2)
            if len(parts) != 3 or parts[0] != key:
                continue
            try:
                cands.append((int(parts[1], 16), spv))
            except ValueError:
                continue
        best = min(cands, key=lambda x: x[0])[1] if cands else None
        if not best:
            continue
        res = best.with_suffix(".res.json")
        shutil.copyfile(best, pick / best.name)
        if res.exists():
            shutil.copyfile(res, pick / res.name)
        picked += 1
    print("键 %d 个，翻译出 SPH@0 的 %d 个" % (len(keys), picked))

    r = subprocess.run([sys.executable, str(TOOLS / "za_pack_xgs.py"), str(pick),
                        str(args.out_dir / "xgs"), "--flat"], text=True)
    for d in (work, pick, xout):
        shutil.rmtree(d, ignore_errors=True)
    if r.returncode == 0:
        ok = len(list((args.out_dir / "xgs").glob("*.xgs")))
    print("产出 %d 个 .xgs -> %s" % (ok, args.out_dir / "xgs"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
