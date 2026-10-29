#!/usr/bin/env python3
"""把 bnsh_xlate 产出的 <名字>.spv + <名字>.res.json 打成 XGS1 着色器包 <ctl_sha16>.xgs。

为什么要这一层：引擎（dm 的 Vulkan 回放层）按 NVN 着色器**控制段**的键去
`files/shaders/<键>.xgs` 取包，而 bnsh_xlate 只能看到 BNSH 文件本身，不知道
容器里的控制段。控制段键的映射我们已经有（work/spv_map_final.tsv，由
tools/build_spv_map_all.py 产出），这里按「BNSH 起点 + SPH 偏移 = 容器相对偏移」
把两边对上。

链（与参考工程 dm/gfx/tools/dmsh_vk.py 相同，直接复用它的函数）：
    rewrite(绑定号 × 6 + 阶段号) → spirv-opt --trim-capabilities
    → add_format_caps(未定格式存储图像) → spirv-val → export(vk.json)
    → pack_game_shaders.pack → <键>.xgs

用法：
    python tools/za_pack_xgs.py <spv 目录> <输出目录> [--map work/spv_map_final.tsv]
                                 [--containers work/shaders_all] [--limit N]
"""
import argparse
import collections
import json
import os
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DM_TOOLS = ROOT / "app" / "native" / "dm" / "gfx" / "tools"

STAGE = {"Vertex": "vs", "Fragment": "ps", "Geometry": "gs", "Hull": "hs", "Domain": "ds", "Compute": "cs"}

DEFAULT_OPT = r"D:\feiniukexinhome\Code\d2r-and\build-tools-win\ndk28\android-ndk-r28c\shader-tools\windows-x86_64\spirv-opt.exe"
DEFAULT_VAL = r"D:\feiniukexinhome\Code\d2r-and\build-tools-win\ndk28\android-ndk-r28c\shader-tools\windows-x86_64\spirv-val.exe"



# ── 能力/扩展裁剪（替代 spirv-opt --trim-capabilities）──────────────────
# NDK 自带的 spirv-opt 没有这个开关（真机/构建机上实测 `Unknown flag`），而引擎
# xbg_game.cpp 的 validate_capabilities 是**白名单**：遇到没列进 switch 的能力
# （例如 Ryujinx 无条件声明的 Sampled1D=46 / Image1D=47）直接 xbg_fatalf。
# 这里按「真的用到了才保留」裁掉：指令里没有对应用法就删掉那条 OpCapability；
# OpExtension 一律删（引擎见到任何扩展都会 fatal）。
# Capability/extension trimming; the engine's validate_capabilities is a whitelist.
# Ryujinx always declares Sampled1D/Image1D and others; drop what the module does
# not actually use. OpExtension is always dropped (the engine rejects any).
def trim_caps(spv):
    w = list(struct.unpack("<%dI" % (len(spv) // 4), spv))
    # 先扫一遍，记录实际用法
    uses_group = uses_f64 = uses_img1d = uses_gather = False
    i = 5
    while i < len(w):
        n = w[i] >> 16
        if n == 0 or i + n > len(w):
            break
        op = w[i] & 0xFFFF
        if 333 <= op <= 366:
            uses_group = True
        elif op in (96, 97):                      # OpImageGather / OpImageDrefGather
            uses_gather = True
        elif op == 22 and n >= 3 and w[i + 2] == 64:   # OpTypeFloat 64
            uses_f64 = True
        elif op == 25 and n >= 9 and w[i + 3] == 1:    # OpTypeImage Dim = 1D
            uses_img1d = True
        i += n
    drop = set()
    if not uses_group:
        drop |= {61, 62, 63, 64, 65, 66}
    if not uses_f64:
        drop.add(10)
    if not uses_img1d:
        drop |= {46, 47}
    if not uses_gather:
        drop.add(25)
    out = w[:5]
    i = 5
    while i < len(w):
        n = w[i] >> 16
        if n == 0 or i + n > len(w):
            break
        op = w[i] & 0xFFFF
        if op == 10:                              # OpExtension：引擎一律拒绝
            i += n
            continue
        if op == 17 and n >= 2 and w[i + 1] in drop:   # OpCapability
            i += n
            continue
        out.extend(w[i:i + n])
        i += n
    return struct.pack("<%dI" % len(out), *out)

def load_core():
    """执行 dmsh_vk.py 的「主流程」之前那一段，拿到 rewrite/add_format_caps/export。

    那个文件的主流程写在模块层，直接 import 会立刻开始构建整个游戏；这里按标记
    截断后 exec，只取函数定义。
    """
    src = (DM_TOOLS / "dmsh_vk.py").read_text(encoding="utf-8")
    head = src.split("# ---- 主流程 ----")[0]
    ns = {"__name__": "dmsh_vk_core", "__file__": str(DM_TOOLS / "dmsh_vk.py")}
    old_argv = sys.argv
    # 头部的模块级代码要两个参数（dm_dir, out）并会读 nvn/shader_map.tsv；
    # 给无害的占位值，用完即还原。
    sys.argv = ["dmsh_vk_core", ".", "."]
    try:
        exec(compile(head, str(DM_TOOLS / "dmsh_vk.py"), "exec"), ns)
    finally:
        sys.argv = old_argv
    return ns


def load_packer():
    sys.path.insert(0, str(DM_TOOLS))
    import pack_game_shaders               # noqa: E402
    return pack_game_shaders


def bns_start_of(containers: Path) -> dict:
    """BNSH 在容器里的起点（容器文件名 → 偏移）。

    build_spv_map_all.py 里有同一套判断；这里只取「起点」这一步：容器若不是以
    BNSH 开头，就在容器里找第一个 BNSH 魔数。
    """
    out = {}
    if not containers.is_dir():
        return out
    for p in containers.iterdir():
        if not p.is_file() or p.stat().st_size <= 64:
            continue
        with open(p, "rb") as f:
            head = f.read(4)
            if head == b"BNSH":
                out[p.stem] = 0
                continue
            data = f.read()
        i = data.find(b"BNSH")
        # ⚠ 偏移要加回已读掉的 4 字节，否则每个容器都差 4（真机调试踩过：
        #  0x8000 被算成 0x7FFC，于是所有着色器都「没有控制段键」）。
        out[p.stem] = (4 + i) if i >= 0 else 0
    return out


def load_map(path: Path):
    """(容器 bnsh 名, 容器相对代码偏移, stage 小写) → ctl_sha16。"""
    key = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                continue
            c = line.rstrip("\n").split("\t")
            if len(c) < 3:
                continue
            ctl, stage, spv = c[0], c[1], c[2]
            name = Path(spv.replace("\\", "/")).name
            parts = name[:-4].rsplit("_", 2)      # <容器>_<码偏移:X8>_<stage>.spv
            if len(parts) != 3:
                continue
            key[(parts[0], int(parts[1], 16), stage.lower())] = ctl
    return key


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("spv_dir", type=Path)
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("--map", type=Path, default=ROOT / "work" / "spv_map_final.tsv")
    ap.add_argument("--containers", type=Path, default=ROOT / "work" / "shaders_all")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--keep-temp", action="store_true")
    args = ap.parse_args()

    opt = os.environ.get("SPIRV_OPT", DEFAULT_OPT)
    val = os.environ.get("SPIRV_VAL", DEFAULT_VAL)
    core = load_core()
    packer = load_packer()
    rewrite, add_format_caps, export = core["rewrite"], core["add_format_caps"], core["export"]

    keys = load_map(args.map)
    starts = bns_start_of(args.containers)
    print("映射 %d 条，容器起点 %d 个" % (len(keys), len(starts)))

    args.out_dir.mkdir(parents=True, exist_ok=True)
    tmp = args.out_dir / "_tmp"
    tmp.mkdir(exist_ok=True)

    stats = collections.Counter()
    reasons = collections.Counter()
    done = 0
    skipped = []
    for spv_path in sorted(args.spv_dir.rglob("*.spv")):
        if spv_path.with_suffix(".res.json").exists() is False:
            stats["缺 res.json"] += 1
            continue
        name = spv_path.stem
        parts = name.rsplit("_", 2)
        if len(parts) != 3:
            stats["名字不合规"] += 1
            continue
        bnsh, sph_s, stage_c = parts
        try:
            sph = int(sph_s, 16)
        except ValueError:
            stats["名字不合规"] += 1
            continue
        stage = STAGE.get(stage_c)
        if stage is None:
            stats["未知阶段"] += 1
            continue
        b0 = starts.get(bnsh)
        if b0 is None:
            stats["没有该容器"] += 1
            skipped.append(name)
            continue
        ctl = keys.get((bnsh, b0 + sph, stage_c.lower()))
        if ctl is None:
            stats["没有控制段键"] += 1
            skipped.append(name)
            continue
        if args.limit and done >= args.limit:
            break

        res = json.loads(spv_path.with_suffix(".res.json").read_text(encoding="utf-8"))
        con = res.get("stage")
        if con and STAGE.get(con, stage) != stage:
            stage = STAGE.get(con, stage)

        spv = rewrite(spv_path.read_bytes(), stage)
        spv = trim_caps(spv)
        spv = add_format_caps(spv)
        f1 = tmp / (ctl + ".r.spv")
        f2 = tmp / (ctl + ".t.spv")
        f2.write_bytes(spv)
        r = subprocess.run([val, "--target-env", "vulkan1.1", str(f2)],
                           capture_output=True, text=True)
        if r.returncode:
            stats["spirv-val 失败"] += 1
            reasons[r.stderr.strip().splitlines()[0][:120] if r.stderr.strip() else "?"] += 1
            continue
        try:
            vk = export(ctl, stage, b"", spv, res)
            out, data = packer.pack_bundle(vk, spv) if hasattr(packer, "pack_bundle") else (None, None)
        except (ValueError, KeyError) as e:
            stats["导出失败"] += 1
            reasons[str(e)[:120]] += 1
            continue
        if out is None:
            # 走参考工程的路径：先写 vk.json 再让 pack() 读
            vk_path = tmp / (ctl + ".vk.json")
            vk_path.write_text(json.dumps(vk, ensure_ascii=False), encoding="utf-8")
            # pack() 会去 vk.json 旁边读同名 .spv 并校验 sha256
            (tmp / (ctl + ".spv")).write_bytes(spv)
            try:
                out, data = packer.pack(vk_path)
            except (ValueError, KeyError) as e:
                stats["打包失败"] += 1
                reasons[str(e)[:120]] += 1
                continue
        (args.out_dir / (out + ".xgs")).write_bytes(data)
        stats["ok"] += 1
        done += 1

    if not args.keep_temp:
        for f in tmp.glob("*"):
            f.unlink()
        tmp.rmdir()
    print("结果：" + "，".join("%s %d" % (k, v) for k, v in stats.most_common()))
    for why, n in reasons.most_common(8):
        print("  [失败] %5d  %s" % (n, why))
    if skipped and len(skipped) <= 8:
        print("  未配对：", ", ".join(skipped))
    return 0 if stats["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
