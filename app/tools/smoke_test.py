#!/usr/bin/env python3
"""宝可梦 Z-A 移植版：每轮迭代都跑的自动化冒烟测试 + 里程碑检查清单。

为什么要有这个：移植已经迭代了很多轮，每轮都在用一次性 adb 命令做诊断，
下一轮接手的人（或下一轮的自己）根本不知道「现在跑到哪一步、卡在哪」。
⇒ 这个脚本把「装 → 跑 → 收现场 → 对检查清单 → 存快照」固化成一条命令。

用法:
    python app/tools/smoke_test.py                # 装 + 跑 + 检查 + 存档
    python app/tools/smoke_test.py --no-install   # 不重装（用已装的）
    python app/tools/smoke_test.py --seconds 30   # 跑多久
    python app/tools/smoke_test.py --serial SCXOHA8TCUN7RWJ7

产物:
    work/smoke/report-<时间戳>.md    本轮的人读报告
    work/smoke/history.jsonl         历轮机器读历史（一行一轮）
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PKG = "org.pokelegza.android.port"
APK = os.path.join(ROOT, "app", "build", "PokemonZA-Android-port.apk")
OUTDIR = os.path.join(ROOT, "work", "smoke")
# 平板（真机）优先；模拟器不要
PREFERRED = ("turner", "25079RPDCC")


def sh(args, timeout=60):
    try:
        p = subprocess.run(args, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return p.stdout or ""
    except Exception as e:                                    # noqa: BLE001
        return ""


def adb(serial, *args, timeout=60):
    return sh(["adb", "-s", serial] + list(args), timeout=timeout)


def pick_device():
    out = sh(["adb", "devices", "-l"], timeout=20)
    cands = []
    for line in out.splitlines():
        line = line.strip()
        if not line or "\tdevice" not in line and " device " not in line:
            continue
        m = re.match(r"^(\S+)\s+device\b", line)
        if not m:
            continue
        serial = m.group(1)
        if serial.startswith("emulator-"):
            continue
        model = ""
        mm = re.search(r"model:(\S+)", line)
        if mm:
            model = mm.group(1)
        cands.append((serial, model))
    for s, model in cands:
        if any(p.lower() in (model or "").lower() for p in PREFERRED):
            return s
    return cands[0][0] if cands else None


# ---------------------------------------------------------------- fs 打开的文件
# 客机静态构造函数会调 nn::fs::OpenFile。我们的 fs 垫片对每个路径都会打一行：
#   ★ fs::OpenFile out=… path="…" mode=… ⇒ 内嵌文件（… 字节…）
#   ★ fs::OpenFile out=… path="…" mode=… ⇒ 未知文件，返回空文件（假句柄 1）
# 下一轮只要跑一次，就能从报告里看到它到底开了哪些文件、哪些命中了内嵌数据。
FS_OPEN_RE = re.compile(r'★ fs::OpenFile.*?path="([^"]*)".*?⇒\s*(内嵌文件|未知文件)')


def fs_open_summary(lg):
    from collections import Counter
    c = Counter()
    for m in FS_OPEN_RE.finditer(lg or ""):
        c[(m.group(1), m.group(2))] += 1
    return c


# ---------------------------------------------------------------- 检查清单
# 每一项： (编号, 标题, 判定函数(logcat文本, 崩溃文本, 崩溃信息dict) -> bool, 说明)
MILESTONES = [
    ("M1", "SDK 映像装载完成",
     lambda lg, cg, cr: "SDK 装载: 基址=" in lg,
     "za_sdk_load 成功（基址 0x200000000）"),
    ("M2", "客机地址空间就绪",
     lambda lg, cg, cr: "客机地址空间：ASLR=" in lg,
     "ASLR/alias/stack/heap 四块区域已预留"),
    ("M3", "进入 nn::init::Start",
     lambda lg, cg, cr: "里程碑 M3" in lg,
     "我们扮演 nnrtld 调 SDK 的 nn::init::Start"),
    ("M4", "nninitStartup 已执行完",
     lambda lg, cg, cr: "里程碑 M4" in lg,
     "回调B 开始 ⇒ SDK 内部已跑完 nninitStartup"),
    ("M5", "SetHostArgc/Argv 已设置",
     lambda lg, cg, cr: "里程碑 M5" in lg,
     "进程参数已交给 SDK ⇒ 下一步进 nnMain"),
    ("M6", "nn::init::Start 返回",
     lambda lg, cg, cr: "里程碑 M6" in lg,
     "nnMain 已跑完/退出"),
]

HEALTH = [
    ("H1", "客机线程栈未溢出",
     lambda lg, cg, cr: not cr.get("stack_overflow"),
     "崩溃时 sp 落在栈保护页 = 无限递归/爆栈"),
    ("H2", "#41 GetInfo 调用次数正常",
     lambda lg, cg, cr: cr.get("c41_max", 0) <= 200,
     "几十次 = 正常；上百万 = SDK 在空区间上空转"),
    ("H3", "无「undefined symbol」",
     lambda lg, cg, cr: "undefined symbol" not in lg and "undefined symbol" not in cg,
     "nnrtld/SDK 的符号解析失败"),
    ("H4", "关键 TLS 指令补丁已生效",
     lambda lg, cg, cr: cr.get("tls_patched"),
     "0x144618 应是 adrp（不是 mrs TPIDRRO_EL0）、0x144620 应是 nop（不是 msr TPIDR_EL0）"),
    ("H5", "进程在跑（未崩）",
     lambda lg, cg, cr: cr.get("alive"),
     "app 进程仍然存活"),
    ("H6", "客机线程还在动（svc 计数在涨）",
     lambda lg, cg, cr: cr.get("guest_alive"),
     "PC 采样/看门狗仍在输出客机 PC"),
    ("H7", "客机栈指针未跑飞",
     lambda lg, cg, cr: cr.get("sp_in_stack", True),
     "sp 必须落在 [栈顶-size, 栈顶]；跑飞 ⇒ 栈被破坏，后面必跳空"),
    ("H8", "PC 采样器取到可信样本",
     lambda lg, cg, cr: ("pc#G" in cg),
     "崩溃日志里应有 pc#G（落在 main/sdk 映像里的客机 PC）"),
]


def parse_crash(cg, lg=""):
    """从崩溃日志（+ logcat 里的指令探针）抽关键信息。"""
    info = {"stack_overflow": False, "c41_max": 0, "tls_patched": False,
            "alive": False, "guest_alive": False}
    # sp 与栈边界
    m_sp = re.search(r"sp=([0-9a-f]+)", cg)
    m_lo = re.search(r"栈\[guest\] 低=([0-9a-f]+) 高=([0-9a-f]+)", cg)
    if m_sp and m_lo:
        sp = int(m_sp.group(1), 16)
        lo = int(m_lo.group(1), 16)
        # sp 落在保护页 = 低于栈底 0x30 左右
        if sp < lo and (lo - sp) < 0x1000:
            info["stack_overflow"] = True
        info["sp_vs_lo"] = sp - lo
    # 真实栈边界（崩溃处理器新加的）与 sp ⇒ 判断「栈指针是否跑飞」
    m_top = re.search(r"真实栈边界 top=([0-9a-f]+) size=([0-9a-f]+) sp=([0-9a-f]+)", cg)
    if m_top:
        top = int(m_top.group(1), 16)
        ssz = int(m_top.group(2), 16)
        sp2 = int(m_top.group(3), 16)
        info["stack_top"] = top
        info["stack_size"] = ssz
        info["sp_in_stack"] = (top - ssz) <= sp2 <= top
    # #41 各 id 次数
    # ⚠ 原来的 [^|]* 会**跨行**吞掉后面的内容，把下一行的 "size=10004400"
    #   （栈大小）当成 #41 的调用次数 ⇒ H2 误报成「1000 万次空转」。
    #   必须同时排除换行（用 [^\n|]*）
    for mm in re.finditer(r"#41 按 id:([^\n|]*)", cg):
        for part in mm.group(1).split():
            mm2 = re.match(r"(\w+)=(\d+)", part)
            if mm2:
                try:
                    info["c41_max"] = max(info["c41_max"], int(mm2.group(2)))
                except ValueError:
                    pass
    # TLS 指令补丁：**探针输出走日志文件/logcat**（不在崩溃日志里）
    # ⚠ 数值带 "0x" 前缀 ⇒ 正则必须把 0x 一起吃掉，否则只匹配到 "0"。
    m618 = re.search(r"code\[0x144618\] = (0x[0-9a-f]+)", lg)
    m620 = re.search(r"code\[0x144620\] = (0x[0-9a-f]+)", lg)
    if m618 and m620:
        v618 = int(m618.group(1), 16)
        v620 = int(m620.group(1), 16)
        info["probe_144618"] = v618
        info["probe_144620"] = v620
        # 0x144618 应是 adrp（0x90......）；0x144620 应是 nop（0xD503201F）
        info["tls_patched"] = (v618 & 0x9F000000) == 0x90000000 and v620 == 0xD503201F
    return info


def guest_crash_block(cg):
    """崩溃日志里有多次崩溃（渲染线程 + 客机线程）⇒ 取客机那一次
    （即最后一次「线程 tid=...」之后的内容）。"""
    idx = cg.rfind("线程 tid=")
    if idx < 0:
        return cg
    return cg[idx:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--serial", default=None)
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--no-install", action="store_true")
    ap.add_argument("--tag", default="ZaGuest:PokemonZA")
    args = ap.parse_args()

    serial = args.serial or pick_device()
    if not serial:
        print("✗ 没找到设备（adb devices 里没有非模拟器设备）")
        return 2
    print(f"设备: {serial}")

    if not args.no_install:
        if not os.path.exists(APK):
            print(f"✗ APK 不存在: {APK}")
            return 2
        r = sh(["adb", "-s", serial, "install", "-r", APK], timeout=300)
        if "Success" not in r:
            print("✗ 安装失败:\n" + r)
            return 2
        print("✓ 安装成功")

    adb(serial, "shell", "svc", "power", "stayon", "true")
    adb(serial, "shell", "input", "keyevent", "KEYCODE_WAKEUP")
    adb(serial, "shell", "wm", "dismiss-keyguard")
    adb(serial, "shell", "am", "force-stop", PKG)
    adb(serial, "logcat", "-c")
    # ★ 上一轮的日志留档，本轮从空文件开始（这样每轮的文件就是本轮的现场）
    adb(serial, "shell", "run-as", PKG, "rm", "-f", "files/za_log.txt")
    adb(serial, "shell", "run-as", PKG, "rm", "-f", "files/za_crash.log")
    # ⚠ za_fatal.log 是 append 打开的：不删就会把**上一轮**的现场当成这一轮的
    #   （踩过：连续几轮都在读同一个旧崩溃现场，白追半天）。
    adb(serial, "shell", "run-as", PKG, "rm", "-f", "files/za_fatal.log")
    time.sleep(1)
    adb(serial, "shell", "am", "start", "-n", f"{PKG}/android.app.NativeActivity")
    print(f"运行 {args.seconds}s …")
    time.sleep(args.seconds)

    # ⚠ logcat 会被系统日志刷掉 ⇒ 以**设备上的日志文件**为主，logcat 只作补充。
    lg = adb(serial, "shell", "run-as", PKG, "cat", "files/za_log.txt", timeout=30)
    lcat = adb(serial, "logcat", "-d", "-s", "ZaGuest:V", "-s", "PokemonZA:V", timeout=60)
    if not lg.strip():
        lg = lcat
    else:
        lg = lg + "\n" + lcat
    cg = adb(serial, "shell", "run-as", PKG, "cat", "files/za_crash.log", timeout=30)
    # ⚠ 客机线程崩溃的**真正现场**写在 za_fatal.log（za_crash.log 是给渲染线程那次用的，
    #   客机崩溃时它是 0 字节）⇒ 只收 za_crash.log 会让报告里「崩溃点」永远为空。
    fg = adb(serial, "shell", "run-as", PKG, "cat", "files/za_fatal.log", timeout=30)
    if fg.strip():
        cg = (cg + "\n" + fg) if cg.strip() else fg
    ei = adb(serial, "shell", "dumpsys", "activity", "exit-info", PKG, timeout=60)
    pid = (adb(serial, "shell", "pidof", PKG) or "").strip()

    info = parse_crash(cg, lg)
    gcb = guest_crash_block(cg)   # 只取客机线程那次崩溃
    info["alive"] = bool(pid)
    # 客机线程还在动：看门狗最近是否还在报客机 PC
    pcs = re.findall(r"客机 PC=", lg)
    info["guest_alive"] = len(pcs) >= 2

    # ---------------- 判定 ----------------
    rows = []
    for code, title, fn, note in MILESTONES:
        rows.append((code, title, "里程碑", bool(fn(lg, cg, info)), note))
    for code, title, fn, note in HEALTH:
        rows.append((code, title, "健康", bool(fn(lg, cg, info)), note))

    reached = [r for r in rows if r[0].startswith("M") and r[3]]
    blocking = reached[-1][1] if reached else "（连 SDK 装载都没到）"

    print()
    print("=" * 74)
    print("宝可梦 Z-A 移植：迭代检查清单")
    print("=" * 74)
    for code, title, kind, ok, note in rows:
        print(f"  {'✅' if ok else '❌'} {code}  {title:<26} {note}")
    print("-" * 74)
    print(f"  当前到达：{blocking}")
    m = re.search(r"signal b pc=([0-9a-f]+).*?addr=([0-9a-f]+)", gcb)
    if m:
        print(f"  崩溃点：pc={m.group(1)}  fault={m.group(2)}")
    m2 = re.search(r"regs (x0=.*)", gcb)
    if m2:
        print(f"  寄存器：{m2.group(1)[:110]}")
    tail = re.findall(r"#41\[\w+\] id=(\w+) @(\S+)", gcb)
    if tail:
        print("  最后几次 #41：" + "  ".join(f"id={a}@{b}" for a, b in tail[-6:]))
    if "probe_144618" in info:
        print(f"  指令探针：0x144618={info.get('probe_144618'):#x}（应为 adrp 0x90xxxxxx）"
              f"  0x144620={info.get('probe_144620'):#x}（应为 nop 0xd503201f）")
    if info.get("c41_max"):
        print(f"  #41 单 id 最大次数：{info['c41_max']}")
    if "stack_top" in info:
        print(f"  真实栈边界：top={info['stack_top']:#x} size={info['stack_size']:#x}"
              f"  sp 在栈内={info.get('sp_in_stack')}")
    qm = re.findall(r"svc#6 QueryMemory addr=(\S+) -> base=(\S+) size=(\S+) state=(\S+)", lg)
    for q in qm[:4]:
        print(f"  QueryMemory addr={q[0]} base={q[1]} size={q[2]} state={q[3]}")
    fs_sum = fs_open_summary(lg)
    if fs_sum:
        print("  fs 打开的文件：")
        for (path, kind), n in fs_sum.most_common(12):
            print(f"    [{kind}] {path} ×{n}")
    ret = re.findall(r"guest ret@\+(\S+) (\S+)", gcb)
    if ret:
        print("  客机调用链：" + " ← ".join(f"{m}+{o}" for o, m in ret))
    print("=" * 74)

    # ---------------- 存档 ----------------
    os.makedirs(OUTDIR, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    md = os.path.join(OUTDIR, f"report-{ts}.md")
    with open(md, "w", encoding="utf-8") as f:
        f.write(f"# 冒烟测试 {ts}  设备 {serial}\n\n")
        f.write(f"- 进程存活：{'是' if info['alive'] else '否（pid=' + (pid or '空') + '）'}\n")
        f.write(f"- 当前到达：{blocking}\n")
        f.write(f"- #41 单 id 最大次数：{info.get('c41_max')}\n\n")
        f.write("| 项 | 类型 | 结论 | 说明 |\n|---|---|---|---|\n")
        for code, title, kind, ok, note in rows:
            f.write(f"| {code} {title} | {kind} | {'✅ 通过' if ok else '❌ 未通过'} | {note} |\n")
        f.write("\n## 崩溃日志\n\n```\n" + cg[:4000] + "\n```\n")
        f.write("\n## 关键日志尾部\n\n```\n" + "\n".join(lg.splitlines()[-120:]) + "\n```\n")
    hist = os.path.join(OUTDIR, "history.jsonl")
    with open(hist, "a", encoding="utf-8") as f:
        f.write(json.dumps({
            "ts": ts, "serial": serial,
            "alive": info["alive"],
            "blocking": blocking,
            "c41_max": info.get("c41_max"),
            "stack_overflow": info.get("stack_overflow"),
            "tls_patched": info.get("tls_patched"),
            "fs_open": [{"path": p, "kind": k, "n": n} for (p, k), n in fs_sum.most_common(20)],
            "milestones": {c: ok for c, t, k, ok, n in rows if c.startswith("M")},
            "health": {c: ok for c, t, k, ok, n in rows if c.startswith("H")},
            "report": os.path.relpath(md, ROOT).replace("\\", "/"),
        }, ensure_ascii=False) + "\n")
    print(f"  报告：{os.path.relpath(md, ROOT)}")
    print(f"  历史：{os.path.relpath(hist, ROOT)}")
    return 0 if all(r[3] for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main())
