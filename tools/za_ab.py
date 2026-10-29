#!/usr/bin/env python3
"""真机 A/B 跑测：按给定的开关组合跑一次 APK，抓 logcat，打印关键指标。

为什么单独写一个：这个工程的所有结论都只能在真机上验证（模拟器是 x86_64，
跑不了 arm64 的客机代码）。每次手动 am start + logcat -d + grep 容易漏项，
也容易把上一轮的日志混进来。这个脚本一次跑完并只打印结论行。

用法：
    python tools/za_ab.py                      # 基线（不带任何实验开关）
    python tools/za_ab.py takeover             # 分配器接管
    python tools/za_ab.py takeover quarantine  # 接管 + 大块不真释放
    python tools/za_ab.py nop-fill             # 跳过 wrapper 填充
    python tools/za_ab.py null-dangle kill-thread

开关名会映射到应用私有目录里的 files/za-<名> 标记文件；每次运行前先清掉全部
标记，再按参数逐个 touch，保证不同轮次互不污染。
"""
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PKG = "org.pokelegza.android.port"
DEV = os.environ.get("ZA_DEVICE", "SCXOHA8TCUN7RWJ7")
ACT = PKG + "/android.app.NativeActivity"
MARKS = ["takeover", "quarantine", "nop-fill", "null-dangle", "kill-thread",
         "lqgrow", "fakewake", "no-lqgrow", "no-nullrecover"]
LOG_DIR = ROOT / "work" / "device"
# ⚠ 必须用**绝对路径**：run-as 的 sh -c 经过 adb 再转一层引号后，相对路径
#   `files/za-x` 会创建失败而**不报错**（实测 22:0x 那几轮所谓「接管/隔离」
#   全是基线，free 计数为 0 就是这个原因）。建完再 ls 回读校验。
FILES = "/data/user/0/%s/files" % PKG


def adb(*args, **kw):
    env = dict(os.environ, MSYS_NO_PATHCONV="1")
    return subprocess.run(["adb", "-s", DEV] + list(args), capture_output=True,
                          text=True, env=env, **kw)


def run_as(shell_cmd):
    # ⚠ adb shell 会把参数用空格拼起来给**设备上的** shell，所以 `sh -c <cmd>`
    #   必须自己带引号，否则设备 shell 把 cmd 当成 $0，`sh -c` 只收到一个词。
    quoted = shell_cmd.replace("'", "'\\''")
    return adb("shell", "run-as %s sh -c '%s'" % (PKG, quoted))


def set_marks(active):
    for m in active:
        if m not in MARKS:
            sys.exit("未知开关: %s（可用：%s）" % (m, ", ".join(MARKS)))
    run_as("rm -f %s/za-* 2>/dev/null; echo ok" % FILES)
    for m in active:
        run_as("touch %s/za-%s" % (FILES, m))
    # 回读校验：开关没建上就干脆别跑，否则结论全是假的
    got = run_as("ls %s 2>/dev/null" % FILES).stdout or ""
    for m in active:
        if ("za-" + m) not in got:
            sys.exit("开关文件没建上：%s/za-%s（run-as 权限或路径问题）" % (FILES, m))


def main():
    active = [a for a in sys.argv[1:] if not a.startswith("-")]
    secs = 90
    for a in sys.argv[1:]:
        if a.startswith("--secs="):
            secs = int(a.split("=")[1])

    devs = adb("devices").stdout or ""
    if DEV not in devs:
        sys.exit("设备 %s 不在线；当前：\n%s" % (DEV, devs.strip()))

    set_marks(active)
    print("开关：%s，运行 %d 秒" % (", ".join(active) or "(基线)", secs), flush=True)
    adb("shell", "am", "force-stop", PKG)
    adb("logcat", "-c")
    adb("shell", "am", "start", "-n", ACT)
    time.sleep(secs)
    raw = adb("logcat", "-d").stdout or ""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    tag = "_".join(active) if active else "base"
    out = LOG_DIR / ("ab_%s.log" % tag)
    out.write_text(raw, encoding="utf-8", errors="replace")

    def count(pat):
        return len(re.findall(pat, raw))

    def last(pat):
        m = re.findall(pat, raw)
        return m[-1] if m else "-"

    alive = adb("shell", "pidof", PKG).stdout.strip()
    print("日志: %s（%d 行）" % (out, raw.count("\n")))
    print("进程: %s" % ("ALIVE pid=" + alive if alive else "DEAD"))
    print("纹理 %d 张 | 着色器命中 %s | 首帧崩点 %s"
          % (count(r"Texture 0x"), last(r"着色器自检累计：命中 (\d+)"),
             last(r"signal 0x[0-9a-f]+ pc=0x[0-9a-f]+ seg=\w+ off=0x[0-9a-f]+")))
    print("帧管线: %s" % last(r"★ 帧管线：.*"))
    print("降级: 悬空读 %d / 悬空写 %d / 野调用 %d / 首次坏读 %d"
          % (count(r"悬空读取→置0"), count(r"悬空写入→安全页"),
             count(r"野调用→按返回0"), count(r"首个坏读调用链")))
    if active and ("takeover" in active):
        print("分配器: free %d 次 / quarantine %d 次"
              % (count(r"\[free\]"), count(r"\[quarantine\]")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
