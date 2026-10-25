"""读 D2R 的 job JSON + 它引用的机器码文件，确认 D2R 喂给 Ryujinx 的代码段到底是什么布局。"""
import json, os, struct, sys

WORK = r"D:\feiniukexinhome\Code\d2r-and\pack-workspace\produce\shaders\work"
jobs = json.load(open(os.path.join(WORK, "jobs.json"), encoding="utf-8"))
print("job 条数 =", len(jobs))
print("job 字段 =", sorted(jobs[0].keys()))

by_stage = {}
for j in jobs:
    by_stage.setdefault(j.get("stage"), []).append(j)
for st, arr in by_stage.items():
    print("  stage=%s: %d 条" % (st, len(arr)))

SPH = bytes.fromhex("78563412")
for st in sorted(by_stage):
    for j in by_stage[st][:2]:
        code = j.get("code")
        if not code or not os.path.exists(code):
            print("  [%s] %s: 代码文件不存在 %s" % (st, j.get("key"), code)); continue
        d = open(code, "rb").read()
        w30 = struct.unpack_from("<I", d, 0x30)[0] if len(d) >= 0x34 else 0
        print("  [%s] %s" % (st, j.get("key")))
        print("      文件 %s  %d 字节" % (os.path.basename(code), len(d)))
        print("      前 0x50: " + " ".join("%02x" % b for b in d[:0x50]))
        print("      code+0x30 = 0x%08X -> 阶段(位10..13)=%d  魔数在 code+0? %s" % (w30, (w30 >> 10) & 0xF, d[:4] == SPH))
        print("      job 其他键: " + ", ".join("%s=%s" % (k, str(v)[:80]) for k, v in j.items() if k not in ("code",)))
