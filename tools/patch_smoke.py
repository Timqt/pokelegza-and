# -*- coding: utf-8 -*-
"""smoke_test.py 修正与增强：
   1) 修 #41 次数解析的跨行吞并（[^|]* 会把下一行的 size=10004400 当成计数 ⇒ H2 误报）
   2) 新增健康项 H7「客机栈指针未跑飞」（sp 必须落在 [栈顶-size, 栈顶]）
   3) 新增健康项 H8「PC 采样器取到可信样本」（崩溃日志里有 pc#G）
   4) 报告里带上真实栈边界与 QueryMemory 记录
"""
import re, sys

P = r"D:\feiniukexinhome\Code\pokeLegza-and\app\tools\smoke_test.py"
s = open(P, encoding="utf-8").read()

# ---------------------------------------------------------------- 1) 跨行吞并
old = '    for mm in re.finditer(r"#41 按 id:([^|]*)", cg):'
new = ('    # ⚠ 原来的 [^|]* 会**跨行**吞掉后面的内容，把下一行的 "size=10004400"\n'
       '    #   （栈大小）当成 #41 的调用次数 ⇒ H2 误报成「1000 万次空转」。\n'
       '    #   必须同时排除换行：[^\n|]*\n'
       '    for mm in re.finditer(r"#41 按 id:([^\\n|]*)", cg):')
if old in s:
    s = s.replace(old, new, 1)
    print("[smoke] 修 #41 次数解析的跨行吞并")
else:
    print("!! 找不到 #41 解析行")

# ---------------------------------------------------------------- 2) 解析真实栈边界
old2 = '''    # #41 各 id 次数'''
new2 = '''    # 真实栈边界（崩溃处理器新加的）与 sp ⇒ 判断「栈指针是否跑飞」
    m_top = re.search(r"真实栈边界 top=([0-9a-f]+) size=([0-9a-f]+) sp=([0-9a-f]+)", cg)
    if m_top:
        top = int(m_top.group(1), 16)
        ssz = int(m_top.group(2), 16)
        sp2 = int(m_top.group(3), 16)
        info["stack_top"] = top
        info["stack_size"] = ssz
        info["sp_in_stack"] = (top - ssz) <= sp2 <= top
    # #41 各 id 次数'''
if old2 in s and '"sp_in_stack"' not in s:
    s = s.replace(old2, new2, 1)
    print("[smoke] 加「真实栈边界」解析")
else:
    print("!! 栈边界解析锚点问题")

# ---------------------------------------------------------------- 3) 健康项
old3 = '''    ("H6", "客机线程还在动（svc 计数在涨）",
     lambda lg, cg, cr: cr.get("guest_alive"),
     "PC 采样/看门狗仍在输出客机 PC"),
]'''
new3 = '''    ("H6", "客机线程还在动（svc 计数在涨）",
     lambda lg, cg, cr: cr.get("guest_alive"),
     "PC 采样/看门狗仍在输出客机 PC"),
    ("H7", "客机栈指针未跑飞",
     lambda lg, cg, cr: cr.get("sp_in_stack", True),
     "sp 必须落在 [栈顶-size, 栈顶]；跑飞 ⇒ 栈被破坏，后面必跳空"),
    ("H8", "PC 采样器取到可信样本",
     lambda lg, cg, cr: ("pc#G" in cg),
     "崩溃日志里应有 pc#G（落在 main/sdk 映像里的客机 PC）"),
]'''
if old3 in s:
    s = s.replace(old3, new3, 1)
    print("[smoke] 加健康项 H7/H8")
else:
    print("!! 找不到健康项列表尾")

# ---------------------------------------------------------------- 4) 报告补充
old4 = '''    if info.get("c41_max"):
        print(f"  #41 单 id 最大次数：{info['c41_max']}")'''
new4 = '''    if info.get("c41_max"):
        print(f"  #41 单 id 最大次数：{info['c41_max']}")
    if "stack_top" in info:
        print(f"  真实栈边界：top={info['stack_top']:#x} size={info['stack_size']:#x}"
              f"  sp 在栈内={info.get('sp_in_stack')}")
    qm = re.findall(r"svc#6 QueryMemory addr=(\\S+) -> base=(\\S+) size=(\\S+) state=(\\S+)", lg)
    for q in qm[:4]:
        print(f"  QueryMemory addr={q[0]} base={q[1]} size={q[2]} state={q[3]}")
    ret = re.findall(r"guest ret@\\+(\\S+) (\\S+)", gcb)
    if ret:
        print("  客机调用链：" + " ← ".join(f"{m}+{o}" for _, m, o in
                                        [(a, b, c) for a, b, c in ret]))'''
if old4 in s:
    s = s.replace(old4, new4, 1)
    print("[smoke] 报告加栈边界/QueryMemory/调用链")
else:
    print("!! 找不到报告打印锚点")

open(P, "w", encoding="utf-8", newline="\n").write(s)
print("done")
