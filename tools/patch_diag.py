# -*- coding: utf-8 -*-
"""诊断增强：
   1) za_log_stack 改成**从 sp 本身**开始 dump（原来总是从下一页开始，
      把当前帧整个跳过了 —— 保存 x30 的槽就在当前页里！）
   2) 打印**全部 31 个寄存器**（原来只打 x0..x7/x29/x30，漏了 x16/x17
      —— PLT 跳板的 ldr/br 就靠这两个寄存器）
"""
import sys

ROOT = r"D:\feiniukexinhome\Code\pokeLegza-and\app\native"
def rd(p):
    with open(p, "rb") as f: return f.read()
def wr(p, b):
    with open(p, "wb") as f: f.write(b)
def enc(s): return s.encode("utf-8")

gp = ROOT + r"\za_guest.c"
g = rd(gp)

# ---------------------------------------------------------------- 1) 从 sp 开始 dump
old = enc("""static void za_log_stack(unsigned long sp)
{
    // 起始地址：跳过保护页，从下一页开始
    unsigned long start = ((sp >> 12) + 1) << 12;
""")
new = enc("""static void za_log_stack(unsigned long sp)
{
    // ★ 2026-10-25 修正：原来**总是**从 sp 的下一页开始扫（为了绕开栈溢出的保护页），
    //   结果把**当前帧整个跳过了** —— 而保存 x30 的槽就在当前页里 ⇒
    //   「ret 跳空」这类问题根本看不到帧里的内容。
    //   现在：**先从 sp 本身 dump 64 个字**（当前帧），再从下一页往上扫。
    {
        char line[512];
        unsigned long w[8];
        for (int r = 0; r < 64; r += 8)
        {
            int ok = 1;
            for (int i = 0; i < 8; i++)
                if (!za_read_word(sp + (unsigned long)(r + i) * 8, &w[i])) ok = 0;
            if (!ok) break;
            char *p = line;
            p = za_put_str(p, "ZaGuest: frame+");
            p = za_put_hex(p, (unsigned long long)(r * 8));
            for (int i = 0; i < 8; i++)
            {
                p = za_put_str(p, " ");
                p = za_put_hex(p, (unsigned long long)w[i]);
            }
            p = za_put_str(p, "\\n");
            size_t len = (size_t)(p - line);
            ssize_t w2 = write(2, line, len);
            (void)w2;
            if (za_crash_fd >= 0) { ssize_t w3 = write(za_crash_fd, line, len); (void)w3; }
        }
    }
    // 起始地址：跳过保护页，从下一页开始
    unsigned long start = ((sp >> 12) + 1) << 12;
""")
if b"ZaGuest: frame+" not in g:
    assert old in g, "za_log_stack 锚点没找到"
    g = g.replace(old, new, 1)
    print("[guest] za_log_stack 增加「当前帧原始 dump」")

# ---------------------------------------------------------------- 2) 全部寄存器
# 找 za_log_regs 的定义
idx = g.find(b"static void za_log_regs")
if idx == -1:
    print("!! 找不到 za_log_regs"); sys.exit(1)
# 找到它的函数结束（下一个 "\n}\n"）
end = g.find(b"\n}\n", idx)
if end == -1:
    print("!! za_log_regs 结束没找到"); sys.exit(1)
end += 3

allregs = enc("""
// 打印**全部 31 个寄存器**（x16/x17 是 PLT 跳板的关键：ldr x17,[GOT]; br x17）
static void za_log_regs_all(const ucontext_t *uc)
{
    if (!uc) return;
    for (int i = 0; i < 31; i += 4)
    {
        char line[256];
        char *p = line;
        for (int k = 0; k < 4; k++)
        {
            int r = i + k;
            p = za_put_str(p, " x");
            p = za_put_hex(p, (unsigned long long)r);
            p = za_put_str(p, "=");
            p = za_put_hex(p, (unsigned long long)uc->uc_mcontext.regs[r]);
        }
        p = za_put_str(p, "\\n");
        size_t len = (size_t)(p - line);
        ssize_t w = write(2, line, len);
        (void)w;
        if (za_crash_fd >= 0) { ssize_t w2 = write(za_crash_fd, line, len); (void)w2; }
    }
}
""")
g = g[:end] + allregs + g[end:]
print("[guest] 加 za_log_regs_all")

# 在崩溃处理器里调用
old2 = enc("""        za_log_regs(uc);
""")
new2 = enc("""        za_log_regs(uc);
        za_log_regs_all(uc);
""")
if b"za_log_regs_all(uc);" not in g:
    assert old2 in g, "za_log_regs 调用点没找到"
    g = g.replace(old2, new2, 1)
    print("[guest] 崩溃处理器调用 za_log_regs_all")

wr(gp, g)
print("done")
