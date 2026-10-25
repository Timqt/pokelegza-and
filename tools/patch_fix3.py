# -*- coding: utf-8 -*-
"""三合一修复：
   1) trampoline 寄存器回写 off-by-one（x1 应取 regs[1]，原来取 regs[0]）
   2) svc #6 QueryMemory 记录「查询地址 + 返回的 MemoryInfo」
   3) 真正的客机栈回溯：扫出栈上所有指向 main/sdk 映像的字（= 返回地址）
"""
import sys

ROOT = r"D:\feiniukexinhome\Code\pokeLegza-and\app\native"
def rd(p):
    with open(p, "rb") as f: return f.read()
def wr(p, b):
    with open(p, "wb") as f: f.write(b)
def enc(s): return s.encode("utf-8")

# ================================================================== 1) trampoline
sp = ROOT + r"\za_horizon_tramp.S"
s = rd(sp)
old = enc("""    ldp  x1, x2, [x16]
    ldp  x3, x4, [x16, #16]
    ldp  x5, x6, [x16, #32]
    ldr  x7, [x16, #48]
""")
new = enc("""    // NOTE: za_horizon_regs[] layout: [0]=x0(result) [1..7]=x1..x7 [8]=pc [9]=sp
    // x0 comes from the C return value, so write back x1..x7 from regs[1..7].
    // (Was reading regs[0..6] -- off by one -- so the guest's x1 got a stale
    //  value instead of the Horizon out-parameter in regs[1].)
    ldp  x1, x2, [x16, #8]
    ldp  x3, x4, [x16, #24]
    ldp  x5, x6, [x16, #40]
    ldr  x7, [x16, #56]
""")
if b"regs[1..7]" not in s:
    assert old in s, "trampoline 回写块没找到"
    s = s.replace(old, new, 1)
    wr(sp, s)
    print("[tramp] 修正寄存器回写 off-by-one")
else:
    print("[tramp] 已修正")

# ================================================================== 2) svc#6 日志
hp = ROOT + r"\za_horizon.c"
h = rd(hp)
old2 = enc("""        unsigned long long mi[5];
        mi[0] = mi[1] = 0;
        unsigned long long pageinfo = za_mem_query_memory((unsigned long long)a2, mi);
        if (a0) memcpy((void *)(uintptr_t)a0, mi, 0x24);
""")
new2 = enc("""        unsigned long long mi[5];
        mi[0] = mi[1] = 0;
        unsigned long long pageinfo = za_mem_query_memory((unsigned long long)a2, mi);
        if (a0) memcpy((void *)(uintptr_t)a0, mi, 0x24);
        // 记录每次 QueryMemory 的查询地址与结果 —— 客机拿到的 MemoryInfo 一旦不对，
        // 后面用它的 base/size 去建对象就会跳空（pc=0），这里是最直接的证据。
        {
            static unsigned qn;
            if (qn < 40)
            {
                qn++;
                ZLOGI("svc#6 QueryMemory addr=%#llx -> base=%#llx size=%#llx state=%#x perm=%#x "
                      "(out=%p)",
                      (unsigned long long)a2, mi[0], mi[1],
                      ((unsigned int *)mi)[4], ((unsigned int *)mi)[6], (void *)(uintptr_t)a0);
            }
        }
""")
if b"svc#6 QueryMemory addr=" not in h:
    assert old2 in h, "svc#6 块没找到"
    h = h.replace(old2, new2, 1)
    wr(hp, h)
    print("[horizon] svc#6 加 MemoryInfo 日志")

# ================================================================== 3) 客机栈回溯
gp = ROOT + r"\za_guest.c"
g = rd(gp)
if b"guest ret@" not in g:
    # 插到 za_log_stack 之前
    anchor = enc("static void za_log_stack(unsigned long sp)\n{\n")
    assert anchor in g, "za_log_stack 没找到"
    fn = enc("""// 真正的客机栈回溯：把栈上所有指向 main/sdk 映像的字找出来（= 返回地址）。
// 按「地址由高到低」排，就是从最内层到最外层的调用链。
static void za_log_guest_trace(unsigned long sp)
{
    unsigned long base_main = za_guest_main_base;
    unsigned long size_main = ZA_IMAGE_SIZE;
    unsigned long base_sdk = za_sdk_base;
    unsigned long size_sdk = za_sdk_size;
    char line[256];
    int found = 0;
    for (int i = 0; i < 512; i++)      // 4KB
    {
        unsigned long w = 0;
        if (!za_read_word(sp + (unsigned long)i * 8, &w)) break;
        const char *mod = NULL;
        unsigned long off = 0;
        if (base_main && w >= base_main && w < base_main + size_main)
        {
            mod = "main"; off = w - base_main;
        }
        else if (base_sdk && w >= base_sdk && w < base_sdk + size_sdk)
        {
            mod = "sdk"; off = w - base_sdk;
        }
        if (!mod) continue;
        found++;
        char *p = line;
        p = za_put_str(p, "ZaGuest: guest ret@+");
        p = za_put_hex(p, (unsigned long long)((unsigned long)i * 8));
        p = za_put_str(p, " ");
        p = za_put_str(p, mod);
        p = za_put_str(p, "+");
        p = za_put_hex(p, (unsigned long long)off);
        p = za_put_str(p, "\\n");
        size_t len = (size_t)(p - line);
        ssize_t wr2 = write(2, line, len);
        (void)wr2;
        if (za_crash_fd >= 0) { ssize_t w3 = write(za_crash_fd, line, len); (void)w3; }
        if (found >= 40) break;
    }
}

""")
    g = g.replace(anchor, fn + anchor, 1)
    print("[guest] 加 za_log_guest_trace")

    # 调用点
    old3 = enc("""        za_log_stack((unsigned long)uc->uc_mcontext.sp);
""")
    new3 = enc("""        za_log_guest_trace((unsigned long)uc->uc_mcontext.sp);
        za_log_stack((unsigned long)uc->uc_mcontext.sp);
""")
    if old3 in g:
        g = g.replace(old3, new3, 1)
        print("[guest] 崩溃处理器调用 za_log_guest_trace")
    else:
        print("!! 崩溃处理器里找不到 za_log_stack 调用点")

    wr(gp, g)
else:
    print("[guest] 已存在 guest ret")

print("done")
