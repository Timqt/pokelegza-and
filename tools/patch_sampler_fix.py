# -*- coding: utf-8 -*-
"""修复 v4：真正安装 PC 采样器的信号处理器（关键 bug）+ 捕获器避开 SIGRTMIN"""
import sys

ROOT = r"D:\feiniukexinhome\Code\pokeLegza-and\app\native"
def rd(p):
    with open(p, "rb") as f: return f.read()
def wr(p, b):
    with open(p, "wb") as f: f.write(b)
def enc(s): return s.encode("utf-8")

gp = ROOT + r"\za_guest.c"
g = rd(gp)

# ---------------------------------------------------------------- 1) 真正装处理器
old = enc("""    // 接管 32..62 全部实时信号：抓出「到底是哪个信号要了我们的命」
    za_install_rt_catch();
""")
new = enc("""    // ★★★ 关键（2026-10-25 定位）：必须**真的**把处理器装上！
    //   以前只设了 sa.sa_sigaction 却漏了 sigaction() ⇒ 定时器信号按**默认动作**
    //   （终止进程）处理 ⇒ 进程被信号静默带走，没日志没 tombstone。
    //   而安卓上 SIGRTMIN == 42（**不是 32**！）⇒ 这正是之前 dumpsys 里
    //   「reason=SIGNALED status=42」的真凶（信号 42 从没装过处理器）。
    sigaction(sev.sigev_signo, &sa, NULL);
    // 接管 32..62 全部实时信号：抓出「到底是哪个信号要了我们的命」
    za_install_rt_catch();
""")
if b"sigaction(sev.sigev_signo, &sa, NULL);" not in g:
    assert old in g, "采样器锚点没找到"
    g = g.replace(old, new, 1)
    print("[guest] ★ 装上采样器处理器 sigaction(sev.sigev_signo)")

# ---------------------------------------------------------------- 2) 捕获器避开 SIGRTMIN
old2 = enc("""// 接管 32..62（63 是 PC 采样器的，不能抢）
void za_install_rt_catch(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = za_rt_catch;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
    for (int s = 32; s <= 62; s++) sigaction(s, &sa, NULL);
}
""")
new2 = enc("""// 接管 32..62（63 是 PC 采样器的，不能抢）
//
// ⚠ SIGRTMIN（安卓上是 42）**不抢**：bionic 内部的 POSIX 定时器线程用它
//   （AOSP libc/bionic/posix_timers.cpp: TIMER_SIGNAL = __SIGRTMIN），
//   抢了会破坏 libc 的定时器语义。只给它挂一个「只记录不致命」的处理器。
// ⚠ 已经装了别的处理器的信号也不抢：SDK 自己装的信号语义不能被我们覆盖。
static void za_rt_note(int sig, siginfo_t *info, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;
    unsigned long pc = uc ? (unsigned long)uc->uc_mcontext.pc : 0;
    char b[192];
    char *q = b;
    q = za_put_str(q, "ZaGuest: (记录) 实时信号 sig=");
    q = za_put_hex(q, (unsigned long long)sig);
    q = za_put_str(q, " si_code=");
    q = za_put_hex(q, (unsigned long long)(info ? info->si_code : 0));
    q = za_put_str(q, " pc=");
    q = za_put_addr(q, pc);
    q = za_put_str(q, "\\n");
    size_t len = (size_t)(q - b);
    ssize_t w = write(2, b, len);
    (void)w;
    if (za_crash_fd >= 0) { ssize_t w2 = write(za_crash_fd, b, len); (void)w2; }
}

// 当前处理器是不是「我们的」/「默认的」—— 只有这两种才允许覆盖
static int za_handler_replaceable(int sig, void *ours)
{
    struct sigaction old;
    memset(&old, 0, sizeof old);
    if (sigaction(sig, NULL, &old) != 0) return 0;
    void *h = (old.sa_flags & SA_SIGINFO) ? (void *)old.sa_sigaction : (void *)old.sa_handler;
    return h == ours || h == (void *)SIG_DFL || h == (void *)SIG_IGN;
}

void za_install_rt_catch(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = za_rt_catch;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
    for (int s = 32; s <= 62; s++)
    {
        if (s == SIGRTMIN) continue;          // bionic 自己要用，只记录不抢
        if (!za_handler_replaceable(s, (void *)za_rt_catch)) continue;
        sigaction(s, &sa, NULL);
    }
    // SIGRTMIN：只记录，不致命
    struct sigaction sn;
    memset(&sn, 0, sizeof sn);
    sn.sa_sigaction = za_rt_note;
    sn.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
    if (za_handler_replaceable(SIGRTMIN, (void *)za_rt_note))
        sigaction(SIGRTMIN, &sn, NULL);
}
""")
if b"za_rt_note" not in g:
    assert old2 in g, "捕获器锚点没找到"
    g = g.replace(old2, new2, 1)
    print("[guest] 捕获器避开 SIGRTMIN + 不覆盖 SDK 的处理器")

wr(gp, g)

# ---------------------------------------------------------------- 3) svc 里重装采样器
zpp = ROOT + r"\za_horizon.c"
z = rd(zpp)
if b"za_reinstall_sampler_handler" not in z:
    old3 = enc("""        za_install_rt_catch();
""")
    new3 = enc("""        za_install_rt_catch();
        za_reinstall_sampler_handler();
""")
    assert old3 in z, "horizon 锚点没找到"
    z = z.replace(old3, new3, 1)
    wr(zpp, z)
    print("[horizon] svc 里重装采样器处理器")

# ---------------------------------------------------------------- 4) 采样器处理器重装函数
if b"void za_reinstall_sampler_handler" not in g:
    anchor = enc("// 接管 32..62（63 是 PC 采样器的，不能抢）")
    assert anchor in g
    add = enc("""// SDK 初始化时会覆盖我们对实时信号的处理权 ⇒ 采样器会静默死掉，
// 于是崩溃时拿不到客机真正的 PC。svc 每次调用时重装一次
//（只在处理器还是「我们的」时才装，不覆盖 SDK 自己装的）。
void za_reinstall_sampler_handler(void)
{
    if (!za_pc_timer_ready) return;
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = za_pc_sampler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    if (za_handler_replaceable(63, (void *)za_pc_sampler))
        sigaction(63, &sa, NULL);
}

""")
    g = g.replace(anchor, add + anchor, 1)
    wr(gp, g)
    print("[guest] 加 za_reinstall_sampler_handler")

# ---------------------------------------------------------------- 5) 头文件声明
hp = ROOT + r"\za_guest_api.h"
h = rd(hp)
if b"za_reinstall_sampler_handler" not in h:
    decl = enc("void za_reinstall_sampler_handler(void);\n")
    idx = h.rfind(b"#endif")
    h = h[:idx] + decl + h[idx:]
    wr(hp, h)
    print("[api] 声明已加")

print("done")
