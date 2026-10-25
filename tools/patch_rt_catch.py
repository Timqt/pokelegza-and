# -*- coding: utf-8 -*-
"""实时信号捕获器补丁 v3（小片段替换，避免整块锚点对不上）"""
import sys

ROOT = r"D:\feiniukexinhome\Code\pokeLegza-and\app\native"
def rd(p):
    with open(p, "rb") as f: return f.read()
def wr(p, b):
    with open(p, "wb") as f: f.write(b)
def enc(s): return s.encode("utf-8")

# ================================================================== za_guest.c
gp = ROOT + r"\za_guest.c"
g = rd(gp)

RT_BLOCK = enc(r'''
// ---------------------------------------------------------------- 实时信号捕获
//
// 现象（2026-10-25 06:54）：进程被 **signal 42** 杀死（dumpsys: reason=SIGNALED
// status=42），但我们请求的定时器信号不是 42，而且**完全没有处理器日志**、
// 没有 tombstone ⇒ 说明这个信号的处理权不在我们手上（被 SDK 换掉了，
// 或者压根不是定时器发的）。
//
// 这里把 32..62 全部接管（63 留给 PC 采样器）：先把「信号号 / si_code /
// si_pid / si_tid / 故障 PC」打出来（si_code 能区分来源：SI_TIMER=内核定时器、
// SI_QUEUE=pthread_kill、SI_USER=kill、SI_TKILL=bionic 内部线程退出），
// 再走完整的崩溃现场流程，最后恢复默认动作重新 raise，让 debuggerd 仍能出 tombstone。
static void za_rt_catch(int sig, siginfo_t *info, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;
    unsigned long pc = uc ? (unsigned long)uc->uc_mcontext.pc : 0;
    char b[320];
    char *q = b;
    q = za_put_str(q, "ZaGuest: *** 收到实时信号 sig=");
    q = za_put_hex(q, (unsigned long long)sig);
    q = za_put_str(q, " si_code=");
    q = za_put_hex(q, (unsigned long long)(info ? info->si_code : 0));
    q = za_put_str(q, " si_pid=");
    q = za_put_hex(q, (unsigned long long)(info ? info->si_pid : 0));
    q = za_put_str(q, " si_tid=");
    q = za_put_hex(q, (unsigned long long)(info ? info->si_tid : 0));
    q = za_put_str(q, " pc=");
    q = za_put_addr(q, pc);
    q = za_put_str(q, "\n");
    size_t len = (size_t)(q - b);
    ssize_t w = write(2, b, len);
    (void)w;
    if (za_crash_fd >= 0) { ssize_t w2 = write(za_crash_fd, b, len); (void)w2; }
    // 完整现场（寄存器 / 客机 PC 环 / svc 轨迹 / 映射表）
    za_fatal_handler(sig, info, ctx);
}

// 接管 32..62（63 是 PC 采样器的，不能抢）
void za_install_rt_catch(void)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = za_rt_catch;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_RESTART;
    for (int s = 32; s <= 62; s++) sigaction(s, &sa, NULL);
}

// 打印本线程当前真正被屏蔽的信号（探针法，不依赖 sigset_t 内部布局）
void za_dump_thread_mask(const char *tag)
{
    sigset_t cur;
    pthread_sigmask(SIG_BLOCK, NULL, &cur);
    static const int probe[] = { SIGFPE, SIGUSR1, SIGALRM, 32, 42, 56, 60, 63 };
    char b[400];
    char *q = b;
    q = za_put_str(q, "ZaGuest: 掩码[");
    q = za_put_str(q, tag ? tag : "?");
    q = za_put_str(q, "]");
    for (unsigned i = 0; i < sizeof probe / sizeof probe[0]; i++)
    {
        q = za_put_str(q, " ");
        q = za_put_hex(q, (unsigned long long)probe[i]);
        q = za_put_str(q, sigismember(&cur, probe[i]) ? "=挡" : "=行");
    }
    q = za_put_str(q, "\n");
    size_t len = (size_t)(q - b);
    ssize_t w = write(2, b, len);
    (void)w;
    if (za_crash_fd >= 0) { ssize_t w2 = write(za_crash_fd, b, len); (void)w2; }
}

''')

anchor = enc("static void za_segv_handler(int sig, siginfo_t *info, void *ctx)\n{\n    za_fatal_handler(sig, info, ctx);\n}\n")
if b"za_install_rt_catch" not in g:
    assert anchor in g, "锚点 za_segv_handler 没找到"
    g = g.replace(anchor, anchor + RT_BLOCK, 1)
    print("[guest] 插入实时信号捕获器")

# 采样器：信号 32 → 63
if b"sev.sigev_signo = 63;" not in g:
    old = b"    sev.sigev_signo = SIGRTMIN;\n"
    assert old in g, "sigev_signo 没找到"
    new = (b"    // \xe2\x80\xbc \xe7\x94\xa8 **63**\xef\xbc\x88\xe6\x9c\x80\xe9\xab\x98\xe5\xae\x9e\xe6\x97\xb6\xe4\xbf\xa1\xe5\x8f\xb7\xe5\x8c\xba\xef\xbc\x89\xe8\x80\x8c\xe4\xb8\x8d\xe6\x98\xaf SIGRTMIN(32)\xef\xbc\x9a\n"
           b"    //   SDK \xe5\x88\x9d\xe5\xa7\x8b\xe6\x97\xb6\xe6\x8a\x8a\xe7\xba\xbf\xe7\xa8\x8b\xe6\x8b\x9c\xe7\xa0\x81\xe8\xae\xbe\xe6\x88\x90 0xffffffffbaff \xe4\xb8\x80\xe7\xb1\xbb\xef\xbc\x88bit0..55 \xe5\x85\xa8\xe6\x8c\xa1\xef\xbc\x89\xef\xbc\x8c\n"
           b"    //   \xe4\xbf\xa1\xe5\x8f\xb7 56..63 \xe5\xa4\xa9\xe7\x84\xb6\xe6\x98\xaf\xe6\x94\xbe\xe8\xa1\x8c\xe7\x9a\x84\xef\xbc\x9b\xe4\xb8\x94 SDK \xe5\x87\xa0\xe5\xb0\x91\xe4\xbc\x9a\xe5\x8d\xa0\xe7\x94\xa8 63\n"
           b"    //   \xe2\x87\x92 \xe9\x87\x87\xe6\xa0\xb7\xe5\x99\xa8\xe8\x83\xbd\xe6\xb4\xbb\xe8\xbf\x87 SDK \xe5\x88\x9d\xe5\xa7\x8b\xe5\x8c\x96\xef\xbc\x8c\xe6\x8b\xbf\xe5\x88\xb0\xe5\xae\xa2\xe6\x9c\xba\xe7\x9c\x9f\xe6\xad\xa3\xe7\x9a\x84\xe5\xb4\xa9\xe6\xba\xb6 PC\xe3\x80\x82\n"
           b"    sev.sigev_signo = 63;\n")
    g = g.replace(old, new, 1)
    print("[guest] 采样器信号 32 -> 63")

# 放行 63
if b"sigaddset(&m, 63);" not in g:
    old = b"        sigaddset(&m, SIGUSR1); sigaddset(&m, SIGALRM); sigaddset(&m, SIGRTMIN);\n        sigaddset(&m, SIGTERM);\n"
    assert old in g, "掩码放行块没找到"
    new = b"        sigaddset(&m, SIGUSR1); sigaddset(&m, SIGALRM); sigaddset(&m, SIGRTMIN);\n        sigaddset(&m, SIGTERM); sigaddset(&m, 63);\n"
    g = g.replace(old, new, 1)
    print("[guest] 放行信号 63")

# 装捕获器 + 打印掩码 + 打印信号号
if b"\xe6\x8b\x9b\xe9\x87\x87\xe5\x99\xa8" not in g:
    old = b"    sev.sigev_signo = 63;\n"
    assert old in g
    new = old + enc('''    // 接管 32..62 全部实时信号：抓出「到底是哪个信号要了我们的命」
    za_install_rt_catch();
    za_dump_thread_mask("采样器启动时");
    {
        char b[200];
        char *q = b;
        q = za_put_str(q, "ZaGuest: 定时器信号号=");
        q = za_put_hex(q, (unsigned long long)sev.sigev_signo);
        q = za_put_str(q, " SIGRTMIN=");
        q = za_put_hex(q, (unsigned long long)SIGRTMIN);
        q = za_put_str(q, " SIGRTMAX=");
        q = za_put_hex(q, (unsigned long long)SIGRTMAX);
        q = za_put_str(q, " 目标tid=");
        q = za_put_hex(q, (unsigned long long)sev.sigev_notify_thread_id);
        q = za_put_str(q, "\\n");
        size_t l = (size_t)(q - b);
        ssize_t w = write(2, b, l); (void)w;
        if (za_crash_fd >= 0) { ssize_t w2 = write(za_crash_fd, b, l); (void)w2; }
    }
''')
    g = g.replace(old, new, 1)
    print("[guest] 采样器装捕获器 + 打印掩码")

wr(gp, g)

# ================================================================== za_guest_api.h
hp = ROOT + r"\za_guest_api.h"
h = rd(hp)
if b"za_install_rt_catch" not in h:
    decl = enc("void za_install_rt_catch(void);\nvoid za_dump_thread_mask(const char *tag);\n")
    idx = h.rfind(b"#endif")
    h = h[:idx] + decl + h[idx:]
    wr(hp, h)
    print("[api] 声明已加")

# ================================================================== za_horizon.c
zpp = ROOT + r"\za_horizon.c"
z = rd(zpp)
if b"za_install_rt_catch" not in z:
    old = b"            sigaddset(&m, SIGTERM);\n            pthread_sigmask(SIG_UNBLOCK, &m, NULL);\n            last_mask = 1;\n        }\n    }\n"
    assert old in z, "horizon 锚点没找到"
    new = (b"            sigaddset(&m, SIGTERM); sigaddset(&m, 63);\n"
           b"            pthread_sigmask(SIG_UNBLOCK, &m, NULL);\n"
           b"            last_mask = 1;\n"
           b"        }\n"
           b"        // \xe2\x98\x85 SDK \xe5\x88\x9d\xe5\xa7\x8b\xe6\x97\xb6\xe4\xbc\x9a\xe6\x8a\x8a\xe8\x87\xaa\xe5\xb7\xb1\xe7\x9a\x84\xe4\xbf\xa1\xe5\x8f\xb7\xe6\x8b\x9c\xe7\xa0\x81\xe8\xae\xbe\xe6\x88\x90\xe3\x80\x8c\xe5\xbf\x87\xe4\xbb\xa5\xe6\x8d\xa2\xe6\x8d\x89\xe3\x80\x8d\n"
           b"        //   \xe2\x87\x92 \xe6\xaf\x8f\xe6\xac\xa1 svc \xe9\x83\xbd\xe9\x87\x8d\xe6\x96\xb0\xe8\xa3\x85\xe4\xb8\x80\xe9\x81\x8d 32..62 \xe7\x9a\x84\xe6\x8d\x95\xe8\x8e\xb7\xe5\x99\xa8\xef\xbc\x8c\xe5\xb9\xb6\xe6\x8a\x8a\xe6\x95\xb4\xe4\xb8\xaa\xe5\xae\x9e\xe6\x97\xb6\xe4\xbf\xa1\xe5\x8f\xb7\xe6\xae\xb5\xe6\x94\xbe\xe8\xa1\x8c\xe3\x80\x82\n"
           b"        za_install_rt_catch();\n"
           b"        {\n"
           b"            sigset_t rt;\n"
           b"            sigemptyset(&rt);\n"
           b"            for (int s = 32; s <= 63; s++) sigaddset(&rt, s);\n"
           b"            pthread_sigmask(SIG_UNBLOCK, &rt, NULL);\n"
           b"        }\n"
           b"    }\n")
    z = z.replace(old, new, 1)
    wr(zpp, z)
    print("[horizon] svc 每次重装捕获器")

print("done")
