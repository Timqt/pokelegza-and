# -*- coding: utf-8 -*-
"""给 za_horizon.c 加一个「帧快照」探针。

目的：把「x30 保存槽到底是哪一步变 0」一刀切开。
  0x14457c 的帧底 sp0 = guest_sp_at_svc + 0x10（三条 svc 的包装函数都先 push 0x10）。
  x29 槽 = sp0+0x40，x30 槽 = sp0+0x48。

  在 svc#6（pc=0x2001445a8）、svc#12（0x2001445cc）、svc#37（0x200144608）
  各拍一张 [sp0, sp0+0x70) 的快照，崩溃时一起打出来：
    - 若 svc#37 那张里 x30 槽已经是 0 ⇒ 坏在 svc#6/#12/0x13e420 之间
    - 若 svc#37 那张里 x30 槽还正常      ⇒ 坏在 0x144610..ret 之间
"""
import io

P = 'app/native/za_horizon.c'

SNAP_DECL = '''
// ── 帧快照探针（2026-10-25 夜）──────────────────────────────────────
// 目的：把 0x14457c 的 x30 槽「何时变 0」一刀切开。
//   帧底 sp0 = 客机 svc 时的 sp + 0x10（包装函数先 str x?,[sp,#-0x10]!）。
//   stp x29,x30,[sp,#0x40] ⇒ x29 槽 = sp0+0x40、x30 槽 = sp0+0x48。
#define ZA_SNAP_N 14            /* 14 words = 0x70 字节 = 整个 0x14457c 帧 */
volatile unsigned long za_frame_snap[4][ZA_SNAP_N];
volatile unsigned long za_frame_snap_pc[4];
volatile unsigned long za_frame_snap_sp[4];
volatile int za_frame_snap_n;

static void za_frame_snapshot(unsigned long guest_pc, unsigned long guest_sp)
{
    // 只对 0x14457c 里那三条 svc 拍快照
    if (guest_pc != 0x2001445a8ul && guest_pc != 0x2001445ccul &&
        guest_pc != 0x200144608ul)
        return;
    int k = za_frame_snap_n;
    if (k >= 4) return;
    unsigned long sp0 = guest_sp + 0x10;
    za_frame_snap_pc[k] = guest_pc;
    za_frame_snap_sp[k] = sp0;
    for (int i = 0; i < ZA_SNAP_N; i++)
    {
        unsigned long v = 0;
        // 直接读客机栈；越界读由客机影像/栈映射保证可读（同一条线程栈）
        v = *(volatile unsigned long *)(uintptr_t)(sp0 + (unsigned long)i * 8);
        za_frame_snap[k][i] = v;
    }
    za_frame_snap_n = k + 1;
}
'''

s = io.open(P, encoding='utf-8').read()
anchor = '__attribute__((visibility("default"))) volatile unsigned long za_horizon_regs[32];'
assert s.count(anchor) == 1
s = s.replace(anchor, anchor + '\n' + SNAP_DECL)

old_trace = '''    za_svc_trace_rich(nr, za_horizon_regs[ZA_REG_PC], (unsigned long)a0,
                      (unsigned long)a2, za_horizon_regs[19]);'''
new_trace = old_trace + '''
    // 帧快照：0x14457c 的三条 svc 各拍一张（见 za_frame_snapshot 注释）
    za_frame_snapshot(za_horizon_regs[ZA_REG_PC], za_horizon_guest_sp());'''
assert s.count(old_trace) == 1
s = s.replace(old_trace, new_trace)

io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('za_horizon.c patched')
