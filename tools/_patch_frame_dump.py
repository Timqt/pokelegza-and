# -*- coding: utf-8 -*-
"""把 za_frame_snap 的 4 张帧快照加进崩溃 dump。"""
import io

P = 'app/native/za_guest.c'

decl = '''
// 帧快照（定义在 za_horizon.c）：0x14457c 三条 svc 时刻的整帧内容
#define ZA_SNAP_N 14
extern volatile unsigned long za_frame_snap[4][ZA_SNAP_N];
extern volatile unsigned long za_frame_snap_pc[4];
extern volatile unsigned long za_frame_snap_sp[4];
extern volatile int za_frame_snap_n;
static void za_dump_frame_snap(void)
{
    char line[320];
    int n = za_frame_snap_n;
    {
        char *p = line;
        p = za_put_str(p, "ZaGuest: frame-snap n=");
        p = za_put_dec(p, (unsigned long long)n);
        p = za_put_str(p, " (each = whole 0x14457c frame, idx3=sp0+0x18 x30=idx9)\\n");
        za_fatal_write(line, (size_t)(p - line));
    }
    for (int k = 0; k < n && k < 4; k++)
    {
        char *p = line;
        p = za_put_str(p, "ZaGuest:  snap#");
        p = za_put_dec(p, (unsigned long long)k);
        p = za_put_str(p, " pc=");
        p = za_put_hex(p, (unsigned long long)za_frame_snap_pc[k]);
        p = za_put_str(p, " sp0=");
        p = za_put_hex(p, (unsigned long long)za_frame_snap_sp[k]);
        p = za_put_str(p, "\\n");
        za_fatal_write(line, (size_t)(p - line));
        for (int i = 0; i < ZA_SNAP_N; i += 4)
        {
            char *q = line;
            q = za_put_str(q, "ZaGuest:    +");
            q = za_put_hex(q, (unsigned long long)(i * 8));
            q = za_put_str(q, ":");
            for (int j = i; j < i + 4 && j < ZA_SNAP_N; j++)
            {
                q = za_put_str(q, " ");
                q = za_put_hex(q, (unsigned long long)za_frame_snap[k][j]);
            }
            q = za_put_str(q, "\\n");
            za_fatal_write(line, (size_t)(q - line));
        }
    }
}
'''

s = io.open(P, encoding='utf-8').read()
anchor = 'static void za_fatal_handler(int sig, siginfo_t *info, void *ctx);'
assert s.count(anchor) == 1
s = s.replace(anchor, anchor + '\n' + decl)

call_anchor = '''        // 客机 PC 采样轨迹：崩溃前最后若干条真实执行地址
        za_dump_pc_ring();'''
assert s.count(call_anchor) == 1
s = s.replace(call_anchor, call_anchor + '\n        // 帧快照：0x14457c 三条 svc 各自时刻的整帧\n        za_dump_frame_snap();')

io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('za_guest.c patched')
