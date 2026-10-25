# -*- coding: utf-8 -*-
"""给 fatal handler 加 **x29 帧链遍历**（AAPCS64 标准帧记录）。

为什么要它：
  现有 za_log_guest_trace(sp) 只是把 sp 往上 8MB 里所有「像客机地址」的 8 字节
  都打印出来 —— 里面混着数据、局部变量、以及历史残留，无法确定真正的调用序列。
  上一轮我就是拿这堆混合值当「返回地址」推理，连错三次。

正确做法（AAPCS64 帧记录）：
  x29 指向的栈槽布局是
      [x29 + 0] = 上一层 x29
      [x29 + 8] = 上一层 x30（返回地址）
  沿着它一路走，就是**精确的调用链**，每一步都可验证（地址必须落在客机映像内）。

本补丁新增 za_dump_fp_chain(x29)，并在 fatal handler 里于 za_log_stack 之前调用。
"""
import io

P = 'app/native/za_guest.c'
s = io.open(P, encoding='utf-8').read()

# 1) 在 za_log_guest_trace 之前插入 fp-chain 函数
anchor = "static void za_log_guest_trace(unsigned long sp)"
assert s.count(anchor) == 1
fp_fn = '''// ── x29 帧链遍历（AAPCS64）──────────────────────────────────────────
// 每个帧：[x29+0]=上一层的 x29，[x29+8]=上一层的 x30（返回地址）。
// 沿链走就是精确调用序列 —— 这是唯一能区分「真返回地址」和「栈上垃圾」的办法。
// 之前只做「sp 往上扫客机地址」，混进大量数据/局部变量，据此推理连错三轮。
static void za_dump_fp_chain(unsigned long fp, unsigned long pc, unsigned long sp)
{
    char line[256];
    {
        char *p = line;
        p = za_put_str(p, "ZaGuest: fp-chain enter fp=");
        p = za_put_hex(p, (unsigned long long)fp);
        p = za_put_str(p, " sp=");
        p = za_put_hex(p, (unsigned long long)sp);
        p = za_put_str(p, "\\n");
        za_fatal_write(line, (size_t)(p - line));
    }
    // 先报当前 PC（abort 现场本身）
    {
        char *p = line;
        unsigned long bm = (unsigned long)za_guest_base, sm = za_sdk_base;
        if (sm && pc >= sm && pc < sm + za_sdk_size)
        {
            p = za_put_str(p, "ZaGuest:   frame[00] pc sdk+");
            p = za_put_hex(p, (unsigned long long)(pc - sm));
        }
        else if (bm && pc >= bm && pc < bm + ZA_IMAGE_SIZE)
        {
            p = za_put_str(p, "ZaGuest:   frame[00] pc main+");
            p = za_put_hex(p, (unsigned long long)(pc - bm));
        }
        else
        {
            p = za_put_str(p, "ZaGuest:   frame[00] pc outside");
            p = za_put_hex(p, (unsigned long long)pc);
        }
        p = za_put_str(p, "\\n");
        za_fatal_write(line, (size_t)(p - line));
    }

    unsigned long bm = (unsigned long)za_guest_base, sm = za_sdk_base;
    for (int i = 1; i <= 24; i++)
    {
        // 帧指针必须 16 字节对齐、且在栈区里，否则视为链断
        if (!fp || (fp & 0xF) || (sp && fp < sp - 0x10000)) break;
        unsigned long next_fp = 0, ret = 0;
        if (!za_read_word(fp, &next_fp)) break;
        if (!za_read_word(fp + 8, &ret)) break;
        // next_fp 必须递增且对齐，否则链坏
        if (next_fp && (next_fp & 0xF)) break;
        if (next_fp && next_fp <= fp) break;

        char *p = line;
        p = za_put_str(p, "ZaGuest:   frame[");
        p = za_put_dec(p, (unsigned long long)i);
        p = za_put_str(p, "] ret=");
        if (sm && ret >= sm && ret < sm + za_sdk_size)
        {
            p = za_put_str(p, "sdk+");
            p = za_put_hex(p, (unsigned long long)(ret - sm));
        }
        else if (bm && ret >= bm && ret < bm + ZA_IMAGE_SIZE)
        {
            p = za_put_str(p, "main+");
            p = za_put_hex(p, (unsigned long long)(ret - bm));
        }
        else
        {
            p = za_put_hex(p, (unsigned long long)ret);
        }
        p = za_put_str(p, "  fp=");
        p = za_put_hex(p, (unsigned long long)next_fp);
        p = za_put_str(p, "\\n");
        za_fatal_write(line, (size_t)(p - line));
        fp = next_fp;
    }
}

'''
s = s.replace(anchor, fp_fn + anchor)

# 2) 在 fatal handler 里调用（放在 za_log_guest_trace 之前）
call_anchor = "        za_log_guest_trace((unsigned long)uc->uc_mcontext.sp);"
assert s.count(call_anchor) == 1
s = s.replace(call_anchor,
              "        // x29 帧链：精确调用序列（优先看这个，不要看下面 sp 扫描的混合值）\n"
              "        za_dump_fp_chain((unsigned long)uc->uc_mcontext.regs[29],\n"
              "                         (unsigned long)pc,\n"
              "                         (unsigned long)uc->uc_mcontext.sp);\n"
              + call_anchor)

io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('fp-chain walker added')
