// Horizon svc host-gate trampoline for the guest (Switch NSO SDK).
//
// Machine code of this file is extracted by tools/patch_svc.py and placed in the
// gate area at the end of the guest image.
//
// Purpose: forward a guest `svc #N` call to the host C implementation:
//   x9      = service number (written by gate_N via `mov w9,#N`)
//   x0..x7  = Horizon arguments
//   result  -> x0
//
// IMPORTANT: Horizon puts out-parameters in W1/W2, not in x0. The C function can
// only return one value, so it stores the values to restore in za_horizon_regs[]
// and this trampoline writes them back into x1..x7 after the call.
//
// 2026-10-25 rewrite: switch to a dedicated HOST stack before calling C.
//
// Why (this was the most subtle bug of the whole port):
//   The guest svc wrapper only reserves 0x10 bytes of stack:
//     170174: str x0, [sp, #-0x10]! ; svc #0x25 ; ldr x2,[sp] ; str x1,[x2] ; add sp,sp,#0x10 ; ret
//   We rewrite the ENTRY of that wrapper (not the svc instruction itself), so the
//   prologue never runs and the guest sp at the gate is the call-site sp
//   (constructor frame S+0x60).  Our old trampoline did `sub sp,sp,#0x70`, so its
//   frame was [S-0x10, S+0x60) -- it stomped the WHOLE guest stack frame including
//   the saved x29/x30.
//   Observed effect: the guest `ret` jumped back to 0x144608 (itself) => infinite
//   loop => sp grew by 0x70 each time => it walked 256MB past the stack top =>
//   pc=0 SIGSEGV.
//   d2r-and (shipping product) uses an 800-byte frame safely because it rewrites
//   the svc instruction itself and its SDK wrapper has NO prologue (svc #N; ret),
//   so the guest sp is unchanged and the whole frame lands below S.
//   This SDK's wrapper HAS a prologue, so we switch stacks instead.
//
// This gate only touches x16/x17 (caller-saved, an svc may clobber them) and
// x0..x7 (which we rewrite). x19..x28 are never touched.  The guest sp and x30
// are parked in za_horizon_regs[].

    .text
    .global za_horizon_tramp
    .type za_horizon_tramp, %function
za_horizon_tramp:
    // ★★★ Horizon 的 svc 语义：**只写 x0，其它寄存器全部保持不变**。
    //     宿主 C 调度器会覆盖 x0–x18，所以必须在调用前把它们存在**客机栈**上。
    //     门桩把服务号放在 x16（IP0：函数入口处按 ABI 必死），不再动 x9。
    stp  x8,  x9,  [sp, #-0x60]!
    stp  x10, x11, [sp, #0x10]
    stp  x12, x13, [sp, #0x20]
    stp  x14, x15, [sp, #0x30]
    stp  x16, x17, [sp, #0x40]
    stp  x18, x30, [sp, #0x50]
    // ★★★ 每线程的 svc 寄存器槽。
    //   以前 `adr x16,2f; ldr x16,[x16]` 取的是**全局** za_horizon_regs[]：
    //   服务号先写进 regs[10] 再读回来当第 9 个参数，x1..x7 也从它回写。
    //   两个线程同时进 svc 时互相覆盖 —— 实测 svc#28 的 nr 被读成另一个线程的
    //   44，x1..x7 被写成别人的陈旧值（Horizon 约定 svc 只改 x0），
    //   客机随后随机跳 pc=0x7fffffff00000000。
    //   现在按 `TPIDR_EL0 → [tp+0x40]（本线程描述符页）→ [+0xa0]（槽地址）` 现取。
    mrs  x16, TPIDR_EL0
    ldr  x16, [x16, #0x40]
    ldr  x16, [x16, #0xa0]
    ldr  x17, [sp, #0x40]           // 服务号（门桩写在 x16 里，已保存）
    str  x17, [x16, #80]            // regs[10] = service number
    mov  x17, sp                    // SP 不能作为 str 的源寄存器
    str  x17, [x16, #72]            // regs[9]  = guest sp（已下移 0x60）
    ldr  x17, [sp, #0x58]           // guest x30
    str  x17, [x16, #88]            // regs[11] = guest x30
    str  x19, [x16, #128]           // regs[16] = guest x19（诊断）
    str  x29, [x16, #136]           // regs[17] = guest x29（诊断）
    str  x28, [x16, #144]           // regs[18] = guest x28（诊断）
    // ★★ 宿主栈：**每线程一条**（描述符 +0xA8 = 栈顶）。
    //   以前用全局槽 3f 的栈顶：所有线程都 `sp = top - 0x80` ⇒ 并发 svc 时
    //   两条线程的 C 栈帧完全重叠，局部变量/canary 互相踩烂
    //   （实测 libc: "stack corruption detected (-fstack-protector)" → abort）。
    //   描述符里没填（mmap 失败）时退回全局槽。
    mrs  x16, TPIDR_EL0
    ldr  x16, [x16, #0x40]
    ldr  x17, [x16, #0xa8]
    cbnz x17, 4f
    adr  x17, 3f
    ldr  x17, [x17]
4:  mov  sp, x17
    sub  sp, sp, #0x80
    // C 第 9 个参数 = 服务号（放在 [sp+0]）—— 从本线程 regs 取
    mrs  x16, TPIDR_EL0
    ldr  x16, [x16, #0x40]
    ldr  x16, [x16, #0xa0]
    ldr  x17, [x16, #80]
    str  x17, [sp, #0x00]
    stp  x19, x20, [sp, #0x10]
    stp  x21, x22, [sp, #0x20]
    stp  x23, x24, [sp, #0x30]
    stp  x25, x26, [sp, #0x40]
    stp  x27, x28, [sp, #0x50]
    stp  x29, x30, [sp, #0x60]
    adr  x17, 1f
    ldr  x17, [x17]
    blr  x17
    ldp  x29, x30, [sp, #0x60]
    ldp  x27, x28, [sp, #0x50]
    ldp  x25, x26, [sp, #0x40]
    ldp  x23, x24, [sp, #0x30]
    ldp  x21, x22, [sp, #0x20]
    ldp  x19, x20, [sp, #0x10]
    add  sp, sp, #0x80
    // 写回 x1..x7（Horizon 的出参在 regs[1..7]，本线程私有）
    mrs  x16, TPIDR_EL0
    ldr  x16, [x16, #0x40]
    ldr  x16, [x16, #0xa0]
    ldp  x1, x2, [x16, #8]
    ldp  x3, x4, [x16, #24]
    ldp  x5, x6, [x16, #40]
    ldr  x7,  [x16, #56]
    // ★ 切回客机栈，恢复 x8–x18 / x30
    ldr  x16, [x16, #72]            // guest sp（调整后的）
    mov  sp,  x16
    ldp  x8,  x9,  [sp]
    ldp  x10, x11, [sp, #0x10]
    ldp  x12, x13, [sp, #0x20]
    ldp  x14, x15, [sp, #0x30]
    ldp  x16, x17, [sp, #0x40]
    ldp  x18, x30, [sp, #0x50]
    add  sp, sp, #0x60
    ret
1:  .quad 0                          // host C function address
2:  .quad 0                          // &za_horizon_regs[]
3:  .quad 0                          // host stack top
    .size za_horizon_tramp, .-za_horizon_tramp
