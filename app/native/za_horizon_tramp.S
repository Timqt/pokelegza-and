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
    adr  x16, 2f
    ldr  x16, [x16]                 // &za_horizon_regs[]
    mov  x17, sp                    // SP cannot be a base register of STR (imm)
    str  x9,  [x16, #80]            // regs[10] = service number
    str  x17, [x16, #72]            // regs[9]  = guest sp (Break handler scans it)
    str  x30, [x16, #88]            // regs[11] = guest x30
    str  x19, [x16, #128]           // regs[16] = guest x19  (diagnostic)
    str  x29, [x16, #136]           // regs[17] = guest x29  (diagnostic)
    str  x28, [x16, #144]           // regs[18] = guest x28  (diagnostic)
    adr  x17, 3f
    ldr  x17, [x17]                 // host stack top (filled at load time)
    mov  sp, x17                    // switch to the host stack
    // Save the guest's callee-saved registers on the HOST stack.
    // (Observed: x19/x29/x30 came back as 0x64e230 / 5 / 0 -- garbage that
    //  looks like values read out of our own TLS shadow area.  Whatever the
    //  cause, the gate must hand the guest its callee-saved registers back
    //  untouched.  x30 is saved here too and restored below.)
    sub  sp, sp, #0x70
    str  x9,  [sp, #0x00]           // C arg #9 = service number
    stp  x19, x20, [sp, #0x10]
    stp  x21, x22, [sp, #0x20]
    stp  x23, x24, [sp, #0x30]
    stp  x25, x26, [sp, #0x40]
    stp  x27, x28, [sp, #0x50]
    stp  x29, x30, [sp, #0x60]
    adr  x17, 1f
    ldr  x17, [x17]                 // host C function address
    blr  x17
    ldp  x29, x30, [sp, #0x60]
    ldp  x27, x28, [sp, #0x50]
    ldp  x25, x26, [sp, #0x40]
    ldp  x23, x24, [sp, #0x30]
    ldp  x21, x22, [sp, #0x20]
    ldp  x19, x20, [sp, #0x10]
    add  sp, sp, #0x70
    // write back x1..x7 (Horizon out-params live in regs[1..7])
    adr  x16, 2f
    ldr  x16, [x16]
    ldp  x1, x2, [x16, #8]
    ldp  x3, x4, [x16, #24]
    ldp  x5, x6, [x16, #40]
    ldr  x7,  [x16, #56]
    ldr  x17, [x16, #72]             // guest sp
    mov  sp,  x17                   // switch back to the guest stack
    ldr  x30, [x16, #88]            // guest x30
    ret
1:  .quad 0                          // host C function address
2:  .quad 0                          // &za_horizon_regs[]
3:  .quad 0                          // host stack top
    .size za_horizon_tramp, .-za_horizon_tramp
