# -*- coding: utf-8 -*-
"""给 svc#31 / svc#33 加取证日志，确定 nn::sm 初始化的真实失败点。

背景（反汇编 sdk+0x153e30 实测）：
```
153e54  ldr  w8,[0xb9c598]        ; 「sm 已初始化」计数，>=1 就跳过
153e6c  adrp/add x1 = 0x937e50    ; 字符串 "sm:"
153e78  add  x0,x29,#0x1c
153e7c  bl   0x170134             ; svc#31 ConnectToNamedPort(out=sp+0x1c, name="sm:")
153e80  cbz  w0, 0x153ec8         ; 返回 0 才继续
153ec8  adrp/add 0xb9c5a0
153ed4  ldarb w8,[0xb9c5a0]       ; 「sm 就绪」标志
153ed8  tbz  w8,#0, 0x153f50      ; 为 0 => 走 0x153f50（懒初始化），不是断言
...
153edc  mov  x8,#0x10 / movk x8,#0x8000,lsl #48
153eec  str  x8,[x19]             ; [tp16+0] = 0x8000000000000010
153ef4  str  w8,[x19,#8]          ; [tp16+8] = 1
153efc  ldr  w0,[0xb9c59c]        ; ★ 会话句柄（这里到底是几？）
153f00  bl   0x17014c             ; svc#33 SendSyncRequest(session=w0)
153f04  cbnz w0, 0x153f4c         ; 非 0 => 错误出口
153f10  str  x8,[x19]             ; [tp16+0] = 0x100000010
153f14  ldr  w8,[x19,#8]          ; ★ 读回 [tp16+8]
153f18  cbnz w8, 0x153f4c         ; ★ 必须为 0，否则错误出口
153f4c  bl   0x62f3d0 -> 0x9ac90  ; abort("stdio")
```

⇒ 需要三个事实才能定案：
  ① svc#31 收到的服务名（确认就是 "sm:"）
  ② svc#31 分配的句柄有没有被客机存到 0xb9c59c
  ③ svc#33 收到的 session 值 + 调用前后 [tp16+8]

⚠ 注意：[tp16+8] 在 svc 之前被客机自己写成 1，之后要求变 0
   ⇒ 说明**必须由 SendSyncRequest 的实现把它清 0**（真机上由内核/服务完成）。
   这条是本轮最可能的直接修复点。
"""
import io

P = 'app/native/za_horizon.c'
s = io.open(P, encoding='utf-8').read()

# ── ① svc#31：把服务名打出来 ────────────────────────────────────────
old31 = """    case 31: // ConnectToNamedPort(out_handle=x0, name=x1) → W1
    {
        int id = za_handle_alloc(ZA_H_MEMORY);
        if (id < 0) return 1;"""
new31 = """    case 31: // ConnectToNamedPort(out_handle=x0, name=x1) → W1
    {
        // 取证：客机连的是哪个服务（无结尾 NUL，按 8 字节打印）
        {
            const char *nm = (const char *)(uintptr_t)a1;
            if (nm)
            {
                unsigned long long w0v = 0, w1v = 0;
                memcpy(&w0v, nm, 8);
                memcpy(&w1v, nm + 8, 8);
                ZLOGI("svc#31 ConnectToNamedPort name=%.8s%s (raw %016llx %016llx) out=%p",
                      nm, (w0v >> 56) ? "" : "...", w0v, w1v, (void *)(uintptr_t)a0);
            }
        }
        int id = za_handle_alloc(ZA_H_MEMORY);
        if (id < 0) return 1;"""
assert s.count(old31) == 1, s.count(old31)
s = s.replace(old31, new31)

# ── ② svc#33：打印 session + 读只读 TLS 的 [tp16+0]/[tp16+8]，并把 +8 清零 ──
old33 = """    case 33: // SendSyncRequest(session=x0)
    case 34: // SendSyncRequestWithUserBuffer(buf=x0, size=x1, session=x2)
    case 35: // SendAsyncRequestWithUserBuffer(out_handle=x0, buf=x1, size=x2, session=x3) → W1"""
new33 = """    case 33: // SendSyncRequest(session=x0)
    {
        // ★ 取证 + 关键修复（见本次补丁头部注释）
        //
        // 客机在 sdk+0x153edc 这样用 svc#33（反汇编实测）：
        //     str  w8,[tp16+8]      ; = 1
        //     ldr  w0,[0xb9c59c]    ; session
        //     bl   svc#33
        //     cbnz w0, error        ; 必须返回 0
        //     ldr  w8,[tp16+8]
        //     cbnz w8, error        ; ★ 必须变回 0
        // 也就是说，**SendSyncRequest 的实现必须把 [tp16+8] 清 0**
        // （真机上这由内核在完成 IPC 时写回「无挂起中断」）。
        // 我们以前只 return 0，[tp16+8] 永远是 1 ⇒ 必走 error ⇒ abort("stdio")。
        unsigned long long tp16 = 0;
        unsigned int pre0 = 0, pre8 = 0, post8 = 0;
        __asm__ __volatile__("mrs %0, TPIDRRO_EL0" : "=r"(tp16));
        // 只读 TLS 页是我们自己映射的，可写
        if (tp16)
        {
            memcpy(&pre0, (void *)(uintptr_t)(tp16 + 0), 4);
            memcpy(&pre8, (void *)(uintptr_t)(tp16 + 8), 4);
            // 清「挂起中断/待处理」位：真机 IPC 完成后为 0
            unsigned int zero = 0;
            memcpy((void *)(uintptr_t)(tp16 + 8), &zero, 4);
            memcpy(&post8, (void *)(uintptr_t)(tp16 + 8), 4);
        }
        ZLOGI("svc#33 SendSyncRequest session=%#llx  tp16=%p  [tp16+0]=%#x  [tp16+8] %#x -> %#x",
              (unsigned long long)(unsigned int)a0, (void *)(uintptr_t)tp16,
              pre0, pre8, post8);
        // IPC 应答：sm 的 GetService 之类需要往缓冲区写回复。
        // 目前最小实现：只保证结果码 0 + 清挂起位，让初始化流程能继续。
        return 0;
    }
    case 34: // SendSyncRequestWithUserBuffer(buf=x0, size=x1, session=x2)
    case 35: // SendAsyncRequestWithUserBuffer(out_handle=x0, buf=x1, size=x2, session=x3) → W1"""
assert s.count(old33) == 1, s.count(old33)
s = s.replace(old33, new33)

io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('za_horizon.c patched: svc#31 取证 + svc#33 清 [tp16+8]')
