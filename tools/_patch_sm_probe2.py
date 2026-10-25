# -*- coding: utf-8 -*-
"""修正 svc#33 探针：不要用 `mrs TPIDRRO_EL0`（客机走到那里已被改写，
真实寄存器本来就是 0，探针读到 0 毫无意义）。

正确的读法：用**我们自己的只读 TLS 页**（za_ro_tls_page，定义在 za_sdk.c），
客机所有被改写的 `mrs` 都指向它 ⇒ 要看客机看到的内容，就得读这个页。

同时把关键判断点补齐：
  · [ro+0x0]  / [ro+0x8]（客机写完、svc 之后要求 +8 == 0）
  · 0xb9c598 计数 / 0xb9c59c 会话句柄（SDK bss，需通过 za_sdk_base 读）
"""
import io

P = 'app/native/za_horizon.c'
s = io.open(P, encoding='utf-8').read()

old = """        unsigned long long tp16 = 0;
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
              pre0, pre8, post8);"""

new = """        // ⚠ 不能用 `mrs TPIDRRO_EL0` 探测：客机里 123 处 `mrs` 已全部改写成
        //   `adrp` 指向我们的只读 TLS 页；真实 TPIDRRO_EL0 在这个进程里本来就是 0
        //   （安卓 bionic 不设置它）⇒ 用 mrs 探到 0 是「探针错」而不是「客机错」。
        //   要看客机看到的内容，必须读**我们自己那一页**。
        unsigned long long ro = za_ro_tls_page;   // 由 za_sdk.c 在装载时填
        unsigned int pre0 = 0, pre8 = 0, post8 = 0;
        if (ro)
        {
            memcpy(&pre0, (void *)(uintptr_t)(ro + 0), 4);
            memcpy(&pre8, (void *)(uintptr_t)(ro + 8), 4);
            // 真机上 IPC 完成后内核会把这个「挂起」位置 0；我们替它清，
            // 否则客机在 sdk+0x153f18 的 `cbnz w8` 必然走 abort("stdio")。
            unsigned int zero = 0;
            memcpy((void *)(uintptr_t)(ro + 8), &zero, 4);
            memcpy(&post8, (void *)(uintptr_t)(ro + 8), 4);
        }
        // SDK bss 里的 sm 计数/会话句柄（反汇编 0x153e54 / 0x153efc 得来）
        unsigned int sm_cnt = 0, sm_sess = 0;
        if (za_sdk_base)
        {
            memcpy(&sm_cnt, (void *)(uintptr_t)(za_sdk_base + 0xb9c598), 4);
            memcpy(&sm_sess, (void *)(uintptr_t)(za_sdk_base + 0xb9c59c), 4);
        }
        ZLOGI("svc#33 SendSyncRequest session=%#llx  ro=%p [ro+0]=%#x [ro+8] %#x->%#x  "
              "sm.cnt=%u sm.sess=%u",
              (unsigned long long)(unsigned int)a0, (void *)(uintptr_t)ro,
              pre0, pre8, post8, sm_cnt, sm_sess);"""

assert s.count(old) == 1, s.count(old)
s = s.replace(old, new)
io.open(P, 'w', encoding='utf-8', newline='').write(s)
print('svc#33 probe fixed -> read own RO TLS page')
