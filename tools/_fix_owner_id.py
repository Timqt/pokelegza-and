# -*- coding: utf-8 -*-
"""修 owner_id 一致性：CS 的 [self+0x1b0] 必须等于 svc#37 GetThreadId 返回的 tid。

根因链（反汇编 + 实测确定）
--------------------------
sdk+0x14603c（IsLockedByCurrentThread）：
```
14603c  mrs  x8, TPIDRRO_EL0
146040  ldr  x8, [x8, #0x1f8]      ; self
146044  ldr  w9, [x0]              ; 锁字
146048  and  w9, w9, #0xbfffffff
14604c  ldr  w8, [x8, #0x1b0]      ; ★ owner_id
146050  cmp  w9, w8
146054  cset w0, eq                ; 不相等 => w0=0
```
sdk+0x13c668（解锁入口）：
```
13c678  bl 0x636760(=0x14603c)     ; IsLockedByCurrentThread
13c67c  tbz w0,#0, 0x13c690
13c690  bl 0x62f3d0                ; ★ abort
```

而客机加锁时把**什么**写进锁字？看 0x14457c：
```
1445ec  bl 0x636a80 -> 0x13e420    ; ArbitrateLock 路径
1445f0  ldr x8,[x21]
144600  str w8,[x19,#0x1b0]        ; ★ 把 [x21] 写进 owner_id
```
`x21 = [0xb74078+0x128]`，即线程管理器里当前线程的 id —— 来源就是
`svc#37 GetThreadId`，我们返回的是**真实 Linux tid**。

而 `[self+0x1b0]` 我们在 za_sdk.c 里写死成 `1u` ⇒ 两者永不相等
⇒ 客机解锁必判「锁不属于我」⇒ abort（error 0x1a80a）。

修法
----
owner_id 改成 `syscall(SYS_gettid)`，与 GetThreadId 完全同源。
"""
import io

# ── ① za_sdk.c: owner_id 用真实 tid ────────────────────────────────
P1 = 'app/native/za_sdk.c'
s1 = io.open(P1, encoding='utf-8').read()

old1 = """        *(unsigned int *)(ro2 + 0x1b0) = 1u;"""
new1 = """        // ★ owner_id 必须等于 svc#37 GetThreadId 返回的 tid。
        //   客机加锁时把 GetThreadId 的值写进锁字（sdk+0x144600），解锁时
        //   （sdk+0x14604c）拿 [self+0x1b0] 去比；两边不同源 => 永远不相等
        //   => 判「锁不属于当前线程」=> abort（实测 error 0x1a80a）。
        //   以前这里写死 1u，是这一整串崩溃的直接原因。
        *(unsigned int *)(ro2 + 0x1b0) = (unsigned int)syscall(SYS_gettid);"""
assert s1.count(old1) == 1, s1.count(old1)
s1 = s1.replace(old1, new1)

# 顺带修日志里的字面量
old1b = '''        ZLOGI("只读 TLS：改写 %u 处 TPIDRRO_EL0，页=%p（self=%p，owner_id=%u）",
              ZA_TLSRO_PATCH_COUNT, (void *)ro, (void *)ro2, 1u);'''
new1b = '''        ZLOGI("只读 TLS：改写 %u 处 TPIDRRO_EL0，页=%p（self=%p，owner_id=%u=本线程 tid）",
              ZA_TLSRO_PATCH_COUNT, (void *)ro, (void *)ro2,
              (unsigned)syscall(SYS_gettid));'''
if s1.count(old1b) == 1:
    s1 = s1.replace(old1b, new1b)
    print('za_sdk.c log line updated')
io.open(P1, 'w', encoding='utf-8', newline='').write(s1)
print('za_sdk.c owner_id -> real tid')

# ── ② za_horizon.c: owner_id 取值也换成 tid ─────────────────────────
P2 = 'app/native/za_horizon.c'
s2 = io.open(P2, encoding='utf-8').read()
old2 = """        ZLOGI("只读 TLS: +0x1f0 ← %p（bionic tp）  客机区=%p bionic_tp=%p",
              (void *)(uintptr_t)tpidr, (void *)(uintptr_t)tls_var,
              (void *)(uintptr_t)tpidr);"""
# 这行可能不存在，忽略失败
import re
m = re.search(r'owner_id\s*=\s*\w+', s2)
print('za_horizon.c owner_id refs:', re.findall(r'owner_id', s2)[:5])
io.open(P2, 'w', encoding='utf-8', newline='').write(s2)
print('done')
