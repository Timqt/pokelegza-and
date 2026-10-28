# 下一步：nn::async Job 队列探针（未完成）

## 目标
判定停摆是否由「作业已入队但从未被任何线程执行」造成。

## 探针位置（SDK 导出符号表确认）
| 语义 | SDK 偏移 | 大小 |
|---|---|---|
| 入队 ExecutionScheduler::Enqueue | sdk+0x8d2c0 | 0x118 |
| 出队并执行 DequeueAndCall | sdk+0x8d550 | 0x1c0 |
| 公共入口 EnqueueExecutable | sdk+0x90250 | 0x8c |

## 实现步骤
1. 读出两处首指令（大概率 stp x29,x30,[sp,#-N]!），各存进宿主槽位 za_async_orig[0..1]；
2. 首指令改写为 b <桩>；桩区用 sdk+0xc70000（已有 svc 门桩，b 偏移 +0x3a2d40，在 ±128MB 内）；
3. 桩：取计数器地址 -> +1 -> 写回 -> 执行原指令 -> b 回入口+4；
4. 计数器放宿主 .bss：volatile unsigned long za_async_enq, za_async_exec；
5. 在 za_guest.c 的停摆快照里打印两者差值。

## 判定
- 差值持续 > 0 且不回落 => 存在已入队未执行的作业（停摆根因）；
- 差值恒为 0 => 调度正常，卡点在别处。

## 注意
- 改 SDK 映像前需 mprotect(RWX)，改后 __builtin___clear_cache；svc 门/断言探针已有同样流程可照抄。
- 只加计数、不改语义，风险低；b 偏移算错会立刻崩，先小轮次验证。
