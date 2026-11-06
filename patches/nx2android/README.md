# nx2android 本地补丁

上游：`https://github.com/shirai91/nx2android` 主分支，本地未提交改动，按天导出为
`local-patches-YYYY-MM-DD.patch`（`git apply` 到上游源码根目录）。

| 补丁 | 内容 |
|---|---|
| `local-patches-2026-11-04.patch` | 零拷贝 fd 修复、脏页策略、present A/B、porter 流式落盘（见下表） |
| `local-patches-2026-11-05.patch` | Z-A 黑屏排查的诊断开关（`DM_VK_DUP_DRAWS` / `DM_VK_FORCE_DW` / `DM_VK_TRACE_*` / `DM_NVN_ERLOG` / pass dump 深度解码等）+ Z-A profile 打开 `render_cond` |
| `local-patches-2026-11-06.patch` | `DM_VK_TRACE_COPY`（追 COPY_T2T，尤其是主机会跳过的 depth↔colour blit，ScarletNX #444）、`DM_VK_TRACE_PROG`（按 pass 打每个 program 的 frag/vert shader key） |

## 2026-11-04 补丁明细

| 文件 | 改动 | 作用 |
|---|---|---|
| `nxnative/dm/android/gfx_vk_core.c` | `ahb_buf_fd()`：按 `fstat` 的 `st_size == 池大小` 选 dma-buf fd；`pool_zero_copy()` / `vk_pool_remap_ro()` 不再用 `fds[0]`，并补齐零拷贝各步诊断日志 | **核心修复**。MTK MT6991（Mali-G925）的 AHardwareBuffer native handle 有 3 个 fd，`fd[0]` 是 size 0 的只读元数据，mmap 必失败；此前 771 MB 的池全部退化为每帧双向 memcpy（375 ms 尾巴） |
| `nxnative/dm/gfx/nvn/nvn_dirty.c` | `DM_NO_DIRTY`（诊断）、`DM_DIRTY_PASSIVE=N`（缺页 N 次后放弃保护） | 脏页策略 A/B；默认 20000，Z-A 上用 500 有收益 |
| `nxnative/dm/android/gfx_vk_present.c` | `DM_VK_IMAGES=N`、`DM_VK_PRESENT=fifo\|mailbox\|immediate` | present 链路 A/B（结论：对 Z-A 无影响） |
| `porter/pipeline.py` | `device_oodle()` 流式落盘 | 原实现把 5.0 GB 的 `job.out` 整体读进内存，32 GB 机器 `MemoryError` |

实测结果见 `docs/ZA-Mali-实测报告.md` §9。

| 文件 | 改动 | 作用 |
|---|---|---|
| `nxnative/dm/android/gfx_vk_core.c` | `ahb_buf_fd()`：按 `fstat` 的 `st_size == 池大小` 选 dma-buf fd；`pool_zero_copy()` / `vk_pool_remap_ro()` 不再用 `fds[0]`，并补齐零拷贝各步诊断日志 | **核心修复**。MTK MT6991（Mali-G925）的 AHardwareBuffer native handle 有 3 个 fd，`fd[0]` 是 size 0 的只读元数据，mmap 必失败；此前 771 MB 的池全部退化为每帧双向 memcpy（375 ms 尾巴） |
| `nxnative/dm/gfx/nvn/nvn_dirty.c` | `DM_NO_DIRTY`（诊断）、`DM_DIRTY_PASSIVE=N`（缺页 N 次后放弃保护） | 脏页策略 A/B；默认 20000，Z-A 上用 500 有收益 |
| `nxnative/dm/android/gfx_vk_present.c` | `DM_VK_IMAGES=N`、`DM_VK_PRESENT=fifo\|mailbox\|immediate` | present 链路 A/B（结论：对 Z-A 无影响） |
| `porter/pipeline.py` | `device_oodle()` 流式落盘 | 原实现把 5.0 GB 的 `job.out` 整体读进内存，32 GB 机器 `MemoryError` |

实测结果见 `docs/ZA-Mali-实测报告.md` §9。
