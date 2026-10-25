# -*- coding: utf-8 -*-
"""把 d2r-android 的 NVN 名字表/调用点表/原型搬进本项目做参考。

d2r-and 的这些资产是 MIT 许可（见 d2r-android/LICENSE），
来源：d2r-and/d2r-android/dm/gfx/nvn/{names.txt,nvn_slots.tsv,nvn_protos.h}

Z-A 也是 Switch 1（同一代 NVN），所以 names.txt 里的 523 个 NVN 名字
**大概率通用**，可以直接当「我们要实现哪些 NVN 函数」的清单用。
"""
import os, shutil

DST = r"D:\feiniukexinhome\Code\pokeLegza-and\work\reference\nvn"
SRC = r"D:\feiniukexinhome\Code\d2r-and\d2r-android\dm\gfx\nvn"

os.makedirs(DST, exist_ok=True)
for name in ("names.txt", "nvn_slots.tsv", "nvn_protos.h"):
    s = os.path.join(SRC, name)
    d = os.path.join(DST, name)
    shutil.copyfile(s, d)
    print("copied %-16s %8d bytes" % (name, os.path.getsize(d)))

n = 0
with open(os.path.join(DST, "names.txt"), "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        if line.strip():
            n += 1
print("names.txt 里 %d 个 NVN 名字" % n)

# 顺带把 d2r 的 NVN 图形层源码位置记下来（供以后移植时对照）
NOTES = """# d2r-android 的 NVN 参考资产

来源：`d2r-and/d2r-android/dm/gfx/nvn/`（MIT，见 d2r-android/LICENSE）
上游：`jhaizhou-ops/d2r-mobile`（d2r-android 是它的安卓移植）

| 文件 | 大小 | 作用 |
|---|---|---|
| `names.txt` | 16 KB | 523 个 NVN 名字（客机按名字取址的目录） |
| `nvn_slots.tsv` | 23.5 KB | 哪些名字在 main 里有调用点（216 个） |
| `nvn_protos.h` | 47 KB | 全部原型（编译期签名检查） |

## 关键机制（我们要照抄的）

Switch 上游戏**只导入一个** NVN 符号 `nvnBootstrapLoader`，
其余 NVN 函数都通过它**按名字**取址。宿主**强制接管**这个导入
（d2r 的 `HLE_FORCE` 宏），SDK 自带的 NVN 驱动**一条指令都不执行**。

我们的等价物：`app/native/za_guest.c` 的 `za_host_syms[]` 宿主符号表 +
`za_resolve()` 里「宿主表优先」的顺序（已经天然等价于 `HLE_FORCE`）。

## 安卓侧要用的回放层（Metal ⇒ Vulkan）

| d2r-mobile（iOS/Mac） | d2r-android（我们要抄的） |
|---|---|
| `dm/gfx/nvn/nvn_mtl.m` 600 KB | `dm/android/native/nvn_vulkan.c` 109 KB + 13 个 `.inc` |

Metal 侧 600 KB 的回放层在安卓版被换成了 Vulkan 版，
接口层（`hle_nvn.c` 123 KB / `nvn_thunks.S` 157 KB / `nvn_obj.h` 17.5 KB）两边共用。

## 其它可借鉴的

- `dm/android/native/runtime.c`：**每线程**一份 TLS 块 + TLR（0x200）+ 当前线程对象
  ⇒ 我们现在是「所有客机线程共享一块 TLS 变量区」，应照它改成每线程一份。
- `dm/android/native/frontend_activity.c` 80 KB：安卓前端（触屏/UI/生命周期）。
- `dm/host/thread.c`：TLR 只填 `TLR[0x1f8]`（当前线程对象），其余留 0
  ⇒ 我们的 TLR 页多填了 8 个指针槽，口径应与之对齐。
- `dm/tools/patch_nso.py`：改写器 + **CUTS**（按构建号逐条断言原字节）与
  **OBS**（观测门：一条指令换成「进观测回调→执行原指令→跳回」，诊断零运行时改码）。
"""
with open(os.path.join(DST, "README.md"), "w", encoding="utf-8", newline="\n") as f:
    f.write(NOTES)
print("wrote README.md")
