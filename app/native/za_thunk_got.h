// 自动生成：tools/scan_thunk_got.py —— 别手改
// SDK text 里所有「导入跳板」(adrp/ldr [GOT]/br x17) 的 GOT 槽。
// 槽值为 0 ⇒ `br x17` 跳到 0 ⇒ 客机 pc=0 跳空。
#ifndef ZA_THUNK_GOT_H
#define ZA_THUNK_GOT_H

#define ZA_THUNK_GOT_COUNT 0

static const unsigned int za_thunk_got[] = {
};

#endif
