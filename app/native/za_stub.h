// 自动生成：tools/gen_stubs.py
#ifndef ZA_STUB_H
#define ZA_STUB_H
#define ZA_STUB_COUNT 1001
#define ZA_IMPORT_COUNT 1001
// 桩被调用时上报符号名（索引对应 za_imports[] 的下标）。
void za_stub_hit(unsigned index);
// 宿主函数调用前后临时切换 TPIDR_EL0（客机用自己的线程上下文，宿主用 bionic 的）。
void za_tls_enter(void);
void za_tls_leave(void);
extern const void *const za_stub_table[ZA_STUB_COUNT];
#endif
