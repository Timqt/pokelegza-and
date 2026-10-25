import re
import shutil

p = r'app/native/za_guest.c'
shutil.copyfile(p, p + '.bak')          # 先备份（吃过一次亏）

s = open(p, encoding='utf-8').read()

# 1) 加十进制小工具（寄存器号要按十进制打，之前用 hex 出来是 x0x0）
dec = (
    "static char *za_put_dec(char *p, unsigned long long v)\n"
    "{\n"
    "    char tmp[24];\n"
    "    int n = 0;\n"
    "    if (!v) { *p++ = '0'; return p; }\n"
    "    while (v) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }\n"
    "    while (n) *p++ = tmp[--n];\n"
    "    return p;\n"
    "}\n\n"
)
anchor = "static char *za_put_hex(char *p, unsigned long long v)"
if "za_put_dec" not in s:
    assert anchor in s
    s = s.replace(anchor, dec + anchor, 1)
    print("added za_put_dec")

# 2) 寄存器号改为十进制
old = '                p = za_put_str(p, " x");\n                p = za_put_hex(p, (unsigned long long)i);\n                p = za_put_str(p, "=");'
new = '                p = za_put_str(p, " x");\n                p = za_put_dec(p, (unsigned long long)i);\n                p = za_put_str(p, "=");'
if old in s:
    s = s.replace(old, new, 1)
    print("register index -> decimal")
else:
    print("WARN: register print pattern not found")

open(p, 'w', encoding='utf-8', newline='').write(s)
print("written")
