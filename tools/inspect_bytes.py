import re
p = r"D:\feiniukexinhome\Code\pokeLegza-and\app\native\za_guest.c"
b = open(p, "rb").read()
i = b.find(b"sev.sigev_signo")
print(repr(b[i-200:i+500]))
