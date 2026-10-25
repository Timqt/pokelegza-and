p = r"D:\feiniukexinhome\Code\pokeLegza-and\app\native\za_guest.c"
with open(p, "rb") as f:
    b = f.read()

bad = b"    // \xef\xbf\xbd\xef\xbf\xbd bit32 "
good = b"    // bit32 "
if bad in b:
    b = b.replace(bad, good, 1)
    with open(p, "wb") as f:
        f.write(b)
    print("fixed mojibake")
else:
    print("not found")
