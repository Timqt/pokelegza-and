import struct
p = r"D:\feiniukexinhome\Code\pokeLegza-and\work\nso_32848007\text.bin"
b = open(p, "rb").read()
n = len(b) // 4
w = struct.unpack_from("<%dI" % n, b, 0)
i = 0x636ba0 // 4
w0, w1, w2, w3 = w[i], w[i+1], w[i+2], w[i+3]
print("w0=%08x w1=%08x w2=%08x w3=%08x" % (w0, w1, w2, w3))
print("adrp ok:", (w0 & 0x9F000000) == 0x90000000)
print("ldr  ok:", (w1 & 0xFFC00000) == 0xF9400000)
print("add  ok:", (w2 & 0xFFE0001F) == 0x91000000, hex(w2 & 0xFFE0001F))
print("br   ok:", (w3 & 0xFFFFFC1F) == 0xD61F0000, hex(w3 & 0xFFFFFC1F))
print("rn1=%d adrp_rd=%d" % ((w1 >> 5) & 0x1F, w0 & 0x1F))
print("br_rn=%d ldr_rt=%d" % ((w3 >> 5) & 0x1F, w1 & 0x1F))
print("off=%#x add_off=%#x" % (((w1 >> 10) & 0xFFF) * 8, (w2 >> 10) & 0xFFF))
