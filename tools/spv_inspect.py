"""解析 SPIR-V：统计 OpEntryPoint 的接口变量、输入/输出类型、Uniform 常量缓冲、纹理。

用法: python tools/spv_inspect.py <spv 文件> [...]
"""
import sys, struct, collections

OP_NAMES = {
    15: "OpEntryPoint", 16: "OpExecutionMode", 19: "OpTypeVoid", 20: "OpTypeBool",
    21: "OpTypeInt", 22: "OpTypeFloat", 23: "OpTypeVector", 24: "OpTypeMatrix",
    25: "OpTypeImage", 26: "OpTypeSampler", 27: "OpTypeSampledImage",
    28: "OpTypeArray", 29: "OpTypeRuntimeArray", 30: "OpTypeStruct",
    32: "OpTypePointer", 33: "OpTypeFunction", 43: "OpConstant", 44: "OpConstantComposite",
    59: "OpVariable", 71: "OpDecorate", 72: "OpMemberDecorate",
    25 + 1000: "?", 12: "OpExtInstImport", 11: "OpExtInst", 5: "OpName",
}

STORAGE = {0: "UniformConstant", 1: "Input", 2: "Uniform", 3: "Output", 4: "Workgroup",
           5: "CrossWorkgroup", 6: "Private", 7: "Function", 8: "Generic",
           9: "PushConstant", 10: "AtomicCounter", 11: "Image", 12: "StorageBuffer"}


def words(path):
    b = open(path, "rb").read()
    return list(struct.unpack_from("<%dI" % (len(b) // 4), b, 0))


def parse(code):
    out = {"entry": [], "vars": {}, "types": {}, "names": {}}
    i = 5
    while i < len(code):
        w = code[i]
        ln = w >> 16
        op = w & 0xFFFF
        if ln == 0:
            break
        ops = code[i + 1:i + ln]
        if op == 15:      # OpEntryPoint: ExecutionModel, EntryPoint, Interface...
            name = decode_str(ops, 1)
            out["entry"].append((ops[0], name, ops[2:]))
        elif op == 5:     # OpName
            out["names"][ops[0]] = decode_str(ops, 1)
        elif op == 59:    # OpVariable: ResultType, ResultId, StorageClass, Initializer
            out["vars"][ops[1]] = {"type": ops[0], "storage": ops[2]}
        elif op in (19, 20, 21, 22, 23, 25, 26, 27, 28, 30, 32, 33):
            out["types"][ops[0]] = (op, ops[1:])
        i += ln
    return out


def decode_str(ops, idx):
    # 字串以字为单位，末尾 0 填充
    s = ""
    j = idx
    while j < len(ops):
        v = ops[j]
        for k in range(4):
            c = (v >> (8 * k)) & 0xFF
            if c == 0:
                return s
            s += chr(c)
        j += 1
    return s


def main():
    for path in sys.argv[1:]:
        code = words(path)
        p = parse(code)
        print("\n=== %s ===" % path.split("\\")[-1])
        for model, name, iface in p["entry"]:
            mname = {0: "Vertex", 1: "TessCtrl", 2: "TessEval", 3: "Geometry",
                     4: "Fragment", 5: "GLCompute"}.get(model, str(model))
            print("  OpEntryPoint %s  model=%s  接口变量 %d 个" % (name, mname, len(iface)))
        cnt = collections.Counter()
        for vid, v in p["vars"].items():
            cnt[STORAGE.get(v["storage"], v["storage"])] += 1
        print("  变量按存储类: " + ", ".join("%s=%d" % (k, v) for k, v in cnt.most_common()))
        # 图像/采样器类型
        imgs = [(t, o) for t, (op, o) in p["types"].items() if op in (25, 27)]
        for t, o in imgs[:8]:
            nm = p["names"].get(t, "?")
            if op == 25:
                # OpTypeImage: sampledType, dim, depth, arrayed, ms, sampled, format, access
                print("    图像 %-28s dim=%d arrayed=%d sampled=%d fmt=%d" % (nm[:28], o[1], o[3], o[5], o[6]))
            else:
                print("    采样器组合 %-24s image=%d" % (nm[:24], o[0]))
        # 输入/输出变量
        ins = [v for v in p["vars"].values() if v["storage"] == 1]
        outs = [v for v in p["vars"].values() if v["storage"] == 3]
        print("  Input 变量 %d 个, Output 变量 %d 个" % (len(ins), len(outs)))


if __name__ == "__main__":
    main()
