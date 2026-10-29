// BNSH → SPIR-V 直译工具（Z-A）。
//
// 思路：不自己逆 BNSH 布局，而是让 Ryujinx.Graphics.Shader 自己去解析——
//   IGpuAccessor.GetCode(addr, size) 直接映射到 BNSH 文件的字节，
//   Translator.CreateContext(sphOffset, accessor, ...) 就会从该偏移解析 SPH、
//   读出 stage（顶点/片元/计算）、解 Maxwell 指令、翻成 SPIR-V。
//
// 用法：bnsh_xlate <BNSH 文件> <输出目录> [--c1 <hex 文件>] [--limit N]
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using Ryujinx.Common.Memory;
using Ryujinx.Graphics.Shader;
using Ryujinx.Graphics.Shader.Translation;

class Accessor : IGpuAccessor
{
    readonly byte[] _data;
    readonly int _c1Base;      // c1 常数段在 BNSH 里的偏移（-1 = 无）
    readonly int _c1Len;
    readonly int _codeEnd;     // 本着色器代码段结束位置（下一个 SPH 之前）
    readonly List<string> _notes = new();
    public readonly List<string> Gets = new();   // 记录 Ryujinx 取字节的位置与长度
    public int MaxAddr;                        // 记录 Ryujinx 请求过的最大地址
    int _binding = 1;

    public Accessor(byte[] data, int c1Base, int c1Len, int codeEnd) { _data = data; _c1Base = c1Base; _c1Len = c1Len; _codeEnd = codeEnd; }
    public List<string> Notes => _notes;

    public uint ConstantBuffer1Read(int offset)
    {
        if (_c1Base >= 0 && offset >= 0 && offset + 4 <= _c1Len)
            return BitConverter.ToUInt32(_data, _c1Base + offset);
        _notes.Add($"c1 读越界 +{offset:X}");
        return 0;
    }

    public SetBindingPair CreateConstantBufferBinding(int index) => new(0, _binding++);
    public SetBindingPair CreateImageBinding(int count, bool isBuffer) { int b = _binding; _binding += count; return new(0, b); }
    public SetBindingPair CreateStorageBufferBinding(int index) => new(0, _binding++);
    public SetBindingPair CreateTextureBinding(int count, bool isBuffer) { int b = _binding; _binding += count; return new(0, b); }
    public ReadOnlySpan<ulong> GetCode(ulong address, int minimumSize)
    {
        int off = (int)address;
        Gets.Add($"GetCode(addr=0x{off:X}, minSize=0x{minimumSize:X})");
        if (off > MaxAddr) MaxAddr = off;
        if (off < 0 || off >= _data.Length) return ReadOnlySpan<ulong>.Empty;
        int end = Math.Min(_data.Length, _codeEnd);
        int len = Math.Min(minimumSize, end - off);
        // MemoryMarshal.Cast 要求长度是元素大小的整数倍，否则抛 ArgumentException
        len -= len % sizeof(ulong);
        if (len <= 0) return ReadOnlySpan<ulong>.Empty;
        return MemoryMarshal.Cast<byte, ulong>(new ReadOnlySpan<byte>(_data, off, len));
    }
    public int QuerySamplerArrayLengthFromPool() => 32;
    public int QueryTextureArrayLengthFromBuffer(int slot) => 32;
    public int QueryTextureArrayLengthFromPool() => 32;
    public SamplerType QuerySamplerType(int handle, int cbufSlot = -1) => SamplerType.Texture2D;
    public TextureFormat QueryTextureFormat(int handle, int cbufSlot = -1) => TextureFormat.R8G8B8A8Unorm;
    public int QueryComputeLocalSizeX() => 1;
    public int QueryComputeLocalSizeY() => 1;
    public int QueryComputeLocalSizeZ() => 1;
    public int QueryComputeSharedMemorySize() => 0;
    public GpuGraphicsState QueryGraphicsState()
    {
        Array32<AttributeType> attr = default; Array8<AttributeType> fout = default;
        return new GpuGraphicsState(false, InputTopology.Triangles, false, TessPatchType.Triangles, TessSpacing.EqualSpacing,
            false, false, false, false /* 深度 0..1 */, false, 1f, AlphaTestOp.Always, 0f, attr, false, fout, false,
            false /* 不做 Y 取反 */, true /* 原点左上 */, false);
    }
    public int QueryHostSubgroupSize() => 32;
    public bool QueryHostSupportsShaderFloat64() => false;
    public bool QueryHostSupportsFragmentShaderInterlock() => false;
    public bool QueryHostSupportsTextureShadowLod() => true;
    public bool QueryHostReducedPrecision() => false;
}

class Program
{
    static readonly byte[] SphMagic = { 0x78, 0x56, 0x34, 0x12 };  // SPH 魔数（小端 0x12345678）

    static Type _shType;
    static ConstructorInfo _shCtor;

    static string TranslatorBinPath => Path.Combine(AppContext.BaseDirectory, "Ryujinx.Graphics.Shader.dll");

    // 列出 Translator / TranslatorContext / ShaderHeader 的可写属性与全部方法，找「改写阶段」的入口
    static int ProbeApi(string dllPath)
    {
        var asm = Assembly.LoadFrom(dllPath);
        foreach (string tn in new[] {
            "Ryujinx.Graphics.Shader.Translation.Translator",
            "Ryujinx.Graphics.Shader.Translation.TranslatorContext",
            "Ryujinx.Graphics.Shader.Translation.ShaderHeader" })
        {
            var t = asm.GetType(tn);
            if (t == null) { Console.WriteLine("MISSING " + tn); continue; }
            Console.WriteLine("\n== " + t.FullName);
            foreach (var p in t.GetProperties(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static))
            {
                var g = p.GetGetMethod(true); var s = p.GetSetMethod(true);
                string gs = g == null ? "-" : (g.IsPublic ? "public" : g.IsAssembly ? "internal" : g.IsPrivate ? "private" : "other");
                string ss = s == null ? "无 setter" : (s.IsPublic ? "public" : s.IsAssembly ? "internal" : s.IsPrivate ? "private" : "other");
                Console.WriteLine($"   prop {p.PropertyType.Name} {p.Name}  get={gs} set={ss}");
            }
            foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            {
                if (m.IsSpecialName) continue;
                Console.WriteLine($"   method {(m.IsPublic ? "public" : m.IsAssembly ? "internal" : "private")} {m.ReturnType.Name} {m.Name}(" +
                    string.Join(", ", m.GetParameters().Select(pp => pp.ParameterType.Name + " " + pp.Name)) + ")");
            }
            foreach (var f in t.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static))
                Console.WriteLine($"   field {(f.IsPublic ? "public" : f.IsAssembly ? "internal" : "private")} {f.FieldType.Name} {f.Name}");
        }
        return 0;
    }

    // 逐字节扰动，定位 Ryujinx 的 ShaderHeader 到底从哪个偏移读哪个字段
    static int Probe(string path)
    {
        byte[] data = File.ReadAllBytes(path);
        var sphOffsets = new List<int>();
        for (int i = 0; i + 4 <= data.Length; i++)
            if (data[i] == SphMagic[0] && data[i + 1] == SphMagic[1] && data[i + 2] == SphMagic[2] && data[i + 3] == SphMagic[3])
                sphOffsets.Add(i);
        Console.WriteLine($"探测 {Path.GetFileName(path)}：{sphOffsets.Count} 个 SPH");

        var asm = typeof(Translator).Assembly;
        _shType = asm.GetType("Ryujinx.Graphics.Shader.Translation.ShaderHeader");
        _shCtor = _shType.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                           .FirstOrDefault(c => c.GetParameters().Length == 2);
        if (_shType == null || _shCtor == null) { Console.WriteLine("找不到 ShaderHeader"); return 1; }

        string[] fields = { "Stage", "SphType", "Version", "SassVersion", "MrtEnable", "OmapTargets", "OmapDepth", "KillsPixels" };

        foreach (int sph in sphOffsets)
        {
            // 真值阶段（D2R 实测规则：code+0x30 bits10..13，1=vs / 5=ps）
            int trueWord = (int)BitConverter.ToUInt32(data, sph + 0x30);
            int trueStage = (trueWord >> 10) & 0xF;
            var baseHdr = Read(data, sph, sphOffsets, fields);
            var getLog = new List<string>();
            Read(data, sph, sphOffsets, fields, getLog);
            Console.WriteLine($"\nSPH@0x{sph:X}  真值阶段字=0x{trueWord:X8} -> {(trueStage == 1 ? "vs 顶点" : trueStage == 5 ? "ps 片元" : "?")}");
            Console.WriteLine($"  Ryujinx 基准: {baseHdr}");
            Console.WriteLine("  Ryujinx 取字节请求: " + string.Join(" | ", getLog.Distinct().Take(8)));

            var changes = new List<string>();
            for (int b = 0; b < 0x100 && sph + b < data.Length; b++)
            {
                byte[] patched = (byte[])data.Clone();
                patched[sph + b] ^= 0xFF;
                string h;
                try { h = Read(patched, sph, sphOffsets, fields); }
                catch (Exception e) { h = "EX:" + e.GetType().Name; }
                if (h != baseHdr)
                    changes.Add($"  +0x{b:X2} -> {h}");
            }
            if (changes.Count == 0) Console.WriteLine("  （前 0x100 字节内无字段受扰动影响）");
            else { Console.WriteLine($"  受扰动影响的偏移 {changes.Count} 个："); foreach (var c in changes.Take(40)) Console.WriteLine(c); }
        }
        return 0;
    }

    static string Read(byte[] data, int sph, List<int> sphOffsets, string[] fields, List<string> gets = null)
    {
        int codeEnd = sphOffsets.Count > 0 ? (sphOffsets.FirstOrDefault(x => x > sph) is int n && n > 0 ? n : data.Length) : data.Length;
        var acc = new Accessor(data, -1, 0, codeEnd);
        var h = _shCtor.Invoke(new object[] { acc, (ulong)sph });
        if (gets != null) gets.AddRange(acc.Gets);
        var sb = new StringBuilder();
        foreach (var f in fields)
        {
            var p = _shType.GetProperty(f, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            object v = p?.GetValue(h);
            sb.Append($"{f}={v} ");
        }
        return sb.ToString().Trim();
    }


    // 资源反射：与 d2r 的 dmsh_xlate 的 <key>.res.json 同形状（cbufs/sbufs/textures/images），
    // 供 dm 的 dmsh_vk.export → pack_game_shaders.pack 出 XGS1 着色器包。
    // Resource reflection, same shape as dmsh_xlate's res.json; consumed by
    // dmsh_vk.export → pack_game_shaders.pack to build the XGS1 bundle.
    static void WriteRes(string path, ShaderProgram prog, string stage)
    {
        var root = new System.Text.Json.Nodes.JsonObject
        {
            ["stage"] = stage,
            ["cbufs"] = new System.Text.Json.Nodes.JsonArray(),
            ["sbufs"] = new System.Text.Json.Nodes.JsonArray(),
            ["textures"] = new System.Text.Json.Nodes.JsonArray(),
            ["images"] = new System.Text.Json.Nodes.JsonArray(),
        };
        var info = prog.Info;
        foreach (var b in info.CBuffers)
            root["cbufs"]!.AsArray().Add(new System.Text.Json.Nodes.JsonObject { ["binding"] = b.Binding, ["slot"] = b.Slot });
        foreach (var b in info.SBuffers)
            root["sbufs"]!.AsArray().Add(new System.Text.Json.Nodes.JsonObject {
                ["binding"] = b.Binding, ["slot"] = b.Slot, ["cb_slot"] = b.SbCbSlot,
                ["cb_offset"] = b.SbCbOffset, ["flags"] = (int)b.Flags });
        foreach (var t in info.Textures)
            root["textures"]!.AsArray().Add(new System.Text.Json.Nodes.JsonObject {
                ["binding"] = t.Binding, ["type"] = (int)t.Type, ["format"] = t.Format.ToString(),
                ["cbuf_slot"] = t.CbufSlot, ["handle"] = t.HandleIndex, ["array"] = t.ArrayLength,
                ["separate"] = t.Separate, ["flags"] = (int)t.Flags });
        foreach (var t in info.Images)
            root["images"]!.AsArray().Add(new System.Text.Json.Nodes.JsonObject {
                ["binding"] = t.Binding, ["type"] = (int)t.Type, ["format"] = t.Format.ToString(),
                ["cbuf_slot"] = t.CbufSlot, ["handle"] = t.HandleIndex, ["array"] = t.ArrayLength,
                ["separate"] = t.Separate, ["flags"] = (int)t.Flags });
        File.WriteAllText(path, root.ToJsonString());
    }

    static int Main(string[] args)
    {
        if (args.Length < 2) { Console.Error.WriteLine("用法: bnsh_xlate <BNSH 文件或目录> <输出目录> [--limit N]"); return 2; }
        string path = args[0], outDir = args[1];
        int limit = 0;
        for (int i = 2; i < args.Length - 1; i++) if (args[i] == "--limit") limit = int.Parse(args[i + 1]);

        var files = Directory.Exists(path)
            ? Directory.GetFiles(path, "*", SearchOption.AllDirectories)
                 .Where(f => !f.EndsWith(".spv", StringComparison.OrdinalIgnoreCase))
                 .Where(f => new FileInfo(f).Length > 64)
                 .OrderBy(f => f).ToList()
            : new List<string> { path };
        Console.WriteLine($"待处理文件 {files.Count} 个 -> {outDir}");

        if (args.Contains("--probe")) { return Probe(path); }
        if (args.Contains("--probeapi")) { return ProbeApi(TranslatorBinPath); }

        int gOk = 0, gBad = 0, gSkip = 0, gSph = 0;
        var gErrs = new Dictionary<string, int>();
        var gErrFirst = new Dictionary<string, string>();
        var stages = new Dictionary<string, int>();
        bool headers = args.Contains("--headers");
        bool trace = Environment.GetEnvironmentVariable("ZA_STACK") == "1";
        foreach (string f in files)
        {
            var (ok, bad, skip, sph, errs, st, errFirst) = One(f, outDir, limit, headers, trace);
            gOk += ok; gBad += bad; gSkip += skip; gSph += sph;
            foreach (var kv in errs) gErrs[kv.Key] = gErrs.TryGetValue(kv.Key, out int c) ? c + kv.Value : kv.Value;
            foreach (var kv in errFirst) if (!gErrFirst.ContainsKey(kv.Key)) gErrFirst[kv.Key] = kv.Value;
            foreach (var kv in st) stages[kv.Key] = stages.TryGetValue(kv.Key, out int c) ? c + kv.Value : kv.Value;
            Console.WriteLine($"  {Path.GetFileName(Path.GetDirectoryName(f))}/{Path.GetFileName(f)}: SPH {sph} 成功 {ok} 失败 {bad} 跳过 {skip}");
        }
        Console.WriteLine("==== 汇总 ====");
        Console.WriteLine($"文件 {files.Count}  SPH 候选 {gSph}  翻译成功 {gOk}  失败 {gBad}  跳过 {gSkip}");
        Console.WriteLine("成功率: " + (gSph > 0 ? (100.0 * (gOk + gSkip) / gSph).ToString("F1") : "0") + "% (跳过=能解析但无产物)");
        foreach (var kv in stages.OrderByDescending(k => k.Value))
            Console.WriteLine("  stage " + kv.Key + ": " + kv.Value);
        foreach (var kv in gErrs.OrderByDescending(k => k.Value).Take(15))
            Console.WriteLine("  failed " + kv.Value.ToString().PadLeft(6) + "  " + kv.Key + "   [例: " + (gErrFirst.TryGetValue(kv.Key, out var fe) ? fe : "-") + "]");
        return 0;
    }

    static (int, int, int, int, Dictionary<string, int>, Dictionary<string, int>, Dictionary<string, string>) One(string path, string outDir, int limit, bool headers, bool trace)
    {
        Directory.CreateDirectory(outDir);
        byte[] data = File.ReadAllBytes(path);
        string sub = Path.Combine(outDir, Path.GetFileName(Path.GetDirectoryName(path)) ?? "_");
        Directory.CreateDirectory(sub);

        var sphOffsets = new List<int>();
        for (int i = 0; i + 4 <= data.Length; i++)
            if (data[i] == SphMagic[0] && data[i + 1] == SphMagic[1] && data[i + 2] == SphMagic[2] && data[i + 3] == SphMagic[3])
                sphOffsets.Add(i);

        int ok = 0, bad = 0, skipped = 0;
        var errs = new Dictionary<string, int>();
        var errFirst = new Dictionary<string, string>();
        var stages = new Dictionary<string, int>();
        for (int si = 0; si < sphOffsets.Count; si++)
        {
            int sph = sphOffsets[si];
            int codeEnd = (si + 1 < sphOffsets.Count) ? sphOffsets[si + 1] : data.Length;
            // 关键：Ryujinx 期望「代码段」从 SPH 本体（0x50 字节）开始，而不是从 0x12345678 魔数开始。
            // 魔数处是 0x30 字节的 NVN 头，SPH 在其后 0x30，SPH 第 0 字是阶段字（bits10..13：1=顶点 5=片元）。
            // 之前从魔数喂，导致头解析错位：**所有着色器都被当成片元**。
            int codeStart = sph;
            if (sph + 0x34 <= data.Length)
            {
                uint w30 = BitConverter.ToUInt32(data, sph + 0x30);
                int st = (int)((w30 >> 10) & 0xF);
                if (st == 1 || st == 5) codeStart = sph + 0x30;
            }
            if (limit > 0 && ok + bad >= limit) break;
            Accessor acc = null;
            try
            {
                acc = new Accessor(data, -1, 0, codeEnd);
                var ctx = Translator.CreateContext((ulong)codeStart, acc, new TranslationOptions(TargetLanguage.Spirv, TargetApi.Vulkan, TranslationFlags.None));
                var stage = ctx.Stage.ToString();
                bool isCompute = ctx.Stage == ShaderStage.Compute;
                if (headers)
                {
                    string imap = "";
                    string extra = "";
                    try
                    {
                        var asm = typeof(Translator).Assembly;
                        var shT = asm.GetType("Ryujinx.Graphics.Shader.Translation.ShaderHeader");
                        if (shT != null)
                        {
                            var ctor = shT.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance)
                                           .FirstOrDefault(c => c.GetParameters().Length == 2);
                            var h = ctor.Invoke(new object[] { acc, (ulong)codeStart });
                            object Get(string n)
                            {
                                var p = shT.GetProperty(n, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
                                return p?.GetValue(h);
                            }
                            imap = (Get("ImapPixelType") as Array)?.Cast<object>().Select(x => ((int)Convert.ToInt32(x)).ToString()).Aggregate("", (a, b) => a + (a.Length > 0 ? "," : "") + b) ?? "";
                            extra = $" sphType={Get("SphType")} ver={Get("Version")} sass={Get("SassVersion")} mrt={Get("MrtEnable")} omapTargets={Get("OmapTargets")} omapDepth={Get("OmapDepth")} imap=[{imap}]";
                        }
                    }
                    catch (Exception he) { extra = " hdrFail:" + he.GetType().Name; }
                    Console.WriteLine($"    [HDR] SPH@0x{sph:X} stage={stage}{extra} size={ctx.Size} cb1Size={ctx.Cb1DataSize}");
                }
                ShaderProgram prog;
                try
                {
                    prog = ctx.Translate(isCompute);
                }
                catch (Exception e1)
                {
                    // ★ 优化器/AST 重建偶尔会抛（实测 AstTextureOperation 的 InvalidCast）。
                    //   参考工程（d2r build_shaders.py）的做法：用 DebugMode 再翻一次
                    //   ——DebugMode 跳过 AST 优化器，语义不变，只是产物临时变量多。
                    //   Optimizer/AST rebuilds occasionally throw; d2r retries with DebugMode.
                    var flags2 = TranslationFlags.DebugMode | (isCompute ? TranslationFlags.Compute : 0);
                    var ctx2 = Translator.CreateContext((ulong)codeStart, acc,
                        new TranslationOptions(TargetLanguage.Spirv, TargetApi.Vulkan, flags2));
                    prog = ctx2.Translate(isCompute);
                    Console.Error.WriteLine($"    [DebugMode 重试] {Path.GetFileName(path)} SPH@0x{sph:X} ← {e1.GetType().Name}");
                }
                if (prog.BinaryCode == null || prog.BinaryCode.Length == 0) { skipped++; continue; }
                string spvName = Path.GetFileNameWithoutExtension(path) + "_" + $"{sph:X8}_{stage}.spv";
                File.WriteAllBytes(Path.Combine(sub, spvName), prog.BinaryCode);
                WriteRes(Path.Combine(sub, Path.GetFileNameWithoutExtension(spvName) + ".res.json"), prog, stage);
                stages[stage] = stages.TryGetValue(stage, out int c) ? c + 1 : 1;
                ok++;
            }
            catch (Exception e)
            {
                bad++;
                string key = e.GetType().Name + ": " + e.Message.Split('\n')[0];
                if (key.Length > 120) key = key.Substring(0, 120);
                errs[key] = errs.TryGetValue(key, out int c2) ? c2 + 1 : 1;
                if (!errFirst.ContainsKey(key))
                    errFirst[key] = $"{Path.GetFileName(path)} SPH@0x{sph:X}";
                if (trace && bad <= 5)
                {
                    Console.WriteLine($"    [ERR] SPH@0x{sph:X} codeStart=0x{codeStart:X} codeEnd=0x{codeEnd:X} 请求次数={acc.Gets.Count} 最大请求地址=0x{acc.MaxAddr:X} 超出窗口={(acc.MaxAddr >= codeEnd ? "是" : "否")} 数据长度=0x{data.Length:X}");
                    Console.WriteLine($"    [ERR] {e.GetType().Name}: {e.Message.Split('\n')[0]}");
                    Console.WriteLine(string.Join("\n", (e.StackTrace ?? "").Split('\n').Take(8)));
                }
            }
        }
        return (ok, bad, skipped, sphOffsets.Count, errs, stages, errFirst);
    }

    static int OldMain(string[] args)
    {
        if (args.Length < 2) { Console.Error.WriteLine("用法: bnsh_xlate <BNSH> <输出目录> [--limit N]"); return 2; }
        string path = args[0], outDir = args[1];
        int limit = 0;
        for (int i = 2; i < args.Length - 1; i++) if (args[i] == "--limit") limit = int.Parse(args[i + 1]);

        Directory.CreateDirectory(outDir);
        byte[] data = File.ReadAllBytes(path);
        Console.WriteLine($"文件 {Path.GetFileName(path)}  {data.Length} 字节");

        var sphOffsets = new List<int>();
        for (int i = 0; i + 4 <= data.Length; i++)
            if (data[i] == SphMagic[0] && data[i + 1] == SphMagic[1] && data[i + 2] == SphMagic[2] && data[i + 3] == SphMagic[3])
                sphOffsets.Add(i);
        Console.WriteLine($"SPH 候选 {sphOffsets.Count} 个: {(sphOffsets.Count > 0 ? string.Join(", ", sphOffsets.Take(8)) : "")}");

        int ok = 0, bad = 0, skipped = 0;
        var errs = new Dictionary<string, int>();
        for (int si = 0; si < sphOffsets.Count; si++)
        {
            int sph = sphOffsets[si];
            int codeEnd = (si + 1 < sphOffsets.Count) ? sphOffsets[si + 1] : data.Length;
            // 关键：Ryujinx 期望「代码段」从 SPH 本体（0x50 字节）开始，而不是从 0x12345678 魔数开始。
            // 魔数处是 0x30 字节的 NVN 头，SPH 在其后 0x30，SPH 第 0 字是阶段字（bits10..13：1=顶点 5=片元）。
            // 之前从魔数喂，导致头解析错位：**所有着色器都被当成片元**。
            int codeStart = sph;
            if (sph + 0x34 <= data.Length)
            {
                uint w30 = BitConverter.ToUInt32(data, sph + 0x30);
                int st = (int)((w30 >> 10) & 0xF);
                if (st == 1 || st == 5) codeStart = sph + 0x30;
            }
            if (limit > 0 && ok + bad >= limit) break;
            try
            {
                var acc = new Accessor(data, -1, 0, codeEnd);
                var ctx = Translator.CreateContext((ulong)codeStart, acc, new TranslationOptions(TargetLanguage.Spirv, TargetApi.Vulkan, TranslationFlags.None));
                var stage = ctx.Stage;
                bool isCompute = stage == ShaderStage.Compute;
                var prog = ctx.Translate(isCompute);
                if (prog.BinaryCode == null || prog.BinaryCode.Length == 0) { skipped++; continue; }
                string name = $"{sph:X8}_{stage}";
                File.WriteAllBytes(Path.Combine(outDir, name + ".spv"), prog.BinaryCode);
                WriteRes(Path.Combine(outDir, name + ".res.json"), prog, stage.ToString());
                ok++;
                if (ok <= 10) Console.WriteLine($"  [OK] SPH@0x{sph:X} stage={stage} spirv={prog.BinaryCode.Length} 字节");
            }
            catch (Exception e)
            {
                bad++;
                string key = e.GetType().Name + ": " + e.Message.Split('\n')[0];
                if (key.Length > 120) key = key.Substring(0, 120);
                errs[key] = errs.TryGetValue(key, out int c) ? c + 1 : 1;
            }
        }
        Console.WriteLine($"翻译 成功 {ok} / 失败 {bad} / 跳过 {skipped}");
        foreach (var kv in errs.OrderByDescending(k => k.Value).Take(10))
            Console.WriteLine("  failed " + kv.Value.ToString().PadLeft(6) + "  " + kv.Key);
        return 0;
    }
}
