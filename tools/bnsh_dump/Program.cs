// BNSH 解析工具：用 Ryujinx.Graphics.Shader 自带的 BNSH 读取器，把 Z-A 的 BNSH
// 拆成「每着色器一条」记录（stage / 机器码 / 控制段），供 dmsh_xlate 翻译成 SPIR-V。
//
// 用法：
//   bnsh_dump reflect <Ryujinx.Graphics.Shader.dll>   列出相关公开 API
//   bnsh_dump dump <bnsh 文件> <输出目录> <Ryujinx.Graphics.Shader.dll>
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;

class Program
{
    static Assembly _shaderAsm;

    static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0) { Console.Error.WriteLine("需要子命令"); return 2; }
            switch (args[0])
            {
                case "reflect": return Reflect(args[1]);
                case "api":
                    _shaderAsm = Assembly.LoadFrom(args[1]);
                    foreach (var n in new[] {
                        "Ryujinx.Graphics.Shader.Decoders.Decoder",
                        "Ryujinx.Graphics.Shader.Decoders.DecodedProgram",
                        "Ryujinx.Graphics.Shader.Translation.Translator",
                        "Ryujinx.Graphics.Shader.Translation.TranslatorContext",
                        "Ryujinx.Graphics.Shader.Translation.TranslationOptions",
                        "Ryujinx.Graphics.Shader.Translation.TargetLanguage",
                        "Ryujinx.Graphics.Shader.Translation.TranslationFlags",
                        "Ryujinx.Graphics.Shader.Translation.ShaderHeader" })
                    {
                        var t = _shaderAsm.GetType(n);
                        if (t == null) { Console.WriteLine("MISSING " + n); continue; }
                        if (t.IsEnum) { Console.WriteLine("== " + t.FullName + " [enum]: " + string.Join(", ", Enum.GetNames(t))); continue; }
                        PrintType(t);
                    }
                    return 0;
                case "dump": return Dump(args[1], args[2], args[3]);
                default: Console.Error.WriteLine("未知子命令 " + args[0]); return 2;
            }
        }
        catch (Exception e)
        {
            Console.Error.WriteLine("异常: " + e);
            return 1;
        }
    }

    static void PrintType(Type t)
    {
        Console.WriteLine("== " + t.FullName);
        foreach (var c in t.GetConstructors(BindingFlags.Public | BindingFlags.Instance))
            Console.WriteLine("   .ctor(" + string.Join(", ", c.GetParameters().Select(p => p.ParameterType.Name + " " + p.Name)) + ")");
        foreach (var p in t.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            Console.WriteLine("   prop " + p.PropertyType.Name + " " + p.Name);
        foreach (var f in t.GetFields(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            Console.WriteLine("   field " + f.FieldType.Name + " " + f.Name);
        foreach (var m in t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
        {
            if (m.IsSpecialName) continue;
            Console.WriteLine("   method " + m.ReturnType.Name + " " + m.Name + "(" +
                string.Join(", ", m.GetParameters().Select(p => p.ParameterType.Name + " " + p.Name)) + ")");
        }
    }

    static int Reflect(string dll)
    {
        _shaderAsm = Assembly.LoadFrom(dll);
        Console.WriteLine("程序集: " + _shaderAsm.FullName);
        Console.WriteLine("--- 全部公开类型（按命名空间）---");
        foreach (var g in _shaderAsm.GetTypes().Where(t => t.IsPublic)
                     .GroupBy(t => t.Namespace).OrderBy(g => g.Key))
        {
            Console.WriteLine((g.Key ?? "-") + " (" + g.Count() + "): " +
                string.Join(", ", g.Select(t => t.Name).Take(80)));
        }
        Console.WriteLine("--- 全部类型（含非公开），按命名空间 ---");
        foreach (var g in _shaderAsm.GetTypes()
                     .GroupBy(t => t.Namespace).OrderBy(g => g.Key))
        {
            Console.WriteLine((g.Key ?? "-") + " (" + g.Count() + "): " +
                string.Join(", ", g.Select(t => t.Name).Take(120)));
        }
        Console.WriteLine("--- 含 BNSH/Maxwell/Nvn 的类型（含非公开）---");
        foreach (var t in _shaderAsm.GetTypes()
                     .Where(t => t.Name.IndexOf("BNSH", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 t.Name.IndexOf("Maxwell", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 t.Name.IndexOf("Nvn", StringComparison.OrdinalIgnoreCase) >= 0))
        {
            PrintType(t);
        }
        return 0;
    }

    static int Dump(string path, string outDir, string dll)
    {
        _shaderAsm = Assembly.LoadFrom(dll);
        Directory.CreateDirectory(outDir);
        byte[] data = File.ReadAllBytes(path);
        Console.WriteLine("文件 " + Path.GetFileName(path) + " " + data.Length + " 字节");

        var readerType = _shaderAsm.GetType("Ryujinx.Graphics.Shader.Nvn.BNSHReader")
            ?? _shaderAsm.GetTypes().FirstOrDefault(t => t.Name == "BNSHReader");
        if (readerType == null) { Console.Error.WriteLine("找不到 BNSHReader"); return 1; }
        Console.WriteLine("BNSHReader: " + readerType.FullName);
        foreach (var c in readerType.GetConstructors())
            Console.WriteLine("   .ctor(" + string.Join(", ", c.GetParameters().Select(p => p.ParameterType.Name + " " + p.Name)) + ")");
        foreach (var m in readerType.GetMembers(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            Console.WriteLine("   " + m.MemberType + " " + m.Name);
        return 0;
    }
}
