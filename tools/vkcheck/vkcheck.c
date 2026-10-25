// 平板端 Vulkan 验收器：让设备上的 Mali 驱动直接编译我们从 Z-A 翻出来的 SPIR-V。
//
// 用法（adb shell 下）： vkcheck <spv 文件> [<spv 文件> ...]
// 不依赖任何 NDK 之外的库：Vulkan 走 dlopen("libvulkan.so")。
#include <dlfcn.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <vulkan/vulkan.h>

typedef struct {
    void *lib;
    PFN_vkGetInstanceProcAddr GetInstanceProcAddr;
    PFN_vkCreateInstance CreateInstance;
    PFN_vkDestroyInstance DestroyInstance;
    PFN_vkEnumeratePhysicalDevices EnumeratePhysicalDevices;
    PFN_vkGetPhysicalDeviceProperties GetPhysicalDeviceProperties;
    PFN_vkGetPhysicalDeviceFeatures GetPhysicalDeviceFeatures;
    PFN_vkGetPhysicalDeviceQueueFamilyProperties GetQueueFamilyProperties;
    PFN_vkCreateDevice CreateDevice;
    PFN_vkDestroyDevice DestroyDevice;
    PFN_vkGetDeviceProcAddr GetDeviceProcAddr;
    PFN_vkCreateShaderModule CreateShaderModule;
    PFN_vkDestroyShaderModule DestroyShaderModule;
    PFN_vkCreateGraphicsPipelines CreateGraphicsPipelines;
    PFN_vkDestroyShaderModule DestroyShaderModule2;
} VkApi;

static void *load_sym(void *lib, const char *name)
{
    void *p = dlsym(lib, name);
    if (!p) fprintf(stderr, "缺少符号 %s\n", name);
    return p;
}

// 从 SPIR-V 里找 OpEntryPoint 的执行模型（0 顶点 / 3 几何 / 4 片元 / 5 计算），找不到返回 -1
static int spirv_exec_model(const uint32_t *code, size_t words)
{
    for (size_t i = 5; i < words;)
    {
        uint32_t w = code[i];
        uint32_t len = w >> 16;
        uint32_t op = w & 0xFFFF;
        if (len == 0) break;
        if (op == 15 && len >= 4) return (int)code[i + 1];   // OpEntryPoint: 第 1 个操作数就是执行模型
        i += len;
    }
    return -1;
}

static const char *model_name(int m)
{
    switch (m)
    {
    case 0: return "顶点";
    case 1: return "曲面控制";
    case 2: return "曲面求值";
    case 3: return "几何";
    case 4: return "片元";
    case 5: return "计算";
    case 6: return "Kernel";
    default: return "未知";
    }
}

#define MAX_FILES 300000
static char *g_files[MAX_FILES];
static int g_nfiles = 0;

static void add_file(const char *path)
{
    if (g_nfiles >= MAX_FILES) return;
    char *s = strdup(path);
    if (s) g_files[g_nfiles++] = s;
}

static void scan_dir(const char *dir)
{
    DIR *d = opendir(dir);
    if (!d) { fprintf(stderr, "打不开目录 %s\n", dir); return; }
    struct dirent *e;
    while ((e = readdir(d)))
    {
        if (e->d_name[0] == '.') continue;
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
        struct stat st;
        if (stat(path, &st) != 0) continue;
        if (S_ISDIR(st.st_mode)) scan_dir(path);
        else
        {
            size_t n = strlen(path);
            if (n > 4 && strcmp(path + n - 4, ".spv") == 0) add_file(path);
        }
    }
    closedir(d);
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "用法: vkcheck <spv 文件或目录>\n"); return 2; }

    for (int i = 1; i < argc; i++)
    {
        struct stat st;
        if (stat(argv[i], &st) == 0 && S_ISDIR(st.st_mode)) scan_dir(argv[i]);
        else add_file(argv[i]);
    }
    printf("待检文件 %d 个\n", g_nfiles);

    void *lib = dlopen("libvulkan.so", RTLD_NOW | RTLD_LOCAL);
    if (!lib) { fprintf(stderr, "dlopen libvulkan.so 失败: %s\n", dlerror()); return 3; }

    VkApi api = {0};
    api.lib = lib;
    *(void **)&api.GetInstanceProcAddr = load_sym(lib, "vkGetInstanceProcAddr");

    VkApplicationInfo app = { VK_STRUCTURE_TYPE_APPLICATION_INFO };
    app.pApplicationName = "vkcheck";
    app.apiVersion = VK_API_VERSION_1_1;
    VkInstanceCreateInfo ici = { VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
    ici.pApplicationInfo = &app;
    VkInstance inst = VK_NULL_HANDLE;
    api.CreateInstance = (PFN_vkCreateInstance)api.GetInstanceProcAddr(NULL, "vkCreateInstance");
    VkResult r = api.CreateInstance(&ici, NULL, &inst);
    if (r != VK_SUCCESS) { fprintf(stderr, "vkCreateInstance 失败: %d\n", r); return 3; }

    api.EnumeratePhysicalDevices = (PFN_vkEnumeratePhysicalDevices)api.GetInstanceProcAddr(inst, "vkEnumeratePhysicalDevices");
    api.GetPhysicalDeviceProperties = (PFN_vkGetPhysicalDeviceProperties)api.GetInstanceProcAddr(inst, "vkGetPhysicalDeviceProperties");
    api.GetPhysicalDeviceFeatures = (PFN_vkGetPhysicalDeviceFeatures)api.GetInstanceProcAddr(inst, "vkGetPhysicalDeviceFeatures");
    api.GetQueueFamilyProperties = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)api.GetInstanceProcAddr(inst, "vkGetPhysicalDeviceQueueFamilyProperties");
    api.CreateDevice = (PFN_vkCreateDevice)api.GetInstanceProcAddr(inst, "vkCreateDevice");
    api.DestroyDevice = (PFN_vkDestroyDevice)api.GetInstanceProcAddr(inst, "vkDestroyDevice");
    api.DestroyInstance = (PFN_vkDestroyInstance)api.GetInstanceProcAddr(inst, "vkDestroyInstance");

    uint32_t n = 0;
    api.EnumeratePhysicalDevices(inst, &n, NULL);
    if (!n) { fprintf(stderr, "没有物理设备\n"); return 3; }
    VkPhysicalDevice *pds = malloc(sizeof(VkPhysicalDevice) * n);
    api.EnumeratePhysicalDevices(inst, &n, pds);

    VkPhysicalDevice pd = pds[0];
    VkPhysicalDeviceProperties props;
    api.GetPhysicalDeviceProperties(pd, &props);
    printf("GPU: %s\n", props.deviceName);
    printf("  API版本 %u.%u.%u  驱动 %u.%u.%u  类型 %d\n",
           VK_VERSION_MAJOR(props.apiVersion), VK_VERSION_MINOR(props.apiVersion),
           VK_VERSION_PATCH(props.apiVersion),
           VK_VERSION_MAJOR(props.driverVersion), VK_VERSION_MINOR(props.driverVersion),
           VK_VERSION_PATCH(props.driverVersion), props.deviceType);

    uint32_t qn = 0;
    api.GetQueueFamilyProperties(pd, &qn, NULL);
    VkQueueFamilyProperties *qfs = malloc(sizeof(VkQueueFamilyProperties) * qn);
    api.GetQueueFamilyProperties(pd, &qn, qfs);
    uint32_t qfi = 0;
    for (uint32_t i = 0; i < qn; i++) if (qfs[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) { qfi = i; break; }

    float prio = 1.0f;
    VkDeviceQueueCreateInfo dqci = { VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO };
    dqci.queueFamilyIndex = qfi;
    dqci.queueCount = 1;
    dqci.pQueuePriorities = &prio;
    VkDeviceCreateInfo dvci = { VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO };
    dvci.queueCreateInfoCount = 1;
    dvci.pQueueCreateInfos = &dqci;
    VkDevice dev = VK_NULL_HANDLE;
    r = api.CreateDevice(pd, &dvci, NULL, &dev);
    if (r != VK_SUCCESS) { fprintf(stderr, "vkCreateDevice 失败: %d\n", r); return 3; }
    printf("  逻辑设备已创建（图形队列族 %u）\n", qfi);

    *(void **)&api.CreateShaderModule = load_sym(lib, "vkCreateShaderModule");
    *(void **)&api.DestroyShaderModule = load_sym(lib, "vkDestroyShaderModule");

    int ok = 0, bad = 0;
    int model_cnt[8];
    memset(model_cnt, 0, sizeof(model_cnt));
    for (int i = 0; i < g_nfiles; i++)
    {
        FILE *f = fopen(g_files[i], "rb");
        if (!f) { fprintf(stderr, "打不开 %s\n", g_files[i]); bad++; continue; }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        uint32_t *code = malloc((size_t)sz);
        if (fread(code, 1, (size_t)sz, f) != (size_t)sz) { fclose(f); bad++; continue; }
        fclose(f);
        int model = spirv_exec_model(code, (size_t)sz / 4);
        if (model >= 0 && model < 8) model_cnt[model]++;
        VkShaderModuleCreateInfo smci = { VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO };
        smci.codeSize = (size_t)sz;
        smci.pCode = code;
        VkShaderModule sm = VK_NULL_HANDLE;
        r = api.CreateShaderModule(dev, &smci, NULL, &sm);
        if (r == VK_SUCCESS) { ok++; api.DestroyShaderModule(dev, sm, NULL); }
        else
        {
            bad++;
            if (bad <= 5)
                fprintf(stderr, "  [失败] %s -> VkResult=%d (magic=%08x)\n", g_files[i], r, code[0]);
        }
        free(code);
    }
    printf("SPIR-V 模块: 接受 %d  拒绝 %d\n", ok, bad);
    printf("执行模型分布: ");
    for (int m = 0; m < 8; m++)
        if (model_cnt[m]) printf("%s %d  ", model_name(m), model_cnt[m]);
    printf("\n");

    api.DestroyDevice(dev, NULL);
    api.DestroyInstance(inst, NULL);
    free(pds); free(qfs);
    return bad ? 1 : 0;
}
