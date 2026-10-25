// 设备端对照实验：把「实例扩展」这个变量单独拎出来。
//
// 用法: vkcheck2 <plain|surface>
//   plain   : 实例不申请任何扩展（vkcheck 就是这样，能成功）
//   surface : 实例申请 VK_KHR_surface + VK_KHR_android_surface
// 两种都建逻辑设备（设备扩展同样按参数），打印每一步结果。
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define VK_USE_PLATFORM_ANDROID_KHR
#include <vulkan/vulkan.h>

static PFN_vkGetInstanceProcAddr gIPA;
#define GET(x, n) x = (PFN_##x) (gIPA ? gIPA(inst, #n) : NULL)

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "plain";
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("模式: %s\n", mode);

    void *lib = dlopen("libvulkan.so", RTLD_NOW | RTLD_LOCAL);
    if (!lib) { printf("dlopen 失败: %s\n", dlerror()); return 3; }
    gIPA = (PFN_vkGetInstanceProcAddr)dlsym(lib, "vkGetInstanceProcAddr");
    PFN_vkCreateInstance CreateInstance = (PFN_vkCreateInstance)gIPA(NULL, "vkCreateInstance");
    printf("符号: CreateInstance=%p\n", (void *)CreateInstance);

    VkApplicationInfo ai = { VK_STRUCTURE_TYPE_APPLICATION_INFO };
    ai.pApplicationName = "vkcheck2";
    ai.apiVersion = (argc > 2 && !strcmp(argv[2], "13")) ? VK_API_VERSION_1_3 : VK_API_VERSION_1_1;
    const char *exts[2] = { VK_KHR_SURFACE_EXTENSION_NAME, VK_KHR_ANDROID_SURFACE_EXTENSION_NAME };
    VkInstanceCreateInfo ici = { VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
    ici.pApplicationInfo = &ai;
    // 模式: plain=都不带；surf=只带实例扩展；swap=只带设备扩展；both=都带
    if (!strcmp(mode, "surf") || !strcmp(mode, "both"))
    { ici.enabledExtensionCount = 2; ici.ppEnabledExtensionNames = exts; }
    VkInstance inst = VK_NULL_HANDLE;
    VkResult r = CreateInstance(&ici, NULL, &inst);
    printf("vkCreateInstance -> %d\n", r);
    if (r != VK_SUCCESS) return 4;

    PFN_vkDestroyInstance DestroyInstance = (PFN_vkDestroyInstance)gIPA(inst, "vkDestroyInstance");
    PFN_vkEnumeratePhysicalDevices EnumPD = (PFN_vkEnumeratePhysicalDevices)gIPA(inst, "vkEnumeratePhysicalDevices");
    PFN_vkGetPhysicalDeviceProperties GetProps = (PFN_vkGetPhysicalDeviceProperties)gIPA(inst, "vkGetPhysicalDeviceProperties");
    PFN_vkGetPhysicalDeviceQueueFamilyProperties GetQFP = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)gIPA(inst, "vkGetPhysicalDeviceQueueFamilyProperties");
    PFN_vkCreateDevice CreateDevice = (PFN_vkCreateDevice)gIPA(inst, "vkCreateDevice");
    printf("符号: CreateDevice=%p GetQFP=%p\n", (void *)CreateDevice, (void *)GetQFP);

    uint32_t n = 0;
    EnumPD(inst, &n, NULL);
    VkPhysicalDevice *pds = malloc(sizeof(VkPhysicalDevice) * n);
    EnumPD(inst, &n, pds);
    VkPhysicalDevice pd = pds[0];
    VkPhysicalDeviceProperties props;
    GetProps(pd, &props);
    printf("GPU: %s (数量 %u)\n", props.deviceName, n);

    uint32_t qn = 0;
    GetQFP(pd, &qn, NULL);
    VkQueueFamilyProperties *qfs = malloc(sizeof(VkQueueFamilyProperties) * qn);
    GetQFP(pd, &qn, qfs);
    uint32_t qfi = 0;
    for (uint32_t i = 0; i < qn; i++) if (qfs[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) { qfi = i; break; }
    printf("队列族 %u 个，图形队列族 %u\n", qn, qfi);

    float prio = 1.0f;
    VkDeviceQueueCreateInfo dq = { VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO };
    dq.queueFamilyIndex = qfi; dq.queueCount = 1; dq.pQueuePriorities = &prio;
    VkDeviceCreateInfo dci = { VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO };
    dci.queueCreateInfoCount = 1; dci.pQueueCreateInfos = &dq;
    if (!strcmp(mode, "swap") || !strcmp(mode, "both"))
    {
        const char *devExt[1] = { VK_KHR_SWAPCHAIN_EXTENSION_NAME };
        dci.enabledExtensionCount = 1; dci.ppEnabledExtensionNames = devExt;
    }
    else if (!strcmp(mode, "other"))
    {
        // 随便挑一个跟交换链无关的设备扩展，测「是不是任何设备扩展都会崩」
        const char *devExt[1] = { "VK_KHR_maintenance1" };
        dci.enabledExtensionCount = 1; dci.ppEnabledExtensionNames = devExt;
    }
    VkDevice dev = VK_NULL_HANDLE;
    printf("开始 vkCreateDevice ...\n"); fflush(stdout);
    r = CreateDevice(pd, &dci, NULL, &dev);
    printf("vkCreateDevice -> %d\n", r);
    if (r == VK_SUCCESS)
    {
        PFN_vkEnumerateDeviceExtensionProperties EnumDevExt = (PFN_vkEnumerateDeviceExtensionProperties)gIPA(inst, "vkEnumerateDeviceExtensionProperties");
        uint32_t dn = 0;
        if (EnumDevExt) EnumDevExt(pd, NULL, &dn, NULL);
        VkExtensionProperties *dp = malloc(sizeof(VkExtensionProperties) * (dn ? dn : 1));
        if (EnumDevExt) EnumDevExt(pd, NULL, &dn, dp);
        printf("设备扩展 %u 个:\n", dn);
        for (uint32_t i = 0; i < dn; i++) printf("  %s\n", dp[i].extensionName);
        free(dp);
        printf("成功\n");
    }
    return r == VK_SUCCESS ? 0 : 5;
}
