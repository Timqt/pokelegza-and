// 宝可梦 Z-A 安卓宿主 —— 原生前端（NativeActivity）。
//
// 目标：在平板上跑起一个**属于宝可梦 Z-A 自己的**原生 Vulkan 应用，
// 与暗黑破坏神那个 APK 完全无关（包名、应用名、so 名、构建目录都分开）。
//
// 这一步做的事（里程碑 M1）：
//   1) 用 dlopen 拿 libvulkan.so，建实例/设备；
//   2) 用 ANativeWindow 建交换链；
//   3) 加载 APK 资产里我们**自己**用 glslc 编出来的 SPIR-V，画一个全屏三角形；
//   4) 把 GPU 型号 / API 版本 / 分辨率 / 帧数打到 logcat（tag: PokemonZA）。
// 后面接游戏时，第 3 步会换成「控制段哈希 → 预翻 SPIR-V」的运行时查表。
//
// 注意：本工程的 NDK 头文件是 Vulkan 1.0 时代的，没有 vkCmdRenderPassBegin（1.2 才加），
// 一律用 1.0 的 vkCmdBeginRenderPass。
#include <android/native_window.h>
#include <android/asset_manager.h>
#include <android/log.h>
#include <android/native_activity.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "za_guest_api.h"
#define VK_USE_PLATFORM_ANDROID_KHR
#include <vulkan/vulkan.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "PokemonZA", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "PokemonZA", __VA_ARGS__)

// 图形层（app/native/dm 里的参考工程 NVN→Vulkan 翻译器）。接管时这里不再自建交换链：
// 一个 ANativeWindow 只有一条 BufferQueue，两套交换链同时呈现必然互相覆盖/崩。
int za_gfx_active(void);
void za_gfx_set_window(ANativeWindow *window);
void za_gfx_start(const char *shader_root);

typedef struct ZaApp
{
    ANativeActivity *activity;
    ANativeWindow *window;
    AAssetManager *assets;
    VkInstance instance;
    VkSurfaceKHR surface;
    VkPhysicalDevice phys;
    VkDevice device;
    VkQueue queue;
    uint32_t queueFamily;
    VkSwapchainKHR swapchain;
    VkFormat swapFormat;
    VkExtent2D extent;
    VkImageView *views;
    VkFramebuffer *frames;
    VkCommandPool cmdPool;
    VkShaderModule vs, fs;
    VkPipelineLayout pipeLayout;
    VkRenderPass renderPass;
    VkPipeline pipeline;
    VkCommandBuffer *cmds;
    VkSemaphore acquire, render, present;
    VkFence fence;
    uint32_t imageCount;
    int running;
    int frameCount;
    // 渲染线程在 onCreate 就起跑，而命令缓冲/信号量要等窗口回调里才分配。
    // 没有这个闸门，渲染线程会在「交换链已建、cmds 还是 NULL」的窗口期里
    // 取到一张图然后解引用空指针 —— 实机就是这么崩的。
    volatile int renderReady;
    pthread_t thread;
} ZaApp;

// ---------------- Vulkan 动态加载 ----------------
static void *g_lib;

static PFN_vkGetInstanceProcAddr gGetInstanceProcAddr;
static PFN_vkCreateInstance gCreateInstance;
static PFN_vkDestroyInstance gDestroyInstance;
static PFN_vkEnumeratePhysicalDevices gEnumeratePhysicalDevices;
static PFN_vkGetPhysicalDeviceProperties gGetPhysicalDeviceProperties;
static PFN_vkGetPhysicalDeviceMemoryProperties gGetPhysicalDeviceMemoryProperties;
static PFN_vkGetPhysicalDeviceQueueFamilyProperties gGetPhysicalDeviceQueueFamilyProperties;
static PFN_vkGetPhysicalDeviceSurfaceSupportKHR gGetPhysicalDeviceSurfaceSupportKHR;
static PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR gGetPhysicalDeviceSurfaceCapabilitiesKHR;
static PFN_vkGetPhysicalDeviceSurfaceFormatsKHR gGetPhysicalDeviceSurfaceFormatsKHR;
static PFN_vkGetPhysicalDeviceSurfacePresentModesKHR gGetPhysicalDeviceSurfacePresentModesKHR;
static PFN_vkCreateAndroidSurfaceKHR gCreateAndroidSurfaceKHR;
static PFN_vkDestroySurfaceKHR gDestroySurfaceKHR;
static PFN_vkCreateDevice gCreateDevice;
static PFN_vkDestroyDevice gDestroyDevice;
static PFN_vkGetDeviceProcAddr gGetDeviceProcAddr;
static PFN_vkGetDeviceQueue gGetDeviceQueue;
static PFN_vkCreateSwapchainKHR gCreateSwapchainKHR;
static PFN_vkDestroySwapchainKHR gDestroySwapchainKHR;
static PFN_vkGetSwapchainImagesKHR gGetSwapchainImages;
static PFN_vkCreateImageView gCreateImageView;
static PFN_vkDestroyImageView gDestroyImageView;
static PFN_vkCreateShaderModule gCreateShaderModule;
static PFN_vkDestroyShaderModule gDestroyShaderModule;
static PFN_vkCreatePipelineLayout gCreatePipelineLayout;
static PFN_vkDestroyPipelineLayout gDestroyPipelineLayout;
static PFN_vkCreateRenderPass gCreateRenderPass;
static PFN_vkDestroyRenderPass gDestroyRenderPass;
static PFN_vkCreateFramebuffer gCreateFramebuffer;
static PFN_vkDestroyFramebuffer gDestroyFramebuffer;
static PFN_vkCreateGraphicsPipelines gCreateGraphicsPipelines;
static PFN_vkDestroyPipeline gDestroyPipeline;
static PFN_vkCreateCommandPool gCreateCommandPool;
static PFN_vkDestroyCommandPool gDestroyCommandPool;
static PFN_vkAllocateCommandBuffers gAllocateCommandBuffers;
static PFN_vkFreeCommandBuffers gFreeCommandBuffers;
static PFN_vkBeginCommandBuffer gBeginCommandBuffer;
static PFN_vkEndCommandBuffer gEndCommandBuffer;
static PFN_vkCmdBeginRenderPass gCmdRenderPassBegin;
static PFN_vkCmdSetViewport gCmdSetViewport;
static PFN_vkCmdSetScissor gCmdSetScissor;
static PFN_vkCmdBindPipeline gCmdBindPipeline;
static PFN_vkCmdDraw gCmdDraw;
static PFN_vkCmdEndRenderPass gCmdEndRenderPass;
static PFN_vkQueueSubmit gQueueSubmit;
static PFN_vkQueuePresentKHR gQueuePresentKHR;
static PFN_vkAcquireNextImageKHR gAcquireNextImageKHR;
static PFN_vkCreateSemaphore gCreateSemaphore;
static PFN_vkDestroySemaphore gDestroySemaphore;
static PFN_vkCreateFence gCreateFence;
static PFN_vkDestroyFence gDestroyFence;
static PFN_vkWaitForFences gWaitForFences;
static PFN_vkResetFences gResetFences;

// ---------------- 着色器 ----------------
static int read_asset(ZaApp *app, const char *name, void **out, size_t *outSize)
{
    AAsset *a = AAssetManager_open(app->assets, name, AASSET_MODE_BUFFER);
    if (!a) { LOGE("APK 里没有资产 %s", name); return 0; }
    off_t n = AAsset_getLength(a);
    void *buf = malloc((size_t)n);
    if (!buf) { AAsset_close(a); return 0; }
    if (AAsset_read(a, buf, (size_t)n) != n) { free(buf); AAsset_close(a); return 0; }
    AAsset_close(a);
    *out = buf;
    *outSize = (size_t)n;
    return 1;
}

static int load_shader(ZaApp *app, const char *asset, VkShaderModule *out)
{
    void *code = NULL;
    size_t size = 0;
    if (!read_asset(app, asset, &code, &size)) return 0;
    VkShaderModuleCreateInfo ci = { VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO };
    ci.codeSize = size;
    ci.pCode = (const uint32_t *)code;
    VkResult r = gCreateShaderModule(app->device, &ci, NULL, out);
    free(code);
    if (r != VK_SUCCESS) { LOGE("创建着色器模块失败 %s: %d", asset, r); return 0; }
    LOGI("着色器模块已加载: %s (%zu 字节)", asset, size);
    return 1;
}

// ---------------- 交换链 ----------------
static int create_swapchain(ZaApp *app)
{
    VkSurfaceCapabilitiesKHR cap;
    gGetPhysicalDeviceSurfaceCapabilitiesKHR(app->phys, app->surface, &cap);
    if (cap.currentExtent.width == UINT32_MAX)
    {
        app->extent.width = ANativeWindow_getWidth(app->window);
        app->extent.height = ANativeWindow_getHeight(app->window);
    }
    else app->extent = cap.currentExtent;
    if (app->extent.width == 0 || app->extent.height == 0) return 0;

    uint32_t fmtCount = 0;
    gGetPhysicalDeviceSurfaceFormatsKHR(app->phys, app->surface, &fmtCount, NULL);
    VkSurfaceFormatKHR *fmts = (VkSurfaceFormatKHR *)malloc(sizeof(VkSurfaceFormatKHR) * (fmtCount ? fmtCount : 1));
    gGetPhysicalDeviceSurfaceFormatsKHR(app->phys, app->surface, &fmtCount, fmts);
    app->swapFormat = fmts[0].format;
    VkColorSpaceKHR colorSpace = fmts[0].colorSpace;
    if (app->swapFormat == VK_FORMAT_UNDEFINED) app->swapFormat = VK_FORMAT_R8G8B8A8_UNORM;
    // **格式必须跟窗口的 BufferQueue 格式一致**，否则安卓 loader 在 present 时
    // 拿交换链格式去匹配 BufferQueue，对不上就在驱动里解引用空指针 +0x30 崩掉。
    // 窗口用的是 WINDOW_FORMAT_RGBA_8888（字节序 R,G,B,A）⇒ 对应 VK_FORMAT_R8G8B8A8_UNORM。
    for (uint32_t i = 0; i < fmtCount; i++)
    {
        if (fmts[i].format == VK_FORMAT_R8G8B8A8_UNORM)
        {
            app->swapFormat = fmts[i].format;
            colorSpace = fmts[i].colorSpace;
            break;
        }
    }
    LOGI("表面格式 %u 种：", fmtCount);
    for (uint32_t i = 0; i < fmtCount && i < 6; i++)
        LOGI("   格式 %d 颜色空间 %d", fmts[i].format, fmts[i].colorSpace);
    free(fmts);

    VkSwapchainCreateInfoKHR sci = { VK_STRUCTURE_TYPE_SWAPCHAIN_CREATE_INFO_KHR };
    sci.surface = app->surface;
    sci.minImageCount = 2;
    sci.imageFormat = app->swapFormat;
    // 颜色空间必须与表面给出的配对一致，写死会导致 loader 呈现时匹配不到而崩。
    sci.imageColorSpace = colorSpace;
    sci.imageExtent = app->extent;
    sci.imageArrayLayers = 1;
    sci.imageUsage = VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
    sci.preTransform = (cap.currentTransform != VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR) ? cap.currentTransform : VK_SURFACE_TRANSFORM_IDENTITY_BIT_KHR;
    sci.compositeAlpha = VK_COMPOSITE_ALPHA_INHERIT_BIT_KHR;
    sci.presentMode = VK_PRESENT_MODE_FIFO_KHR;
    sci.clipped = VK_TRUE;
    VkResult r = gCreateSwapchainKHR(app->device, &sci, NULL, &app->swapchain);
    if (r != VK_SUCCESS) { LOGE("创建交换链失败: %d", r); return 0; }

    uint32_t n = 0;
    gGetSwapchainImages(app->device, app->swapchain, &n, NULL);
    app->imageCount = n;
    VkImage *imgs = (VkImage *)malloc(sizeof(VkImage) * n);
    gGetSwapchainImages(app->device, app->swapchain, &n, imgs);

    app->views = (VkImageView *)calloc(n, sizeof(VkImageView));
    app->frames = (VkFramebuffer *)calloc(n, sizeof(VkFramebuffer));
    for (uint32_t i = 0; i < n; i++)
    {
        VkImageViewCreateInfo vi = { VK_STRUCTURE_TYPE_IMAGE_VIEW_CREATE_INFO };
        vi.image = imgs[i];
        vi.viewType = VK_IMAGE_VIEW_TYPE_2D;
        vi.format = app->swapFormat;
        vi.subresourceRange.aspectMask = VK_IMAGE_ASPECT_COLOR_BIT;
        vi.subresourceRange.levelCount = 1;
        vi.subresourceRange.layerCount = 1;
        gCreateImageView(app->device, &vi, NULL, &app->views[i]);
    }
    free(imgs);

    VkAttachmentDescription att = {0};
    att.format = app->swapFormat;
    att.samples = VK_SAMPLE_COUNT_1_BIT;
    att.loadOp = VK_ATTACHMENT_LOAD_OP_CLEAR;
    att.storeOp = VK_ATTACHMENT_STORE_OP_STORE;
    att.stencilLoadOp = VK_ATTACHMENT_LOAD_OP_DONT_CARE;
    att.stencilStoreOp = VK_ATTACHMENT_STORE_OP_DONT_CARE;
    att.initialLayout = VK_IMAGE_LAYOUT_UNDEFINED;
    att.finalLayout = VK_IMAGE_LAYOUT_PRESENT_SRC_KHR;
    VkAttachmentReference ref = {0};
    ref.attachment = 0;
    ref.layout = VK_IMAGE_LAYOUT_COLOR_ATTACHMENT_OPTIMAL;
    VkSubpassDescription sub = {0};
    sub.pipelineBindPoint = VK_PIPELINE_BIND_POINT_GRAPHICS;
    sub.colorAttachmentCount = 1;
    sub.pColorAttachments = &ref;
    VkRenderPassCreateInfo rp = { VK_STRUCTURE_TYPE_RENDER_PASS_CREATE_INFO };
    rp.attachmentCount = 1;
    rp.pAttachments = &att;
    rp.subpassCount = 1;
    rp.pSubpasses = &sub;
    // renderPass 只建一次：重建交换链时格式不变，pipeline 还指着它。
    if (!app->renderPass) gCreateRenderPass(app->device, &rp, NULL, &app->renderPass);

    for (uint32_t i = 0; i < n; i++)
    {
        VkFramebufferCreateInfo fi = { VK_STRUCTURE_TYPE_FRAMEBUFFER_CREATE_INFO };
        fi.renderPass = app->renderPass;
        fi.attachmentCount = 1;
        fi.pAttachments = &app->views[i];
        fi.width = app->extent.width;
        fi.height = app->extent.height;
        fi.layers = 1;
        gCreateFramebuffer(app->device, &fi, NULL, &app->frames[i]);
    }
    LOGI("交换链就绪: %u 张图, %ux%u, 格式 %d", n, app->extent.width, app->extent.height, app->swapFormat);
    return 1;
}

static void destroy_swapchain(ZaApp *app)
{
    if (!app->device) return;
    for (uint32_t i = 0; i < app->imageCount; i++)
    {
        if (app->frames && app->frames[i]) gDestroyFramebuffer(app->device, app->frames[i], NULL);
        if (app->views && app->views[i]) gDestroyImageView(app->device, app->views[i], NULL);
    }
    free(app->frames); app->frames = NULL;
    free(app->views); app->views = NULL;
    // 注意：**不**销毁 renderPass。renderPass 只跟格式有关，跟交换链无关；
    // 销毁它会让已经建好的 pipeline 引用一个已销毁的对象（未定义行为）。
    if (app->swapchain) { gDestroySwapchainKHR(app->device, app->swapchain, NULL); app->swapchain = VK_NULL_HANDLE; }
    app->imageCount = 0;
}

// ---------------- 渲染 ----------------
static int create_pipeline(ZaApp *app)
{
    if (!load_shader(app, "shaders/za.vert.spv", &app->vs)) return 0;
    if (!load_shader(app, "shaders/za.frag.spv", &app->fs)) return 0;

    VkPipelineShaderStageCreateInfo stages[2] = {0};
    stages[0].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[0].stage = VK_SHADER_STAGE_VERTEX_BIT;
    stages[0].module = app->vs;
    stages[0].pName = "main";
    stages[1].sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO;
    stages[1].stage = VK_SHADER_STAGE_FRAGMENT_BIT;
    stages[1].module = app->fs;
    stages[1].pName = "main";

    VkPipelineVertexInputStateCreateInfo vi = { VK_STRUCTURE_TYPE_PIPELINE_VERTEX_INPUT_STATE_CREATE_INFO };
    VkPipelineInputAssemblyStateCreateInfo ia = { VK_STRUCTURE_TYPE_PIPELINE_INPUT_ASSEMBLY_STATE_CREATE_INFO };
    ia.topology = VK_PRIMITIVE_TOPOLOGY_TRIANGLE_LIST;
    VkViewport vp = { 0, 0, (float)app->extent.width, (float)app->extent.height, 0, 1 };
    VkRect2D sc = { { 0, 0 }, app->extent };
    VkPipelineViewportStateCreateInfo vps = { VK_STRUCTURE_TYPE_PIPELINE_VIEWPORT_STATE_CREATE_INFO };
    vps.viewportCount = 1; vps.pViewports = &vp;
    vps.scissorCount = 1; vps.pScissors = &sc;
    VkPipelineRasterizationStateCreateInfo rs = { VK_STRUCTURE_TYPE_PIPELINE_RASTERIZATION_STATE_CREATE_INFO };
    rs.polygonMode = VK_POLYGON_MODE_FILL;
    rs.cullMode = VK_CULL_MODE_NONE;
    rs.frontFace = VK_FRONT_FACE_COUNTER_CLOCKWISE;
    rs.lineWidth = 1.0f;
    VkPipelineMultisampleStateCreateInfo ms = { VK_STRUCTURE_TYPE_PIPELINE_MULTISAMPLE_STATE_CREATE_INFO };
    ms.rasterizationSamples = VK_SAMPLE_COUNT_1_BIT;
    VkPipelineColorBlendAttachmentState blend = {0};
    blend.colorWriteMask = 0xF;
    VkPipelineColorBlendStateCreateInfo cb = { VK_STRUCTURE_TYPE_PIPELINE_COLOR_BLEND_STATE_CREATE_INFO };
    cb.attachmentCount = 1; cb.pAttachments = &blend;
    VkPipelineDynamicStateCreateInfo dyn = { VK_STRUCTURE_TYPE_PIPELINE_DYNAMIC_STATE_CREATE_INFO };
    VkDynamicState dynStates[2] = { VK_DYNAMIC_STATE_VIEWPORT, VK_DYNAMIC_STATE_SCISSOR };
    dyn.dynamicStateCount = 2; dyn.pDynamicStates = dynStates;

    VkPipelineLayoutCreateInfo pli = { VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO };
    gCreatePipelineLayout(app->device, &pli, NULL, &app->pipeLayout);

    VkGraphicsPipelineCreateInfo gp = { VK_STRUCTURE_TYPE_GRAPHICS_PIPELINE_CREATE_INFO };
    gp.stageCount = 2; gp.pStages = stages;
    gp.pVertexInputState = &vi;
    gp.pInputAssemblyState = &ia;
    gp.pViewportState = &vps;
    gp.pRasterizationState = &rs;
    gp.pMultisampleState = &ms;
    gp.pColorBlendState = &cb;
    gp.pDynamicState = &dyn;
    gp.layout = app->pipeLayout;
    gp.renderPass = app->renderPass;
    gp.subpass = 0;
    VkResult r = gCreateGraphicsPipelines(app->device, VK_NULL_HANDLE, 1, &gp, NULL, &app->pipeline);
    if (r != VK_SUCCESS) { LOGE("创建管线失败: %d", r); return 0; }
    LOGI("渲染管线就绪");
    return 1;
}

// 命令池 + 命令缓冲。交换链重建后图片数会变，必须重新分配，
// 否则命令缓冲数量和 swapchain image 数量对不上。
static int alloc_command_buffers(ZaApp *app)
{
    if (app->cmdPool) { gDestroyCommandPool(app->device, app->cmdPool, NULL); app->cmdPool = VK_NULL_HANDLE; }
    free(app->cmds); app->cmds = NULL;
    if (!app->imageCount) return 0;
    VkCommandPoolCreateInfo cpi = { VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO };
    cpi.queueFamilyIndex = app->queueFamily;
    cpi.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT;
    gCreateCommandPool(app->device, &cpi, NULL, &app->cmdPool);
    app->cmds = (VkCommandBuffer *)calloc(app->imageCount, sizeof(VkCommandBuffer));
    if (!app->cmds) { LOGE("命令缓冲分配失败"); return 0; }
    VkCommandBufferAllocateInfo ai = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO };
    ai.commandPool = app->cmdPool;
    ai.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY;
    ai.commandBufferCount = app->imageCount;
    gAllocateCommandBuffers(app->device, &ai, app->cmds);
    LOGI("命令缓冲 %u 个已分配", app->imageCount);
    return 1;
}

static void record_and_draw(ZaApp *app, uint32_t imageIndex)
{
    VkCommandBufferBeginInfo bi = { VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO };
    bi.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    gBeginCommandBuffer(app->cmds[imageIndex], &bi);

    VkClearValue clear = { { 0.08f, 0.09f, 0.13f, 1.0f } };
    VkRenderPassBeginInfo rpb = { VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO };
    rpb.renderPass = app->renderPass;
    rpb.framebuffer = app->frames[imageIndex];
    rpb.renderArea.extent = app->extent;
    rpb.clearValueCount = 1;
    rpb.pClearValues = &clear;
    gCmdRenderPassBegin(app->cmds[imageIndex], &rpb, VK_SUBPASS_CONTENTS_INLINE);
    gCmdBindPipeline(app->cmds[imageIndex], VK_PIPELINE_BIND_POINT_GRAPHICS, app->pipeline);
    // viewport/scissor 声明成动态状态，管线里的值会被忽略，必须每帧用命令设置。
    // 这个 NDK 头是旧签名（4 参，没有 viewportArray/offset 形式）。
    VkViewport vp = { 0, 0, (float)app->extent.width, (float)app->extent.height, 0.0f, 1.0f };
    gCmdSetViewport(app->cmds[imageIndex], 0, 1, &vp);
    VkRect2D scissor = { { 0, 0 }, app->extent };
    gCmdSetScissor(app->cmds[imageIndex], 0, 1, &scissor);
    gCmdDraw(app->cmds[imageIndex], 3, 1, 0, 0);
    gCmdEndRenderPass(app->cmds[imageIndex]);
    gEndCommandBuffer(app->cmds[imageIndex]);

    VkPipelineStageFlags waitStage = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    VkSubmitInfo si = { VK_STRUCTURE_TYPE_SUBMIT_INFO };
    si.waitSemaphoreCount = 1; si.pWaitSemaphores = &app->render;
    si.pWaitDstStageMask = &waitStage;
    si.commandBufferCount = 1; si.pCommandBuffers = &app->cmds[imageIndex];
    si.signalSemaphoreCount = 1; si.pSignalSemaphores = &app->present;
    gResetFences(app->device, 1, &app->fence);
    gQueueSubmit(app->queue, 1, &si, app->fence);
    gWaitForFences(app->device, 1, &app->fence, VK_TRUE, UINT64_MAX);
}

// 渲染线程的崩溃不能带死整个进程（否则客机移植的进展全被掩盖）——
// 信号处理里靠这个标记区分「渲染崩了」和「客机崩了」。
extern __attribute__((visibility("default"))) volatile long za_render_tid;
extern __attribute__((visibility("default"))) volatile long za_render_entry;
extern __attribute__((visibility("default"))) volatile int za_render_crashes;
void za_install_signal_handlers(void);
void za_open_crash_log(void);
static void *render_thread(void *arg)
{
    ZaApp *app = (ZaApp *)arg;
    za_render_tid = syscall(SYS_gettid);
    za_render_entry = (unsigned long)render_thread;   // 崩了跳回这里重新来一帧
    while (app->running)
    {
        // ⚠ 连续崩太多次（窗口被系统销毁时 present 路径必崩）就**先歇着**：
        //   不歇的话会变成「崩→跳回→再崩」的死循环，100% CPU 空转，
        //   而且日志文件会被刷成几 MB（实测 20 秒 55000 行），
        //   最后整个进程被拖死 —— 客机的进展全被掩盖。
        if (za_render_crashes > 16)
        {
            struct timespec ts = { 0, 200 * 1000 * 1000 };
            nanosleep(&ts, NULL);
            continue;
        }
        // 闸门：交换链、命令缓冲、信号量没齐之前一律不碰。
        // （线程在 onCreate 就起了，窗口回调里的资源分配比它慢一拍。）
        if (!app->renderReady || !app->swapchain || !app->cmds || !app->imageCount)
        {
            struct timespec ts = { 0, 16 * 1000 * 1000 };
            nanosleep(&ts, NULL);
            continue;
        }
        uint32_t idx = 0;
        VkResult r = gAcquireNextImageKHR(app->device, app->swapchain, UINT64_MAX, app->acquire, VK_NULL_HANDLE, &idx);
        if (r != VK_SUCCESS)
        {
            LOGI("取图返回 %d%s", r, (r == VK_ERROR_OUT_OF_DATE_KHR) ? "（交换链过期，重建）" : "");
            if (r == VK_ERROR_OUT_OF_DATE_KHR)
            {
                // 重建交换链：图片数可能变，命令缓冲必须跟着重分配。
                app->renderReady = 0;
                destroy_swapchain(app);
                if (create_swapchain(app)) alloc_command_buffers(app);
                app->renderReady = 1;
            }
            else { struct timespec ts = { 0, 16 * 1000 * 1000 }; nanosleep(&ts, NULL); }
            continue;
        }
        if (idx >= app->imageCount) continue;   // 防御：越界索引会取到野指针
        // 窗口可能已经被系统销毁（息屏/旋转/通知栏遮挡）⇒ 这时 present 必崩，先跳过。
        if (!app->window || ANativeWindow_getWidth(app->window) <= 0 ||
            ANativeWindow_getHeight(app->window) <= 0) continue;
        record_and_draw(app, idx);
        VkPresentInfoKHR pi = { VK_STRUCTURE_TYPE_PRESENT_INFO_KHR };
        pi.waitSemaphoreCount = 1; pi.pWaitSemaphores = &app->present;
        pi.swapchainCount = 1; pi.pSwapchains = &app->swapchain;
        pi.pImageIndices = &idx;
        VkResult pr = gQueuePresentKHR(app->queue, &pi);
        if (pr != VK_SUCCESS)
        {
            LOGI("呈现返回 %d", pr);
            // 交换链过期（息屏/旋转/窗口被系统销毁都会这样）→ 重建后继续。
            if (pr == VK_ERROR_OUT_OF_DATE_KHR)
            {
                app->renderReady = 0;
                if (app->window) { destroy_swapchain(app); if (create_swapchain(app)) alloc_command_buffers(app); }
                app->renderReady = (app->window != NULL);
            }
        }
        app->frameCount++;
        if (app->frameCount == 1 || app->frameCount % 120 == 0)
            LOGI("已渲染 %d 帧 (%ux%u)", app->frameCount, app->extent.width, app->extent.height);
    }
    return NULL;
}

// 两种名字都要试，顺序有讲究：AOSP loader 的包装函数以 **KHR 后缀名**导出
// （vkGetDeviceProcAddr 查核心名可能拿到 ICD 的裸函数，loader 侧的交换链数据就没建立，present 时必崩）。
static void *gipa2(void *inst, const char *core, const char *khr)
{
    void *p = khr ? gGetInstanceProcAddr(inst, khr) : NULL;
    if (!p) p = gGetInstanceProcAddr(inst, core);
    return p;
}
// 设备级同理：KHR 别名优先，核心名兜底。
static void *gdp2(void *dev, const char *core, const char *khr)
{
    void *p = khr ? gGetDeviceProcAddr(dev, khr) : NULL;
    if (!p) p = gGetDeviceProcAddr(dev, core);
    return p;
}
// ---------------- 客机模块（main NSO + SDK NSO）装载与启动 ----------------
#include "za_guest_api.h"

int za_guest_load_sdk(const unsigned char *text, size_t tsz,
                      const unsigned char *rodata, size_t rsz,
                      const unsigned char *data, size_t dsz, size_t bss,
                      const unsigned char *exp, size_t explen,
                      const unsigned char *rel, size_t rellen,
                      const unsigned char *gate, size_t gatelen);
int za_guest_run_sdk_init(void);

static void *za_read_asset(AAssetManager *mgr, const char *name, size_t *size)
{
    AAsset *a = AAssetManager_open(mgr, name, AASSET_MODE_BUFFER);
    if (!a) return NULL;
    off_t n = AAsset_getLength(a);
    void *buf = malloc((size_t)n);
    if (!buf) { AAsset_close(a); return NULL; }
    if (AAsset_read(a, buf, (size_t)n) != n) { free(buf); AAsset_close(a); return NULL; }
    AAsset_close(a);
    *size = (size_t)n;
    return buf;
}

static void *guest_thread(void *arg)
{
    ANativeActivity *activity = (ANativeActivity *)arg;
    // PC 采样器要**最早**装上：SDK 初始化就在后面，崩溃多半发生在那里面。
    za_guest_start_sampler();
    // 登记本线程的栈边界：栈溢出时要知道「用了多少栈」。
    {
        long gtid = (long)syscall(SYS_gettid);
        za_stack_register_current(gtid, "guest");
        const za_stack_region_t *sr = za_stack_find(gtid);
        LOGI("客机线程栈: tid=%ld 范围=%p..%p", gtid,
             sr ? (void *)sr->lo : NULL, sr ? (void *)sr->hi : NULL);
    }
    // 心跳：用来判断「进程死了」时到底是哪条线程死的
    // （渲染线程崩了有处理器接着，客机线程死了却没人接 ⇒ 进程直接被内核杀掉）
    {
        static int beat = 0;
        beat++;
        if ((beat & 7) == 1) LOGI("客机线程心跳 #%d", beat);
    }
    AAssetManager *assets = activity->assetManager;
    // 图形层先起跑：它在自己的线程里建 Vulkan 实例/设备/交换链，并阻塞等窗口出现，
    // 这段耗时（真机 100–300 ms）与客机装载并行，别占客机线程。
    za_gfx_start(activity->internalDataPath ? activity->internalDataPath : "/data/local/tmp");
    size_t tsz = 0, rsz = 0, dsz = 0;
    unsigned char *text = (unsigned char *)za_read_asset(assets, "guest/text.bin", &tsz);
    unsigned char *rodata = (unsigned char *)za_read_asset(assets, "guest/rodata.bin", &rsz);
    unsigned char *data = (unsigned char *)za_read_asset(assets, "guest/data.bin", &dsz);
    if (!text || !rodata || !data) {
        LOGE("客机映像资产缺失（text=%p rodata=%p data=%p）", text, rodata, data);
        return NULL;
    }
    LOGI("客机映像: text=%zu rodata=%zu data=%zu 字节", tsz, rsz, dsz);

    // ---- 第 1 步：映射 main（固定基址 0x100000000）并建立它的导出符号视图 ----
    // （SDK 导入的 nnMain/nninitStartup 要从 main 的导出表查，所以 main 先映射）
    unsigned char *mbase = NULL;
    if (za_guest_map(text, rodata, data, 0x21FAE40u, &mbase) != 0) return NULL;
    size_t me_len = 0;
    unsigned char *mexp = (unsigned char *)za_read_asset(assets, "guest/main_exports.bin", &me_len);
    if (mexp) za_guest_mod_init(mbase, mexp, me_len);

    // ---- 第 2 步：装载 SDK NSO（提供 main 需要的 23,000 个 nn::* 符号）----
    size_t sts = 0, srs = 0, sds = 0, se_len = 0, sr_len = 0, sg_len = 0;
    unsigned char *stext = (unsigned char *)za_read_asset(assets, "guest_sdk/text.bin", &sts);
    unsigned char *srodata = (unsigned char *)za_read_asset(assets, "guest_sdk/rodata.bin", &srs);
    unsigned char *sdata = (unsigned char *)za_read_asset(assets, "guest_sdk/data.bin", &sds);
    unsigned char *sexp = (unsigned char *)za_read_asset(assets, "guest_sdk/sdk_exports.bin", &se_len);
    unsigned char *srel = (unsigned char *)za_read_asset(assets, "guest_sdk/sdk_relocs.bin", &sr_len);
    unsigned char *sgate = (unsigned char *)za_read_asset(assets, "guest_sdk/sdk_gate.bin", &sg_len);
    if (!stext || !srodata || !sdata || !sexp || !srel || !sgate) {
        LOGE("SDK 资产缺失（text=%p rodata=%p data=%p exp=%p rel=%p）",
             stext, srodata, sdata, sexp, srel, sgate);
    } else {
        LOGI("SDK 映像: text=%zu rodata=%zu data=%zu 字节", sts, srs, sds);
        if (za_guest_load_sdk(stext, sts, srodata, srs, sdata, sds, 0xCEB20u,
                              sexp, se_len, srel, sr_len, sgate, sg_len) == 0)
        {
            // ---- 第 3 步：重定位 main（它的导入会查到 SDK 的导出表）----
            za_guest_t g;
            if (za_guest_relocate(mbase, &g) == 0)
            {
                LOGI("装载完成：系统符号 %d 个，自动桩 %d 个，无解 %d 个",
                     g.resolved, g.stubbed, g.missing);
                // ---- 第 4 步：按 nn::init::Start 的真实顺序启动 ----
                //     （SDK 的 _init/构造器在 za_guest_boot 里、nninitStartup 之后跑）
                za_guest_boot(&g);
            }
        }
    }
    return NULL;
}

// ---------------- NativeActivity 回调 ----------------
static int ensure_vulkan(ZaApp *app);

// 窗口回调可能早于/晚于 onCreate 走到哪一步，两个入口都调用它（幂等）。
static void on_native_window_created(ANativeActivity *activity, ANativeWindow *window)
{
    ZaApp *app = (ZaApp *)activity->instance;
    LOGI("onNativeWindowCreated: window=%p 实例=%p 设备=%p", (void *)window, (void *)app->instance, (void *)app->device);
    if (za_gfx_active()) { za_gfx_set_window(window); return; }
    if (!ensure_vulkan(app)) { LOGE("Vulkan 初始化未完成，无法建表面"); return; }
    app->window = window;

    // 安卓表面要等窗口有了才能建（NDK 的 ANativeActivity 结构里没有 window 成员）。
    if (!gCreateAndroidSurfaceKHR) { LOGE("安卓表面函数不可用"); return; }
    // 窗口重建时先把旧表面丢掉，否则会泄漏。
    if (app->surface && gDestroySurfaceKHR) { gDestroySurfaceKHR(app->instance, app->surface, NULL); app->surface = VK_NULL_HANDLE; }
    // 必须在建表面之前给窗口设定缓冲区几何/格式：loader 的呈现路径要拿窗口的 BufferQueue，
    // 格式不匹配或没设过会直接解引用空指针（present 时崩在 loader 内部）。
    ANativeWindow_setBuffersGeometry(window, 0, 0, WINDOW_FORMAT_RGBA_8888);
    VkAndroidSurfaceCreateInfoKHR asi = { VK_STRUCTURE_TYPE_ANDROID_SURFACE_CREATE_INFO_KHR };
    asi.window = window;
    VkResult sr = gCreateAndroidSurfaceKHR(app->instance, &asi, NULL, &app->surface);
    LOGI("vkCreateAndroidSurfaceKHR -> %d", sr);
    if (sr != VK_SUCCESS) { LOGE("创建 Android 表面失败: %d", sr); return; }

    if (!create_swapchain(app)) { LOGE("交换链创建失败"); return; }
    if (!create_pipeline(app)) { LOGE("管线创建失败"); return; }

    if (!alloc_command_buffers(app)) { LOGE("命令缓冲分配失败"); return; }
    // vkCreateSemaphore 的 pCreateInfo 是必需参数，传 NULL 会让驱动解引用空指针。
    VkSemaphoreCreateInfo si = { VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO };
    gCreateSemaphore(app->device, &si, NULL, &app->acquire);
    gCreateSemaphore(app->device, &si, NULL, &app->render);
    gCreateSemaphore(app->device, &si, NULL, &app->present);
    VkFenceCreateInfo fi = { VK_STRUCTURE_TYPE_FENCE_CREATE_INFO };
    gCreateFence(app->device, &fi, NULL, &app->fence);
    // 所有渲染期资源齐了才放行渲染线程。
    app->renderReady = 1;
    LOGI("窗口就绪，开始渲染");
}

static void on_native_window_destroyed(ANativeActivity *activity, ANativeWindow *window)
{
    ZaApp *app = (ZaApp *)activity->instance;
    LOGI("onNativeWindowDestroyed");
    app->window = NULL;
    app->renderReady = 0;
    if (za_gfx_active()) { za_gfx_set_window(NULL); return; }
    destroy_swapchain(app);
}

static void on_activity_destroy(ANativeActivity *activity)
{
    ZaApp *app = (ZaApp *)activity->instance;
    app->running = 0;
    if (!za_gfx_active())
    {
        pthread_join(app->thread, NULL);
        destroy_swapchain(app);
        if (app->device) { gDestroyDevice(app->device, NULL); app->device = NULL; }
        if (app->surface && gDestroySurfaceKHR) { gDestroySurfaceKHR(app->instance, app->surface, NULL); app->surface = VK_NULL_HANDLE; }
        if (app->instance && gDestroyInstance) { gDestroyInstance(app->instance, NULL); app->instance = NULL; }
    }
    LOGI("宿主退出");
}

static int ensure_vulkan(ZaApp *app)
{
    // 幂等：窗口回调可能先来，重复调用直接返回。
    if (app->device) return 1;
    app->running = 1;

    g_lib = dlopen("libvulkan.so", RTLD_NOW | RTLD_LOCAL);
    if (!g_lib) { LOGE("dlopen libvulkan.so 失败: %s", dlerror()); return 0; }
    gGetInstanceProcAddr = (PFN_vkGetInstanceProcAddr)dlsym(g_lib, "vkGetInstanceProcAddr");
    gCreateInstance = (PFN_vkCreateInstance)gGetInstanceProcAddr(NULL, "vkCreateInstance");

    VkApplicationInfo appInfo = { VK_STRUCTURE_TYPE_APPLICATION_INFO };
    appInfo.pApplicationName = "PokemonZA";
    appInfo.apiVersion = VK_API_VERSION_1_1;
    // 交换链需要 surface 扩展；安卓表面走 VK_KHR_android_surface。
    const char *instExts[2] = { VK_KHR_SURFACE_EXTENSION_NAME, VK_KHR_ANDROID_SURFACE_EXTENSION_NAME };
    VkInstanceCreateInfo ici = { VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO };
    ici.pApplicationInfo = &appInfo;
    ici.enabledExtensionCount = 2;
    ici.ppEnabledExtensionNames = instExts;
    VkResult r = gCreateInstance(&ici, NULL, &app->instance);
    if (r != VK_SUCCESS) { LOGE("创建实例失败: %d", r); return 0; }
    gDestroyInstance = (PFN_vkDestroyInstance)gGetInstanceProcAddr(app->instance, "vkDestroyInstance");
    gDestroySurfaceKHR = (PFN_vkDestroySurfaceKHR)gGetInstanceProcAddr(app->instance, "vkDestroySurfaceKHR");
    // 安卓表面函数：Android 的 libvulkan.so 对「NULL 实例」查扩展函数常常返回 NULL，
    // 必须用实例再查一次，或者直接从 so 里 dlsym 取。
    gCreateAndroidSurfaceKHR = (PFN_vkCreateAndroidSurfaceKHR)gGetInstanceProcAddr(app->instance, "vkCreateAndroidSurfaceKHR");
    if (!gCreateAndroidSurfaceKHR)
        gCreateAndroidSurfaceKHR = (PFN_vkCreateAndroidSurfaceKHR)dlsym(g_lib, "vkCreateAndroidSurfaceKHR");
    if (!gCreateAndroidSurfaceKHR) { LOGE("拿不到 vkCreateAndroidSurfaceKHR"); return 0; }
    gEnumeratePhysicalDevices = (PFN_vkEnumeratePhysicalDevices)gGetInstanceProcAddr(app->instance, "vkEnumeratePhysicalDevices");
    gGetPhysicalDeviceProperties = (PFN_vkGetPhysicalDeviceProperties)gGetInstanceProcAddr(app->instance, "vkGetPhysicalDeviceProperties");
    gGetPhysicalDeviceMemoryProperties = (PFN_vkGetPhysicalDeviceMemoryProperties)gGetInstanceProcAddr(app->instance, "vkGetPhysicalDeviceMemoryProperties");
    gGetPhysicalDeviceQueueFamilyProperties = (PFN_vkGetPhysicalDeviceQueueFamilyProperties)gGetInstanceProcAddr(app->instance, "vkGetPhysicalDeviceQueueFamilyProperties");
    gGetPhysicalDeviceSurfaceSupportKHR = (PFN_vkGetPhysicalDeviceSurfaceSupportKHR)gipa2(app->instance, "vkGetPhysicalDeviceSurfaceSupport", "vkGetPhysicalDeviceSurfaceSupportKHR");
    gGetPhysicalDeviceSurfaceCapabilitiesKHR = (PFN_vkGetPhysicalDeviceSurfaceCapabilitiesKHR)gipa2(app->instance, "vkGetPhysicalDeviceSurfaceCapabilities", "vkGetPhysicalDeviceSurfaceCapabilitiesKHR");
    gGetPhysicalDeviceSurfaceFormatsKHR = (PFN_vkGetPhysicalDeviceSurfaceFormatsKHR)gipa2(app->instance, "vkGetPhysicalDeviceSurfaceFormats", "vkGetPhysicalDeviceSurfaceFormatsKHR");
    gGetPhysicalDeviceSurfacePresentModesKHR = (PFN_vkGetPhysicalDeviceSurfacePresentModesKHR)gipa2(app->instance, "vkGetPhysicalDeviceSurfacePresentModes", "vkGetPhysicalDeviceSurfacePresentModesKHR");
    gCreateDevice = (PFN_vkCreateDevice)gGetInstanceProcAddr(app->instance, "vkCreateDevice");
    gDestroyDevice = (PFN_vkDestroyDevice)gGetInstanceProcAddr(app->instance, "vkDestroyDevice");
    if (!gCreateDevice) { LOGE("拿不到 vkCreateDevice"); return 0; }

    uint32_t n = 0;
    gEnumeratePhysicalDevices(app->instance, &n, NULL);
    VkPhysicalDevice *pds = (VkPhysicalDevice *)malloc(sizeof(VkPhysicalDevice) * n);
    gEnumeratePhysicalDevices(app->instance, &n, pds);
    app->phys = pds[0];
    free(pds);
    VkPhysicalDeviceProperties props;
    gGetPhysicalDeviceProperties(app->phys, &props);
    LOGI("GPU: %s", props.deviceName);
    LOGI("Vulkan API %u.%u.%u  驱动 %u.%u.%u", VK_VERSION_MAJOR(props.apiVersion), VK_VERSION_MINOR(props.apiVersion),
         VK_VERSION_PATCH(props.apiVersion), VK_VERSION_MAJOR(props.driverVersion), VK_VERSION_MINOR(props.driverVersion),
         VK_VERSION_PATCH(props.driverVersion));

    uint32_t qn = 0;
    LOGI("步骤: 查队列族");
    gGetPhysicalDeviceQueueFamilyProperties(app->phys, &qn, NULL);
    LOGI("步骤: 队列族数 = %u", qn);
    VkQueueFamilyProperties *qfs = (VkQueueFamilyProperties *)malloc(sizeof(VkQueueFamilyProperties) * qn);
    gGetPhysicalDeviceQueueFamilyProperties(app->phys, &qn, qfs);
    for (uint32_t i = 0; i < qn; i++)
        if (qfs[i].queueFlags & VK_QUEUE_GRAPHICS_BIT) { app->queueFamily = i; break; }
    free(qfs);
    LOGI("步骤: 图形队列族 = %u", app->queueFamily);

    float prio = 1.0f;
    VkDeviceQueueCreateInfo dq = { VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO };
    dq.queueFamilyIndex = app->queueFamily;
    dq.queueCount = 1;
    dq.pQueuePriorities = &prio;
    VkDeviceCreateInfo dci = { VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO };
    const char *devExts[1] = { VK_KHR_SWAPCHAIN_EXTENSION_NAME };
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &dq;
    dci.enabledExtensionCount = 1;
    dci.ppEnabledExtensionNames = devExts;
    LOGI("步骤: 建逻辑设备");
    // 必须申请 VK_KHR_swapchain：不申请的话 loader 会给 vkQueuePresentKHR 装上「拒绝桩」，
    // 呈现时必崩（devExts 是函数作用域的数组，全程有效）。
    dci.enabledExtensionCount = 1;
    dci.ppEnabledExtensionNames = devExts;
    r = gCreateDevice(app->phys, &dci, NULL, &app->device);
    LOGI("步骤: 带 swapchain 扩展建设备 = %d", r);
    if (r != VK_SUCCESS)
    {
        // 退路：不申请扩展（此时不能用交换链，但至少设备能建起来）
        dci.enabledExtensionCount = 0;
        dci.ppEnabledExtensionNames = NULL;
        r = gCreateDevice(app->phys, &dci, NULL, &app->device);
        LOGI("步骤: 无扩展建设备 = %d", r);
    }
    if (r != VK_SUCCESS) { LOGE("创建设备失败: %d", r); return 0; }
    gGetDeviceProcAddr = (PFN_vkGetDeviceProcAddr)gGetInstanceProcAddr(app->instance, "vkGetDeviceProcAddr");
    gGetDeviceQueue = (PFN_vkGetDeviceQueue)gGetDeviceProcAddr(app->device, "vkGetDeviceQueue");
    gCreateSwapchainKHR = (PFN_vkCreateSwapchainKHR)gipa2(app->instance, "vkCreateSwapchain", "vkCreateSwapchainKHR");
    gDestroySwapchainKHR = (PFN_vkDestroySwapchainKHR)gipa2(app->instance, "vkDestroySwapchain", "vkDestroySwapchainKHR");
    gGetSwapchainImages = (PFN_vkGetSwapchainImagesKHR)gipa2(app->instance, "vkGetSwapchainImages", "vkGetSwapchainImagesKHR");
    gCreateImageView = (PFN_vkCreateImageView)gGetDeviceProcAddr(app->device, "vkCreateImageView");
    gDestroyImageView = (PFN_vkDestroyImageView)gGetDeviceProcAddr(app->device, "vkDestroyImageView");
    gCreateShaderModule = (PFN_vkCreateShaderModule)gGetDeviceProcAddr(app->device, "vkCreateShaderModule");
    gDestroyShaderModule = (PFN_vkDestroyShaderModule)gGetDeviceProcAddr(app->device, "vkDestroyShaderModule");
    gCreatePipelineLayout = (PFN_vkCreatePipelineLayout)gGetDeviceProcAddr(app->device, "vkCreatePipelineLayout");
    gDestroyPipelineLayout = (PFN_vkDestroyPipelineLayout)gGetDeviceProcAddr(app->device, "vkDestroyPipelineLayout");
    gCreateRenderPass = (PFN_vkCreateRenderPass)gGetDeviceProcAddr(app->device, "vkCreateRenderPass");
    gDestroyRenderPass = (PFN_vkDestroyRenderPass)gGetDeviceProcAddr(app->device, "vkDestroyRenderPass");
    gCreateFramebuffer = (PFN_vkCreateFramebuffer)gGetDeviceProcAddr(app->device, "vkCreateFramebuffer");
    gDestroyFramebuffer = (PFN_vkDestroyFramebuffer)gGetDeviceProcAddr(app->device, "vkDestroyFramebuffer");
    gCreateGraphicsPipelines = (PFN_vkCreateGraphicsPipelines)gGetDeviceProcAddr(app->device, "vkCreateGraphicsPipelines");
    gDestroyPipeline = (PFN_vkDestroyPipeline)gGetDeviceProcAddr(app->device, "vkDestroyPipeline");
    gCreateCommandPool = (PFN_vkCreateCommandPool)gGetDeviceProcAddr(app->device, "vkCreateCommandPool");
    gDestroyCommandPool = (PFN_vkDestroyCommandPool)gGetDeviceProcAddr(app->device, "vkDestroyCommandPool");
    gAllocateCommandBuffers = (PFN_vkAllocateCommandBuffers)gGetDeviceProcAddr(app->device, "vkAllocateCommandBuffers");
    gFreeCommandBuffers = (PFN_vkFreeCommandBuffers)gGetDeviceProcAddr(app->device, "vkFreeCommandBuffers");
    gBeginCommandBuffer = (PFN_vkBeginCommandBuffer)gGetDeviceProcAddr(app->device, "vkBeginCommandBuffer");
    gEndCommandBuffer = (PFN_vkEndCommandBuffer)gGetDeviceProcAddr(app->device, "vkEndCommandBuffer");
    gCmdRenderPassBegin = (PFN_vkCmdBeginRenderPass)gGetDeviceProcAddr(app->device, "vkCmdBeginRenderPass");
    gCmdSetViewport = (PFN_vkCmdSetViewport)gGetDeviceProcAddr(app->device, "vkCmdSetViewport");
    gCmdSetScissor = (PFN_vkCmdSetScissor)gGetDeviceProcAddr(app->device, "vkCmdSetScissor");
    gCmdBindPipeline = (PFN_vkCmdBindPipeline)gGetDeviceProcAddr(app->device, "vkCmdBindPipeline");
    gCmdDraw = (PFN_vkCmdDraw)gGetDeviceProcAddr(app->device, "vkCmdDraw");
    gCmdEndRenderPass = (PFN_vkCmdEndRenderPass)gGetDeviceProcAddr(app->device, "vkCmdEndRenderPass");
    gQueueSubmit = (PFN_vkQueueSubmit)gGetDeviceProcAddr(app->device, "vkQueueSubmit");
    gQueuePresentKHR = (PFN_vkQueuePresentKHR)gipa2(app->instance, "vkQueuePresent", "vkQueuePresentKHR");
    gAcquireNextImageKHR = (PFN_vkAcquireNextImageKHR)gipa2(app->instance, "vkAcquireNextImage", "vkAcquireNextImageKHR");
    gCreateSemaphore = (PFN_vkCreateSemaphore)gGetDeviceProcAddr(app->device, "vkCreateSemaphore");
    gDestroySemaphore = (PFN_vkDestroySemaphore)gGetDeviceProcAddr(app->device, "vkDestroySemaphore");
    gCreateFence = (PFN_vkCreateFence)gGetDeviceProcAddr(app->device, "vkCreateFence");
    gDestroyFence = (PFN_vkDestroyFence)gGetDeviceProcAddr(app->device, "vkDestroyFence");
    gWaitForFences = (PFN_vkWaitForFences)gGetDeviceProcAddr(app->device, "vkWaitForFences");
    gResetFences = (PFN_vkResetFences)gGetDeviceProcAddr(app->device, "vkResetFences");
    gGetDeviceQueue(app->device, app->queueFamily, 0, &app->queue);
    LOGI("Vulkan 设备就绪（队列族 %u）", app->queueFamily);
    return 1;
}

static void on_activity_create(ANativeActivity *activity)
{
    ZaApp *app = (ZaApp *)calloc(1, sizeof(ZaApp));
    activity->instance = app;
    app->activity = activity;
    app->assets = activity->assetManager;
    if (!za_gfx_active()) ensure_vulkan(app);
}

__attribute__((visibility("default"))) void ANativeActivity_onCreate(ANativeActivity *activity, void *savedState, size_t savedStateSize)
{
    LOGI("ANativeActivity_onCreate 入口");
    za_install_signal_handlers();
    za_open_crash_log();
    on_activity_create(activity);
    activity->callbacks->onNativeWindowCreated = on_native_window_created;
    activity->callbacks->onNativeWindowDestroyed = on_native_window_destroyed;
    activity->callbacks->onDestroy = on_activity_destroy;
    ZaApp *app = (ZaApp *)activity->instance;
    if (!za_gfx_active()) pthread_create(&app->thread, NULL, render_thread, app);
    // 客机模块另起一条线程装载+启动：它崩了也不影响 Vulkan 画面。
    // 栈给大一点：Switch 游戏的静态构造器吃栈很凶，默认 1MB 会直接栈溢出
    // （症状是进程被 SIGSEGV 静默杀掉，连 tombstone 都没有）。
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 256 * 1024 * 1024);
    pthread_t guest;
    // 诊断开关：files 目录下存在 za_noguest 时**不启动客机**。
    // 用来把「宿主/ART 自己的问题」与「客机把宿主搞坏」分开。
    {
        char p[512];
        const char *d = activity->internalDataPath;
        int skip = 0;
        p[0] = 0;
        if (d) {
            snprintf(p, sizeof p, "%s/za_noguest", d);
            skip = (access(p, F_OK) == 0);
        }
        if (skip) {
            LOGI("★ 诊断开关生效：不启动客机（%s）", p);
        } else if (pthread_create(&guest, &attr, guest_thread, activity) == 0) {
            pthread_detach(guest);
        }
    }
    pthread_attr_destroy(&attr);
    LOGI("ANativeActivity_onCreate 返回");
}
