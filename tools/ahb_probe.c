// Probe: why does the AHardwareBuffer zero-copy path fail on Mali-G925 (MT6991)?
// (1) does the AHB dma-buf fd allow mmap at all, per usage flag combination; (2) which external-memory
// extensions the Vulkan device has, and minImportedHostPointerAlignment for VK_EXT_external_memory_host.
// Runs as the app's uid (run-as), like the port itself.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <android/hardware_buffer.h>
#include <vulkan/vulkan.h>

static int recv_fds(int sock, int *fds, int max) {
    char buf[1]; struct iovec iov = {buf, 1}; char cmsgbuf[CMSG_SPACE(sizeof(int) * 16)];
    struct msghdr msg = {0}; msg.msg_iov = &iov; msg.msg_iovlen = 1; msg.msg_control = cmsgbuf; msg.msg_controllen = sizeof cmsgbuf;
    if (recvmsg(sock, &msg, 0) < 0) return -1;
    int n = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c))
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS)
            for (size_t o = 0; o + sizeof(int) <= c->cmsg_len - CMSG_LEN(0); o += sizeof(int)) fds[n++] = *(int *)(CMSG_DATA(c) + o);
    return n;
}

static uint8_t *map_buf_fd(int *fds, int n, uint64_t size, uint8_t *at) {
    int pick = -1;
    for (int i = 0; i < n; i++) { struct stat st; if (!fstat(fds[i], &st) && (uint64_t)st.st_size == size) { pick = i; break; } }
    if (pick < 0) pick = n > 1 ? 1 : 0;
    printf("  buffer fd = [%d] (of %d)\n", pick, n);
    int fl = at ? MAP_SHARED | MAP_FIXED : MAP_SHARED;
    void *m = mmap(at, size, PROT_READ | PROT_WRITE, fl, fds[pick], 0);
    if (m != MAP_FAILED && m != at) { printf("  MAP_FIXED at %p returned %p\n", at, m); munmap(m, size); return NULL; }
    return m == MAP_FAILED ? NULL : m;
}

// the whole mechanism the port uses: the dma-buf mapped over the guest's own pages, CPU writes there, the GPU's import reads them
static void map_fixed_test(void) {
    uint64_t size = 16 << 20;
    AHardwareBuffer_Desc d = {(uint32_t)size, 1, 1, AHARDWAREBUFFER_FORMAT_BLOB,
        AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN | AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN | AHARDWAREBUFFER_USAGE_GPU_DATA_BUFFER, 0, 0, 0};
    AHardwareBuffer *ahb = NULL;
    if (AHardwareBuffer_allocate(&d, &ahb)) return;
    void *guest = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    memset(guest, 0xAB, size);
    int sv[2]; if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv)) return;
    int fds[16]; int n = AHardwareBuffer_sendHandleToUnixSocket(ahb, sv[0]) ? -1 : recv_fds(sv[1], fds, 16);
    printf("=== MAP_FIXED test over guest %p (%llu MB), nfd=%d\n", guest, (unsigned long long)(size >> 20), n);
    uint8_t *m = n > 0 ? map_buf_fd(fds, n, size, guest) : NULL;
    if (m == guest) {
        m[0] = 0x5A; memset(m + size - 64, 0x77, 64);
        void *p = NULL; int lr = AHardwareBuffer_lock(ahb, AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN, -1, NULL, &p);
        printf("  wrote through the mapping; lock rc=%d first=%#x last=%#x\n", lr, lr ? 0 : ((uint8_t *)p)[0], lr ? 0 : ((uint8_t *)p)[size - 1]);
        if (!lr) AHardwareBuffer_unlock(ahb, NULL);
    } else printf("  MAP_FIXED failed: %s\n", strerror(errno));
    for (int i = 0; i < n; i++) close(fds[i]);
    close(sv[0]); close(sv[1]);
    AHardwareBuffer_release(ahb);
}

static void try_usage(const char *name, uint64_t usage, uint64_t size) {
    AHardwareBuffer_Desc d = {(uint32_t)size, 1, 1, AHARDWAREBUFFER_FORMAT_BLOB, usage, 0, 0, 0};
    AHardwareBuffer *ahb = NULL;
    int rc = AHardwareBuffer_allocate(&d, &ahb);
    printf("=== %s usage=%#llx allocate rc=%d (%s)\n", name, (unsigned long long)usage, rc, rc ? strerror(-rc) : "ok");
    if (rc) return;
    void *p = NULL; int lr = AHardwareBuffer_lock(ahb, usage & (AHARDWAREBUFFER_USAGE_CPU_READ_MASK | AHARDWAREBUFFER_USAGE_CPU_WRITE_MASK), -1, NULL, &p);
    printf("  lock rc=%d (%s) ptr=%p\n", lr, lr ? strerror(-lr) : "ok", p);
    if (!lr) AHardwareBuffer_unlock(ahb, NULL);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv)) { perror("socketpair"); AHardwareBuffer_release(ahb); return; }
    int snd = AHardwareBuffer_sendHandleToUnixSocket(ahb, sv[0]);
    int fds[16]; int n = snd ? -1 : recv_fds(sv[1], fds, 16);
    printf("  send=%d nfd=%d\n", snd, n);
    for (int i = 0; i < n; i++) {
        int fl = fcntl(fds[i], F_GETFL); struct stat st; fstat(fds[i], &st);
        int acc = fl & O_ACCMODE;
        printf("  fd[%d] flags=%#x acc=%s st_size=%lld\n", i, fl, acc == O_RDONLY ? "RDONLY" : acc == O_WRONLY ? "WRONLY" : "RDWR", (long long)st.st_size);
        void *m = mmap(NULL, size, PROT_READ, MAP_SHARED, fds[i], 0);
        printf("    mmap RO -> %p %s\n", m, m == MAP_FAILED ? strerror(errno) : "ok");
        if (m != MAP_FAILED) munmap(m, size);
        errno = 0;
        m = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fds[i], 0);
        printf("    mmap RW -> %p %s\n", m, m == MAP_FAILED ? strerror(errno) : "ok");
        if (m != MAP_FAILED) munmap(m, size);
        errno = 0;
    }
    for (int i = 0; i < n; i++) close(fds[i]);
    close(sv[0]); close(sv[1]);
    AHardwareBuffer_release(ahb);
}

static void vk_probe(void) {
    VkApplicationInfo app = {VK_STRUCTURE_TYPE_APPLICATION_INFO, NULL, "probe", 1, "probe", 1, VK_API_VERSION_1_3};
    VkInstanceCreateInfo ci = {VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, NULL, 0, &app, 0, NULL, 0, NULL};
    VkInstance inst;
    if (vkCreateInstance(&ci, NULL, &inst)) { printf("vkCreateInstance failed\n"); return; }
    uint32_t np = 0; vkEnumeratePhysicalDevices(inst, &np, NULL); VkPhysicalDevice pd[4];
    if (!np || np > 4) { printf("no physical device\n"); return; }
    vkEnumeratePhysicalDevices(inst, &np, pd);
    uint32_t ne = 0; vkEnumerateDeviceExtensionProperties(pd[0], NULL, &ne, NULL);
    VkExtensionProperties *ex = calloc(ne, sizeof *ex);
    vkEnumerateDeviceExtensionProperties(pd[0], NULL, &ne, ex);
    printf("=== %u device extensions; external-memory ones:\n", ne);
    int has_host = 0;
    for (uint32_t i = 0; i < ne; i++) {
        if (!strstr(ex[i].extensionName, "external_memory") && !strstr(ex[i].extensionName, "dma_buf") && !strstr(ex[i].extensionName, "hardware_buffer")) continue;
        printf("  %s\n", ex[i].extensionName);
        if (!strcmp(ex[i].extensionName, "VK_EXT_external_memory_host")) has_host = 1;
    }
    PFN_vkGetPhysicalDeviceProperties2 gpp2 = (PFN_vkGetPhysicalDeviceProperties2)vkGetInstanceProcAddr(inst, "vkGetPhysicalDeviceProperties2");
    if (has_host && gpp2) {
        VkPhysicalDeviceExternalMemoryHostPropertiesEXT hp = {VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_MEMORY_HOST_PROPERTIES_EXT};
        VkPhysicalDeviceProperties2 p2 = {VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2, &hp};
        gpp2(pd[0], &p2);
        printf("  minImportedHostPointerAlignment = %llu\n", (unsigned long long)hp.minImportedHostPointerAlignment);
    }
    free(ex); vkDestroyInstance(inst, NULL);
}

int main(int argc, char **argv) {
    uint64_t mb = argc > 1 ? strtoull(argv[1], NULL, 0) : 16;
    uint64_t size = mb << 20;
    printf("probe pid %d uid %d size %llu MB\n", getpid(), getuid(), (unsigned long long)mb);
    vk_probe();
    map_fixed_test();
    const uint64_t R = AHARDWAREBUFFER_USAGE_CPU_READ_OFTEN, W = AHARDWAREBUFFER_USAGE_CPU_WRITE_OFTEN, G = AHARDWAREBUFFER_USAGE_GPU_DATA_BUFFER;
    try_usage("R|W|GPU_DATA", R | W | G, size);
    try_usage("R|W", R | W, size);
    try_usage("GPU_DATA", G, size);
    try_usage("R|W|SAMPLED", R | W | AHARDWAREBUFFER_USAGE_GPU_SAMPLED_IMAGE, size);
    printf("done\n");
    return 0;
}
