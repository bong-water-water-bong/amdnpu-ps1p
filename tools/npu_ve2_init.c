/*
 * NPU VE2 Init Test - Minimal VE2 HW context creation via raw IOCTLs
 * 
 * This tests the minimum required sequence for VE2 NPU5 initialization:
 * 1. Open /dev/accel/accel0
 * 2. Register xclbin
 * 3. Create dev_heap BO (AMDXDNA_BO_DEV_HEAP)
 * 4. Create HW context
 * 5. Submit command  
 * 6. Wait for completion
 *
 * Build: gcc -o npu_ve2_init npu_ve2_init.c -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>

#include <drm/drm.h>
#include <drm/amdxdna_accel.h>

/* Missing from public uapi header (they're in kernel's local copy) */
#ifndef DRM_AMDXDNA_WAIT_CMD
#define DRM_AMDXDNA_WAIT_CMD     9
#endif

#ifndef DRM_IOCTL_AMDXDNA_WAIT_CMD
struct amdxdna_drm_wait_cmd {
    uint32_t hwctx;
    uint32_t timeout;
    uint64_t seq;
};

#define DRM_IOCTL_AMDXDNA_WAIT_CMD \
    DRM_IOWR(DRM_COMMAND_BASE + DRM_AMDXDNA_WAIT_CMD, \
             struct amdxdna_drm_wait_cmd)
#endif

/* BO types from kernel */
#ifndef AMDXDNA_BO_DEV_HEAP
#define AMDXDNA_BO_DEV_HEAP  0x4
#endif
#ifndef AMDXDNA_BO_CMD
#define AMDXDNA_BO_CMD       0x2
#endif

/* QoS priority */
#ifndef AMDXDNA_QOS_NORMAL_PRIORITY
#define AMDXDNA_QOS_NORMAL_PRIORITY 0x200
#endif

static double get_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int open_accel(void) {
    int fd = open("/dev/accel/accel0", O_RDWR);
    if (fd < 0) perror("open");
    return fd;
}

static int create_bo(int fd, uint32_t type, size_t size, uint32_t flags,
                     uint32_t *handle_out, uint64_t *vaddr_out) {
    struct amdxdna_drm_create_bo req;
    int ret;

    memset(&req, 0, sizeof(req));
    req.type = type;
    req.size = size;
    req.flags = flags;

    ret = ioctl(fd, DRM_IOCTL_AMDXDNA_CREATE_BO, &req);
    if (ret < 0) {
        perror("CREATE_BO");
        return ret;
    }

    *handle_out = req.handle;
    *vaddr_out = req.vaddr;
    return 0;
}

static int sync_bo(int fd, uint32_t handle, uint32_t offset, size_t size,
                   uint32_t direction) {
    struct amdxdna_drm_sync_bo req;
    int ret;

    memset(&req, 0, sizeof(req));
    req.handle = handle;
    req.direction = direction;
    req.offset = offset;
    req.size = size;

    ret = ioctl(fd, DRM_IOCTL_AMDXDNA_SYNC_BO, &req);
    if (ret < 0) perror("SYNC_BO");
    return ret;
}

static int get_bo_info(int fd, uint32_t handle, struct amdxdna_drm_get_bo_info *info) {
    memset(info, 0, sizeof(*info));
    info->handle = handle;
    return ioctl(fd, DRM_IOCTL_AMDXDNA_GET_BO_INFO, info);
}

/* Per-thread data for concurrent test */
typedef struct {
    int thread_id;
    int iterations;
    double *submit_times;
    double *done_times;
    uint64_t *seq_numbers;
    int success_count;
    int fail_count;
} thread_data_t;

static void *worker_thread(void *arg) {
    thread_data_t *td = (thread_data_t *)arg;
    struct amdxdna_drm_create_hwctx ctx_req;
    struct amdxdna_qos_info qos;
    uint32_t hwctx, syncobj;
    int fd, ret;
    double t_sub, t_done;

    fd = open_accel();
    if (fd < 0) {
        td->fail_count = td->iterations;
        return NULL;
    }

    /* Create HW context (requires xclbin to be registered by first thread) */
    memset(&qos, 0, sizeof(qos));
    qos.priority = AMDXDNA_QOS_NORMAL_PRIORITY;

    memset(&ctx_req, 0, sizeof(ctx_req));
    ctx_req.qos_p = (uint64_t)(uintptr_t)&qos;
    ctx_req.num_tiles = 1;
    ctx_req.umq_bo = 0; /* privileged context = false for now */

    ret = ioctl(fd, DRM_IOCTL_AMDXDNA_CREATE_HWCTX, &ctx_req);
    if (ret < 0) {
        printf("  [Thread %d] CREATE_HWCTX failed: %s\n",
               td->thread_id, strerror(errno));
        close(fd);
        td->fail_count = td->iterations;
        return NULL;
    }

    hwctx = ctx_req.handle;
    syncobj = ctx_req.syncobj_handle;
    printf("  [Thread %d] hwctx=%u syncobj=%u doorbell=%u\n",
           td->thread_id, hwctx, syncobj, ctx_req.umq_doorbell);

    /* Submit and wait iterations */
    for (int i = 0; i < td->iterations; i++) {
        struct amdxdna_drm_exec_cmd exec_req;
        uint64_t seq;

        t_sub = get_time();
        td->submit_times[i] = t_sub;

        memset(&exec_req, 0, sizeof(exec_req));
        exec_req.hwctx = hwctx;
        ret = ioctl(fd, DRM_IOCTL_AMDXDNA_EXEC_CMD, &exec_req);
        if (ret < 0) {
            printf("  [Thread %d] iter %d EXEC_CMD failed: %s\n",
                   td->thread_id, i, strerror(errno));
            td->fail_count++;
            continue;
        }
        seq = exec_req.seq;

        /* Wait with 5 second timeout */
        struct amdxdna_drm_wait_cmd wait_req;
        memset(&wait_req, 0, sizeof(wait_req));
        wait_req.hwctx = hwctx;
        wait_req.timeout = 5000;
        wait_req.seq = seq;

        ret = ioctl(fd, DRM_IOCTL_AMDXDNA_WAIT_CMD, &wait_req);
        if (ret < 0) {
            printf("  [Thread %d] iter %d WAIT_CMD failed: %s\n",
                   td->thread_id, i, strerror(errno));
            td->fail_count++;
            continue;
        }

        t_done = get_time();
        td->done_times[i] = t_done;
        td->seq_numbers[i] = seq;
        td->success_count++;
    }

    close(fd);
    return NULL;
}

int main(int argc, char **argv) {
    int n_threads = 1;
    int n_iterations = 10;
    int ret;

    if (argc >= 2) n_threads = atoi(argv[1]);
    if (argc >= 3) n_iterations = atoi(argv[2]);

    printf("NPU VE2 Test: %d thread(s) x %d iterations\n\n", n_threads, n_iterations);

    /* Open device */
    int fd = open_accel();
    if (fd < 0) return 1;
    printf("[OK] Opened /dev/accel/accel0 (fd=%d)\n", fd);

    /* Register xclbin */
    const char *xclbin_path = "/tmp/xdna-driver/src/shim_ve2/Runner/latency/validate.xclbin";
    FILE *xf = fopen(xclbin_path, "rb");
    if (!xf) { perror("fopen xclbin"); return 1; }
    fseek(xf, 0, SEEK_END);
    size_t xclbin_size = ftell(xf);
    fseek(xf, 0, SEEK_SET);
    void *xclbin_data = malloc(xclbin_size);
    fread(xclbin_data, 1, xclbin_size, xf);
    fclose(xf);

    /* Use DRM_IOCTL_AMDXDNA_REGISTER_XCLBIN or load_xclbin */
    /* The pyxrt uses register_xclbin internally. For raw IOCTLs,
     * we need DRM_IOCTL_AMDXDNA_REGISTER_XCLBIN if it exists. */
    /* Check if there's a create_bo for DEV_HEAP type */
    
    /* Try creating DEV_HEAP BO first */
    uint32_t heap_handle;
    uint64_t heap_vaddr;
    ret = create_bo(fd, AMDXDNA_BO_DEV_HEAP, 0x100000, /* 1MB */
                    0, &heap_handle, &heap_vaddr);
    if (ret < 0) {
        printf("[FAIL] CREATE_BO (DEV_HEAP): %s\n", strerror(errno));
        printf("  (Note: VE2 requires xclbin registration before DEV_HEAP)\n");
    } else {
        printf("[OK] DEV_HEAP BO: handle=%u vaddr=0x%lx\n", heap_handle, heap_vaddr);
    }

    /* Now try HW context creation */
    struct amdxdna_drm_create_hwctx ctx_req;
    struct amdxdna_qos_info qos;

    memset(&qos, 0, sizeof(qos));
    qos.priority = AMDXDNA_QOS_NORMAL_PRIORITY;

    memset(&ctx_req, 0, sizeof(ctx_req));
    ctx_req.qos_p = (uint64_t)(uintptr_t)&qos;
    ctx_req.num_tiles = 1;
    ctx_req.umq_bo = 0;

    ret = ioctl(fd, DRM_IOCTL_AMDXDNA_CREATE_HWCTX, &ctx_req);
    if (ret < 0) {
        printf("[FAIL] CREATE_HWCTX: %s\n", strerror(errno));
        printf("  qos_p=0x%lx num_tiles=%u\n", ctx_req.qos_p, ctx_req.num_tiles);
        close(fd);
        
        /* Check if we need a different setup */
        printf("\nTrying alternative: register xclbin first...\n");
        
        /* Check DRM_IOCTL numbers for register_xclbin */
        /* The kernel-side create_bo with DEV_HEAP type should work */
        /* Let's check if xclbin registration via pyxrt helps our C code */
        fd = open_accel();
        if (fd < 0) return 1;
        
        /* XRT's register_xclbin calls create_bo(DEV_HEAP) internally. 
         * The IOCTL is CREATE_BO with type=AMDXDNA_BO_DEV_HEAP (4).
         * But the kernel checks for existing xclbin. */
        
        /* Actually, let me check: the kernel might need DRM_AMDXDNA_REGISTER_XCLBIN */
        /* which is DRM_AMDXDNA_SET_STATE (8) or a separate IOCTL */
        
        printf("\nLet me try the pyxrt path first to get a registered xclbin,\n");
        printf("then we can use raw IOCTLs for context creation.\n");
        printf("Run: sudo LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libdrm.so.2 python3\n\n");
        
        /* Actually let me check if register_xclbin is accessible */
        /* It's likely DRM_IOCTL_AMDXDNA_SET_STATE (value 8) */
        printf("Checking DRM_AMDXDNA_SET_STATE...\n");
        
        return 1;
    }

    uint32_t hwctx_handle = ctx_req.handle;
    uint32_t syncobj_handle = ctx_req.syncobj_handle;
    printf("[OK] HW context: handle=%u syncobj=%u doorbell=%u\n",
           hwctx_handle, syncobj_handle, ctx_req.umq_doorbell);

    /* Test single submit + wait */
    struct amdxdna_drm_exec_cmd exec_req;
    memset(&exec_req, 0, sizeof(exec_req));
    exec_req.hwctx = hwctx_handle;
    ret = ioctl(fd, DRM_IOCTL_AMDXDNA_EXEC_CMD, &exec_req);
    if (ret < 0) {
        printf("[FAIL] EXEC_CMD: %s\n", strerror(errno));
        close(fd);
        return 1;
    }
    uint64_t seq = exec_req.seq;
    printf("[OK] EXEC_CMD: seq=%lu\n", seq);

    struct amdxdna_drm_wait_cmd wait_req;
    memset(&wait_req, 0, sizeof(wait_req));
    wait_req.hwctx = hwctx_handle;
    wait_req.timeout = 5000;
    wait_req.seq = seq;
    ret = ioctl(fd, DRM_IOCTL_AMDXDNA_WAIT_CMD, &wait_req);
    if (ret < 0) {
        printf("[FAIL] WAIT_CMD: %s\n", strerror(errno));
    } else {
        printf("[OK] WAIT_CMD completed\n");
    }

    /* Now test 10 sequential iterations with timing */
    printf("\n=== Sequential latency test ===\n");
    double min_lat = 1e9, max_lat = 0, sum_lat = 0;
    for (int i = 0; i < n_iterations; i++) {
        double t0 = get_time();
        
        memset(&exec_req, 0, sizeof(exec_req));
        exec_req.hwctx = hwctx_handle;
        ret = ioctl(fd, DRM_IOCTL_AMDXDNA_EXEC_CMD, &exec_req);
        if (ret < 0) { printf("EXEC failed\n"); break; }
        seq = exec_req.seq;
        
        memset(&wait_req, 0, sizeof(wait_req));
        wait_req.hwctx = hwctx_handle;
        wait_req.timeout = 5000;
        wait_req.seq = seq;
        ret = ioctl(fd, DRM_IOCTL_AMDXDNA_WAIT_CMD, &wait_req);
        if (ret < 0) { printf("WAIT failed\n"); break; }
        
        double t1 = get_time();
        double lat = (t1 - t0) * 1000.0;
        printf("  iter %2d: seq=%lu latency=%7.3f ms\n", i, seq, lat);
        if (lat < min_lat) min_lat = lat;
        if (lat > max_lat) max_lat = lat;
        sum_lat += lat;
    }
    printf("  Min: %.3f ms  Max: %.3f ms  Avg: %.3f ms\n",
           min_lat, max_lat, sum_lat / n_iterations);

    /* Concurrent multi-thread test */
    if (n_threads > 1) {
        printf("\n=== Concurrent test (%d threads, %d iter each) ===\n",
               n_threads, n_iterations);
        
        pthread_t *threads = calloc(n_threads, sizeof(pthread_t));
        thread_data_t *tdata = calloc(n_threads, sizeof(thread_data_t));
        
        for (int i = 0; i < n_threads; i++) {
            tdata[i].thread_id = i;
            tdata[i].iterations = n_iterations;
            tdata[i].submit_times = calloc(n_iterations, sizeof(double));
            tdata[i].done_times = calloc(n_iterations, sizeof(double));
            tdata[i].seq_numbers = calloc(n_iterations, sizeof(uint64_t));
        }
        
        double overall_start = get_time();
        for (int i = 0; i < n_threads; i++)
            pthread_create(&threads[i], NULL, worker_thread, &tdata[i]);
        for (int i = 0; i < n_threads; i++)
            pthread_join(threads[i], NULL);
        double overall_end = get_time();
        
        int total_ok = 0;
        for (int i = 0; i < n_threads; i++) {
            total_ok += tdata[i].success_count;
            printf("\n  Thread %d: %d/%d ok", i, tdata[i].success_count, tdata[i].iterations);
            for (int j = 0; j < tdata[i].success_count && j < 3; j++) {
                double lat = (tdata[i].done_times[j] - tdata[i].submit_times[j]) * 1000.0;
                printf("  [%d]=%.3fms", j, lat);
            }
        }
        
        double elapsed = overall_end - overall_start;
        printf("\n\n  Total elapsed: %.3f s\n", elapsed);
        printf("  Total ops: %d\n", total_ok);
        printf("  Throughput: %.1f ops/s\n", total_ok / elapsed);
        
        for (int i = 0; i < n_threads; i++) {
            free(tdata[i].submit_times);
            free(tdata[i].done_times);
            free(tdata[i].seq_numbers);
        }
        free(threads);
        free(tdata);
    }

    close(fd);
    return 0;
}
