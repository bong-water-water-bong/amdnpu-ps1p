/*
 * NPU Concurrent Workload Serialization Latency Test (V2)
 * 
 * Uses the correct IOCTL struct from the kernel's amdxdna_accel.h
 * to test if concurrent NPU workload submissions actually serialize.
 *
 * Build: gcc -o npu_concurrent_test npu_concurrent_test.c -lpthread
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdint.h>

/* Use the actual kernel header definitions */
#include <drm/drm.h>
#include <drm/amdxdna_accel.h>

/* The public header is MISSING WAIT_CMD definition.
 * We need to define the IOCTL number ourselves. */
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

/* Per-thread timing data */
typedef struct {
    int thread_id;
    int iterations;
    double *submit_times;    /* CLOCK_MONOTONIC time at submit call */
    double *done_times;      /* CLOCK_MONOTONIC time after wait returns */
    uint64_t *seq_numbers;   /* sequence numbers returned */
    int success_count;
    int fail_count;
} thread_data_t;

static __thread int local_fd = -1;

static double get_time_monotonic(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int open_accel(void) {
    int fd;
    fd = open("/dev/accel/accel0", O_RDWR);
    if (fd < 0) {
        perror("open /dev/accel/accel0");
        return -1;
    }
    return fd;
}

static void create_hwctx(int fd, uint32_t *hwctx_out, uint32_t *syncobj_out) {
    struct amdxdna_drm_create_hwctx req;
    struct amdxdna_qos_info qos;
    int ret;

    memset(&req, 0, sizeof(req));
    memset(&qos, 0, sizeof(qos));
    qos.priority = AMDXDNA_QOS_NORMAL_PRIORITY;

    req.qos_p = (uint64_t)(uintptr_t)&qos;
    req.num_tiles = 1;
    req.mem_size = 4096;

    ret = ioctl(fd, DRM_IOCTL_AMDXDNA_CREATE_HWCTX, &req);
    if (ret < 0) {
        perror("CREATE_HWCTX");
        *hwctx_out = 0;
        *syncobj_out = 0;
        return;
    }

    *hwctx_out = req.handle;
    *syncobj_out = req.syncobj_handle;
}

static int submit_cmd(int fd, uint32_t hwctx, uint64_t *seq) {
    struct amdxdna_drm_exec_cmd req;
    int ret;

    memset(&req, 0, sizeof(req));
    req.hwctx = hwctx;
    req.type = 0;  /* default type */
    req.cmd_handles = 0;
    req.cmd_count = 0;

    ret = ioctl(fd, DRM_IOCTL_AMDXDNA_EXEC_CMD, &req);
    if (ret < 0) {
        perror("EXEC_CMD");
        return ret;
    }

    *seq = req.seq;
    return 0;
}

static int wait_cmd(int fd, uint32_t hwctx, uint64_t seq, uint32_t timeout_ms) {
    struct amdxdna_drm_wait_cmd req;
    int ret;

    memset(&req, 0, sizeof(req));
    req.hwctx = hwctx;
    req.timeout = timeout_ms;
    req.seq = seq;

    ret = ioctl(fd, DRM_IOCTL_AMDXDNA_WAIT_CMD, &req);
    if (ret < 0) {
        perror("WAIT_CMD");
        return ret;
    }

    return 0;
}

static void *worker_thread(void *arg) {
    thread_data_t *td = (thread_data_t *)arg;
    uint32_t hwctx, syncobj;
    double t_submit, t_done;

    local_fd = open_accel();
    if (local_fd < 0) {
        td->fail_count = td->iterations;
        return NULL;
    }

    create_hwctx(local_fd, &hwctx, &syncobj);
    if (hwctx == 0) {
        close(local_fd);
        td->fail_count = td->iterations;
        return NULL;
    }

    printf("  [Thread %d] hwctx=%u syncobj=%u\n", td->thread_id, hwctx, syncobj);

    for (int i = 0; i < td->iterations; i++) {
        uint64_t seq;

        t_submit = get_time_monotonic();
        td->submit_times[i] = t_submit;

        if (submit_cmd(local_fd, hwctx, &seq) < 0) {
            td->fail_count++;
            continue;
        }

        td->seq_numbers[i] = seq;

        /* Wait for completion (5 second timeout) */
        if (wait_cmd(local_fd, hwctx, seq, 5000) < 0) {
            td->fail_count++;
            continue;
        }

        t_done = get_time_monotonic();
        td->done_times[i] = t_done;

        td->success_count++;
    }

    close(local_fd);
    return NULL;
}

int main(int argc, char **argv) {
    int n_threads = 4;
    int n_iterations = 10;
    pthread_t *threads;
    thread_data_t *tdata;
    double overall_start, overall_end;

    if (argc >= 2) n_threads = atoi(argv[1]);
    if (argc >= 3) n_iterations = atoi(argv[2]);

    printf("NPU Concurrent Workload Serialization Test\n");
    printf("  Device:   /dev/accel/accel0\n");
    printf("  Threads:  %d\n", n_threads);
    printf("  Iters:    %d per thread\n", n_iterations);
    printf("  Total:    %d operations\n\n", n_threads * n_iterations);

    /* First, verify we can access the NPU with a single-threaded warmup */
    printf("Warmup - single context test...\n");
    int warmup_fd = open_accel();
    if (warmup_fd < 0) {
        fprintf(stderr, "FATAL: Cannot open NPU device\n");
        return 1;
    }
    uint32_t w_hwctx, w_syncobj;
    create_hwctx(warmup_fd, &w_hwctx, &w_syncobj);
    if (w_hwctx == 0) {
        fprintf(stderr, "FATAL: Cannot create HW context\n");
        close(warmup_fd);
        return 1;
    }
    printf("  Context created: handle=%u syncobj=%u\n", w_hwctx, w_syncobj);

    uint64_t w_seq;
    if (submit_cmd(warmup_fd, w_hwctx, &w_seq) < 0) {
        printf("  Single submit failed (expected if no xclbin loaded)\n");
    } else {
        printf("  Submit OK: seq=%lu\n", w_seq);
        if (wait_cmd(warmup_fd, w_hwctx, w_seq, 5000) < 0) {
            printf("  Wait failed\n");
        } else {
            printf("  Wait OK!\n");
        }
    }
    close(warmup_fd);

    /* Prepare thread data */
    threads = calloc(n_threads, sizeof(pthread_t));
    tdata = calloc(n_threads, sizeof(thread_data_t));

    for (int i = 0; i < n_threads; i++) {
        tdata[i].thread_id = i;
        tdata[i].iterations = n_iterations;
        tdata[i].submit_times = calloc(n_iterations, sizeof(double));
        tdata[i].done_times = calloc(n_iterations, sizeof(double));
        tdata[i].seq_numbers = calloc(n_iterations, sizeof(uint64_t));
    }

    /* Concurrent test */
    printf("\n=== CONCURRENT TEST (%d threads x %d iterations) ===\n",
           n_threads, n_iterations);
    overall_start = get_time_monotonic();

    for (int i = 0; i < n_threads; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &tdata[i]);
    }
    for (int i = 0; i < n_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    overall_end = get_time_monotonic();

    /* Results */
    printf("\n=== RESULTS ===\n");
    int total_ok = 0, total_fail = 0;
    double min_lat = 1e9, max_lat = 0, sum_lat = 0;

    for (int i = 0; i < n_threads; i++) {
        total_ok += tdata[i].success_count;
        total_fail += tdata[i].fail_count;

        printf("\nThread %d: %d ok / %d fail\n",
               i, tdata[i].success_count, tdata[i].fail_count);

        double t_sum = 0;
        int n_samples = tdata[i].success_count > 10 ? 10 : tdata[i].success_count;
        for (int j = 0; j < n_samples; j++) {
            double lat = (tdata[i].done_times[j] - tdata[i].submit_times[j]) * 1000.0;
            printf("    [%d] seq=%-5lu  latency=%8.3f ms\n",
                   j, tdata[i].seq_numbers[j], lat);
            if (lat < min_lat) min_lat = lat;
            if (lat > max_lat) max_lat = lat;
            t_sum += lat;
            sum_lat += lat;
        }

        double t_avg = 0;
        for (int j = 0; j < tdata[i].success_count; j++)
            t_avg += (tdata[i].done_times[j] - tdata[i].submit_times[j]) * 1000.0;
        t_avg /= tdata[i].success_count;
        printf("    Average: %.3f ms\n", t_avg);
    }

    double elapsed = overall_end - overall_start;
    double total_lat_sum_avg = sum_lat / (total_ok > 0 ? total_ok : 1);

    printf("\n=== SUMMARY ===\n");
    printf("Total time:    %.3f s\n", elapsed);
    printf("Ops completed: %d / %d\n", total_ok, n_threads * n_iterations);
    printf("Throughput:    %.1f ops/s\n", total_ok / elapsed);
    printf("Avg latency:   %.3f ms\n", total_lat_sum_avg);
    printf("Min latency:   %.3f ms\n", min_lat);
    printf("Max latency:   %.3f ms\n", max_lat);

    if (total_ok > 0) {
        double ideal_tp = 1000.0 / total_lat_sum_avg;
        double ser_factor = ideal_tp / (total_ok / elapsed);
        printf("Ideal TP:      %.0f ops/s (no serialization)\n", ideal_tp);
        printf("Serialization: %.1fx penalty\n", ser_factor);

        if (ser_factor > 1.0) {
            printf("\nVERDICT: Serialization CONFIRMED\n");
            printf("  %.0f threads are achieving only %.1f ops/s\n",
                   (double)n_threads, total_ok / elapsed);
            printf("  vs ideal %.0f ops/s at %.3f ms each\n", ideal_tp, total_lat_sum_avg);
        } else {
            printf("\nVERDICT: No serialization detected\n");
        }
    }

    /* Cleanup */
    for (int i = 0; i < n_threads; i++) {
        free(tdata[i].submit_times);
        free(tdata[i].done_times);
        free(tdata[i].seq_numbers);
    }
    free(threads);
    free(tdata);

    return 0;
}
