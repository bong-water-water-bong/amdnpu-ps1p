/*
 * NPU XRT C++ Test - Uses XRT API directly to create HW contexts
 * and measure serialization latency.
 *
 * This uses the proper XRT C++ API (not raw IOCTLs) which handles
 * VE2/NPU5 initialization correctly.
 *
 * Build:
 *   g++ -std=c++17 -o npu_xrt_test npu_xrt_test.cpp \
 *       -I/usr/include -L/opt/xilinx/xrt/lib64 \
 *       -lxrt_core -lxrt_coreutil -lpthread
 *
 * Run:
 *   LD_LIBRARY_PATH=/opt/xilinx/xrt/lib64 ./npu_xrt_test
 *
 * Note:
 *   An xclbin file must be available on the system.  The default search
 *   path can be overridden via the XCLBIN_PATH environment variable.
 *   If no xclbin is found the test prints an error and exits gracefully.
 */

#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdint>

#include "xrt/xrt_device.h"
#include "xrt/xrt_hw_context.h"
#include "xrt/xrt_kernel.h"
#include "xrt/xrt_bo.h"
#include "xrt/detail/xclbin.h"

// For timing
using clock_type = std::chrono::high_resolution_clock;

// Per-thread results
struct thread_result {
    int id;
    int submissions;
    int completions;
    double min_latency_ms;
    double max_latency_ms;
    double avg_latency_ms;
    double total_latency_ms;
};

// Worker function for concurrent submissions
static void worker_func(const xrt::device& dev, const xrt::uuid& xclbin_uuid,
                         int thread_id, int iterations,
                         std::atomic<int>& completed,
                         thread_result* result_out) {
    thread_result& r = *result_out;
    r.id = thread_id;
    r.submissions = 0;
    r.completions = 0;
    r.min_latency_ms = 1e9;
    r.max_latency_ms = 0;
    r.total_latency_ms = 0;

    try {
        // Create a hardware context for this thread
        xrt::hw_context ctx(dev, xclbin_uuid, xrt::hw_context::access_mode::shared);
        std::cout << "  [Thread " << thread_id << "] hw_context created" << std::endl;

        // Get a kernel from the context
        auto kernels = ctx.get_xclbin().get_kernels();
        if (kernels.empty()) {
            std::cerr << "  [Thread " << thread_id << "] No kernels in xclbin!" << std::endl;
            return;
        }
        
        std::string kernel_name = kernels[0].get_name();
        std::cout << "  [Thread " << thread_id << "] kernel=" << kernel_name << std::endl;
        
        xrt::kernel krnl(ctx, kernel_name);
        
        // Allocate BOs for kernel arguments
        auto bo0 = xrt::bo(ctx, 32, xrt::bo::flags::normal, 0);
        auto bo1 = xrt::bo(ctx, 32, xrt::bo::flags::normal, 0);
        auto bo2 = xrt::bo(ctx, 32, xrt::bo::flags::normal, 0);
        
        // Fill input buffers
        auto buf0 = bo0.map<int*>();
        auto buf1 = bo1.map<int*>();
        auto buf2 = bo2.map<int*>();
        buf0[0] = 1;
        buf1[0] = 2;
        memset(buf2, 0, 32);
        
        // Sync BOs to device
        bo0.sync(XCL_BO_SYNC_BO_TO_DEVICE);
        bo1.sync(XCL_BO_SYNC_BO_TO_DEVICE);

        for (int i = 0; i < iterations; i++) {
            auto t_start = clock_type::now();

            // Run the kernel
            auto run = krnl(bo0, bo1, bo2);
            run.wait();

            auto t_end = clock_type::now();
            
            double lat_ms = std::chrono::duration<double, std::milli>(t_end - t_start).count();
            
            r.total_latency_ms += lat_ms;
            if (lat_ms < r.min_latency_ms) r.min_latency_ms = lat_ms;
            if (lat_ms > r.max_latency_ms) r.max_latency_ms = lat_ms;
            r.completions++;
            
            completed.fetch_add(1);
        }
    } catch (const std::exception& e) {
        std::cerr << "  [Thread " << thread_id << "] Error: " << e.what() << std::endl;
    }
}

int main(int argc, char** argv) {
    int n_threads = 1;
    int n_iterations = 10;
    
    if (argc >= 2) n_threads = std::stoi(argv[1]);
    if (argc >= 3) n_iterations = std::stoi(argv[2]);
    
    std::cout << "=== NPU XRT Serialization Test ===" << std::endl;
    std::cout << "Threads:    " << n_threads << std::endl;
    std::cout << "Iterations: " << n_iterations << " per thread" << std::endl;
    std::cout << "Total:      " << n_threads * n_iterations << " operations" << std::endl;
    std::cout << std::endl;
    
    try {
        // Get XRT device
        xrt::device dev(0);
        std::cout << "Device: " << dev.get_info<xrt::info::device::name>() << " ("
                  << dev.get_info<xrt::info::device::bdf>() << ")" << std::endl;
        
        // Determine xclbin path: use XCLBIN_PATH env var if set, else default
        const char* env_path = std::getenv("XCLBIN_PATH");
        std::string xclbin_path;
        if (env_path && env_path[0] != '\0') {
            xclbin_path = env_path;
        } else {
            xclbin_path = "/tmp/xdna-driver/src/shim_ve2/Runner/latency/validate.xclbin";
        }

        // Check if xclbin file exists
        {
            FILE* f = fopen(xclbin_path.c_str(), "r");
            if (!f) {
                std::cerr << "xclbin file not found: " << xclbin_path << std::endl;
                std::cerr << "Set XCLBIN_PATH environment variable to point to a valid xclbin." << std::endl;
                return 1;
            }
            fclose(f);
        }

        // Load xclbin
        std::cout << "Loading xclbin: " << xclbin_path << std::endl;
        auto xclbin = xrt::xclbin(xclbin_path);
        auto uuid = dev.register_xclbin(xclbin);
        
        std::cout << "UUID: " << uuid.to_string() << std::endl;
        std::cout << std::endl;
        
        // First run single-threaded warmup + latency measurement
        std::cout << "=== Single-threaded warmup ===" << std::endl;
        {
            xrt::hw_context ctx(dev, uuid, xrt::hw_context::access_mode::shared);
            
            auto kernels = xclbin.get_kernels();
            if (kernels.empty()) {
                std::cerr << "No kernels in xclbin!" << std::endl;
                return 1;
            }
            
            std::string kn = kernels[0].get_name();
            xrt::kernel krnl(ctx, kn);
            
            auto bo0 = xrt::bo(ctx, 32, xrt::bo::flags::normal, 0);
            auto bo1 = xrt::bo(ctx, 32, xrt::bo::flags::normal, 0);
            
            double min_lat = 1e9, max_lat = 0, sum_lat = 0;
            
            for (int i = 0; i < n_iterations; i++) {
                auto t0 = clock_type::now();
                auto bo2 = xrt::bo(ctx, 32, xrt::bo::flags::normal, 0);
                auto run = krnl(bo0, bo1, bo2);
                run.wait();
                auto t1 = clock_type::now();
                
                double lat = std::chrono::duration<double, std::milli>(t1 - t0).count();
                std::cout << "  iter " << i << ": " << lat << " ms" << std::endl;
                
                sum_lat += lat;
                if (lat < min_lat) min_lat = lat;
                if (lat > max_lat) max_lat = lat;
            }
            
            std::cout << "  Min: " << min_lat << " ms  Max: " << max_lat
                      << " ms  Avg: " << (sum_lat / n_iterations) << " ms" << std::endl;
        }
        
        // Now run concurrent test
        if (n_threads > 1) {
            std::cout << std::endl;
            std::cout << "=== Concurrent test (" << n_threads << " threads, "
                      << n_iterations << " iter each) ===" << std::endl;
            
            std::vector<std::thread> threads;
            std::vector<thread_result> results(n_threads);
            std::atomic<int> completed{0};
            
            auto overall_start = clock_type::now();
            
            for (int i = 0; i < n_threads; i++) {
                threads.emplace_back(worker_func, std::ref(dev), std::ref(uuid),
                                     i, n_iterations, std::ref(completed),
                                     &results[i]);
            }
            
            for (auto& t : threads) {
                t.join();
            }
            
            auto overall_end = clock_type::now();
            
            double elapsed = std::chrono::duration<double>(overall_end - overall_start).count();
            int total_ok = 0;
            
            std::cout << std::endl;
            for (auto& r : results) {
                total_ok += r.completions;
                double avg = r.completions > 0 ? r.total_latency_ms / r.completions : 0;
                std::cout << "  Thread " << r.id << ": " << r.completions << "/"
                          << n_iterations << "  avg=" << avg << " ms" << std::endl;
            }
            
            std::cout << std::endl;
            std::cout << "Total elapsed: " << elapsed << " s" << std::endl;
            std::cout << "Total ops:     " << total_ok << std::endl;
            std::cout << "Throughput:    " << (total_ok / elapsed) << " ops/s" << std::endl;
        }
        
    } catch (const std::exception& e) {
        std::cerr << "FATAL: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << std::endl << "Done." << std::endl;
    return 0;
}
