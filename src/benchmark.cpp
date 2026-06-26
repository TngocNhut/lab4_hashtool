#include "hashtool/benchmark.hpp"

#include "hashtool/hash_tool.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace hashtool {

namespace {

std::vector<uint8_t> make_input(size_t size) {
    std::vector<uint8_t> data(size);

    for (size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<uint8_t>(i & 0xff);
    }

    return data;
}

template <typename Fn>
double measure_ms(Fn&& fn) {
    const auto start = std::chrono::steady_clock::now();
    fn();
    const auto end = std::chrono::steady_clock::now();

    return std::chrono::duration<double, std::milli>(end - start).count();
}

size_t iterations_for_size(size_t size) {
    if (size <= 1024) {
        return 10000;
    }

    if (size <= 1024 * 1024) {
        return 200;
    }

    return 3;
}

size_t outlen_for_algo(const std::string& algo) {
    if (algo == "shake128" || algo == "shake256") {
        return 64;
    }

    return 0;
}

} // namespace

void run_hash_benchmark_csv(const std::string& out_csv) {
    const std::vector<std::string> algos = {
        "sha256",
        "sha512",
        "sha3-256",
        "sha3-512",
        "shake128",
        "shake256"
    };

    const std::vector<size_t> sizes = {
        1024,
        1024 * 1024,
        100 * 1024 * 1024
    };

    const std::filesystem::path out_path(out_csv);
    if (!out_path.parent_path().empty()) {
        std::filesystem::create_directories(out_path.parent_path());
    }

    std::ofstream out(out_csv);
    if (!out) {
        throw std::runtime_error("cannot open benchmark CSV for writing: " + out_csv);
    }

    out << "algorithm,size_bytes,iterations,total_ms,avg_ms,throughput_mib_s,digest_size_bytes\n";

    std::cout << "[INFO] Hash benchmark output CSV: " << out_csv << "\n";

    for (const size_t size : sizes) {
        std::cout << "[INFO] Preparing input size: " << size << " bytes\n";

        const std::vector<uint8_t> input = make_input(size);
        const size_t iterations = iterations_for_size(size);

        for (const std::string& algo : algos) {
            const size_t outlen = outlen_for_algo(algo);

            // Warm-up
            volatile auto warm_digest = compute_hash(algo, input, outlen);
            (void)warm_digest;

            std::vector<uint8_t> digest;

            const double total_ms = measure_ms([&]() {
                for (size_t i = 0; i < iterations; ++i) {
                    digest = compute_hash(algo, input, outlen);
                }
            });

            const double avg_ms = total_ms / static_cast<double>(iterations);

            const double total_mib =
                static_cast<double>(size) * static_cast<double>(iterations) /
                (1024.0 * 1024.0);

            const double throughput =
                total_mib / (total_ms / 1000.0);

            out << algo << ","
                << size << ","
                << iterations << ","
                << std::fixed << std::setprecision(6)
                << total_ms << ","
                << avg_ms << ","
                << throughput << ","
                << digest.size()
                << "\n";

            std::cout << "[OK] algo=" << algo
                      << ", size=" << size
                      << ", iterations=" << iterations
                      << ", avg_ms=" << avg_ms
                      << ", MiB/s=" << throughput
                      << ", digest_size=" << digest.size()
                      << "\n";
        }
    }

    std::cout << "[OK] Hash benchmark completed\n";
}

} // namespace hashtool
