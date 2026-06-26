#include "hashtool/kat_runner.hpp"

#include "hashtool/encoding.hpp"
#include "hashtool/file_utils.hpp"
#include "hashtool/hash_tool.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace hashtool {

namespace {

uint8_t hex_value(char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
    }

    if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(10 + c - 'a');
    }

    if (c >= 'A' && c <= 'F') {
        return static_cast<uint8_t>(10 + c - 'A');
    }

    throw std::runtime_error("invalid hex character");
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("hex string length must be even");
    }

    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        const uint8_t hi = hex_value(hex[i]);
        const uint8_t lo = hex_value(hex[i + 1]);
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return out;
}

} // namespace

int run_hash_kat_file(const std::string& kat_json_path) {
    const std::vector<uint8_t> file_bytes = read_binary_file(kat_json_path);
    const std::string text(file_bytes.begin(), file_bytes.end());

    nlohmann::json tests;

    try {
        tests = nlohmann::json::parse(text);
    } catch (...) {
        throw std::runtime_error("invalid KAT JSON file");
    }

    if (!tests.is_array()) {
        throw std::runtime_error("KAT JSON must be an array");
    }

    size_t passed = 0;
    size_t failed = 0;

    std::cout << "[INFO] KAT file: " << kat_json_path << "\n";
    std::cout << "[INFO] Test count: " << tests.size() << "\n";

    for (const auto& t : tests) {
        const std::string name = t.at("name").get<std::string>();
        const std::string algo = t.at("algo").get<std::string>();
        const std::string message_hex = t.at("message_hex").get<std::string>();
        const size_t outlen = t.at("outlen").get<size_t>();
        const std::string expected_hex = t.at("expected_hex").get<std::string>();

        const std::vector<uint8_t> message = from_hex(message_hex);
        const std::vector<uint8_t> digest = compute_hash(algo, message, outlen);
        const std::string actual_hex = to_hex(digest);

        if (actual_hex == expected_hex) {
            ++passed;
            std::cout << "[PASS] " << name << "\n";
        } else {
            ++failed;
            std::cout << "[FAIL] " << name << "\n";
            std::cout << "       algo     : " << algo << "\n";
            std::cout << "       expected : " << expected_hex << "\n";
            std::cout << "       actual   : " << actual_hex << "\n";
        }
    }

    std::cout << "[INFO] Passed: " << passed << "\n";
    std::cout << "[INFO] Failed: " << failed << "\n";

    if (failed == 0) {
        std::cout << "[OK] All hash KAT tests passed\n";
        return 0;
    }

    std::cout << "[ERROR] Some hash KAT tests failed\n";
    return 1;
}

} // namespace hashtool
