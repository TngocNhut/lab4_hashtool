#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace hashtool {

std::vector<uint8_t> compute_hash(
    const std::string& algo,
    const std::vector<uint8_t>& input,
    size_t outlen
);

bool is_supported_hash_algo(const std::string& algo);

} // namespace hashtool
