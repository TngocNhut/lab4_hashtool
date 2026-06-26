#include "hashtool/encoding.hpp"

#include <iomanip>
#include <sstream>

namespace hashtool {

std::string to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');

    for (uint8_t b : data) {
        oss << std::setw(2) << static_cast<int>(b);
    }

    return oss.str();
}

} // namespace hashtool
