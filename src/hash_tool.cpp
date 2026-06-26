#include "hashtool/hash_tool.hpp"

#include <cryptopp/filters.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h>

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>
#include <vector>

namespace hashtool {

namespace {

std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

template <typename HashT>
std::vector<uint8_t> hash_fixed(const std::vector<uint8_t>& input) {
    HashT hash;
    std::vector<uint8_t> digest(hash.DigestSize());

    hash.Update(input.data(), input.size());
    hash.Final(digest.data());

    return digest;
}

template <typename XofT>
std::vector<uint8_t> hash_xof(const std::vector<uint8_t>& input, size_t outlen) {
    if (outlen == 0) {
        throw std::runtime_error("SHAKE requires --outlen greater than 0");
    }

    XofT xof;
    std::vector<uint8_t> digest(outlen);

    xof.Update(input.data(), input.size());
    xof.TruncatedFinal(digest.data(), digest.size());

    return digest;
}

} // namespace

bool is_supported_hash_algo(const std::string& algo_raw) {
    const std::string algo = lower_copy(algo_raw);

    return algo == "sha224" ||
           algo == "sha256" ||
           algo == "sha384" ||
           algo == "sha512" ||
           algo == "sha3-224" ||
           algo == "sha3-256" ||
           algo == "sha3-384" ||
           algo == "sha3-512" ||
           algo == "shake128" ||
           algo == "shake256";
}

std::vector<uint8_t> compute_hash(
    const std::string& algo_raw,
    const std::vector<uint8_t>& input,
    size_t outlen
) {
    const std::string algo = lower_copy(algo_raw);

    if (algo == "sha224") {
        return hash_fixed<CryptoPP::SHA224>(input);
    }

    if (algo == "sha256") {
        return hash_fixed<CryptoPP::SHA256>(input);
    }

    if (algo == "sha384") {
        return hash_fixed<CryptoPP::SHA384>(input);
    }

    if (algo == "sha512") {
        return hash_fixed<CryptoPP::SHA512>(input);
    }

    if (algo == "sha3-224") {
        return hash_fixed<CryptoPP::SHA3_224>(input);
    }

    if (algo == "sha3-256") {
        return hash_fixed<CryptoPP::SHA3_256>(input);
    }

    if (algo == "sha3-384") {
        return hash_fixed<CryptoPP::SHA3_384>(input);
    }

    if (algo == "sha3-512") {
        return hash_fixed<CryptoPP::SHA3_512>(input);
    }

    if (algo == "shake128") {
        return hash_xof<CryptoPP::SHAKE128>(input, outlen);
    }

    if (algo == "shake256") {
        return hash_xof<CryptoPP::SHAKE256>(input, outlen);
    }

    throw std::runtime_error("unsupported hash algorithm: " + algo_raw);
}

} // namespace hashtool
