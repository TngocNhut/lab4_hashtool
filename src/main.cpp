#include "hashtool/encoding.hpp"
#include "hashtool/file_utils.hpp"
#include "hashtool/hash_tool.hpp"

#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/shake.h>

#include <exception>
#include <iostream>
#include <string>
#include <vector>

namespace {

void print_help() {
    std::cout
        << "hashtool - Lab 4 Hashing Suite\n\n"
        << "Usage:\n"
        << "  hashtool --help\n"
        << "  hashtool version\n"
        << "  hashtool selftest\n"
        << "  hashtool hash --algo sha256 --in file.bin [--out digest.bin]\n"
        << "  hashtool hash --algo shake256 --outlen 64 --in file.bin [--out digest.bin]\n\n"
        << "Supported algorithms:\n"
        << "  sha224, sha256, sha384, sha512\n"
        << "  sha3-224, sha3-256, sha3-384, sha3-512\n"
        << "  shake128, shake256\n";
}

std::string get_arg(int argc, char* argv[], const std::string& name) {
    for (int i = 0; i < argc - 1; ++i) {
        if (argv[i] == name) {
            return argv[i + 1];
        }
    }
    return {};
}

int run_selftest() {
    std::vector<uint8_t> input = {'a', 'b', 'c'};

    const auto sha256 = hashtool::compute_hash("sha256", input, 0);
    const auto sha3_256 = hashtool::compute_hash("sha3-256", input, 0);
    const auto shake256 = hashtool::compute_hash("shake256", input, 64);

    std::cout << "[OK] Crypto++ SHA-256 works, digest size: "
              << sha256.size() << " bytes\n";
    std::cout << "[OK] Crypto++ SHA3-256 works, digest size: "
              << sha3_256.size() << " bytes\n";
    std::cout << "[OK] Crypto++ SHAKE256 works, output size: "
              << shake256.size() << " bytes\n";

    std::cout << "[INFO] SHA-256(abc): "
              << hashtool::to_hex(sha256) << "\n";

    return 0;
}

int run_hash(int argc, char* argv[]) {
    const std::string algo = get_arg(argc, argv, "--algo");
    const std::string in_path = get_arg(argc, argv, "--in");
    const std::string out_path = get_arg(argc, argv, "--out");
    const std::string outlen_str = get_arg(argc, argv, "--outlen");

    if (algo.empty() || in_path.empty()) {
        std::cerr << "ERROR: hash requires --algo ALGO --in file.bin [--out digest.bin]\n";
        return 1;
    }

    if (!hashtool::is_supported_hash_algo(algo)) {
        std::cerr << "ERROR: unsupported hash algorithm: " << algo << "\n";
        return 1;
    }

    size_t outlen = 0;
    if (!outlen_str.empty()) {
        try {
            outlen = static_cast<size_t>(std::stoul(outlen_str));
        } catch (...) {
            std::cerr << "ERROR: invalid --outlen value\n";
            return 1;
        }
    }

    if ((algo == "shake128" || algo == "shake256") && outlen == 0) {
        std::cerr << "ERROR: SHAKE requires --outlen N\n";
        return 1;
    }

    const std::vector<uint8_t> input = hashtool::read_binary_file(in_path);
    const std::vector<uint8_t> digest = hashtool::compute_hash(algo, input, outlen);

    if (!out_path.empty()) {
        hashtool::write_binary_file(out_path, digest);
    }

    std::cout << "[OK] Hash completed\n";
    std::cout << "[OK] Algorithm: " << algo << "\n";
    std::cout << "[OK] Input file: " << in_path << "\n";
    std::cout << "[OK] Input size: " << input.size() << " bytes\n";
    std::cout << "[OK] Digest size: " << digest.size() << " bytes\n";

    if (!out_path.empty()) {
        std::cout << "[OK] Raw digest output: " << out_path << "\n";
    }

    std::cout << "[HEX] " << hashtool::to_hex(digest) << "\n";

    return 0;
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc <= 1) {
            print_help();
            return 0;
        }

        const std::string command = argv[1];

        if (command == "--help" || command == "-h") {
            print_help();
            return 0;
        }

        if (command == "version") {
            std::cout << "hashtool 1.0.0\n";
            std::cout << "Crypto++ SHA-2 / SHA-3 / SHAKE hashing suite\n";
            return 0;
        }

        if (command == "selftest") {
            return run_selftest();
        }

        if (command == "hash") {
            return run_hash(argc, argv);
        }

        std::cerr << "ERROR: unknown command: " << command << "\n";
        std::cerr << "Run: hashtool --help\n";
        return 1;
    } catch (const std::exception& ex) {
        std::cerr << "ERROR: " << ex.what() << "\n";
        return 1;
    }
}
