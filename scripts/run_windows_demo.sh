#!/usr/bin/env bash
set -euo pipefail

BIN="./build-windows-ucrt64/hashtool.exe"
ART="artifacts/windows"

mkdir -p "$ART/benchmark" "$ART/certs" "$ART/md5_collision" "$ART/length_extension"

echo "===== LAB 4 WINDOWS DEMO ====="

echo
echo "===== SELFTEST ====="
$BIN selftest

echo
echo "===== HASH KAT ====="
$BIN kat --vectors vectors/hash_kat.json

echo
echo "===== HASH SAMPLE SHA-256 / SHA3-256 / SHAKE256 ====="
cat > samples/demo_hash_msg.txt <<'TXT'
Lab 4 Windows demo hashing message.
Student: Tran Ngoc Nhat.
TXT

$BIN hash --algo sha256 --in samples/demo_hash_msg.txt --out "$ART/demo_hash_msg.sha256.raw"
$BIN hash --algo sha3-256 --in samples/demo_hash_msg.txt --out "$ART/demo_hash_msg.sha3_256.raw"
$BIN hash --algo shake256 --outlen 64 --in samples/demo_hash_msg.txt --out "$ART/demo_hash_msg.shake256_64.raw"

echo
echo "===== NEGATIVE HASH VALIDATION ====="
set +e
$BIN hash --algo md6 --in samples/demo_hash_msg.txt
bad_algo_rc=$?
$BIN hash --algo shake256 --in samples/demo_hash_msg.txt
bad_shake_rc=$?
set -e

if [[ "$bad_algo_rc" -eq 0 ]]; then
  echo "[FAIL] Unsupported hash algorithm unexpectedly accepted"
  exit 1
fi

if [[ "$bad_shake_rc" -eq 0 ]]; then
  echo "[FAIL] SHAKE without outlen unexpectedly accepted"
  exit 1
fi

echo "[OK] Unsupported algorithm and missing SHAKE outlen rejected"

echo
echo "===== HASH BENCHMARK ====="
$BIN bench --out "$ART/benchmark/demo_bench_hash_windows.csv"

echo
echo "===== X.509 CERTIFICATE ANALYSIS ====="
openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -out "$ART/certs/demo_lab4_rsa3072.key"

MSYS_NO_PATHCONV=1 openssl req -new -x509 \
  -key "$ART/certs/demo_lab4_rsa3072.key" \
  -out "$ART/certs/demo_lab4_selfsigned.crt" \
  -days 365 \
  -sha256 \
  -subj "/C=VN/ST=HoChiMinh/L=HCM/O=University Lab/OU=Applied Cryptography/CN=Tran Ngoc Nhat Lab4 Demo"

openssl x509 \
  -in "$ART/certs/demo_lab4_selfsigned.crt" \
  -noout \
  -subject \
  -issuer \
  -dates \
  -serial \
  -fingerprint \
  -sha256

openssl verify \
  -CAfile "$ART/certs/demo_lab4_selfsigned.crt" \
  "$ART/certs/demo_lab4_selfsigned.crt"

openssl genpkey \
  -algorithm RSA \
  -pkeyopt rsa_keygen_bits:3072 \
  -out "$ART/certs/demo_wrong_ca.key"

MSYS_NO_PATHCONV=1 openssl req -new -x509 \
  -key "$ART/certs/demo_wrong_ca.key" \
  -out "$ART/certs/demo_wrong_ca.crt" \
  -days 365 \
  -sha256 \
  -subj "/C=VN/ST=HoChiMinh/L=HCM/O=Wrong CA/OU=Lab/CN=Wrong CA Demo"

set +e
openssl verify \
  -CAfile "$ART/certs/demo_wrong_ca.crt" \
  "$ART/certs/demo_lab4_selfsigned.crt"
wrong_ca_rc=$?
set -e

if [[ "$wrong_ca_rc" -eq 0 ]]; then
  echo "[FAIL] Certificate unexpectedly verified with wrong CA"
  exit 1
fi

echo "[OK] Certificate verification with wrong CA rejected"

echo
echo "===== MD5 COLLISION DEMO ====="
mkdir -p samples/md5_collision

python3 - <<'PY'
from pathlib import Path

m1_hex = (
    "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70"
)
m2_hex = (
    "d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f89"
    "55ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5b"
    "d8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0"
    "e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70"
)

out = Path("samples/md5_collision")
out.mkdir(parents=True, exist_ok=True)
(out / "msg1.bin").write_bytes(bytes.fromhex(m1_hex))
(out / "msg2.bin").write_bytes(bytes.fromhex(m2_hex))
print("[OK] Created MD5 collision sample files")
PY

cmp -l samples/md5_collision/msg1.bin samples/md5_collision/msg2.bin | head
openssl dgst -md5 samples/md5_collision/msg1.bin samples/md5_collision/msg2.bin
openssl dgst -sha256 samples/md5_collision/msg1.bin samples/md5_collision/msg2.bin

echo
echo "===== SHA-256 LENGTH EXTENSION DEMO ====="
python3 scripts/length_extension_sha256_demo.py
xxd -g 1 "$ART/length_extension/forged_message.bin" | head -8

echo
echo "[OK] Lab 4 Windows demo completed successfully."
