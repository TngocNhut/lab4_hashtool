#!/usr/bin/env python3
import hashlib
import hmac
import struct
from pathlib import Path


# SHA-256 constants
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xffffffff


def sha256_compress(chunk, h):
    assert len(chunk) == 64

    w = list(struct.unpack(">16I", chunk))

    for i in range(16, 64):
        s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
        s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)

    a, b, c, d, e, f, g, hh = h

    for i in range(64):
        S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)
        ch = (e & f) ^ ((~e) & g)
        temp1 = (hh + S1 + ch + K[i] + w[i]) & 0xffffffff
        S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)
        maj = (a & b) ^ (a & c) ^ (b & c)
        temp2 = (S0 + maj) & 0xffffffff

        hh = g
        g = f
        f = e
        e = (d + temp1) & 0xffffffff
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & 0xffffffff

    return [
        (h[0] + a) & 0xffffffff,
        (h[1] + b) & 0xffffffff,
        (h[2] + c) & 0xffffffff,
        (h[3] + d) & 0xffffffff,
        (h[4] + e) & 0xffffffff,
        (h[5] + f) & 0xffffffff,
        (h[6] + g) & 0xffffffff,
        (h[7] + hh) & 0xffffffff,
    ]


def sha256_padding(message_length_bytes):
    bit_len = message_length_bytes * 8
    padding = b"\x80"

    while (message_length_bytes + len(padding)) % 64 != 56:
        padding += b"\x00"

    padding += struct.pack(">Q", bit_len)
    return padding


def digest_to_state(hex_digest):
    raw = bytes.fromhex(hex_digest)
    if len(raw) != 32:
        raise ValueError("SHA-256 digest must be 32 bytes")
    return list(struct.unpack(">8I", raw))


def state_to_digest(h):
    return "".join(f"{x:08x}" for x in h)


def sha256_continue_from_state(initial_state, already_processed_len, append_data):
    """
    Continue SHA-256 from a known internal state.

    already_processed_len must be the length, in bytes, already represented by
    the current internal state. This must be block-aligned.
    """
    data = append_data
    final_padding = sha256_padding(already_processed_len + len(data))
    work = data + final_padding

    if len(work) % 64 != 0:
        raise ValueError("internal error: continuation blocks not aligned")

    h = initial_state[:]

    for i in range(0, len(work), 64):
        h = sha256_compress(work[i:i + 64], h)

    return state_to_digest(h)


def naive_mac(secret, message):
    return hashlib.sha256(secret + message).hexdigest()


def hmac_sha256(secret, message):
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def main():
    out_dir = Path("artifacts/windows/length_extension")
    out_dir.mkdir(parents=True, exist_ok=True)

    # Simulated server secret.
    # Attacker does NOT know this value.
    secret = b"Lab4SecretKey!!"  # 15 bytes

    original_message = b"user=tranngocnhat&role=user&amount=100"
    append_data = b"&role=admin&amount=1000000"

    original_mac = naive_mac(secret, original_message)

    print("===== Server uses vulnerable MAC: SHA256(secret || message) =====")
    print("[INFO] Original message:", original_message.decode())
    print("[INFO] Original MAC    :", original_mac)
    print("[INFO] Attacker wants to append:", append_data.decode())
    print()

    print("===== Attacker performs length extension =====")

    guessed_secret_len = len(secret)

    glue_padding = sha256_padding(guessed_secret_len + len(original_message))
    forged_message = original_message + glue_padding + append_data

    initial_state = digest_to_state(original_mac)

    already_processed_len = guessed_secret_len + len(original_message) + len(glue_padding)

    forged_mac = sha256_continue_from_state(
        initial_state,
        already_processed_len,
        append_data
    )

    server_check_mac = naive_mac(secret, forged_message)

    print("[INFO] Guessed secret length:", guessed_secret_len)
    print("[INFO] Glue padding length  :", len(glue_padding))
    print("[INFO] Forged message length:", len(forged_message))
    print("[INFO] Forged MAC           :", forged_mac)
    print("[INFO] Server recomputed MAC:", server_check_mac)

    if forged_mac == server_check_mac:
        print("[OK] Length extension attack succeeded against SHA256(secret || message)")
    else:
        print("[FAIL] Length extension attack failed")

    print()
    print("===== HMAC-SHA256 comparison =====")

    original_hmac = hmac_sha256(secret, original_message)
    forged_hmac_server = hmac_sha256(secret, forged_message)

    print("[INFO] HMAC original message:", original_hmac)
    print("[INFO] HMAC forged message  :", forged_hmac_server)

    if forged_mac != forged_hmac_server:
        print("[OK] Forged naive MAC does not validate as HMAC-SHA256")
        print("[OK] HMAC-SHA256 is not vulnerable to this length extension technique")
    else:
        print("[FAIL] Unexpected HMAC match")

    (out_dir / "original_message.bin").write_bytes(original_message)
    (out_dir / "forged_message.bin").write_bytes(forged_message)
    (out_dir / "append_data.bin").write_bytes(append_data)

    summary = f"""Lab 4 - SHA-256 Length Extension Attack Demo

Vulnerable MAC construction:
- MAC = SHA256(secret || message)

Original message:
- {original_message.decode()}

Append data:
- {append_data.decode()}

Original MAC:
- {original_mac}

Guessed secret length:
- {guessed_secret_len} bytes

Forged MAC:
- {forged_mac}

Server recomputed MAC on secret || forged_message:
- {server_check_mac}

Result:
- Length extension attack succeeded against SHA256(secret || message).

HMAC comparison:
- HMAC-SHA256 does not validate using the forged naive MAC.
- HMAC-SHA256 should be used instead of SHA256(secret || message).
"""

    (out_dir / "length_extension_summary.txt").write_text(summary)

    print()
    print("[OK] Wrote artifacts/windows/length_extension/length_extension_summary.txt")
    print("[OK] Wrote original_message.bin, forged_message.bin, append_data.bin")


if __name__ == "__main__":
    main()
