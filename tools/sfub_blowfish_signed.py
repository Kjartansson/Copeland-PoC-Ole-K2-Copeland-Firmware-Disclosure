#!/usr/bin/env python3
"""Probe the signed-key-byte Blowfish variant found in the E2E updater."""

import hashlib
import json
import os
import struct
import time

import sfub_crypt_probe as probe

ROOT = probe.ROOT
UPDATER = "extracted/E2E_4.11F03/SysUpdt.embedded.elf"
SBOX_FILE_OFFSET = 0x134FC0
PARRAY_FILE_OFFSET = 0x135FC0
MASK = 0xFFFFFFFF


def constants():
    with open(os.path.join(ROOT, UPDATER), "rb") as handle:
        handle.seek(SBOX_FILE_OFFSET)
        sbox_data = handle.read(4096)
        handle.seek(PARRAY_FILE_OFFSET)
        parray_data = handle.read(18 * 4)
    if len(sbox_data) != 4096 or len(parray_data) != 72:
        raise ValueError("truncated Blowfish constants")
    sboxes = struct.unpack("<1024I", sbox_data)
    parray = struct.unpack("<18I", parray_data)
    if parray[:4] != (0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344):
        raise ValueError("Blowfish P-array mismatch")
    if sboxes[:4] != (0xD1310BA6, 0x98DFB5AC, 0x2FFD72DB, 0xD01ADFB7):
        raise ValueError("Blowfish S-box mismatch")
    return list(parray), [list(sboxes[i:i + 256]) for i in range(0, 1024, 256)]


INITIAL_P = None
SBOXES = None


def expand_key(key, signed):
    global INITIAL_P, SBOXES
    if INITIAL_P is None:
        INITIAL_P, SBOXES = constants()
    p = INITIAL_P.copy()
    s = [box.copy() for box in SBOXES]
    index = 0
    for i in range(18):
        value = 0
        for _ in range(4):
            byte = key[index]
            if signed and byte >= 0x80:
                byte -= 256
            value = ((value << 8) | byte) & MASK
            index = (index + 1) % len(key)
        p[i] ^= value

    def encrypt(left, right):
        for i in range(16):
            left ^= p[i]
            f = ((((s[0][left >> 24] + s[1][(left >> 16) & 0xFF]) & MASK)
                  ^ s[2][(left >> 8) & 0xFF]) + s[3][left & 0xFF]) & MASK
            right ^= f
            left, right = right, left
        left, right = right, left
        return left ^ p[17], right ^ p[16]

    left = right = 0
    for i in range(0, 18, 2):
        left, right = encrypt(left, right)
        p[i], p[i + 1] = left, right
    for box in s:
        for i in range(0, 256, 2):
            left, right = encrypt(left, right)
            box[i], box[i + 1] = left, right
    return p, s


def crypt_block(block, key, signed, direction, byteorder):
    p, s = expand_key(key, signed)
    left, right = struct.unpack((">" if byteorder == "big" else "<") + "II", block)

    def f(value):
        return ((((s[0][value >> 24] + s[1][(value >> 16) & 0xFF]) & MASK)
                 ^ s[2][(value >> 8) & 0xFF]) + s[3][value & 0xFF]) & MASK

    indices = range(16) if direction == "enc" else range(17, 1, -1)
    for i in indices:
        left ^= p[i]
        right ^= f(left)
        left, right = right, left
    left, right = right, left
    if direction == "enc":
        right ^= p[16]
        left ^= p[17]
    else:
        right ^= p[1]
        left ^= p[0]
    return struct.pack((">" if byteorder == "big" else "<") + "II", left & MASK, right & MASK)


def crypt(data, key, signed, direction, byteorder):
    p, s = expand_key(key, signed)

    def f(value):
        return ((((s[0][value >> 24] + s[1][(value >> 16) & 0xFF]) & MASK)
                 ^ s[2][(value >> 8) & 0xFF]) + s[3][value & 0xFF]) & MASK

    order = ">" if byteorder == "big" else "<"
    output = []
    for offset in range(0, len(data), 8):
        left, right = struct.unpack_from(order + "II", data, offset)
        indices = range(16) if direction == "enc" else range(17, 1, -1)
        for i in indices:
            left ^= p[i]
            right ^= f(left)
            left, right = right, left
        left, right = right, left
        if direction == "enc":
            right ^= p[16]
            left ^= p[17]
        else:
            right ^= p[1]
            left ^= p[0]
        output.append(struct.pack(order + "II", left & MASK, right & MASK))
    return b"".join(output)


def run_kats():
    zero = b"\x00" * 8
    if crypt(zero, zero, False, "enc", "big") != bytes.fromhex("4ef997456198dd78"):
        raise ValueError("standard Blowfish KAT failed")
    key = bytes.fromhex("0123456789abcdeff0e0d0c0b0a09080")
    block = bytes.fromhex("0123456789abcdef")
    for byteorder in ("big", "little"):
        encrypted = crypt(block, key, True, "enc", byteorder)
        if crypt(encrypted, key, True, "dec", byteorder) != block:
            raise ValueError("signed Blowfish roundtrip failed")
        standard = probe.ecb_crypt("blowfish", key, block, "enc")
        if byteorder == "big":
            reference = standard
        else:
            transformed = b"".join(block[i:i + 4][::-1] for i in (0, 4))
            encrypted_std = probe.ecb_crypt("blowfish", key, transformed, "enc")
            reference = b"".join(encrypted_std[i:i + 4][::-1] for i in (0, 4))
        if crypt(block, key, False, "enc", byteorder) != reference:
            raise ValueError("unsigned Blowfish cross-check failed")
    ascii_key = b"kb?A68D+tl?2@KL_"
    if crypt(block, ascii_key, True, "enc", "big") != probe.ecb_crypt("blowfish", ascii_key, block, "enc"):
        raise ValueError("E2E ASCII-key cross-check failed")
    high_bit = ascii_key[:3] + b"\x80" + ascii_key[4:]
    if crypt(block, high_bit, True, "enc", "big") == crypt(block, high_bit, False, "enc", "big"):
        raise ValueError("signed variant did not diverge for a high-bit key")
    return ["standard-zero-vector", "signed-roundtrips", "unsigned-cross-checks",
            "E2E-ASCII-cross-check", "high-bit-divergence"]


def header_candidates():
    values = set()
    for product, version, rel in probe.PKGS:
        header = probe.read_header(os.path.join(ROOT, rel))
        field = header[0x20:0x30]
        inputs = [field, header, header[:0x30], header[0x10:0x20].rstrip(b"\x00"),
                  header[0x10:0x20] + field, header[0x30:0x34] + field]
        for value in inputs:
            for derived in (value, hashlib.md5(value).digest(), hashlib.sha1(value).digest(),
                            hashlib.sha256(value).digest()):
                if 4 <= len(derived) <= 56 and any(byte >= 0x80 for byte in derived):
                    values.add(derived)
                if len(derived) < 32:
                    doubled = derived * 2
                    if 4 <= len(doubled) <= 56 and any(byte >= 0x80 for byte in doubled):
                        values.add(doubled)
    return sorted(values)


def related_candidates():
    import sfub_related_binary_probe as related

    words = set(related.EXTRA_WORDS)
    for rel in related.INPUTS:
        words.update(related.binary_strings(os.path.join(ROOT, rel)))
    keys = probe.key_candidates([], words=sorted(words))
    return sorted({key for cipher, key, _provenance in keys
                   if cipher == "blowfish" and any(key[i] >= 0x80 for i in range(3, len(key), 4))})


def main():
    import sys

    if any(flag in sys.argv for flag in ("-h", "--help")):
        print("usage: sfub_blowfish_signed.py [--related]")
        print("Requires operator-supplied E2E updater and SFUB firmware artifacts.")
        return
    related = "--related" in sys.argv
    kats = run_kats()
    candidates = related_candidates() if related else header_candidates()
    targets = [(label, bytes.fromhex(value)) for label, value in probe.BASE_TARGETS]
    blob = b"".join(value for _label, value in targets)
    exact = {block: label for label, block in probe.PLAINTEXT_CANDIDATES}
    hits = []
    operations = 0
    started = time.time()
    for key in candidates:
        for direction in ("dec", "enc"):
            for byteorder in ("big", "little"):
                output = crypt(blob, key, True, direction, byteorder)
                operations += len(targets)
                for index, (target_label, target) in enumerate(targets):
                    plaintext = output[index * 8:index * 8 + 8]
                    classification = probe.classify_plaintext(plaintext, exact)
                    if classification:
                        hit = {"cipher": "blowfish-signed-key-bytes", "key_hex": key.hex(),
                               "direction": direction, "block_byteorder": byteorder,
                               "target": target_label, "target_hex": target.hex(),
                               "plaintext_hex": plaintext.hex(), "class": classification}
                        hits.append(hit)
                        print("HIT", json.dumps(hit), flush=True)
    source = "related" if related else "header"
    result = {"tool": os.path.basename(__file__), "source": source, "kats": kats,
              "high_bit_candidates": len(candidates), "block_operations": operations,
              "elapsed_seconds": round(time.time() - started, 3), "hits": hits}
    output = os.path.join(ROOT, "results", f"blowfish-signed-{source}-probe.json")
    with open(output, "w") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
