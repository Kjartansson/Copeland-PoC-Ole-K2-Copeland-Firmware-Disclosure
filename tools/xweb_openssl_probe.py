#!/usr/bin/env python3
"""Bounded password/KDF probe for XWEB OpenSSL Salted__ update components."""

import argparse
import hashlib
import json
import os
import subprocess

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

import sfub_hashcat_probe as gpu

ROOT = gpu.ROOT
INPUT = os.path.join(ROOT, "extracted", "XWEB_PRO_1.15.1", "rootfs")
MAGICS = (b"\x1f\x8b\x08", b"hsqs", b"sqsh", b"070701", b"070702", b"UBI#", b"ustar", b"PK\x03\x04", b"\x7fELF")


def evp_bytes_to_key(password, salt, key_iv_len, digest):
    output = b""
    previous = b""
    while len(output) < key_iv_len:
        previous = digest(previous + password + salt).digest()
        output += previous
    return output[:key_iv_len]


def derive(password, salt, cipher_name, kdf_name):
    if kdf_name.startswith("pbkdf2"):
        length = 48 if cipher_name == "aes-256-cbc" else 40 if cipher_name == "aes-128-cbc" else 32
        material = PBKDF2HMAC(algorithm=hashes.SHA256(), length=length, salt=salt,
                              iterations=10000).derive(password)
    else:
        length = 48 if cipher_name == "aes-256-cbc" else 40 if cipher_name == "aes-128-cbc" else 32
        digest = hashlib.md5 if kdf_name == "evp-md5" else hashlib.sha256
        material = evp_bytes_to_key(password, salt, length, digest)
    if cipher_name == "aes-256-cbc":
        return material[:32], material[32:48]
    if cipher_name == "aes-128-cbc":
        return material[:16], material[16:32]
    return material[:24], material[24:32]


def decrypt(cipher_name, key, iv, ciphertext):
    algorithm = algorithms.AES(key) if cipher_name.startswith("aes") else algorithms.TripleDES(key)
    context = Cipher(algorithm, modes.CBC(iv)).decryptor()
    return context.update(ciphertext) + context.finalize()


def encrypt_openssl(cipher_name, key, iv, plaintext):
    algorithm = algorithms.AES(key) if cipher_name.startswith("aes") else algorithms.TripleDES(key)
    context = Cipher(algorithm, modes.CBC(iv)).encryptor()
    return context.update(plaintext) + context.finalize()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expanded", action="store_true")
    parser.add_argument("--target", default=INPUT)
    parser.add_argument("--words", help="optional file containing one password candidate per line")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--no-pbkdf2", action="store_true")
    parser.add_argument("--json", default=os.path.join(ROOT, "results", "xweb-openssl.json"))
    args = parser.parse_args()
    with open(args.target, "rb") as handle:
        header = handle.read(48)
    assert header.startswith(b"Salted__")
    salt, ciphertext = header[8:16], header[16:48]
    for cipher_name, kdf_name in (("aes-256-cbc", "evp-md5"), ("aes-256-cbc", "pbkdf2-sha256")):
        key, iv = derive(b"test", salt, cipher_name, kdf_name)
        options = ["-md", "md5"] if kdf_name == "evp-md5" else ["-pbkdf2"]
        expected = subprocess.run(["openssl", "enc", "-" + cipher_name, "-e", "-salt", "-pass", "pass:test",
                                   "-S", salt.hex(), *options], input=b"known plaintext!", capture_output=True, check=True).stdout
        actual = encrypt_openssl(cipher_name, key, iv, b"known plaintext!")
        if actual != expected[:16]:
            raise SystemExit(f"KAT failed {cipher_name}/{kdf_name}: {actual.hex()} != {expected[:16].hex()}")
    if args.words:
        with open(args.words, encoding="utf-8") as handle:
            words = sorted({line.rstrip("\r\n") for line in handle if line.rstrip("\r\n")})
    else:
        words = gpu.expanded_words() if args.expanded else gpu.factory_words()
    if args.limit:
        words = words[:args.limit]
    jobs = [("aes-256-cbc", "evp-md5"), ("aes-256-cbc", "evp-sha256"),
            ("aes-128-cbc", "evp-md5"), ("aes-128-cbc", "evp-sha256"),
            ("des-ede3-cbc", "evp-md5"), ("des-ede3-cbc", "evp-sha256")]
    if not args.no_pbkdf2:
        jobs.append(("aes-256-cbc", "pbkdf2-sha256"))
    hits = []
    operations = 0
    for cipher_name, kdf_name in jobs:
        for word in words:
            key, iv = derive(word.encode(), salt, cipher_name, kdf_name)
            plaintext = decrypt(cipher_name, key, iv, ciphertext)
            operations += 1
            if plaintext.startswith(MAGICS):
                hit = {"cipher": cipher_name, "kdf": kdf_name, "password": word,
                       "key_hex": key.hex(), "iv_hex": iv.hex(), "plaintext_hex": plaintext.hex()}
                hits.append(hit)
                print("HIT", json.dumps(hit), flush=True)
        print(f"completed {cipher_name}/{kdf_name}: {len(words)} passwords", flush=True)
    result = {"tool": os.path.basename(__file__), "expanded": args.expanded, "words": len(words),
              "limit": args.limit, "pbkdf2_included": not args.no_pbkdf2,
              "operations": operations, "hits": hits}
    with open(args.json, "w") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    main()
