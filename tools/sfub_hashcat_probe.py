#!/usr/bin/env python3
"""Bounded GPU dictionary probe for Copeland SFUB 8-byte block payloads.

Expands sfub_crypt_probe's vendor/product wordlist with common embedded-key
suffixes and tests DES plus 2-key/3-key 3DES with hashcat. Hashcat's raw-cipher
modes require a known plaintext, so this probe uses only the documented exact
plaintext candidates and all 256 uniform-byte blocks. It does not claim an
exhaustive key search or support a cipher identification by itself.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time

import sfub_crypt_probe as probe

ROOT = probe.ROOT
RESULTS = os.path.join(ROOT, "results")
SUFFIXES = ("", "0", "1", "01", "7", "12", "123", "1234", "!", "!!",
            "2020", "2021", "2022", "2023", "2024", "2025", "2026")
LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})
FACTORY_DEFAULTS = (
    "user", "pass", "userpass", "user_pass", "user-pass", "user:pass",
    "ONEDAY", "oneday", "OneDay", "one day", "one_day", "one-day",
    "msc", "mscomsc", "mscmsc", "admin", "adminadmin", "root", "rootroot",
    "service", "support", "technician", "setup", "setupinprogress",
)


def factory_words():
    return sorted(set(FACTORY_DEFAULTS))


def expanded_words():
    words = set(probe.word_variants()) | set(FACTORY_DEFAULTS)
    for word in list(words):
        variants = {word, word.translate(LEET)}
        if word.lower() != word:
            variants.add(word.lower().translate(LEET))
        for variant in variants:
            for suffix in SUFFIXES:
                words.add(variant + suffix)
                if suffix:
                    words.add(suffix + variant)
    return sorted(words)


def derive_keys(words):
    keys = {"des": set(), "3des": set()}
    for word in words:
        raw = word.encode()
        md5 = hashlib.md5(raw).digest()
        sha1 = hashlib.sha1(raw).digest()
        sha256 = hashlib.sha256(raw).digest()
        keys["des"].update((probe.pad_nul(raw, 8), probe.pad_space(raw, 8),
                            md5[:8], sha1[:8], sha256[:8]))
        keys["3des"].update((probe.pad_nul(raw, 24), sha256[:24],
                             md5 + sha1[:8], sha1 + md5[:4],
                             probe.pad_nul(raw, 16) + probe.pad_nul(raw, 8),
                             md5 + md5[:8], sha1[:16] + sha1[:8],
                             sha256[:16] + sha256[:8]))
    field20 = []
    for product, version, rel in probe.PKGS:
        header = probe.read_header(os.path.join(ROOT, rel))
        field20.append((f"{product} {version}", header[0x20:0x30].hex()))
    for cipher, key, _provenance in probe.key_candidates(field20):
        if cipher == "des":
            keys["des"].add(key)
        elif cipher == "3des-3key":
            keys["3des"].add(key)
        elif cipher == "3des-2key":
            keys["3des"].add(key + key[:8])
    return {name: sorted(values) for name, values in keys.items()}


def plaintexts():
    return [block for _label, block in probe.PLAINTEXT_CANDIDATES] + [bytes([i]) * 8 for i in range(256)]


def write_lines(path, lines):
    with open(path, "w") as handle:
        handle.write("\n".join(lines) + "\n")


def prepare(words):
    os.makedirs(RESULTS, exist_ok=True)
    keys = derive_keys(words)
    write_lines(os.path.join(RESULTS, "hashcat-words.txt"), words)
    for name, values in keys.items():
        write_lines(os.path.join(RESULTS, f"hashcat-{name}.keys"),
                    ["$HEX[" + key.hex() + "]" for key in values])
    hashes = []
    for label, target_hex in probe.BASE_TARGETS:
        target = bytes.fromhex(target_hex)
        for plaintext in plaintexts():
            hashes.append(f"{target.hex()}:{plaintext.hex()}")
            hashes.append(f"{plaintext.hex()}:{target.hex()}")
    hash_path = os.path.join(RESULTS, "hashcat-targets.hashes")
    write_lines(hash_path, sorted(set(hashes)))
    return words, keys, hash_path


def decode_key(value):
    if value.startswith("$HEX[") and value.endswith("]"):
        return bytes.fromhex(value[5:-1])
    return value.encode()


def run_hashcat(name, mode, key_count, hash_path, runtime, validator=None):
    output = os.path.join(RESULTS, f"hashcat-{name}.out")
    if os.path.exists(output):
        os.remove(output)
    cuda_lib = os.environ.get("HASHCAT_CUDA_LIB", "")
    cuda_shim = os.environ.get("HASHCAT_CUDA_SHIM", "")
    env = os.environ.copy()
    if os.path.exists(os.path.join(cuda_shim, "libnvrtc.so")) and os.path.exists(cuda_lib):
        device_args = ["-d", "1", "-O", "-w", "3", "--backend-ignore-opencl"]
        env["LD_LIBRARY_PATH"] = cuda_shim + ":" + cuda_lib + (
            ":" + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
        backend = "cuda"
    else:
        device_args = ["-D", "2"]
        backend = "opencl-fallback"
    command = [
        "hashcat", "-m", str(mode), "-a", "0", *device_args, "--quiet",
        "--potfile-disable", "--logfile-disable", "--runtime", str(runtime),
        "--restore-file-path", os.path.join(RESULTS, f"hashcat-{name}.restore"),
        "--outfile", output, "--outfile-format", "1,2",
        hash_path, os.path.join(RESULTS, f"hashcat-{name}.keys"),
    ]
    started = time.time()
    completed = subprocess.run(command, cwd=ROOT, env=env)
    elapsed = time.time() - started
    if completed.returncode not in (0, 1):
        raise RuntimeError(f"hashcat {name} failed with exit code {completed.returncode}")
    hits = []
    if os.path.exists(output):
        with open(output) as handle:
            for line in handle:
                encoded_hash, encoded_key = line.rstrip("\n").rsplit(":", 1)
                ciphertext_hex, plaintext_hex = encoded_hash.split(":", 1)
                key = decode_key(encoded_key)
                cipher_name = "des" if name == "des" else "3des-3key"
                if validator is None:
                    valid = probe.ecb_crypt(cipher_name, key, bytes.fromhex(plaintext_hex), "enc") == bytes.fromhex(ciphertext_hex)
                else:
                    valid, cipher_name = validator(key, ciphertext_hex, plaintext_hex)
                if not valid:
                    raise RuntimeError(f"unverified hashcat hit: {line.rstrip()}")
                hits.append({"cipher": cipher_name, "key_hex": key.hex(),
                             "ciphertext_hex": ciphertext_hex, "plaintext_hex": plaintext_hex})
    return {"mode": mode, "backend": backend, "key_candidates": key_count,
            "runtime_seconds": round(elapsed, 2), "exit_code": completed.returncode, "hits": hits}


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--generate-only", action="store_true")
    parser.add_argument("--defaults-only", action="store_true",
                        help="test only documented factory and generic embedded defaults")
    parser.add_argument("--runtime", type=int, default=900,
                        help="maximum hashcat seconds per cipher (default: 900)")
    args = parser.parse_args()
    if shutil.which("hashcat") is None:
        raise SystemExit("hashcat is required")
    kat_log = []
    kats = probe.run_kats(kat_log)
    if not all(item["ok"] for item in kats):
        raise SystemExit("cipher known-answer test failed; aborting")
    write_lines(os.path.join(RESULTS, "hashcat-kat.txt"), kat_log)
    words = factory_words() if args.defaults_only else expanded_words()
    words, keys, hash_path = prepare(words)
    summary = {"tool": os.path.basename(__file__), "defaults_only": args.defaults_only,
               "words": len(words), "known_plaintext_blocks": len(plaintexts()),
               "hash_target_pairs": sum(1 for _ in open(hash_path)),
               "key_candidates": {name: len(values) for name, values in keys.items()},
               "runs": []}
    print(json.dumps({k: v for k, v in summary.items() if k != "runs"}, indent=2))
    if not args.generate_only:
        for name, mode in (("des", 14000), ("3des", 14100)):
            result = run_hashcat(name, mode, len(keys[name]), hash_path, args.runtime)
            summary["runs"].append(result)
            print(f"{name}: {result['key_candidates']} keys, {len(result['hits'])} verified hits, "
                  f"exit={result['exit_code']}, {result['runtime_seconds']}s")
    output_name = "hashcat-defaults.json" if args.defaults_only else "hashcat-probe.json"
    with open(os.path.join(RESULTS, output_name), "w") as handle:
        json.dump(summary, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
