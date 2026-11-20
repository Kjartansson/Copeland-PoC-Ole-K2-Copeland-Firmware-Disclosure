#!/usr/bin/env python3
"""Test printable strings from recovered related updater binaries against SFUB."""

import json
import os
import re
import time

import sfub_crypt_probe as probe

ROOT = probe.ROOT
INPUTS = [
    "extracted/E2E_4.11F03/SysUpdt.embedded.elf",
]
EXTRA_WORDS = [
    "kb?A68D+tl?2@KL_",
    "$tIkb?A68D+tl?2@KL_",  # exact 16-byte reference and surrounding string
]


def binary_strings(path):
    data = open(path, "rb").read()
    return [match.group().decode("ascii") for match in re.finditer(rb"[ -~]{4,}", data)]


def main():
    words = set(EXTRA_WORDS)
    origins = {}
    for rel in INPUTS:
        path = os.path.join(ROOT, rel)
        current = binary_strings(path)
        origins[rel] = len(current)
        words.update(current)
    words = sorted(words)
    keys = probe.key_candidates([], words=words)
    targets = [(label, bytes.fromhex(value)) for label, value in probe.BASE_TARGETS]
    log = []
    started = time.time()
    hits, operations, elapsed = probe.sweep(keys, targets, log)
    result = {
        "tool": os.path.basename(__file__),
        "inputs": INPUTS,
        "strings_per_input": origins,
        "unique_strings": len(words),
        "cipher_key_candidates": len(keys),
        "targets": len(targets),
        "cipher_operations": operations,
        "block_operations": operations * len(targets),
        "elapsed_seconds": round(time.time() - started, 3),
        "hits": hits,
        "log": log,
    }
    output = os.path.join(ROOT, "results", "related-binary-probe.json")
    with open(output, "w") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps({key: value for key, value in result.items() if key != "log"}))


if __name__ == "__main__":
    main()
