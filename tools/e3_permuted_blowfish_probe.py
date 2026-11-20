#!/usr/bin/env python3
"""Recover and test the E3 updater's permuted static Blowfish key."""

import argparse
import hashlib
import json
import os
import struct
import sys
import time

import sfub_crypt_probe as probe
import sfub_blowfish_signed as blowfish

ROOT = probe.ROOT
ELF = os.path.join(ROOT, "extracted", "E2_4.11F02", "SysUpdt.embedded.elf")
BLOB_ADDRESS = 0x768D20
KEY_SETUP = 0x655FC0
RETURN_SENTINEL = 0x1000
CODE_BASE = 0x600000
CODE_SIZE = 0x200000
INPUT_BASE = 0x1000000
OBJECT_BASE = 0x13000000
STACK_BASE = 0x14000000


def load_segments():
    with open(ELF, "rb") as handle:
        data = handle.read()
    if data[:4] != b"\x7fELF" or data[4] != 1 or data[5] != 1:
        raise ValueError("unexpected E3 updater ELF")
    phoff = struct.unpack_from("<I", data, 0x1C)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)
    segments = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, p_offset, vaddr, _physical, filesz, memsz = struct.unpack_from("<IIIIII", data, offset)
        if p_type == 1:
            if filesz > memsz or p_offset + filesz > len(data):
                raise ValueError("invalid E3 updater segment")
            segments.append((p_offset, vaddr, filesz, memsz))
    if len(segments) != 2:
        raise ValueError("unexpected E3 updater segment count")
    return data, segments


def virtual_bytes(data, segments, address):
    for offset, vaddr, filesz, _memsz in segments:
        if vaddr <= address < vaddr + filesz:
            position = offset + address - vaddr
            end = data.index(0, position)
            return data[position:end]
    raise ValueError("static blob is not file-backed")


def permute(raw):
    output = bytearray(raw)
    for index in range(0, len(raw), 2):
        output[len(raw) - index - 1] = raw[index]
    return bytes(output)


def recover_key():
    data, segments = load_segments()
    raw = virtual_bytes(data, segments, BLOB_ADDRESS)
    if len(raw) != 175 or not all(0x20 <= byte <= 0x7E for byte in raw):
        raise ValueError("unexpected E3 static blob")
    return raw, permute(raw)[:56]


def emulation_check(key):
    sys.path.insert(0, os.path.join(ROOT, "tools", "third-party", "unicorn-runtime"))
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_32
    from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP

    data, segments = load_segments()
    uc = Uc(UC_ARCH_X86, UC_MODE_32)
    uc.mem_map(CODE_BASE, CODE_SIZE)
    for offset, vaddr, filesz, memsz in segments:
        uc.mem_write(vaddr, data[offset:offset + filesz])
        if memsz > filesz:
            uc.mem_write(vaddr + filesz, b"\x00" * (memsz - filesz))
    uc.mem_map(0, 0x2000)
    uc.mem_write(RETURN_SENTINEL, b"\xC3")
    uc.mem_map(INPUT_BASE, 0x1000)
    uc.mem_map(OBJECT_BASE, 0x10000)
    uc.mem_map(STACK_BASE, 0x20000)
    uc.mem_write(INPUT_BASE, b"00:11:22:33:44:55\x00")
    uc.mem_write(INPUT_BASE + 0x100, key + b"\x00")
    esp = STACK_BASE + 0x1F000
    uc.mem_write(esp, struct.pack("<IIII", RETURN_SENTINEL, OBJECT_BASE, INPUT_BASE, INPUT_BASE + 0x100))
    uc.reg_write(UC_X86_REG_ESP, esp)
    uc.reg_write(UC_X86_REG_EIP, KEY_SETUP)
    uc.emu_start(KEY_SETUP, RETURN_SENTINEL, count=20_000_000)
    emulated_key_length = struct.unpack("<H", uc.mem_read(OBJECT_BASE + 0x10BA, 2))[0]
    emulated_key = bytes(uc.mem_read(OBJECT_BASE + 0x1081, emulated_key_length))
    emulated_p = list(struct.unpack("<18I", uc.mem_read(OBJECT_BASE, 18 * 4)))
    expected_p, _sboxes = blowfish.expand_key(key, True)
    if emulated_key != key or emulated_key_length != len(key) or emulated_p != expected_p:
        mismatch = next((index for index, pair in enumerate(zip(emulated_p, expected_p))
                         if pair[0] != pair[1]), None)
        raise ValueError(f"E3 key model mismatch: length={emulated_key_length}, "
                         f"key_match={emulated_key == key}, p_mismatch={mismatch}, "
                         f"emulated_p={emulated_p[:4]}, expected_p={expected_p[:4]}")
    return {
        "key_setup_address": hex(KEY_SETUP),
        "mac_input": "00:11:22:33:44:55",
        "selected_key_sha256": hashlib.sha256(emulated_key).hexdigest(),
        "selected_key_length": emulated_key_length,
        "p_array_matches": True,
        "return_eax": uc.reg_read(UC_X86_REG_EAX),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-discover", action="store_true")
    parser.add_argument("--skip-emulation", action="store_true")
    parser.add_argument("--json", default=os.path.join(ROOT, "results", "e3-permuted-blowfish-probe.json"))
    args = parser.parse_args()
    started = time.time()
    raw, key = recover_key()
    kats = blowfish.run_kats()
    emulation = None if args.skip_emulation else emulation_check(key)
    targets = [(label, bytes.fromhex(value)) for label, value in probe.BASE_TARGETS]
    discovery = None
    if not args.skip_discover:
        log = []
        discovery = probe.discover_shared_blocks(log)
        existing = {value for _label, value in targets}
        targets.extend((f"shared:{value.hex()}", value)
                       for value in (bytes.fromhex(item) for item in discovery["shared_by_at_least_two"])
                       if value not in existing)
    exact = {block: label for label, block in probe.PLAINTEXT_CANDIDATES}
    blob = b"".join(value for _label, value in targets)
    hits = []
    operations = 0
    for direction in ("dec", "enc"):
        for byteorder in ("big", "little"):
            plaintext = blowfish.crypt(blob, key, True, direction, byteorder)
            operations += len(targets)
            for index, (label, target) in enumerate(targets):
                block = plaintext[index * 8:index * 8 + 8]
                classification = probe.classify_plaintext(block, exact)
                if classification:
                    hits.append({"target": label, "target_hex": target.hex(),
                                 "plaintext_hex": block.hex(), "class": classification,
                                 "direction": direction, "block_byteorder": byteorder})
                    print("CANDIDATE", json.dumps(hits[-1]), flush=True)
    result = {
        "tool": os.path.basename(__file__),
        "updater_sha256": hashlib.sha256(load_segments()[0]).hexdigest(),
        "static_blob_address": hex(BLOB_ADDRESS),
        "raw_blob_length": len(raw),
        "permutation": "even-indexed bytes reversed into even output positions; odd bytes unchanged",
        "key_length": len(key),
        "effective_schedule_prefix_length": 72,
        "key_sha256": hashlib.sha256(key).hexdigest(),
        "signed_backend_kats": kats,
        "emulation": emulation,
        "base_targets": len(probe.BASE_TARGETS),
        "targets_total": len(targets),
        "block_operations": operations,
        "hits": hits,
        "discovery": discovery,
        "elapsed_seconds": round(time.time() - started, 3),
    }
    with open(args.json, "w") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")
    print(json.dumps({key: value for key, value in result.items() if key != "discovery"}, indent=2))


if __name__ == "__main__":
    main()
