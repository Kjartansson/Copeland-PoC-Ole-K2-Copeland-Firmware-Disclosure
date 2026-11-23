#!/usr/bin/env python3
"""Sequential decode of the magic-header Crunch stream table in E2/E2E packages.

Applies the corrected genuine-wrapper semantics from
results/crunch-runtime/RECOVERY.md: constructor fcn.00649860, declared-size
probe fcn.00649790, then vtable[3] = 0x6499f0 with arg5 = 0 (magic-header
mode). Each stream must start with 5aa5a55a; the decoder is fed the remaining
package bytes and 'consumed' tells the exact stream length. Streams are
expected to be contiguous (alignment gaps are recorded, not skipped silently).
"""

import hashlib
import json
import os
import struct
import sys

TOOLS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
sys.path.insert(0, TOOLS)
import e2e_crunch_emulate as codec

MAGIC = 0x5AA5A55A


def decode_one(package_data, pos, region_end):
    """Decode one magic-header stream at pos. Returns a record dict."""
    compressed = package_data[pos:region_end]
    record = {"offset": pos, "offset_hex": hex(pos)}
    if len(compressed) < 8 or struct.unpack_from("<I", compressed)[0] != MAGIC:
        record["error"] = "magic missing"
        return record, None
    declared = struct.unpack_from("<I", compressed, 4)[0]
    record["declared"] = declared
    if not declared or declared > codec.OUTPUT_SIZE - 0x1000:
        record["error"] = f"unreasonable declared size {declared:#x}"
        return record, None

    emulator = codec.Uc(codec.UC_ARCH_X86, codec.UC_MODE_32)
    codec.load_code(emulator)
    emulator.mem_map(codec.INPUT_BASE, codec.INPUT_SIZE)
    emulator.mem_write(codec.INPUT_BASE, compressed)
    out_size = codec.align_up(declared + 0x1000)
    emulator.mem_map(codec.OUTPUT_BASE, out_size)
    emulator.mem_map(codec.OBJECT_BASE, codec.OBJECT_SIZE)
    emulator.mem_map(codec.STACK_BASE, codec.STACK_SIZE)

    invalid = []
    def invalid_memory(_uc, access, address, size, value, _user):
        invalid.append((access, address, size, value))
        return False
    from unicorn import UC_HOOK_MEM_INVALID
    emulator.hook_add(UC_HOOK_MEM_INVALID, invalid_memory)

    codec.call(emulator, codec.CONSTRUCTOR, [codec.OBJECT_BASE], 1_000_000)
    probe = codec.call(emulator, 0x649790, [codec.OBJECT_BASE, codec.INPUT_BASE], 100_000)
    record["declared_probe"] = probe
    if probe != declared:
        record["error"] = f"declared probe {probe:#x} != header {declared:#x}"
        return record, None
    result = codec.call(emulator, codec.DECOMPRESS,
                        [codec.OBJECT_BASE, codec.INPUT_BASE, len(compressed),
                         codec.OUTPUT_BASE, 0],
                        250_000_000)
    flags = bytes(emulator.mem_read(codec.OBJECT_BASE + 0x20, 2))
    input_position = struct.unpack("<I", emulator.mem_read(codec.OBJECT_BASE + 0x04, 4))[0]
    consumed = input_position - codec.INPUT_BASE
    produced = struct.unpack("<I", emulator.mem_read(codec.OBJECT_BASE + 0x14, 4))[0]
    record.update(result=result if result != 0xFFFFFFFF else -1,
                  produced=produced, consumed=consumed,
                  flags=flags.hex(),
                  wrapper_accept=(result == declared and flags == b"\x00\x00"))
    if invalid:
        record["error"] = f"invalid memory access {invalid[0]}"
        return record, None
    output = bytes(emulator.mem_read(codec.OUTPUT_BASE, produced))
    record["sha256"] = hashlib.sha256(output).hexdigest()
    record["head16"] = output[:16].hex()
    return record, output


def classify(output):
    if output[:4] == b"\x7fELF":
        return "elf"
    if output[:2] == b"MZ":
        return "pe"
    printable = sum(1 for b in output[:4096] if b in b"\t\n\r" or 32 <= b < 127)
    if output[:4096] and printable / min(len(output), 4096) > 0.9:
        return "text"
    return "binary"


def main():
    if len(sys.argv) != 6:
        raise SystemExit("usage: decode_stream_table.py PKG START END OUTDIR MANIFEST.json")
    pkg, start_text, end_text, outdir, manifest_path = sys.argv[1:6]
    start, end = int(start_text, 0), int(end_text, 0)
    data = open(pkg, "rb").read()
    if end <= 0 or end > len(data):
        end = len(data)
    os.makedirs(outdir, exist_ok=True)
    records = []
    pos = start
    index = 0
    while pos < end:
        if data[pos:pos + 4] != struct.pack("<I", MAGIC):
            nxt = data.find(struct.pack("<I", MAGIC), pos, min(pos + 0x100, end))
            if nxt < 0:
                records.append({"offset": pos, "offset_hex": hex(pos),
                                "error": "stream chain ended",
                                "trailing_bytes": end - pos,
                                "trailing_hex": data[pos:pos + 32].hex()})
                break
            records.append({"offset": pos, "offset_hex": hex(pos),
                            "gap_bytes": nxt - pos, "gap_hex": data[pos:nxt].hex()})
            pos = nxt
            continue
        record, output = decode_one(data, pos, end)
        record["index"] = index
        if output is not None:
            record["class"] = classify(output)
            name = f"{index:04d}_{pos:x}.bin"
            with open(os.path.join(outdir, name), "wb") as handle:
                handle.write(output)
            record["file"] = name
        records.append(record)
        consumed = record.get("consumed")
        if not consumed or consumed <= 0:
            break
        pos += consumed
        index += 1
    with open(manifest_path, "w") as handle:
        json.dump({"package": pkg, "start": start, "end": end,
                   "streams": records}, handle, indent=1)
    ok = sum(1 for r in records if r.get("wrapper_accept"))
    reject = sum(1 for r in records if r.get("sha256") and not r.get("wrapper_accept"))
    errors = sum(1 for r in records if r.get("error"))
    print(f"streams_ok={ok} streams_reject={reject} errors={errors} "
          f"records={len(records)} end_pos={pos:#x} region_end={end:#x}")
    print(f"manifest={manifest_path}")


if __name__ == "__main__":
    main()
