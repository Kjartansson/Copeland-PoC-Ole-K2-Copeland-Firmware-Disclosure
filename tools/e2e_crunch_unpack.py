#!/usr/bin/env python3
"""Decode exactly one selected E2E Crunch stream with bounded emulation."""

import hashlib
import struct
import sys

import e2e_crunch_emulate as codec


def main():
    if len(sys.argv) not in (5, 6):
        raise SystemExit("usage: e2e_crunch_unpack.py PACKAGE OFFSET INPUT_SIZE OUTPUT [EXPECTED_SIZE]")
    package, offset_text, size_text, output_path = sys.argv[1:5]
    offset = int(offset_text, 0)
    input_size = int(size_text, 0)
    with open(package, "rb") as handle:
        handle.seek(offset)
        compressed = handle.read(input_size)
    if len(compressed) != input_size:
        raise ValueError("truncated compressed input")
    headerless = len(sys.argv) == 6
    if headerless:
        capacity = int(sys.argv[5], 0)
    else:
        if len(compressed) < 8 or struct.unpack_from("<I", compressed)[0] != 0x5AA5A55A:
            raise ValueError("Crunch magic not present at requested offset")
        capacity = struct.unpack_from("<I", compressed, 4)[0]
    if not capacity or capacity > codec.OUTPUT_SIZE - 0x1000:
        raise ValueError(f"unreasonable output capacity {capacity}")

    emulator = codec.Uc(codec.UC_ARCH_X86, codec.UC_MODE_32)
    codec.load_code(emulator)
    emulator.mem_map(codec.INPUT_BASE, codec.INPUT_SIZE)
    emulator.mem_write(codec.INPUT_BASE, compressed)
    emulator.mem_map(codec.OUTPUT_BASE, codec.OUTPUT_SIZE)
    emulator.mem_map(codec.OBJECT_BASE, codec.OBJECT_SIZE)
    emulator.mem_map(codec.STACK_BASE, codec.STACK_SIZE)

    codec.call(emulator, codec.CONSTRUCTOR, [codec.OBJECT_BASE], 1_000_000)
    result = codec.call(
        emulator, codec.DECOMPRESS,
        [codec.OBJECT_BASE, codec.INPUT_BASE, len(compressed),
         codec.OUTPUT_BASE, capacity, 1 if headerless else 0],
        250_000_000)
    flags = bytes(emulator.mem_read(codec.OBJECT_BASE + 0x20, 2))
    input_position = struct.unpack("<I", emulator.mem_read(codec.OBJECT_BASE + 0x04, 4))[0]
    consumed = input_position - codec.INPUT_BASE
    if result == 0xFFFFFFFF or result > capacity or flags != b"\x00\x00":
        raise RuntimeError(f"decoder failed: result={result:#x} flags={flags.hex()}")
    if consumed <= 0:
        raise RuntimeError("decoder made no input progress")

    output = bytes(emulator.mem_read(codec.OUTPUT_BASE, result))
    with open(output_path, "wb") as handle:
        handle.write(output)
    print(f"result={result} capacity={capacity} consumed={consumed}/{len(compressed)} "
          f"remaining={len(compressed) - consumed} sha256={hashlib.sha256(output).hexdigest()}")
    print(f"wrote={output_path}")


if __name__ == "__main__":
    main()
