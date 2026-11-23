#!/usr/bin/env python3
"""Emulate the genuine E2E Crunch wrapper fcn.006470c0 semantics with Unicorn.

Faithful argument mapping recovered from SysUpdt.embedded.elf:
  wrapper fcn.006470c0(input, insize, &outbuf, &outsize):
    obj = new(0xef74); ctor fcn.00649860(obj)
    declared = fcn.00649790(obj, input)      # checks magic, returns *(input+4)
    outbuf = malloc(declared + 1)
    ret = obj->vtable[3](obj, input, insize, outbuf, 0)   # vtable[3]=0x6499f0
    # arg5 == 0 -> decoder verifies 0x5aa5a55a magic, skips 8-byte header,
    # reads declared size from the stream, decodes until output end.
    success iff ret == declared
"""

import hashlib
import os
import struct
import sys

TOOLS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
sys.path.insert(0, TOOLS)
import e2e_crunch_emulate as codec

from unicorn import UC_HOOK_MEM_INVALID
from unicorn.x86_const import UC_X86_REG_EAX


def main():
    if len(sys.argv) not in (4, 5):
        raise SystemExit("usage: wrapper_decode_unicorn.py PACKAGE OFFSET INPUT_SIZE [OUTPUT]")
    package, offset_text, size_text = sys.argv[1:4]
    offset = int(offset_text, 0)
    input_size = int(size_text, 0)
    with open(package, "rb") as handle:
        handle.seek(offset)
        compressed = handle.read(input_size)
    if len(compressed) != input_size:
        raise ValueError("truncated input")

    emulator = codec.Uc(codec.UC_ARCH_X86, codec.UC_MODE_32)
    codec.load_code(emulator)
    emulator.mem_map(codec.INPUT_BASE, codec.INPUT_SIZE)
    emulator.mem_write(codec.INPUT_BASE, compressed)
    emulator.mem_map(codec.OUTPUT_BASE, codec.OUTPUT_SIZE)
    emulator.mem_map(codec.OBJECT_BASE, codec.OBJECT_SIZE)
    emulator.mem_map(codec.STACK_BASE, codec.STACK_SIZE)

    invalid = []
    def invalid_memory(_uc, access, address, size, value, _user):
        invalid.append((access, address, size, value))
        return False
    emulator.hook_add(UC_HOOK_MEM_INVALID, invalid_memory)

    # constructor
    codec.call(emulator, codec.CONSTRUCTOR, [codec.OBJECT_BASE], 1_000_000)
    # declared-size probe exactly as the wrapper does (fcn.00649790)
    declared = codec.call(emulator, 0x649790, [codec.OBJECT_BASE, codec.INPUT_BASE], 100_000)
    print(f"declared={declared} ({declared:#x})")
    if not declared or declared > codec.OUTPUT_SIZE - 0x1000:
        raise RuntimeError("magic/declared-size check failed")
    # genuine vtable[3] call: (obj, input, insize, outbuf, 0)
    result = codec.call(emulator, codec.DECOMPRESS,
                        [codec.OBJECT_BASE, codec.INPUT_BASE, len(compressed),
                         codec.OUTPUT_BASE, 0],
                        20_000_000_000)
    flags = bytes(emulator.mem_read(codec.OBJECT_BASE + 0x20, 2))
    input_position = struct.unpack("<I", emulator.mem_read(codec.OBJECT_BASE + 0x04, 4))[0]
    consumed = input_position - codec.INPUT_BASE
    produced = struct.unpack("<I", emulator.mem_read(codec.OBJECT_BASE + 0x14, 4))[0]
    print(f"result={result} produced={produced} declared={declared} "
          f"consumed={consumed}/{len(compressed)} flags={flags.hex()}")
    if invalid:
        raise RuntimeError(f"invalid emulated memory access: {invalid[0]}")
    output = bytes(emulator.mem_read(codec.OUTPUT_BASE, produced))
    if result == 0xFFFFFFFF or produced != declared or flags != b"\x00\x00":
        print(f"WARNING: wrapper would reject: result={result:#x} "
              f"declared={declared:#x} flags={flags.hex()}")
    print(f"sha256={hashlib.sha256(output).hexdigest()}")
    print(f"prefix={output[:64].hex()}")
    print(f"suffix={output[-64:].hex()}")
    if len(sys.argv) == 5 and output:
        with open(sys.argv[4], "wb") as handle:
            handle.write(output)
        print(f"wrote={sys.argv[4]}")


if __name__ == "__main__":
    main()
