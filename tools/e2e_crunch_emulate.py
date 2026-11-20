#!/usr/bin/env python3
"""Function-level, bounded emulation of the reviewed E2E Crunch decoder."""

import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "third-party", "unicorn-runtime"))
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_MEM_INVALID
from unicorn.x86_const import UC_X86_REG_EAX, UC_X86_REG_EIP, UC_X86_REG_ESP

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ELF = os.path.join(ROOT, "extracted", "E2E_4.11F03", "SysUpdt.embedded.elf")
CODE_BASE = 0x600000
CODE_SIZE = 0x200000
INPUT_BASE = 0x1000000
INPUT_SIZE = 0x1000000
OUTPUT_BASE = 0x2000000
OUTPUT_SIZE = 0x10000000
OBJECT_BASE = 0x13000000
OBJECT_SIZE = 0x10000
STACK_BASE = 0x14000000
STACK_SIZE = 0x20000
RETURN_SENTINEL = 0x1000
CONSTRUCTOR = 0x649860
DECOMPRESS = 0x6499F0


def align_down(value, alignment=0x1000):
    return value & ~(alignment - 1)


def align_up(value, alignment=0x1000):
    return (value + alignment - 1) & ~(alignment - 1)


def load_code(emulator):
    with open(ELF, "rb") as handle:
        data = handle.read()
    entry = struct.unpack_from("<I", data, 0x18)[0]
    offset, virtual, _physical, filesz, memsz = struct.unpack_from("<IIIII", data, 0x38)
    if entry != 0x608000 or virtual != entry or offset != 0x60:
        raise ValueError("unexpected E2E ELF layout")
    emulator.mem_map(CODE_BASE, CODE_SIZE)
    emulator.mem_write(CODE_BASE, b"\x00" * CODE_SIZE)
    emulator.mem_write(0x608000, data[offset:offset + filesz])
    if memsz < filesz:
        raise ValueError("invalid E2E ELF segment")
    emulator.mem_map(align_down(RETURN_SENTINEL), 0x1000)
    emulator.mem_write(RETURN_SENTINEL, b"\xC3")


def call(emulator, address, arguments, instruction_limit):
    stack = struct.pack("<I", RETURN_SENTINEL) + struct.pack(f"<{len(arguments)}I", *arguments)
    esp = STACK_BASE + STACK_SIZE - 0x1000
    emulator.mem_write(esp, stack)
    emulator.reg_write(UC_X86_REG_ESP, esp)
    emulator.reg_write(UC_X86_REG_EIP, address)
    emulator.emu_start(address, RETURN_SENTINEL, count=instruction_limit)
    return emulator.reg_read(UC_X86_REG_EAX)


def main():
    if len(sys.argv) not in (4, 5):
        raise SystemExit("usage: e2e_crunch_emulate.py PACKAGE MAGIC_OFFSET COMPRESSED_SIZE [OUTPUT]")
    package, offset_text, size_text = sys.argv[1:4]
    offset = int(offset_text, 0)
    compressed_size = int(size_text, 0)
    with open(package, "rb") as handle:
        handle.seek(offset)
        compressed = handle.read(compressed_size)
    if len(compressed) != compressed_size:
        raise ValueError("truncated compressed input")
    if len(compressed) < 8 or struct.unpack_from("<I", compressed)[0] != 0x5AA5A55A:
        raise ValueError("Crunch magic not present at requested offset")
    expected_size = struct.unpack_from("<I", compressed, 4)[0]
    if not expected_size or expected_size > OUTPUT_SIZE - 0x1000:
        raise ValueError(f"unreasonable uncompressed size {expected_size}")

    emulator = Uc(UC_ARCH_X86, UC_MODE_32)
    load_code(emulator)
    emulator.mem_map(INPUT_BASE, INPUT_SIZE)
    emulator.mem_write(INPUT_BASE, compressed)
    emulator.mem_map(OUTPUT_BASE, OUTPUT_SIZE)
    emulator.mem_map(OBJECT_BASE, OBJECT_SIZE)
    emulator.mem_map(STACK_BASE, STACK_SIZE)

    invalid = []
    def invalid_memory(_uc, access, address, size, value, _user):
        invalid.append((access, address, size, value))
        return False
    emulator.hook_add(UC_HOOK_MEM_INVALID, invalid_memory)
    error_writes = []
    def error_write(uc, _access, address, size, value, _user):
        error_writes.append((uc.reg_read(UC_X86_REG_EIP), address, size, value))
    from unicorn import UC_HOOK_MEM_WRITE
    emulator.hook_add(UC_HOOK_MEM_WRITE, error_write,
                      begin=OBJECT_BASE + 0x20, end=OBJECT_BASE + 0x21)

    call(emulator, CONSTRUCTOR, [OBJECT_BASE], 1_000_000)
    result = call(emulator, DECOMPRESS,
                  [OBJECT_BASE, INPUT_BASE, len(compressed), OUTPUT_BASE, expected_size, 0],
                  250_000_000)
    flags = bytes(emulator.mem_read(OBJECT_BASE + 0x20, 2))
    output = bytes(emulator.mem_read(OUTPUT_BASE, min(result, expected_size)))
    input_position = struct.unpack("<I", emulator.mem_read(OBJECT_BASE + 0x04, 4))[0]
    consumed = input_position - INPUT_BASE
    print(f"result={result} capacity={expected_size} consumed={consumed} flags={flags.hex()} "
          f"sha256={hashlib.sha256(output).hexdigest()}")
    print(f"prefix={output[:64].hex()}")
    print(f"error_writes={[(hex(eip), hex(address), size, value) for eip, address, size, value in error_writes]}")
    if invalid:
        raise RuntimeError(f"invalid emulated memory access: {invalid[0]}")
    if result == 0xFFFFFFFF or result > expected_size or flags != b"\x00\x00":
        raise RuntimeError("decoder failed")
    if len(sys.argv) == 5:
        output_path = sys.argv[4]
        with open(output_path, "wb") as handle:
            handle.write(output)
        print(f"wrote={output_path}")


if __name__ == "__main__":
    main()
