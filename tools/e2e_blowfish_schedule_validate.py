#!/usr/bin/env python3
"""Compare emulated E2E Blowfish schedules with the local signed-byte model."""

import hashlib
import struct

import e2e_crunch_emulate as codec
import sfub_blowfish_signed as signed

KEY_SCHEDULE = 0x655DB0


def main():
    emulator = codec.Uc(codec.UC_ARCH_X86, codec.UC_MODE_32)
    codec.load_code(emulator)
    emulator.mem_map(codec.INPUT_BASE, codec.INPUT_SIZE)
    emulator.mem_map(codec.OUTPUT_BASE, codec.OUTPUT_SIZE)
    emulator.mem_map(codec.OBJECT_BASE, codec.OBJECT_SIZE)
    emulator.mem_map(codec.STACK_BASE, codec.STACK_SIZE)

    keys = [
        b"kb?A68D+tl?2@KL_",
        b"abc\x80" + bytes(range(1, 13)),
        b"\x80" + bytes(range(1, 16)),
        bytes(range(1, 33)),
    ]
    for key in keys:
        emulator.mem_write(codec.OBJECT_BASE, b"\x00" * codec.OBJECT_SIZE)
        emulator.mem_write(codec.INPUT_BASE, key)
        emulator.mem_write(codec.OBJECT_BASE + 0x1081, key)
        emulator.mem_write(codec.OBJECT_BASE + 0x10BA, struct.pack("<H", len(key)))
        codec.call(emulator, KEY_SCHEDULE, [codec.OBJECT_BASE], 5_000_000)
        parray, sboxes = signed.expand_key(key, True)
        expected = (struct.pack("<18I", *parray)
                    + struct.pack("<1024I", *(value for box in sboxes for value in box)))
        actual = bytes(emulator.mem_read(codec.OBJECT_BASE, len(expected)))
        if actual != expected:
            mismatch = next((i for i, (a, b) in enumerate(zip(actual, expected)) if a != b), None)
            raise RuntimeError(f"schedule mismatch for {key.hex()}: offset={mismatch}")
        print(f"PASS key={key.hex()} sha256={hashlib.sha256(actual).hexdigest()}")
    print(f"PASS emulated E2E schedules match signed model for {len(keys)} keys")


if __name__ == "__main__":
    main()
