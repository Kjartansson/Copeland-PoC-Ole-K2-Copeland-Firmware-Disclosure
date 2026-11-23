# E2E Crunch/CpcPackage full plaintext recovery (e2_fw-vxWorks.bin)

Date: 2026-11-23. Lane: Copeland code recovery, genuine E2E Crunch/CpcPackage path.
No password/oracle work involved; pure genuine-decoder emulation.

**Disclosure copy:** the recovered proprietary image, updater image, and raw
experiment outputs are not redistributed. Hashes and the two independent
harnesses are included for verification against the operator's official package.

## Result

Valid full plaintext image recovered from the genuine decoder path and
cross-validated by two independent emulators producing byte-identical output.

- Input stream: `extracted/E2E_4.11F03/e2_fw-vxWorks.bin` offset **6**,
  length **4,467,601** (0x442b91) = rest of file.
  Element prefix at offset 0: `70 00 b6 cf 11 00` (6 bytes; not part of stream).
- Stream header at offset 6: magic `5aa5a55a`, declared size
  **10,361,268** (0x9e19b4) at offset 10 (LE u32).
- Recovered plaintext: `results/crunch-runtime/e2_fw-vxWorks.decoded.bin`
  - size 10,361,268
  - SHA-256 `80204568f1ddfe8202f5781657c80c50766f1c2b1070c95c244a1392bf1c7c9f`
  - consumed exactly 4,467,601 / 4,467,601 input bytes
  - produced exactly 10,361,268 / 10,361,268 output bytes

## Decoder semantics (corrected; earlier harness was wrong)

Genuine wrapper `fcn.006470c0(input, insize, &outbuf, &outsize)` in
`extracted/E2E_4.11F03/SysUpdt.embedded.elf`:

1. `obj = operator new(0xef74)`; constructor `fcn.00649860` sets vtable
   0x7556a8 = {0x649900, 0x6498e0, 0x649920 (compress), 0x6499f0 (decompress)}.
2. `declared = fcn.00649790(obj, input)` — verifies magic, returns `*(input+4)`.
3. `outbuf = malloc(declared + 1)`.
4. `ret = obj->vtable[3](obj, input, insize, outbuf, 0)`.
   **arg5 = 0 selects magic-header mode**: the decoder verifies 0x5aa5a55a,
   skips the 8-byte header, reads the declared size from the stream, and
   decodes until the output end. Success iff `ret == declared`.

`tools/e2e_crunch_emulate.py` passed the declared size as arg5 (nonzero), which
selects the *headerless* mode and decodes the magic bytes themselves — the
"first chunk 17517/469" result and the block-137 garbage were artifacts of
that wrong mode, not stream structure.

## Boundary finding: genuine wrapper rejects this stream

The decoder core `fcn.0064bcd0` produced exactly `declared` bytes and consumed
exactly the whole input, then set error flag `obj+0x20`:

- Bit-reader helpers (0x64b3e0, 0x64b460) set `obj+0x20=1` on input underrun
  and feed zero bits.
- First underrun occurs at produced=10,361,248 (0x9e19a0), consumed=4,467,601
  (all input). The stream simply does not encode the final **20 bytes**
  (declared = encoded + 20).
- The last 20 output bytes (0x9e19a0..0x9e19b4) are emitted from
  zero-bit-fed symbols as five length-4 distance-1 matches echoing window byte
  0x94; they are **decoder padding, not stream-encoded plaintext**. The byte at
  0x9e199f (0x94) is still stream-encoded.
- `0x6499f0` then sets `obj+0x21=1` and returns -1; wrapper 0x6470c0 requires
  `ret == declared`, so the genuine wrapper would return failure (freeing the
  buffer) even though the first 10,361,248 bytes are the complete,
  bit-exact plaintext and the full 10,361,268-byte buffer is deterministic.

So the stream is *not* wrapper-clean: either the genuine update path decodes
this element through the streaming element-reader (0x6476c0/0x6477c0) with a
different completion check, or the vendor packer emitted a stream the strict
wrapper would reject. All load-relevant content is unaffected (see below).

## Cross-engine validation

- Unicorn harness: `build/crunch-runtime/wrapper_decode_unicorn.py`
  (function-level emulation of constructor + genuine vtable[3] call).
- Independent QEMU harness: `build/crunch-runtime/qemu_harness.c`
  (qemu-i386; maps the genuine image at 0x608000, hooks operator
  new/malloc/free to a bump allocator, calls the genuine wrapper 0x6470c0).
- Both report declared=0x9e19b4, produced=0x9e19b4, consumed=0x442b91,
  flags=0x0101, wrapper-reject — and byte-identical output
  (same SHA-256). Emulation bug vs genuine behavior is therefore settled:
  the rejection is genuine code behavior on this stream.

Commands:

    python3 build/crunch-runtime/wrapper_decode_unicorn.py \
        extracted/E2E_4.11F03/e2_fw-vxWorks.bin 6 4467601 OUT.bin
    gcc -m32 -nostdlib -static -fno-pic -no-pie -fno-stack-protector \
        -o build/crunch-runtime/qemu_harness build/crunch-runtime/qemu_harness.c
    qemu-i386 build/crunch-runtime/qemu_harness \
        build/crunch-runtime/vxworks-image.bin \
        extracted/E2E_4.11F03/e2_fw-vxWorks.bin OUT.bin

## Plaintext validation

- ELF32 EXEC i386, entry 0x608000, 3 LOAD segments covering file offsets
  0x1000..0x9e1865; entry code is a textbook VxWorks boot sequence
  (cli, CR0/CR4 setup, iret into 0x628afa).
- Section table: null / PROGBITS .text (0x608000, 0x91c28d) / NOBITS /
  PROGBITS .data (0xf25000) / NOBITS / PROGBITS build-vars / STRTAB —
  same toolchain layout as SysUpdt.embedded.elf.
- 59,448 strings, fully coherent: "Copyright 1984-2004 Wind River Systems",
  "GPC PENTIUM2", VxWorks boot lines (`ata:2(0,0)host:/ata00:2/system/vxworks`),
  `C:/code/E2ESoftware/Software/code/Source/...` paths. This is the complete
  E2E main VxWorks firmware image for the 4.11F03 update.
- Only questionable region: the final 20 bytes (0x9e19a0..0x9e19b4), decoder
  padding (0x94) inside the trailing shstrtab section-header tail — metadata
  beyond all LOAD segments, not used by any loader. Everything up to and
  including 0x9e199f is stream-encoded and engine-identical.
- No `SFUB` strings in the recovered image.

## Executable/updater knowledge gained

Yes: a complete, valid i386 VxWorks firmware executable for the E2E controller
(4.11F03), suitable for static analysis (Ghidra/rizin). It is E2E-related
code, not an E3/Site Supervisor artifact, and contains no SFUB references.

## Quarantine / notes

- `build/crunch-runtime/e2_fw-vxWorks.decoded-uncapped.bin`: experiment with a
  patched declared-size field (+0x100000); contains 20,098 bytes of
  zero-bit-underrun garbage past offset 0x9e19a0. Do not use as plaintext.
- Prior `results/failed-crunch/` artifacts remain quarantined; they came from
  the wrong (headerless) decode mode.
