#!/usr/bin/env python3
"""Broad first-block oracle for XWEB OpenSSL Salted__ components.

Construction: EVP_BytesToKey-SHA256 + AES-256-CBC (openssl enc -md sha256).
The GPU kernel returns the first plaintext block for every candidate
(return_plaintexts=True); this driver performs broad first-block
recognition in Python (JSON/text/XML, tar semantics, xz/zstd/bzip2/lz4/
lzma, uImage/DTB/SQLite/UBIFS and more) and then applies strict
full-stream validation (PKCS7 unpad + format parse / CRC / integrity
checks) so random-key false positives are rejected.

Self-contained: pure-Python AES fallback when the `cryptography`
package is unavailable, so it runs identically on the compute worker.
"""

import argparse
import bz2
import ctypes
import gzip
import hashlib
import io
import json
import lzma
import os
import random
import sqlite3
import struct
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
KERNEL = os.path.join(HERE, "xweb_broad_oracle.cl")
MAX_PASSWORD = 512
CL_DEVICE_TYPE_GPU = 1 << 2
CL_MEM_READ_ONLY = 1 << 2
CL_MEM_WRITE_ONLY = 1 << 1
CL_TRUE = 1

# ---------------------------------------------------------------------------
# Pure-Python AES-256 (decrypt + encrypt), used as an independent CPU path.
# ---------------------------------------------------------------------------

_SBOX = []
_INV_SBOX = []


def _build_tables():
    p = q = 1
    sbox = [0] * 256
    while True:
        p = p ^ ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        xformed = q ^ ((q << 1) | (q >> 7)) ^ ((q << 2) | (q >> 6)) \
            ^ ((q << 3) | (q >> 5)) ^ ((q << 4) | (q >> 4))
        sbox[p] = (xformed ^ 0x63) & 0xFF
        if p == 1:
            break
    sbox[0] = 0x63
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return sbox, inv


_SBOX, _INV_SBOX = _build_tables()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
         0x6C, 0xD8, 0xAB, 0x4D]


def _gmul(a, b):
    r = 0
    for _ in range(8):
        if b & 1:
            r ^= a
        a = ((a << 1) ^ (0x1B if a & 0x80 else 0)) & 0xFF
        b >>= 1
    return r


def _expand_key(key):
    words = [list(key[i:i + 4]) for i in range(0, 32, 4)]
    for i in range(8, 60):
        temp = list(words[i - 1])
        if i % 8 == 0:
            temp = [_SBOX[temp[1]] ^ _RCON[i // 8 - 1], _SBOX[temp[2]],
                    _SBOX[temp[3]], _SBOX[temp[0]]]
        elif i % 8 == 4:
            temp = [_SBOX[b] for b in temp]
        words.append([words[i - 8][j] ^ temp[j] for j in range(4)])
    return [sum(words[4 * r:4 * r + 4], []) for r in range(15)]


def _state(block):
    return [[block[4 * c + r] for c in range(4)] for r in range(4)]


def _unstate(s):
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _add_round_key(s, rk):
    for c in range(4):
        for r in range(4):
            s[r][c] ^= rk[4 * c + r]


def _inv_shift_sub(s):
    for r in range(4):
        s[r] = [_INV_SBOX[s[r][(c - r) % 4]] for c in range(4)]


def _shift_sub(s):
    for r in range(4):
        s[r] = [_SBOX[s[r][(c + r) % 4]] for c in range(4)]


def _mix_columns(s, inv):
    table = (14, 11, 13, 9) if inv else (2, 3, 1, 1)
    for c in range(4):
        col = [s[r][c] for r in range(4)]
        for r in range(4):
            coeffs = table[-r:] + table[:-r] if inv else table[r:] + table[:r]
            s[r][c] = 0
            for k in range(4):
                s[r][c] ^= _gmul(col[k], coeffs[k])


def aes256_decrypt_block(key, block):
    rks = _expand_key(key)
    s = _state(block)
    _add_round_key(s, rks[14])
    for rnd in range(13, 0, -1):
        _inv_shift_sub(s)
        _add_round_key(s, rks[rnd])
        _mix_columns(s, inv=True)
    _inv_shift_sub(s)
    _add_round_key(s, rks[0])
    return _unstate(s)


def aes256_encrypt_block(key, block):
    rks = _expand_key(key)
    s = _state(block)
    _add_round_key(s, rks[0])
    for rnd in range(1, 14):
        _shift_sub(s)
        _mix_columns(s, inv=False)
        _add_round_key(s, rks[rnd])
    _shift_sub(s)
    _add_round_key(s, rks[14])
    return _unstate(s)


def aes256_cbc_decrypt(key, iv, data):
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = data[off:off + 16]
        dec = aes256_decrypt_block(key, block)
        out += bytes(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)


def aes256_cbc_encrypt(key, iv, data):
    out = bytearray()
    prev = iv
    for off in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[off:off + 16], prev))
        enc = aes256_encrypt_block(key, block)
        out += enc
        prev = enc
    return bytes(out)


def evp_bytes_to_key(password, salt, length, digest=hashlib.sha256):
    output = b""
    previous = b""
    while len(output) < length:
        previous = digest(previous + password + salt).digest()
        output += previous
    return output[:length]


def derive(password, salt):
    material = evp_bytes_to_key(password, salt, 48)
    return material[:32], material[32:48]


try:
    from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher
    from cryptography.hazmat.primitives.ciphers import algorithms as _algorithms
    from cryptography.hazmat.primitives.ciphers import modes as _modes
except ImportError:
    _Cipher = None


def cpu_decrypt(password, salt, ciphertext):
    """Full-stream decrypt; fast `cryptography` path with a pure-Python
    fallback so the oracle runs identically without third-party packages."""
    key, iv = derive(password, salt)
    if _Cipher is not None:
        context = _Cipher(_algorithms.AES(key), _modes.CBC(iv)).decryptor()
        return context.update(ciphertext) + context.finalize()
    return aes256_cbc_decrypt(key, iv, ciphertext)


# ---------------------------------------------------------------------------
# OpenCL wrapper (same protocol as tools/xweb_openssl_fused.py).
# ---------------------------------------------------------------------------

class OpenCL:
    def __init__(self):
        self.lib = ctypes.CDLL("libOpenCL.so.1")
        self._signatures()
        self.context = None
        self.queue = None
        self.program = None
        self.kernel = None
        self.buffers = []
        self._select_device()

    def _signatures(self):
        lib = self.lib
        pointer = ctypes.c_void_p
        uint = ctypes.c_uint
        size = ctypes.c_size_t
        lib.clGetPlatformIDs.argtypes = [uint, pointer, ctypes.POINTER(uint)]
        lib.clGetDeviceIDs.argtypes = [pointer, ctypes.c_ulong, uint, pointer, ctypes.POINTER(uint)]
        lib.clCreateContext.argtypes = [pointer, uint, pointer, pointer, pointer, ctypes.POINTER(ctypes.c_int)]
        lib.clCreateContext.restype = pointer
        lib.clCreateCommandQueue.argtypes = [pointer, pointer, ctypes.c_ulong, ctypes.POINTER(ctypes.c_int)]
        lib.clCreateCommandQueue.restype = pointer
        lib.clCreateProgramWithSource.argtypes = [pointer, uint, ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(size), ctypes.POINTER(ctypes.c_int)]
        lib.clCreateProgramWithSource.restype = pointer
        lib.clBuildProgram.argtypes = [pointer, uint, pointer, ctypes.c_char_p, pointer, pointer]
        lib.clGetProgramBuildInfo.argtypes = [pointer, pointer, uint, size, pointer, ctypes.POINTER(size)]
        lib.clCreateKernel.argtypes = [pointer, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
        lib.clCreateKernel.restype = pointer
        lib.clCreateBuffer.argtypes = [pointer, ctypes.c_ulong, size, pointer, ctypes.POINTER(ctypes.c_int)]
        lib.clCreateBuffer.restype = pointer
        lib.clSetKernelArg.argtypes = [pointer, uint, size, pointer]
        lib.clEnqueueWriteBuffer.argtypes = [pointer, pointer, uint, size, size, pointer, uint, pointer, pointer]
        lib.clEnqueueReadBuffer.argtypes = [pointer, pointer, uint, size, size, pointer, uint, pointer, pointer]
        lib.clEnqueueNDRangeKernel.argtypes = [pointer, pointer, uint, pointer, ctypes.POINTER(size), ctypes.POINTER(size), uint, pointer, pointer]
        lib.clFinish.argtypes = [pointer]
        lib.clGetDeviceInfo.argtypes = [pointer, uint, size, pointer, ctypes.POINTER(size)]
        for name in ("clReleaseMemObject", "clReleaseKernel", "clReleaseProgram",
                     "clReleaseCommandQueue", "clReleaseContext"):
            getattr(lib, name).argtypes = [pointer]

    def check(self, status, operation):
        if status != 0:
            raise RuntimeError(f"{operation} failed with OpenCL status {status}")

    def _select_device(self):
        count = ctypes.c_uint()
        self.check(self.lib.clGetPlatformIDs(0, None, ctypes.byref(count)), "clGetPlatformIDs count")
        platforms = (ctypes.c_void_p * count.value)()
        self.check(self.lib.clGetPlatformIDs(count, platforms, None), "clGetPlatformIDs")
        self.device = None
        for platform in platforms:
            device_count = ctypes.c_uint()
            status = self.lib.clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, 0, None, ctypes.byref(device_count))
            if status != 0 or not device_count.value:
                continue
            devices = (ctypes.c_void_p * device_count.value)()
            self.check(self.lib.clGetDeviceIDs(platform, CL_DEVICE_TYPE_GPU, device_count, devices, None), "clGetDeviceIDs")
            self.device = ctypes.c_void_p(devices[0])
            break
        if self.device is None:
            raise RuntimeError("no OpenCL GPU device found")
        status = ctypes.c_int()
        self.context = self.lib.clCreateContext(None, 1, ctypes.byref(self.device), None, None, ctypes.byref(status))
        self.check(status.value, "clCreateContext")
        self.queue = self.lib.clCreateCommandQueue(self.context, self.device, 0, ctypes.byref(status))
        self.check(status.value, "clCreateCommandQueue")

    def device_name(self):
        size = ctypes.c_size_t()
        self.lib.clGetDeviceInfo(self.device, 0x102B, 0, None, ctypes.byref(size))
        buffer = ctypes.create_string_buffer(size.value)
        self.lib.clGetDeviceInfo(self.device, 0x102B, size, buffer, None)
        return buffer.value.decode(errors="replace")

    def build(self, source_path):
        with open(source_path, "rb") as handle:
            source = handle.read()
        status = ctypes.c_int()
        source_pointer = ctypes.c_char_p(source)
        source_length = ctypes.c_size_t(len(source))
        self.program = self.lib.clCreateProgramWithSource(
            self.context, 1, ctypes.byref(source_pointer), ctypes.byref(source_length), ctypes.byref(status))
        self.check(status.value, "clCreateProgramWithSource")
        status_value = self.lib.clBuildProgram(self.program, 1, ctypes.byref(self.device), b"-cl-std=CL1.2", None, None)
        if status_value != 0:
            size = ctypes.c_size_t()
            self.lib.clGetProgramBuildInfo(self.program, self.device, 0x1183, 0, None, ctypes.byref(size))
            log = ctypes.create_string_buffer(size.value)
            self.lib.clGetProgramBuildInfo(self.program, self.device, 0x1183, size, log, None)
            raise RuntimeError(f"clBuildProgram failed {status_value}:\n{log.value.decode(errors='replace')}")
        self.kernel = self.lib.clCreateKernel(self.program, b"fused_probe", ctypes.byref(status))
        self.check(status.value, "clCreateKernel")

    def buffer(self, size, flags):
        status = ctypes.c_int()
        result = self.lib.clCreateBuffer(self.context, flags, size, None, ctypes.byref(status))
        self.check(status.value, "clCreateBuffer")
        self.buffers.append(result)
        return result

    def set_arg(self, index, buffer):
        value = ctypes.c_void_p(buffer)
        self.check(self.lib.clSetKernelArg(self.kernel, index, ctypes.sizeof(value), ctypes.byref(value)),
                   f"clSetKernelArg {index}")

    def run(self, words, salt, ciphertext, return_plaintexts=False):
        count = len(words)
        if not count:
            return [], []
        packed = bytearray(count * MAX_PASSWORD)
        lengths = (ctypes.c_uint * count)()
        for index, word in enumerate(words):
            if not 0 < len(word) <= MAX_PASSWORD:
                raise ValueError(f"unsupported password length {len(word)}")
            packed[index * MAX_PASSWORD:index * MAX_PASSWORD + len(word)] = word
            lengths[index] = len(word)
        packed_array = (ctypes.c_ubyte * len(packed)).from_buffer(packed)
        salt_array = (ctypes.c_ubyte * 8).from_buffer_copy(salt)
        cipher_array = (ctypes.c_ubyte * 16).from_buffer_copy(ciphertext)
        plaintext_array = (ctypes.c_ubyte * (count * 16))() if return_plaintexts else None
        hits_array = (ctypes.c_uint * count)()
        buffers = [
            self.buffer(len(packed), CL_MEM_READ_ONLY),
            self.buffer(ctypes.sizeof(lengths), CL_MEM_READ_ONLY),
            self.buffer(8, CL_MEM_READ_ONLY),
            self.buffer(16, CL_MEM_READ_ONLY),
            self.buffer(count * 16, CL_MEM_WRITE_ONLY),
            self.buffer(count * 4, CL_MEM_WRITE_ONLY),
        ]
        host_arrays = [packed_array, lengths, salt_array, cipher_array]
        for index in range(4):
            self.check(self.lib.clEnqueueWriteBuffer(
                self.queue, buffers[index], CL_TRUE, 0, ctypes.sizeof(host_arrays[index]),
                host_arrays[index], 0, None, None), f"clEnqueueWriteBuffer {index}")
        for index, buffer in enumerate(buffers):
            self.set_arg(index, buffer)
        global_size = ctypes.c_size_t(count)
        self.check(self.lib.clEnqueueNDRangeKernel(
            self.queue, self.kernel, 1, None, ctypes.byref(global_size), None, 0, None, None),
            "clEnqueueNDRangeKernel")
        if return_plaintexts:
            self.check(self.lib.clEnqueueReadBuffer(
                self.queue, buffers[4], CL_TRUE, 0, ctypes.sizeof(plaintext_array), plaintext_array, 0, None, None),
                "read plaintexts")
        self.check(self.lib.clEnqueueReadBuffer(
            self.queue, buffers[5], CL_TRUE, 0, ctypes.sizeof(hits_array), hits_array, 0, None, None),
            "read hits")
        self.check(self.lib.clFinish(self.queue), "clFinish")
        for buffer in buffers:
            self.lib.clReleaseMemObject(buffer)
            self.buffers.remove(buffer)
        plaintexts = ([bytes(plaintext_array[index * 16:index * 16 + 16]) for index in range(count)]
                      if return_plaintexts else None)
        return plaintexts, list(hits_array)

    def close(self):
        for buffer in self.buffers:
            self.lib.clReleaseMemObject(buffer)
        self.buffers.clear()
        for value, release in ((self.kernel, self.lib.clReleaseKernel),
                               (self.program, self.lib.clReleaseProgram),
                               (self.queue, self.lib.clReleaseCommandQueue),
                               (self.context, self.lib.clReleaseContext)):
            if value:
                release(value)


# ---------------------------------------------------------------------------
# Broad first-block classification.
# ---------------------------------------------------------------------------

def _is_printable_ascii(block):
    return all(b in (9, 10, 13) or 32 <= b < 127 for b in block)


def classify_first_block(p):
    """Return a prioritized list of candidate formats for this first block."""
    formats = []
    if p[:3] == b"\x1f\x8b\x08":
        formats.append("gzip")
    if p[:6] == b"\xfd7zXZ\x00":
        formats.append("xz")
    if p[:4] == b"\x28\xb5\x2f\xfd":
        formats.append("zstd")
    if p[:3] == b"BZh" and p[3:4] in b"123456789":
        formats.append("bzip2")
    if p[:4] == b"\x04\x22\x4d\x18":
        formats.append("lz4")
    if p[0] == 0x5D and p[1] == 0 and p[2] == 0:
        formats.append("lzma")
    if p[:4] == b"PK\x03\x04":
        formats.append("zip")
    if p[:4] == b"\x7fELF":
        formats.append("elf")
    if p[:6] in (b"070701", b"070702"):
        formats.append("cpio")
    if p[:4] in (b"hsqs", b"sqsh"):
        formats.append("squashfs")
    if p[:4] == b"UBI#":
        formats.append("ubi-ec")
    if p[:4] == b"\x31\x18\x10\x06":
        formats.append("ubifs")
    if p[:4] == b"\x27\x05\x19\x56":
        formats.append("uimage")
    if p[:4] == b"\xd0\x0d\xfe\xed":
        formats.append("dtb")
    if p[:16] == b"SQLite format 3\x00":
        formats.append("sqlite")
    if p[:5] == b"<?xml" or (p[:1] == b"<" and p[1:2].isalpha()):
        formats.append("xml")
    stripped = p.lstrip(b" \t\r\n")
    if stripped[:1] in (b"{", b"["):
        formats.append("json")
    if p[:3] == b"#!/":
        formats.append("shebang")
    if _is_printable_ascii(p):
        formats.append("text")
    elif all(b == 0 or 32 <= b < 127 for b in p) and any(32 <= b < 127 for b in p):
        # A tar header opens with a NUL-padded ASCII path name; the ustar
        # magic sits at offset 257 and is proven by full-stream validation.
        formats.append("tar")
    return formats


# ---------------------------------------------------------------------------
# Strict full-stream validation.  Every path starts from PKCS7-unpadded
# plaintext; acceptance requires the whole stream to parse or carry a
# format-level CRC/integrity proof.
# ---------------------------------------------------------------------------

class Unverifiable(Exception):
    pass


def openssl_unpad(data):
    if not data or len(data) % 16:
        raise ValueError("invalid CBC plaintext length")
    padding = data[-1]
    if not 1 <= padding <= 16 or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("invalid PKCS7 padding")
    return data[:-padding]


def _validate_gzip(data):
    raw = gzip.decompress(data)
    return f"gzip-full-stream inflated={len(raw)}"


def _validate_xz(data):
    raw = lzma.decompress(data, format=lzma.FORMAT_XZ)
    return f"xz-full-stream inflated={len(raw)}"


def _validate_lzma(data):
    raw = lzma.decompress(data, format=lzma.FORMAT_ALONE)
    return f"lzma-full-stream inflated={len(raw)}"


def _validate_bzip2(data):
    raw = bz2.decompress(data)
    return f"bzip2-full-stream inflated={len(raw)}"


def _validate_zstd(data):
    try:
        from compression import zstd
    except ImportError:
        try:
            import zstandard as zstd_mod
        except ImportError:
            raise Unverifiable("no zstd module")
        dctx = zstd_mod.ZstdDecompressor()
        raw = dctx.stream_reader(io.BytesIO(data)).read()
        return f"zstd-full-stream inflated={len(raw)}"
    raw = zstd.decompress(data)
    return f"zstd-full-stream inflated={len(raw)}"


def _validate_lz4(data):
    try:
        import lz4.frame
    except ImportError:
        raise Unverifiable("no lz4 module")
    raw = lz4.frame.decompress(data)
    return f"lz4-full-stream inflated={len(raw)}"


def _validate_zip(data):
    import zipfile
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        bad = archive.testzip()
        if bad is not None:
            raise ValueError(f"corrupt member {bad}")
        return f"zip-full-archive members={len(archive.namelist())}"


def _validate_tar(data):
    if len(data) < 512 or data[257:262] != b"ustar":
        raise ValueError("no ustar magic at offset 257")
    if data[:512] == bytes(512):
        raise ValueError("null first header")
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
        members = archive.getmembers()
    return f"tar-ustar members={len(members)}"


def _validate_json(data):
    text = data.decode("utf-8", "strict").strip()
    if not text:
        raise ValueError("empty json")
    parsed = json.loads(text)
    return f"json-document type={type(parsed).__name__}"


def _validate_xml(data):
    root = ET.fromstring(data.decode("utf-8", "strict"))
    return f"xml-document root={root.tag}"


def _validate_sqlite(data):
    if len(data) < 100 or data[:16] != b"SQLite format 3\x00":
        raise ValueError("bad sqlite header")
    page_size = struct.unpack(">H", data[16:18])[0]
    page_size = 65536 if page_size == 1 else page_size
    if page_size < 512 or page_size & (page_size - 1):
        raise ValueError("bad sqlite page size")
    pages = struct.unpack(">I", data[28:32])[0]
    detail = f"sqlite page_size={page_size} pages={pages}"
    try:
        connection = sqlite3.connect(":memory:")
        connection.deserialize(data)
        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        connection.close()
        if integrity == "ok":
            return detail + " integrity=ok"
    except (sqlite3.DatabaseError, AttributeError):
        pass
    if pages and pages * page_size == len(data):
        return detail + " size-consistent"
    raise ValueError("sqlite structure not self-consistent")


def _validate_text(data):
    text = data.decode("utf-8", "strict")
    if len(text) < 4:
        raise ValueError("too short")
    for ch in text:
        if not (ch.isprintable() or ch in "\t\n\r"):
            raise ValueError("non-printable character")
    return f"text-utf8-printable chars={len(text)}"


def _validate_shebang(data):
    if not data.startswith(b"#!/") or b"\n" not in data:
        raise ValueError("bad shebang")
    return "shebang-" + _validate_text(data)


def _validate_elf(data):
    if len(data) < 52 or data[4] not in (1, 2) or data[5] not in (1, 2) or data[6] != 1:
        raise ValueError("bad e_ident")
    order = "<" if data[5] == 1 else ">"
    e_type = struct.unpack(order + "H", data[16:18])[0]
    machine = struct.unpack(order + "H", data[18:20])[0]
    if e_type not in (1, 2, 3, 4) or machine == 0:
        raise ValueError("bad elf type/machine")
    return f"elf-header class={data[4]} type={e_type} machine={machine}"


def _validate_dtb(data):
    if len(data) < 40:
        raise ValueError("short dtb")
    totalsize = struct.unpack(">I", data[4:8])[0]
    off_struct = struct.unpack(">I", data[8:12])[0]
    version = struct.unpack(">I", data[20:24])[0]
    if totalsize != len(data):
        raise ValueError(f"dtb totalsize {totalsize} != {len(data)}")
    if off_struct >= totalsize or version not in range(1, 25):
        raise ValueError("bad dtb offsets/version")
    return f"dtb-structural totalsize={totalsize} version={version}"


def _validate_uimage(data):
    if len(data) < 64:
        raise ValueError("short uimage")
    stored = struct.unpack(">I", data[4:8])[0]
    header = data[:4] + bytes(4) + data[8:64]
    if zlib.crc32(header) & 0xFFFFFFFF != stored:
        raise ValueError("uimage header crc mismatch")
    size = struct.unpack(">I", data[12:16])[0]
    return f"uimage-header-crc ok data_size={size}"


def _validate_ubi_ec(data):
    if len(data) < 64 or data[4] not in (1, 2):
        raise ValueError("bad ubi ec header")
    stored = struct.unpack(">I", data[60:64])[0]
    if zlib.crc32(data[:60]) & 0xFFFFFFFF != stored:
        raise ValueError("ubi ec crc mismatch")
    return f"ubi-ec-crc ok version={data[4]}"


def _validate_ubifs(data):
    if len(data) < 24:
        raise ValueError("short ubifs node")
    stored = struct.unpack("<I", data[4:8])[0]
    node_len = struct.unpack("<I", data[12:16])[0]
    if node_len < 24 or node_len > len(data):
        raise ValueError("bad ubifs node length")
    if zlib.crc32(data[8:node_len]) & 0xFFFFFFFF != stored:
        raise ValueError("ubifs node crc mismatch")
    return f"ubifs-node-crc ok node_type={data[16]} len={node_len}"


def _validate_cpio(data):
    offset = 0
    entries = 0
    while True:
        if data[offset:offset + 6] not in (b"070701", b"070702"):
            raise ValueError(f"bad cpio magic at {offset}")
        fields = [int(data[offset + 6 + 8 * i:offset + 14 + 8 * i], 16) for i in range(13)]
        namesize, filesize = fields[11], fields[6]
        if not 0 < namesize < 4096:
            raise ValueError("bad cpio namesize")
        name = data[offset + 110:offset + 110 + namesize - 1]
        if data[offset + 110 + namesize - 1] != 0:
            raise ValueError("cpio name not nul-terminated")
        offset += (110 + namesize + 3) & ~3
        offset += (filesize + 3) & ~3
        if offset > len(data):
            raise ValueError("cpio overruns data")
        if name == b"TRAILER!!!":
            return f"cpio-newc entries={entries}"
        entries += 1
        if entries > 100000:
            raise ValueError("cpio entry flood")


def _validate_squashfs(data):
    if len(data) < 96:
        raise ValueError("short squashfs")
    order = "<" if data[:4] == b"hsqs" else ">"
    s_bytes = struct.unpack(order + "Q", data[40:48])[0]
    if s_bytes != len(data):
        raise ValueError(f"squashfs s_bytes {s_bytes} != {len(data)}")
    return f"squashfs-size-consistent bytes={s_bytes}"


VALIDATORS = {
    "gzip": _validate_gzip,
    "xz": _validate_xz,
    "lzma": _validate_lzma,
    "bzip2": _validate_bzip2,
    "zstd": _validate_zstd,
    "lz4": _validate_lz4,
    "zip": _validate_zip,
    "tar": _validate_tar,
    "json": _validate_json,
    "xml": _validate_xml,
    "sqlite": _validate_sqlite,
    "text": _validate_text,
    "shebang": _validate_shebang,
    "elf": _validate_elf,
    "dtb": _validate_dtb,
    "uimage": _validate_uimage,
    "ubi-ec": _validate_ubi_ec,
    "ubifs": _validate_ubifs,
    "cpio": _validate_cpio,
    "squashfs": _validate_squashfs,
}


def strict_validate(padded_plaintext, formats):
    """Return (status, detail): status in accepted/rejected/unverifiable."""
    try:
        data = openssl_unpad(padded_plaintext)
    except ValueError as error:
        return "rejected", f"pkcs7:{error}"
    rejections = []
    for fmt in formats:
        validator = VALIDATORS[fmt]
        try:
            return "accepted", validator(data)
        except Unverifiable as note:
            return "unverifiable", f"{fmt}:{note}"
        except Exception as error:  # noqa: BLE001 - any parse failure is a rejection
            rejections.append(f"{fmt}:{type(error).__name__}")
    return "rejected", ";".join(rejections) or "no-format"


# ---------------------------------------------------------------------------
# Target loading.
# ---------------------------------------------------------------------------

def read_target(path):
    with open(path, "rb") as handle:
        blob = handle.read()
    if len(blob) < 32 or not blob.startswith(b"Salted__"):
        raise ValueError("target is not an OpenSSL Salted__ component")
    ciphertext = blob[16:]
    if len(ciphertext) % 16:
        raise ValueError("ciphertext is not block aligned")
    return blob[8:16], ciphertext


def load_words(path, limit):
    words = set()
    with open(path, "rb") as handle:
        for line in handle:
            word = line.rstrip(b"\r\n")
            if 0 < len(word) <= MAX_PASSWORD:
                words.add(word)
    words = sorted(words)
    return words[:limit] if limit else words


# ---------------------------------------------------------------------------
# Self-tests: OpenSSL KAT, GPU/CPU equivalence, synthetic positives per
# newly accepted format, and negative random/wrong-password controls.
# ---------------------------------------------------------------------------

def _openssl_encrypt(payload, password, salt):
    result = subprocess.run([
        "openssl", "enc", "-aes-256-cbc", "-e", "-salt", "-md", "sha256",
        "-pass", f"pass:{password}", "-S", salt.hex(),
    ], input=payload, capture_output=True, check=True)
    encrypted = result.stdout
    if encrypted.startswith(b"Salted__"):
        encrypted = encrypted[16:]
    return encrypted


def _synthetic_payloads():
    payloads = {}
    payloads["gzip"] = gzip.compress(b"broad-oracle gzip payload " * 8, mtime=0)
    payloads["xz"] = lzma.compress(b"broad-oracle xz payload " * 8, format=lzma.FORMAT_XZ)
    payloads["lzma"] = lzma.compress(b"broad-oracle lzma payload " * 8, format=lzma.FORMAT_ALONE)
    payloads["bzip2"] = bz2.compress(b"broad-oracle bzip2 payload " * 8)
    try:
        from compression import zstd
        payloads["zstd"] = zstd.compress(b"broad-oracle zstd payload " * 8)
    except ImportError:
        pass
    try:
        import lz4.frame
        payloads["lz4"] = lz4.frame.compress(b"broad-oracle lz4 payload " * 8)
    except ImportError:
        pass
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:") as archive:
        info = tarfile.TarInfo("hello.txt")
        body = b"broad-oracle tar payload\n"
        info.size = len(body)
        archive.addfile(info, io.BytesIO(body))
    payloads["tar"] = buffer.getvalue()
    payloads["json"] = json.dumps({"tool": "broad-oracle", "ok": True,
                                   "items": list(range(10))}).encode()
    payloads["xml"] = b'<?xml version="1.0"?><xweb><component name="test"/></xweb>'
    payloads["text"] = ("# broad-oracle synthetic manifest\n"
                        "component: xweb-pro\nversion: 1.3.0\n"
                        "0123456789 abcdef\n").encode()
    payloads["shebang"] = b"#!/bin/sh\necho broad-oracle\nexit 0\n"
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)")
    db.execute("INSERT INTO t(v) VALUES ('broad-oracle')")
    db.commit()
    payloads["sqlite"] = db.serialize()
    db.close()
    node = bytearray(64)
    struct.pack_into("<I", node, 0, 0x06101831)
    struct.pack_into("<Q", node, 8, 1)
    struct.pack_into("<I", node, 12, 64)
    node[16] = 6
    struct.pack_into("<I", node, 4, zlib.crc32(bytes(node[8:64])) & 0xFFFFFFFF)
    payloads["ubifs"] = bytes(node) + bytes(48)
    ec = bytearray(64)
    ec[:4] = b"UBI#"
    ec[4] = 1
    struct.pack_into(">Q", ec, 8, 7)
    struct.pack_into(">II", ec, 16, 64, 128)
    struct.pack_into(">I", ec, 60, zlib.crc32(bytes(ec[:60])) & 0xFFFFFFFF)
    payloads["ubi-ec"] = bytes(ec) + bytes(64)
    uh = bytearray(64)
    uh[:4] = b"\x27\x05\x19\x56"
    struct.pack_into(">7I", uh, 8, 0, 0, 32, 0x8000, 0x8000, 0, 0)
    uh[28:32] = bytes([2, 5, 7, 3])
    uh[32:60] = b"broad-oracle-uimage".ljust(28, b"\x00")
    struct.pack_into(">I", uh, 4, zlib.crc32(bytes(uh[:4]) + bytes(4) + bytes(uh[8:64])) & 0xFFFFFFFF)
    payloads["uimage"] = bytes(uh) + bytes(32)
    dtb = bytearray(64)
    dtb[:4] = b"\xd0\x0d\xfe\xed"
    struct.pack_into(">I", dtb, 4, 64)
    struct.pack_into(">I", dtb, 8, 40)
    struct.pack_into(">I", dtb, 20, 17)
    payloads["dtb"] = bytes(dtb)
    def _cpio_entry(name, body):
        fields = (1, 0o100644, 0, 0, 1, 0, len(body), 0, 0, 0, 0, len(name) + 1, 0)
        header = b"070701" + b"".join(f"{value:08x}".encode() for value in fields) + name + b"\x00"
        header += bytes((4 - len(header) % 4) % 4)
        return header + body + bytes((4 - len(body) % 4) % 4)

    payloads["cpio"] = _cpio_entry(b"a.txt", b"data") + _cpio_entry(b"TRAILER!!!", b"")
    elf = bytearray(64)
    elf[:4] = b"\x7fELF"
    elf[4:7] = bytes([2, 1, 1])
    struct.pack_into("<HHI", elf, 16, 3, 0x28, 1)
    payloads["elf"] = bytes(elf)
    sq = bytearray(112)
    sq[:4] = b"hsqs"
    struct.pack_into("<Q", sq, 40, 112)
    payloads["squashfs"] = bytes(sq)
    return payloads


def self_test(engine):
    report = {"openssl_kat": False, "gpu_cpu_blocks": 0, "positives": {},
              "negatives": {}, "openssl_cli": True}
    salt = bytes.fromhex("0011223344556677")
    probe_plaintext = bytes.fromhex("1f8b0800000000000003") + b"fused OpenSSL known-answer test"
    try:
        lines = subprocess.run([
            "openssl", "enc", "-aes-256-cbc", "-e", "-salt", "-md", "sha256",
            "-pass", "pass:test", "-S", salt.hex(), "-P",
        ], capture_output=True, check=True, text=True).stdout.splitlines()
        expected = dict(line.split("=", 1) for line in lines if "=" in line)
        key_iv = evp_bytes_to_key(b"test", salt, 48)
        if expected["key"].strip() != key_iv[:32].hex().upper() or \
                expected["iv "].strip() != key_iv[32:].hex().upper():
            raise RuntimeError("OpenSSL and Python EVP_BytesToKey outputs differ")
        report["openssl_kat"] = True
    except (OSError, subprocess.CalledProcessError, KeyError) as error:
        report["openssl_cli"] = False
        report["openssl_error"] = str(error)
    encrypted = _openssl_encrypt(probe_plaintext, "test", salt)
    words = [b"test", b"wrong", b"x", b"a" * 55, b"b" * 56, b"c" * 127, b"d" * 255]
    plaintexts, hits = engine.run(words, salt, encrypted[:16], return_plaintexts=True)
    for index, word in enumerate(words):
        cpu = cpu_decrypt(word, salt, encrypted[:16])
        if plaintexts[index] != cpu:
            raise RuntimeError(f"GPU/CPU mismatch at index {index}: "
                               f"{plaintexts[index].hex()} != {cpu.hex()}")
    if hits != [1, 0, 0, 0, 0, 0, 0]:
        raise RuntimeError(f"unexpected GPU magic results: {hits}")
    report["gpu_cpu_blocks"] = len(words)

    # Round-trip proof of the pure-Python CBC path against OpenSSL output,
    # plus agreement with the fast path when it is available.
    pure = aes256_cbc_decrypt(*derive(b"test", salt), encrypted)
    if pure[:len(probe_plaintext)] != probe_plaintext:
        raise RuntimeError("pure-Python AES-256-CBC round-trip failed")
    if cpu_decrypt(b"test", salt, encrypted) != pure:
        raise RuntimeError("fast and pure-Python AES-256-CBC paths disagree")
    report["pure_python_aes"] = True

    # Positive synthetic tests: each supported format must classify and
    # pass strict full-stream validation with the correct password.
    for fmt, payload in sorted(_synthetic_payloads().items()):
        target = _openssl_encrypt(payload, "synthetic", salt)
        blocks, _ = engine.run([b"synthetic"], salt, target[:16], return_plaintexts=True)
        formats = classify_first_block(blocks[0])
        status, detail = strict_validate(cpu_decrypt(b"synthetic", salt, target), formats)
        report["positives"][fmt] = {"formats": formats, "status": status, "detail": detail}
        if status != "accepted":
            raise RuntimeError(f"positive {fmt} failed: {formats} {status} {detail}")

    # Negative control 1: encrypted random garbage must never validate.
    rng = random.Random(20261123)
    bad = 0
    for trial in range(50):
        payload = bytes(rng.randrange(256) for _ in range(512))
        password = f"neg{trial}".encode()
        target = _openssl_encrypt(payload, password.decode(), salt)
        blocks, _ = engine.run([password], salt, target[:16], return_plaintexts=True)
        formats = classify_first_block(blocks[0])
        status, detail = strict_validate(cpu_decrypt(password, salt, target), formats)
        if status == "accepted":
            bad += 1
    report["negatives"]["random_payload_accepted"] = bad
    if bad:
        raise RuntimeError(f"{bad} random payloads falsely validated")

    # Negative control 2: wrong passwords against a JSON target must never
    # validate, even when a random first block passes the broad screen.
    json_target = _openssl_encrypt(b'{"manifest": "broad-oracle", "n": 1}', "right", salt)
    wrong = [f"wrong{i}".encode() for i in range(200)] + [b"right"]
    blocks, _ = engine.run(wrong, salt, json_target[:16], return_plaintexts=True)
    accepted_wrong = 0
    screened = 0
    for index, word in enumerate(wrong):
        formats = classify_first_block(blocks[index])
        if formats:
            screened += 1
        status, _ = strict_validate(cpu_decrypt(word, salt, json_target), formats)
        if status == "accepted" and word != b"right":
            accepted_wrong += 1
        if word == b"right" and status != "accepted":
            raise RuntimeError("correct password failed to validate JSON control")
    report["negatives"]["wrong_password_screened"] = screened
    report["negatives"]["wrong_password_accepted"] = accepted_wrong
    if accepted_wrong:
        raise RuntimeError(f"{accepted_wrong} wrong passwords falsely validated")
    return report


# ---------------------------------------------------------------------------
# Main driver.
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--target")
    parser.add_argument("--words")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--chunk-size", type=int, default=65536)
    parser.add_argument("--json", default=os.path.join(HERE, "broad-oracle-results.json"))
    args = parser.parse_args()
    if not args.self_test and not (args.target and args.words):
        parser.error("use --self-test or provide --target and --words")
    engine = OpenCL()
    try:
        engine.build(KERNEL)
        device = engine.device_name()
        kat = self_test(engine) if args.self_test else None
        if args.self_test and not args.target:
            print(json.dumps({"tool": os.path.basename(__file__), "device": device,
                              "self_test": kat, "validated_hits": []}, indent=2))
            return
        salt, ciphertext = read_target(args.target)
        words = load_words(args.words, args.limit)
        with open(args.target, "rb") as handle:
            target_sha256 = hashlib.sha256(handle.read()).hexdigest()
        result = {"tool": os.path.basename(__file__), "device": device,
                  "construction": "EVP_BytesToKey-SHA256 + AES-256-CBC",
                  "self_test": kat, "target": os.path.abspath(args.target),
                  "target_sha256": target_sha256, "salt_hex": salt.hex(),
                  "ciphertext_blocks": len(ciphertext) // 16,
                  "first_ciphertext_hex": ciphertext[:16].hex(),
                  "unique_words": len(words), "operations": 0,
                  "screened_candidates": 0, "candidates": [], "validated_hits": []}
        started = time.time()
        for start in range(0, len(words), args.chunk_size):
            chunk = words[start:start + args.chunk_size]
            plaintexts, _ = engine.run(chunk, salt, ciphertext[:16], return_plaintexts=True)
            result["operations"] += len(chunk)
            for index, block in enumerate(plaintexts):
                formats = classify_first_block(block)
                if not formats:
                    continue
                word = chunk[index]
                result["screened_candidates"] += 1
                full = cpu_decrypt(word, salt, ciphertext)
                status, detail = strict_validate(full, formats)
                candidate = {"password_hex": word.hex(), "formats": formats,
                             "first_plaintext_hex": block.hex(),
                             "validation": f"{status}:{detail}",
                             "plaintext_sha256": hashlib.sha256(full).hexdigest()}
                result["candidates"].append(candidate)
                if status == "accepted":
                    result["validated_hits"].append(candidate)
                print("CANDIDATE", json.dumps(candidate), flush=True)
            print(f"progress {result['operations']}/{len(words)} "
                  f"screened={result['screened_candidates']}", flush=True)
        result["elapsed_seconds"] = round(time.time() - started, 3)
        result["candidates_per_second"] = round(result["operations"] / result["elapsed_seconds"], 3) \
            if result["elapsed_seconds"] else None
        with open(args.json, "w") as handle:
            json.dump(result, handle, indent=2)
            handle.write("\n")
        print(json.dumps(result, indent=2))
    finally:
        engine.close()


if __name__ == "__main__":
    main()
