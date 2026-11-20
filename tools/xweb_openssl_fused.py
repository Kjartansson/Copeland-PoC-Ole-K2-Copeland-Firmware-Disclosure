#!/usr/bin/env python3
"""Fused OpenCL EVP_BytesToKey-SHA256/AES-256-CBC XWEB probe."""

import argparse
import ctypes
import gzip
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

import xweb_openssl_probe as openssl_probe

ROOT = openssl_probe.ROOT
MAX_PASSWORD = 512
CL_DEVICE_TYPE_GPU = 1 << 2
CL_MEM_READ_ONLY = 1 << 2
CL_MEM_WRITE_ONLY = 1 << 1
CL_TRUE = 1


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
        for name in ("clReleaseMemObject", "clReleaseKernel", "clReleaseProgram",
                     "clReleaseCommandQueue", "clReleaseContext"):
            function = getattr(lib, name)
            function.argtypes = [pointer]

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
        plaintexts = ([bytes(plaintext_array[index*16:index*16+16]) for index in range(count)]
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


def read_target(path):
    with open(path, "rb") as handle:
        header = handle.read(32)
    if len(header) != 32 or not header.startswith(b"Salted__"):
        raise ValueError("target is not an OpenSSL Salted__ component")
    return header[8:16], header[16:32]


def self_test(engine):
    salt = bytes.fromhex("0011223344556677")
    plaintext = bytes.fromhex("1f8b0800000000000003") + b"fused OpenSSL known-answer test"
    expected_lines = subprocess.run([
        "openssl", "enc", "-aes-256-cbc", "-e", "-salt", "-md", "sha256",
        "-pass", "pass:test", "-S", salt.hex(), "-P",
    ], capture_output=True, check=True, text=True).stdout.splitlines()
    expected = dict(line.split("=", 1) for line in expected_lines)
    key_iv = openssl_probe.evp_bytes_to_key(b"test", salt, 48, hashlib.sha256)
    if expected["key"] != key_iv[:32].hex().upper() or expected["iv "] != key_iv[32:].hex().upper():
        raise RuntimeError("OpenSSL and Python EVP_BytesToKey outputs differ")
    encrypted = subprocess.run([
        "openssl", "enc", "-aes-256-cbc", "-e", "-salt", "-md", "sha256",
        "-pass", "pass:test", "-S", salt.hex(),
    ], input=plaintext, capture_output=True, check=True).stdout
    if encrypted.startswith(b"Salted__"):
        encrypted = encrypted[16:]
    ciphertext = encrypted[:16]
    words = [b"test", b"wrong", b"x", b"a" * 55, b"b" * 56, b"c" * 127, b"d" * 255]
    plaintexts, hits = engine.run(words, salt, ciphertext, return_plaintexts=True)
    for index, word in enumerate(words):
        key, iv = openssl_probe.derive(word, salt, "aes-256-cbc", "evp-sha256")
        cpu = openssl_probe.decrypt("aes-256-cbc", key, iv, ciphertext)
        if plaintexts[index] != cpu:
            raise RuntimeError(f"GPU/CPU mismatch at self-test index {index}: {plaintexts[index].hex()} != {cpu.hex()}")
    if hits != [1, 0, 0, 0, 0, 0, 0]:
        raise RuntimeError(f"unexpected GPU self-test magic results: {hits}")
    return {"openssl_key_iv_match": True, "gpu_cpu_first_blocks": len(words),
            "magic_hits": hits, "ciphertext_hex": ciphertext.hex()}


def load_words(path, limit):
    words = set()
    with open(path, "rb") as handle:
        for line in handle:
            word = line.rstrip(b"\r\n")
            if 0 < len(word) <= MAX_PASSWORD:
                words.add(word)
    words = sorted(words)
    return words[:limit] if limit else words


def full_validation(plaintext, magic):
    import zlib

    try:
        if magic == 1:
            gzip.decompress(plaintext)
            return "gzip-full-stream"
        if magic == 9:
            ET.fromstring(openssl_unpad(plaintext))
            return "xml-full-document"
        if magic == 8:
            return "elf-prefix-only"
        if magic in (2, 3) and len(plaintext) >= 96:
            return "squashfs-prefix-only"
        return "magic-only"
    except (OSError, EOFError, ET.ParseError, ValueError, zlib.error) as error:
        return f"rejected:{type(error).__name__}"


def openssl_unpad(data):
    if not data or len(data) % 16:
        raise ValueError("invalid CBC plaintext length")
    padding = data[-1]
    if not 1 <= padding <= 16 or data[-padding:] != bytes([padding]) * padding:
        raise ValueError("invalid PKCS7 padding")
    return data[:-padding]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--target")
    parser.add_argument("--words")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--chunk-size", type=int, default=16384)
    parser.add_argument("--json", default=os.path.join(ROOT, "results", "xweb-fused-opencl-probe.json"))
    args = parser.parse_args()
    if not args.self_test and not (args.target and args.words):
        parser.error("use --self-test or provide --target and --words")
    engine = OpenCL()
    try:
        engine.build(os.path.join(ROOT, "tools", "xweb_openssl_fused.cl"))
        kat = self_test(engine) if args.self_test else None
        if args.self_test and not args.target:
            print(json.dumps({"tool": os.path.basename(__file__), "self_test": kat, "hits": []}, indent=2))
            return
        salt, ciphertext = read_target(args.target)
        words = load_words(args.words, args.limit)
        result = {"tool": os.path.basename(__file__), "construction": "EVP_BytesToKey-SHA256 + AES-256-CBC",
                  "self_test": kat, "target": args.target, "salt_hex": salt.hex(),
                  "ciphertext_hex": ciphertext.hex(), "unique_words": len(words),
                  "operations": 0, "candidates": [], "validated_hits": []}
        started = time.time()
        for start in range(0, len(words), args.chunk_size):
            chunk = words[start:start + args.chunk_size]
            plaintexts, magics = engine.run(chunk, salt, ciphertext)
            result["operations"] += len(chunk)
            for index, magic in enumerate(magics):
                if not magic:
                    continue
                word = chunk[index]
                key, iv = openssl_probe.derive(word, salt, "aes-256-cbc", "evp-sha256")
                first_plaintext = openssl_probe.decrypt("aes-256-cbc", key, iv, ciphertext)
                candidate = {"password_hex": word.hex(), "magic": magic,
                             "first_plaintext_hex": first_plaintext.hex()}
                if not first_plaintext.startswith(openssl_probe.MAGICS + (b"<?xml", b"#!/", b"\x5a\xa5\xa5\x5a")):
                    raise RuntimeError("GPU candidate does not match CPU")
                with open(args.target, "rb") as handle:
                    encrypted = handle.read()[16:]
                plaintext = openssl_probe.decrypt("aes-256-cbc", key, iv, encrypted)
                candidate["validation"] = full_validation(plaintext, magic)
                candidate["plaintext_sha256"] = hashlib.sha256(plaintext).hexdigest()
                result["candidates"].append(candidate)
                if not candidate["validation"].startswith(("rejected", "magic-only")) and not candidate["validation"].endswith("prefix-only"):
                    result["validated_hits"].append(candidate)
                print("CANDIDATE", json.dumps(candidate), flush=True)
            print(f"progress {result['operations']}/{len(words)}", flush=True)
        result["elapsed_seconds"] = round(time.time() - started, 3)
        result["candidates_per_second"] = round(result["operations"] / result["elapsed_seconds"], 3) if result["elapsed_seconds"] else None
        with open(args.json, "w") as handle:
            json.dump(result, handle, indent=2)
            handle.write("\n")
        print(json.dumps(result, indent=2))
    finally:
        engine.close()


if __name__ == "__main__":
    main()
