#!/usr/bin/env python3
"""Offline known-plaintext cryptanalysis probe for Copeland SFUB_update payloads.

Scope and method (see analysis/CRYPTANALYSIS.md for the full report):

  * Established by analysis/CONTAINER-FORMAT.md: the 2.23F02/2.31F01 payloads
    show deterministic, equality-preserving behavior at aligned 8-byte
    granularity. This does not establish conventional ECB or identify the
    cipher and key, which remain unknown.
  * This probe tests a bounded, documented candidate space:
      ciphers  : DES, 2-key 3DES, 3-key 3DES, Blowfish, CAST5, IDEA
      keys     : vendor/product/container-derived ASCII words plus weak/generic
                 embedded defaults, each encoded as raw NUL/space-padded or
                 truncated, MD5/SHA-1/SHA-256 truncations, DES odd-parity
                 variants; plus binary specials (all-zero/all-FF/sequential,
                 DES weak+semi-weak keys, the six header field@0x20 values).
      targets  : the documented shared ciphertext blocks plus (with numpy)
                 every 8-byte block shared by >=2 of the six payloads.
      plaintexts: exact candidates (filesystem/executable magics, ASCII fill,
                 repeated patterns) and a generic "uniform single byte" test
                 (false-positive probability ~2^-56 per block).
  * Every cipher path is validated against published test vectors and, where
    OpenSSL supports the primitive, cross-checked against `openssl enc` before
    any negative result is trusted. The sweep is aborted if any KAT fails.
  * Both primitive directions are tested (dec and enc), covering devices whose
    "encrypt" path uses the cipher's decryption primitive.
  * On a hit, plaintext structure is validated across several blocks/files
    (terminal pad -> uniform fill, entropy collapse, strings/magic) before any
    decrypted payload is written to extracted/<product>_<version>/.

Read-only with respect to firmware/ and the rest of the repository. Writes only
results/crypt-* and (on a validated hit) extracted/<product>_<version>/.

Usage:
  sfub_crypt_probe.py [--skip-discover] [--kat-only]
                      [--json results/crypt-probe.json]
                      [--report results/crypt-probe.txt]
"""

import argparse
import hashlib
import json
import os
import string
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sfub_info  # noqa: E402  (open_sfub_stream)

try:
    import numpy as np
except ImportError:
    np = None

from cryptography.hazmat.primitives.ciphers import Cipher, modes
try:
    from cryptography.hazmat.decrepit.ciphers import algorithms as dec_alg
except ImportError:
    from cryptography.hazmat.primitives.ciphers import algorithms as dec_alg

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HEADER_SIZE = 0x210

PKGS = [
    ("SS", "2.23F02", "firmware/SS_2.23F02_Firmware_Update.pkg"),
    ("SS", "2.31F01", "firmware/SS_2.31F01_Firmware_Update.pkg"),
    ("SS", "2.34F01", "firmware/SS_2.34F01_Firmware_Update.pkg"),
    ("E3", "2.23F02", "firmware/E3_2.23F02_Display_Update.pkg"),
    ("E3", "2.31F01", "firmware/E3_2.31F01_Display_Update.pkg"),
    ("E3", "2.34F01", "firmware/E3_2.34F01_Display_Update.pkg"),
]

# Documented cross-file ciphertext blocks (analysis/CONTAINER-FORMAT.md section 2.1).
BASE_TARGETS = [
    ("terminal-pad(SS+E3 2.23F02/2.31F01)", "985aecbcb0d9ed8a"),
    ("shared-fill(all six files)", "49b9f8397062e325"),
    ("payload+0x00(SS 2.23F02/2.31F01)", "f3c288cb85b65922"),
    ("payload+0x10(all 2.23F02/2.31F01)", "a67094665b094a30"),
    ("payload+0x18(all 2.23F02/2.31F01)", "72bd0fc47621f2cf"),
    ("payload+0x38(all 2.23F02/2.31F01)", "539ab1e748bc7789"),
    ("payload+0x00(SS+E3 2.34F01)", "9a4d60069633674e"),
]

# Exact plaintext block candidates (label, 8 bytes). The generic uniform-byte
# test in the sweep covers all 256 single-byte fills (00, ff, space, aa, ...),
# so those are not enumerated here.
PLAINTEXT_CANDIDATES = [
    ("elf32-header", bytes.fromhex("7f454c4601010100")),
    ("elf64-header", bytes.fromhex("7f454c4602010100")),
    ("squashfs-le-v4", b"hsqs\x04\x00\x00\x00"),
    ("squashfs-be", b"sqsh\x00\x00\x04\x00"),
    ("ubi-ec-header", b"UBI#\x01\x00\x00\x00"),
    ("uimage-magic-pad", bytes.fromhex("27051956") + b"\x00" * 4),
    ("zip-local-v20", b"PK\x03\x04\x14\x00\x00\x00"),
    ("zip-local-v10", b"PK\x03\x04\x0a\x00\x00\x00"),
    ("gzip", bytes.fromhex("1f8b080000000000")),
    ("xz", bytes.fromhex("fd377a585a000000")),
    ("bzip2", b"BZh91AY&"),
    ("lzma-alone", bytes.fromhex("5d00008000000000")),
    ("zstd", bytes.fromhex("28b52ffd00000000")),
    ("android-boot", b"ANDROID!"),
    ("devicetree", bytes.fromhex("d00dfeed00000000")),
    ("sfub-prefix", b"SFUB_upd"),
    ("copeland", b"Copeland"),
    ("emerson", b"Emerson "),
    ("shell-bin", b"#!/bin/\x00"),
    ("xml", b"<?xml ve"),
    ("pem", b"-----BEG"),
    ("ascii-zeros", b"00000000"),
    ("ascii-ff-upper", b"FFFFFFFF"),
    ("ascii-ff-lower", b"ffffffff"),
    ("ascii-12345678", b"12345678"),
    ("ascii-underscores", b"________"),
    ("ascii-dots", b"........"),
    ("ascii-stars", b"********"),
    ("ascii-hashes", b"########"),
    ("deadbeef-be-x2", bytes.fromhex("deadbeef") * 2),
    ("deadbeef-le-x2", bytes.fromhex("efbeadde") * 2),
    ("12345678-be-x2", bytes.fromhex("12345678") * 2),
    ("12345678-le-x2", bytes.fromhex("78563412") * 2),
]

# Word phrases as tuples; separators {' ', '_', '-', ''} and case variants are
# applied to every multi-word phrase. Origin: vendor/org names (Copeland,
# formerly Emerson Climate Technologies), product names from the packages and
# manual (Site Supervisor, E3 Supervisory Control), container magic, version
# strings, controller brands in the same product family, and common weak
# embedded defaults.
PHRASES = [
    ("copeland",), ("emerson",), ("emerson", "electric"),
    ("emerson", "climate"), ("emerson", "climate", "technologies"),
    ("copeland", "lp"), ("copeland", "scroll"),
    ("climate", "technologies"), ("retail", "solutions"),
    ("emerson", "retail", "solutions"), ("copeland", "retail"),
    ("site", "supervisor",), ("supervisor",), ("supervisory",),
    ("supervisory", "control"), ("e3",), ("e3", "supervisory"),
    ("e3", "supervisory", "control"), ("e3", "controller"),
    ("e3", "display"), ("controller",), ("display",),
    ("copeland", "e3"), ("copeland", "ss"), ("emerson", "e3"),
    ("emerson", "site", "supervisor"), ("copeland", "site", "supervisor"),
    ("sfub",), ("sfub", "update"), ("sfubupdate",), ("sfub", "key"),
    ("sfub", "firmware"), ("update",), ("firmware",),
    ("firmware", "update"), ("display", "update"), ("pkg",),
    ("2.23f02",), ("2.31f01",), ("2.34f01",),
    ("223f02",), ("231f01",), ("234f01",), ("f02",), ("f01",),
    ("dixell",), ("xweb",), ("dixel",),
    ("e3", "firmware"), ("ss", "firmware"), ("site", "supervisor", "firmware"),
    ("12345678",), ("1234567890123456",), ("0123456789abcdef",),
    ("0123456789ABCDEF",), ("password",), ("passw0rd",), ("changeme",),
    ("default",), ("secret",), ("security",), ("letmein",), ("admin",),
    ("root",), ("master", "key"), ("masterkey",), ("key",), ("test",),
    ("debug",), ("copeland", "sfub"), ("emerson", "sfub"),
]

SEPARATORS = (" ", "_", "-", "")

DES_WEAK = ["0101010101010101", "fefefefefefefefe",
            "e0e0e0e0f1f1f1f1", "1f1f1f1f0e0e0e0e"]
DES_SEMIWEAK = ["01fe01fe01fe01fe", "fe01fe01fe01fe01",
                "1fe01fe00ef10ef1", "e01fe01ff10ef10e",
                "01e001e001f101f1", "e001e001f101f101",
                "1ffe1ffe0efe0efe", "fe1ffe1ffe0efe0e",
                "011f011f010e010e", "1f011f010e010e01",
                "e0fee0fef1fef1fe", "fee0fee0fef1fef1"]


# ---------------------------------------------------------------- primitives

def des_set_odd_parity(key):
    out = bytearray()
    for b in key:
        b &= 0xFE
        if bin(b).count("1") % 2 == 0:
            b |= 0x01
        out.append(b)
    return bytes(out)


def pad_nul(b, n):
    return (b + b"\x00" * n)[:n]


def pad_space(b, n):
    return (b + b" " * n)[:n]


# IDEA in pure Python: neither the installed OpenSSL 3.5 build nor the
# `cryptography` bindings linked against it provide IDEA, so it is implemented
# here and validated against published test vectors before use (see run_kats).

def _idea_mul(a, b):
    if a == 0:
        a = 65536
    if b == 0:
        b = 65536
    r = (a * b) % 65537
    return 0 if r == 65536 else r


def _idea_mulinv(a):
    r = pow(65536 if a == 0 else a, -1, 65537)
    return 0 if r == 65536 else r


def _idea_enc_subkeys(key):
    kb = int.from_bytes(key, "big")
    subs = []
    for _g in range(7):  # 52 = 6*8 + 4; extra rotations are sliced off
        for j in range(8):
            subs.append((kb >> (112 - 16 * j)) & 0xFFFF)
        kb = ((kb << 25) | (kb >> 103)) & ((1 << 128) - 1)
    return subs[:52]


def _idea_dec_subkeys(z):
    dk = [0] * 52
    dk[0] = _idea_mulinv(z[48])
    dk[1] = (-z[49]) & 0xFFFF
    dk[2] = (-z[50]) & 0xFFFF
    dk[3] = _idea_mulinv(z[51])
    dk[4] = z[46]
    dk[5] = z[47]
    for r in range(1, 8):
        base = 48 - 6 * r
        o = 6 * r
        dk[o] = _idea_mulinv(z[base])
        dk[o + 1] = (-z[base + 2]) & 0xFFFF
        dk[o + 2] = (-z[base + 1]) & 0xFFFF
        dk[o + 3] = _idea_mulinv(z[base + 3])
        dk[o + 4] = z[base - 2]
        dk[o + 5] = z[base - 1]
    dk[48] = _idea_mulinv(z[0])
    dk[49] = (-z[1]) & 0xFFFF
    dk[50] = (-z[2]) & 0xFFFF
    dk[51] = _idea_mulinv(z[3])
    return dk


def _idea_rounds(subs, block):
    x1, x2, x3, x4 = struct.unpack(">4H", block)
    p = 0
    for _r in range(8):
        x1 = _idea_mul(x1, subs[p])
        x2 = (x2 + subs[p + 1]) & 0xFFFF
        x3 = (x3 + subs[p + 2]) & 0xFFFF
        x4 = _idea_mul(x4, subs[p + 3])
        t0 = _idea_mul(x1 ^ x3, subs[p + 4])
        t1 = _idea_mul((t0 + (x2 ^ x4)) & 0xFFFF, subs[p + 5])
        t0 = (t0 + t1) & 0xFFFF
        x1 ^= t1
        x4 ^= t0
        x2, x3 = x3 ^ t1, x2 ^ t0
        p += 6
    y1 = _idea_mul(x1, subs[48])
    y2 = (x3 + subs[49]) & 0xFFFF
    y3 = (x2 + subs[50]) & 0xFFFF
    y4 = _idea_mul(x4, subs[51])
    return struct.pack(">4H", y1, y2, y3, y4)


def idea_crypt(key, data, op):
    subs = _idea_enc_subkeys(key) if op == "enc" else _idea_dec_subkeys(_idea_enc_subkeys(key))
    return b"".join(_idea_rounds(subs, data[i:i + 8]) for i in range(0, len(data), 8))


def make_cipher(name, key):
    if name == "des":
        # cryptography has no single-DES; 3DES-EDE with K1==K2==K3 is exactly DES.
        return Cipher(dec_alg.TripleDES(key * 3), modes.ECB())
    if name == "3des-2key":
        return Cipher(dec_alg.TripleDES(key), modes.ECB())
    if name == "3des-3key":
        return Cipher(dec_alg.TripleDES(key), modes.ECB())
    if name == "blowfish":
        return Cipher(dec_alg.Blowfish(key), modes.ECB())
    if name == "cast5":
        return Cipher(dec_alg.CAST5(key), modes.ECB())
    if name == "idea":
        return None  # handled by local idea_crypt()
    raise ValueError(name)


def ecb_crypt(name, key, data, op):
    if name == "idea":
        return idea_crypt(key, data, op)
    c = make_cipher(name, key)
    ctx = c.encryptor() if op == "enc" else c.decryptor()
    return ctx.update(data) + ctx.finalize()


def openssl_ecb(openssl_name, key, data):
    """Cross-check via `openssl enc`; None if the primitive is unavailable."""
    try:
        p = subprocess.run(
            ["openssl", "enc", "-" + openssl_name, "-K", key.hex(), "-nopad",
             "-provider", "legacy", "-provider", "default"],
            input=data, capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.stdout if p.returncode == 0 else None


# ---------------------------------------------------------------------- KATs

def run_kats(log):
    """Validate every cipher path before any sweep result is trusted."""
    results = []

    def rec(name, ok, detail):
        results.append({"name": name, "ok": bool(ok), "detail": detail})
        log.append(f"{'PASS' if ok else 'FAIL'}  {name}: {detail}")

    rec("plaintext candidates are 8-byte blocks", all(len(block) == 8 for _label, block in PLAINTEXT_CANDIDATES),
        f"{len(PLAINTEXT_CANDIDATES)} exact candidates")

    # DES, FIPS/textbook vector: key 0123456789ABCDEF, "Now is t" -> 3FA40E8A984D4815
    k = bytes.fromhex("0123456789ABCDEF")
    pt = b"Now is t"
    want = bytes.fromhex("3fa40e8a984d4815")
    got = ecb_crypt("des", k, pt, "enc")
    rec("des published vector", got == want, f"enc(0123456789ABCDEF,'Now is t')={got.hex()} want {want.hex()}")
    rec("des roundtrip", ecb_crypt("des", k, got, "dec") == pt, "dec(enc(pt))==pt")
    ossl = openssl_ecb("des-ecb", k, pt)
    rec("des openssl cross-check", ossl is None or ossl == got,
        "openssl unavailable (skipped)" if ossl is None else f"openssl={ossl.hex()}")

    # DES parity helper sanity: preserves high 7 bits, yields odd popcount bytes.
    rk = bytes(range(1, 25))
    pk = des_set_odd_parity(rk)
    rec("des parity helper",
        all((a & 0xFE) == (b & 0xFE) and bin(b).count("1") % 2 == 1 for a, b in zip(rk, pk)),
        f"in={rk.hex()} out={pk.hex()}")

    # 3DES: internal consistency (K1=K2=K3 equals DES above) + openssl cross-check.
    k2 = bytes.fromhex("0123456789abcdeffedcba9876543210")
    k3 = bytes.fromhex("0123456789abcdeffedcba987654321089abcdef01234567")
    pt8 = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
    g2 = ecb_crypt("3des-2key", k2, pt8, "enc")
    g3 = ecb_crypt("3des-3key", k3, pt8, "enc")
    rec("3des-3key(k,k,k) == des(k)", ecb_crypt("3des-3key", k * 3, pt, "enc") == want,
        "EDE with equal subkeys reproduces the DES vector")
    o2 = openssl_ecb("des-ede-ecb", k2, pt8)
    o3 = openssl_ecb("des-ede3-ecb", k3, pt8)
    rec("3des-2key openssl cross-check", o2 is None or o2 == g2,
        "openssl unavailable (skipped)" if o2 is None else f"ours={g2.hex()} openssl={o2.hex()}")
    rec("3des-3key openssl cross-check", o3 is None or o3 == g3,
        "openssl unavailable (skipped)" if o3 is None else f"ours={g3.hex()} openssl={o3.hex()}")
    rec("3des roundtrips",
        ecb_crypt("3des-2key", k2, g2, "dec") == pt8 and ecb_crypt("3des-3key", k3, g3, "dec") == pt8,
        "dec(enc(pt))==pt for both keyings")

    # Blowfish, Schneier test vector: zero key / zero block -> 4EF997456198DD78
    z8 = b"\x00" * 8
    gb = ecb_crypt("blowfish", z8, z8, "enc")
    rec("blowfish published vector", gb == bytes.fromhex("4ef997456198dd78"),
        f"enc(0^64,0^64)={gb.hex()} want 4ef997456198dd78")
    bk = bytes.fromhex("0123456789abcdeffedcba9876543210")
    bp = bytes.fromhex("0123456789abcdef")
    ob = openssl_ecb("bf-ecb", bk, bp)
    rec("blowfish openssl cross-check", ob is None or ob == ecb_crypt("blowfish", bk, bp, "enc"),
        "openssl unavailable (skipped)" if ob is None else f"ours={ecb_crypt('blowfish', bk, bp, 'enc').hex()} openssl={ob.hex()}")

    # CAST5 (CAST-128), RFC 2144 appendix B 128-bit vector.
    ck = bytes.fromhex("0123456712345678234567893456789a")
    cp = bytes.fromhex("0123456789abcdef")
    cw = bytes.fromhex("238b4fe5847e44b2")
    gc = ecb_crypt("cast5", ck, cp, "enc")
    rec("cast5 RFC2144 vector", gc == cw, f"enc(...)={gc.hex()} want {cw.hex()}")
    oc = openssl_ecb("cast5-ecb", ck, cp)
    rec("cast5 openssl cross-check", oc is None or oc == gc,
        "openssl unavailable (skipped)" if oc is None else f"ours={gc.hex()} openssl={oc.hex()}")

    # IDEA, standard MediaCrypt/crypto++ test vector (local implementation;
    # installed OpenSSL/cryptography provide no IDEA to cross-check against).
    ik = bytes.fromhex("00010002000300040005000600070008")
    ip = bytes.fromhex("0000000100020003")
    iw = bytes.fromhex("11fbed2b01986de5")
    gi = ecb_crypt("idea", ik, ip, "enc")
    rec("idea published vector (local impl)", gi == iw, f"enc(...)={gi.hex()} want {iw.hex()}")
    rec("idea decrypt of published vector (local impl)", ecb_crypt("idea", ik, iw, "dec") == ip,
        f"dec({iw.hex()})={ecb_crypt('idea', ik, iw, 'dec').hex()} want {ip.hex()}")
    rt_ok = True
    for i in range(8):
        tk = hashlib.sha256(b"idea-kat-key-%d" % i).digest()[:16]
        tp = hashlib.sha256(b"idea-kat-pt-%d" % i).digest()[:16]
        if ecb_crypt("idea", tk, ecb_crypt("idea", tk, tp, "enc"), "dec") != tp:
            rt_ok = False
    rec("idea roundtrips (8 random key/pt pairs)", rt_ok, "dec(enc(pt))==pt")

    return results


# ----------------------------------------------------------------- key space

def word_variants():
    out = set()
    for phrase in PHRASES:
        for sep in SEPARATORS:
            joined = [sep.join(w.lower() for w in phrase)]
            if len(phrase) > 1:
                joined.append(sep.join(w.capitalize() for w in phrase))
            for j in joined:
                out.add(j)
                out.add(j.upper())
    return sorted(out)


def key_candidates(field20_hexes, words=None):
    """Yield (cipher, key, provenance) for the whole documented candidate space."""
    words = word_variants() if words is None else words
    md5 = {w: hashlib.md5(w.encode()).digest() for w in words}
    sha1 = {w: hashlib.sha1(w.encode()).digest() for w in words}
    sha256 = {w: hashlib.sha256(w.encode()).digest() for w in words}

    def emit():
        for w in words:
            b = w.encode()
            prov = f"word={w!r}"
            # DES (8-byte keys)
            yield "des", pad_nul(b, 8), prov + ", raw NUL-pad/trunc-8"
            yield "des", pad_space(b, 8), prov + ", raw space-pad/trunc-8"
            yield "des", md5[w][:8], prov + ", md5[:8]"
            yield "des", sha1[w][:8], prov + ", sha1[:8]"
            yield "des", sha256[w][:8], prov + ", sha256[:8]"
            # 2-key 3DES (16-byte keys)
            yield "3des-2key", pad_nul(b, 16), prov + ", raw NUL-pad/trunc-16"
            yield "3des-2key", md5[w], prov + ", md5"
            yield "3des-2key", sha1[w][:16], prov + ", sha1[:16]"
            yield "3des-2key", sha256[w][:16], prov + ", sha256[:16]"
            # 3-key 3DES (24-byte keys)
            yield "3des-3key", pad_nul(b, 24), prov + ", raw NUL-pad/trunc-24"
            yield "3des-3key", sha256[w][:24], prov + ", sha256[:24]"
            yield "3des-3key", md5[w] + sha1[w][:8], prov + ", md5+sha1[:8]"
            yield "3des-3key", sha1[w] + md5[w][:4], prov + ", sha1+md5[:4]"
            # Blowfish (4..56-byte keys)
            if 4 <= len(b) <= 56:
                yield "blowfish", b, prov + ", raw ascii"
            yield "blowfish", pad_nul(b, 16), prov + ", raw NUL-pad/trunc-16"
            yield "blowfish", pad_nul(b, 32), prov + ", raw NUL-pad/trunc-32"
            yield "blowfish", md5[w], prov + ", md5"
            yield "blowfish", sha1[w], prov + ", sha1"
            yield "blowfish", sha256[w], prov + ", sha256"
            # CAST5 (5..16-byte keys; RFC 2144 zero-extends shorter keys)
            if 5 <= len(b) <= 16:
                yield "cast5", b, prov + ", raw ascii"
            yield "cast5", pad_nul(b, 16), prov + ", raw NUL-pad/trunc-16"
            yield "cast5", md5[w], prov + ", md5"
            yield "cast5", sha1[w][:16], prov + ", sha1[:16]"
            yield "cast5", sha256[w][:16], prov + ", sha256[:16]"
            # IDEA (16-byte keys)
            yield "idea", pad_nul(b, 16), prov + ", raw NUL-pad/trunc-16"
            yield "idea", md5[w], prov + ", md5"
            yield "idea", sha1[w][:16], prov + ", sha1[:16]"
            yield "idea", sha256[w][:16], prov + ", sha256[:16]"

        specials = [
            ("binary zeros-8", b"\x00" * 8), ("binary zeros-16", b"\x00" * 16),
            ("binary zeros-24", b"\x00" * 24), ("binary ff-8", b"\xff" * 8),
            ("binary ff-16", b"\xff" * 16), ("binary ff-24", b"\xff" * 24),
            ("binary seq-8", bytes(range(8))), ("binary seq-16", bytes(range(16))),
            ("binary 0123456789abcdef", bytes.fromhex("0123456789abcdef")),
            ("binary 0123..4567(24)", bytes.fromhex("0123456789abcdeffedcba987654321089abcdef01234567")),
            ("binary a5a5..-8", b"\xa5" * 8), ("binary a5a5..-16", b"\xa5" * 16),
        ]
        for hx in DES_WEAK:
            specials.append(("des weak key " + hx, bytes.fromhex(hx)))
        for hx in DES_SEMIWEAK:
            specials.append(("des semi-weak key " + hx, bytes.fromhex(hx)))
        for label, hx in field20_hexes:
            v = bytes.fromhex(hx)
            specials.append((f"header field@0x20 of {label}", v))
        for prov, v in specials:
            if len(v) >= 8:
                yield "des", v[:8], prov + "[:8]"
            if len(v) == 8:
                yield "des", v, prov
            if len(v) >= 16:
                yield "3des-2key", v[:16], prov + "[:16]"
                yield "cast5", v[:16], prov + "[:16]"
                yield "idea", v[:16], prov + "[:16]"
                yield "blowfish", v[:16], prov + "[:16]"
            if len(v) >= 24:
                yield "3des-3key", v[:24], prov + "[:24]"
            if 4 <= len(v) <= 56:
                yield "blowfish", v, prov

    # dedupe identical (cipher, key) pairs, keeping first provenance
    seen = set()
    out = []
    for cipher, key, prov in emit():
        tag = (cipher, key)
        if tag in seen:
            continue
        seen.add(tag)
        out.append((cipher, key, prov))
        if cipher in ("des", "3des-2key", "3des-3key"):
            pk = des_set_odd_parity(key)
            if (cipher, pk) not in seen:
                seen.add((cipher, pk))
                out.append((cipher, pk, prov + ", odd-parity-adjusted"))
    return out


# ------------------------------------------------------------- file handling

def read_header(path):
    stream, _size, _info = sfub_info.open_sfub_stream(path)
    try:
        return stream.read(HEADER_SIZE)
    finally:
        stream.close()


def read_payload(path):
    stream, _size, _info = sfub_info.open_sfub_stream(path)
    try:
        hdr = stream.read(HEADER_SIZE)
        declared = struct.unpack_from("<I", hdr, 0x34)[0]
        chunks = []
        left = declared
        while left > 0:
            c = stream.read(min(left, 8 << 20))
            if not c:
                break
            chunks.append(c)
            left -= len(c)
        return b"".join(chunks)
    finally:
        stream.close()


def discover_shared_blocks(log):
    """All 8-byte blocks shared by >=2 of the six payloads (numpy fast path)."""
    uniques = []
    for product, ver, rel in PKGS:
        t0 = time.time()
        payload = read_payload(os.path.join(ROOT, rel))
        n = (len(payload) // 8) * 8
        arr = np.frombuffer(payload[:n], dtype=np.uint64)
        u = np.unique(arr)
        uniques.append(u)
        log.append(f"  {product} {ver}: {len(payload)} bytes payload, "
                   f"{n // 8} blocks, {len(u)} unique "
                   f"({time.time() - t0:.1f}s)")
        del payload, arr
    all_values, counts = np.unique(np.concatenate(uniques), return_counts=True)
    shared_all = all_values[counts == len(PKGS)]
    shared_pair = all_values[counts >= 2]
    fmt = lambda v: int(v).to_bytes(8, sys.byteorder).hex()
    return {
        "shared_by_all_six": [fmt(v) for v in shared_all.tolist()],
        "shared_by_at_least_two": [fmt(v) for v in shared_pair.tolist()],
        "unique_blocks_per_file": {f"{p} {v}": int(len(uniques[i])) for i, (p, v, _r) in enumerate(PKGS)},
    }


# -------------------------------------------------------------------- sweep

def classify_plaintext(pt, exact_map):
    if pt in exact_map:
        return "exact:" + exact_map[pt]
    if pt == pt[:1] * 8:
        return f"uniform-fill:0x{pt[0]:02x}"
    return None


def sweep(keys, targets, log):
    exact_map = {pt: label for label, pt in PLAINTEXT_CANDIDATES}
    blob = b"".join(t for _label, t in targets)
    labels = [label for label, _t in targets]
    hits = []
    ops = 0
    t0 = time.time()
    for i, (cipher, key, prov) in enumerate(keys):
        if i and i % 2000 == 0:
            log.append(f"  sweep progress: {i}/{len(keys)} keys, {time.time() - t0:.1f}s")
        for op in ("dec", "enc"):
            out = ecb_crypt(cipher, key, blob, op)
            ops += 1
            for j in range(len(targets)):
                pt = out[j * 8:j * 8 + 8]
                cls = classify_plaintext(pt, exact_map)
                if cls:
                    hits.append({
                        "cipher": cipher, "key_hex": key.hex(), "provenance": prov,
                        "direction": op, "target": labels[j],
                        "target_hex": targets[j][1].hex(),
                        "plaintext_hex": pt.hex(), "class": cls,
                    })
                    log.append(f"  HIT: {hits[-1]}")
    return hits, ops, time.time() - t0


# ------------------------------------------------- hit verification/decrypt

def verify_and_decrypt(hit, log):
    """Validate plaintext structure across several blocks/files before writing
    anything to extracted/. Returns list of written paths."""
    cipher = hit["cipher"]
    key = bytes.fromhex(hit["key_hex"])
    written = []
    for product, ver, rel in PKGS:
        path = os.path.join(ROOT, rel)
        payload = read_payload(path)
        nblocks = len(payload) // 8
        sample_idx = sorted(set(
            list(range(0, min(512, nblocks)))
            + [nblocks // 4, nblocks // 2, (3 * nblocks) // 4]
            + list(range(max(0, nblocks - 512), nblocks))))
        sample = b"".join(payload[i * 8:i * 8 + 8] for i in sample_idx)
        dec = ecb_crypt(cipher, key, sample, "dec")
        printable = sum(1 for b in dec if b in b"\t\n\r" or 0x20 <= b < 0x7F)
        zeros = dec.count(0)
        uniform_tail = False
        if hit["target"].startswith("terminal-pad"):
            tail = b"".join(payload[i * 8:i * 8 + 8] for i in range(nblocks - 64, nblocks))
            dt = ecb_crypt(cipher, key, tail, "dec")
            uniform_tail = len(set(dt)) <= 2
        log.append(f"  verify {product} {ver}: sampled {len(sample)} bytes decrypted, "
                   f"printable={printable / len(dec):.2%}, zero-bytes={zeros / len(dec):.2%}, "
                   f"uniform-decrypted-tail={uniform_tail}")
        plausible = uniform_tail or printable / len(dec) > 0.35 or zeros / len(dec) > 0.10
        if not plausible:
            log.append(f"  verify {product} {ver}: NOT plausible plaintext, skipping write")
            continue
        outdir = os.path.join(ROOT, "extracted", f"{product}_{ver}")
        os.makedirs(outdir, exist_ok=True)
        out = os.path.join(outdir, f"payload-decrypted-{cipher}-{key.hex()[:12]}.bin")
        if os.path.exists(out):
            log.append(f"  refusing to overwrite {out}")
            continue
        dec_full = ecb_crypt(cipher, key, payload[:nblocks * 8], "dec")
        with open(out, "wb") as fh:
            fh.write(dec_full)
            if len(payload) % 8:
                fh.write(payload[nblocks * 8:])
        written.append(out)
        log.append(f"  wrote {out} ({nblocks * 8} decrypted bytes"
                   f"{', +' + str(len(payload) % 8) + ' raw tail bytes' if len(payload) % 8 else ''})")
    return written


# --------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--skip-discover", action="store_true",
                    help="skip numpy cross-file shared-block discovery")
    ap.add_argument("--kat-only", action="store_true", help="run only the known-answer tests")
    ap.add_argument("--expanded", action="store_true",
                    help="use factory defaults and expanded words from sfub_hashcat_probe")
    ap.add_argument("--json", default=os.path.join(ROOT, "results", "crypt-probe.json"))
    ap.add_argument("--report", default=os.path.join(ROOT, "results", "crypt-probe.txt"))
    ap.add_argument("--kat-log", default=os.path.join(ROOT, "results", "crypt-kat.txt"))
    ap.add_argument("--wordlist", default=os.path.join(ROOT, "results", "crypt-wordlist.txt"))
    args = ap.parse_args()

    log = []
    t_start = time.time()
    log.append(f"sfub_crypt_probe run at {time.strftime('%Y-%m-%d %H:%M:%S %z')}")

    kat_results = run_kats(log)
    kat_fail = [k for k in kat_results if not k["ok"]]
    os.makedirs(os.path.dirname(args.kat_log), exist_ok=True)
    with open(args.kat_log, "w") as fh:
        fh.write("\n".join(log) + "\n")
    if kat_fail:
        log.append(f"ABORT: {len(kat_fail)} known-answer test(s) failed; "
                   "cipher implementations not trustworthy, sweep not run.")
        print("\n".join(log))
        sys.exit(2)
    log.append(f"all {len(kat_results)} known-answer/cross-checks passed (unavailable "
               "openssl primitives are PASS-by-skip only when the published vector passed)")
    if args.kat_only:
        print("\n".join(log))
        return

    # per-file header field@0x20 values as key candidates
    field20 = []
    for product, ver, rel in PKGS:
        hdr = read_header(os.path.join(ROOT, rel))
        field20.append((f"{product} {ver}", hdr[0x20:0x30].hex()))

    if args.expanded:
        import sfub_hashcat_probe as gpu
        words = gpu.expanded_words()
    else:
        words = word_variants()
    with open(args.wordlist, "w") as fh:
        fh.write("\n".join(words) + "\n")
    keys = key_candidates(field20, words)
    per_cipher = {}
    for c, _k, _p in keys:
        per_cipher[c] = per_cipher.get(c, 0) + 1
    log.append(f"wordlist: {len(words)} unique strings -> {len(keys)} (cipher,key) candidates")
    log.append(f"per-cipher key counts: {per_cipher}")

    targets = [(label, bytes.fromhex(hx)) for label, hx in BASE_TARGETS]
    discovery = None
    if args.skip_discover or np is None:
        log.append("shared-block discovery skipped "
                   + ("(numpy unavailable)" if np is None else "(--skip-discover)"))
    else:
        log.append("shared-block discovery over all six payloads:")
        discovery = discover_shared_blocks(log)
        for hx in discovery["shared_by_at_least_two"]:
            b = bytes.fromhex(hx)
            if all(b != t for _l, t in targets):
                targets.append((f"shared>=2:{hx}", b))
        log.append(f"  blocks shared by all six: {len(discovery['shared_by_all_six'])}")
        log.append(f"  blocks shared by >=2 files: {len(discovery['shared_by_at_least_two'])}")
    log.append(f"sweep targets: {len(targets)} ciphertext blocks x 2 directions")

    hits, ops, sweep_s = sweep(keys, targets, log)
    log.append(f"sweep done: {len(keys)} keys x {len(targets)} targets x 2 directions "
               f"= {ops * len(targets)} block operations in {sweep_s:.1f}s; hits={len(hits)}")

    written = []
    if hits:
        best = hits[0]
        log.append(f"verifying hit {best['cipher']}/{best['key_hex']} ({best['provenance']})")
        written = verify_and_decrypt(best, log)
        if not written:
            log.append("hit did NOT survive plaintext-structure validation; treated as false positive")
    else:
        log.append("no key in the documented candidate space reproduces any shared/fill block")

    result = {
        "tool": os.path.basename(__file__),
        "runtime_seconds": round(time.time() - t_start, 2),
        "kat": kat_results,
        "wordlist_size": len(words),
        "key_candidates_total": len(keys),
        "key_candidates_per_cipher": per_cipher,
        "plaintext_candidates": [label for label, _p in PLAINTEXT_CANDIDATES]
        + ["<any uniform single byte x8>"],
        "base_targets": [label for label, _t in BASE_TARGETS],
        "discovery": discovery,
        "targets_total": len(targets),
        "block_operations": ops * len(targets),
        "hits": hits,
        "validated_decryptions_written": written,
    }
    with open(args.json, "w") as fh:
        json.dump(result, fh, indent=2)
        fh.write("\n")
    with open(args.report, "w") as fh:
        fh.write("\n".join(log) + "\n")
    with open(args.kat_log, "w") as fh:
        fh.write("\n".join(l for l in log if l.startswith(("PASS", "FAIL"))) + "\n")
    print("\n".join(log))


if __name__ == "__main__":
    main()
