#!/usr/bin/env python3
"""Read-only structural analyzer for Copeland SFUB_update firmware containers.

Accepts a raw SFUB file or a ZIP-wrapped ".pkg" that contains exactly one SFUB
member. Never writes to the input, never extracts to disk, and never executes
any firmware code. All parsing is done with the Python standard library
(numpy, if installed, is used only to speed up byte histograms).

Observed container layout (see analysis/CONTAINER-FORMAT.md for evidence):

  0x000  16 bytes  magic "SFUB_update" (NUL padded)
  0x010  16 bytes  ASCII firmware version, e.g. "2.23F02" (NUL padded)
  0x020  16 bytes  unidentified per-file field (not md5/sha1[:16]/sha256[:16]
                    of the payload; possibly a hash of the plaintext payload,
                    a nonce, or key material - unknown)
  0x030   u32 LE   product-correlated field: 0x24 = Site Supervisor,
                    0x44 = E3 Display (observed correlation, 3 files each)
  0x034   u32 LE   declared payload size in bytes
  0x038   u32 LE   constant 1 in all observed files
  0x03C..0x20F     reserved, all zero in all observed files
  0x210            payload, high entropy (encrypted; see report)
  0x210+size       trailing data (present only in observed 2.34F01 files)

Usage:
  sfub_info.py [--json OUT.json] [--find HEXBYTES]... FILE [FILE...]
"""

import argparse
import collections
import hashlib
import json
import math
import os
import struct
import sys
import zipfile

try:
    import numpy as _np
except ImportError:
    _np = None

MAGIC = b"SFUB_update"
HEADER_SIZE = 0x210
CHUNK = 4 << 20
SAMPLE_LEN = 1 << 20
FULL_HISTOGRAM_LIMIT = 64 << 20  # stdlib fallback histograms above this are sampled


def open_sfub_stream(path):
    """Return (stream, size, container_info). Caller must close the stream."""
    with open(path, "rb") as probe:
        head = probe.read(4)
    if head == b"PK\x03\x04":
        zf = zipfile.ZipFile(path)
        members = [i for i in zf.infolist() if not i.is_dir()]
        if len(members) != 1:
            zf.close()
            raise ValueError(f"{path}: ZIP with {len(members)} members, expected exactly 1")
        info = members[0]
        stream = zf.open(info, "r")
        return stream, info.file_size, {
            "outer": "zip",
            "member_name": info.filename,
            "member_size": info.file_size,
            "member_compressed_size": info.compress_size,
            "member_compress_type": info.compress_type,
            "member_date": "%04d-%02d-%02d %02d:%02d:%02d" % info.date_time,
            "member_crc32": "%08x" % info.CRC,
        }
    return open(path, "rb"), os.path.getsize(path), {"outer": "raw"}


def shannon_entropy(counts, total):
    if total == 0:
        return None
    h = 0.0
    for c in counts:
        if c:
            p = c / total
            h -= p * math.log2(p)
    return h


def chi2_uniform(counts, total):
    if total == 0:
        return None
    e = total / 256.0
    return sum((c - e) ** 2 / e for c in counts)


class RegionStats:
    """Streaming byte histogram; numpy when available, else exact only for
    small regions (large regions fall back to three samples)."""

    def __init__(self, total_len, sample_offsets):
        self.total_len = total_len
        self.counts = [0] * 256
        self.exact = _np is not None or total_len <= FULL_HISTOGRAM_LIMIT
        self.sampled_bytes = 0
        self.sample_offsets = sorted(sample_offsets)  # absolute region-relative starts
        self.sample_counts = [0] * 256
        self._sample_spans = [(o, o + SAMPLE_LEN) for o in self.sample_offsets]

    def feed(self, region_off, data):
        if self.exact:
            if _np is not None:
                b = _np.bincount(_np.frombuffer(data, dtype=_np.uint8), minlength=256)
                for i, v in enumerate(b):
                    if v:
                        self.counts[i] += int(v)
            else:
                for b, n in collections.Counter(data).items():
                    self.counts[b] += n
        else:
            for s, e in self._sample_spans:
                lo = max(s, region_off)
                hi = min(e, region_off + len(data))
                if lo < hi:
                    piece = data[lo - region_off:hi - region_off]
                    for b, n in collections.Counter(piece).items():
                        self.sample_counts[b] += n
                    self.sampled_bytes += len(piece)

    def report(self):
        if self.exact:
            return {
                "method": "exact-numpy" if _np is not None else "exact",
                "bytes": self.total_len,
                "entropy_bits_per_byte": round(shannon_entropy(self.counts, self.total_len), 6),
                "chi2_uniform_df255": round(chi2_uniform(self.counts, self.total_len), 2),
            }
        return {
            "method": "sampled (3 x 1 MiB: start/middle/end)",
            "bytes_sampled": self.sampled_bytes,
            "entropy_bits_per_byte": round(shannon_entropy(self.sample_counts, self.sampled_bytes), 6),
            "chi2_uniform_df255": round(chi2_uniform(self.sample_counts, self.sampled_bytes), 2),
        }


def dup_block_counts(sample, block):
    c = collections.Counter(sample[i:i + block] for i in range(0, len(sample) - block + 1, block))
    dups = {k: v for k, v in c.items() if v > 1}
    return {
        "block_size": block,
        "distinct_repeated_blocks": len(dups),
        "repeated_block_occurrences": sum(dups.values()),
        "top": [{"hex": k.hex(), "count": v} for k, v in
                sorted(dups.items(), key=lambda kv: (-kv[1], kv[0]))[:8]],
    }


def analyze(path, find_patterns):
    stream, size, container = open_sfub_stream(path)
    try:
        whole_sha256 = hashlib.sha256()
        pay_md5 = hashlib.md5()
        pay_sha1 = hashlib.sha1()
        pay_sha256 = hashlib.sha256()

        header = b""
        pos = 0
        payload_stats = None
        trailing_stats = None
        payload_first = b""
        tail_buf = b""
        samples = {"start": b"", "middle": b"", "end": b""}
        run_prev = None
        run_cur = None
        run_len = 0
        runs = collections.Counter()
        run_max = collections.Counter()
        block_buf = b""
        find_hits = {p.hex(): [] for p in find_patterns}
        declared = None

        while True:
            chunk = stream.read(CHUNK)
            if not chunk:
                break
            whole_sha256.update(chunk)
            chunk_start = pos
            pos += len(chunk)

            if len(header) < HEADER_SIZE:
                need = HEADER_SIZE - len(header)
                header += chunk[:need]

            if len(header) >= HEADER_SIZE and declared is None:
                declared = struct.unpack_from("<I", header, 0x34)[0]
                pay_span = (HEADER_SIZE, HEADER_SIZE + declared)
                mid = (pay_span[0] + pay_span[1]) // 2 - SAMPLE_LEN // 2
                mid -= (mid - HEADER_SIZE) % 8
                end_start = pay_span[1] - SAMPLE_LEN
                end_start -= (end_start - HEADER_SIZE) % 8
                offs = [HEADER_SIZE, max(HEADER_SIZE, mid), max(HEADER_SIZE, end_start)]
                payload_stats = RegionStats(declared, [o - HEADER_SIZE for o in offs])
                trailing_stats = RegionStats(size - pay_span[1], [0]) if size > pay_span[1] else None
                sample_windows = {"start": offs[0], "middle": offs[1], "end": offs[2]}

            pay_lo = HEADER_SIZE
            pay_hi = HEADER_SIZE + declared

            # payload portion of this chunk
            lo = max(pay_lo, chunk_start)
            hi = min(pay_hi, chunk_start + len(chunk))
            if lo < hi:
                piece = chunk[lo - chunk_start:hi - chunk_start]
                pay_md5.update(piece)
                pay_sha1.update(piece)
                pay_sha256.update(piece)
                payload_stats.feed(lo - pay_lo, piece)
                if len(payload_first) < 64:
                    payload_first += piece[:64 - len(payload_first)]
                tail_buf = (tail_buf + piece)[-4096:]
                for name, off in sample_windows.items():
                    s_lo = max(off, lo)
                    s_hi = min(off + SAMPLE_LEN, hi)
                    if s_lo < s_hi:
                        samples[name] += chunk[s_lo - chunk_start:s_hi - chunk_start]
                # 8-byte consecutive run detection (offset-anchored to payload start)
                data = block_buf + piece
                base = lo - pay_lo - len(block_buf)
                n8 = (len(data) // 8) * 8
                for i in range(0, n8, 8):
                    b = data[i:i + 8]
                    if b == run_cur:
                        run_len += 1
                    else:
                        if run_len >= 2:
                            runs[run_cur] += 1
                            if run_len > run_max[run_cur]:
                                run_max[run_cur] = run_len
                        run_cur = b
                        run_len = 1
                block_buf = data[n8:]

            # trailing portion
            t_lo = max(pay_hi, chunk_start)
            t_hi = chunk_start + len(chunk)
            if trailing_stats is not None and t_lo < t_hi:
                trailing_stats.feed(t_lo - pay_hi, chunk[t_lo - chunk_start:t_hi - chunk_start])

            # pattern search across chunk boundary
            if find_patterns:
                search = chunk  # boundary overlap handled by re-scanning with 16-byte prefix
                pref_start = max(0, chunk_start - 16)
                if chunk_start > 0:
                    # re-read prefix from previous chunk is not possible; keep small overlap buffer
                    pass
                data = (getattr(analyze, "_ovl", b"") + chunk)
                ovl_base = chunk_start - len(getattr(analyze, "_ovl", b""))
                for p in find_patterns:
                    i = data.find(p)
                    while i >= 0:
                        abspos = ovl_base + i
                        if abspos >= chunk_start or chunk_start == 0:
                            if not find_hits[p.hex()] or find_hits[p.hex()][-1] != abspos:
                                find_hits[p.hex()].append(abspos)
                        i = data.find(p, i + 1)
                analyze._ovl = chunk[-16:]
    finally:
        stream.close()

    if hasattr(analyze, "_ovl"):
        del analyze._ovl

    magic = header[0x00:0x10].rstrip(b"\0")
    version = header[0x10:0x20].rstrip(b"\0")
    field_0x20 = header[0x20:0x30]
    u32_0x30, u32_0x34, u32_0x38 = struct.unpack_from("<III", header, 0x30)
    reserved_ok = len(header) == HEADER_SIZE and not any(header[0x3C:HEADER_SIZE])
    trailing_size = size - (HEADER_SIZE + u32_0x34)

    terminal_pad = None
    if run_len >= 2 and run_cur is not None:
        terminal_pad = {
            "block_hex": run_cur.hex(),
            "blocks": run_len,
            "bytes": run_len * 8,
            "run_start_payload_offset": u32_0x34 - run_len * 8,
        }

    payload = {
        "offset": HEADER_SIZE,
        "declared_size": u32_0x34,
        "end_offset": HEADER_SIZE + u32_0x34,
        "size_mod_8": u32_0x34 % 8,
        "size_mod_16": u32_0x34 % 16,
        "first64_hex": payload_first.hex(),
        "last64_hex": tail_buf[-64:].hex(),
        "md5": pay_md5.hexdigest(),
        "sha1": pay_sha1.hexdigest(),
        "sha256": pay_sha256.hexdigest(),
        "field_0x20_matches_md5": pay_md5.digest() == field_0x20,
        "field_0x20_matches_sha1_first16": pay_sha1.digest()[:16] == field_0x20,
        "field_0x20_matches_sha256_first16": pay_sha256.digest()[:16] == field_0x20,
        "histogram": payload_stats.report(),
        "consecutive_8byte_runs": {
            "distinct_blocks": len(runs),
            "top": [{"hex": b.hex(), "runs": runs[b], "max_run_blocks": run_max[b]}
                    for b, _ in runs.most_common(8)],
        },
        "terminal_padding_run": terminal_pad,
        "samples": {
            name: {
                "payload_offset": sample_windows[name] - HEADER_SIZE,
                "length": len(samples[name]),
                "dup8": dup_block_counts(samples[name], 8),
                "dup16": dup_block_counts(samples[name], 16),
            }
            for name in ("start", "middle", "end")
        },
    }

    result = {
        "input": path,
        "container": container,
        "sfub_size": size,
        "sfub_sha256": whole_sha256.hexdigest(),
        "header": {
            "size": HEADER_SIZE,
            "magic": magic.decode("ascii", "replace"),
            "magic_ok": magic == MAGIC.rstrip(b"\0"),
            "version": version.decode("ascii", "replace"),
            "field_0x20_hex": field_0x20.hex(),
            "u32_0x30": u32_0x30,
            "u32_0x30_hex": "0x%08x" % u32_0x30,
            "u32_0x34_payload_size": u32_0x34,
            "u32_0x38": u32_0x38,
            "reserved_0x3c_0x20f_all_zero": reserved_ok,
        },
        "payload": payload,
        "trailing": None,
        "find_hits": {k: {"count": len(v), "offsets_hex": [hex(o) for o in v[:64]]}
                      for k, v in find_hits.items()},
    }
    if trailing_size > 0:
        result["trailing"] = {
            "offset": HEADER_SIZE + u32_0x34,
            "size": trailing_size,
            "size_mod_8": trailing_size % 8,
            "histogram": trailing_stats.report(),
        }
    return result


def text_report(r):
    out = []
    a = out.append
    c = r["container"]
    a(f"input:          {r['input']}")
    if c["outer"] == "zip":
        a(f"container:      ZIP member {c['member_name']} "
          f"({c['member_size']} bytes, deflate {c['member_compressed_size']} bytes, "
          f"date {c['member_date']}, crc32 {c['member_crc32']})")
    else:
        a("container:      raw SFUB file")
    a(f"sfub size:      {r['sfub_size']} bytes")
    a(f"sfub sha256:    {r['sfub_sha256']}")
    h = r["header"]
    a(f"magic:          {h['magic']!r} (ok={h['magic_ok']})")
    a(f"version:        {h['version']!r}")
    a(f"field @0x20:    {h['field_0x20_hex']}  (unidentified, 16 bytes)")
    a(f"u32 @0x30:      {h['u32_0x30_hex']}  (0x24 observed on SS, 0x44 on E3)")
    a(f"u32 @0x34:      {h['u32_0x34_payload_size']} bytes payload (declared)")
    a(f"u32 @0x38:      {h['u32_0x38']}")
    a(f"reserved zero:  0x3C..0x20F all zero: {h['reserved_0x3c_0x20f_all_zero']}")
    p = r["payload"]
    a(f"payload:        offset 0x{p['offset']:x}, size {p['declared_size']} "
      f"(mod8={p['size_mod_8']}, mod16={p['size_mod_16']}), end 0x{p['end_offset']:x}")
    hg = p["histogram"]
    a(f"payload stats:  entropy {hg['entropy_bits_per_byte']} bits/byte, "
      f"chi2 {hg['chi2_uniform_df255']} (df=255, uniform ~255+/-23), method: {hg['method']}")
    a(f"payload first64: {p['first64_hex']}")
    a(f"payload last64:  {p['last64_hex']}")
    a(f"payload md5:    {p['md5']}")
    a(f"payload sha256: {p['sha256']}")
    a(f"field@0x20 == md5(payload): {p['field_0x20_matches_md5']}, "
      f"sha1[:16]: {p['field_0x20_matches_sha1_first16']}, "
      f"sha256[:16]: {p['field_0x20_matches_sha256_first16']}")
    runs = p["consecutive_8byte_runs"]
    a(f"consecutive 8-byte identical-block runs in payload: {runs['distinct_blocks']} distinct blocks")
    for t in runs["top"]:
        a(f"    {t['hex']} runs={t['runs']} max_run={t['max_run_blocks']} blocks")
    tp = p["terminal_padding_run"]
    if tp:
        a(f"terminal padding: block {tp['block_hex']} x {tp['blocks']} "
          f"({tp['bytes']} bytes), starts at payload+0x{tp['run_start_payload_offset']:x}")
    else:
        a("terminal padding: none (no repeated 8-byte block at payload end)")
    for name, s in p["samples"].items():
        a(f"sample {name}: payload+0x{s['payload_offset']:x} len={s['length']} "
          f"dup8={s['dup8']['distinct_repeated_blocks']} dup16={s['dup16']['distinct_repeated_blocks']}")
    if r["trailing"]:
        t = r["trailing"]
        a(f"trailing:       offset 0x{t['offset']:x}, size {t['size']} (mod8={t['size_mod_8']}), "
          f"entropy {t['histogram']['entropy_bits_per_byte']}")
    else:
        a("trailing:       none (payload size field exactly reaches EOF)")
    for pat, hits in r["find_hits"].items():
        a(f"find {pat}: {hits['count']} hits at {hits['offsets_hex']}")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description="Read-only SFUB_update container analyzer")
    ap.add_argument("files", nargs="+")
    ap.add_argument("--json", help="write JSON report to this path (per file: <path> is a directory or use one input)")
    ap.add_argument("--find", action="append", default=[],
                    help="hex byte string to locate in the inner file (repeatable)")
    args = ap.parse_args()

    patterns = []
    for f in args.find:
        try:
            patterns.append(bytes.fromhex(f))
        except ValueError:
            ap.error(f"--find value is not hex: {f!r}")

    for path in args.files:
        r = analyze(path, patterns)
        print(text_report(r))
        print()
        if args.json:
            if len(args.files) == 1 and not os.path.isdir(args.json):
                out = args.json
            else:
                base = os.path.basename(path).replace(".pkg", "") or "sfub"
                out = os.path.join(args.json, f"sfub-{base}.json")
            os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
            with open(out, "w") as fh:
                json.dump(r, fh, indent=2)
                fh.write("\n")


if __name__ == "__main__":
    main()
