#!/usr/bin/env python3
"""Decode every magic-header Crunch stream in a package region, independently.

Applies the corrected genuine-wrapper semantics from
results/crunch-runtime/RECOVERY.md (ctor fcn.00649860, probe fcn.00649790,
vtable[3]=0x6499f0 with arg5=0 = magic-header mode). Stream offsets come from
a magic scan; chaining is validated afterwards via offset+consumed vs the next
magic offset, so a decoder bit-buffer over-read cannot break enumeration.
"""

import hashlib
import json
import os
import struct
import sys

TOOLS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
sys.path.insert(0, TOOLS)
import e2e_crunch_emulate as codec
from decode_stream_table import decode_one, classify

MAGIC_LE = struct.pack("<I", 0x5AA5A55A)
MAX_DECLARED = 0x1000000


def main():
    if len(sys.argv) != 6:
        raise SystemExit("usage: decode_stream_list.py PKG START END OUTDIR MANIFEST.json")
    pkg, start_text, end_text, outdir, manifest_path = sys.argv[1:6]
    start, end = int(start_text, 0), int(end_text, 0)
    data = open(pkg, "rb").read()
    if end <= 0 or end > len(data):
        end = len(data)
    os.makedirs(outdir, exist_ok=True)

    offsets = []
    pos = start
    while True:
        i = data.find(MAGIC_LE, pos, end)
        if i < 0:
            break
        offsets.append(i)
        pos = i + 1

    records = []
    for index, off in enumerate(offsets):
        declared = struct.unpack_from("<I", data, off + 4)[0] if off + 8 <= len(data) else 0
        if not declared or declared > MAX_DECLARED:
            records.append({"index": index, "offset": off, "offset_hex": hex(off),
                            "declared": declared,
                            "error": f"declared {declared:#x} implausible; likely false magic"})
            continue
        record, output = decode_one(data, off, end)
        record["index"] = index
        if output is not None:
            record["class"] = classify(output)
            name = f"{index:04d}_{off:x}.bin"
            with open(os.path.join(outdir, name), "wb") as handle:
                handle.write(output)
            record["file"] = name
        records.append(record)
        print(f"[{index+1}/{len(offsets)}] {off:#x} declared={declared} "
              f"consumed={record.get('consumed')} accept={record.get('wrapper_accept')}",
              flush=True)

    for index, record in enumerate(records):
        consumed = record.get("consumed")
        if consumed and index + 1 < len(offsets):
            record["next_magic_delta"] = offsets[index + 1] - (record["offset"] + consumed)

    with open(manifest_path, "w") as handle:
        json.dump({"package": pkg, "start": start, "end": end,
                   "streams": records}, handle, indent=1)
    ok = sum(1 for r in records if r.get("wrapper_accept"))
    reject = sum(1 for r in records if r.get("sha256") and not r.get("wrapper_accept"))
    errors = sum(1 for r in records if r.get("error"))
    deltas = {}
    for r in records:
        if "next_magic_delta" in r:
            deltas[r["next_magic_delta"]] = deltas.get(r["next_magic_delta"], 0) + 1
    print(f"streams_ok={ok} streams_reject={reject} errors={errors} total={len(records)}")
    print(f"next_magic_delta histogram={dict(sorted(deltas.items()))}")
    print(f"manifest={manifest_path}")


if __name__ == "__main__":
    main()
