# XWEB Pro 1.16.1 acquisition and initial assessment

## Scope

Official public Copeland downloads only. No recovered repository credentials,
device contact, or third-party target was used. Acquisition date: 2026-11-03.

The previously failing `pLoadContent` catalog API responded during this pass and
listed XWEB Pro 1.16.1, released 2026-10-29. This supersedes earlier notes that
treated 1.15.1 as the current XWEB300D/500D/500B/1000D release. XWEB5000's
catalog still listed 1.15.1 as its newest package in the same response.

## Official artifacts

| Artifact | Size | SHA-256 |
|---|---:|---|
| XWEB300D/500D Pro 1.16.1 | 41,992,780 bytes | `7571a9e337fe794e79a09bc57ee92855998fa365cb1ca567649a43652c864cf8` |
| XWEB500B/Coolmate Pro 1.16.1 | 43,735,372 bytes | `b11a47a54a6ceba1ded517cf72c99e0011736316d8a8ba8d5b9fa3847cc6e534` |
| XWEB1000D Pro 1.16.1 | 37,647,536 bytes | `a40c60db42104351bafa36fb8760b5e660bf8ad0197788f2cc4700725b814d0a` |
| 1.16.1 release notes | 318,514 bytes | `c3ebf54020aef2816bc2ac856ec83b2848abd8beaa83b6a33b3eac8611877262` |

Packages are under `firmware/related/`; extracted members are under
`extracted/XWEB_PRO_xw500d_1.16.1/`,
`extracted/XWEB_PRO_xwcoolmate_1.16.1/`, and
`extracted/XWEB_PRO_xw1000d_1.16.1/`. The release notes are
`firmware/reference/Changelog_XWEB-PRO_v.1.16.1_EN.pdf` and
`results/Changelog_XWEB-PRO_v.1.16.1_EN.txt`.

## Container and signature verification

The XWEB500D and Coolmate packages contain `v2`, `key`, `rootfs`, `xweb`, `www`,
`kernel`, `libraries`, and `manifest`; XWEB1000D has the same layout without a
kernel member. Every non-marker object has a detached signature. All 20
signatures across the three packages returned `Verified OK` with
`results/xweb-pro-rsa4096-public.pem` and SHA-512.

Every payload member begins with OpenSSL `Salted__`; the new Coolmate kernel is
not a plaintext shortcut. XWEB500D 1.15.1 already contained a kernel component,
so only the Coolmate kernel addition is new relative to the compared 1.15.1
layouts. All 24 salts compared across the initial two 1.16.1 and selected 1.15.1
components were unique. Public RSA `verifyrecover` failed with invalid PKCS#1
type-1 padding for the initial two key blobs. No plaintext updater, rootfs,
private key, or package passphrase was recovered.

## Bounded GPU candidate testing

The existing self-tested OpenCL implementation was run against all three new
manifests with five local dictionaries:

| Dictionary | Candidates per manifest |
|---|---:|
| Recovered/reversed/permuted firmware strings | 2,973,657 |
| Rockyou | 14,344,390 |
| Expanded case variants | 15,403,581 |
| Firmware subtokens | 3,782,372 |
| Copeland/industrial terms | 1,518,809 |
| **Total per manifest** | **38,022,809** |
| **Total across three manifests** | **114,068,427** |

Five visible Claroty example strings were also tested against each manifest,
bringing the total to **114,068,442** candidates. There were zero validated
hits. A small number of short-magic candidates were fully decrypted and rejected
or remained magic-only; none is a decryption result. Evidence:
`results/xweb-pro-*-1.16.1-manifest-*-fused-opencl.json`. Further generic
dictionary growth has low expected value compared with recovering the
updater/private-key unwrap path.

The full Copeland/industrial list was also tested with AES-128-CBC,
AES-256-CBC, and triple-DES using MD5/SHA-256 EVP derivation: 9,112,854
operations per manifest and 27,338,562 across all three. There were no valid
hits. One Coolmate candidate (`670948`, triple-DES/MD5) matched only a short
gzip-like prefix; full-stream validation failed with `invalid block type`, so it
is rejected (`results/xweb-pro-xwcoolmate-1.16.1-manifest-alternate-candidate-validation.json`).
The initial unbounded alternate-cipher attempt timed out without a result; the
replacement bounded jobs provide explicit operation counts. A 100,000-candidate
PBKDF2 job also timed out inconclusively. A final 1,000-candidate PBKDF2-SHA256
job completed all seven supported constructions with 7,000 operations per
manifest and zero hits (`results/xweb-pro-*-1.16.1-manifest-pbkdf2-1k.json`).

## Utility and public research

The restored official catalog exposed only the already-audited WIZMATE/driver
utilities and legacy firmware in the other sections. WIZMATE and LIB Builder
remain incapable of reading Pro packages or emulating Pro services
(`results/wizmate-libbuilder-capability-audit.md`). Authenticated GitHub code
and repository searches for exact Pro/package identifiers found no Pro updater,
recovery image, decoder, emulator, or API client; results were unrelated
projects or CVE mirrors (`results/github-*-2026-11-03.json`).

Claroty's public research confirms a Lighttpd/Lua architecture, SSH and
Shellinabox access paths, and RS485 Modbus field-controller communication. Its
authentication and command-injection details are useful for comparison after a
Pro runtime is recovered. The visible Basic-auth example and redacted key
screenshot do not disclose the package private key. Source:
https://claroty.com/team82/research/chilling-discoveries-unpacking-vulnerabilities-in-copeland-xweb-pro-controllers

No physical device is available, so device-dump and on-device updater-capture
paths are excluded. The useful public acquisition remains a Pro updater,
recovery/base image, or an equivalent authorized runtime.

## Independent archive and boot checks

7-Zip 26.00 independently enumerated 15 stored-ZIP members in XWEB500D and
Coolmate and 13 in XWEB1000D. It exposed no additional nested image or plaintext
updater. Binwalk found only the expected OpenSSL header plus isolated signatures
with impossible image sizes inside encrypted data; those are not treated as
valid embedded images.

A bounded `qemu-system-arm` boot attempt used the XWEB500D 1.16.1 `kernel` with
the generic `virt` machine. After 15 seconds there was no vendor console output
and the CPU-error log was empty; timeout terminated the attempt. Evidence:
`results/xweb-pro-xw500d-1.16.1-qemu-console.log` and
`results/xweb-pro-xw500d-1.16.1-qemu-cpu.log`. This is not a successful firmware
boot and yields no service inventory or runtime logs. QEMU cannot substitute for
decrypting the kernel and rootfs.

Ghidra 12.2 also rejected the encrypted kernel with `No load spec found`, and
Rizin reported no architecture, executable class, machine, or code. Evidence:
`results/xweb-pro-xw500d-1.16.1-ghidra.log`. Raw disassembly of ciphertext
would not be a valid reverse-engineering result.

A complete EMBA 2.0.4 quick scan with 12 module workers and one thread per
module found entropy of 7.999995 bits/byte but no kernel version, distribution,
executable services, account/network configuration, password hashes, private
keys, or CVE matches. Its QNX label is explicitly unverified and is not used.
Evidence: `results/emba-xweb-pro-xw500d-1.16.1/`. EMBA's additional
`*_foscam_enc_extracted` files remain high-entropy data, not decrypted images.

## EVO compatibility-tool attempt

The real EVO 5.8.8 ARM `xwcrypt` was also run against the XWEB500D Pro package
in a network-disabled container. The untouched EVO rootfs supplied its exact
`libscrambling.so` and `libiconv.so`; verified Debian bookworm ARMEL packages
supplied the remaining ordinary runtime dependencies. No proprietary library
was downloaded from a third party or installed on the host.

The official LIB20241125 archive was separately decoded with
`tools/xweb_epkg_decrypt.py`. It contains device-definition JSON data, not the
missing shared objects. Decoder evidence:
`results/evo-5.8.8-library-package-decoder.json`.

`xwcrypt` exited zero and produced a same-length 41,992,780-byte output with
SHA-256 `a797a4d4f5ff04bf18352009e5ba9a25e145d79eba3cd8f877ea086e9a1dff31`.
The output has no valid ZIP, shell, filesystem, or other supported magic and
7-Zip rejects it. Its isolated Binwalk signatures are not valid images. Tool
log: `results/xweb-pro-xw500d-1.16.1-evo-arm-xwcrypt.log`. This is a completed
negative compatibility test, not a Pro decryption path.

## Publicly identified services and routes

The official operating manual documents network/USB/browser update channels,
custom update-server settings, LDAP authentication, backup restore, and a
Modbus TCP gateway with read-only/read-write modes and a network whitelist. It
does not expose an updater executable or additional download URL
(`results/XWEB-PRO-OPR-EN.txt`).

The 1.13–1.16.1 notes add API v2 library-update and system-log endpoints, JSON
Data Push, DNS/LDAP/custom-URL network tools, and custom update-server
credentials. These are concrete SSRF, injection, authorization, and
credential-handling review targets if plaintext services become available;
they are not runtime findings.

Public CVE material for 1.12.1 and earlier identifies unauthenticated arbitrary
file read (`CVE-2026-22877`), API stack corruption (`CVE-2026-20797`), and
library-install command injection (`CVE-2026-24663`). On an older runtime, the
file-read class would be especially relevant to updater/key exposure. No
physical target is available and no vulnerability is claimed against 1.16.1.

## Release-note leads for future PoCs

The official 1.16.1 notes identify strengthened authentication and account
protection, stricter role-based access controls, improved system-configuration
validation, and safer file/package/backup handling. They also say API v1 will be
removed from releases after July 2027 and that API v2 is already available with
improved security.

Once plaintext is available, the highest-value comparisons are:

1. API v1 versus v2 authentication and role-enforcement paths, including Bearer
   token error handling.
2. Backup/package filename, archive-member, signature, and compatibility checks.
3. Configuration-validation enforcement and any remaining unauthenticated write.
4. Update-version comparison and acceptance of validly signed older packages.
5. The data-acquisition memory-leak and crash fixes as availability-only cases,
   not assumed code-execution primitives.

These are research directions from vendor notes, not demonstrated
vulnerabilities. The decisive artifact remains a Pro updater executable,
recovery/base image, owned-device flash dump, or equivalent authorized runtime.
