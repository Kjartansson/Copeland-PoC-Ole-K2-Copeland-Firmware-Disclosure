# Public-copy verification

Date: 2026-11-20

All checks in this summary used the exact files published in this repository or
their documented genuine-firmware inputs. Tests used official public packages,
loopback-only runtimes, synthetic accounts, and harmless canaries. No personal
remote device or third-party target was contacted.

## Decoders and offline models

- `xweb_evo_xor_extract.py`: decoded the official x86 EVO/FCEVO 5.8.8 package;
  both CPIO outputs matched the research-tree outputs byte-for-byte.
- `xweb_epkg_decrypt.py`: decoded ARM EVO 5.8.8 and matched the independently
  recovered plaintext byte-for-byte.
- `xweb2009_xor_extract.py`: recovered the 4.0.19 package and validated all five
  CPIO entries.
- `xweb_evo_password.py`: documentation vectors returned `O0ANI3` and
  `xwebdixO0ANI3`.
- `xweb_evo_api_validate.py`: shell-construction and in-memory SQL models passed.
- Python compilation and tool `--help` checks passed after making the Blowfish
  constants lazy-load only when the research path actually runs.

## Public x86 lab validators

The following public scripts all completed with `overall: PASS`:

- email configuration injection
- restore-member injection
- factory password reset
- debug backup and debug restore injection
- download filename injection
- exportpars traversal
- restore and backup password injection
- restore-server credential injection
- x86 5.8.8 service smoke test
- native dependency loader audit
- self-edit command injection
- locale traversal
- image upload/delete authorization

The first email run exposed missing `msmtp` binds and a writable log directory in
the public launcher. The launcher was corrected and the same public test then
passed; this was a lab-packaging fix, not a change to the firmware handler.

## Unified remote runner

`tools/xweb_evo_remote.py` passed its complete loopback battery for `info`,
`self-edit`, `locale`, `images`, `xss`, and `specialuser`. Checks included:

- genuine login/logout and role controls;
- canary creation/readback/deletion and username restoration;
- no-session negative controls;
- output checks for target, username, password, and session-token leakage;
- unreachable-target and missing-authorization exit behavior.

The runner reports only sanitized results. Its `list` mode requires no device
contact; every contacting mode requires `--authorized`.

## New native upload validator

`lab/evo-x86-5.8.8-upload-parser-test.sh` passed twice consecutively, with 10/10
checks each time. It confirms the hidden `finalfile` plaintext escape, overlong
filename SIGSEGV as DoS only, and unauthenticated `evoupfile` staging with
basename containment. No-session negative controls and cleanup passed. A
multipart-boundary compatibility issue in the initial public test was corrected
and the final validator was rerun successfully.

## Forged-update validator

`lab/forged-update/` passed repeatedly after its per-run `/opt/log` overlay was
added to prevent updater SQLite state carry-over. The genuine updater listed the
fabricated manifest, accepted the payload, and created a unique harmless canary;
no-session denial and cleanup passed. The operator's rootfs configuration and
runtime remained unchanged. No RPM, reboot, firmware write, or external
repository was used.

## Crypto known-answer checks

- `e2e_blowfish_schedule_validate.py`: emulated schedules matched the signed
  model for four keys, including high-bit and 32-byte cases.
- `e3_permuted_blowfish_probe.py --skip-discover --skip-emulation`: recovered
  the documented key material and completed its signed-backend known-answer and
  bounded target checks without a plaintext hit.
- The OpenSSL/EVP and signed-Blowfish tools compile and expose their usage
  without requiring firmware until an actual research run is requested.

## Crunch recovery and broad-oracle campaign

- `results/crunch-runtime/wrapper_decode_unicorn.py` and the independent
  qemu-i386 harness produced byte-identical 10,361,268-byte output from the
  genuine E2E Crunch stream, SHA-256
  `80204568f1ddfe8202f5781657c80c50766f1c2b1070c95c244a1392bf1c7c9f`.
  Both reported the same final-20-byte underrun/wrapper-rejection boundary. The
  recovered image is validated as an i386 VxWorks ELF and is not redistributed.
  The corrected decoder then accepted all 942 additional streams in the two
  E2/E2E packages (504 + 436 + 2); manifests and decoder scripts are public,
  while proprietary decoded outputs remain excluded. Static analysis recovered
  29,365 symbols and identified GoAhead HTTP, `/JSON-RPC`, UltraSite/E2 peer
  protocols, schema-only unsigned updates, and the signed-byte salted Blowfish
  family. A Ghidra working copy has only five header bytes zeroed; every LOAD
  segment remains byte-identical. No SFUB parser or E3/SS access path was found.
- `tools/xweb_broad_oracle.py` passed the public self-test and an independent
  OpenSSL positive-control reproduction. The campaign covered 102 Salted__
  components with 1,571,165,262 operations and zero validated hits. Recovered
  images and raw candidate dumps are excluded from the public evidence set.

## Shared credential and TLS-key checks

Both official EVO and FCEVO shadow entries verified `dixell:dixell` using their
shipped SHA-512 hashes. Both PEM files had the documented SHA-256 and contained
an RSA-2048 private key whose modulus matched the certificate. No SSH login or
TLS interception was attempted.

## Standalone RCE, SSH, and ARM chains

- `tools/xweb_evo_rce.py`: passed in the root-mapped x86 lab with real
  `uid=0(root)` proof and confirmed canary removal.
- `tools/xweb_evo_ssh_chain.py`: passed the genuine ARM chain with
  `EVO_ROOT_PROOF`, `uid=0(root)`, and `ssh_stopped: true`. Verification exposed
  and fixed three public-tool issues: bounded reading for a malformed CGI header,
  acceptance of the genuine `{"SSH":"start"/"stop"}` responses, and a
  lab-only daily-code override for the date-frozen fixture. The normal derived
  credential path is unchanged.
- `EVO_CONFIG_TEST=1 lab/run-evo-arm.sh`: configuration canary passed and the
  original was restored.
- `EVO_RESTORE_SERVER_TEST=1 lab/run-evo-arm.sh`: authorization controls and both
  restore-server command canaries passed.
- `lab/evo-arm-dropbear-canary.py`: real root password authentication and canary
  passed; the regenerated result was byte-identical to the committed result.
- `lab/evo-arm-ssh-chain-canary.py`: SSH start, root canary, lab account, SSH stop,
  and privileged web login passed; its result was also byte-identical.

No physical device was contacted. The date-frozen lab used `--daily-code` only
for fixture compatibility; production credential derivation was not bypassed.

## Evidence handling

Raw runtimes, firmware images, request corpora, and detailed logs remain outside
the public repository. This summary intentionally contains only synthetic
results and no personal remote-device identifiers, credentials, sessions,
configuration, or captures.
