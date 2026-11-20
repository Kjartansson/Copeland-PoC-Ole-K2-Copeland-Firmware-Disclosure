# PoC30 — XWEB EVO unsigned update metadata leads to command execution

## Status

Lab-only result, validated against the genuine native updater in a disposable
QEMU/bubblewrap sandbox with a loopback-only fake update repository. **No safe
one-click remote check exists for this finding, and none is provided.** The
public remote checker deliberately does not exercise the update flow.

- XWEB3000/5000 EVO 5.8.8 i686: genuine `new_xwrpm.cgi` (byte-identical to the
  extracted original) run in a root-mapped disposable sandbox.
- A wholly fabricated, unsigned manifest and payload were accepted from
  `127.0.0.1` and a harmless `touch` canary command was executed.
- No RPM was installed, no reboot was performed, and no firmware or flash
  write occurred. This is an authenticated update-path result, not a claim of
  unauthenticated Internet compromise or of a completed firmware installation.
- Physical reachability, the real update-server infrastructure, and hardware
  update reliability were not tested.

## Root cause

The genuine `new_xwrpm.cgi` implements repeating-XOR obfuscation, not package
authentication. Its `SetHash` routine derives a 20-byte key from the package
filename and the constant `0xA1` (for the name `evopack` the key is identical
to the one protecting the genuine 5.8.8 archive), so anyone can produce
"valid" update metadata. The manifest format supports `<action cmd=...>`
command templates, which the updater executes. No signature verification
exists anywhere in the flow.

The web gate is equally weak: the CGI requires that a `SSES` parameter exists
and that `/dev/shm/usp_<SSES>` exists (a `stat()` check at
`new_xwrpm.cgi+0x4950`). No update-specific permission was observed in that
flow. The repository URL is read from `/opt/setup/system.conf` (`[Updates]`
section).

## Harmless lab proof

The updater's repository setting (`[Updates]` in `system.conf`) is redirected
to a loopback fake repository (`127.0.0.1`) by bind-mounting a patched copy of
the file, leaving the original untouched. The repository serves a fabricated
package:

```text
name    = CanaryPkg
version = 9.9.9.LABCHECK-FORGED
action  = /usr/bin/touch /opt/log/EVO_FORGED_CANARY_<unique-token>
```

A session file `/dev/shm/usp_<token>` is created to mirror a logged-in web
session (the session-file gate); a control run without it is rejected with
`{"e":2}`. The genuine updater then:

1. returns a successful repository listing (`{"pks":[{...}],"err":0}`),
2. returns a successful update response (`{"updt":[{...}],"err":0}`),
3. creates the unique canary by executing the forged manifest's command
   template, and
4. records the fabricated package in its own SQLite update log.

All writes are confined to the disposable sandbox and per-run temporary
directories; the operator's rootfs and runtime are untouched, and the canary
and session file are removed before exit.

## Reproduce

There is intentionally no remote reproduction for this finding. Pointing a
real device's update flow at fabricated metadata can execute commands and, in
a full run, install packages and reboot the controller — that is destructive
and must stay in the isolated lab.

The self-contained lab validator under `lab/forged-update/` reproduces the
complete flow against an operator-supplied derived rootfs/runtime (never
committed; see `lab/EVO.md`):

```bash
cd /path/to/Ole-K2-Copeland-Firmware-Disclosure
EVO_X86_588_ROOT=/path/to/evo-x86-5.8.8-rootfs \
EVO_X86_588_RUNTIME=/path/to/evo-x86-5.8.8-runtime \
lab/forged-update/run-forged-update.sh
```

`lab/forged-update/build-forged-repo.py` fabricates the unsigned XOR-obfuscated
manifest and marker payload with a unique canary command;
`lab/forged-update/run-forged-update.sh` binds a loopback-redirected copy of
`system.conf` over the original (the operator's rootfs is never modified),
serves the fake repository on `127.0.0.1` inside a network-disabled sandbox,
and runs the genuine CGI under qemu-i386 with a uid-0 user-namespace mapping
to emulate its setuid-root context;
`lab/forged-update/evo-x86-5.8.8-forged-update-test.sh` performs the
no-session negative control, the `gu=0`/`mu=10` flow, the canary check, and
cleanup verification. Raw runtimes and external run logs remain intentionally
unredistributed.

## Expected result

Not applicable for remote use; no remote check is offered. In the lab, the
validator prints the two updater JSON responses with `"err":0`, confirms
`PASS forged unsigned manifest listed as a valid package`,
`PASS forged unsigned payload accepted for update`, and
`PASS updater executed the forged manifest command (canary present)`, then
ends with `overall: PASS` (exit 0).

## Cleanup

The validator removes the canary, the synthetic session file, and the update
staging directory, and verifies their absence before exiting. The generated
fake repository, the patched `system.conf` copy, and the updater's own SQLite
log live in a temporary directory that is deleted on exit; the operator's
rootfs and runtime accumulate nothing, so repeated runs are idempotent.

## Impact and boundaries

An attacker who can satisfy the session-file gate and deliver a repository to
the device (for example through a spoofed or compromised update server, a
DNS/routing position, or USB-delivered metadata — all deployment-dependent and
not demonstrated here) obtains command execution in the updater's context,
which is root on the shipped device. The loopback test does not demonstrate
any specific delivery route, does not claim unauthenticated compromise, and
does not claim a completed firmware installation. This result must not be
transferred to XWEB PRO, whose packages use a different detached-signature
envelope that this scheme cannot forge (see `analysis/XWEB-EVO-5.8.8-X86.md`).

## Remediation

- Require vendor signatures over the complete manifest and payload, verified
  before parsing and before any command construction.
- Remove arbitrary command templates from package metadata; replace them with
  a fixed set of server-side actions.
- Replace the session-file `stat()` gate with real per-operation
  authorization tied to an update permission.
- Pin and authenticate the update repository (HTTPS with a pinned, per-device
  or properly anchored trust chain — not the shared default certificate).
- Add regression tests that reject unsigned, wrongly signed, and
  command-bearing manifests.
