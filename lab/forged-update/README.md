# Forged-update validator (PoC30, lab-only)

Validates that the genuine XWEB EVO 5.8.8 x86 updater (`new_xwrpm.cgi`)
accepts a wholly fabricated, unsigned update manifest from a loopback-only
fake repository and executes its command template. The command is limited to
touching a unique harmless canary file. No RPM is installed, no reboot or
firmware write occurs, and no external network is used (bubblewrap
`--unshare-net`; the fake repository is busybox httpd on `127.0.0.1`).

## Requirements

- `bwrap`, `qemu-i386`, `python3`, and unprivileged user namespaces (the
  genuine CGI is setuid-root and aborts with `{"e":2}` unless the sandbox uid
  is mapped to 0; `EVO_AS_ROOT=0` opts out).
- Operator-supplied derived rootfs/runtime (see `lab/EVO.md`; never
  committed), pointed to via environment:

```bash
EVO_X86_588_ROOT=/path/to/evo-x86-5.8.8-rootfs \
EVO_X86_588_RUNTIME=/path/to/evo-x86-5.8.8-runtime \
lab/forged-update/run-forged-update.sh
```

Defaults are `build/evo-x86-5.8.8-rootfs` and `build/evo-x86-5.8.8-runtime`
inside this repository (both git-ignored).

## What it does

1. Generates a unique canary token and builds the fake repository
   (`build-forged-repo.py`): an XOR-obfuscated unsigned `evopack` manifest
   plus a marker payload. The manifest's only action is
   `/usr/bin/touch /opt/log/EVO_FORGED_CANARY_<token>`.
2. Renders a patched copy of the operator's `system.conf` with `[Updates]`
   pointed at `127.0.0.1` and bind-mounts it over the original — the
   operator's rootfs is never modified. `/opt/log` is a fresh per-run scratch
   dir so the updater's own SQLite log cannot suppress re-runs.
3. Runs the genuine CGI directly under qemu-i386: a no-session negative
   control (expect `{"e":2}`), then `gu=0` listing and `mu=10` update against
   the fake repository with a synthetic session file.
4. Checks the canary, then removes the canary, session file, and staging
   directory, and verifies their absence. Expected final output:
   `overall: PASS` (exit 0).

Everything generated lives in a `mktemp` directory that is deleted on exit;
nothing is added to Git and nothing persists on the operator's rootfs.
