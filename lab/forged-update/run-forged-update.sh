#!/usr/bin/env bash
# Lab-only validator for PoC30: the genuine EVO 5.8.8 x86 updater accepts a
# wholly fabricated, unsigned update manifest from a loopback-only fake
# repository and executes its command template (a unique harmless canary).
#
# Operator supplies the derived rootfs/runtime (never committed; see
# lab/EVO.md) through the environment:
#   EVO_X86_588_ROOT    derived i686 rootfs  (default: build/evo-x86-5.8.8-rootfs)
#   EVO_X86_588_RUNTIME derived runtime dir  (default: build/evo-x86-5.8.8-runtime)
#   QEMU_I386           qemu-i386 binary     (default: /usr/bin/qemu-i386)
#   EVO_AS_ROOT=0       opt out of uid-0 user-namespace mapping (the genuine
#                       setuid-root CGI aborts with {"e":2} without it)
#
# The launcher never modifies the operator's rootfs: a patched copy of
# system.conf (update server pointed at 127.0.0.1) is bind-mounted over the
# original inside the sandbox. No external network, no RPM installation, no
# reboot, no firmware write. The canary, session file, and staging directory
# are removed by the validator; the generated fake repository is removed on
# exit.
set -euo pipefail

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
ROOT=${EVO_X86_588_ROOT:-$REPO/build/evo-x86-5.8.8-rootfs}
RUN=${EVO_X86_588_RUNTIME:-$REPO/build/evo-x86-5.8.8-runtime}
QEMU=${QEMU_I386:-/usr/bin/qemu-i386}
REPO_PORT=18089

[[ -x "$ROOT/opt/xweb/www/cgi-bin/new_xwrpm.cgi" ]] || {
  echo "missing derived i686 rootfs (set EVO_X86_588_ROOT)" >&2; exit 1; }
[[ -f "$ROOT/opt/setup/system.conf" ]] || {
  echo "rootfs has no opt/setup/system.conf" >&2; exit 1; }
[[ -d "$RUN" ]] || { echo "missing derived runtime (set EVO_X86_588_RUNTIME)" >&2; exit 1; }
[[ -x "$QEMU" ]] || { echo "missing qemu-i386: $QEMU" >&2; exit 1; }
command -v python3 >/dev/null || { echo "missing python3" >&2; exit 1; }
command -v bwrap >/dev/null || { echo "missing bwrap" >&2; exit 1; }

if [[ ${EVO_AS_ROOT:-1} != 0 ]]; then
  AS_ROOT=(--unshare-user --uid 0 --gid 0)
  echo "note: sandbox uid mapped to 0 to emulate the setuid-root CGI context (EVO_AS_ROOT=0 disables)"
else
  AS_ROOT=()
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

TOKEN=$(python3 -c 'import secrets; print(secrets.token_hex(4))')
CANARY=/opt/log/EVO_FORGED_CANARY_$TOKEN
SSES=forged$TOKEN

python3 "$REPO/lab/forged-update/build-forged-repo.py" "$WORK/fake-repo" "$CANARY"

# Point the update flow at the loopback fake repository without touching the
# operator's rootfs: render a patched copy and bind it over system.conf.
python3 - "$ROOT/opt/setup/system.conf" "$WORK/system.conf" "$REPO_PORT" <<'PY'
import sys

src, dst, port = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(src).read().splitlines()
out, in_updates, seen = [], False, False
for line in lines:
    if line.strip().startswith("["):
        in_updates = line.strip() == "[Updates]"
        seen = seen or in_updates
        out.append(line)
        continue
    if in_updates:
        if line.startswith("Dixell_Default="):
            line = "Dixell_Default=0"
        elif line.startswith("Server_Address="):
            line = f"Server_Address=http://127.0.0.1:{port}"
        elif line.startswith("Server_Path="):
            line = "Server_Path=/"
    out.append(line)
if not seen:
    sys.exit("system.conf has no [Updates] section")
open(dst, "w").write("\n".join(out) + "\n")
PY

# /opt/log gets a fresh scratch dir per run: the updater records installed
# packages in its own SQLite log there, and a reused log would suppress
# re-installation of the canary package. The operator's runtime is never
# written by this flow.
mkdir -p "$WORK/opt-log"

bwrap \
  --unshare-net --unshare-pid --unshare-uts --unshare-ipc --die-with-parent \
  "${AS_ROOT[@]}" \
  --bind "$ROOT" / \
  --ro-bind "$ROOT/bin/bash" /bin/sh \
  --ro-bind "$ROOT/bin/busybox" /bin/rm \
  --ro-bind "$ROOT/bin/busybox" /bin/cp \
  --ro-bind "$ROOT/bin/busybox" /bin/mkdir \
  --ro-bind "$ROOT/bin/busybox" /bin/chmod \
  --ro-bind "$ROOT/bin/busybox" /usr/bin/touch \
  --ro-bind "$ROOT/bin/busybox" /bin/sleep \
  --ro-bind "$ROOT/bin/busybox" /bin/sync \
  --ro-bind "$ROOT/bin/busybox" /usr/bin/id \
  --ro-bind "$ROOT/bin/busybox" /bin/cat \
  --ro-bind "$QEMU" /usr/bin/qemu-i386 \
  --ro-bind /lib/i386-linux-gnu/ld-linux.so.2 /lib/ld-linux.so.2 \
  --ro-bind /lib/i386-linux-gnu /lib/i386-linux-gnu \
  --ro-bind /usr/lib/i386-linux-gnu /usr/lib/i386-linux-gnu \
  --ro-bind /lib64/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2 \
  --ro-bind /lib/x86_64-linux-gnu /lib/x86_64-linux-gnu \
  --ro-bind /usr/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu \
  --proc /proc --dev /dev \
  --bind "$RUN/opt-tmp" /opt/tmp \
  --bind "$WORK/opt-log" /opt/log \
  --bind "$RUN/shm" /dev/shm \
  --bind "$RUN/tmp" /tmp \
  --bind "$RUN/var-log" /var/log \
  --bind "$RUN/var-run" /var/run \
  --bind "$RUN/xwebconfig.json" /etc/xwebconfig.json \
  --ro-bind "$WORK/system.conf" /opt/setup/system.conf \
  --ro-bind "$WORK/fake-repo" /fake-repo \
  --ro-bind "$REPO/lab" /lab \
  --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
  --setenv FORGED_CANARY "$CANARY" \
  --setenv FORGED_SSES "$SSES" \
  /bin/busybox sh /lab/forged-update/evo-x86-5.8.8-forged-update-test.sh
