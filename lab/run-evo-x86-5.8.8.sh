#!/usr/bin/env bash
set -euo pipefail

REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
ROOT=${EVO_X86_588_ROOT:-$REPO/build/evo-x86-5.8.8-rootfs}
RUN=${EVO_X86_588_RUNTIME:-$REPO/build/evo-x86-5.8.8-runtime}
QEMU=${QEMU_I386:-/usr/bin/qemu-i386}

[[ -x "$ROOT/usr/sbin/lighttpd" ]] || { echo "missing derived i686 rootfs" >&2; exit 1; }
[[ -x "$QEMU" ]] || { echo "missing qemu-i386: $QEMU" >&2; exit 1; }

CURL="$RUN/curl"
mkdir -p "$RUN/opt-log"

BWRAP=(bwrap
  --unshare-net --unshare-pid --unshare-uts --unshare-ipc --die-with-parent
  --bind "$ROOT" /
  --ro-bind "$ROOT/bin/bash" /bin/sh
  --ro-bind "$ROOT/bin/busybox" /bin/rm
  --ro-bind "$ROOT/bin/busybox" /bin/cp
  --ro-bind "$ROOT/bin/busybox" /bin/mv
  --ro-bind "$ROOT/bin/busybox" /bin/tar
  --ro-bind "$ROOT/bin/busybox" /usr/bin/tar
  --ro-bind "$ROOT/bin/busybox" /bin/mkdir
  --ro-bind "$ROOT/bin/busybox" /bin/chmod
  --ro-bind "$ROOT/bin/busybox" /usr/bin/touch
  --ro-bind "$ROOT/bin/busybox" /bin/sleep
  --ro-bind "$ROOT/bin/busybox" /bin/sync
  --ro-bind "$ROOT/bin/busybox" /usr/bin/id
  --ro-bind "$ROOT/bin/busybox" /usr/bin/awk
  --ro-bind "$QEMU" /usr/bin/qemu-i386
  --ro-bind /lib/i386-linux-gnu/ld-linux.so.2 /lib/ld-linux.so.2
  --ro-bind /lib/i386-linux-gnu /lib/i386-linux-gnu
  --ro-bind /usr/lib/i386-linux-gnu /usr/lib/i386-linux-gnu
  --ro-bind /lib64/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2
  --ro-bind /lib/x86_64-linux-gnu /lib/x86_64-linux-gnu
  --ro-bind /usr/lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu
  --ro-bind "$REPO/build/msmtp-host/usr/bin/msmtp" /usr/bin/msmtp
  --ro-bind "$REPO/build/msmtp-host/usr/lib/x86_64-linux-gnu" /opt/msmtp-lib
  --dir /opt/evo-compat
  --ro-bind "$REPO/build/evo-lua-x86/root/lib/i386-linux-gnu" /opt/evo-compat/lib
  --ro-bind "$REPO/build/evo-lua-x86/root/usr/lib/i386-linux-gnu" /opt/evo-compat/usr-lib
  --setenv LD_LIBRARY_PATH /opt/evo-compat/lib:/opt/evo-compat/usr-lib:/lib/i386-linux-gnu:/usr/lib/i386-linux-gnu:/lib:/usr/lib:/opt/msmtp-lib
  --proc /proc --dev /dev
  --bind "$RUN/opt-tmp" /opt/tmp
  --bind "$RUN/opt-log" /opt/log
  --bind "$RUN/shm" /dev/shm
  --bind "$RUN/tmp" /tmp
  --bind "$RUN/var-log" /var/log
  --bind "$RUN/var-run" /var/run
  --bind "$RUN/lighttpd-custom.conf" /etc/lighttpd/lighttpd-custom.conf
  --bind "$RUN/xwebconfig.json" /etc/xwebconfig.json
  --bind "$RUN/xwpasswd" /opt/xweb/bin/tools/xwpasswd
  --bind "$RUN/wlua" /opt/xweb/bin/tools/wlua
  --bind "$CURL" /usr/bin/curl
  --ro-bind /usr/bin/curl /opt/host-curl
  --bind "$RUN/ip" /usr/bin/ip
  --bind "$RUN/mount" /bin/mount
  --bind "$RUN/mount" /usr/bin/mount
  --bind "$RUN/umount" /usr/bin/umount
  --bind "$RUN/unzip" /usr/bin/unzip
  --bind "$RUN/find" /usr/bin/find
  --bind "$RUN/md5sum" /usr/bin/md5sum
  --bind "$RUN/zip" /usr/bin/zip
  --ro-bind "$RUN/restore-injection.zip" /opt/restore-injection.zip
  --ro-bind "$REPO/lab" /lab
  --setenv PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/xweb/bin/tools
)

if [[ -n ${EVO_TEST_SCRIPT:-} ]]; then
  [[ "$EVO_TEST_SCRIPT" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "invalid test script name" >&2; exit 1; }
  exec "${BWRAP[@]}" /bin/busybox sh "/lab/$EVO_TEST_SCRIPT"
fi

exec "${BWRAP[@]}" /usr/bin/qemu-i386 -L / /usr/sbin/lighttpd \
  -f /etc/lighttpd/lighttpd.conf -D
