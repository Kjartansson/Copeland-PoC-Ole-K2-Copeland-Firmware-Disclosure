#!/bin/sh
set -eu

BASE=http://127.0.0.1:18082/cgi-bin
SERVER_PID=

cleanup() {
  set +e
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

/usr/bin/qemu-i386 -L / /usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf -D &
SERVER_PID=$!
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if SYSINFO=$(/bin/busybox wget -qO- "$BASE/sysinfo.lua"); then
    break
  fi
  sleep 1
done

case "$SYSINFO" in
  *'"status":"ok"'*'5.8.8.STANDARD.24--25902d'*) ;;
  *) echo "FAIL genuine 5.8.8 sysinfo: $SYSINFO"; exit 1;;
esac
echo "PASS genuine x86 5.8.8 service"

MISSING=$(/bin/busybox wget -qO- --post-data 'action=acq&target=start' "$BASE/api.lua") || true
case "$MISSING" in
  *'"error":"NOT_ENOUGH_PARAMETERS"'*) ;;
  *) echo "FAIL acq missing-credential control: $MISSING"; exit 1;;
esac
echo "PASS acquisition missing-credential control"

DENIED=$(/bin/busybox wget -qO- --post-data 'action=acq&target=start&username=x&password=x' "$BASE/api.lua") || true
case "$DENIED" in
  *'"error":"PERMISSION_DENIED"'*) ;;
  *) echo "FAIL unauthenticated acq control: $DENIED"; exit 1;;
esac
[ ! -e /opt/.xwon ] || { echo "FAIL unauthenticated acquisition start"; exit 1; }
echo "PASS unauthenticated acquisition start denied"
echo "overall: PASS"
