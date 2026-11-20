#!/bin/sh
set -eu

BASE=http://127.0.0.1:18082/cgi-bin
AUTH=
SERVER_PID=
IMAGE=
BODY=/tmp/evo-image-multipart

cleanup() {
  set +e
  rm -f "$BODY"
  if [ -n "$IMAGE" ]; then
    rm -f "$IMAGE"
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

mkdir_body() {
  printf '%s\n' '<svg xmlns="http://www.w3.org/2000/svg"><text>EVO_IMAGE_CANARY</text></svg>' > "$BODY"
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

mkdir_body ''
DENIED=$(/opt/host-curl -sS -F 'SSES=' -F 'action=upload' -F "file=@$BODY;filename=probe.svg;type=application/octet-stream" "$BASE/images.lua") || true
case "$DENIED" in
  *'"error":"PERMISSION_DENIED"'*) ;;
  *) echo "FAIL unauthenticated image control: $DENIED"; exit 1;;
esac
echo "PASS unauthenticated image upload denied"

mkdir_body "$AUTH"
UPLOAD=$(/opt/host-curl -sS -F "SSES=$AUTH" -F 'action=upload' -F "file=@$BODY;filename=probe.svg;type=application/octet-stream" "$BASE/images.lua") || true
case "$UPLOAD" in
  *'"status":"ok"'*) ;;
  *) echo "FAIL low-privilege SVG upload: $UPLOAD"; exit 1;;
esac
set -- /opt/setup/images/*.svg
[ -f "$1" ] || { echo "FAIL uploaded SVG missing"; exit 1; }
IMAGE=$1
CONTENT=$(cat "$IMAGE")
case "$CONTENT" in
  *'EVO_IMAGE_CANARY'*) ;;
  *) echo "FAIL uploaded SVG content"; exit 1;;
esac
echo "PASS restore-only account stored SVG without a permission check"

NAME=$(/bin/busybox basename "$IMAGE")
DELETE=$(post "SSES=$AUTH&action=delete&filename=$NAME" images.lua) || true
case "$DELETE" in
  *'"status":"ok"'*) ;;
  *) echo "FAIL low-privilege image delete: $DELETE"; exit 1;;
esac
[ ! -e "$IMAGE" ] || { echo "FAIL uploaded SVG cleanup"; exit 1; }
echo "PASS restore-only account deleted stored image"
echo "overall: PASS"
