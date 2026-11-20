#!/bin/sh
set -u

FAILED=0
for binary in \
  /usr/bin/lua \
  /usr/lib/libxwfunc.so \
  /opt/xweb/bin/tools/xwcrypt \
  /opt/xweb/www/cgi-bin/new_xwrpm.cgi \
  /opt/xweb/bin/xwacq \
  /opt/xweb/www/cgi-bin/upload.cgi
do
  echo "== $binary =="
  OUTPUT=$(/usr/bin/qemu-i386 -L / /lib/ld-linux.so.2 --list "$binary" 2>&1)
  STATUS=$?
  echo "$OUTPUT"
  case "$OUTPUT" in
    *'not found'*) FAILED=1;;
  esac
  if [ "$STATUS" -ne 0 ]; then
    FAILED=1
  fi
done
if [ "$FAILED" -ne 0 ]; then
  echo "overall: FAIL"
  exit 1
fi
echo "overall: PASS"
