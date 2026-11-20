# PoC33 — XWEB EVO native `upload.cgi` multipart parser flaws

## Status

Validated dynamically against the genuine EVO 5.8.8 i686 `upload.cgi`
(setuid ELF32) served by the recovered Lighttpd stack under qemu-i386 in a
network-disabled bubblewrap lab. Authentication used the synthetic lab
credential fixture only; no `session_exists` stubbing, no physical controller,
and no external network were involved. Only the i686 build was executed; ARM
builds and physical-device behavior remain unverified. Account data and file
content are synthetic.

## Vulnerabilities

### 1. Hidden `finalfile` parameter escapes the upload directory (authenticated)

The action dispatcher joins the operator-controlled `finalfile` query
parameter to a fixed per-`path` base directory without any sanitization
(`sprintf(dest, "%s/%s", mapped_dir, finalfile)`), while the multipart
`filename` value itself is reduced to a basename. `finalfile` is not used by
any shipped web-UI page; it is a hidden/legacy parameter.

```http
POST /cgi-bin/upload.cgi?SSES=<session>&action=upload&path=parameters&finalfile=../../../tmp/poc33-escape-canary.txt
Content-Type: multipart/form-data; boundary=----evopoc33boundary

------evopoc33boundary
Content-Disposition: form-data; name="file"; filename="poc33-src.par"
Content-Type: application/octet-stream

POC33-PLAINTEXT-CANARY
------evopoc33boundary--
```

Response `{"e":0}`; the file is written outside the intended `/opt/tmp/upl`
tree (here `/tmp/poc33-escape-canary.txt`, resolved through the `../`
segments) with **attacker-controlled plaintext** because the `parameters`
flow copies the staged file verbatim. The `docs` flow escapes identically but
passes the content through the device scrambling routine first, so its bytes
are encrypted rather than attacker-chosen.

Constraints confirmed by negative controls:

- a valid session is required (same request without `SSES` → `{"e":2}`, no
  file written);
- the `path` value is restricted to a fixed mapping table (`docs`,
  `parameters`, …), so the traversal always starts from a legitimate upload
  directory;
- parent directories of the target must already exist;
- an absolute `finalfile` is appended to the base directory, not honored as
  an absolute path (`{"e":1,"info":"Internal error C"}`).

### 2. Overlong multipart filename crashes the setuid parser (authenticated, DoS)

The binary (built without stack canaries) copies the multipart filename into
fixed-size stack buffers with `strcpy`/`sprintf`. A basename of about 65–72
bytes or more — in any flow (`file` + `path=docs`, `file` +
`path=parameters`, or `evoupfile` staging) — faults the process. A filename
containing CR/LF (`filename="a\r\nb.txt"`) faults the same way. The binary's
own signal handler logs `SIG: 11 -> SSEGV` and Lighttpd returns
`HTTP 500 Internal Server Error`; the file write completes before the crash.
This PoC claims denial of service of the request handler only; code execution
is not claimed.

Observed threshold on the genuine binary: 64-byte filename → `{"e":0}`;
66-byte and longer → HTTP 500 plus a new `SIG: 11` entry in the parser's
breakage log. The Lighttpd service itself survives.

### 3. Unauthenticated `evoupfile` staging persists (basename-contained)

Multipart parts named `evoupfile`/`evoupfilec` are written to
`/opt/tmp/upl/<basename>` before the `session_exists()` gate runs, and the
denial-path cleanup only unlinks files staged under `/opt/tmp/upload/`, so
the planted file persists after the `{"e":2}` rejection — with
attacker-controlled plaintext for `evoupfile`. Containment was verified:
`filename="../../../tmp/poc33-should-not-escape.evo"` still lands as
`/opt/tmp/upl/poc33-should-not-escape.evo` (the parser strips everything up
to the last `/` or `\`), so no traversal is possible here. Impact is limited
to filling the upload tmpfs and planting predictable-path content that later
authenticated update flows operate on. Generic `file`-field parts are also
staged before the gate but are removed by the denial-path cleanup.

## Runtime proof

Prerequisites: the derived i686 5.8.8 rootfs and a disposable runtime (see
`lab/README.md`), plus `bwrap` and `qemu-i386`. Both paths are
operator-supplied through environment variables; nothing is downloaded and no
device is contacted.

```bash
export EVO_X86_588_ROOT=/path/to/evo-x86-5.8.8-rootfs
export EVO_X86_588_RUNTIME=/path/to/evo-x86-5.8.8-runtime   # disposable
EVO_TEST_SCRIPT=evo-x86-5.8.8-upload-parser-test.sh ./lab/run-evo-x86-5.8.8.sh
```

Observed output on the genuine 5.8.8 i686 stack:

```text
PASS genuine x86 5.8.8 service
PASS unauthenticated evoupfile denied ({"e":2}) yet staged plaintext in /opt/tmp/upl
PASS pre-auth staging filename traversal contained to basename
PASS Administrator authentication (lab fixture)
PASS finalfile escape denied without session ({"e":2})
PASS authenticated finalfile writes plaintext outside upload dir ({"e":0})
PASS plain finalfile stays inside /opt/tmp/upl ({"e":0})
PASS 64-char filename accepted ({"e":0})
PASS 72-char filename crashes parser (HTTP 500, SIGSEGV logged)
PASS service survives parser crash
overall: PASS
```

The validator builds its tiny multipart bodies at runtime, writes only to
disposable lab storage (`/tmp`, `/opt/tmp`, `/dev/shm`, `/var/log` inside the
private namespace), and removes everything it created on exit.

## Impact and boundaries

- `finalfile` escape: an authenticated web user can create or overwrite files
  outside the upload directory (plaintext via `parameters`, scrambled content
  via `docs`), bounded by the web process privileges, existing parent
  directories, and the fixed base-directory table.
- Overlong filename: authenticated crash of a setuid-root parser process;
  denial of service only as demonstrated. The underlying defect is a
  memory-safety bug in a setuid binary, so hardening is still warranted.
- Pre-auth staging: unauthenticated persistent file creation in a fixed
  directory with fixed basename semantics; no traversal observed.
- The native parser's session gate itself holds: no pre-auth dispatch of
  `action=upload`, and no pre-auth bypass is claimed anywhere in this PoC.
- Physical-device privilege level, ARM parity, and interaction with later
  update stages were not exercised.

## Remediation

- Remove or strictly validate `finalfile`: resolve the joined path and reject
  anything outside the mapped base directory; prefer basename-only semantics
  matching the multipart `filename` handling.
- Replace every `strcpy`/`sprintf` on request-controlled data with
  length-bounded equivalents and rebuild with stack canaries and
  `_FORTIFY_SOURCE`; reject CR/LF and overlong header values up front.
- Stage no uploaded bytes before the session check, and extend denial-path
  cleanup to every staging directory (`/opt/tmp/upl` included).
- Keep the upload handler non-setuid where possible and run it with least
  privilege so parser faults cannot affect a root context.
- Add regression tests covering traversal `finalfile`, 65+-byte filenames,
  CR/LF in header values, and unauthenticated staging persistence.
