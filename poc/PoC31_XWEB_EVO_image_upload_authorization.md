# PoC31 — XWEB EVO image upload/delete missing authorization check

## Status

Dynamically validated with official vendor Lighttpd/Lua code in an isolated
QEMU/bubblewrap lab, and re-validated with the public authorization-gated
remote checker against the same loopback runtime. No physical controller or
third-party address was contacted.

- XWEB3000/5000 EVO 5.8.8 i686: confirmed over loopback HTTP.
- Any authenticated account is sufficient; a profile granting only
  `system/restore` was used. An unauthenticated control was denied. This is
  not an unauthenticated finding.
- Browser execution of uploaded SVG active content was not tested; no
  script-bearing payload was used.
- EVO reached End of Support in March 2026. Physical reachability on a
  controller remains unverified.

## Root cause

`images.lua:19-22` checks only `Session.isValid(SSES)`. Unlike its sibling
handlers, the upload and delete actions perform no permission check at all:

- `images.lua:40-73` (upload): accepts a multipart file whose extension is in
  `png|jpg|jpeg|gif|svg` and stores it under `/opt/setup/images/` as
  `<md5-of-content><ext>`.
- `images.lua:79-97` (delete): removes any basename under that directory
  (path separators are rejected).

The stored files are served without a session through the static `/imgimage/`
alias (`etc/lighttpd/lighttpd.conf:212`).

## Harmless proof

The remote checker uploads a unique, inert SVG containing only a text marker:

```xml
<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><text>EVOPOC<random></text></svg>
```

and then verifies, in order:

1. the identical multipart upload with an empty session is denied
   (`PERMISSION_DENIED`) — unauthenticated negative control;
2. the authenticated upload returns `{"status":"ok"}`;
3. the deterministic stored name `md5(content).svg` appears in the
   `images.lua` `list` action;
4. `GET /imgimage/<name>` returns the marker content — unauthenticated static
   readback;
5. the `delete` action returns `{"status":"ok"}` and the file is gone (404).

## Reproduce (authorized remote check)

Run only against a device you own and may modify:

```bash
cd /path/to/Ole-K2-Copeland-Firmware-Disclosure
python3 tools/xweb_evo_remote.py --authorized \
  --username <your-user> --password <your-password> \
  images http://<your-device>
```

The loopback-only lab validator is `lab/evo-x86-5.8.8-images-test.sh` (via
`lab/run-evo-x86-5.8.8.sh`).

## Expected sanitized result

```json
{
  "confirmed": true,
  "unauthenticated_upload_denied": true,
  "upload_status": "ok",
  "listed": true,
  "content_retrieved": true,
  "canary_deleted": true,
  "exit_code": 0
}
```

Output contains no target address, credentials, session token, MAC/IP, or raw
device response.

## Cleanup

The checker deletes the uploaded image through the same API in a `finally`
path and confirms it is no longer served; exit code 5 with
`"canary_deleted": false` means the stored file may remain and should be
removed manually (`images.lua` `delete` with the reported deterministic name).

## Impact and boundaries

Any account, regardless of role, can place stored content on the device and
delete existing images, enabling defacement and stored-content delivery to
other users through the unauthenticated `/imgimage/` route. SVG active-content
impact depends on how the image is later rendered and was not tested; the
proof used an inert document. Upload size/type constraints beyond the
extension allowlist were not enumerated.

## Remediation

- Require an explicit image-administration permission for upload and delete,
  matching the permission model of sibling handlers.
- Serve uploaded SVG as inert content (`Content-Security-Policy` /
  `Content-Disposition` / sanitization) or disallow SVG uploads.
- Keep authentication on the `/imgimage/` route consistent with the
  sensitivity of stored operator content.
- Add regression tests for sessions without the permission and for
  unauthenticated requests; deny them by default.
