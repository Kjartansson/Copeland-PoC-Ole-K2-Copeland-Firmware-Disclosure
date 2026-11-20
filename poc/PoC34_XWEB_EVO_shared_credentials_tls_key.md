# PoC34 — XWEB EVO shared support credential and TLS private key

## Status

Verified statically in the official EVO and FCEVO 5.8.8 i686 trees. No device
login, TLS connection, or third-party target was used. The private key itself
and any device-derived configuration are intentionally not redistributed.

## Findings

### Shared `dixell:dixell` account

Both trees ship a `dixell` account whose SHA-512 password hash verifies against
the literal password `dixell`. The account's shell,
`opt/xweb/bin/tools/mac_date.sh`, prints the MAC address and date inputs used by
the daily-password mechanism.

This combines dangerously with the existing daily root-credential design (see
PoC12): the support account discloses the values needed to compute the changing
root password rather than providing an independent security boundary. FCEVO
also explicitly sets `PermitRootLogin yes` in `etc/ssh/sshd_config`.

### Firmware-wide TLS private key

Both trees contain the same `etc/ssl_cert_dixell.pem`, with an unencrypted
RSA-2048 private key and matching certificate. SHA-256:

```text
53cbadef705a2bff41aa2b6f9864991e3708765d77e915b1fa9fb4ab3cd3ae71
```

The certificate is self-signed with `C=IT, ST=Italy, L=Alpago, O=Dixell`, valid
from 2017-01-31 through 2027-01-29. Where this default key is deployed, anyone
with the public firmware can impersonate the service or attempt TLS interception;
the key is not a device identity.

This RSA-2048 TLS key is unrelated to the RSA-4096 XWEB PRO update-wrapping key
and cannot decrypt PRO packages.

## Offline verification

Use only an official, operator-supplied extracted rootfs. These commands compare
the private-key and certificate public components without publishing the key:

```bash
ROOT=/path/to/official-evo-rootfs
openssl pkey -in "$ROOT/etc/ssl_cert_dixell.pem" -noout -modulus
openssl x509 -in "$ROOT/etc/ssl_cert_dixell.pem" -noout -modulus -subject -dates
sha256sum "$ROOT/etc/ssl_cert_dixell.pem"
```

The two modulus values must match. The certificate dates and PEM hash above are
expected for the reviewed 5.8.8 artifact. To verify the support credential
offline, compute its shipped SHA-512 hash with the documented salt and literal
`dixell`; do not attempt a login against someone else's device.

## Impact and boundaries

- A shared default support credential removes per-device authentication
  uniqueness and feeds the predictable root-credential chain.
- A shared TLS private key prevents meaningful server authentication wherever it
  is deployed. SCEP or another per-device certificate-provisioning process must
  replace it for TLS to provide device identity.
- No physical SSH login, TLS interception, certificate deployment check, or
  physical-controller result is claimed.

## Remediation

- Disable the shared support account or require a unique, strong credential on
  first use; do not expose MAC/date-to-credential derivation as an account shell.
- Require per-device TLS keys and certificates; remove the firmware-wide private
  key from update images and rotate any deployed copies.
- Disable password-based root SSH and direct Internet exposure; use a restricted
  management network and per-account keys where SSH is required.
- Migrate from End-of-Support EVO and review Copeland's upgrade resources.
