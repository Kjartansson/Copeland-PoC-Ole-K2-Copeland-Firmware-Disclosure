# Sanitized disclosure status

Researcher: Ole-k2.

Vendor channel: https://www.copeland.com/en-gb/product-security-resources

## Repository state

Public release was approved by Ole-k2 on 2026-11-03. This copy contains no
personal remote/test-device information, private configuration, session
identifiers, personal account names, or raw device captures.

## Vendor response

An initial XWEB EVO 5.8.7/5.8.8 report was submitted through Copeland's
vulnerability form without technical details. Copeland PSIRT replied that all
XWEB EVO models reached End of Support in March 2026 and that no further
security updates or vulnerability fixes will be released. Copeland recommends
its published upgrade resources and avoiding direct Internet exposure.

The reply also says: "We appreciate you taking the time to responsibly disclose
your findings and help improve cybersecurity awareness." This supports the
repository's educational and defensive purpose. Individual contact details are
omitted, and no vendor endorsement of exploitation or each later finding is
claimed.

The additional findings in this repository retain that product boundary. No
current XWEB Pro or E3/Site Supervisor exploit is claimed.

## 2026-11-20 x86 EVO update

The x86 EVO 5.8.8 self-edit, locale, unsigned-update, image, `doevo.cgi`, and
native upload-parser results were added at the researcher's direction using the
same public-release and sanitization rules. Validation remained in isolated
vendor-code runtimes. No new vendor response, physical-device compromise, or
current-product impact is implied by this update.

## Disclosure rules

1. Report suspected new vulnerabilities through Copeland product security
   before public disclosure and allow a reasonable coordination window.
2. Publish only reproducible evidence, preserving static, model, emulation, and
   physical-device distinctions.
3. Do not perform third-party Internet-facing testing. Dynamic validation must
   use isolated vendor-code runtimes or explicitly authorized equipment.
4. Sanitize all outputs before sharing; never publish personal device data,
   credentials, live sessions, addresses, hostnames, or raw captures.
5. Publicly known CVEs and third-party research are not attributed to Ole-k2.
