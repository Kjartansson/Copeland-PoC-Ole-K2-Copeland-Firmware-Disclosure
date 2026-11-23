# XWEB Pro broad-oracle validation summary

Date: 2026-11-23. Authorized offline analysis of official encrypted components.
No live controller or external target was contacted. Original encrypted packages
and raw candidate dumps are not redistributed.

## Outcome

The broad-oracle campaign completed **102 Salted__ components** with
**1,571,165,262 candidate operations** and **zero validated plaintext hits**:

- 22 manifests: 338,878,782 operations (the initial manifest plus 21 matrix targets).
- 80 components of at least 1 MiB: 1,232,286,480 operations.
- Each component was tested against the same 15,403,581-candidate expanded-case list.
- 10,754,607 first-block-screened candidates on the 80 large components were all
  rejected by strict full-stream validation; no unverifiable candidates remained.

This closes the earlier narrow-magic false-negative gap for these targets and this
wordlist. It is not proof that the packages cannot be decrypted by another method,
and it is not a claim that the correct password was present in the list.

## Validation method

`tools/xweb_broad_oracle.py` and `xweb_broad_oracle.cl` add recognition for
JSON/text/XML, real tar semantics, xz, zstd, bzip2, lz4, lzma, uImage, DTB,
SQLite, UBI/UBIFS, and other formats, followed by strict full-stream parsing,
decompression, CRC, or integrity checks. The original narrow-magic GPU oracle
would have discarded candidates producing several of these plaintext types.

Self-tests passed on both compute workers: OpenSSL known-answer tests, GPU/CPU
first-block equivalence, pure-Python AES checks, 19 synthetic positive formats,
random-payload negatives, and wrong-password negatives. A planted JSON manifest
was recovered end-to-end and independently reproduced through OpenSSL with the
same SHA-256. The large-component run also passed self-tests on both GPUs.

A final-block PKCS7 optimization was used on the large run: only padding-valid
candidates received full-stream decryption and validation. Rejection details and
verdicts are unchanged from the unmodified flow.

## Reproduce

```bash
python3 tools/xweb_broad_oracle.py --self-test
python3 tools/xweb_broad_oracle.py --target ENCRYPTED_COMPONENT \
  --words CANDIDATE_LIST --chunk-size 262144 --json result.json
```

Any candidate that passes strict validation must be independently reproduced with
OpenSSL or a separate CPU decryptor before being reported as plaintext. No such
candidate occurred in this campaign.
