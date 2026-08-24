# Experimental AO HTTP Signature Signing

This feature build reports app version `1.1.2` so it cannot be confused with the official `1.0.25` release while it is being sideloaded and validated.

This branch adds bounded parsing and RSA-4096 signing for AO mainnet HTTP
signature bases. It is development software and is not approved for production
use.

## Safety boundary

- Use only a dedicated development Ledger initialized with a test seed.
- The device accepts printable ASCII signature bases up to its transaction buffer limit.
- The final line must be `"@signature-params"`.
- Its component list must exactly match every preceding reviewed field, in order.
- The algorithm must be `rsa-pss-sha512` and may appear only once.
- The key ID may appear only once and must encode the device RSA public key. Raw
  base64url and `publickey:`-prefixed standard or URL-safe base64 are accepted.
- Every committed field is shown before approval.
- The device hashes the exact input bytes; it never signs a host-supplied digest.
- Ledger validation and an independent security audit are still required.

## APDU

`SIGN_HTTP` uses `CLA=0x44`, `INS=0x04`, `P2=0`, and the same chunk protocol as
the transaction and ANS-104 signing commands:

| P1 | Meaning |
| --- | --- |
| `0x00` | Initialize an empty buffer |
| `0x01` | Append a chunk |
| `0x02` | Append the final chunk, parse, validate, and open review |

After approval, the response contains the 64-byte SHA-512 digest followed by
`0x9000`. The 512-byte RSA-PSS/SHA-512 signature, using a 64-byte salt, is
retrieved through the existing two `GET_SIG` calls.

## Ownership boundaries

The host AO library owns canonicalization. The wallet must transmit the exact
signature-base bytes and independently verify the returned digest and signature.
The device owns parsing, field review, algorithm validation, key binding, and
signature generation.

The command is intentionally not a generic `signMessage` or `signDigest`
primitive. New canonical forms require parser and review updates plus native and
Speculos test vectors.
