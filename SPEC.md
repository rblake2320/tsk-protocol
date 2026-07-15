# TSK Wire Protocol 1

This document describes the behavior implemented by package version `0.1.0`.

## Request Headers

- `X-TSK-Client-ID`: exact provisioned client identifier.
- `X-TSK-Key`: assembled segment values followed by the integrity tag.
- `X-TSK-Version`: `1`.

## Key Construction

Each segment value is derived with HMAC-SHA-256 from the 32-byte shared secret
and a domain-separated input:

- static: `static:<segmentId>`
- time-window: `totp:<segmentId>:<windowNumber>`
- counter: `hotp:<segmentId>:<counter>`

The names describe scheduling behavior. These values are not RFC 4226 or RFC
6238 OTP codes. Values are base64url encoded and truncated or expanded to the
provisioned segment length. Ordered lengths reveal cumulative boundaries.

Wire v1 stores HOTP counters as safe integers in `0..2,147,483,647`. Values
`0..2,147,483,646` are derivation inputs. `2,147,483,647` is the exhausted
sentinel committed by the final legal use and is never used to derive another
credential. This is a project limit, not RFC 4226's 8-byte representation.

The final 12 characters are a truncated HMAC-SHA-256 over
`checksum:<keyWithoutChecksum>`. This is an integrity tag, not Ed25519 and not a
digital signature.

## Validation And Commit

The server checks version, size, lifecycle, integrity tag, and all segment
values. A valid map must include at least one counter-based segment. After
validation, the store atomically:

1. rechecks revocation, expiry, and the hard request cap;
2. requires exactly one match for every HOTP segment and verifies that none was
   already consumed;
3. advances all matched counters without crossing the wire-v1 maximum;
4. increments `requestCount` and records `lastUsedAt`;
5. enters `expiring` when either the usage-cap or closest HOTP-counter warning
   window is reached, and enters `expired` when numeric capacity reaches zero.

Any failed precondition changes none of the counters or usage fields, except
that an expired/capped credential may be persisted as `expired`.

## Response Contract

An HTTP adapter applies `buildTSKResponseHeaders()` after successful
authentication. `X-TSK-Authenticated: 1` tells the client to commit its local
counters even when downstream application work returns a non-2xx response.
Rotation state is carried in `X-TSK-Rotation-Required` and
`X-TSK-Requests-Remaining`. `X-TSK-HOTP-Counters-Remaining` reports the legal
uses remaining for the HOTP segment closest to exhaustion.

## Replacement

`replaceKey()` is disabled unless the deployment supplies a replacement
authorizer. On approval, the store atomically creates the new credential and
marks the prior credential revoked. Expired credentials do not use this flow;
recovery is a separate operator-controlled ceremony.
