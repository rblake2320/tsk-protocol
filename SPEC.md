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

The final 12 characters are a truncated HMAC-SHA-256 over
`checksum:<keyWithoutChecksum>`. This is an integrity tag, not Ed25519 and not a
digital signature.

## Validation And Commit

The server checks version, size, lifecycle, integrity tag, and all segment
values. A valid map must include at least one counter-based segment. After
validation, the store atomically:

1. rechecks revocation, expiry, and the hard request cap;
2. verifies that no matched counter was already consumed;
3. advances all matched counters;
4. increments `requestCount` and records `lastUsedAt`;
5. enters `expiring` state when the rotation warning window is reached.

Any failed precondition changes none of the counters or usage fields, except
that an expired/capped credential may be persisted as `expired`.

## Response Contract

An HTTP adapter applies `buildTSKResponseHeaders()` after successful
authentication. `X-TSK-Authenticated: 1` tells the client to commit its local
counters even when downstream application work returns a non-2xx response.
Rotation state is carried in `X-TSK-Rotation-Required` and
`X-TSK-Requests-Remaining`.

## Replacement

`replaceKey()` is disabled unless the deployment supplies a replacement
authorizer. On approval, the store atomically creates the new credential and
marks the prior credential revoked. Expired credentials do not use this flow;
recovery is a separate operator-controlled ceremony.
