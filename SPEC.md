# TSK Protocol Specification v1.1

## Overview
The Tumbler Secret Key (TSK) protocol is a structural authentication layer designed to defeat credential theft and replay attacks. It relies on a rotating, multi-segment key where the format and position of the segments are themselves a server-side secret.

## Wire Format
TSK authentication is transmitted via HTTP headers:
*   `X-TSK-Client-ID`: The unique client identifier (must start with `tsk_`).
*   `X-TSK-Key`: The assembled key string.
*   `X-TSK-Version`: The protocol version (currently `1`).

## Key Assembly
The `X-TSK-Key` is a concatenated string of multiple segments, followed by a checksum.
1.  **Static Segments**: Fixed alphanumeric strings.
2.  **TOTP Segments**: Time-based One-Time Passwords.
3.  **HOTP Segments**: HMAC-based One-Time Passwords (counter-driven).

The exact number, length, type, and order of these segments are defined by the `TumblerMap` provisioned to the client. The server holds the authoritative copy of this map.

## Canonical Serialization (MED-06)
When calculating the Ed25519 checksum over the key segments, the client and server MUST use a canonical JSON serialization of the segment array to ensure the hash matches exactly across different platforms (e.g., Node.js vs. Python).

**Rules for Canonical Serialization:**
1.  No whitespace between keys and values or around colons/commas.
2.  Keys MUST be sorted lexicographically.
3.  Strings MUST be UTF-8 encoded.

*Failure to use canonical serialization will result in a `CHECKSUM_INVALID` error.*

## Checksum
The final segment of the key is a base64url-encoded Ed25519 signature of the canonically serialized segment array, signed using the `sharedSecret` provisioned to the client. The server verifies this checksum before attempting to validate the individual TOTP/HOTP segments.

## Lifecycle Management
TSK keys support the following lifecycle fields, enforced by the server:
*   `status`: `active`, `revoked`, or `expired`.
*   `expiresAt`: Epoch timestamp (ms) after which the key is automatically rejected.
*   `maxRequests`: Maximum number of successful validations allowed before the key is auto-expired.
