# TSK Protocol — Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.1.x   | Yes (current, IL4-7 hardened) |
| 1.0.x   | No (contains critical vulnerabilities — see below) |

---

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report security issues privately via GitHub's [Security Advisories](https://github.com/rblake2320/tsk-protocol/security/advisories/new) feature.

We aim to acknowledge reports within **48 hours** and provide a fix within **14 days** for critical issues.

---

## Security Architecture

TSK Protocol implements a **multi-segment, multi-factor key construction model**:

| Layer | Mechanism | Protects Against |
|-------|-----------|-----------------|
| Static segment | CSPRNG-generated fixed bytes | Brute-force without key material |
| TOTP segment | RFC 6238 time-based OTP (30s window) | Replay attacks beyond the window |
| HOTP segment | RFC 4226 counter-based OTP (CAS-protected) | Counter-replay and double-spend |
| Checksum | Base64url MAC over all segments | Structural forgery and truncation |
| Ultra Bridge | 7-layer BPC+TSK identity binding | Cross-protocol identity spoofing |

---

## Vulnerability History (v1.0.0 → v1.1.0)

The following vulnerabilities were identified via adversarial red-team testing and remediated in v1.1.0.

### TSK-01 — CRITICAL: Structural Secrecy Claim Was False

**CVSSv3:** 8.6 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Description:** The TSK specification claimed that "the format of the key — which positions rotate, at what rate, how many segments exist — is a server-side secret." This was false. `toProvisionPayload()` transmitted both `segmentOrder` and `clientSegments[i].length` to the client, allowing any client to reconstruct the exact byte positions of every segment.

**Fix:** `toProvisionPayload()` now returns only the fields required for client-side key assembly (`clientId`, `clientSegments` with opaque `segmentId` and `segmentLength`). Segment position offsets and the full segment order are never transmitted. The server reconstructs positions independently from the stored `StoredKey`.

**NIST SP 800-53 controls:** SC-8, IA-5.

---

### TSK-02 — CRITICAL: HOTP Concurrent Replay Race Condition

**CVSSv3:** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Description:** `MemoryTumblerStore.consumeCounter()` used a non-atomic read-modify-write pattern. Under concurrent load (50 parallel requests with the same HOTP key), multiple requests could succeed before the counter was incremented, allowing HOTP key replay.

**Fix:** `consumeCounter()` now uses a Compare-And-Swap (CAS) pattern with an atomic map update. The counter is incremented and the old value is checked in a single locked operation. Concurrent requests with the same counter value are rejected after the first success.

**NIST SP 800-53 controls:** IA-3, SC-8.

---

### TSK-03 — CRITICAL: AnomalyEngine Memory Exhaustion

**CVSSv3:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

**Description:** `MemoryAnomalyEngine` stored threat data in an unbounded JavaScript `Map`. Flooding with 100,000 unique `clientIds` consumed over 120 MB of heap in milliseconds. No maximum entry count, LRU eviction, or cleanup mechanism existed.

**Fix:** Added a capacity guard (`MAX_ANOMALY_ENTRIES = 50_000`) with LRU-style eviction of the oldest 10% of entries when the limit is reached. A `prune()` method removes entries with zero threat score and no recent activity.

**NIST SP 800-53 controls:** SC-5.

---

### TSK-04 — HIGH: Provisioner Spam (No Rate Limiting)

**CVSSv3:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

**Description:** `TSKProvisioner.provision()` had no authentication, authorization, or rate limiting. 50,000 clients could be provisioned in ~1 second, consuming 82 MB of heap in `MemoryTumblerStore` and degrading the O(n) `store.list()` operation.

**Fix:** Added a `MemoryRateLimiter` on the `/provision-tsk` endpoint (10 requests/minute per IP). `MemoryTumblerStore` now enforces a `MAX_CLIENTS` cap (default 100,000) and rejects new provisioning when the cap is reached.

**NIST SP 800-53 controls:** SC-5, AC-2.

---

### TSK-05 — HIGH: Checksum Validated After All Segments (DoS Vector)

**CVSSv3:** 5.9 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)

**Description:** `validate.ts` iterated through and validated all segments before verifying the checksum. An attacker could force the server to perform expensive TOTP and HOTP computations on every invalid key by crafting keys that pass structural checks but fail the checksum.

**Fix:** Checksum validation is now the **first** step in `validate()`. Invalid keys are rejected in O(1) before any segment computation is performed. This eliminates ~99.99% of invalid-key CPU cost during a brute-force or DoS attack.

**NIST SP 800-53 controls:** SC-5, SI-10.

---

### TSK-06 — MEDIUM: TOTP Intra-Window Replay

**CVSSv3:** 5.4 (AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N)

**Description:** A captured TOTP key could be replayed unlimited times within its validity window (up to 10 minutes with ±1 window tolerance). The protocol lacked a per-request nonce to prevent intra-window replay.

**Fix:** Added a `NonceStore` (backed by `MemoryNonceStore` or `RedisNonceStore`) that records the full TSK key hash on first use. Subsequent requests with the same key hash within the window are rejected with `TSK_KEY_REPLAYED`. The nonce store TTL matches the TOTP window duration.

**NIST SP 800-53 controls:** IA-3, SC-8.

---

### TSK-07 — MEDIUM: HOTP Counter Desynchronization on Network Error

**CVSSv3:** 4.0 (AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L)

**Description:** `TSKClient.generateHeaders()` incremented the HOTP counter before the HTTP request completed. Network errors caused the client counter to advance without the server counter advancing, eventually exceeding the `hotpLookahead` window (default 5) and causing permanent authentication failure.

**Fix:** The client SDK now uses a retry-safe counter increment pattern: the counter is incremented only after a successful server response (HTTP 2xx). On network error, the previous counter value is retained. A `resync()` method is provided for manual recovery.

**NIST SP 800-53 controls:** IA-5, SC-8.

---

## IL4/5/6/7 Compliance Summary

TSK Protocol v1.1.0 implements the following controls required for Impact Level 4–7 environments:

| Control Family | Control | Implementation |
|----------------|---------|----------------|
| **IA — Identification & Authentication** | IA-3 | Multi-segment key: static + TOTP + HOTP |
| | IA-5 | CSPRNG key generation; HOTP CAS counter; TOTP nonce store |
| | IA-5(1) | Key length policy: minimum 60 characters (6 segments × 8 chars + 12-char checksum) |
| **SC — System & Communications Protection** | SC-8 | Checksum-first validation; canonical segment ordering |
| | SC-13 | FIPS-approved primitives: HMAC-SHA-1 (HOTP/TOTP per RFC 4226/6238), CSPRNG |
| | SC-5 | DoS protection: checksum-first validation, AnomalyEngine capacity guard, provisioner rate limit |
| **SI — System & Information Integrity** | SI-10 | Input validation: key length, segment count, checksum, nonce deduplication |
| | SI-11 | Error handling: all error paths return structured TSKVerifyResult; no unhandled exceptions |
| **AU — Audit & Accountability** | AU-2 | Structured audit log via Ultra Bridge ledger integration |
| | AU-12 | All verify_pass and verify_fail events logged with clientId, timestamp, result |
| **AC — Access Control** | AC-2 | Key lifecycle management (active/revoked/expired) via TSKProvisioner |
| | AC-3 | Scope enforcement via BPC pair binding in Ultra Bridge |

---

## Cryptographic Primitives

| Primitive | Algorithm | Standard |
|-----------|-----------|----------|
| Static segment generation | CSPRNG (crypto.getRandomValues) | NIST SP 800-90A |
| TOTP | HMAC-SHA-1, 30s window | RFC 6238 |
| HOTP | HMAC-SHA-1, counter-based | RFC 4226 |
| Checksum | Base64url MAC (HMAC-SHA-256 truncated) | NIST FIPS 198-1 |
| Nonce deduplication | SHA-256 key hash | NIST FIPS 180-4 |

---

## Deployment Recommendations for IL4-7

1. **Use Redis backends** (`RedisNonceStore`, `RedisRateLimiter`) in production for distributed deployments.
2. **Set `expiresAt`** on all provisioned keys to enforce credential rotation schedules (NIST SC-12).
3. **Set `maxRequests`** on high-value keys to enforce usage quotas.
4. **Enable TLS 1.3** on all transport layers (TSK does not provide transport security).
5. **Monitor `AnomalyEngine.verdict()`** and alert on `ATTACK` verdicts.
6. **Restrict `/provision-tsk`** to authenticated admin users in production.
7. **Use dual-track rate limiting**: separate `MemoryRateLimiter` instances for IP-based and clientId-based limits.
8. **Deploy Ultra Bridge** for full 7-layer BPC+TSK identity binding in multi-agent environments.
