# TSK Protocol Specification v1.0
# Tumbler-Style Rotating Segment Keys

**Author:** R. Blake  
**Date:** 2026-04-09  
**Status:** CONFIDENTIAL — Pre-patent-filing. Do not distribute publicly.  
**Version:** 1.0  

---

## 1. Abstract

TSK (Tumbler-Style Rotating Segment Keys) is an API authentication protocol where an API key is composed of multiple independently-rotating segments whose **positional structure is a per-client secret**. Unlike existing rotating key schemes that replace an entire key on a schedule, TSK makes the *map of which positions rotate* — and at what rate — a secret authentication factor stored only on the server. An attacker who intercepts a valid TSK key cannot determine which characters are static and which have already expired, making any captured key structurally useless after its shortest rotation window.

---

## 2. Motivation

### 2.1 Limitations of Static API Keys

Standard API keys are static strings. If compromised (leaked in code, intercepted in transit, exfiltrated from a secrets manager), they are fully usable by an attacker until manually rotated. Major incidents — including the 2022 npm/axios supply chain attack where 100,000+ keys were harvested via malicious packages — demonstrate that static keys are a systemic vulnerability in the API authentication landscape.

### 2.2 Limitations of Existing Rotation Schemes

Standard key rotation (AWS Secrets Manager, HashiCorp Vault, Akeyless) replaces the entire key on a schedule. The key is static *within* the rotation period. A key compromised at the start of a 30-day rotation window is fully usable for up to 30 days.

TOTP/HOTP (RFC 6238/4226) rotate the *entire value* on a time/counter schedule. They generate short numeric codes, not structured API keys, and require the authenticating party to know exactly what to expect.

### 2.3 TSK's Novel Contribution

TSK applies positional TOTP/HOTP rotation to individual segments *within* a key, with the critical additional property that the **segment positions are a per-client secret**. This "structural secrecy" means:

1. Each key looks like one normal string — attackers cannot determine the format
2. Individual segments expire independently at different rates
3. The positional map provides an additional authentication factor beyond the key values themselves
4. Anomaly detection gains fine-grained intelligence: which segments failed tells the server whether the failure is clock drift (single TOTP segment near boundary) or a stolen key (static segment matches, rotating segments expired)

---

## 3. Protocol Overview

### 3.1 Key Structure

A TSK key is a string of exactly `keyLength` characters (default: 52). It consists of:

```
[segment_0][segment_1][...][segment_N][checksum]
```

Where:
- Each `segment_i` occupies a contiguous range `[position_start, position_end)` in the string
- `checksum` occupies the last 8 characters
- **Positions are randomized per-client at provisioning and stored server-side only**

### 3.2 Segment Types

| Type | Derivation | Rotation |
|------|-----------|---------|
| `static` | `HMAC(secret, "static:<segmentId>")` | Never |
| `totp` | `HMAC(secret, "totp:<segmentId>:<T>")` where `T = floor(unixMs/1000 / windowSec)` | Every `windowSec` seconds |
| `hotp` | `HMAC(secret, "hotp:<segmentId>:<counter>")` | Every use (counter increments) |

The static segment (always the first) serves as a client identity anchor. The server uses it to look up the client's tumbler map.

### 3.3 Checksum

```
checksum = HMAC(sharedSecret, "checksum:" + key[0..keyLength-8])[0..7]
```

The checksum provides fast tamper detection before segment-level validation.

### 3.4 HMAC Function

All HMAC operations use HMAC-SHA256 with the client's 256-bit shared secret as the key. Output is base64url-encoded for URL-safe characters. Output is truncated or repeated (via additional HMAC rounds) to fill the target segment length.

---

## 4. Tumbler Map

The tumbler map is the central data structure. It is generated once per client at provisioning and stored server-side only.

```typescript
interface TumblerMap {
  clientId: string;              // Stable client identifier
  sharedSecret: string;          // 256-bit hex — NEVER transmitted after provisioning
  keyLength: number;             // Total key length in characters
  segments: SegmentConfig[];     // All segments including static and rotating
  checksum: {
    position: [number, number];  // Last N chars
  };
  createdAt: number;             // Unix ms timestamp
  version: '1';
}
```

### 4.1 Structural Secrecy Property

The client receives a **provision payload** that contains:
- `clientId`
- Segment IDs, types, and timing parameters
- **Positions, lengths, and segment ordering are strictly omitted**

The server uses its stored positions to validate incoming keys. The client generates segment values as an unordered map and the server assembles them. An attacker who compromises the client only learns which segments exist and their types — not where they appear in the key string, nor their lengths.

### 4.2 Tumbler Map Generation

At provisioning, the server:
1. Generates a random 256-bit `sharedSecret`
2. Generates a random `clientId`
3. Randomly selects 2-5 rotating segments
4. Randomly divides `keyLength - 8` characters among segments with jittered boundaries
5. Randomly shuffles segment positions (further preventing structural inference)
6. Randomly assigns each segment a type (`static`, `totp`, or `hotp`) and timing parameters
7. Stores the complete map
8. Returns the provision payload (positions omitted) to the client

---

## 5. Key Generation (Client Side)

```
for each segment in clientSegments:
  if type == "static":
    value = HMAC(sharedSecret, "static:" + segmentId)
  elif type == "totp":
    T = floor(currentUnixMs / 1000 / windowSec)
    value = HMAC(sharedSecret, "totp:" + segmentId + ":" + T)
  elif type == "hotp":
    value = HMAC(sharedSecret, "hotp:" + segmentId + ":" + counter)
    counter++

key = concatenate(values in segmentId order) + HMAC(sharedSecret, "checksum:" + keyWithoutChecksum)[0..7]
```

The client sends the assembled key in the `X-TSK-Key` header.

---

## 6. Server Validation

```
1. Extract clientId from X-TSK-Client-ID header
2. Look up TumblerMap for clientId
3. Validate key length == map.keyLength
4. Validate checksum (constant-time compare)
5. For each segment in map:
   a. Extract key[position_start:position_end]
   b. Static: compare to HMAC(secret, "static:" + segId)
   c. TOTP: compare to HMAC(secret, "totp:" + segId + ":" + T)
              check T-1, T, T+1 (tolerance windows)
   d. HOTP: check counter, counter+1, ..., counter+5
              advance stored counter on match
6. If any segment fails → reject, record anomaly
7. If all pass → accept, return clientId
```

All comparisons use constant-time byte comparison (Node.js `crypto.timingSafeEqual`).

---

## 7. Protocol Headers

| Header | Direction | Description |
|--------|-----------|-------------|
| `X-TSK-Client-ID` | Client → Server | Client identifier |
| `X-TSK-Key` | Client → Server | Assembled key string |
| `X-TSK-Version` | Client → Server | Protocol version ("1") |

---

## 8. Security Properties

### 8.1 Replay Attack Resistance
TOTP segments expire after their window (30-300 seconds). HOTP segments can only be used once. A key captured and replayed after the shortest segment's window expires is rejected. The HOTP implementation uses an atomic Compare-And-Swap (CAS) operation (`consumeCounter`) to ensure that concurrent replay attacks (e.g., submitting the same valid HOTP key simultaneously across multiple threads) are blocked.

### 8.2 Partial Key Leakage
An attacker who learns part of the key cannot reconstruct the full key. Without knowing segment positions, they cannot determine which characters are live vs. expired vs. static.

### 8.3 Structural Secrecy
The format of the key — which positions rotate, at what rate, how many segments exist — is a server-side secret. This is a novel security property with no equivalent in existing standards.

### 8.4 Brute Force Resistance
An attacker must correctly guess both the segment values (HMAC output space) and their correct positions. The number of valid positional arrangements is given by `C(L - S + N, N)` where `L` is key length, `S` is sum of segment lengths, and `N` is number of segments. For a 512-character key with 5 segments, the search space for positions alone is massive. Furthermore, the checksum validation (12 chars = 72 bits of entropy) rejects `1 - (1/2^72)` of all brute force attempts with a single HMAC operation, preventing the attacker from forcing the server to perform expensive per-segment positional brute-forcing.

### 8.5 Stolen Key Detection via Anomaly Analysis
Per-segment validation results feed the anomaly engine:
- **Static segment matches, rotating segments fail** → strong stolen-key indicator
- **All segments fail** → brute force or wrong client
- **One TOTP segment off by one window** → likely clock drift, low threat score

---

## 9. Anomaly Detection

The anomaly engine maintains a rolling 5-minute window of validation failures per client. Threat scoring (0-100):

| Pattern | Score Added |
|---------|------------|
| ≥10 failures in window | +40 |
| 3-9 failures | +15 |
| Static passes, rotating fails (×2+) | +50 |
| Static passes, rotating fails (×1) | +20 |
| Total failures (×3+) | +30 |

Verdicts:
- 0-29: `clean`
- 30-69: `suspicious`
- 70-100: `attack`

---

## 10. Ultra Enhancement (BPC + TSK)

When combined with BPC (Bound Pair Credentials), the protocol stack reaches 7 security layers:

| Layer | Protocol | Property |
|-------|----------|---------|
| 1 | BPC | Device-bound ECDSA P-256 (TPM, extractable: false) |
| 2 | BPC | Explicit pair registry (closed whitelist) |
| 3 | BPC | User-chosen secret HMAC'd into every signature |
| 4 | BPC | Per-request nonce + ±60s timestamp anti-replay |
| 5 | BPC | Behavioral anomaly engine (per-pair threat scoring) |
| 6 | TSK | Tumbler key with per-client secret position map |
| 7 | TSK | Structural secrecy (key format itself is a secret) |

BPC and TSK are **independent orthogonal factors**: BPC uses device-bound ECDSA hardware keys; TSK uses HMAC-based rotating segment keys. An attacker must defeat both systems simultaneously.

The bridge is a thin wrapper: `verifyBPCRequest()` (BPC's pure exported function) is called first; TSK verification runs only if BPC passes. Zero BPC source code modifications required.

---

## 11. Comparison to Related Work

| Protocol | Positional Map Secret | Independent Segment Rotation | Structural Secrecy | TSK Similarity |
|----------|----------------------|-----------------------------|--------------------|---------------|
| TOTP (RFC 6238) | No | No (single value) | No | PARTIAL — TSK uses TOTP per segment |
| HOTP (RFC 4226) | No | No | No | PARTIAL — TSK uses HOTP per segment |
| US10735398 | No | No | No | FAR — windowed segment of single stream |
| BPC | N/A (ECDSA) | N/A | No | COMPLEMENTARY |
| AWS SigV4 | No | No | No | FAR |
| **TSK** | **YES** | **YES** | **YES** | **Novel** |

---

## 12. Implementation Notes

### 12.1 Clock Synchronization
TOTP segments require client/server clock agreement within the tolerance window (default ±1 window = ±30s for 30s windows, ±60s for 60s windows). Production deployments should use NTP.

### 12.2 HOTP Counter Drift
The server accepts HOTP codes within a lookahead window (default 5). If the client has generated codes that weren't transmitted, the server will catch up. The counter is advanced to `matchedCounter + 1` on success.

### 12.3 Shared Secret Distribution
The 256-bit shared secret must be delivered to the client over a secure channel at provisioning time. Recommended channels:
- BPC-authenticated endpoint (for ultra mode — the BPC ECDSA signature authenticates the provisioning request)
- Mutual TLS
- Out-of-band (QR code, secure link with one-time use)

The secret should be stored in:
- Browser: IndexedDB with AES-GCM wrapping key stored in Web Crypto non-extractable form
- Node.js: OS keychain via the `keytar` library, or HashiCorp Vault
- Never in environment variables or source code

---

## 13. Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-04-09 | Initial specification |
| 1.1 | 2026-05-18 | IL4/5/6/7 Hardening: Fixed structural secrecy (removed lengths/order from payload), upgraded checksum to 72 bits, added checksum-first validation, added atomic HOTP CAS, added bounded memory and IP tracking to anomaly engine. |

---

*This document and its contents are confidential intellectual property of R. Blake. All rights reserved. Do not distribute pending patent filing.*
