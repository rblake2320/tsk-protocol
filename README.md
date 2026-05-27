# TSK (Tumbler Secret Key) Protocol

A structural authentication layer designed to defeat credential theft and replay attacks.

## What is TSK?

Traditional API keys are static bearer tokens. If an attacker steals one, they can replay it indefinitely until it is manually revoked.

TSK replaces static keys with a **rotating, multi-segment key** where the format and position of the segments are themselves a server-side secret. A TSK key looks like a single opaque string, but it is actually composed of:
1.  **Static Segments**: Fixed alphanumeric strings.
2.  **TOTP Segments**: Time-based One-Time Passwords (valid for a specific time window).
3.  **HOTP Segments**: HMAC-based One-Time Passwords (valid for exactly one request).
4.  **Checksum**: An Ed25519 signature over the canonically serialized segments.

## Why it works

Even if an attacker intercepts a TSK key in transit:
*   They cannot replay it because the HOTP segment counter advances on every successful request.
*   They cannot forge a new key because they do not know the structural map (which segments are TOTP vs HOTP, what the segment lengths are, or where they are positioned).
*   They cannot tamper with the key because the Ed25519 checksum covers the entire payload.

The window of exploitation for a stolen TSK key is effectively **zero requests**.

## Packages

This repository contains a monorepo with four packages:

*   `@tsk/core`: Core cryptographic primitives, key assembly, and validation logic.
*   `@tsk/server`: Server middleware, Nonce Deduplication Store, and Anomaly Engine.
*   `@tsk/client-sdk`: Client SDK with automatic HOTP counter management and `fetch` wrapper.
*   `@tsk/bpc-bridge`: Ultra Bridge combining TSK and BPC into a 7-layer authentication stack.

## Getting Started

### 1. Provisioning
The server provisions a `TumblerMap` and generates a `ClientPayload` containing the shared secret and structural map. The `TumblerMap` stays on the server; the `ClientPayload` is sent to the client.

### 2. Client Usage
```typescript
import { TSKClient } from '@tsk/client-sdk';

const client = new TSKClient({
  clientId: 'tsk_12345',
  storage: myPersistentStorage
});

await client.init(provisionPayload, sharedSecret);

// The fetch wrapper automatically generates the key, adds headers,
// and advances the HOTP counters ONLY on a successful 2xx response.
const response = await client.fetch('https://api.example.com/data');
```

### 3. Server Validation
```typescript
import { verifyTSKRequest } from '@tsk/server';

const result = await verifyTSKRequest(req, tskStore);
if (!result.ok) {
  return res.status(401).json({ error: result.error });
}
```

## Security & Compliance
TSK is designed for high-security environments and relies exclusively on FIPS-approved algorithms (SHA-256, HMAC-SHA-256, Ed25519). See `SECURITY.md` for the Adversarial Break Report and compliance mappings.
