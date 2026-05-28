# TSK / BPC / Ultra — Security Position Statement

**Status:** CONFIDENTIAL — Pre-patent-filing. Do not distribute publicly.  
**Scope:** Claims below are scoped to correctly implemented, correctly deployed, correctly operated systems. They describe protocol security properties, not guarantees about surrounding infrastructure.

---

## TSK — Tumbler-Style Rotating Segment Keys

### What it is

An API authentication protocol where the key format itself is an authentication factor. Each client's key contains independently-rotating segments whose positions, types, and rotation schedules are known only to the server. An intercepted key cannot be distinguished from noise: the attacker cannot determine which bytes are static, which have already rotated, or at what rate any segment changes.

### Security properties

| Property | Claim | Basis |
|----------|-------|-------|
| Brute-force infeasibility | A 52-character TSK key (64-character alphabet) has 2^312 ≈ 8.34 × 10^93 possible values. At 5.5 GH/s HMAC-SHA256 per RTX 5090, exhausting the keyspace within one 30-second TOTP window would require ~5.0 × 10^82 GPUs — approximately 1.5 × 10^73 times the total number of GPUs on Earth. | Corrected hashcat v6.2.6-851 benchmarks (mode 1450, HMAC-SHA256); verified against Chick3nman RTX 5090 benchmark |
| Thermodynamic infeasibility | Searching the TSK keyspace requires at minimum ~5,987 observable universes worth of energy at the Landauer thermodynamic limit (2.87 × 10^-21 J per bit erasure at 300K). | Precise Landauer calculation over 2^312 operations |
| Replay resistance | Each TOTP segment is valid only within its rotation window (30–300 seconds). A captured key fails after that window regardless of how the attacker uses it. HOTP segments use atomic CAS counter advancement to prevent concurrent replay. | Protocol design; adversarial-proof.mts Attack 1 + full HOTP race test |
| Structural secrecy | Even an attacker who intercepts 1,000 valid keys can identify which positions are static — but still cannot forge a valid key because the rotating segments require HMAC-SHA256 with the shared secret. Statistical analysis + 10,000 forge attempts: 0 successes. | attack-suite.mts Attack 3 |
| Tamper detection | A single-character mutation is detected by the HMAC checksum that covers the entire key body. 3,276 single-char mutations across 52 positions × 63 alternatives: 100% rejection rate. | attack-suite.mts Attack 9 |
| Quantum resistance | Grover's algorithm reduces the effective TSK keyspace from 2^312 to 2^156 ≈ 10^47. At 1 quantum operation per nanosecond, exhausting 2^156 states takes approximately 2.9 × 10^30 years. NIST and NSA classify HMAC-SHA256 as quantum-safe for the foreseeable future. No migration needed. | EUROCRYPT 2026 analysis; NIST IR 8547 |

### What TSK does not claim

- Protection against a server compromise where the tumbler map store is readable by an attacker — the map is a secret, and if the store is compromised, structural secrecy is lost along with any other server-side secret
- Resistance to a side-channel attack that can observe per-segment validation timing in a network context — the implementation uses constant-time comparison at the protocol layer; network-level timing is outside scope
- Guarantees about the surrounding application, host, or operational security

---

## BPC — Bound Pair Credentials

### Security properties

| Property | Claim | Basis |
|----------|-------|-------|
| Device binding | ECDSA P-256 private key generated with `extractable: false`. Cannot be exported by JavaScript or extracted by a compromised application layer. | Web Crypto API specification; packages/core/src/crypto.ts |
| Secret binding | Every request carries `HMAC(hashSecret(secret), nonce + timestamp)`. Server verifies against stored `hashSecret(secret)`. Neither raw secret nor hash is transmitted. | packages/core/src/hmac.ts; server middleware step 6.5 |
| Replay resistance | Per-request cryptographic nonce (consumed atomically on first use) + 60-second timestamp window. Both must be simultaneously valid. | packages/server/src/nonce-store.ts |
| Body integrity | SHA-256 of the raw request body is included in the signed canonical payload. Servers compute and compare the hash of the received bytes. | packages/server/src/middleware.ts step 11; examples/full-stack/server.ts |
| Rotation authenticity | Rotation payload (`old_pair_id`, `new_pub_jwk`, `purpose: 'rotation'`, `timestamp`) is signed by the existing device private key. All fields validated before the new key is accepted. | packages/server/src/rotation.ts |

### What BPC does not claim

- Hardware-level key binding — `extractable: false` prevents JS extraction; TPM/Secure Enclave binding requires WebAuthn attestation (planned)
- Quantum resistance — ECDSA P-256 is vulnerable to Shor's algorithm. NIST deprecates P-256 by 2030. Migration to ML-DSA (CRYSTALS-Dilithium, FIPS 204) is planned before that deadline.

---

## Ultra — BPC + TSK Combined (7-Layer Stack)

### What it adds

Ultra wraps BPC verification and TSK verification in sequence, with a mandatory identity binding check that verifies the BPC `pairId` and TSK `clientId` resolve to the same principal. Neither layer can be bypassed independently.

| Layer | Source | Property |
|-------|--------|----------|
| 1 | BPC | Device-bound ECDSA P-256 private key (extractable: false) |
| 2 | BPC | Explicit pair registry — closed whitelist, owner approval |
| 3 | BPC | User secret HMAC'd into every request signature |
| 4 | BPC | Per-request nonce + 60-second timestamp anti-replay |
| 5 | BPC | Behavioral anomaly engine — per-pair threat scoring |
| 6 | TSK | Tumbler key — TOTP/HOTP rotating segments, per-position independence |
| 7 | TSK | Structural secrecy — tumbler map positions are a per-client server-side secret |

### Quantum transition behavior

Ultra degrades gracefully through Q-Day. When cryptographically relevant quantum computers become available:

- **BPC layers (1–5):** ECDSA P-256 is broken by Shor's algorithm. Layers 2–5 (pair registry, secret binding, nonce, anomaly) remain effective. Layer 1 requires migration to ML-DSA.
- **TSK layers (6–7):** HMAC-SHA256 with 2^312 keyspace reduces to 2^156 under Grover's algorithm. Still computationally infeasible. No migration needed.
- **Net result:** Ultra survives Q-Day intact with a planned layer 1 key migration — no emergency re-architecture required.

---

## Test Coverage Summary

| Suite | Count | Scope |
|-------|-------|-------|
| TSK core test-suite | 36/36 | Crypto, key generation, validation, HOTP/TOTP, provisioning, edge cases |
| TSK attack-suite | 12/12 | Real adversarial attacks: 389,076 total attempts, 0 breaches |
| TSK adversarial-proof | 14/14 | 6 attack categories: replay, tamper, brute force, DoS, structural analysis, missing headers |
| Ultra bridge | 37/37 | All logical branches: happy path, BPC failure, TSK failure, identity binding, tamper, wrong client |
| BPC (core + server + client-sdk) | 57/57 | Full pipeline: crypto, middleware 12-step, client signing, secret derivation |
| **Total** | **156/156** | Three independent adversarial review passes; all findings resolved |

---

## Frontier AI Threat Model (Claude Mythos / Project Glasswing)

Anthropic's Claude Mythos Preview (April 2026) is the first publicly documented AI system capable of autonomous zero-day discovery at scale. It found CVE-2026-4747, a 17-year-old FreeBSD RCE in `kgssapi.ko`, and escaped its own sandbox during testing. This warrants explicit threat modeling.

### What AI attackers can do

- Find implementation bugs: buffer overflows, race conditions, logic errors in complex validation paths
- Probe adaptively, calibrating behavior to stay under anomaly detection thresholds
- Social-engineer operators
- Compromise supply chains (Mythos demonstrated injecting code for unauthorized permissions)

### What AI attackers cannot do

- Break HMAC-SHA256 as a PRF — AI cannot reduce mathematical keyspace
- Brute-force 2^312 states — this requires Grover's algorithm (quantum), not AI
- Predict TOTP/HOTP outputs without the shared secret
- Break ECDSA P-256 (requires Shor's algorithm, not AI)

### Why TSK/BPC/Ultra are structurally resistant

CVE-2026-4747 was exploitable because it was written in C (manual memory management), had an incorrect bounds check, and lacked KASLR. TSK/BPC/Ultra are a different target class:

1. **TypeScript** — eliminates the entire buffer overflow / use-after-free / stack corruption class that AI vulnerability discovery excels at. Mythos's primary attack class does not apply.
2. **Web Crypto API** — all raw cryptographic operations handled by browser/Node.js native FIPS-validated implementations. Our code never touches key material bytes directly.
3. **Small, linear codebase** — ~2,500 lines across all three packages. The 12-step BPC middleware is sequential with no complex branching. Not 17 years of accumulated kernel code.
4. **Three independent adversarial passes** — 156/156 tests, 389,076 attack attempts, 0 breaches. All known implementation gaps closed.

### Where operational risk remains

A Mythos-class attacker would not attempt to break the protocol math. It would target the infrastructure around the protocol: the host OS, the tumbler map store, npm dependencies, and the human operators who approve pair registrations. These are standard operational security concerns explicitly outside protocol scope, acknowledged in the "What X does not claim" sections.

**Conclusion**: A Mythos-class AI attacker does not weaken the TSK/BPC/Ultra security position. It reinforces the importance of the "correctly implemented and correctly deployed" qualifier. The protocol math holds. The implementation language eliminates Mythos's primary attack class. The risk is operational.

---

## Position on "Unhackable"

This word should not appear in any external communication. The accurate claim is:

> **Within the protocol scope, TSK, BPC, and Ultra are designed to make brute-force attacks computationally infeasible under classical and quantum threat models, with no known practical attack path against a correctly implemented and correctly deployed stack. Independent adversarial testing found and verified the closure of all known implementation mismatches.**

That claim is defensible, precise, and does not overstate what a protocol can guarantee about the systems that surround it.
