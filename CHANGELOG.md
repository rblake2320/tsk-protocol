# Changelog

All notable changes to the TSK Protocol will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-05-27

### Added
- **HIGH-06**: Added `SECURITY.md` detailing the adversarial break history (TSK-01 through TSK-07), IL4-7 compliance mapping, and secure deployment recommendations.
- **HIGH-01**: Added lifecycle management fields (`status`, `expiresAt`, `maxRequests`, `label`) to `TSKClientRecord`.
- Added Ultra Server lifecycle API endpoints (`GET /tsk/keys`, `PATCH /tsk/keys/:clientId`) for programmatic key management and revocation.
- Added `requestCount` tracking to enforce `maxRequests` quota limits.

### Changed
- **HIGH-03**: Updated the Ultra Bridge (`verifyUltraRequest`) to extract and propagate the BPC `scope` field to `UltraVerifyResult`, enabling cross-layer scope coherence enforcement.
- Updated `verifyTSKRequest` to enforce `expiresAt` and `maxRequests` constraints before cryptographic validation.

### Fixed
- Fixed HOTP client desynchronization on network failure (Adversarial Break Report 2.2) by implementing the commit-after-success pattern in the client SDK `fetch` wrapper.

## [1.0.0] - 2026-05-20

### Added
- Initial release of the TSK (Tumbler Secret Key) Protocol.
- Client SDK with automatic HOTP counter management and `fetch` wrapper.
- Server middleware with Ed25519 signature verification and Nonce Deduplication Store.
- BPC Bridge (`ultra-verify`) combining BPC and TSK into a 7-layer authentication stack.
- Adversarial Break Report documenting the mitigation of 7 identified attack vectors.
