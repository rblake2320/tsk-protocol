# Parked Claims And Designs

Git history preserves the original wording. Items here are not active product or
security claims.

## P-001: Structural secrecy

- **Parked:** ordered segment layout as a server-only authentication factor.
- **Reason:** the provisioned client receives lengths in positional order and can
  reconstruct boundaries by cumulative sum.
- **Current claim:** the server retains authoritative secret, counter, and
  lifecycle state; forgery resistance depends on the shared secret, not layout.
- **Restore only with:** a new protocol that lets the client generate a valid
  request without receiving data that reconstructs the protected structure,
  plus an independent cryptographic analysis and interoperability tests.

## P-002: Ed25519 checksum

- **Parked:** describing the final key characters as an Ed25519 signature.
- **Reason:** the implementation truncates HMAC-SHA-256 output.
- **Current claim:** truncated integrity tag, not signature/non-repudiation.

## P-003: FIPS, Impact Level, and regulatory compliance

- **Parked:** product-level FIPS validation, FedRAMP, DoD IL, HIPAA, PCI DSS,
  SOC 2, ISO 27001, or similar status.
- **Reason:** algorithms and tests do not establish a validated module,
  assessed deployment, authorization boundary, audit opinion, or ATO.
- **Restore only with:** exact deployment evidence and the applicable qualified
  external determination.

## P-004: BPC hardware/device identity

- **Parked:** describing `extractable: false` as TPM or device identity.
- **Reason:** WebCrypto non-exportability is not hardware attestation.
- **Restore only with:** implemented attestation, certificate validation,
  device-policy binding, revocation, and runtime evidence.

## P-005: Honeypot segments and automatic active defense

- **Parked:** decoy segments, automatic anomaly rotation, federated alerts, and
  performance/false-positive metrics.
- **Reason:** these behaviors and measurements are not implemented in this repo.

## P-006: Patent status and prior-art conclusions

- **Parked:** runtime claims of filing status, patent-pending status, or no
  equivalent prior art.
- **Reason:** legal status and novelty require the controlling filing records and
  a qualified legal/prior-art analysis, not a software test.
- **Restore only with:** counsel-approved wording linked to dated records.

## P-007: Post-expiry grace mode

- **Parked:** allowing requests after the hard cap while rotation occurs.
- **Reason:** it converts a hard security boundary into a fail-open path.
- **Current design:** pre-cap warning plus authorized atomic replacement.

## P-008: Production HA from the bundled volatile queue

- **Parked:** treating an empty in-memory retry queue as sufficient promotion
  evidence after restart or host loss.
- **Reason:** the primary mutation and replication enqueue are not one durable
  transaction, and receiver apply/checkpoint persistence is deployment-owned.
- **Current design:** promotion evidence fails closed unless a deployment
  supplies positive transactional durability evidence; writer fencing remains
  independently enforced.
- **Restore only with:** a durable transactional outbox in the primary authority,
  atomic receiver apply/checkpoint persistence, crash/restart fault injection,
  backup/restore evidence, and loss/reordering tests against the selected stores.
