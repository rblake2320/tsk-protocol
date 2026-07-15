# TSK, BPC, And Composed Verification: Security Position

## Bounded Position

TSK and BPC are independent beta protocol implementations. TSK authenticates a
shared secret and synchronized rotating state. BPC authenticates possession of
an authorized pair signing key and request-bound secret material. The bridge
accepts a request only when both verifiers succeed and their identifiers resolve
to the same principal.

The composition adds independent checks; it does not turn either credential into
hardware identity, establish compliance, or make the surrounding system secure.

## TSK

- Generated maps have at least one single-use counter component.
- Counter updates and usage caps commit atomically in bundled stores.
- Replacement is fail-closed without an external authorizer and revokes the old
  credential atomically when authorized.
- Layout is visible to the provisioned client and is not an authentication
  factor.
- Shared-secret compromise defeats TSK until replacement/revocation completes.

## BPC

- The signed request binds method, path, body digest, pair identifier,
  timestamp, nonce, and protocol version.
- Shared nonce state is required across every verifier that can accept the same
  pair.
- WebCrypto `extractable: false` limits ordinary API export. It is not hardware
  attestation or physical-device identity.

## Composition

- BPC failure denies before TSK acceptance.
- TSK failure denies after BPC success.
- Missing or mismatched identity binding denies.
- Downstream application authorization must still enforce the verified BPC
  scope and resource policy.

## Evidence

The test suites exercise finite named replay, tamper, lifecycle, concurrency,
identity mismatch, replication, promotion, and restart cases. Zero failures in
those cases is evidence for those cases only. It is not proof that every attack
has been discovered or that a deployment is authorized.
