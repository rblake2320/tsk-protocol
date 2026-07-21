# PostgreSQL Credential Authority

`PgHaTumblerMapStore` is the production HA adapter for the server's complete
`TumblerMapStore` contract. Each lifecycle or HOTP-counter mutation updates the
authoritative secret-bearing map and appends a signed, hash-linked TSK record in
the same SERIALIZABLE PostgreSQL transaction. The existing source lease is
rechecked immediately before commit, so a revoked or stale writer cannot commit
either side alone.

The runtime role has no direct mutation rights on the credential tables or
outbox. It can invoke only fixed `SECURITY DEFINER` routines. Each atomic apply
requires a transaction-bound, five-second, single-use HMAC mutation ticket over
the exact signed record and credential effects. The ticket key is installed by
the provisioning identity, is unreadable by the runtime database role, and is
bound into an unforgeable runtime-boundary capability.

The replicated mutation is deliberately secret-free. It contains the public map,
its digest, a digest of the source secret, and the monotonic per-credential
revision. Node B verifies the operation digest, signed stream head, fence, global
sequence, head chain, and credential revision before staging it. Staged public
state cannot authenticate requests. Promotion must use the governed TSK cutover
and separately reprovision secret material through an approved custody channel.

## Deployment boundary

- Install `TSK_CREDENTIAL_AUTHORITY_SCHEMA` with a separate provisioning role.
- Run the application with no DDL privilege. Every owned operation pins the
  schema, holds `ACCESS SHARE` locks, and compares the live full catalog to the
  compiled PostgreSQL 16 manifest before reading or mutating authority state.
- Obtain `CredentialAuthorityReadyToken` only through
  `assertCredentialAuthorityReady`; it is bound to the exact transactor and
  schema and has no public mint helper.
- Provision the runtime mutation boundary with a dedicated key, retain that key
  only in the application signer/custody layer, and erase temporary provisioning
  copies. Re-run `assertCredentialRuntimeMutationBoundary` at startup.
- Construct `PgHaTumblerMapStore` with the attested outbox and credential tokens,
  the runtime-boundary token and signer, and a verified source-fence capability.
- Keep source A, receiver B, and the control database in independent state
  authorities. Transport and promotion use the existing authenticated TSK HA
  path; this adapter does not create a second replication protocol.

This slice establishes the source credential authority and secret-free receiver
staging. It does not by itself activate a promoted receiver as an authentication
authority. Enterprise activation remains gated on the signed cutover receipt,
secret reprovisioning under approved custody, and the Enterprise #28 acceptance
drill.

The real-PG drill is `npm run test:credential-authority`. It fails rather than
skips when either independent PostgreSQL URL is absent.
