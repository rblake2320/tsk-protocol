# PostgreSQL Credential Authority

`PgHaTumblerMapStore` is the production HA adapter for the server's complete
`TumblerMapStore` contract. Each lifecycle or HOTP-counter mutation updates the
authoritative secret-bearing map and appends a signed, hash-linked TSK record in
the same SERIALIZABLE PostgreSQL transaction. The existing source lease is
rechecked immediately before commit, so a revoked or stale writer cannot commit
either side alone.

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
- Use `PgTskDurableOutbox` with a verified source-fence readiness capability.
- Keep source A, receiver B, and the control database in independent state
  authorities. Transport and promotion use the existing authenticated TSK HA
  path; this adapter does not create a second replication protocol.

The real-PG drill is `npm run test:credential-authority`. It fails rather than
skips when either independent PostgreSQL URL is absent.
