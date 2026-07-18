# Two-node authenticated outbox transport (#10, PR1)

`HttpOutboxTransport` + `createHttpOutboxReceiver` are the network implementation of
`TskOutboxTransport` — the publisher→receiver hop between two genuinely independent
nodes (node A durable-outbox authority → node B receiver authority). It is the **only**
A→B path in the two-node topology and is treated as fully untrusted.

## Request authentication (raw bytes before semantics)

Every request is HMAC-SHA256 signed under a `keyId` over a fixed, unambiguous string:

```
TSKv1\n POST \n <path> \n <timestamp> \n <nonce> \n <sha256(raw body) hex>
```

The receiver, **before parsing any JSON**:

1. requires `POST` + `Content-Type: application/json`, reads the body under a hard size cap;
2. resolves `keyId` → secret (returning a secret for several keyIds implements **rotation overlap**);
3. rejects a `timestamp` outside the freshness window;
4. constant-time compares the signature over the exact raw bytes;
5. rejects a **replayed nonce** via a durable single-use store (`PgReplayNonceStore`), so a
   receiver restart cannot reopen the replay window;
6. only then parses + structurally validates and applies the record.

Redirects are refused (`redirect: 'manual'`). Any auth failure is fail-closed with no
semantic processing.

## Decision-bound reply

The receiver replies with a `TskAckReceipt` whose signature binds the **decision** to this
exact record `(streamId, sourceEpoch, sequence, opDigest)`. The client verifies the receipt
binds and verifies its signature; a forged or swapped-decision receipt is rejected.

## Fail-closed ambiguity

A transient network / HTTP / timeout / oversize / malformed-reply condition **throws**
(`OutboxTransportError`, retriable) and **never fabricates an ack** — the outbox row stays
undelivered and is retried. If the request was applied on B but the reply was lost,
redelivery reconciles by the receiver's idempotency (`duplicate-ok`), so delivery is
exactly-once.

## Boundary

HMAC shared-secret is the PR1 mechanism; mTLS is a deployment upgrade. This is **not** an
HA claim. #10 stays **OPEN**: PR1 proves the authenticated transport, exactly-once under a
partition (dropped ACK), and receiver-unavailable retry, with measured RPO/RTO. Split-brain
fencing, node-A crash recovery, snapshot+tail resync, promotion convergence, and Redis
authority failover are PR2 — the full acceptance drill that closes #10.

## Evidence

- `npm run test:http-outbox -w packages/server` — hermetic loopback unit suite (auth reject,
  unknown key, replay, stale timestamp, forged/unbound ack, network error → retriable,
  rotation overlap).
- `npm run test:two-node` — two independent PG16 + the authenticated transport: happy A→B
  strict-ordered exactly-once, lost-ACK partition (RPO/RTO), node-B PostgreSQL down + recover.
