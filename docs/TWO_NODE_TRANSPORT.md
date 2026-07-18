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

## Error taxonomy (enforced by the publisher)

Every failure throws an `OutboxTransportError` carrying `retriable`, and **never fabricates
an ack**. `PgTskPublisher.drainOnce` enforces the taxonomy (via the core
`isTerminalTransportError` contract):

| Condition | `retriable` | Publisher action |
|---|---|---|
| network error, connect refused, timeout/deadline | **true** (transient) | leave row undelivered, retry next drain |
| HTTP 5xx, 408 (request timeout), 429 (too many requests) | **true** (transient) | leave row undelivered, retry |
| HTTP 3xx redirect, 401/403/404 and all other 4xx | **false** (terminal) | **quarantine + durably halt** the stream (`reject-transport-terminal`) |
| unknown response key, envelope MAC invalid, receipt malformed/unbound, stale challenge, bad content-type/JSON | **false** (terminal) | **quarantine + halt** |
| request body over `maxRequestBytes` (client preflight) | **false** (terminal) | quarantine + halt (never dispatched) |

A **transient** failure leaves the row undelivered and never acked; if the request was
applied on B but the reply was lost, redelivery reconciles by the receiver's idempotency
(`duplicate-ok`), so delivery is exactly-once. A **terminal** failure can never succeed, so
the publisher quarantines the row and halts the stream rather than retry it forever.

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
