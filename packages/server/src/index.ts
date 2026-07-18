export * from './store.js';
export * from './provisioner.js';
export * from './anomaly.js';
export * from './middleware.js';
export * from './principal-session.js';
export * from './agent-cache.js';
export * from './replicating-tumbler-store.js';
export * from './replica-receiver.js';
export * from './promotion.js';
export * from './redis-fencing-store.js';
export * from './ha-outbox-contract.js';
// Explicit named exports for the durable HOTP-outbox — deliberately OMITS
// __internalUnsafeMintReadyToken so the public package API cannot mint an
// unattested readiness token (the hermetic tests import it via the module path).
export {
  TSK_HOTP_MAX_COUNTER,
  TSK_OUTBOX_SCHEMA_VERSION,
  TSK_OUTBOX_PG_SCHEMA,
  TSK_OUTBOX_SCHEMA_MANIFEST,
  GENESIS_HEAD,
  StreamHeadVerificationUnavailableError,
  PgTskDurableOutbox,
  UnfencedSingleNodeTskDurableOutbox,
  PgTskPublisher,
  PgTskReceiverCheckpoint,
  schemaManifest,
  attestSchema,
  assertSchemaReady,
  provisionSchemaVersion,
  adoptCurrentSchemaVersion,
} from './tsk-hotp-outbox-pg.js';
export {
  NodePostgresTransactor,
  AmbiguousCommitError,
  PostCommitReleaseError,
  ConnectionDisposalError,
} from './pg-transactor.js';
export type {
  NodePostgresPool,
  NodePostgresClient,
  NodePostgresResult,
  NodePostgresTransactorOptions,
} from './pg-transactor.js';
export type {
  TskPgBackend,
  PgTx,
  PgExecutor,
  PgTransactor,
  SchemaReadyToken,
  StreamHeadSigner,
  TskAckReceipt,
  TskAckReceiptVerifier,
  TskOutboxTransport,
  HotpApplier,
  PgTskOutboxOptions,
  SourceFenceGate,
  PgTskPublisherOptions,
  TskDrainResult,
} from './tsk-hotp-outbox-pg.js';
export {
  HttpOutboxTransport,
  OutboxTransportError,
  MemoryReplayNonceStore,
  PgReplayNonceStore,
  TSK_TRANSPORT_NONCE_SCHEMA,
  createHttpOutboxReceiver,
} from './http-outbox-transport.js';
export {
  HA_CONTROL_PG_SCHEMA,
  HA_CONTROL_TABLES,
  HA_CONTROL_MANIFEST_DIGEST,
  CONTROL_SCHEMA_VERSION,
  HaControlFencing,
  GuardSigner,
  verifyGuard,
  fenceTokenForEpoch,
  encodeEvidence,
  decodeEvidence,
  assertRedisAuthority,
  reconcileFencedRedis,
  provisionControlSchema,
  assertControlSchemaReady,
  FenceAuthorityQuarantineError,
} from './ha-control-fencing.js';
export {
  TSK_SOURCE_LEASE_SCHEMA,
  TSK_SOURCE_LEASE_TABLES,
  signLeaseGrant,
  installLeaseGrant,
  verifyLeaseGrant,
  readSourceLease,
  assertSourceLeaseWritable,
  computeSourceStateDigest,
  signSourceFrozenReceipt,
  verifySourceFrozenReceipt,
  emitSourceFrozenReceipt,
  TSK_SOURCE_WITNESS_SCHEMA,
  TSK_SOURCE_WITNESS_TABLES,
  readSourceWitness,
  assertSourceWitnessConsistent,
  advanceSourceWitness,
  verifySourceCheckpointReceipt,
  issueSourceCheckpointReceipt,
  SourceFenceQuarantineError,
  SOURCE_LEASE_MANIFEST_DIGEST,
  SOURCE_WITNESS_MANIFEST_DIGEST,
  attestSourceWitness,
  assertSourceFenceReady,
  requireSourceFenceReady,
  assertSourceWitnessReady,
  requireSourceWitnessReady,
} from './tsk-source-fence.js';
export type {
  SourceFenceReadyToken,
  SourceWitnessReadyToken,
  SourceVerifyKeyResolver,
  LeaseGrant,
  BareLeaseGrant,
  LeaseState as SourceLeaseState,
  SourceFrozenReceipt,
  SourceCheckpointReceipt,
  CheckpointIssueOptions,
  SourceLiveState,
  WitnessState as SourceWitnessState,
} from './tsk-source-fence.js';
export type {
  GuardKeyResolver,
  ControlSchemaReadyToken,
  HaControlPolicy,
  ProvisioningState,
  LeaseState,
  WitnessState,
  CutoverState,
  FenceProof,
  FenceEvidence,
} from './ha-control-fencing.js';
export type {
  ReplayNonceStore,
  FetchLike,
  FetchResponseLike,
  HttpOutboxTransportOptions,
  HttpOutboxReceiverOptions,
} from './http-outbox-transport.js';

import { MemoryTumblerStore } from './store.js';
import { TSKProvisioner } from './provisioner.js';
import { MemoryAnomalyEngine } from './anomaly.js';
import { MemoryPrincipalSessionLedger } from './principal-session.js';

export interface TSKServerInstance {
  store: MemoryTumblerStore;
  provisioner: TSKProvisioner;
  anomaly: MemoryAnomalyEngine;
  principalLedger: MemoryPrincipalSessionLedger;
}

/**
 * Factory function to create a TSK server with in-memory backends (dev/testing).
 * For production: replace with PgTumblerStore + Redis anomaly.
 */
export function createTSKServer(): TSKServerInstance {
  const store = new MemoryTumblerStore();
  const provisioner = new TSKProvisioner(store);
  const anomaly = new MemoryAnomalyEngine();
  const principalLedger = new MemoryPrincipalSessionLedger();
  return { store, provisioner, anomaly, principalLedger };
}
