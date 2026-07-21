import { createHash } from 'node:crypto';

import type { TumblerMap } from '@tsk/core';

import {
  ContractValidationError,
  assertStreamHeadBinds,
  canonicalize,
  canonicalOpDigest,
  type OutboxRecord,
  type PublisherBackpressure,
  type SignedStreamHead,
  type StreamHeadVerifier,
} from './ha-outbox-contract.js';
import {
  GENESIS_HEAD,
  PgTskDurableOutbox,
  StreamHeadVerificationUnavailableError,
  type PgExecutor,
  type PgTransactor,
  type SchemaReadyToken,
  type SourceFenceGate,
  type StreamHeadSigner,
} from './tsk-hotp-outbox-pg.js';
import { fenceTokenForEpoch } from './ha-control-fencing.js';
import { assertTumblerMapCounterState, commitValidationToMap, type TumblerMapStore, type ValidationCommitInput,
  type ValidationCommitResult } from './store.js';

const ID = /^[A-Za-z0-9_.:/-]{1,128}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SCHEMA = /^[a-z_][a-z0-9_]{0,62}$/;
const MAX_MAP_BYTES = 256 * 1024;
const CREDENTIAL_TABLES = ['tsk_credential_maps', 'tsk_credential_replica_maps'] as const;
/** Compiled PG16 catalog pin. Re-pin only through a reviewed schema change. */
export const CREDENTIAL_AUTHORITY_MANIFEST_DIGEST = '885ee55478a32f19497675d82de8a0d228108db6b6619c1017837e3f568bd614';

export const TSK_CREDENTIAL_AUTHORITY_SCHEMA = `
CREATE TABLE IF NOT EXISTS tsk_credential_maps (
  client_id TEXT PRIMARY KEY,
  map JSONB NOT NULL,
  revision BIGINT NOT NULL CHECK (revision >= 1 AND revision <= 2147483647),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
CREATE TABLE IF NOT EXISTS tsk_credential_replica_maps (
  stream_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  public_map JSONB NOT NULL,
  public_map_digest TEXT NOT NULL CHECK (public_map_digest ~ '^[0-9a-f]{64}$'),
  secret_digest TEXT NOT NULL CHECK (secret_digest ~ '^[0-9a-f]{64}$'),
  source_epoch TEXT NOT NULL,
  sequence BIGINT NOT NULL CHECK (sequence >= 1),
  revision BIGINT NOT NULL CHECK (revision >= 1 AND revision <= 2147483647),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT pg_catalog.clock_timestamp(),
  PRIMARY KEY(stream_id, client_id)
);
`;

export type CredentialMutation = {
  kind: 'tsk.credential.snapshot.v1';
  clientId: string;
  tumblerId: string;
  counter: number;
  publicMap: Record<string, unknown>;
  publicMapDigest: string;
  secretDigest: string;
} | {
  kind: 'tsk.credential.delete.v1';
  clientId: string;
  tumblerId: string;
  counter: number;
};

const READY = new WeakMap<object, { db: PgTransactor; schema: string }>();
export interface CredentialAuthorityReadyToken { readonly __credentialAuthorityReady: never }

function id(value: unknown, name: string): string {
  if (typeof value !== 'string' || !ID.test(value)) throw new ContractValidationError(`${name} invalid`);
  return value;
}

function plain(value: unknown, name: string): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype || Object.getOwnPropertySymbols(value).length) {
    throw new ContractValidationError(`${name} must be exact plain data`);
  }
  return value as Record<string, unknown>;
}

function exact(value: Record<string, unknown>, expected: string[], name: string): void {
  const keys = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (keys.length !== wanted.length || keys.some((key, index) => key !== wanted[index])) {
    throw new ContractValidationError(`${name} has an invalid shape`);
  }
}

function cloneJson<T>(value: T, name: string): T {
  const visit = (input: unknown, depth: number): unknown => {
    if (depth > 32) throw new ContractValidationError(`${name} exceeds maximum depth`);
    if (input === null || typeof input === 'string' || typeof input === 'boolean') return input;
    if (typeof input === 'number' && Number.isFinite(input)) return input;
    if (!input || typeof input !== 'object') throw new ContractValidationError(`${name} must be JSON data`);
    if (Object.getOwnPropertySymbols(input).length) throw new ContractValidationError(`${name} contains symbols`);
    if (Array.isArray(input)) return input.map((item) => visit(item, depth + 1));
    if (Object.getPrototypeOf(input) !== Object.prototype) {
      throw new ContractValidationError(`${name} must be exact plain data`);
    }
    const output: Record<string, unknown> = {};
    for (const key of Object.keys(input)) {
      const descriptor = Object.getOwnPropertyDescriptor(input, key);
      if (!descriptor || !('value' in descriptor) || descriptor.get || descriptor.set) {
        throw new ContractValidationError(`${name} contains an accessor`);
      }
      if (descriptor.value === undefined) continue;
      output[key] = visit(descriptor.value, depth + 1);
    }
    return output;
  };
  const snapshot = visit(value, 0) as T;
  if (Buffer.byteLength(canonicalize(snapshot), 'utf8') > MAX_MAP_BYTES) {
    throw new ContractValidationError(`${name} exceeds ${MAX_MAP_BYTES} bytes`);
  }
  return snapshot;
}

function digest(value: unknown): string {
  return createHash('sha256').update(canonicalize(value), 'utf8').digest('hex');
}

function containsSecret(value: unknown, key = ''): boolean {
  if (/(?:secret|password|private|credential|token)/i.test(key)) return true;
  if (Array.isArray(value)) return value.some((item) => containsSecret(item));
  if (value && typeof value === 'object') {
    return Object.entries(value).some(([childKey, child]) => containsSecret(child, childKey));
  }
  return false;
}

function publicSnapshot(map: TumblerMap): Omit<Extract<CredentialMutation,
  { kind: 'tsk.credential.snapshot.v1' }>, 'kind' | 'clientId' | 'tumblerId' | 'counter'> {
  const source = cloneJson(map, 'TSK credential map') as unknown as Record<string, unknown>;
  const clientId = id(source.clientId, 'map.clientId');
  if (typeof source.sharedSecret !== 'string' || source.sharedSecret.length < 32) {
    throw new ContractValidationError('TSK credential sharedSecret invalid');
  }
  const secretDigest = createHash('sha256').update(source.sharedSecret, 'utf8').digest('hex');
  delete source.sharedSecret;
  if (Array.isArray(source.segments)) {
    for (const raw of source.segments) {
      if (raw && typeof raw === 'object') {
        delete (raw as Record<string, unknown>).secret;
        delete (raw as Record<string, unknown>).key;
      }
    }
  }
  if (source.clientId !== clientId || containsSecret(source)) {
    throw new ContractValidationError('TSK public credential snapshot contains secret material');
  }
  return { publicMap: source, publicMapDigest: digest(source), secretDigest };
}

function sanitizeMutation(value: unknown): CredentialMutation {
  const raw = plain(cloneJson(value, 'credential mutation'), 'credential mutation');
  if (raw.kind === 'tsk.credential.delete.v1') {
    exact(raw, ['kind', 'clientId', 'counter', 'tumblerId'], String(raw.kind));
    const clientId = id(raw.clientId, 'clientId');
    if (raw.tumblerId !== clientId || !Number.isSafeInteger(raw.counter) ||
        (raw.counter as number) < 1 || (raw.counter as number) > 2_147_483_647) {
      throw new ContractValidationError('credential delete revision invalid');
    }
    return { kind: raw.kind, clientId, tumblerId: clientId, counter: raw.counter as number };
  }
  if (raw.kind !== 'tsk.credential.snapshot.v1') {
    throw new ContractValidationError('unsupported credential mutation');
  }
  exact(raw, ['kind', 'clientId', 'counter', 'publicMap', 'publicMapDigest',
    'secretDigest', 'tumblerId'], String(raw.kind));
  const clientId = id(raw.clientId, 'clientId');
  const publicMap = plain(raw.publicMap, 'publicMap');
  if (publicMap.clientId !== clientId || Object.hasOwn(publicMap, 'sharedSecret') || containsSecret(publicMap) ||
      typeof raw.publicMapDigest !== 'string' || !HEX64.test(raw.publicMapDigest) ||
      digest(publicMap) !== raw.publicMapDigest || typeof raw.secretDigest !== 'string' ||
      !HEX64.test(raw.secretDigest) || raw.tumblerId !== clientId ||
      !Number.isSafeInteger(raw.counter) || (raw.counter as number) < 1 ||
      (raw.counter as number) > 2_147_483_647) {
    throw new ContractValidationError('credential snapshot is not exact, bound, and secret-free');
  }
  return { kind: raw.kind, clientId, tumblerId: clientId, counter: raw.counter as number,
    publicMap, publicMapDigest: raw.publicMapDigest, secretDigest: raw.secretDigest };
}

export const credentialMutationSanitizer = Object.freeze({
  sanitize: sanitizeMutation,
  assertSanitized(value: unknown): asserts value is CredentialMutation {
    const clean = sanitizeMutation(value);
    if (canonicalize(clean) !== canonicalize(value)) {
      throw new ContractValidationError('credential mutation is not exactly sanitized');
    }
  },
});

async function enter(exec: PgExecutor, schema: string): Promise<void> {
  if (!SCHEMA.test(schema)) throw new ContractValidationError('schema invalid');
  const isolation = String((await exec.query('SHOW transaction_isolation')).rows[0]?.transaction_isolation ?? '').toLowerCase();
  if (isolation !== 'serializable') throw new ContractValidationError('credential authority requires SERIALIZABLE');
  await exec.query("SELECT pg_catalog.set_config('search_path',$1,true)", [`${schema},pg_temp`]);
  const current = (await exec.query('SELECT pg_catalog.current_schema() AS schema')).rows[0]?.schema;
  if (current !== schema) throw new ContractValidationError('credential authority schema context mismatch');
  await exec.query('LOCK TABLE tsk_credential_maps, tsk_credential_replica_maps IN ACCESS SHARE MODE');
  const manifest = await credentialAuthorityManifest(exec);
  const actual = createHash('sha256').update(manifest, 'utf8').digest('hex');
  if (actual !== CREDENTIAL_AUTHORITY_MANIFEST_DIGEST) {
    throw new ContractValidationError(`credential authority attestation failed: live catalog digest ${actual} != pinned ${CREDENTIAL_AUTHORITY_MANIFEST_DIGEST}`);
  }
}

async function credentialAuthorityManifest(exec: PgExecutor): Promise<string> {
  const tables = [...CREDENTIAL_TABLES];
  const rel = (await exec.query(
    `SELECT rel.relname AS t,rel.relkind,rel.relpersistence,rel.relrowsecurity,rel.relforcerowsecurity
       FROM pg_catalog.pg_class rel JOIN pg_catalog.pg_namespace ns ON ns.oid=rel.relnamespace
      WHERE ns.nspname=pg_catalog.current_schema() AND rel.relname=ANY($1)`, [tables])).rows;
  const cols = (await exec.query(
    `SELECT table_name,ordinal_position,column_name,data_type,is_nullable,COALESCE(column_default,'') AS d
       FROM information_schema.columns WHERE table_schema=pg_catalog.current_schema() AND table_name=ANY($1)`, [tables])).rows;
  const cons = (await exec.query(
    `SELECT rel.relname AS t,c.contype,pg_catalog.pg_get_constraintdef(c.oid) AS def
       FROM pg_catalog.pg_constraint c JOIN pg_catalog.pg_class rel ON rel.oid=c.conrelid
       JOIN pg_catalog.pg_namespace ns ON ns.oid=rel.relnamespace
      WHERE ns.nspname=pg_catalog.current_schema() AND rel.relname=ANY($1) AND c.contype IN ('p','c','u','f')`, [tables])).rows;
  const idx = (await exec.query(
    `SELECT tablename AS t,indexname AS n,indexdef AS def FROM pg_catalog.pg_indexes
      WHERE schemaname=pg_catalog.current_schema() AND tablename=ANY($1)`, [tables])).rows;
  const trg = (await exec.query(
    `SELECT rel.relname AS t,tg.tgname AS n,pg_catalog.pg_get_triggerdef(tg.oid) AS def,tg.tgenabled
       FROM pg_catalog.pg_trigger tg JOIN pg_catalog.pg_class rel ON rel.oid=tg.tgrelid
       JOIN pg_catalog.pg_namespace ns ON ns.oid=rel.relnamespace
      WHERE ns.nspname=pg_catalog.current_schema() AND rel.relname=ANY($1) AND NOT tg.tgisinternal`, [tables])).rows;
  const pol = (await exec.query(
    `SELECT tablename AS t,policyname AS n,permissive,roles::text AS roles,cmd,COALESCE(qual,'') AS qual,COALESCE(with_check,'') AS wc
       FROM pg_catalog.pg_policies WHERE schemaname=pg_catalog.current_schema() AND tablename=ANY($1)`, [tables])).rows;
  const present = rel.map((row) => String(row.t)).sort();
  const lines = [`PRESENT|${present.join(',')}|n=${present.length}`,
    ...rel.map((r) => `R|${r.t}|${r.relkind}|${r.relpersistence}|${r.relrowsecurity}|${r.relforcerowsecurity}`),
    ...cols.map((r) => `C|${r.table_name}|${r.ordinal_position}|${r.column_name}|${r.data_type}|${r.is_nullable}|${r.d}`),
    ...cons.map((r) => `K|${r.t}|${r.contype}|${r.def}`),
    ...idx.map((r) => `I|${r.t}|${r.n}|${r.def}`),
    ...trg.map((r) => `T|${r.t}|${r.n}|${r.tgenabled}|${r.def}`),
    ...pol.map((r) => `P|${r.t}|${r.n}|${r.permissive}|${r.roles}|${r.cmd}|${r.qual}|${r.wc}`)];
  lines.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return ['Vcredential_authority/1', ...lines].join('\n');
}

export async function assertCredentialAuthorityReady(
  db: PgTransactor, schema: string,
): Promise<CredentialAuthorityReadyToken> {
  await db.transaction((exec) => enter(exec, schema));
  const token = Object.freeze({}) as CredentialAuthorityReadyToken;
  READY.set(token as object, { db, schema });
  return token;
}

function requireReady(token: CredentialAuthorityReadyToken, db: PgTransactor, schema: string): void {
  const state = READY.get(token as object);
  if (!state || state.db !== db || state.schema !== schema) {
    throw new ContractValidationError('invalid credential-authority readiness capability');
  }
}

export interface PgHaTumblerMapStoreOptions {
  streamId: string;
  sourceEpoch: number;
  signer: StreamHeadSigner;
  maxPendingRows?: number;
  backpressure?: PublisherBackpressure;
  schema?: string;
}

export class PgHaTumblerMapStore implements TumblerMapStore {
  readonly outbox: PgTskDurableOutbox;
  private readonly schema: string;
  private readonly streamId: string;
  private readonly fenceToken: bigint;

  constructor(
    private readonly db: PgTransactor,
    outboxReady: SchemaReadyToken,
    credentialReady: CredentialAuthorityReadyToken,
    options: PgHaTumblerMapStoreOptions,
    fence: SourceFenceGate,
  ) {
    this.schema = options.schema ?? 'public';
    requireReady(credentialReady, db, this.schema);
    this.streamId = id(options.streamId, 'streamId');
    if (!Number.isSafeInteger(options.sourceEpoch) || options.sourceEpoch < 0 || options.sourceEpoch > 2 ** 40) {
      throw new ContractValidationError('sourceEpoch invalid');
    }
    this.fenceToken = BigInt(fenceTokenForEpoch(options.sourceEpoch));
    this.outbox = new PgTskDurableOutbox(db, outboxReady, {
      streamId: this.streamId,
      sanitizer: credentialMutationSanitizer as never,
      signer: options.signer,
      maxPendingRows: options.maxPendingRows ?? 10_000,
      backpressure: options.backpressure ?? 'fail-authoritative-mutation',
    }, fence);
  }

  private async readInTx(exec: PgExecutor, clientId: string, lock = false): Promise<{
    map: TumblerMap; revision: number;
  } | null> {
    const row = (await exec.query(
      `SELECT map,revision FROM tsk_credential_maps WHERE client_id=$1${lock ? ' FOR UPDATE' : ''}`,
      [id(clientId, 'clientId')],
    )).rows[0];
    return row ? { map: cloneJson(row.map as TumblerMap, 'stored credential map'),
      revision: Number(row.revision) } : null;
  }

  private async persist(tx: unknown, exec: PgExecutor, map: TumblerMap, revision: number): Promise<void> {
    const clientId = id(map.clientId, 'map.clientId');
    if (!Number.isSafeInteger(revision) || revision < 1 || revision > 2_147_483_647) {
      throw new ContractValidationError('credential revision exhausted');
    }
    assertTumblerMapCounterState(map);
    const mutation = sanitizeMutation({ kind: 'tsk.credential.snapshot.v1', clientId,
      tumblerId: clientId, counter: revision,
      ...publicSnapshot(map) });
    await this.outbox.appendInTx(tx as never, {
      streamId: this.streamId, rawMutation: mutation as never, fenceToken: this.fenceToken,
    });
    await exec.query(
      `INSERT INTO tsk_credential_maps(client_id,map,revision) VALUES($1,$2::jsonb,$3)
       ON CONFLICT(client_id) DO UPDATE SET map=EXCLUDED.map,revision=EXCLUDED.revision,
         updated_at=pg_catalog.clock_timestamp()`,
      [clientId, JSON.stringify(map), revision],
    );
  }

  async get(clientId: string): Promise<TumblerMap | null> {
    return this.db.transaction(async (exec) => {
      await enter(exec, this.schema);
      return (await this.readInTx(exec, clientId))?.map ?? null;
    });
  }

  async list(): Promise<string[]> {
    return this.db.transaction(async (exec) => {
      await enter(exec, this.schema);
      return (await exec.query('SELECT client_id FROM tsk_credential_maps ORDER BY client_id COLLATE "C"'))
        .rows.map((row) => String(row.client_id));
    });
  }

  async set(clientId: string, value: TumblerMap): Promise<void> {
    const incoming = cloneJson(value, 'credential map');
    if (incoming.clientId !== clientId) throw new ContractValidationError('credential clientId mismatch');
    await this.outbox.withOutboxTx(async (tx, exec) => {
      await enter(exec, this.schema);
      const currentRow = await this.readInTx(exec, clientId, true);
      const current = currentRow?.map;
      if (current) {
        const counters = new Map(current.segments.filter((s) => s.type === 'hotp')
          .map((s) => [s.segmentId, s.counter ?? 0]));
        for (const segment of incoming.segments) {
          if (segment.type === 'hotp' && counters.has(segment.segmentId)) {
            segment.counter = Math.max(segment.counter ?? 0, counters.get(segment.segmentId)!);
          }
        }
        const currentCount = current.requestCount ?? 0, incomingCount = incoming.requestCount ?? 0;
        const currentUsed = current.lastUsedAt ?? 0, incomingUsed = incoming.lastUsedAt ?? 0;
        incoming.requestCount = incomingUsed > currentUsed
          ? Math.max(incomingCount, currentCount + 1) : Math.max(incomingCount, currentCount);
        if (currentUsed > incomingUsed) incoming.lastUsedAt = current.lastUsedAt;
      }
      await this.persist(tx, exec, incoming, (currentRow?.revision ?? 0) + 1);
    });
  }

  async delete(clientId: string): Promise<void> {
    await this.outbox.withOutboxTx(async (tx, exec) => {
      await enter(exec, this.schema);
      const deleted = await exec.query(
        'DELETE FROM tsk_credential_maps WHERE client_id=$1 RETURNING client_id,revision', [id(clientId, 'clientId')],
      );
      if (deleted.rowCount === 0) return;
      await this.outbox.appendInTx(tx, { streamId: this.streamId,
        rawMutation: { kind: 'tsk.credential.delete.v1', clientId, tumblerId: clientId,
          counter: Number(deleted.rows[0]!.revision) + 1 } as never,
        fenceToken: this.fenceToken });
    });
  }

  async updateCounters(clientId: string, updates: Map<string, number>): Promise<void> {
    await this.outbox.withOutboxTx(async (tx, exec) => {
      await enter(exec, this.schema);
      const row = await this.readInTx(exec, clientId, true);
      if (!row) return;
      for (const segment of row.map.segments) {
        if (segment.type === 'hotp' && updates.has(segment.segmentId)) {
          const next = updates.get(segment.segmentId)!;
          if (!Number.isSafeInteger(next) || next < (segment.counter ?? 0) || next > 2_147_483_647) {
            throw new ContractValidationError('HOTP counter update must be monotonic and bounded');
          }
          segment.counter = next;
        }
      }
      await this.persist(tx, exec, row.map, row.revision + 1);
    });
  }

  async consumeCounter(clientId: string, segmentId: string, matchedCounter: number): Promise<boolean> {
    return this.outbox.withOutboxTx(async (tx, exec) => {
      await enter(exec, this.schema);
      const row = await this.readInTx(exec, clientId, true);
      if (!row) return false;
      const segment = row.map.segments.find((s) => s.segmentId === segmentId);
      if (!segment || segment.type !== 'hotp' || (segment.counter ?? 0) > matchedCounter) return false;
      segment.counter = matchedCounter + 1;
      await this.persist(tx, exec, row.map, row.revision + 1);
      return true;
    });
  }

  async commitValidation(clientId: string, input: ValidationCommitInput): Promise<ValidationCommitResult> {
    return this.outbox.withOutboxTx(async (tx, exec) => {
      await enter(exec, this.schema);
      const row = await this.readInTx(exec, clientId, true);
      if (!row) return { ok: false, error: 'TSK_KEY_EXPIRED' };
      const result = commitValidationToMap(row.map, input);
      await this.persist(tx, exec, row.map, row.revision + 1);
      return result;
    });
  }

  async replaceCredential(oldClientId: string, replacement: TumblerMap): Promise<boolean> {
    const next = cloneJson(replacement, 'replacement credential map');
    return this.outbox.withOutboxTx(async (tx, exec) => {
      await enter(exec, this.schema);
      const oldRow = await this.readInTx(exec, oldClientId, true);
      if (!oldRow || (oldRow.map.status !== undefined && oldRow.map.status !== 'active' && oldRow.map.status !== 'expiring')) return false;
      if (await this.readInTx(exec, next.clientId, true)) return false;
      oldRow.map.status = 'revoked';
      await this.persist(tx, exec, oldRow.map, oldRow.revision + 1);
      await this.persist(tx, exec, next, 1);
      return true;
    });
  }
}

export class PgTskCredentialReceiverCheckpoint {
  constructor(
    private readonly db: PgTransactor,
    private readonly streamId: string,
    private readonly verifier: StreamHeadVerifier,
    private readonly outboxReady: SchemaReadyToken,
    private readonly credentialReady: CredentialAuthorityReadyToken,
    private readonly schema = 'public',
  ) {
    id(streamId, 'streamId');
    requireReady(credentialReady, db, schema);
    void outboxReady;
  }

  async verifyAndApplyDelivered(
    recordValue: OutboxRecord<CredentialMutation>, headValue: SignedStreamHead,
  ): Promise<'applied' | 'duplicate-ok' | 'reject-gap' | 'reject-fence' | 'reject-fork'> {
    const record = cloneJson(recordValue, 'credential record');
    const head = cloneJson(headValue, 'credential head');
    return this.db.transaction(async (exec) => {
      await enter(exec, this.schema);
      let mutation: CredentialMutation;
      try {
        mutation = sanitizeMutation(record.mutation);
        if (canonicalize(mutation) !== canonicalize(record.mutation) ||
            canonicalOpDigest({ ...record, mutation: mutation as never }) !== record.opDigest) {
          return 'reject-fork';
        }
        assertStreamHeadBinds(record, head);
        await this.verifier.verify(head);
      } catch (error) {
        if (error instanceof StreamHeadVerificationUnavailableError) throw error;
        return 'reject-fork';
      }
      const cp = (await exec.query(
        'SELECT source_epoch,sequence,head_digest FROM tsk_outbox_receiver_checkpoint WHERE stream_id=$1 FOR UPDATE',
        [this.streamId],
      )).rows[0];
      const fence = (await exec.query(
        'SELECT fence_token::text FROM tsk_outbox_fence WHERE stream_id=$1 FOR UPDATE', [this.streamId],
      )).rows[0];
      if (!cp || !fence || fence.fence_token !== record.fenceToken) return 'reject-fence';
      const expected = Number(cp.sequence) + 1;
      if (record.sequence < expected) {
        const prior = (await exec.query(
          'SELECT op_digest FROM tsk_outbox_applied WHERE stream_id=$1 AND source_epoch=$2 AND sequence=$3',
          [this.streamId, record.sourceEpoch, record.sequence],
        )).rows[0];
        return prior?.op_digest === record.opDigest ? 'duplicate-ok' : 'reject-fork';
      }
      if (record.sequence !== expected) return 'reject-gap';
      if (String(cp.source_epoch) !== record.sourceEpoch ||
          String(cp.head_digest || GENESIS_HEAD) !== head.prevHeadDigest) return 'reject-fork';
      const current = (await exec.query(
        'SELECT revision FROM tsk_credential_replica_maps WHERE stream_id=$1 AND client_id=$2 FOR UPDATE',
        [this.streamId, mutation.clientId],
      )).rows[0];
      const expectedRevision = current ? Number(current.revision) + 1 : 1;
      if (mutation.counter !== expectedRevision) return 'reject-fork';
      if (mutation.kind === 'tsk.credential.delete.v1') {
        if (!current) return 'reject-fork';
        await exec.query('DELETE FROM tsk_credential_replica_maps WHERE stream_id=$1 AND client_id=$2',
          [this.streamId, mutation.clientId]);
      } else {
        await exec.query(
          `INSERT INTO tsk_credential_replica_maps
             (stream_id,client_id,public_map,public_map_digest,secret_digest,source_epoch,sequence,revision)
           VALUES($1,$2,$3::jsonb,$4,$5,$6,$7,$8)
           ON CONFLICT(stream_id,client_id) DO UPDATE SET public_map=EXCLUDED.public_map,
             public_map_digest=EXCLUDED.public_map_digest,secret_digest=EXCLUDED.secret_digest,
             source_epoch=EXCLUDED.source_epoch,sequence=EXCLUDED.sequence,revision=EXCLUDED.revision,
             updated_at=pg_catalog.clock_timestamp()`,
          [this.streamId, mutation.clientId, JSON.stringify(mutation.publicMap),
            mutation.publicMapDigest, mutation.secretDigest, record.sourceEpoch, record.sequence,
            mutation.counter],
        );
      }
      await exec.query(
        'INSERT INTO tsk_outbox_applied(stream_id,source_epoch,sequence,op_digest) VALUES($1,$2,$3,$4)',
        [this.streamId, record.sourceEpoch, record.sequence, record.opDigest],
      );
      await exec.query(
        'UPDATE tsk_outbox_receiver_checkpoint SET sequence=$2,head_digest=$3 WHERE stream_id=$1',
        [this.streamId, record.sequence, head.headDigest],
      );
      return 'applied';
    });
  }
}
