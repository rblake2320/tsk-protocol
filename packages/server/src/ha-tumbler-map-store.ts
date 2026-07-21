import { createHash, createHmac, randomBytes } from 'node:crypto';

import type { TumblerMap } from '@tsk/core';
import { assertValidHOTPStoredCounter, isUsableHOTPDerivationCounter,
  minimumHOTPUsesRemaining } from '@tsk/core';

import {
  ContractValidationError,
  assertHeaderConformant,
  assertStreamHeadBinds,
  canonicalize,
  canonicalOpDigest,
  streamHeadDigest,
  type OutboxRecord,
  type PublisherBackpressure,
  type SignedStreamHead,
  type StreamHeadVerifier,
} from './ha-outbox-contract.js';
import {
  GENESIS_HEAD,
  StreamHeadVerificationUnavailableError,
  attestOutboxSchemaInTx,
  requireSchemaReady,
  type PgExecutor,
  type PgTransactor,
  type SchemaReadyToken,
  type SourceFenceGate,
  type StreamHeadSigner,
} from './tsk-hotp-outbox-pg.js';
import { fenceTokenForEpoch } from './ha-control-fencing.js';
import { requireSourceFenceReady } from './tsk-source-fence.js';
import { assertTumblerMapCounterState, commitValidationToMap, type TumblerMapStore, type ValidationCommitInput,
  reconcileTumblerMapCounterStatus, type ValidationCommitResult } from './store.js';

const ID = /^[A-Za-z0-9_.:/-]{1,128}$/;
const HEX64 = /^[0-9a-f]{64}$/;
const SCHEMA = /^[a-z_][a-z0-9_]{0,62}$/;
const MAX_MAP_BYTES = 256 * 1024;
const CREDENTIAL_TABLES = ['tsk_credential_maps', 'tsk_credential_replica_maps',
  'tsk_credential_mutation_key', 'tsk_credential_mutation_nonce'] as const;
const GOVERNED_TABLES = [...CREDENTIAL_TABLES, 'tsk_outbox_meta', 'tsk_outbox_fence',
  'tsk_outbox_source_checkpoint', 'tsk_outbox_receiver_checkpoint', 'tsk_outbox_rows',
  'tsk_outbox_publisher_lease', 'tsk_outbox_quarantine', 'tsk_outbox_applied',
  'tsk_hotp_consumed', 'tsk_outbox_stream_halted', 'tsk_source_lease',
  'tsk_source_lease_history'] as const;
const EXPOSED_ROUTINES = ['tsk_apply_credential_mutation', 'tsk_prepare_credential_append',
  'tsk_credential_ticket_context', 'tsk_verify_credential_mutation_key'] as const;
const GOVERNED_ROUTINES = [...EXPOSED_ROUTINES, 'tsk_credential_constant_time_equal'] as const;
/** Compiled PG16 catalog pin. Re-pin only through a reviewed schema change. */
export const CREDENTIAL_AUTHORITY_MANIFEST_DIGEST = 'c24a259460dd46531df48bcf06b674850e4805f2a698c8ee6b55c23d8383c02b';
const MAP_KEYS = ['checksum', 'clientId', 'createdAt', 'expiresAt', 'hotpRotationWarningCounters',
  'keyLength', 'label', 'lastUsedAt', 'maxRequests', 'requestCount', 'rotationWarningRequests',
  'segments', 'sharedSecret', 'status', 'version'] as const;
const PUBLIC_MAP_KEYS = MAP_KEYS.filter((key) => key !== 'sharedSecret');
const STATUS_RANK = { active: 0, expiring: 1, expired: 2, revoked: 2 } as const;

export const TSK_CREDENTIAL_AUTHORITY_SCHEMA = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;
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
CREATE TABLE IF NOT EXISTS tsk_credential_mutation_key (
  key_id text PRIMARY KEY,
  secret bytea NOT NULL CHECK(octet_length(secret)>=32),
  active boolean NOT NULL DEFAULT true
);
CREATE TABLE IF NOT EXISTS tsk_credential_mutation_nonce (
  nonce text PRIMARY KEY CHECK(nonce ~ '^[A-Za-z0-9_-]{22,128}$'),
  expires_at_ms bigint NOT NULL,
  used_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp()
);
CREATE INDEX IF NOT EXISTS tsk_credential_mutation_nonce_expires_idx
  ON tsk_credential_mutation_nonce(expires_at_ms,nonce);
CREATE OR REPLACE FUNCTION tsk_credential_constant_time_equal(left_value bytea, right_value bytea)
RETURNS boolean LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = public, pg_temp AS $fn$
DECLARE difference integer:=0; i integer;
BEGIN
  IF octet_length(left_value)<>octet_length(right_value) THEN RETURN false; END IF;
  FOR i IN 0..octet_length(left_value)-1 LOOP
    difference:=difference | (get_byte(left_value,i) # get_byte(right_value,i));
  END LOOP;
  RETURN difference=0;
END $fn$;
REVOKE ALL ON FUNCTION tsk_credential_constant_time_equal(bytea,bytea) FROM PUBLIC;
CREATE OR REPLACE FUNCTION tsk_verify_credential_mutation_key(
  requested_key_id text, challenge text, supplied_mac text
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $fn$
DECLARE k record;
BEGIN
  IF requested_key_id !~ '^[A-Za-z0-9._-]{1,64}$'
     OR challenge !~ '^[A-Za-z0-9_-]{32,128}$' OR supplied_mac !~ '^[0-9a-f]{64}$' THEN
    RETURN false;
  END IF;
  SELECT * INTO k FROM tsk_credential_mutation_key
    WHERE key_id=requested_key_id AND active FOR SHARE;
  IF NOT FOUND THEN RETURN false; END IF;
  RETURN tsk_credential_constant_time_equal(
    public.hmac(pg_catalog.convert_to(challenge,'UTF8'),k.secret,'sha256'),
    pg_catalog.decode(supplied_mac,'hex'));
END $fn$;
REVOKE ALL ON FUNCTION tsk_verify_credential_mutation_key(text,text,text) FROM PUBLIC;
CREATE OR REPLACE FUNCTION tsk_credential_ticket_context(
  ticket jsonb, requested_stream text, requested_epoch text, requested_sequence bigint,
  requested_fence numeric, requested_digest text, mutation jsonb,
  requested_head_prev text, requested_head_digest text, head_key_id text, head_alg text,
  head_sig text, effects jsonb
) RETURNS text LANGUAGE sql SECURITY DEFINER SET search_path = public, pg_temp AS $fn$
  SELECT pg_catalog.jsonb_build_object(
    'domain','tsk-credential-db-mutation/v1','ticket',ticket,
    'payload',pg_catalog.jsonb_build_array(requested_stream,requested_epoch,requested_sequence::text,
      requested_fence::text,requested_digest,mutation,requested_head_prev,requested_head_digest,
      head_key_id,head_alg,head_sig,effects)
  )::text
$fn$;
REVOKE ALL ON FUNCTION tsk_credential_ticket_context(jsonb,text,text,bigint,numeric,text,jsonb,text,text,text,text,text,jsonb) FROM PUBLIC;
CREATE OR REPLACE FUNCTION tsk_prepare_credential_append(
  requested_stream text, requested_epoch bigint, requested_holder text,
  requested_lease text, requested_grant text, skew_ms bigint, max_pending bigint
) RETURNS TABLE(source_epoch text,next_sequence bigint,prev_head text,fence_value numeric)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $fn$
DECLARE lease record; latest record; cp record; now_ms bigint; pending bigint;
BEGIN
  LOCK TABLE tsk_credential_mutation_key, tsk_credential_mutation_nonce IN ACCESS SHARE MODE;
  SELECT * INTO lease FROM tsk_source_lease WHERE stream_id=requested_stream FOR SHARE;
  SELECT lease_grant_seq,grant_digest INTO latest FROM tsk_source_lease_history
    WHERE stream_id=requested_stream ORDER BY lease_grant_seq DESC LIMIT 1;
  now_ms:=floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint;
  IF lease.stream_id IS NULL OR latest.lease_grant_seq IS NULL
     OR lease.lease_status<>'active' OR lease.lease_epoch<>requested_epoch
     OR lease.holder_node_id<>requested_holder OR lease.lease_id<>requested_lease
     OR lease.grant_digest<>requested_grant OR latest.lease_grant_seq<>lease.lease_grant_seq
     OR latest.grant_digest<>lease.grant_digest OR now_ms+skew_ms>=lease.lease_expires_at_ms THEN
    RAISE EXCEPTION 'source lease is missing, stale, expired, or not latest';
  END IF;
  SELECT fence_token INTO fence_value FROM tsk_outbox_fence
    WHERE stream_id=requested_stream AND fence_token=requested_epoch FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'source fence missing or stale'; END IF;
  SELECT * INTO cp FROM tsk_outbox_source_checkpoint WHERE stream_id=requested_stream FOR UPDATE;
  IF NOT FOUND OR cp.sequence>=9007199254740991 THEN RAISE EXCEPTION 'source checkpoint missing or exhausted'; END IF;
  SELECT count(*) INTO pending FROM tsk_outbox_rows WHERE stream_id=requested_stream
    AND acked_at IS NULL AND quarantined_at IS NULL;
  IF max_pending<1 OR pending>=max_pending THEN RAISE EXCEPTION 'credential outbox backpressure'; END IF;
  source_epoch:=cp.source_epoch; next_sequence:=cp.sequence+1;
  prev_head:=COALESCE(NULLIF(cp.head_digest,''),'${'0'.repeat(64)}');
  RETURN NEXT;
END $fn$;
REVOKE ALL ON FUNCTION tsk_prepare_credential_append(text,bigint,text,text,text,bigint,bigint) FROM PUBLIC;
DROP FUNCTION IF EXISTS tsk_apply_credential_mutation(text,text,bigint,text,jsonb);
DROP FUNCTION IF EXISTS tsk_apply_credential_mutation(text,text,bigint,numeric,text,jsonb,text,text,text,text,text,jsonb);
CREATE OR REPLACE FUNCTION tsk_apply_credential_mutation(
  ticket jsonb, requested_stream text, requested_epoch text, requested_sequence bigint,
  requested_fence numeric, requested_digest text, mutation jsonb,
  requested_head_prev text, requested_head_digest text, head_key_id text, head_alg text, head_sig text,
  effects jsonb
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $fn$
DECLARE effect jsonb; affected bigint; cp record; k record; canonical text; now_ms bigint;
BEGIN
  IF jsonb_typeof(ticket)<>'object' OR (SELECT count(*) FROM pg_catalog.jsonb_object_keys(ticket))<>5
     OR ticket->>'keyId' !~ '^[A-Za-z0-9._-]{1,64}$'
     OR ticket->>'nonce' !~ '^[A-Za-z0-9_-]{22,128}$'
     OR ticket->>'txid'<>pg_catalog.txid_current()::text
     OR ticket->>'expiresAtMs' !~ '^[0-9]{1,16}$' OR ticket->>'mac' !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'credential mutation ticket invalid';
  END IF;
  now_ms:=floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint;
  IF (ticket->>'expiresAtMs')::bigint<now_ms OR (ticket->>'expiresAtMs')::bigint>now_ms+10000 THEN
    RAISE EXCEPTION 'credential mutation ticket expired';
  END IF;
  SELECT * INTO k FROM tsk_credential_mutation_key WHERE key_id=ticket->>'keyId' AND active FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'credential mutation ticket key unavailable'; END IF;
  canonical:=tsk_credential_ticket_context(ticket-'mac',requested_stream,requested_epoch,requested_sequence,
    requested_fence,requested_digest,mutation,requested_head_prev,requested_head_digest,
    head_key_id,head_alg,head_sig,effects);
  IF NOT tsk_credential_constant_time_equal(
      public.hmac(pg_catalog.convert_to(canonical,'UTF8'),k.secret,'sha256'),
      pg_catalog.decode(ticket->>'mac','hex')) THEN
    RAISE EXCEPTION 'credential mutation ticket MAC invalid';
  END IF;
  LOCK TABLE tsk_credential_mutation_nonce IN SHARE ROW EXCLUSIVE MODE;
  DELETE FROM tsk_credential_mutation_nonce WHERE nonce IN (
    SELECT nonce FROM tsk_credential_mutation_nonce WHERE expires_at_ms<now_ms
      ORDER BY expires_at_ms,nonce LIMIT 1000
  );
  IF (SELECT count(*) FROM tsk_credential_mutation_nonce)>=10000 THEN
    RAISE EXCEPTION 'credential mutation nonce capacity exhausted';
  END IF;
  INSERT INTO tsk_credential_mutation_nonce(nonce,expires_at_ms)
    VALUES(ticket->>'nonce',(ticket->>'expiresAtMs')::bigint);
  SELECT * INTO cp FROM tsk_outbox_source_checkpoint WHERE stream_id=requested_stream FOR UPDATE;
  IF NOT FOUND OR cp.source_epoch<>requested_epoch OR cp.sequence+1<>requested_sequence
     OR COALESCE(NULLIF(cp.head_digest,''),'${'0'.repeat(64)}')<>requested_head_prev
     OR NOT EXISTS(SELECT 1 FROM tsk_outbox_fence WHERE stream_id=requested_stream AND fence_token=requested_fence FOR UPDATE)
     OR jsonb_typeof(effects)<>'array' THEN RAISE EXCEPTION 'credential append precondition changed'; END IF;
  INSERT INTO tsk_outbox_rows(stream_id,source_epoch,sequence,fence_token,op_digest,tumbler_id,hotp_counter,
    mutation,head_prev,head_digest,head_key_id,head_alg,head_sig)
  VALUES(requested_stream,requested_epoch,requested_sequence,requested_fence,requested_digest,
    mutation->>'tumblerId',(mutation->>'counter')::bigint,mutation,requested_head_prev,requested_head_digest,head_key_id,head_alg,head_sig);
  UPDATE tsk_outbox_source_checkpoint SET sequence=requested_sequence,head_digest=requested_head_digest
    WHERE stream_id=requested_stream;
  IF mutation->>'kind'='tsk.credential.snapshot.v1' THEN
    IF jsonb_array_length(effects)<>1 THEN RAISE EXCEPTION 'snapshot effect count invalid'; END IF;
    effect:=effects->0;
    IF effect->>'action'<>'upsert' OR effect->>'clientId'<>mutation->>'clientId'
       OR effect->>'revision'<>mutation->>'counter'
       OR effect->'map'->>'clientId'<>mutation->>'clientId'
       OR effect->'map'->>'sharedSecret' !~ '^[0-9a-f]{64}$'
       OR pg_catalog.encode(public.digest(pg_catalog.convert_to(effect->'map'->>'sharedSecret','UTF8'),'sha256'),'hex')<>mutation->>'secretDigest'
       OR (effect->'map')-'sharedSecret'<>mutation->'publicMap' THEN
      RAISE EXCEPTION 'snapshot effect does not bind the signed mutation';
    END IF;
    INSERT INTO tsk_credential_maps(client_id,map,revision)
      VALUES(effect->>'clientId',effect->'map',(effect->>'revision')::bigint)
      ON CONFLICT(client_id) DO UPDATE SET map=excluded.map,revision=excluded.revision,
        updated_at=pg_catalog.clock_timestamp()
      WHERE tsk_credential_maps.revision+1=excluded.revision;
    GET DIAGNOSTICS affected=ROW_COUNT;
    IF affected<>1 THEN RAISE EXCEPTION 'credential snapshot revision precondition failed'; END IF;
  ELSIF mutation->>'kind'='tsk.credential.delete.v1' THEN
    IF jsonb_array_length(effects)<>1 THEN RAISE EXCEPTION 'delete effect count invalid'; END IF;
    effect:=effects->0;
    IF effect->>'action'<>'delete' OR effect->>'clientId'<>mutation->>'clientId'
       OR effect->>'revision'<>mutation->>'counter' THEN
      RAISE EXCEPTION 'delete effect does not bind the signed mutation';
    END IF;
    DELETE FROM tsk_credential_maps WHERE client_id=effect->>'clientId'
      AND revision+1=(effect->>'revision')::bigint;
    GET DIAGNOSTICS affected=ROW_COUNT;
    IF affected<>1 THEN RAISE EXCEPTION 'credential delete revision precondition failed'; END IF;
  ELSIF mutation->>'kind'='tsk.credential.replace.v1' THEN
    IF jsonb_array_length(effects)<>2 THEN RAISE EXCEPTION 'replace effect count invalid'; END IF;
    IF effects->0->>'action'<>'upsert' OR effects->1->>'action'<>'insert'
       OR effects->0->>'clientId'<>mutation->'old'->>'clientId'
       OR effects->1->>'clientId'<>mutation->'replacement'->>'clientId'
       OR effects->0->>'revision'<>mutation->'old'->>'counter'
       OR effects->1->>'revision'<>mutation->'replacement'->>'counter'
       OR effects->0->'map'->>'sharedSecret' !~ '^[0-9a-f]{64}$'
       OR effects->1->'map'->>'sharedSecret' !~ '^[0-9a-f]{64}$'
       OR pg_catalog.encode(public.digest(pg_catalog.convert_to(effects->0->'map'->>'sharedSecret','UTF8'),'sha256'),'hex')<>mutation->'old'->>'secretDigest'
       OR pg_catalog.encode(public.digest(pg_catalog.convert_to(effects->1->'map'->>'sharedSecret','UTF8'),'sha256'),'hex')<>mutation->'replacement'->>'secretDigest'
       OR ((effects->0->'map')-'sharedSecret')<>mutation->'old'->'publicMap'
       OR ((effects->1->'map')-'sharedSecret')<>mutation->'replacement'->'publicMap' THEN
      RAISE EXCEPTION 'replace effects do not bind the signed mutation';
    END IF;
    UPDATE tsk_credential_maps SET map=effects->0->'map',revision=(effects->0->>'revision')::bigint,
      updated_at=pg_catalog.clock_timestamp()
      WHERE client_id=effects->0->>'clientId' AND revision+1=(effects->0->>'revision')::bigint;
    GET DIAGNOSTICS affected=ROW_COUNT;
    IF affected<>1 THEN RAISE EXCEPTION 'replacement old credential precondition failed'; END IF;
    INSERT INTO tsk_credential_maps(client_id,map,revision)
      VALUES(effects->1->>'clientId',effects->1->'map',(effects->1->>'revision')::bigint);
  ELSE
    RAISE EXCEPTION 'unsupported credential mutation';
  END IF;
END $fn$;
REVOKE ALL ON FUNCTION tsk_apply_credential_mutation(jsonb,text,text,bigint,numeric,text,jsonb,text,text,text,text,text,jsonb) FROM PUBLIC;
`;

export interface CredentialSnapshot {
  clientId: string;
  counter: number;
  publicMap: Record<string, unknown>;
  publicMapDigest: string;
  secretDigest: string;
}

export type CredentialMutation = {
  kind: 'tsk.credential.snapshot.v1';
  tumblerId: string;
  counter: number;
} & CredentialSnapshot | {
  kind: 'tsk.credential.replace.v1';
  tumblerId: string;
  counter: number;
  old: CredentialSnapshot;
  replacement: CredentialSnapshot;
} | {
  kind: 'tsk.credential.delete.v1';
  clientId: string;
  tumblerId: string;
  counter: number;
};

const READY = new WeakMap<object, { db: PgTransactor; schema: string }>();
export interface CredentialAuthorityReadyToken { readonly __credentialAuthorityReady: never }
const BOUNDARY = new WeakMap<object, { db: PgTransactor; schema: string; role: string; keyId: string }>();
export interface CredentialMutationBoundaryToken { readonly __credentialMutationBoundary: never }
export interface CredentialMutationTicketSigner { readonly keyId: string; sign(canonical: string): Promise<string> | string }
export class HmacCredentialMutationTicketSigner implements CredentialMutationTicketSigner {
  private readonly secret: Buffer;
  constructor(readonly keyId: string, secret: Uint8Array) {
    id(keyId, 'credential mutation keyId'); this.secret = Buffer.from(secret);
    if (this.secret.length < 32) throw new ContractValidationError('credential mutation ticket secret too short');
  }
  sign(canonical: string): string { return createHmac('sha256', this.secret).update(canonical, 'utf8').digest('hex'); }
}

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

function optionalKeys(value: Record<string, unknown>, allowed: readonly string[], name: string): void {
  const extras = Object.keys(value).filter((key) => !allowed.includes(key));
  if (extras.length) throw new ContractValidationError(`${name} has unsupported fields: ${extras.join(',')}`);
}

function safeOptionalInt(value: unknown, name: string, min = 0): number | undefined {
  if (value === undefined) return undefined;
  if (!Number.isSafeInteger(value) || (value as number) < min) throw new ContractValidationError(`${name} invalid`);
  return value as number;
}

function validateMap(value: unknown, requireSecret: boolean): TumblerMap {
  const map = plain(value, 'credential map');
  optionalKeys(map, requireSecret ? MAP_KEYS : PUBLIC_MAP_KEYS, 'credential map');
  const clientId = id(map.clientId, 'map.clientId');
  if (map.version !== '1' || !Number.isSafeInteger(map.keyLength) ||
      (map.keyLength as number) < 20 || (map.keyLength as number) > 512 ||
      !Number.isSafeInteger(map.createdAt) || (map.createdAt as number) < 0) {
    throw new ContractValidationError('credential map core fields invalid');
  }
  if (requireSecret) {
    if (typeof map.sharedSecret !== 'string' || !/^[0-9a-f]{64}$/.test(map.sharedSecret)) {
      throw new ContractValidationError('credential sharedSecret must be canonical 256-bit hex');
    }
  } else if (Object.hasOwn(map, 'sharedSecret')) {
    throw new ContractValidationError('public credential map contains sharedSecret');
  }
  if (!Array.isArray(map.segments) || map.segments.length < 2 || map.segments.length > 9) {
    throw new ContractValidationError('credential segments invalid');
  }
  const ids = new Set<string>();
  let cursor = 0, hotp = 0;
  for (const entry of map.segments) {
    const segment = plain(entry, 'credential segment');
    const type = segment.type;
    const allowed = type === 'totp' ? ['position', 'segmentId', 'type', 'windowSec']
      : type === 'hotp' ? ['counter', 'position', 'segmentId', 'type']
        : ['position', 'segmentId', 'type'];
    optionalKeys(segment, allowed, 'credential segment');
    const segmentId = id(segment.segmentId, 'segmentId');
    if (ids.has(segmentId) || !['static', 'totp', 'hotp'].includes(String(type)) ||
        !Array.isArray(segment.position) || segment.position.length !== 2) {
      throw new ContractValidationError('credential segment shape invalid');
    }
    ids.add(segmentId);
    const [start, end] = segment.position;
    if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start !== cursor ||
        (end as number) <= (start as number) || (end as number) > (map.keyLength as number)) {
      throw new ContractValidationError('credential segment positions invalid');
    }
    if (type === 'totp' && (!Number.isSafeInteger(segment.windowSec) || (segment.windowSec as number) < 1)) {
      throw new ContractValidationError('TOTP window invalid');
    }
    if (type === 'hotp') {
      hotp++;
      if (!Number.isSafeInteger(segment.counter) || (segment.counter as number) < 0 ||
          (segment.counter as number) > 2_147_483_647) throw new ContractValidationError('HOTP counter invalid');
    }
    cursor = end as number;
  }
  const checksum = plain(map.checksum, 'checksum');
  exact(checksum, ['position'], 'checksum');
  if (!Array.isArray(checksum.position) || checksum.position.length !== 2 ||
      checksum.position[0] !== cursor || checksum.position[1] !== map.keyLength || hotp < 1) {
    throw new ContractValidationError('checksum or HOTP coverage invalid');
  }
  safeOptionalInt(map.expiresAt, 'expiresAt');
  safeOptionalInt(map.maxRequests, 'maxRequests');
  safeOptionalInt(map.rotationWarningRequests, 'rotationWarningRequests', 1);
  safeOptionalInt(map.hotpRotationWarningCounters, 'hotpRotationWarningCounters', 1);
  safeOptionalInt(map.requestCount, 'requestCount');
  if (map.lastUsedAt !== undefined && map.lastUsedAt !== null) safeOptionalInt(map.lastUsedAt, 'lastUsedAt');
  if (map.status !== undefined && !Object.hasOwn(STATUS_RANK, String(map.status))) {
    throw new ContractValidationError('credential status invalid');
  }
  if (map.label !== undefined && (typeof map.label !== 'string' || map.label.length > 256)) {
    throw new ContractValidationError('credential label invalid');
  }
  if (map.clientId !== clientId) throw new ContractValidationError('credential clientId invalid');
  assertTumblerMapCounterState(map as unknown as TumblerMap);
  return map as unknown as TumblerMap;
}

function assertMonotonicMap(current: TumblerMap, next: TumblerMap): void {
  if (current.clientId !== next.clientId || current.sharedSecret !== next.sharedSecret ||
      current.createdAt !== next.createdAt || current.version !== next.version) {
    throw new ContractValidationError('credential identity or secret pivot requires governed replacement');
  }
  const previous = new Map(current.segments.map((segment) => [segment.segmentId, segment]));
  if (previous.size !== next.segments.length) throw new ContractValidationError('credential segment layout changed');
  for (const segment of next.segments) {
    const old = previous.get(segment.segmentId);
    const oldShape = old ? cloneJson(old, 'old segment') as unknown as Record<string, unknown> : null;
    const nextShape = cloneJson(segment, 'next segment') as unknown as Record<string, unknown>;
    if (oldShape) delete oldShape.counter;
    delete nextShape.counter;
    if (!old || canonicalize(oldShape) !== canonicalize(nextShape) ||
        (segment.type === 'hotp' && (segment.counter ?? 0) < (old.counter ?? 0))) {
      throw new ContractValidationError('credential segment layout or counter rolled back');
    }
  }
  if ((next.requestCount ?? 0) < (current.requestCount ?? 0) ||
      (next.lastUsedAt ?? 0) < (current.lastUsedAt ?? 0)) {
    throw new ContractValidationError('credential usage state rolled back');
  }
  const oldRank = current.status ? STATUS_RANK[current.status] : 0;
  const nextRank = next.status ? STATUS_RANK[next.status] : 0;
  if (nextRank < oldRank || ((current.status === 'revoked' || current.status === 'expired') && next.status !== current.status)) {
    throw new ContractValidationError('terminal credential cannot be reactivated');
  }
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
  const source = validateMap(cloneJson(map, 'TSK credential map'), true) as unknown as Record<string, unknown>;
  const clientId = id(source.clientId, 'map.clientId');
  const secretDigest = createHash('sha256').update(String(source.sharedSecret), 'utf8').digest('hex');
  delete source.sharedSecret;
  if (source.clientId !== clientId || containsSecret(source)) {
    throw new ContractValidationError('TSK public credential snapshot contains secret material');
  }
  return { publicMap: source, publicMapDigest: digest(source), secretDigest };
}

function sanitizeSnapshot(value: unknown, name: string): CredentialSnapshot {
  const raw = plain(value, name);
  exact(raw, ['clientId', 'counter', 'publicMap', 'publicMapDigest', 'secretDigest'], name);
  const clientId = id(raw.clientId, `${name}.clientId`);
  const publicMap = plain(raw.publicMap, `${name}.publicMap`);
  validateMap(publicMap, false);
  if (publicMap.clientId !== clientId || containsSecret(publicMap) ||
      typeof raw.publicMapDigest !== 'string' || !HEX64.test(raw.publicMapDigest) ||
      digest(publicMap) !== raw.publicMapDigest || typeof raw.secretDigest !== 'string' ||
      !HEX64.test(raw.secretDigest) || !Number.isSafeInteger(raw.counter) ||
      (raw.counter as number) < 1 || (raw.counter as number) > 2_147_483_647) {
    throw new ContractValidationError(`${name} is not exact, bound, and secret-free`);
  }
  return { clientId, counter: raw.counter as number, publicMap,
    publicMapDigest: raw.publicMapDigest, secretDigest: raw.secretDigest };
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
  if (raw.kind === 'tsk.credential.replace.v1') {
    exact(raw, ['counter', 'kind', 'old', 'replacement', 'tumblerId'], String(raw.kind));
    const old = sanitizeSnapshot(raw.old, 'replace.old');
    const replacement = sanitizeSnapshot(raw.replacement, 'replace.replacement');
    if (old.clientId === replacement.clientId || raw.tumblerId !== old.clientId || raw.counter !== old.counter ||
        old.publicMap.status !== 'revoked' || replacement.publicMap.status === 'revoked' ||
        replacement.publicMap.status === 'expired') {
      throw new ContractValidationError('credential replacement binding invalid');
    }
    return { kind: raw.kind, tumblerId: old.clientId, counter: old.counter, old, replacement };
  }
  if (raw.kind !== 'tsk.credential.snapshot.v1') {
    throw new ContractValidationError('unsupported credential mutation');
  }
  exact(raw, ['kind', 'clientId', 'counter', 'publicMap', 'publicMapDigest',
    'secretDigest', 'tumblerId'], String(raw.kind));
  const clientId = id(raw.clientId, 'clientId');
  const snapshot = sanitizeSnapshot({ clientId: raw.clientId, counter: raw.counter,
    publicMap: raw.publicMap, publicMapDigest: raw.publicMapDigest, secretDigest: raw.secretDigest },
  'credential snapshot');
  if (raw.tumblerId !== clientId || snapshot.clientId !== clientId) {
    throw new ContractValidationError('credential snapshot binding invalid');
  }
  return { kind: raw.kind, tumblerId: clientId, ...snapshot };
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
  await attestOutboxSchemaInTx(exec, schema);
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
    `SELECT rel.relname AS t,rel.relkind,rel.relpersistence,rel.relrowsecurity,rel.relforcerowsecurity,
            owner.rolname AS owner
       FROM pg_catalog.pg_class rel JOIN pg_catalog.pg_namespace ns ON ns.oid=rel.relnamespace
       JOIN pg_catalog.pg_roles owner ON owner.oid=rel.relowner
      WHERE ns.nspname=pg_catalog.current_schema() AND rel.relname=ANY($1)`, [tables])).rows;
  const cols = (await exec.query(
    `SELECT rel.relname AS table_name,a.attnum AS ordinal_position,a.attname AS column_name,
            pg_catalog.format_type(a.atttypid,a.atttypmod) AS data_type,
            CASE WHEN a.attnotnull THEN 'NO' ELSE 'YES' END AS is_nullable,
            COALESCE(pg_catalog.pg_get_expr(ad.adbin,ad.adrelid),'') AS d
       FROM pg_catalog.pg_attribute a JOIN pg_catalog.pg_class rel ON rel.oid=a.attrelid
       JOIN pg_catalog.pg_namespace ns ON ns.oid=rel.relnamespace
       LEFT JOIN pg_catalog.pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum
      WHERE ns.nspname=pg_catalog.current_schema() AND rel.relname=ANY($1)
        AND a.attnum>0 AND NOT a.attisdropped`, [tables])).rows;
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
  const routines = (await exec.query(
    `SELECT p.proname AS n,p.prosecdef,p.proconfig,pg_catalog.pg_get_function_identity_arguments(p.oid) AS args,
            pg_catalog.pg_get_functiondef(p.oid) AS def,owner.rolname AS owner
       FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace ns ON ns.oid=p.pronamespace
       JOIN pg_catalog.pg_roles owner ON owner.oid=p.proowner
      WHERE ns.nspname=pg_catalog.current_schema() AND p.proname=ANY($1)`,
    [[...GOVERNED_ROUTINES]])).rows;
  const authorityOwners = new Set([...rel, ...routines].map((row) => String(row.owner)));
  if (authorityOwners.size !== 1) {
    throw new ContractValidationError('credential authority objects do not have one consistent owner');
  }
  const present = rel.map((row) => String(row.t)).sort();
  const lines = [`PRESENT|${present.join(',')}|n=${present.length}`,
    ...rel.map((r) => `R|${r.t}|${r.relkind}|${r.relpersistence}|${r.relrowsecurity}|${r.relforcerowsecurity}|authority-owner`),
    ...cols.map((r) => `C|${r.table_name}|${r.ordinal_position}|${r.column_name}|${r.data_type}|${r.is_nullable}|${r.d}`),
    ...cons.map((r) => `K|${r.t}|${r.contype}|${r.def}`),
    ...idx.map((r) => `I|${r.t}|${r.n}|${r.def}`),
    ...trg.map((r) => `T|${r.t}|${r.n}|${r.tgenabled}|${r.def}`),
    ...pol.map((r) => `P|${r.t}|${r.n}|${r.permissive}|${r.roles}|${r.cmd}|${r.qual}|${r.wc}`),
    ...routines.map((r) => `F|${r.n}|${r.args}|${r.prosecdef}|${JSON.stringify(r.proconfig)}|authority-owner|${r.def}`)];
  lines.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  return ['Vcredential_authority/1', ...lines].join('\n');
}

export async function assertCredentialAuthorityReady(
  db: PgTransactor, schema: string, outboxReady: SchemaReadyToken,
): Promise<CredentialAuthorityReadyToken> {
  if (schema !== 'public') throw new ContractValidationError('credential authority v1 requires public schema');
  if (requireSchemaReady(outboxReady, db) !== schema) {
    throw new ContractValidationError('outbox and credential authority schema mismatch');
  }
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

async function assertRuntimeBoundaryInTx(exec: PgExecutor, schema: string,
  expectedRole: string, signer: CredentialMutationTicketSigner): Promise<void> {
  const current = String((await exec.query('SELECT current_user AS role')).rows[0]?.role);
  if (current !== expectedRole || !SCHEMA.test(current)) {
    throw new ContractValidationError('credential runtime role changed or is invalid');
  }
  const attrs = (await exec.query(
    'SELECT rolsuper,rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=$1', [current],
  )).rows[0];
  if (!attrs || attrs.rolsuper || attrs.rolbypassrls) {
    throw new ContractValidationError('credential runtime holds bypass authority');
  }
  const posture = (await exec.query(
    `SELECT
       pg_catalog.has_schema_privilege($1,$2,'CREATE') AS can_create,
       EXISTS(SELECT 1 FROM pg_catalog.unnest($3::text[]) t
         WHERE pg_catalog.has_table_privilege($1,$2||'.'||t,'INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')) AS has_dml,
       EXISTS(SELECT 1 FROM pg_catalog.unnest($4::text[]) t
         WHERE pg_catalog.has_table_privilege($1,$2||'.'||t,'SELECT')) AS has_secret_read,
       EXISTS(SELECT 1 FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
         WHERE n.nspname=$2 AND c.relname=ANY($3)
           AND pg_catalog.pg_has_role($1,c.relowner,'MEMBER')) AS owns_table,
       EXISTS(SELECT 1 FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
         WHERE n.nspname=$2 AND p.proname=ANY($5)
           AND pg_catalog.pg_has_role($1,p.proowner,'MEMBER')) AS owns_routine`,
    [current, schema, [...GOVERNED_TABLES], ['tsk_credential_mutation_key', 'tsk_credential_mutation_nonce'],
      [...GOVERNED_ROUTINES]],
  )).rows[0];
  const fn = (await exec.query(
    `SELECT count(*)::int n,bool_and(p.prosecdef) secdef,
            bool_and(p.proconfig @> ARRAY['search_path=public, pg_temp']::text[]) fixed_path,
            bool_and(pg_catalog.has_function_privilege($2,p.oid,'EXECUTE')) runtime_exec,
            bool_or(pg_catalog.has_function_privilege('public',p.oid,'EXECUTE')) public_exec
       FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname=$1 AND p.proname=ANY($3)`,
    [schema, current, [...EXPOSED_ROUTINES]],
  )).rows[0];
  const helper = (await exec.query(
    `SELECT count(*)::int n,bool_or(pg_catalog.has_function_privilege($2,p.oid,'EXECUTE')) runtime_exec,
            bool_or(pg_catalog.has_function_privilege('public',p.oid,'EXECUTE')) public_exec
       FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
      WHERE n.nspname=$1 AND p.proname='tsk_credential_constant_time_equal'`,
    [schema, current],
  )).rows[0];
  if (!posture || posture.can_create || posture.has_dml || posture.has_secret_read ||
      posture.owns_table || posture.owns_routine || Number(fn?.n) !== EXPOSED_ROUTINES.length ||
      !fn.secdef || !fn.fixed_path || !fn.runtime_exec || fn.public_exec ||
      Number(helper?.n) !== 1 || helper.runtime_exec || helper.public_exec) {
    throw new ContractValidationError('credential runtime mutation boundary is unsafe or drifted');
  }
  const challenge = randomBytes(32).toString('base64url');
  const mac = await signer.sign(challenge);
  if (!HEX64.test(mac) || (await exec.query(
    'SELECT tsk_verify_credential_mutation_key($1,$2,$3) AS verified',
    [signer.keyId, challenge, mac],
  )).rows[0]?.verified !== true) {
    throw new ContractValidationError('credential mutation key is missing, inactive, or mismatched');
  }
}

export async function provisionCredentialRuntimeMutationBoundary(
  db: PgTransactor, schema: string, runtimeRole: string, keyId: string, secretValue: Uint8Array,
): Promise<void> {
  id(keyId, 'credential mutation keyId');
  const secret = Buffer.from(secretValue);
  if (schema !== 'public' || !SCHEMA.test(runtimeRole) || secret.length < 32) {
    throw new ContractValidationError('credential runtime schema/role invalid');
  }
  try {
    await db.transaction(async (exec) => {
      await enter(exec, schema);
      const role = (await exec.query(
        'SELECT rolsuper,rolbypassrls FROM pg_catalog.pg_roles WHERE rolname=$1', [runtimeRole],
      )).rows[0];
      if (!role || role.rolsuper || role.rolbypassrls) {
        throw new ContractValidationError('credential runtime role missing or holds bypass authority');
      }
      const owner = (await exec.query(
        `SELECT 1 FROM (
           SELECT c.relowner AS owner FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid=c.relnamespace
            WHERE n.nspname=$2 AND c.relname=ANY($3)
           UNION ALL
           SELECT p.proowner AS owner FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace
            WHERE n.nspname=$2 AND p.proname=ANY($4)
         ) governed WHERE pg_catalog.pg_has_role($1,governed.owner,'MEMBER') LIMIT 1`,
        [runtimeRole, schema, [...GOVERNED_TABLES], [...GOVERNED_ROUTINES]],
      )).rows[0];
      if (owner) throw new ContractValidationError('credential runtime role inherits authority ownership');
      await exec.query(`REVOKE CREATE ON SCHEMA ${schema} FROM PUBLIC,${runtimeRole}`);
      const governedTableSql = GOVERNED_TABLES.map((table) => `${schema}.${table}`).join(',');
      await exec.query(`REVOKE INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER ON TABLE ${governedTableSql} FROM PUBLIC,${runtimeRole}`);
      await exec.query(`REVOKE ALL ON TABLE ${schema}.tsk_credential_mutation_key,
        ${schema}.tsk_credential_mutation_nonce FROM PUBLIC,${runtimeRole}`);
      await exec.query(`REVOKE ALL ON FUNCTION ${schema}.tsk_apply_credential_mutation(jsonb,text,text,bigint,numeric,text,jsonb,text,text,text,text,text,jsonb),
        ${schema}.tsk_prepare_credential_append(text,bigint,text,text,text,bigint,bigint),
        ${schema}.tsk_credential_ticket_context(jsonb,text,text,bigint,numeric,text,jsonb,text,text,text,text,text,jsonb),
        ${schema}.tsk_verify_credential_mutation_key(text,text,text),
        ${schema}.tsk_credential_constant_time_equal(bytea,bytea) FROM PUBLIC,${runtimeRole}`);
      await exec.query(`GRANT USAGE ON SCHEMA ${schema} TO ${runtimeRole}`);
      await exec.query(`GRANT SELECT ON TABLE ${schema}.tsk_credential_maps,${schema}.tsk_credential_replica_maps,
        ${schema}.tsk_outbox_meta,${schema}.tsk_outbox_fence,${schema}.tsk_outbox_source_checkpoint,
        ${schema}.tsk_outbox_receiver_checkpoint,${schema}.tsk_outbox_rows,
        ${schema}.tsk_outbox_publisher_lease,${schema}.tsk_outbox_quarantine,
        ${schema}.tsk_outbox_applied,${schema}.tsk_hotp_consumed,${schema}.tsk_outbox_stream_halted,
        ${schema}.tsk_source_lease,${schema}.tsk_source_lease_history TO ${runtimeRole}`);
      await exec.query(`GRANT EXECUTE ON FUNCTION ${schema}.tsk_prepare_credential_append(text,bigint,text,text,text,bigint,bigint) TO ${runtimeRole}`);
      await exec.query(`GRANT EXECUTE ON FUNCTION ${schema}.tsk_credential_ticket_context(jsonb,text,text,bigint,numeric,text,jsonb,text,text,text,text,text,jsonb) TO ${runtimeRole}`);
      await exec.query(`GRANT EXECUTE ON FUNCTION ${schema}.tsk_apply_credential_mutation(jsonb,text,text,bigint,numeric,text,jsonb,text,text,text,text,text,jsonb) TO ${runtimeRole}`);
      await exec.query(`GRANT EXECUTE ON FUNCTION ${schema}.tsk_verify_credential_mutation_key(text,text,text) TO ${runtimeRole}`);
      await exec.query(`INSERT INTO ${schema}.tsk_credential_mutation_key(key_id,secret,active) VALUES($1,$2,true)
        ON CONFLICT(key_id) DO UPDATE SET secret=excluded.secret,active=true`, [keyId, secret]);
    });
  } finally {
    secret.fill(0);
  }
}

export async function assertCredentialRuntimeMutationBoundary(
  db: PgTransactor, schema: string, signer: CredentialMutationTicketSigner,
): Promise<CredentialMutationBoundaryToken> {
  id(signer.keyId, 'credential mutation keyId');
  if (schema !== 'public') throw new ContractValidationError('credential runtime v1 requires public schema');
  const role = await db.transaction(async (exec) => {
    await enter(exec, schema);
    const current = String((await exec.query('SELECT current_user AS role')).rows[0]?.role);
    await assertRuntimeBoundaryInTx(exec, schema, current, signer);
    return current;
  });
  const token = Object.freeze({}) as CredentialMutationBoundaryToken;
  BOUNDARY.set(token as object, { db, schema, role, keyId: signer.keyId });
  return token;
}

function requireBoundary(token: CredentialMutationBoundaryToken, db: PgTransactor, schema: string,
  signer: CredentialMutationTicketSigner): { role: string } {
  const state = BOUNDARY.get(token as object);
  if (!state || state.db !== db || state.schema !== schema || state.keyId !== signer.keyId) {
    throw new ContractValidationError('invalid credential mutation-boundary capability');
  }
  return { role: state.role };
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
  private readonly schema: string;
  private readonly streamId: string;
  private readonly fenceToken: bigint;
  private readonly signer: StreamHeadSigner;
  private readonly maxPendingRows: number;
  private readonly lease: { holderNodeId: string; leaseId: string; grantDigest: string; skewMs: number };
  private readonly ticketSigner: CredentialMutationTicketSigner;
  private readonly runtimeRole: string;

  constructor(
    private readonly db: PgTransactor,
    outboxReady: SchemaReadyToken,
    credentialReady: CredentialAuthorityReadyToken,
    mutationBoundary: CredentialMutationBoundaryToken,
    ticketSigner: CredentialMutationTicketSigner,
    options: PgHaTumblerMapStoreOptions,
    fence: SourceFenceGate,
  ) {
    this.schema = options.schema ?? 'public';
    if (requireSchemaReady(outboxReady, db) !== this.schema) {
      throw new ContractValidationError('outbox readiness is foreign to credential authority');
    }
    requireReady(credentialReady, db, this.schema);
    this.runtimeRole = requireBoundary(mutationBoundary, db, this.schema, ticketSigner).role;
    this.ticketSigner = ticketSigner;
    this.streamId = id(options.streamId, 'streamId');
    if (!Number.isSafeInteger(options.sourceEpoch) || options.sourceEpoch < 0 || options.sourceEpoch > 2 ** 40) {
      throw new ContractValidationError('sourceEpoch invalid');
    }
    this.fenceToken = BigInt(fenceTokenForEpoch(options.sourceEpoch));
    this.signer = options.signer;
    this.maxPendingRows = options.maxPendingRows ?? 10_000;
    if (!Number.isSafeInteger(this.maxPendingRows) || this.maxPendingRows < 1 || this.maxPendingRows > 1_000_000) {
      throw new ContractValidationError('maxPendingRows invalid');
    }
    if (options.backpressure !== undefined && options.backpressure !== 'fail-authoritative-mutation') {
      throw new ContractValidationError('credential authority requires fail-authoritative-mutation backpressure');
    }
    const bound = requireSourceFenceReady(fence.ready, { db, schema: this.schema, streamId: this.streamId });
    this.lease = { holderNodeId: bound.holderNodeId, leaseId: bound.leaseId,
      grantDigest: bound.grantDigest, skewMs: fence.controlToASkewBoundMs };
  }

  private async prepare(exec: PgExecutor, maxPending = this.maxPendingRows): Promise<{
    sourceEpoch: string; sequence: number; prevHead: string; fence: string;
  }> {
    const row = (await exec.query(
      `SELECT source_epoch,next_sequence::text,prev_head,fence_value::text
         FROM tsk_prepare_credential_append($1,$2,$3,$4,$5,$6,$7)`,
      [this.streamId, this.fenceToken.toString(), this.lease.holderNodeId, this.lease.leaseId,
        this.lease.grantDigest, this.lease.skewMs, maxPending],
    )).rows[0];
    if (!row) throw new ContractValidationError('credential append preparation failed');
    const sequence = Number(row.next_sequence);
    if (!Number.isSafeInteger(sequence) || sequence < 1) throw new ContractValidationError('credential sequence invalid');
    return { sourceEpoch: String(row.source_epoch), sequence, prevHead: String(row.prev_head),
      fence: String(row.fence_value) };
  }

  private mutate<T>(fn: (exec: PgExecutor) => Promise<T>): Promise<T> {
    return this.db.transaction(async (exec) => {
      await enter(exec, this.schema);
      await assertRuntimeBoundaryInTx(exec, this.schema, this.runtimeRole, this.ticketSigner);
      return fn(exec);
    }, {
      onBeforeCommit: async (exec) => {
        await assertRuntimeBoundaryInTx(exec, this.schema, this.runtimeRole, this.ticketSigner);
        await this.prepare(exec, this.maxPendingRows + 1);
      },
    });
  }

  private async readInTx(exec: PgExecutor, clientId: string, lock = false): Promise<{
    map: TumblerMap; revision: number;
  } | null> {
    const row = (await exec.query(
      'SELECT map,revision FROM tsk_credential_maps WHERE client_id=$1',
      [id(clientId, 'clientId')],
    )).rows[0];
    void lock;
    return row ? { map: validateMap(cloneJson(row.map as TumblerMap, 'stored credential map'), true),
      revision: Number(row.revision) } : null;
  }

  private snapshot(map: TumblerMap, revision: number): CredentialSnapshot {
    const clientId = id(map.clientId, 'map.clientId');
    if (!Number.isSafeInteger(revision) || revision < 1 || revision > 2_147_483_647) {
      throw new ContractValidationError('credential revision exhausted');
    }
    assertTumblerMapCounterState(map);
    return sanitizeSnapshot({ clientId, counter: revision, ...publicSnapshot(map) }, 'credential snapshot');
  }

  private async appendAndApply(exec: PgExecutor, rawMutation: CredentialMutation,
    effects: readonly Record<string, unknown>[]): Promise<void> {
    const mutation = sanitizeMutation(rawMutation);
    const prepared = await this.prepare(exec);
    const header = { contractVersion: '1' as const, streamId: this.streamId,
      sourceEpoch: prepared.sourceEpoch, sequence: prepared.sequence, fenceToken: prepared.fence,
      opDigest: canonicalOpDigest({ streamId: this.streamId, sourceEpoch: prepared.sourceEpoch,
        sequence: prepared.sequence, fenceToken: prepared.fence, mutation: mutation as never }) };
    assertHeaderConformant(header);
    const headDigest = streamHeadDigest({ streamId: this.streamId, sequence: prepared.sequence,
      prevHeadDigest: prepared.prevHead, opDigest: header.opDigest, keyId: this.signer.keyId,
      alg: this.signer.alg });
    const signature = await this.signer.sign(headDigest);
    const ticketClock = (await exec.query(
      `SELECT pg_catalog.txid_current()::text AS txid,
              floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint::text AS now_ms`,
    )).rows[0];
    if (!ticketClock) throw new ContractValidationError('credential mutation ticket clock unavailable');
    const nowMs = Number(ticketClock.now_ms);
    if (!Number.isSafeInteger(nowMs)) throw new ContractValidationError('credential mutation ticket clock invalid');
    const ticketBase = { keyId: this.ticketSigner.keyId, nonce: randomBytes(24).toString('base64url'),
      txid: String(ticketClock.txid), expiresAtMs: String(nowMs + 5_000) };
    const values = [header.streamId, header.sourceEpoch, header.sequence, header.fenceToken, header.opDigest,
      JSON.stringify(mutation), prepared.prevHead, headDigest, this.signer.keyId, this.signer.alg,
      signature, JSON.stringify(effects)] as const;
    const canonical = String((await exec.query(
      'SELECT tsk_credential_ticket_context($1::jsonb,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12,$13::jsonb) AS canonical',
      [JSON.stringify(ticketBase), ...values],
    )).rows[0]?.canonical ?? '');
    const mac = await this.ticketSigner.sign(canonical);
    if (!HEX64.test(mac)) throw new ContractValidationError('credential mutation ticket MAC invalid');
    const ticket = { ...ticketBase, mac };
    await exec.query(
      'SELECT tsk_apply_credential_mutation($1::jsonb,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12,$13::jsonb)',
      [JSON.stringify(ticket), ...values],
    );
  }

  private async persist(exec: PgExecutor, map: TumblerMap, revision: number): Promise<void> {
    const snapshot = this.snapshot(map, revision);
    const mutation = sanitizeMutation({ kind: 'tsk.credential.snapshot.v1',
      tumblerId: snapshot.clientId, ...snapshot });
    await this.appendAndApply(exec, mutation, [{ action: 'upsert', clientId: snapshot.clientId,
      revision: snapshot.counter, map }]);
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
    const incoming = validateMap(cloneJson(value, 'credential map'), true);
    if (incoming.clientId !== clientId) throw new ContractValidationError('credential clientId mismatch');
    await this.mutate(async (exec) => {
      await enter(exec, this.schema);
      const currentRow = await this.readInTx(exec, clientId, true);
      const current = currentRow?.map;
      if (current) {
        assertMonotonicMap(current, incoming);
      }
      await this.persist(exec, incoming, (currentRow?.revision ?? 0) + 1);
    });
  }

  async delete(clientId: string): Promise<void> {
    await this.mutate(async (exec) => {
      await enter(exec, this.schema);
      const current = await this.readInTx(exec, clientId, true);
      if (!current) return;
      await this.appendAndApply(exec, { kind: 'tsk.credential.delete.v1', clientId,
        tumblerId: clientId, counter: current.revision + 1 },
      [{ action: 'delete', clientId, revision: current.revision + 1 }]);
    });
  }

  async updateCounters(clientId: string, updates: Map<string, number>): Promise<void> {
    if (!(updates instanceof Map)) throw new ContractValidationError('counter updates must be a Map');
    const captured = [...updates.entries()].map(([segmentId, counter]) => ({
      segmentId: id(segmentId, 'segmentId'), counter,
    }));
    for (const update of captured) assertValidHOTPStoredCounter(update.counter,
      `HOTP counter for ${update.segmentId}`);
    await this.mutate(async (exec) => {
      await enter(exec, this.schema);
      const row = await this.readInTx(exec, clientId, true);
      if (!row) return;
      for (const update of captured) {
        const segment = row.map.segments.find((item) => item.segmentId === update.segmentId);
        if (!segment || segment.type !== 'hotp') throw new ContractValidationError('HOTP counter update target invalid');
        if (update.counter < (segment.counter ?? 0)) {
          throw new ContractValidationError('HOTP counter update must be monotonic');
        }
        segment.counter = update.counter;
      }
      const remaining = minimumHOTPUsesRemaining(row.map.segments);
      if (remaining !== undefined) reconcileTumblerMapCounterStatus(row.map, remaining);
      await this.persist(exec, row.map, row.revision + 1);
    });
  }

  async consumeCounter(clientId: string, segmentId: string, matchedCounter: number): Promise<boolean> {
    const capturedClientId = id(clientId, 'clientId');
    const capturedSegmentId = id(segmentId, 'segmentId');
    if (!isUsableHOTPDerivationCounter(matchedCounter)) return false;
    return this.mutate(async (exec) => {
      await enter(exec, this.schema);
      const row = await this.readInTx(exec, capturedClientId, true);
      if (!row) return false;
      const segment = row.map.segments.find((s) => s.segmentId === capturedSegmentId);
      if (!segment || segment.type !== 'hotp') return false;
      const stored = segment.counter ?? 0;
      if (!isUsableHOTPDerivationCounter(stored)) {
        if (stored === 2_147_483_647 && row.map.status !== 'expired' && row.map.status !== 'revoked') {
          row.map.status = 'expired';
          await this.persist(exec, row.map, row.revision + 1);
        }
        return false;
      }
      if (stored > matchedCounter) return false;
      segment.counter = matchedCounter + 1;
      const remaining = minimumHOTPUsesRemaining(row.map.segments);
      if (remaining !== undefined) reconcileTumblerMapCounterStatus(row.map, remaining);
      await this.persist(exec, row.map, row.revision + 1);
      return true;
    });
  }

  async commitValidation(clientId: string, input: ValidationCommitInput): Promise<ValidationCommitResult> {
    const captured = plain(cloneJson(input, 'validation commit'), 'validation commit');
    exact(captured, ['counterMatches', 'usedAt'], 'validation commit');
    if (!Array.isArray(captured.counterMatches) || !Number.isSafeInteger(captured.usedAt) ||
        (captured.usedAt as number) < 0) throw new ContractValidationError('validation commit invalid');
    const commitInput: ValidationCommitInput = { usedAt: captured.usedAt as number,
      counterMatches: captured.counterMatches.map((entry) => {
        const match = plain(entry, 'counter match');
        exact(match, ['matchedCounter', 'segmentId'], 'counter match');
        if (!Number.isSafeInteger(match.matchedCounter) || (match.matchedCounter as number) < 0 ||
            (match.matchedCounter as number) > 2_147_483_647) throw new ContractValidationError('matched counter invalid');
        return { segmentId: id(match.segmentId, 'segmentId'), matchedCounter: match.matchedCounter as number };
      }) };
    return this.mutate(async (exec) => {
      await enter(exec, this.schema);
      const row = await this.readInTx(exec, clientId, true);
      if (!row) return { ok: false, error: 'TSK_KEY_EXPIRED' };
      const before = canonicalize(row.map);
      const result = commitValidationToMap(row.map, commitInput);
      if (canonicalize(row.map) !== before) await this.persist(exec, row.map, row.revision + 1);
      return result;
    });
  }

  async replaceCredential(oldClientId: string, replacement: TumblerMap): Promise<boolean> {
    const next = validateMap(cloneJson(replacement, 'replacement credential map'), true);
    return this.mutate(async (exec) => {
      await enter(exec, this.schema);
      const oldRow = await this.readInTx(exec, oldClientId, true);
      if (!oldRow || (oldRow.map.status !== undefined && oldRow.map.status !== 'active' && oldRow.map.status !== 'expiring')) return false;
      if (await this.readInTx(exec, next.clientId, true)) return false;
      oldRow.map.status = 'revoked';
      const old = this.snapshot(oldRow.map, oldRow.revision + 1);
      const replacement = this.snapshot(next, 1);
      const mutation = sanitizeMutation({ kind: 'tsk.credential.replace.v1',
        tumblerId: old.clientId, counter: old.counter, old, replacement });
      await this.appendAndApply(exec, mutation, [
        { action: 'upsert', clientId: old.clientId, revision: old.counter, map: oldRow.map },
        { action: 'insert', clientId: replacement.clientId, revision: replacement.counter, map: next },
      ]);
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
    if (requireSchemaReady(outboxReady, db) !== schema) {
      throw new ContractValidationError('outbox readiness is foreign to credential receiver');
    }
  }

  async verifyAndApplyDelivered(
    recordValue: OutboxRecord<CredentialMutation>, headValue: SignedStreamHead,
  ): Promise<'applied' | 'duplicate-ok' | 'reject-gap' | 'reject-fence' | 'reject-fork'> {
    const record = cloneJson(recordValue, 'credential record');
    const head = cloneJson(headValue, 'credential head');
    if (record.streamId !== this.streamId || head.streamId !== this.streamId) return 'reject-fork';
    try { assertHeaderConformant(record); } catch { return 'reject-fork'; }
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
      const readReplica = async (clientId: string) => (await exec.query(
        'SELECT public_map,revision,secret_digest FROM tsk_credential_replica_maps WHERE stream_id=$1 AND client_id=$2 FOR UPDATE',
        [this.streamId, clientId],
      )).rows[0];
      const verifySnapshot = (snapshot: CredentialSnapshot, current: Record<string, unknown> | undefined): boolean => {
        if (snapshot.counter !== (current ? Number(current.revision) + 1 : 1)) return false;
        if (current) {
          if (snapshot.secretDigest !== current.secret_digest) return false;
          try {
            const secret = '0'.repeat(64);
            assertMonotonicMap({ ...current.public_map as TumblerMap, sharedSecret: secret },
              { ...snapshot.publicMap as unknown as TumblerMap, sharedSecret: secret });
          } catch { return false; }
        }
        return true;
      };
      const upsert = (snapshot: CredentialSnapshot) => exec.query(
        `INSERT INTO tsk_credential_replica_maps
           (stream_id,client_id,public_map,public_map_digest,secret_digest,source_epoch,sequence,revision)
         VALUES($1,$2,$3::jsonb,$4,$5,$6,$7,$8)
         ON CONFLICT(stream_id,client_id) DO UPDATE SET public_map=EXCLUDED.public_map,
           public_map_digest=EXCLUDED.public_map_digest,secret_digest=EXCLUDED.secret_digest,
           source_epoch=EXCLUDED.source_epoch,sequence=EXCLUDED.sequence,revision=EXCLUDED.revision,
           updated_at=pg_catalog.clock_timestamp()`,
        [this.streamId, snapshot.clientId, JSON.stringify(snapshot.publicMap),
          snapshot.publicMapDigest, snapshot.secretDigest, record.sourceEpoch, record.sequence,
          snapshot.counter],
      );
      if (mutation.kind === 'tsk.credential.replace.v1') {
        const oldCurrent = await readReplica(mutation.old.clientId);
        const newCurrent = await readReplica(mutation.replacement.clientId);
        if (!oldCurrent || newCurrent || !verifySnapshot(mutation.old, oldCurrent) ||
            !verifySnapshot(mutation.replacement, undefined)) return 'reject-fork';
        await upsert(mutation.old);
        await upsert(mutation.replacement);
      } else if (mutation.kind === 'tsk.credential.delete.v1') {
        const current = await readReplica(mutation.clientId);
        if (!current || mutation.counter !== Number(current.revision) + 1) return 'reject-fork';
        await exec.query('DELETE FROM tsk_credential_replica_maps WHERE stream_id=$1 AND client_id=$2',
          [this.streamId, mutation.clientId]);
      } else {
        const current = await readReplica(mutation.clientId);
        if (!verifySnapshot(mutation, current)) return 'reject-fork';
        await upsert(mutation);
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
