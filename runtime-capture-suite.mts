/**
 * Runtime capture + principal session continuity suite.
 * Run with: npx tsx runtime-capture-suite.mts
 */

import {
  generateKeyFromClientPayload,
  generateSharedSecret,
  generateTumblerMap,
  setKeyGenerationCaptureSink,
  toProvisionPayload,
  type KeyGenerationCaptureEvent,
} from './packages/core/src/index.js';
import {
  buildPrincipalSessionProofPayload,
  CacheExpiredError,
  CacheTamperedError,
  CacheUnavailableError,
  createTSKServer,
  DpapiFailClosedAgentCache,
  MemoryAgentCredentialCacheStore,
  MemoryPrincipalSessionLedger,
  computePermissionsHash,
  principalDigestFromSecret,
  sealPrincipalCache,
  sealAgentCredentialCacheEntry,
  signPrincipalSessionProof,
  verifyFallbackAuthorization,
  type BindSessionInput,
  type DpapiProtector,
  type SealedAgentCredentialCache,
} from './packages/server/src/index.js';

type TestResult = { name: string; passed: boolean; detail: string };
const results: TestResult[] = [];

function assert(name: string, condition: boolean, detail = '') {
  results.push({ name, passed: condition, detail });
  console.log(`  ${condition ? 'OK' : 'FAIL'} ${name}`);
  if (!condition) console.log(`    ${detail}`);
}

class PlaintextCurrentUserProtector implements DpapiProtector {
  readonly scope = 'CurrentUser' as const;

  async protect(plaintext: Uint8Array): Promise<Uint8Array> {
    return Buffer.from(plaintext);
  }

  async unprotect(ciphertext: Uint8Array): Promise<Uint8Array> {
    return Buffer.from(ciphertext);
  }
}

function makeBindingInput(
  principalSecret: string,
  overrides: Partial<BindSessionInput> = {},
): BindSessionInput {
  const provider = overrides.provider ?? 'codex';
  const providerSessionId = overrides.providerSessionId ?? 'abc-123';
  const agentInstanceId = overrides.agentInstanceId ?? `${provider}:${providerSessionId}`;
  const policyDigest = overrides.policyDigest ?? 'policy:v1:test';
  const signedAt = overrides.proof?.signedAt ?? Date.now();
  const challengeNonce = overrides.proof?.challengeNonce ?? 'nonce-1234567890abcdef';
  const principalDigest = principalDigestFromSecret(principalSecret);
  const payload = buildPrincipalSessionProofPayload({
    principalDigest,
    provider,
    providerSessionId,
    agentInstanceId,
    policyDigest,
    challengeNonce,
    signedAt,
  });

  return {
    principalSecret,
    provider,
    providerSessionId,
    agentInstanceId,
    policyDigest,
    proof: {
      challengeNonce,
      signedAt,
      signature: signPrincipalSessionProof(principalSecret, payload),
    },
    ...overrides,
  };
}

console.log('\n[TSK Runtime Capture]');

{
  const events: KeyGenerationCaptureEvent[] = [];
  setKeyGenerationCaptureSink(event => {
    events.push(event);
  });
  try {
    const map = generateTumblerMap(
      { keyLength: 64, minTumblers: 2, maxTumblers: 3 },
      { runtimeMetadata: { tool: 'codex', model: 'gpt-5.5', sessionId: 'session-1' } },
    );
    const payload = toProvisionPayload(map);
    const key = generateKeyFromClientPayload(
      map.sharedSecret,
      payload,
      new Map(),
      Date.now(),
      { captureDetails: { sharedSecret: 'must-not-leak', rawKey: keyLeakSentinel() } },
    );

    const serialized = JSON.stringify(events);
    assert('capture emits map + key events', events.length >= 2, `events=${events.length}`);
    assert('capture includes runtime model', serialized.includes('gpt-5.5'), serialized);
    assert('capture never includes raw TSK key', !serialized.includes(key), 'raw generated key leaked');
    assert('capture redacts secret-like fields', !serialized.includes('must-not-leak'), serialized);
  } finally {
    setKeyGenerationCaptureSink(undefined);
  }
}

console.log('\n[TSK Principal Session Binding]');

{
  const ledger = new MemoryPrincipalSessionLedger();
  const principalSecret = generateSharedSecret();
  const binding = await ledger.bindSession(makeBindingInput(principalSecret, {
    authorizationContext: { role: 'mesh-agent', scope: 'admin' },
    runtimeMetadata: { tool: 'claude-code', model: 'opusplan' },
  }));

  assert('session binds after fresh HMAC proof', binding.bindingHash.length === 64, binding.bindingHash);
  assert('continuity verifies after binding', (await ledger.verifyPrincipalContinuity(binding.principalId)).valid);

  const stale = makeBindingInput(principalSecret);
  stale.proof.signedAt = Date.now() - 10 * 60_000;
  let staleRejected = false;
  try {
    await ledger.bindSession(stale);
  } catch {
    staleRejected = true;
  }
  assert('stale proof fails closed', staleRejected);
}

console.log('\n[TSK Concurrent Streams]');

{
  const ledger = new MemoryPrincipalSessionLedger();
  const principalSecret = generateSharedSecret();
  const first = await ledger.bindSession(makeBindingInput(principalSecret, {
    provider: 'codex',
    providerSessionId: 'abc-123',
    agentInstanceId: 'forge-worker-a',
  }));
  const second = await ledger.bindSession(makeBindingInput(principalSecret, {
    provider: 'gemini',
    providerSessionId: 'ghi-789',
    agentInstanceId: 'forge-worker-b',
  }));

  assert('same principal spans provider sessions', first.principalId === second.principalId);
  assert('concurrent sessions use separate streams', first.streamId !== second.streamId);
  const principal = await ledger.getPrincipal(first.principalId);
  assert('principal records both session ids', JSON.stringify(principal?.sessionIds) === JSON.stringify(['abc-123', 'ghi-789']));
  assert('checkpointed continuity verifies', (await ledger.verifyPrincipalContinuity(first.principalId)).valid);

  await ledger.appendStreamEvent(first.principalId, first.streamId, 'session_event', { action: 'did-work' });
  const snapshot = ledger.snapshotStream(first.streamId);
  snapshot[1].payload = { action: 'tampered' };
  (ledger as unknown as { events: Map<string, typeof snapshot> }).events.set(first.streamId, snapshot);
  const result = await ledger.verifyPrincipalContinuity(first.principalId);
  assert('tamper in any stream breaks verification', !result.valid && result.reason === 'stream_entry_hash_mismatch', JSON.stringify(result));
}

console.log('\n[TSK Fail-Closed Fallback]');

{
  const ledger = new MemoryPrincipalSessionLedger();
  const principalSecret = generateSharedSecret();
  const sealKey = generateSharedSecret();
  const binding = await ledger.bindSession(makeBindingInput(principalSecret));
  const now = Date.now();
  const cache = sealPrincipalCache({
    source: 'sealed_cache',
    principalId: binding.principalId,
    policyDigest: binding.policyDigest,
    checkpointHash: binding.checkpointHash,
    issuedAt: now - 1000,
    expiresAt: now + 60_000,
    sealKey,
  });

  assert('sealed fallback authorizes only with equivalent checks', verifyFallbackAuthorization({
    cache,
    sealKey,
    requestedPolicyDigest: binding.policyDigest,
    expectedCheckpointHash: binding.checkpointHash,
    challengeNonce: 'nonce-1234567890abcdef',
    proofVerified: true,
    nowMs: now,
  }).ok);

  assert('tampered fallback cache fails closed', verifyFallbackAuthorization({
    cache: { ...cache, policyDigest: 'tampered' },
    sealKey,
    requestedPolicyDigest: binding.policyDigest,
    expectedCheckpointHash: binding.checkpointHash,
    challengeNonce: 'nonce-1234567890abcdef',
    proofVerified: true,
    nowMs: now,
  }).error === 'cache_seal_invalid');

  assert('policy mismatch fails closed', verifyFallbackAuthorization({
    cache,
    sealKey,
    requestedPolicyDigest: 'policy:other',
    expectedCheckpointHash: binding.checkpointHash,
    challengeNonce: 'nonce-1234567890abcdef',
    proofVerified: true,
    nowMs: now,
  }).error === 'policy_mismatch');

  assert('fallback still requires fresh proof', verifyFallbackAuthorization({
    cache,
    sealKey,
    requestedPolicyDigest: binding.policyDigest,
    expectedCheckpointHash: binding.checkpointHash,
    challengeNonce: 'nonce-1234567890abcdef',
    proofVerified: false,
    nowMs: now,
  }).error === 'fresh_proof_required');
}

console.log('\n[TSK DPAPI Fail-Closed Agent Cache]');

{
  const now = Date.now();
  const protector = new PlaintextCurrentUserProtector();
  const store = new MemoryAgentCredentialCacheStore();
  const cache = new DpapiFailClosedAgentCache(store, protector);
  const permissionsHash = computePermissionsHash({ permissions: ['write:credentials'] });

  await cache.write('agent-a', {
    principalId: 'principal_abc',
    bindingHash: 'sha256:binding-a',
    policyDigest: 'sha256:policy-a',
    permissionsHash,
    expiresAt: now + 60_000,
    credentialMaterial: 'tsk-principal-secret',
    nowMs: now,
  });

  const validEntry = await cache.read('agent-a', {
    principalId: 'principal_abc',
    bindingHash: 'sha256:binding-a',
    policyDigest: 'sha256:policy-a',
    permissionsHash,
    nowMs: now + 1,
  });
  assert('agent cache restores only after policy and permissions match',
    validEntry.policy_digest === 'sha256:policy-a' && validEntry.permissions_hash === permissionsHash);

  const tampered = tamperSealedEntry(await sealAgentCredentialCacheEntry({
    principalId: 'principal_abc',
    bindingHash: 'sha256:binding-a',
    policyDigest: 'sha256:policy-a',
    permissionsHash,
    expiresAt: now + 60_000,
    credentialMaterial: 'tsk-principal-secret',
    nowMs: now,
  }, protector), entry => {
    entry.binding_hash = 'sha256:binding-b';
  });
  await store.put('tampered-agent', tampered);
  let bindingTamperRejected = false;
  try {
    await cache.read('tampered-agent', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      nowMs: now + 1,
    });
  } catch (error) {
    bindingTamperRejected = error instanceof CacheTamperedError;
  }
  assert('binding_hash tamper throws CacheTamperedError', bindingTamperRejected);

  let stalePolicyRejected = false;
  try {
    await cache.read('agent-a', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-b',
      permissionsHash,
      nowMs: now + 1,
    });
  } catch (error) {
    stalePolicyRejected = error instanceof CacheTamperedError;
  }
  assert('stale policy digest throws CacheTamperedError', stalePolicyRejected);

  await store.put('scope-tampered-agent', {
    ...(await sealAgentCredentialCacheEntry({
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      expiresAt: now + 60_000,
      credentialMaterial: 'tsk-principal-secret',
      nowMs: now,
    }, protector)),
    scope: 'LocalMachine' as 'CurrentUser',
  });
  let invalidScopeRejected = false;
  try {
    await cache.read('scope-tampered-agent', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      nowMs: now + 1,
    });
  } catch (error) {
    invalidScopeRejected = error instanceof CacheTamperedError;
  }
  assert('LocalMachine cache scope throws CacheTamperedError', invalidScopeRejected);

  await cache.write('expired-agent', {
    principalId: 'principal_abc',
    bindingHash: 'sha256:binding-a',
    policyDigest: 'sha256:policy-a',
    permissionsHash,
    expiresAt: now - 1,
    credentialMaterial: 'tsk-principal-secret',
    nowMs: now - 1000,
  });
  let expiredRejected = false;
  try {
    await cache.read('expired-agent', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      nowMs: now,
    });
  } catch (error) {
    expiredRejected = error instanceof CacheExpiredError;
  }
  assert('expired cache throws CacheExpiredError', expiredRejected);

  let missingRejected = false;
  try {
    await cache.read('missing-agent', {
      principalId: 'principal_abc',
      bindingHash: 'sha256:binding-a',
      policyDigest: 'sha256:policy-a',
      permissionsHash,
      nowMs: now,
    });
  } catch (error) {
    missingRejected = error instanceof CacheUnavailableError;
  }
  assert('missing cache throws CacheUnavailableError', missingRejected);
}

console.log('\n[TSK Factory]');

{
  const server = createTSKServer();
  assert('factory exposes principal ledger', server.principalLedger instanceof MemoryPrincipalSessionLedger);
}

const failed = results.filter(r => !r.passed);
console.log('\n' + '-'.repeat(60));
console.log(`TSK Runtime Capture Suite: ${results.length - failed.length}/${results.length} passed`);
if (failed.length > 0) {
  for (const f of failed) console.log(`  FAIL ${f.name}: ${f.detail}`);
  process.exit(1);
}
console.log('ALL TESTS PASSED - runtime capture and principal continuity verified');

function keyLeakSentinel(): string {
  return 'raw-key-sentinel';
}

function tamperSealedEntry(
  sealed: SealedAgentCredentialCache,
  mutate: (entry: Record<string, unknown>) => void,
): SealedAgentCredentialCache {
  const entry = JSON.parse(Buffer.from(sealed.ciphertext_b64, 'base64').toString('utf8')) as Record<string, unknown>;
  mutate(entry);
  return {
    ...sealed,
    ciphertext_b64: Buffer.from(JSON.stringify(entry), 'utf8').toString('base64'),
  };
}
