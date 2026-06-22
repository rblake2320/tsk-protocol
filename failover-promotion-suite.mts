/**
 * TSK HA — promotion gate + FailoverTransport suite
 * Run with: npx tsx failover-promotion-suite.mts
 *
 * Tests the REAL promotion gate (server) and FailoverTransport (client). Both
 * are protocol-agnostic copies shared with BPC; this proves the TSK copies
 * behave identically under the Option A contract.
 */
import {
  PromotionController, assertWritable, handlePromotionCommand,
} from './packages/server/src/promotion.ts';
import {
  FailoverTransport, PrimaryUnavailableError,
} from './packages/client-sdk/src/failover-transport.ts';

let passed = 0, failed = 0;
const failures: string[] = [];
async function test(name: string, fn: () => Promise<void> | void) {
  try { await fn(); passed++; console.log(`  ✓ ${name}`); }
  catch (e: any) { failed++; failures.push(`${name}: ${e?.message ?? e}`); console.log(`  ✗ ${name}\n    ${e?.message ?? e}`); }
}
function assert(c: boolean, m: string) { if (!c) throw new Error(m); }

const GUARD = 'guard-token-xyz';
const PRIMARY = 'https://primary.test';
const REPLICA = 'https://replica.test';

function makeNet() {
  const up: Record<string, boolean> = {};
  const hits: string[] = [];
  const impl = (async (url: any) => {
    const u = String(url);
    hits.push(u);
    const base = Object.keys(up).find((b) => u.startsWith(b));
    if (base && up[base]) return new Response('{}', { status: 200 });
    throw new Error(`network down: ${u}`);
  }) as unknown as typeof fetch;
  return { impl, hits, set: (b: string, v: boolean) => { up[b] = v; } };
}

console.log('\nTSK Promotion Gate + FailoverTransport Suite\n' + '─'.repeat(60));

// ── Promotion gate (PR-01/02/03) ──
await test('PR-01: fresh replica is NOT writable; promote makes it writable', () => {
  const r = new PromotionController('replica');
  assert(!r.isWritable(), 'fresh replica must be read-only');
  assert(assertWritable(r).ok === false, 'assertWritable must 503 a fresh replica');
  r.promote('fleet-guard', 'primary down');
  assert(r.isWritable(), 'promoted replica must be writable');
  assert(assertWritable(r).ok === true, 'assertWritable must pass a promoted replica');
});

await test('PR-01: primary is always writable and cannot be promoted/demoted', () => {
  const p = new PromotionController('primary');
  assert(p.isWritable(), 'primary always writable');
  let threw = false;
  try { p.promote('g'); } catch { threw = true; }
  assert(threw, 'promoting a primary must throw');
});

await test('PR-02: promoted state never auto-clears (explicit demote only)', () => {
  const r = new PromotionController('replica');
  r.promote('guard');
  assert(r.isWritable(), 'still writable');
  assert(r.isWritable(), 'still writable on re-check (no auto-expiry)');
  r.demote('guard', 'primary recovered');
  assert(!r.isWritable(), 'explicit demote reverts to read-only');
});

await test('PR-03: guard-only admin command (401 wrong token, 200 valid, 409 on primary)', () => {
  const r = new PromotionController('replica');
  assert(handlePromotionCommand(r, { 'x-guard-token': 'bad' }, { command: 'promote', by: 'x' }, GUARD).status === 401, 'wrong token → 401');
  assert(!r.isWritable(), 'unchanged after 401');
  const ok = handlePromotionCommand(r, { 'x-guard-token': GUARD }, { command: 'promote', by: 'guard', reason: 'failover' }, GUARD);
  assert(ok.status === 200, 'valid guard token → 200');
  assert(r.isWritable(), 'promoted via command');
  const p = new PromotionController('primary');
  assert(handlePromotionCommand(p, { 'x-guard-token': GUARD }, { command: 'promote', by: 'g' }, GUARD).status === 409, 'promote on primary → 409');
});

// ── FailoverTransport (FT-01/02/03) ──
await test('FT-02: writes are primary-only; PrimaryUnavailableError, never replica', async () => {
  const net = makeNet(); net.set(PRIMARY, false); net.set(REPLICA, true);
  const t = new FailoverTransport({ primary: PRIMARY, replicas: [REPLICA], missThreshold: 1, fetchImpl: net.impl });
  let firstThrew = false;
  try { await t.write('/provision', {}); } catch { firstThrew = true; }
  assert(firstThrew, 'first write attempt fails (trips primary unhealthy)');
  let isPrimaryUnavail = false;
  try { await t.write('/provision', {}); } catch (e) { isPrimaryUnavail = e instanceof PrimaryUnavailableError; }
  assert(isPrimaryUnavail, 'second write throws PrimaryUnavailableError');
  assert(!net.hits.some((h) => h.startsWith(REPLICA)), 'replica must NEVER receive a write');
});

await test('FT-01: reads fail over to replica and stay sticky after threshold', async () => {
  const net = makeNet(); net.set(PRIMARY, false); net.set(REPLICA, true);
  const t = new FailoverTransport({ primary: PRIMARY, replicas: [REPLICA], missThreshold: 3, fetchImpl: net.impl });
  for (let i = 0; i < 3; i++) {
    const res = await t.read('/status');
    assert(res.status === 200, 'read should be served by replica');
  }
  assert(t.primaryHealthy === false, 'primary marked unhealthy after 3 misses');
  assert(t.activeReadUrl === REPLICA, 'sticky to replica');
});

await test('FT-03: primary probe restores health and reads fail back', async () => {
  const net = makeNet(); net.set(PRIMARY, false); net.set(REPLICA, true);
  const t = new FailoverTransport({ primary: PRIMARY, replicas: [REPLICA], missThreshold: 1, fetchImpl: net.impl });
  await t.read('/status');
  assert(t.primaryHealthy === false, 'primary down after miss');
  net.set(PRIMARY, true);
  const ok = await t.probePrimary();
  assert(ok === true, 'probe passes after recovery');
  assert(t.primaryHealthy === true, 'primary failed back');
  assert(t.activeReadUrl === PRIMARY, 'reads return to primary');
});

console.log('\n' + '─'.repeat(60));
console.log(`TSK Promotion + Failover Suite: ${passed}/${passed + failed} passed`);
if (failed > 0) {
  console.log(`\nFAILURES (${failed}):`);
  for (const f of failures) console.log(`  ✗ ${f}`);
  process.exit(1);
} else {
  console.log('ALL TESTS PASSED — TSK promotion gate + failover transport verified');
  process.exit(0);   // explicit: a pending backoff setTimeout would otherwise keep node alive
}
