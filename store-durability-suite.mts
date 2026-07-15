import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { generateTumblerMap } from './packages/core/src/index.ts';
import { FileClientStorage } from './packages/client-sdk/src/index.ts';
import { FileTumblerStore } from './packages/server/src/file-store.ts';
import { MemoryTumblerStore } from './packages/server/src/store.ts';

let passed = 0;
function assert(name: string, condition: boolean, detail = ''): void {
  if (!condition) throw new Error(`${name}: ${detail}`);
  passed++;
  console.log(`  ✓ ${name}`);
}

const directory = await mkdtemp(join(tmpdir(), 'tsk-store-durability-'));
try {
  const memory = new MemoryTumblerStore({ maxEntries: 1 });
  const first = generateTumblerMap();
  await memory.set(first.clientId, first);
  const exposed = await memory.get(first.clientId);
  exposed!.status = 'revoked';
  assert('mutating a retrieved map does not mutate stored authority', (await memory.get(first.clientId))?.status !== 'revoked');

  let capacityRejected = false;
  try {
    const second = generateTumblerMap();
    await memory.set(second.clientId, second);
  } catch (error) {
    capacityRejected = String(error).includes('TSK_STORE_CAPACITY_REACHED');
  }
  assert('capacity rejects instead of evicting an active credential', capacityRejected && await memory.get(first.clientId) !== null);

  const serverFile = join(directory, 'server.json');
  const fileStore = new FileTumblerStore(serverFile);
  await fileStore.set(first.clientId, first);
  await fileStore.commitValidation(first.clientId, { counterMatches: [], usedAt: Date.now() });
  const restarted = new FileTumblerStore(serverFile);
  assert('server file store survives restart with lifecycle state', (await restarted.get(first.clientId))?.requestCount === 1);

  const corruptServer = join(directory, 'corrupt-server.json');
  await writeFile(corruptServer, '{not-json', 'utf8');
  let serverCorruptionRejected = false;
  try { new FileTumblerStore(corruptServer); } catch { serverCorruptionRejected = true; }
  assert('corrupt server store fails closed instead of resetting', serverCorruptionRejected);

  const corruptClient = join(directory, 'corrupt-client.json');
  await writeFile(corruptClient, '{not-json', 'utf8');
  let clientCorruptionRejected = false;
  try { await new FileClientStorage(corruptClient).load(first.clientId); } catch { clientCorruptionRejected = true; }
  assert('corrupt client store fails closed instead of resetting counters', clientCorruptionRejected);

  console.log(`Store durability suite: ${passed}/${passed} named cases passed`);
} finally {
  await rm(directory, { recursive: true, force: true });
}
