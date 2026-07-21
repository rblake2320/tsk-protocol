import { access, readFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

interface PackageManifest {
  name: string;
  version: string;
  main: string;
  types: string;
  files?: string[];
  engines?: Record<string, string>;
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  exports?: {
    '.': {
      import?: string;
      types?: string;
    };
  };
}

const workspaces = ['core', 'server', 'client-sdk', 'bpc-bridge'];
let passed = 0;

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

for (const workspace of workspaces) {
  const packageDir = path.resolve('packages', workspace);
  const manifest = JSON.parse(
    await readFile(path.join(packageDir, 'package.json'), 'utf8'),
  ) as PackageManifest;

  assert(manifest.files?.includes('dist'), `${manifest.name} does not publish dist`);
  assert(manifest.engines?.node === '>=24 <25', `${manifest.name} does not declare the validated Node runtime`);
  assert(manifest.exports?.['.']?.import === manifest.main, `${manifest.name} import export disagrees with main`);
  assert(manifest.exports?.['.']?.types === manifest.types, `${manifest.name} type export disagrees with types`);
  for (const [dependency, range] of Object.entries(manifest.dependencies ?? {})) {
    if (dependency.startsWith('@tsk/')) {
      assert(range === `^${manifest.version}`, `${manifest.name} has unbounded internal dependency ${dependency}@${range}`);
    }
  }
  if (manifest.name === '@tsk/bpc-bridge') {
    assert(
      manifest.peerDependencies?.['@bpc/server'] === '^0.2.0',
      `${manifest.name} is not aligned with the validated BPC 0.2 package line`,
    );
  }

  const mainPath = path.resolve(packageDir, manifest.main);
  const typesPath = path.resolve(packageDir, manifest.types);
  await access(mainPath);
  await access(typesPath);

  const exports = await import(pathToFileURL(mainPath).href);
  assert(Object.keys(exports).length > 0, `${manifest.name} runtime entry point has no exports`);

  // (HIGH1) the shipped package MUST NOT expose any readiness-token mint helper:
  // a deep import into dist/ could otherwise construct an unattested SchemaReadyToken.
  // Guard both the public entry AND the shipped outbox module by source scan.
  // Scoped to the readiness-token concept so unrelated names (e.g. secureRandomInt)
  // do not false-trip.
  const READINESS_MINT = /mintready|readymint|unsafe.*mint|mint.*readytoken|__internalunsafe/i;
  assert(
    !Object.keys(exports).some((k) => READINESS_MINT.test(k)),
    `${manifest.name} public API exposes a readiness-token mint helper`,
  );
  if (manifest.name === '@tsk/server') {
    const distDir = path.resolve(packageDir, 'dist');
    const outbox = await readFile(path.join(distDir, 'tsk-hotp-outbox-pg.js'), 'utf8');
    assert(
      !/export\s+(?:async\s+)?(?:function|const|let|var)\s+\w*[Mm]intReady\w*/.test(outbox)
        && !/export\s+(?:async\s+)?(?:function|const|let|var)\s+__internalUnsafe\w*/.test(outbox)
        && !/export\s*\{[^}]*(?:[Mm]intReady|__internalUnsafe)[^}]*\}/.test(outbox),
      '@tsk/server dist exports a readiness-token mint helper (deep-import bypass)',
    );
    // (#10 production transactor) `pg` MUST stay OUT of the runtime dependency
    // closure: the NodePostgresTransactor depends only on the structural
    // NodePostgres* interfaces, so a real pg.Pool is injected by the app, never
    // pulled in by @tsk/server itself.
    assert(
      !Object.keys(manifest.dependencies ?? {}).includes('pg') && !Object.keys(manifest.dependencies ?? {}).includes('@types/pg'),
      '@tsk/server must not depend on `pg` at runtime (structural injection only)',
    );
    // and the production transactor + its outcome taxonomy MUST be exported.
    for (const sym of ['NodePostgresTransactor', 'AmbiguousCommitError', 'PostCommitReleaseError', 'ConnectionDisposalError']) {
      assert(typeof (exports as Record<string, unknown>)[sym] === 'function', `@tsk/server must export ${sym}`);
    }
    for (const sym of ['PgHaTumblerMapStore', 'PgTskCredentialReceiverCheckpoint',
      'assertCredentialAuthorityReady', 'provisionCredentialRuntimeMutationBoundary',
      'assertCredentialRuntimeMutationBoundary', 'HmacCredentialMutationTicketSigner']) {
      assert(typeof (exports as Record<string, unknown>)[sym] === 'function', `@tsk/server must export ${sym}`);
    }
    assert(typeof (exports as Record<string, unknown>).TSK_CREDENTIAL_AUTHORITY_SCHEMA === 'string',
      '@tsk/server must export the credential-authority provisioning DDL');
  }
  passed++;
  console.log(`  PASS ${manifest.name} entry points exist and import (no mint/unsafe export)`);
}

console.log(`TSK package boundary suite: ${passed}/${workspaces.length} passed`);
