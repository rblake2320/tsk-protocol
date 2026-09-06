# Reality audit — tsk-protocol

Audit date: 2026-09-01. Scope: `C:\Users\techai\tsk-protocol`. Read-only
execution was used; this report is the sole audit artifact. Pre-existing changes
to `.github/workflows/ci.yml` and `screenshots/` were not inspected or changed.

## Verdict

**The repository is real Node/TypeScript reference-library software, not an
AI-harness control plane.** Seven of twelve executable components were directly
proven under a plain PowerShell/Node shell; the core mission—deriving and
validating TSK credentials with server-side lifecycle/counter state—ran from
compiled packages without an AI model or harness. The project is **not a
production authentication service**: its default server is in-memory
([packages/server/src/index.ts:28-31](../packages/server/src/index.ts)), Redis
fencing could not be exercised because its required service was absent, and the
included demo has deliberately unsafe operational defaults. Docs, parked code,
and unexecuted browser UI remain UNKNOWN rather than being counted as real.

### Post-audit remediation

The audit found that the former `live-demo.mts` printed generated secrets and
implemented an independent demonstration algorithm. It has since been replaced
with a redacted demonstration that imports `@tsk/core`; see
[PRODUCT_CLAIMS.md](PRODUCT_CLAIMS.md) for the current claim boundary. This
report retains the original findings as historical audit evidence.

## Decision gates

1. Is `demo/server.ts` strictly local demonstration code, or is it expected to
   be deployed? If deployable, stop and redesign its auth/lifecycle endpoints:
   it has a known default admin token ([demo/server.ts:29](../demo/server.ts)),
   provisions without an admin check ([demo/server.ts:151-189](../demo/server.ts)),
   and deletes credentials without one ([demo/server.ts:193-210](../demo/server.ts)).
2. Choose and provision a real Redis 7.4-compatible endpoint, then rerun the
   only true cross-process fencing test; it defaults to port 6389
   ([redis-fencing-integration.mts:14-25](../redis-fencing-integration.mts)).
3. Decide whether the parked red-team/simulation lineages are historical
   evidence or intended product code. They are not invoked by any package script.

## Inventory

| Component | Type | Claims to do | Actually does (observed) | Depends on | Verdict | Evidence |
|---|---|---|---|---|---|---|
| Root workspace/build | config | Build four packages | TypeScript compilation completed | Node 24, npm | REAL | `npm run build` exited 0; package scripts at [package.json:12-21](../package.json) |
| `@tsk/core` | code | Map/key derivation and validation | Compiled export generated and validated a key | Node crypto | REAL | Built-artifact command reported `coreValidated:true`; entrypoint [packages/core/package.json:8-15](../packages/core/package.json) |
| `@tsk/server` | code | Provisioning, verification, lifecycle | Compiled export provisioned and verified a request | Node; selected store | REAL | Built-artifact command reported `serverValidated:true`; commit boundary [middleware.ts:70-150](../packages/server/src/middleware.ts) |
| `@tsk/client-sdk` | code | Client headers and counter persistence | Constructed compiled client; T0 suite passed file-restart and response-gating cases | Fetch endpoint supplied by adopter; filesystem for file store | REAL | Built-artifact command reported `clientSdkConstructed:true`; T0 `client-lifecycle-suite` 6/6 |
| `@tsk/bpc-bridge` | code | Compose BPC and TSK identity verification | Export loaded; real sibling BPC checkout completed 10 compatibility assertions | `@bpc/server` peer and `../bpc-protocol` checkout | REAL | `npm run test:bpc-compat` 10/10; peer declaration [packages/bpc-bridge/package.json:27-33](../packages/bpc-bridge/package.json) |
| Core/lifecycle/adversarial suites | code | Exercise crypto, caps, stores, attacks | 36/36 core, 32/32 lifecycle, 10/10 bounded adversarial, and related suites passed | Node/tsx; mostly in-process stores | REAL | `npm test` completed with all named suites passing |
| HA suites | code | Replication, receiver, promotion rules | 6/6, 9/9, and 10/10 passed | In-process simulated transport/store | REAL | `npm run test:ha` completed |
| Redis fencing integration | code | Cross-process Redis lease authority | Could not connect; no assertions ran | Redis at `TSK_REDIS_URL` or `127.0.0.1:6389` | UNKNOWN | T0 first error: `ECONNREFUSED 127.0.0.1:6389`; endpoint [redis-fencing-integration.mts:14](../redis-fencing-integration.mts) |
| `live-demo.mts` | code | Show crypto behavior | Ran eight demonstrations and reported 6/6 expected results | Node/tsx | REAL | `npx tsx live-demo.mts` completed; it prints live secrets/keys at [live-demo.mts:99-100](../live-demo.mts) and [130](../live-demo.mts) |
| `demo/server.ts` | code | HTTP demo with protected routes | Started at port 3200; `/health` and `/` returned 200; unauthenticated `/api/data` returned 401 | Node; optional filesystem; no AI | REAL | Startup [demo/server.ts:400-415](../demo/server.ts); captured HTTP responses |
| `demo/*.jsx` UI and browser E2E | code | Interactive demo screens | Server served source UI, but browser interaction suite was not run | Browser, Python Playwright, network CDN imports | UNKNOWN | E2E requires Playwright [demo/e2e_browser_test.py:6-25](../demo/e2e_browser_test.py) |
| Runtime-capture metadata | code | Capture AI-runtime metadata without blocking keys | T0 suite passed 23/23; it is optional telemetry, not execution | Optional caller-provided sink; reads Codex/Claude env names | REAL | Sink is optional [runtime-capture.ts:121-136](../packages/core/src/runtime-capture.ts); harness env references [77-103](../packages/core/src/runtime-capture.ts) |
| README/spec/security/parked docs | docs | Describe protocol and history | Not executable; selected current claims match the exercised packages, but no full claim-by-claim proof | None | UNKNOWN | Package list [README.md:52-55](../README.md); docs are claims, not runtime evidence |
| `parked/legacy-*` scripts | code/docs | Historical red-team/simulation work | Present but not in `package.json` scripts and not executed | Unknown historical environment | UNKNOWN | Files under [parked](../parked); root scripts [package.json:12-21](../package.json) |

## Unplug tests

### T0 — no AI, plain PowerShell

```text
node --version                         -> v24.17.0
npm run build                          -> exit 0 (all four packages compiled)
npm run typecheck                      -> exit 0
npm test                               -> all named suites passed
npm run test:ha                        -> 25/25 named HA cases passed
npm run test:pack                      -> compiled entry points imported; dry-run workspace packs produced
npm run test:bpc-compat                -> 10/10 passed against ../bpc-protocol
npm run test:redis                     -> FAILED: ECONNREFUSED 127.0.0.1:6389
npx tsx live-demo.mts                  -> 6/6 demo outcomes correct
npx tsx demo/server.ts                 -> started at http://localhost:3200
GET /health, GET /                     -> 200; GET /api/data without TSK -> 401
```

Built-artifact probe (after `npm run build`):

```json
{"coreValidated":true,"serverValidated":true,"clientSdkConstructed":true,"bridgeExported":true}
```

`npm pack --dry-run --workspaces` lists only `dist` files for the packages, but
it does not install those tarballs into a clean consumer project. That is useful
build evidence, not installed-package evidence.

### T1 — local model only

Not applicable. The runtime packages contain no model endpoint, agent loop, or
tool-execution dependency. They ran under T0.

### T2 — with an AI harness

Not needed. No component required it. The optional runtime-capture feature
recognizes `CODEX_*` and `CLAUDE_*` environment variables, but absent values
are ordinary optional metadata—not an execution dependency.

## Failure-class checklist

| Check | Result | Evidence |
|---|---|---|
| Instructions masquerading as software | CLEAR | `.claude` contains only an empty worktrees directory; no prompt/skill runtime was found. |
| Harness welds | FOUND, non-core telemetry only | Runtime capture reads harness-named environment variables [runtime-capture.ts:77-103](../packages/core/src/runtime-capture.ts), but the capture sink is optional [121](../packages/core/src/runtime-capture.ts). |
| Stubs presented as layers | CLEAR in active packages | No `TODO`, `NotImplementedError`, or placeholder implementation found in active `packages/*/src`; parked scripts remain UNKNOWN. |
| Green tests that prove nothing | FOUND, bounded | Most core tests are real Node crypto but use in-process stores; client network failure/success uses a replaced `globalThis.fetch` ([client-lifecycle-suite.mts:62-66](../client-lifecycle-suite.mts)). Redis had 0 real assertions because no server was available. |
| Silent-proceed failures | FOUND | Runtime capture intentionally swallows sink errors [runtime-capture.ts:129-136](../packages/core/src/runtime-capture.ts); appropriate for telemetry, but it cannot be evidence of a completed audit trail. |
| Missing fault barriers | CLEAR for model→tool boundary; UNKNOWN for arbitrary deployer network parsers | There is no model→tool execution path. Demo JSON parser returns 400 on invalid revoke/analytics payloads ([demo/server.ts:196-204](../demo/server.ts), [280-295](../demo/server.ts)). |
| Doc/code divergence | FOUND | README says this is a reference implementation, but `live-demo` prints a raw generated secret/key despite its name and output posture ([live-demo.mts:99-100](../live-demo.mts), [130](../live-demo.mts)). Demo server’s unauthenticated lifecycle endpoints are also not a deployable secure adapter. |
| Missing or tribal source | CLEAR for active packages | All shipped packages compile from tracked TypeScript; no source-less executable or package binary was found outside `node_modules`. |
| Duplicate lineages | CLEAR | No active duplicate module lineage found. Generated `dist/` is the build output of `packages/*/src`, not an alternate source. |
| Two engines, one mission | CLEAR | One active core/server/client/bridge implementation; parked files are excluded from scripts. |
| Environment traps | FOUND | Node is pinned to `>=24 <25` ([package.json:6-8](../package.json)); Redis defaults to a nonstandard local port 6389; BPC defaults to a sibling checkout ([bpc-compatibility-suite.mts:10](../bpc-compatibility-suite.mts)). |
| Frozen/installed-only defects | UNKNOWN | There is no exe/container artifact. Workspace packs were dry-run only, not clean-installed and exercised. |
| Secrets & credentials | FOUND | `live-demo` prints live shared secrets/keys; demo fallback admin token is source-visible [demo/server.ts:29](../demo/server.ts). Test secrets are fixtures, not production credentials. |
| Confabulation surface | FOUND | Runtime capture is optional and drops sink failures; replication/principal chains have tests, but the base deployment has no mandatory tamper-evident operational ledger. |

## What would make the unproven rows real

| Row | Testable condition | Rough AI time |
|---|---|---|
| Redis fencing | Run `npm run test:redis` against an isolated Redis 7.4 service and retain its six assertion transcript. | 1–2 hours |
| Demo UI E2E | Start demo in an isolated directory, run Playwright, and retain the browser console/network transcript with no unexpected errors. | 1–3 hours |
| Clean consumer packages | Pack each workspace, install it into a fresh directory, and run one core/server/client/bridge end-to-end program against those installed tarballs. | 2–4 hours |
| Parked legacy code | Identify the intended lineage, dependencies, and a reproducible command; execute it or delete/archive it by owner decision. | 2–8 hours |

## Recommended order if the goal is deployable software

1. Make the server adapter safe and explicit: require lifecycle authorization,
   remove fallback credentials and secret-bearing logs, and add a self-test that
   proves unauthenticated provision/revoke/export are denied.
2. Add a clean-installed-package smoke test that uses the compiled tarballs.
3. Bring up isolated Redis and make the fencing integration required in CI.
4. Choose a durable store, deployment config, TLS/endpoint authorization, and
   operations evidence; then test failover against those real boundaries.
5. Only then validate the browser demo as a non-production demonstration layer.

No implementation work from this order was performed.
