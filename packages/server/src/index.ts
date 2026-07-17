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
