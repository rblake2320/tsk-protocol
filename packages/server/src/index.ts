export * from './store.js';
export * from './provisioner.js';
export * from './anomaly.js';
export * from './middleware.js';

import { MemoryTumblerStore } from './store.js';
import { TSKProvisioner } from './provisioner.js';
import { MemoryAnomalyEngine } from './anomaly.js';

export interface TSKServerInstance {
  store: MemoryTumblerStore;
  provisioner: TSKProvisioner;
  anomaly: MemoryAnomalyEngine;
}

/**
 * Factory function to create a TSK server with in-memory backends (dev/testing).
 * For production: replace with PgTumblerStore + Redis anomaly.
 */
export function createTSKServer(): TSKServerInstance {
  const store = new MemoryTumblerStore();
  const provisioner = new TSKProvisioner(store);
  const anomaly = new MemoryAnomalyEngine();
  return { store, provisioner, anomaly };
}
