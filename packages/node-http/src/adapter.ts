import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import {
  buildTSKResponseHeaders,
  type TSKServerConfig,
  type TumblerMapStore,
  type TSKProvisioner,
  verifyTSKRequest,
} from '@tsk/server';
import {
  verifyUltraRequest,
  type BPCLikeResult,
  type BPCScope,
  type UltraVerifyOptions,
} from '@tsk/bpc-bridge';

export interface TSKAuthentication {
  clientId: string;
  requestId: string;
  rotationRequired: boolean;
  requestsRemaining?: number;
}

export interface TSKHttpAuthenticatorOptions {
  store: TumblerMapStore;
  config?: TSKServerConfig;
  /** Supply this when the proxy is trusted and has a canonical client address. */
  resolveIpAddress?: (request: IncomingMessage) => string | undefined;
}

/**
 * Authenticate one incoming HTTP request and apply the TSK response contract.
 * The caller owns authorization and must call it before invoking a protected
 * application handler. Authentication failures have deliberately generic JSON.
 */
export async function authenticateTSKHttpRequest(
  request: IncomingMessage,
  response: ServerResponse,
  options: TSKHttpAuthenticatorOptions,
): Promise<TSKAuthentication | null> {
  const requestId = request.headers['x-request-id']?.toString() || randomUUID();
  response.setHeader('X-Request-ID', requestId);
  const ipAddress = options.resolveIpAddress?.(request) ?? request.socket.remoteAddress;
  const result = await verifyTSKRequest(
    { headers: request.headers },
    options.store,
    { ...options.config, ipAddress: options.config?.ipAddress ?? ipAddress },
  );
  if (!result.ok || !result.clientId) {
    writeJson(response, 401, { error: { code: 'TSK_AUTHENTICATION_FAILED', message: 'Authentication failed' }, meta: { requestId } });
    return null;
  }
  for (const [name, value] of Object.entries(buildTSKResponseHeaders(result))) response.setHeader(name, value);
  return {
    clientId: result.clientId,
    requestId,
    rotationRequired: result.rotationRequired === true,
    requestsRemaining: result.requestsRemaining,
  };
}

export interface BpcTskHttpAuthenticatorOptions extends TSKHttpAuthenticatorOptions {
  bpcVerify: (request: IncomingMessage) => Promise<BPCLikeResult>;
  identityBinding: UltraVerifyOptions['identityBinding'];
}

export interface BpcTskAuthentication extends TSKAuthentication {
  pairId: string;
  scope: BPCScope;
}

/** Authenticate BPC first, then TSK, and require the two identities to bind. */
export async function authenticateBpcTskHttpRequest(
  request: IncomingMessage,
  response: ServerResponse,
  options: BpcTskHttpAuthenticatorOptions,
): Promise<BpcTskAuthentication | null> {
  const requestId = request.headers['x-request-id']?.toString() || randomUUID();
  response.setHeader('X-Request-ID', requestId);
  const result = await verifyUltraRequest(
    { headers: request.headers },
    () => options.bpcVerify(request),
    { tskStore: options.store, tskConfig: options.config, identityBinding: options.identityBinding },
  );
  if (!result.ok || !result.clientId || !result.pairId || !result.scope) {
    writeJson(response, 401, { error: { code: 'BPC_TSK_AUTHENTICATION_FAILED', message: 'Authentication failed' }, meta: { requestId } });
    return null;
  }
  // The bridge invokes the same TSK verifier; successful responses must carry
  // the wire-level confirmation required by @tsk/client-sdk.
  response.setHeader('x-tsk-authenticated', '1');
  return { clientId: result.clientId, pairId: result.pairId, scope: result.scope, requestId, rotationRequired: false };
}

export interface AdminPrincipal { operatorId: string; }

export interface CredentialDelivery {
  clientId: string;
  sharedSecret: string;
  provisionPayload: NonNullable<Awaited<ReturnType<TSKProvisioner['provision']>>['provisionPayload']>;
}

export interface CredentialAdminApiOptions {
  provisioner: TSKProvisioner;
  /** Mandatory deployment-owned authorization, e.g. mTLS/JWT/OIDC gateway. */
  authenticateOperator: (request: IncomingMessage) => Promise<AdminPrincipal | null>;
  /** Mandatory secure channel to the client or customer vault. Never HTTP output. */
  deliverCredential: (credential: CredentialDelivery, principal: AdminPrincipal) => Promise<void>;
  maxBodyBytes?: number;
}

/**
 * A deliberately small lifecycle API. It is not an identity provider: the
 * customer must plug in OIDC/mTLS/another operator boundary through
 * `authenticateOperator`. All credentials are delivered out-of-band.
 */
export function createCredentialAdminHandler(options: CredentialAdminApiOptions): (request: IncomingMessage, response: ServerResponse) => Promise<boolean> {
  const maxBodyBytes = options.maxBodyBytes ?? 16 * 1024;
  if (!options.authenticateOperator || !options.deliverCredential) throw new Error('TSK_ADMIN_AUTH_AND_DELIVERY_REQUIRED');
  return async (request, response) => {
    const url = new URL(request.url ?? '/', 'http://tsk.local');
    if (!url.pathname.startsWith('/v1/credentials')) return false;
    const requestId = request.headers['x-request-id']?.toString() || randomUUID();
    response.setHeader('X-Request-ID', requestId);
    const principal = await options.authenticateOperator(request);
    if (!principal?.operatorId) {
      writeJson(response, 401, { error: { code: 'OPERATOR_AUTHENTICATION_REQUIRED', message: 'Authentication required' }, meta: { requestId } });
      return true;
    }
    try {
      if (request.method === 'GET' && url.pathname === '/v1/credentials') {
        writeJson(response, 200, { data: await options.provisioner.listKeys(), meta: { requestId } });
        return true;
      }
      if (request.method === 'POST' && url.pathname === '/v1/credentials') {
        const body = await readJson(request, maxBodyBytes);
        const result = await options.provisioner.provision(
          parseMapOptions(body), principal.operatorId, parseLifecycle(body),
        );
        if (!result.ok || !result.clientId || !result.tumblerMap || !result.provisionPayload) {
          writeJson(response, result.error === 'PROVISION_RATE_LIMIT_EXCEEDED' ? 429 : 422,
            { error: { code: result.error ?? 'PROVISION_FAILED', message: 'Credential could not be provisioned' }, meta: { requestId } });
          return true;
        }
        await options.deliverCredential({ clientId: result.clientId, sharedSecret: result.tumblerMap.sharedSecret, provisionPayload: result.provisionPayload }, principal);
        writeJson(response, 201, { data: { clientId: result.clientId, status: 'active', createdAt: result.tumblerMap.createdAt }, meta: { requestId } });
        return true;
      }
      const match = /^\/v1\/credentials\/([^/]+)$/.exec(url.pathname);
      if (request.method === 'DELETE' && match) {
        const body = await readJson(request, maxBodyBytes);
        const reason = optionalString(body.reason);
        if (!reason) return writeValidationError(response, requestId, 'reason is required');
        const revoked = await options.provisioner.revoke(decodeURIComponent(match[1]), principal.operatorId, reason);
        if (!revoked) {
          writeJson(response, 404, { error: { code: 'CREDENTIAL_NOT_FOUND_OR_NOT_AUTHORIZED', message: 'Credential not found' }, meta: { requestId } });
        } else response.writeHead(204).end();
        return true;
      }
      writeJson(response, 404, { error: { code: 'NOT_FOUND', message: 'Not found' }, meta: { requestId } });
      return true;
    } catch (error) {
      const message = error instanceof Error ? error.message : 'INVALID_REQUEST';
      const status = message === 'REQUEST_BODY_TOO_LARGE' ? 413 : 400;
      writeJson(response, status, { error: { code: status === 413 ? message : 'INVALID_REQUEST', message: 'Invalid request' }, meta: { requestId } });
      return true;
    }
  };
}

async function readJson(request: IncomingMessage, maxBodyBytes: number): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += value.length;
    if (total > maxBodyBytes) throw new Error('REQUEST_BODY_TOO_LARGE');
    chunks.push(value);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  if (!text) return {};
  const value: unknown = JSON.parse(text);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('INVALID_JSON_OBJECT');
  return value as Record<string, unknown>;
}

function parseMapOptions(body: Record<string, unknown>) {
  return {
    keyLength: optionalInteger(body.keyLength),
    minTumblers: optionalInteger(body.minTumblers),
    maxTumblers: optionalInteger(body.maxTumblers),
  };
}

function parseLifecycle(body: Record<string, unknown>) {
  const expiresAt = optionalInteger(body.expiresAt);
  const maxRequests = optionalInteger(body.maxRequests);
  const rotationWarningRequests = optionalInteger(body.rotationWarningRequests);
  const label = optionalString(body.label);
  if (expiresAt !== undefined && expiresAt <= Date.now()) throw new Error('INVALID_EXPIRY');
  return { label, expiresAt, maxRequests, rotationWarningRequests };
}

function optionalInteger(value: unknown): number | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'number' || !Number.isSafeInteger(value)) throw new Error('INVALID_INTEGER');
  return value;
}

function optionalString(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.trim() === '' || value.length > 256) throw new Error('INVALID_STRING');
  return value;
}

function writeValidationError(response: ServerResponse, requestId: string, detail: string): boolean {
  writeJson(response, 422, { error: { code: 'VALIDATION_ERROR', message: detail }, meta: { requestId } });
  return true;
}

function writeJson(response: ServerResponse, status: number, body: unknown): void {
  if (response.headersSent) return;
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  response.end(JSON.stringify(body));
}
