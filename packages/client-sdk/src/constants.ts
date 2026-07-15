export const TSK_HEADERS = {
  CLIENT_ID: 'x-tsk-client-id',
  KEY: 'x-tsk-key',
  VERSION: 'x-tsk-version',
} as const;

export const TSK_RESPONSE_HEADERS = {
  AUTHENTICATED: 'x-tsk-authenticated',
  ROTATION_REQUIRED: 'x-tsk-rotation-required',
  REQUESTS_REMAINING: 'x-tsk-requests-remaining',
} as const;

export const TSK_PROTOCOL_VERSION = '1';
