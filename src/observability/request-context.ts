import { randomUUID } from 'node:crypto';
import { AsyncLocalStorage } from 'node:async_hooks';

export interface RequestContext {
  requestId: string;
  tenantId?: string;
  s3Operation?: string;
  bucket?: string;
  key?: string;
  startTime: number;
}

const als = new AsyncLocalStorage<RequestContext>();

export function runWithContext<T>(
  ctx: RequestContext,
  fn: () => T,
): T {
  return als.run(ctx, fn);
}

export function getContext(): RequestContext | undefined {
  return als.getStore();
}

export function createRequestContext(): RequestContext {
  return {
    requestId: randomUUID(),
    startTime: Date.now(),
  };
}

export function getRequestId(): string {
  return getContext()?.requestId ?? 'no-request-id';
}