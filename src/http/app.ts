import Fastify, { type FastifyInstance, type FastifyRequest, type FastifyReply } from 'fastify';
import { type TenantRegistry } from '../tenancy/tenant-registry.js';
import { handleS3Request } from '../s3/router.js';
import { registerAdminRoutes } from '../admin/routes.js';
import { createRequestContext, runWithContext, getRequestId } from '../observability/request-context.js';
import { info, error } from '../observability/logger.js';

export interface AppOptions {
  tenantRegistry: TenantRegistry;
  adminKey: string;
}

export function buildApp(opts: AppOptions): FastifyInstance {
  const { tenantRegistry, adminKey } = opts;

  const app = Fastify({
    logger: false,
    bodyLimit: 5 * 1024 ** 3,
    requestTimeout: 300_000,
  });

  // Request context
  app.addHook('onRequest', async (req: FastifyRequest) => {
    const ctx = createRequestContext();
    runWithContext(ctx, () => {
      (req as any).__requestId = ctx.requestId;
      (req as any).__startTime = ctx.startTime;
    });
  });

  // Response logging
  app.addHook('onResponse', async (req: FastifyRequest, reply: FastifyReply) => {
    const requestId = (req as any).__requestId || getRequestId();
    if (!reply.sent) {
      reply.header('x-amz-request-id', requestId);
    }
    const startTime = (req as any).__startTime as number | undefined;
    const durationMs = startTime ? Date.now() - startTime : 0;
    info('request', {
      requestId,
      method: req.method,
      url: req.url,
      statusCode: reply.statusCode,
      durationMs,
    });
  });

  // Health
  app.get('/healthz', async (_req, reply) => reply.status(200).send({ status: 'ok' }));
  app.get('/readyz', async (_req, reply) => {
    if (tenantRegistry.allTenants.length === 0) {
      return reply.status(503).send({ status: 'not ready', reason: 'no tenants configured' });
    }
    return reply.status(200).send({ status: 'ready', tenants: tenantRegistry.allTenants.length });
  });

  // Admin routes (registered before catch-all)
  registerAdminRoutes(app, adminKey, tenantRegistry);

  // Admin key endpoint info
  app.get('/admin', async (_req, reply) => {
    return reply.status(200).send({ path: `/admin/${adminKey}`, hint: 'append the admin key to access the panel' });
  });

  // S3 catch-all
  app.all('*', async (req: FastifyRequest, reply: FastifyReply) => {
    try {
      await handleS3Request(req, reply, tenantRegistry);
    } catch (err) {
      const requestId = (req as any).__requestId || 'unknown';
      error('unhandled error', { requestId, error: String(err) });
      if (!reply.sent) {
        return reply.status(500).type('application/xml').send(
          `<?xml version="1.0" encoding="UTF-8"?><Error><Code>InternalError</Code><Message>${String(err)}</Message><RequestId>${requestId}</RequestId></Error>`,
        );
      }
    }
  });

  return app;
}