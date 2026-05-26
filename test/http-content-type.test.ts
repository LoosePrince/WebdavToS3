import { afterEach, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../src/http/app.js';
import { TenantRegistry } from '../src/tenancy/tenant-registry.js';

describe('HTTP body parsing for S3 uploads', () => {
  const apps: FastifyInstance[] = [];

  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  function createApp(): FastifyInstance {
    const app = buildApp({
      tenantRegistry: new TenantRegistry(),
      adminKey: 'test-admin-key',
    });
    apps.push(app);
    return app;
  }

  it('passes unknown file content types through to the S3 layer', async () => {
    const app = createApp();

    const response = await app.inject({
      method: 'PUT',
      url: '/demo-bucket/photo.png',
      payload: Buffer.from('abc'),
      headers: {
        'content-type': 'image/png',
      },
    });

    expect(response.statusCode).toBe(404);
    expect(response.headers['content-type']).toContain('application/xml');
    expect(response.body).toContain('<Error>');
    expect(response.body).toContain('NoSuchBucket');
  });

  it('does not break JSON parsing for non-S3 routes', async () => {
    const app = createApp();

    app.post('/json-check', async (req, reply) => {
      const body = req.body as Record<string, unknown>;
      return reply.send({
        isBuffer: Buffer.isBuffer(req.body),
        value: body.value,
      });
    });

    const response = await app.inject({
      method: 'POST',
      url: '/json-check',
      payload: { value: 'ok' },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      isBuffer: false,
      value: 'ok',
    });
  });
});