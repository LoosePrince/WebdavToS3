import { afterEach, describe, expect, it } from 'vitest';
import { createHmac, createHash } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../src/http/app.js';
import { TenantRegistry, type Tenant } from '../src/tenancy/tenant-registry.js';

const REGION = 'us-east-1';
const ACCESS_KEY = 'AKIAUNIID002';
const SECRET_KEY = 'f0rUn11dS3cr3tK3yP4s5';
const EMPTY_BODY_SHA256 = createHash('sha256').update('').digest('hex');

function createTenant(): Tenant {
  return {
    id: 'uniid-tenant',
    accessKeyId: ACCESS_KEY,
    secretAccessKey: SECRET_KEY,
    upstreams: new Map([
      [
        'primary',
        {
          id: 'primary',
          endpoint: 'https://example.com/webdav',
          username: 'demo',
          password: 'demo',
          rejectUnauthorized: true,
          connectTimeoutMs: 1000,
          requestTimeoutMs: 1000,
        },
      ],
    ]),
    buckets: new Map([
      [
        'uniid',
        {
          name: 'uniid',
          upstreamId: 'primary',
          rootPath: '/uniid',
          region: REGION,
        },
      ],
    ]),
  };
}

function createApp(): FastifyInstance {
  const registry = new TenantRegistry();
  registry.add(createTenant());
  return buildApp({ tenantRegistry: registry, adminKey: 'test-admin-key' });
}

function buildCanonicalQueryString(queryString: string): string {
  if (!queryString) return '';

  return queryString
    .split('&')
    .filter((segment) => segment.length > 0)
    .map((segment) => {
      const eqIndex = segment.indexOf('=');
      const rawKey = eqIndex === -1 ? segment : segment.slice(0, eqIndex);
      const rawValue = eqIndex === -1 ? '' : segment.slice(eqIndex + 1);
      return {
        key: encodeRfc3986(decodeQueryComponent(rawKey)),
        value: encodeRfc3986(decodeQueryComponent(rawValue)),
      };
    })
    .sort((a, b) => {
      if (a.key === b.key) return a.value.localeCompare(b.value);
      return a.key.localeCompare(b.key);
    })
    .map(({ key, value }) => `${key}=${value}`)
    .join('&');
}

function decodeQueryComponent(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, '%20'));
  } catch {
    return value;
  }
}

function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}

function signRequest(method: string, pathname: string, queryString: string, host: string): Record<string, string> {
  const amzDate = new Date().toISOString().replace(/[:-]/g, '').split('.')[0] + 'Z';
  const dateStamp = amzDate.slice(0, 8);

  const headers: Record<string, string> = {
    host,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': EMPTY_BODY_SHA256,
  };

  const signedHeaderNames = Object.keys(headers).sort();
  const canonicalHeaders = signedHeaderNames.map((name) => `${name}:${headers[name]!.trim()}\n`).join('');
  const signedHeaders = signedHeaderNames.join(';');

  const canonicalRequest = [
    method.toUpperCase(),
    pathname,
    buildCanonicalQueryString(queryString),
    canonicalHeaders,
    signedHeaders,
    EMPTY_BODY_SHA256,
  ].join('\n');

  const credentialScope = `${dateStamp}/${REGION}/s3/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');

  const signingKey = deriveSigningKey(SECRET_KEY, dateStamp, REGION);
  const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  return {
    ...headers,
    authorization: `AWS4-HMAC-SHA256 Credential=${ACCESS_KEY}/${credentialScope},SignedHeaders=${signedHeaders},Signature=${signature}`,
  };
}

function deriveSigningKey(secret: string, dateStamp: string, region: string): Buffer {
  const kDate = createHmac('sha256', `AWS4${secret}`).update(dateStamp).digest();
  const kRegion = createHmac('sha256', kDate).update(region).digest();
  const kService = createHmac('sha256', kRegion).update('s3').digest();
  return createHmac('sha256', kService).update('aws4_request').digest();
}

describe('SigV4 query string auth', () => {
  const apps: FastifyInstance[] = [];

  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
  });

  it('accepts bucket requests signed with x-id query string', async () => {
    const app = createApp();
    apps.push(app);

    const queryString = 'x-id=PutObject';
    const response = await app.inject({
      method: 'HEAD',
      url: `/uniid?${queryString}`,
      headers: signRequest('HEAD', '/uniid', queryString, '127.0.0.1'),
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['x-amz-bucket-region']).toBe(REGION);
  });

  it('normalizes query parameter order during verification', async () => {
    const app = createApp();
    apps.push(app);

    const queryString = 'z=last&x-id=PutObject&a=first';
    const response = await app.inject({
      method: 'HEAD',
      url: `/uniid?${queryString}`,
      headers: signRequest('HEAD', '/uniid', queryString, '127.0.0.1'),
    });

    expect(response.statusCode).toBe(200);
  });
});