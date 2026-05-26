import { afterEach, describe, expect, it } from 'vitest';
import { createHmac, createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../src/http/app.js';
import { TenantRegistry, type Tenant } from '../src/tenancy/tenant-registry.js';

const REGION = 'us-east-1';
const ACCESS_KEY = 'AKIAUNIID002';
const SECRET_KEY = 'f0rUn11dS3cr3tK3yP4s5';
const SESSION_TOKEN = 'local-session-token';
const EMPTY_BODY_SHA256 = createHash('sha256').update('').digest('hex');

interface RunningWebdav {
  endpoint: string;
  close: () => Promise<void>;
}

async function startMemoryWebdav(): Promise<RunningWebdav> {
  const files = new Map<string, Buffer>();
  const collections = new Set<string>(['/']);

  const server = createServer(async (req, res) => {
    const pathname = new URL(req.url ?? '/', 'http://127.0.0.1').pathname;
    const body = await readRequestBody(req);

    if (req.method === 'MKCOL') {
      collections.add(pathname);
      return send(res, 201);
    }

    if (req.method === 'PUT') {
      addParentCollections(pathname, collections);
      files.set(pathname, body);
      return send(res, 201, '', {
        etag: quotedMd5(body),
      });
    }

    if (req.method === 'GET') {
      const data = files.get(pathname);
      if (!data) return send(res, 404);
      return send(res, 200, data, {
        'content-length': String(data.length),
        'content-type': 'application/octet-stream',
        etag: quotedMd5(data),
        'last-modified': new Date(0).toUTCString(),
      });
    }

    if (req.method === 'DELETE') {
      files.delete(pathname);
      collections.delete(pathname);
      return send(res, 204);
    }

    if (req.method === 'PROPFIND') {
      const data = files.get(pathname);
      if (!data && !collections.has(pathname)) return send(res, 404);
      return send(res, 207, propfindXml(pathname, data), {
        'content-type': 'application/xml',
      });
    }

    return send(res, 405);
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    endpoint: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve()))),
  };
}

function createTenant(endpoint: string): Tenant {
  return {
    id: 'uniid-tenant',
    accessKeyId: ACCESS_KEY,
    secretAccessKey: SECRET_KEY,
    upstreams: new Map([
      [
        'primary',
        {
          id: 'primary',
          endpoint,
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

function createApp(endpoint: string): FastifyInstance {
  const registry = new TenantRegistry();
  registry.add(createTenant(endpoint));
  return buildApp({ tenantRegistry: registry, adminKey: 'test-admin-key' });
}

function createSessionTokenApp(endpoint: string): FastifyInstance {
  const registry = new TenantRegistry();
  registry.add({ ...createTenant(endpoint), sessionToken: SESSION_TOKEN });
  return buildApp({ tenantRegistry: registry, adminKey: 'test-admin-key' });
}

function signRequest(params: {
  method: string;
  pathname: string;
  queryString?: string;
  host: string;
  payloadHash?: string;
  extraHeaders?: Record<string, string>;
}): Record<string, string> {
  const amzDate = new Date().toISOString().replace(/[:-]/g, '').split('.')[0] + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const payloadHash = params.payloadHash ?? EMPTY_BODY_SHA256;
  const headers: Record<string, string> = {
    host: params.host,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
    ...(params.extraHeaders ?? {}),
  };
  const signedHeaderNames = Object.keys(headers).map((name) => name.toLowerCase()).sort();
  const canonicalHeaders = signedHeaderNames.map((name) => `${name}:${headers[name]!.trim()}\n`).join('');
  const signedHeaders = signedHeaderNames.join(';');
  const canonicalRequest = [
    params.method.toUpperCase(),
    params.pathname,
    buildCanonicalQueryString(params.queryString ?? ''),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');
  const credentialScope = `${dateStamp}/${REGION}/s3/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');
  const signature = createHmac('sha256', deriveSigningKey(SECRET_KEY, dateStamp, REGION)).update(stringToSign).digest('hex');

  return {
    ...headers,
    authorization: `AWS4-HMAC-SHA256 Credential=${ACCESS_KEY}/${credentialScope},SignedHeaders=${signedHeaders},Signature=${signature}`,
  };
}

function createPresignedQuery(params: {
  method: string;
  pathname: string;
  host: string;
  extraQuery?: string;
}): string {
  const amzDate = new Date().toISOString().replace(/[:-]/g, '').split('.')[0] + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${REGION}/s3/aws4_request`;
  const baseQuery = [
    'X-Amz-Algorithm=AWS4-HMAC-SHA256',
    `X-Amz-Content-Sha256=${encodeURIComponent('UNSIGNED-PAYLOAD')}`,
    `X-Amz-Credential=${encodeURIComponent(`${ACCESS_KEY}/${credentialScope}`)}`,
    `X-Amz-Date=${amzDate}`,
    'X-Amz-Expires=300',
    'X-Amz-SignedHeaders=host',
    params.extraQuery ?? 'x-id=GetObject',
  ].join('&');
  const canonicalRequest = [
    params.method.toUpperCase(),
    params.pathname,
    buildCanonicalQueryString(baseQuery),
    `host:${params.host}\n`,
    'host',
    'UNSIGNED-PAYLOAD',
  ].join('\n');
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    createHash('sha256').update(canonicalRequest).digest('hex'),
  ].join('\n');
  const signature = createHmac('sha256', deriveSigningKey(SECRET_KEY, dateStamp, REGION)).update(stringToSign).digest('hex');
  return `${baseQuery}&X-Amz-Signature=${signature}`;
}

function createPostPolicyForm(fields: Record<string, string>, file: Buffer): Buffer {
  const boundary = '----webdavtos3-test-boundary';
  const parts = Object.entries(fields).map(([name, value]) => multipartField(boundary, name, value));
  parts.push(
    Buffer.concat([
      Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="upload.txt"\r\nContent-Type: application/octet-stream\r\n\r\n`),
      file,
      Buffer.from('\r\n'),
    ]),
  );
  parts.push(Buffer.from(`--${boundary}--\r\n`));
  return Buffer.concat(parts);
}

function postPolicyHeaders(body: Buffer): Record<string, string> {
  return {
    host: '127.0.0.1',
    'content-type': 'multipart/form-data; boundary=----webdavtos3-test-boundary',
    'content-length': String(body.length),
  };
}

function createPostPolicyFields(key: string): Record<string, string> {
  const amzDate = new Date().toISOString().replace(/[:-]/g, '').split('.')[0] + 'Z';
  const dateStamp = amzDate.slice(0, 8);
  const credential = `${ACCESS_KEY}/${dateStamp}/${REGION}/s3/aws4_request`;
  const policy = Buffer.from(JSON.stringify({
    expiration: new Date(Date.now() + 300_000).toISOString(),
    conditions: [
      { bucket: 'uniid' },
      { key },
      { 'x-amz-algorithm': 'AWS4-HMAC-SHA256' },
      { 'x-amz-credential': credential },
      { 'x-amz-date': amzDate },
    ],
  })).toString('base64');
  const signature = createHmac('sha256', deriveSigningKey(SECRET_KEY, dateStamp, REGION)).update(policy).digest('hex');
  return {
    key,
    Policy: policy,
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': credential,
    'X-Amz-Date': amzDate,
    'X-Amz-Signature': signature,
  };
}

function multipartField(boundary: string, name: string, value: string): Buffer {
  return Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`);
}

function awsChunkedBody(data: Buffer): Buffer {
  return Buffer.concat([
    Buffer.from(`${data.length.toString(16)};chunk-signature=${'0'.repeat(64)}\r\n`),
    data,
    Buffer.from(`\r\n0;chunk-signature=${'0'.repeat(64)}\r\n\r\n`),
  ]);
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
    .sort((a, b) => (a.key === b.key ? a.value.localeCompare(b.value) : a.key.localeCompare(b.key)))
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

function deriveSigningKey(secret: string, dateStamp: string, region: string): Buffer {
  const kDate = createHmac('sha256', `AWS4${secret}`).update(dateStamp).digest();
  const kRegion = createHmac('sha256', kDate).update(region).digest();
  const kService = createHmac('sha256', kRegion).update('s3').digest();
  return createHmac('sha256', kService).update('aws4_request').digest();
}

function readRequestBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function send(res: ServerResponse, statusCode: number, body: Buffer | string = '', headers: Record<string, string> = {}) {
  res.writeHead(statusCode, headers);
  res.end(body);
}

function addParentCollections(pathname: string, collections: Set<string>) {
  const parts = pathname.split('/').filter(Boolean);
  let current = '';
  for (const part of parts.slice(0, -1)) {
    current += `/${part}`;
    collections.add(current);
  }
}

function quotedMd5(body: Buffer): string {
  return `"${createHash('md5').update(body).digest('hex')}"`;
}

function propfindXml(pathname: string, data?: Buffer): string {
  const isCollection = data === undefined;
  const length = data?.length ?? 0;
  const etag = data ? quotedMd5(data) : '"collection"';
  return `<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>${pathname}</d:href>
    <d:propstat>
      <d:prop>
        <d:getcontentlength>${length}</d:getcontentlength>
        <d:getetag>${etag}</d:getetag>
        <d:getlastmodified>${new Date(0).toUTCString()}</d:getlastmodified>
        <d:resourcetype>${isCollection ? '<d:collection/>' : ''}</d:resourcetype>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>`;
}

describe('S3 compatibility flows', () => {
  const apps: FastifyInstance[] = [];
  const webdavs: RunningWebdav[] = [];

  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
    await Promise.all(webdavs.splice(0).map((webdav) => webdav.close()));
  });

  it('accepts virtual-host-style bucket requests', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);

    const host = 'uniid.localhost';
    const response = await app.inject({
      method: 'HEAD',
      url: '/',
      headers: signRequest({ method: 'HEAD', pathname: '/', host }),
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers['x-amz-bucket-region']).toBe(REGION);
  });

  it('uploads, lists, completes, and reads a multipart object', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);

    const host = '127.0.0.1';
    const keyPath = '/uniid/multipart-object.txt';
    const createQuery = 'uploads=';
    const createResponse = await app.inject({
      method: 'POST',
      url: `${keyPath}?${createQuery}`,
      headers: signRequest({ method: 'POST', pathname: keyPath, queryString: createQuery, host }),
    });
    expect(createResponse.statusCode).toBe(200);
    const uploadId = createResponse.body.match(/<UploadId>([^<]+)<\/UploadId>/)?.[1];
    expect(uploadId).toBeTruthy();

    const partOne = Buffer.from('hello ');
    const partTwo = Buffer.from('world');
    for (const [partNumber, body] of [[1, partOne], [2, partTwo]] as const) {
      const queryString = `partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId!)}`;
      const response = await app.inject({
        method: 'PUT',
        url: `${keyPath}?${queryString}`,
        payload: body,
        headers: signRequest({
          method: 'PUT',
          pathname: keyPath,
          queryString,
          host,
          payloadHash: createHash('sha256').update(body).digest('hex'),
          extraHeaders: {
            'content-length': String(body.length),
          },
        }),
      });
      expect(response.statusCode).toBe(200);
      expect(response.headers.etag).toBeTruthy();
    }

    const listPartsQuery = `uploadId=${encodeURIComponent(uploadId!)}`;
    const listPartsResponse = await app.inject({
      method: 'GET',
      url: `${keyPath}?${listPartsQuery}`,
      headers: signRequest({ method: 'GET', pathname: keyPath, queryString: listPartsQuery, host }),
    });
    expect(listPartsResponse.statusCode).toBe(200);
    expect(listPartsResponse.body).toContain('<PartNumber>1</PartNumber>');
    expect(listPartsResponse.body).toContain('<PartNumber>2</PartNumber>');

    const completeBody = Buffer.from('<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part><Part><PartNumber>2</PartNumber></Part></CompleteMultipartUpload>');
    const completeQuery = `uploadId=${encodeURIComponent(uploadId!)}`;
    const completeResponse = await app.inject({
      method: 'POST',
      url: `${keyPath}?${completeQuery}`,
      payload: completeBody,
      headers: signRequest({
        method: 'POST',
        pathname: keyPath,
        queryString: completeQuery,
        host,
        payloadHash: createHash('sha256').update(completeBody).digest('hex'),
        extraHeaders: {
          'content-length': String(completeBody.length),
        },
      }),
    });
    expect(completeResponse.statusCode).toBe(200);
    expect(completeResponse.body).toContain('<CompleteMultipartUploadResult');

    const readResponse = await app.inject({
      method: 'GET',
      url: keyPath,
      headers: signRequest({ method: 'GET', pathname: keyPath, host }),
    });
    expect(readResponse.statusCode).toBe(200);
    expect(readResponse.body).toBe('hello world');
  });

  it('accepts virtual-host-style object write and read requests', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);

    const host = 'uniid.localhost';
    const pathname = '/nested/object.txt';
    const body = Buffer.from('virtual-host-body');
    const putResponse = await app.inject({
      method: 'PUT',
      url: pathname,
      payload: body,
      headers: signRequest({
        method: 'PUT',
        pathname,
        host,
        payloadHash: createHash('sha256').update(body).digest('hex'),
        extraHeaders: {
          'content-length': String(body.length),
        },
      }),
    });
    expect(putResponse.statusCode).toBe(200);

    const getResponse = await app.inject({
      method: 'GET',
      url: pathname,
      headers: signRequest({ method: 'GET', pathname, host }),
    });
    expect(getResponse.statusCode).toBe(200);
    expect(getResponse.body).toBe('virtual-host-body');
  });

  it('downloads objects through browser-style presigned URLs', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);

    const host = '127.0.0.1';
    const pathname = '/uniid/presigned-download.txt';
    const body = Buffer.from('presigned-body');
    const putResponse = await app.inject({
      method: 'PUT',
      url: pathname,
      payload: body,
      headers: signRequest({
        method: 'PUT',
        pathname,
        host,
        payloadHash: createHash('sha256').update(body).digest('hex'),
        extraHeaders: {
          'content-length': String(body.length),
        },
      }),
    });
    expect(putResponse.statusCode).toBe(200);

    const queryString = createPresignedQuery({ method: 'GET', pathname, host });
    const getResponse = await app.inject({
      method: 'GET',
      url: `${pathname}?${queryString}`,
      headers: {
        host,
      },
    });
    expect(getResponse.statusCode).toBe(200);
    expect(getResponse.body).toBe('presigned-body');
  });

  it('requires configured session tokens for signed requests', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createSessionTokenApp(webdav.endpoint);
    apps.push(app);

    const host = '127.0.0.1';
    const okResponse = await app.inject({
      method: 'HEAD',
      url: '/uniid',
      headers: signRequest({
        method: 'HEAD',
        pathname: '/uniid',
        host,
        extraHeaders: {
          'x-amz-security-token': SESSION_TOKEN,
        },
      }),
    });
    expect(okResponse.statusCode).toBe(200);

    const deniedResponse = await app.inject({
      method: 'HEAD',
      url: '/uniid',
      headers: signRequest({ method: 'HEAD', pathname: '/uniid', host }),
    });
    expect(deniedResponse.statusCode).toBe(403);
    expect(deniedResponse.body).toContain('Missing security token');
  });

  it('accepts SigV4 streaming payload identifiers for SDK chunked uploads', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);

    const host = '127.0.0.1';
    const pathname = '/uniid/streaming-marker.txt';
    const decoded = Buffer.from('streaming-compatible-body');
    const body = awsChunkedBody(decoded);
    const response = await app.inject({
      method: 'PUT',
      url: pathname,
      payload: body,
      headers: signRequest({
        method: 'PUT',
        pathname,
        host,
        payloadHash: 'STREAMING-AWS4-HMAC-SHA256-PAYLOAD',
        extraHeaders: {
          'content-length': String(body.length),
          'x-amz-decoded-content-length': String(decoded.length),
        },
      }),
    });
    expect(response.statusCode).toBe(200);

    const readResponse = await app.inject({
      method: 'GET',
      url: pathname,
      headers: signRequest({ method: 'GET', pathname, host }),
    });
    expect(readResponse.statusCode).toBe(200);
    expect(readResponse.body).toBe('streaming-compatible-body');
  });

  it('accepts browser POST policy uploads', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);

    const key = 'post-policy-object.txt';
    const body = createPostPolicyForm(createPostPolicyFields(key), Buffer.from('post-policy-body'));
    const uploadResponse = await app.inject({
      method: 'POST',
      url: '/uniid',
      payload: body,
      headers: postPolicyHeaders(body),
    });
    expect(uploadResponse.statusCode).toBe(204);

    const readPathname = `/uniid/${key}`;
    const readResponse = await app.inject({
      method: 'GET',
      url: readPathname,
      headers: signRequest({ method: 'GET', pathname: readPathname, host: '127.0.0.1' }),
    });
    expect(readResponse.statusCode).toBe(200);
    expect(readResponse.body).toBe('post-policy-body');
  });
});