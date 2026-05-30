import { afterEach, describe, expect, it } from 'vitest';
import { createHmac, createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { FastifyInstance } from 'fastify';
import {
  AbortMultipartUploadCommand,
  CompleteMultipartUploadCommand,
  CopyObjectCommand,
  CreateBucketCommand,
  CreateMultipartUploadCommand,
  DeleteBucketCommand,
  DeleteBucketCorsCommand,
  DeleteBucketEncryptionCommand,
  DeleteBucketLifecycleCommand,
  DeleteBucketPolicyCommand,
  DeleteBucketTaggingCommand,
  DeleteObjectCommand,
  DeleteObjectsCommand,
  DeleteObjectTaggingCommand,
  DeletePublicAccessBlockCommand,
  GetBucketAclCommand,
  GetBucketCorsCommand,
  GetBucketEncryptionCommand,
  GetBucketLifecycleConfigurationCommand,
  GetBucketLocationCommand,
  GetBucketPolicyCommand,
  GetBucketTaggingCommand,
  GetBucketVersioningCommand,
  GetObjectCommand,
  GetObjectLegalHoldCommand,
  GetObjectRetentionCommand,
  GetObjectTaggingCommand,
  GetPublicAccessBlockCommand,
  HeadBucketCommand,
  HeadObjectCommand,
  ListBucketsCommand,
  ListMultipartUploadsCommand,
  ListObjectsCommand,
  ListObjectsV2Command,
  ListObjectVersionsCommand,
  ListPartsCommand,
  PutBucketAclCommand,
  PutBucketCorsCommand,
  PutBucketEncryptionCommand,
  PutBucketLifecycleConfigurationCommand,
  PutBucketPolicyCommand,
  PutBucketTaggingCommand,
  PutBucketVersioningCommand,
  PutObjectCommand,
  PutObjectLegalHoldCommand,
  PutObjectRetentionCommand,
  PutObjectTaggingCommand,
  PutPublicAccessBlockCommand,
  S3Client,
  UploadPartCommand,
} from '@aws-sdk/client-s3';
import { getSignedUrl } from '@aws-sdk/s3-request-presigner';
import { buildApp } from '../src/http/app.js';
import { createStorageBackendFactory } from '../src/s3/storage-backend.js';
import { TenantRegistry, type Tenant } from '../src/tenancy/tenant-registry.js';
import { runLifecycleOnce } from '../src/s3/lifecycle/worker.js';

const REGION = 'us-east-1';
const ACCESS_KEY = 'AKIAUNIID002';
const SECRET_KEY = 'f0rUn11dS3cr3tK3yP4s5';
const SESSION_TOKEN = 'local-session-token';
const EMPTY_BODY_SHA256 = createHash('sha256').update('').digest('hex');
const AWS_CLI_AVAILABLE = spawnSync('aws', ['--version'], { encoding: 'utf-8', shell: true }).status === 0;

interface RunningWebdav {
  endpoint: string;
  close: () => Promise<void>;
}

interface RunningS3App {
  endpoint: string;
  close: () => Promise<void>;
}

async function startS3App(app: FastifyInstance): Promise<RunningS3App> {
  await app.listen({ host: '127.0.0.1', port: 0 });
  const address = app.server.address() as AddressInfo;
  return {
    endpoint: `http://127.0.0.1:${address.port}`,
    close: () => app.close(),
  };
}

function createAwsSdkClient(endpoint: string): S3Client {
  return new S3Client({
    endpoint,
    region: REGION,
    forcePathStyle: true,
    credentials: {
      accessKeyId: ACCESS_KEY,
      secretAccessKey: SECRET_KEY,
    },
  });
}

async function streamToString(body: unknown): Promise<string> {
  if (!body || typeof (body as AsyncIterable<Uint8Array>)[Symbol.asyncIterator] !== 'function') return '';
  const chunks: Buffer[] = [];
  for await (const chunk of body as AsyncIterable<Uint8Array>) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString('utf-8');
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
      return send(res, 207, propfindXml(pathname, files, collections), {
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
      [
        'archive',
        {
          name: 'archive',
          upstreamId: 'primary',
          rootPath: '/archive',
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

function createSqliteApp(endpoint: string, metadataPath: string): FastifyInstance {
  const registry = new TenantRegistry();
  registry.add(createTenant(endpoint));
  return buildApp({
    tenantRegistry: registry,
    adminKey: 'test-admin-key',
    metadata: { driver: 'sqlite', path: metadataPath },
  });
}

function createSessionTokenApp(endpoint: string): FastifyInstance {
  const registry = new TenantRegistry();
  registry.add({ ...createTenant(endpoint), sessionToken: SESSION_TOKEN });
  return buildApp({ tenantRegistry: registry, adminKey: 'test-admin-key' });
}

function runAwsCli(args: string[]): { stdout: string; stderr: string } {
  const result = spawnSync('aws', args, {
    encoding: 'utf-8',
    shell: true,
    env: {
      ...process.env,
      AWS_ACCESS_KEY_ID: ACCESS_KEY,
      AWS_SECRET_ACCESS_KEY: SECRET_KEY,
      AWS_DEFAULT_REGION: REGION,
      AWS_EC2_METADATA_DISABLED: 'true',
    },
  });
  if (result.status !== 0) {
    throw new Error(`aws ${args.join(' ')} failed\n${result.stdout}\n${result.stderr}`);
  }
  return {
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
  };
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

function compareCanonicalComponent(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
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
    .sort((a, b) => (a.key === b.key ? compareCanonicalComponent(a.value, b.value) : compareCanonicalComponent(a.key, b.key)))
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

function contentBlobPath(body: Buffer): string {
  const digest = createHash('sha256').update(body).digest('hex');
  return `/.webdavtos3-blobs/sha256/${digest.slice(0, 2)}/${digest.slice(2, 4)}/${digest}`;
}

function propfindXml(pathname: string, files: Map<string, Buffer>, collections: Set<string>): string {
  const normalized = pathname.replace(/\/+$/, '') || '/';
  const prefix = normalized === '/' ? '/' : `${normalized}/`;
  const responsePaths = new Set<string>([normalized]);

  for (const path of collections) {
    const cleanPath = path.replace(/\/+$/, '') || '/';
    if (cleanPath !== normalized && cleanPath.startsWith(prefix) && !cleanPath.slice(prefix.length).includes('/')) {
      responsePaths.add(cleanPath);
    }
  }
  for (const path of files.keys()) {
    const cleanPath = path.replace(/\/+$/, '') || '/';
    if (cleanPath !== normalized && cleanPath.startsWith(prefix) && !cleanPath.slice(prefix.length).includes('/')) {
      responsePaths.add(cleanPath);
    }
  }

  const responses = [...responsePaths].sort().map((path) => {
    const data = files.get(path);
    const isCollection = data === undefined;
    const length = data?.length ?? 0;
    const etag = data ? quotedMd5(data) : '"collection"';
    return `  <d:response>
    <d:href>${path}</d:href>
    <d:propstat>
      <d:prop>
        <d:getcontentlength>${length}</d:getcontentlength>
        <d:getetag>${etag}</d:getetag>
        <d:getlastmodified>${new Date(0).toUTCString()}</d:getlastmodified>
        <d:resourcetype>${isCollection ? '<d:collection/>' : ''}</d:resourcetype>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>`;
  }).join('\n');

  return `<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:">
${responses}
</d:multistatus>`;
}

describe('S3 compatibility flows', () => {
  const apps: FastifyInstance[] = [];
  const webdavs: RunningWebdav[] = [];
  const tempDirs: string[] = [];

  afterEach(async () => {
    await Promise.all(apps.splice(0).map((app) => app.close()));
    await Promise.all(webdavs.splice(0).map((webdav) => webdav.close()));
    await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
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

  it('stores new SQLite-indexed objects as WebDAV blobs', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const tempDir = await mkdtemp(join(tmpdir(), 'webdavtos3-blob-backend-'));
    tempDirs.push(tempDir);
    const app = createSqliteApp(webdav.endpoint, join(tempDir, 'metadata.sqlite'));
    apps.push(app);

    const host = '127.0.0.1';
    const pathname = '/uniid/blob-indexed.txt';
    const body = Buffer.from('blob-indexed-body');
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
          'content-type': 'text/plain',
        },
      }),
    });
    expect(putResponse.statusCode).toBe(200);

    const directWebdavObject = await fetch(`${webdav.endpoint}${pathname}`);
    expect(directWebdavObject.status).toBe(404);

    const digest = createHash('sha256').update(body).digest('hex');
    const blobPath = `/.webdavtos3-blobs/sha256/${digest.slice(0, 2)}/${digest.slice(2, 4)}/${digest}`;
    const rawBlob = await fetch(`${webdav.endpoint}${blobPath}`);
    expect(rawBlob.status).toBe(200);
    expect(await rawBlob.text()).toBe('blob-indexed-body');

    const getResponse = await app.inject({
      method: 'GET',
      url: pathname,
      headers: signRequest({ method: 'GET', pathname, host }),
    });
    expect(getResponse.statusCode).toBe(200);
    expect(getResponse.headers['content-type']).toBe('text/plain');
    expect(getResponse.body).toBe('blob-indexed-body');

    const listQuery = 'prefix=blob-';
    const listResponse = await app.inject({
      method: 'GET',
      url: `/uniid?${listQuery}`,
      headers: signRequest({ method: 'GET', pathname: '/uniid', queryString: listQuery, host }),
    });
    expect(listResponse.statusCode).toBe(200);
    expect(listResponse.body).toContain('<Key>blob-indexed.txt</Key>');

    const deleteResponse = await app.inject({
      method: 'DELETE',
      url: pathname,
      headers: signRequest({ method: 'DELETE', pathname, host }),
    });
    expect(deleteResponse.statusCode).toBe(204);

    const getAfterDelete = await app.inject({
      method: 'GET',
      url: pathname,
      headers: signRequest({ method: 'GET', pathname, host }),
    });
    expect(getAfterDelete.statusCode).toBe(404);
    expect((await fetch(`${webdav.endpoint}${blobPath}`)).status).toBe(200);
  });

  it('copies SQLite-indexed objects by bodyPath without creating legacy object bodies', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const tempDir = await mkdtemp(join(tmpdir(), 'webdavtos3-copy-blob-'));
    tempDirs.push(tempDir);
    const app = createSqliteApp(webdav.endpoint, join(tempDir, 'metadata.sqlite'));
    apps.push(app);

    const host = '127.0.0.1';
    const sourceBucketPath = '/uniid';
    const versioningQuery = 'versioning=';
    const versioningBody = Buffer.from('<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>');
    const enableSourceVersioningResponse = await app.inject({
      method: 'PUT',
      url: `${sourceBucketPath}?${versioningQuery}`,
      payload: versioningBody,
      headers: signRequest({
        method: 'PUT',
        pathname: sourceBucketPath,
        queryString: versioningQuery,
        host,
        payloadHash: createHash('sha256').update(versioningBody).digest('hex'),
        extraHeaders: {
          'content-length': String(versioningBody.length),
          'content-type': 'application/xml',
        },
      }),
    });
    expect(enableSourceVersioningResponse.statusCode).toBe(200);

    const sourcePath = '/uniid/copy-source-versioned.txt';
    const firstBody = Buffer.from('copy-version-one');
    const firstPutResponse = await app.inject({
      method: 'PUT',
      url: sourcePath,
      payload: firstBody,
      headers: signRequest({
        method: 'PUT',
        pathname: sourcePath,
        host,
        payloadHash: createHash('sha256').update(firstBody).digest('hex'),
        extraHeaders: {
          'content-length': String(firstBody.length),
          'content-type': 'text/plain',
          'x-amz-meta-origin': 'copy-source',
        },
      }),
    });
    expect(firstPutResponse.statusCode).toBe(200);
    const firstVersionId = firstPutResponse.headers['x-amz-version-id'] as string;
    expect(firstVersionId).toBeTruthy();

    const secondBody = Buffer.from('copy-version-two');
    const secondPutResponse = await app.inject({
      method: 'PUT',
      url: sourcePath,
      payload: secondBody,
      headers: signRequest({
        method: 'PUT',
        pathname: sourcePath,
        host,
        payloadHash: createHash('sha256').update(secondBody).digest('hex'),
        extraHeaders: {
          'content-length': String(secondBody.length),
          'content-type': 'text/plain',
          'x-amz-meta-origin': 'copy-source',
        },
      }),
    });
    expect(secondPutResponse.statusCode).toBe(200);
    const secondVersionId = secondPutResponse.headers['x-amz-version-id'] as string;
    expect(secondVersionId).toBeTruthy();
    expect(secondVersionId).not.toBe(firstVersionId);

    expect((await fetch(`${webdav.endpoint}${sourcePath}`)).status).toBe(404);
    const firstDigest = createHash('sha256').update(firstBody).digest('hex');
    const firstBlobPath = `/.webdavtos3-blobs/sha256/${firstDigest.slice(0, 2)}/${firstDigest.slice(2, 4)}/${firstDigest}`;
    const secondDigest = createHash('sha256').update(secondBody).digest('hex');
    const secondBlobPath = `/.webdavtos3-blobs/sha256/${secondDigest.slice(0, 2)}/${secondDigest.slice(2, 4)}/${secondDigest}`;
    expect((await fetch(`${webdav.endpoint}${firstBlobPath}`)).status).toBe(200);
    expect((await fetch(`${webdav.endpoint}${secondBlobPath}`)).status).toBe(200);

    const specificCopyPath = '/archive/copied-specific-version.txt';
    const specificCopySource = `/uniid/copy-source-versioned.txt?versionId=${encodeURIComponent(firstVersionId)}`;
    const specificCopyResponse = await app.inject({
      method: 'PUT',
      url: specificCopyPath,
      headers: signRequest({
        method: 'PUT',
        pathname: specificCopyPath,
        host,
        extraHeaders: {
          'x-amz-copy-source': specificCopySource,
        },
      }),
    });
    expect(specificCopyResponse.statusCode).toBe(200);

    const specificReadResponse = await app.inject({
      method: 'GET',
      url: specificCopyPath,
      headers: signRequest({ method: 'GET', pathname: specificCopyPath, host }),
    });
    expect(specificReadResponse.statusCode).toBe(200);
    expect(specificReadResponse.body).toBe('copy-version-one');
    expect(specificReadResponse.headers['x-amz-version-id']).toBeUndefined();
    expect(specificReadResponse.headers['x-amz-meta-origin']).toBe('copy-source');
    expect((await fetch(`${webdav.endpoint}${specificCopyPath}`)).status).toBe(404);

    const archiveBucketPath = '/archive';
    const enableArchiveVersioningResponse = await app.inject({
      method: 'PUT',
      url: `${archiveBucketPath}?${versioningQuery}`,
      payload: versioningBody,
      headers: signRequest({
        method: 'PUT',
        pathname: archiveBucketPath,
        queryString: versioningQuery,
        host,
        payloadHash: createHash('sha256').update(versioningBody).digest('hex'),
        extraHeaders: {
          'content-length': String(versioningBody.length),
          'content-type': 'application/xml',
        },
      }),
    });
    expect(enableArchiveVersioningResponse.statusCode).toBe(200);

    const currentCopyPath = '/archive/copied-current-versioned.txt';
    const currentCopyResponse = await app.inject({
      method: 'PUT',
      url: currentCopyPath,
      headers: signRequest({
        method: 'PUT',
        pathname: currentCopyPath,
        host,
        extraHeaders: {
          'x-amz-copy-source': '/uniid/copy-source-versioned.txt',
        },
      }),
    });
    expect(currentCopyResponse.statusCode).toBe(200);
    const copiedVersionId = currentCopyResponse.headers['x-amz-version-id'] as string;
    expect(copiedVersionId).toBeTruthy();

    const copiedVersionQuery = `versionId=${encodeURIComponent(copiedVersionId)}`;
    const currentVersionReadResponse = await app.inject({
      method: 'GET',
      url: `${currentCopyPath}?${copiedVersionQuery}`,
      headers: signRequest({ method: 'GET', pathname: currentCopyPath, queryString: copiedVersionQuery, host }),
    });
    expect(currentVersionReadResponse.statusCode).toBe(200);
    expect(currentVersionReadResponse.headers['x-amz-version-id']).toBe(copiedVersionId);
    expect(currentVersionReadResponse.body).toBe('copy-version-two');
    expect((await fetch(`${webdav.endpoint}${currentCopyPath}`)).status).toBe(404);

    const deleteSourceResponse = await app.inject({
      method: 'DELETE',
      url: sourcePath,
      headers: signRequest({ method: 'DELETE', pathname: sourcePath, host }),
    });
    expect(deleteSourceResponse.statusCode).toBe(204);

    const specificAfterDeleteResponse = await app.inject({
      method: 'GET',
      url: specificCopyPath,
      headers: signRequest({ method: 'GET', pathname: specificCopyPath, host }),
    });
    expect(specificAfterDeleteResponse.statusCode).toBe(200);
    expect(specificAfterDeleteResponse.body).toBe('copy-version-one');

    const currentAfterDeleteResponse = await app.inject({
      method: 'GET',
      url: `${currentCopyPath}?${copiedVersionQuery}`,
      headers: signRequest({ method: 'GET', pathname: currentCopyPath, queryString: copiedVersionQuery, host }),
    });
    expect(currentAfterDeleteResponse.statusCode).toBe(200);
    expect(currentAfterDeleteResponse.body).toBe('copy-version-two');
  });

  it('keeps shared SQLite blob bodies readable after lifecycle pruning', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const tempDir = await mkdtemp(join(tmpdir(), 'webdavtos3-lifecycle-blob-'));
    tempDirs.push(tempDir);

    const registry = new TenantRegistry();
    registry.add(createTenant(webdav.endpoint));
    const app = buildApp({
      tenantRegistry: registry,
      adminKey: 'test-admin-key',
      metadata: { driver: 'sqlite', path: join(tempDir, 'metadata.sqlite') },
    });
    apps.push(app);

    const host = '127.0.0.1';
    const versioningPath = '/uniid';
    const versioningQuery = 'versioning=';
    const versioningBody = Buffer.from('<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>');
    const enableVersioningResponse = await app.inject({
      method: 'PUT',
      url: `${versioningPath}?${versioningQuery}`,
      payload: versioningBody,
      headers: signRequest({
        method: 'PUT',
        pathname: versioningPath,
        queryString: versioningQuery,
        host,
        payloadHash: createHash('sha256').update(versioningBody).digest('hex'),
        extraHeaders: {
          'content-length': String(versioningBody.length),
          'content-type': 'application/xml',
        },
      }),
    });
    expect(enableVersioningResponse.statusCode).toBe(200);

    const pathname = '/uniid/shared-blob.txt';
    const body = Buffer.from('shared-blob-body');
    const firstPutResponse = await app.inject({
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
          'content-type': 'text/plain',
        },
      }),
    });
    expect(firstPutResponse.statusCode).toBe(200);
    const firstVersionId = firstPutResponse.headers['x-amz-version-id'] as string;

    const secondPutResponse = await app.inject({
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
          'content-type': 'text/plain',
        },
      }),
    });
    expect(secondPutResponse.statusCode).toBe(200);
    const secondVersionId = secondPutResponse.headers['x-amz-version-id'] as string;
    expect(secondVersionId).not.toBe(firstVersionId);

    const lifecycleFactory = createStorageBackendFactory({ metadata: { driver: 'sqlite', path: join(tempDir, 'metadata.sqlite') } });
    try {
      const result = await runLifecycleOnce(registry, {
        enabled: true,
        intervalMs: 1000,
        expireNoncurrentVersionsAfterMs: 0,
      }, lifecycleFactory);
      expect(result.removedVersions).toBe(1);
    } finally {
      lifecycleFactory.close();
    }

    const currentReadResponse = await app.inject({
      method: 'GET',
      url: pathname,
      headers: signRequest({ method: 'GET', pathname, host }),
    });
    expect(currentReadResponse.statusCode).toBe(200);
    expect(currentReadResponse.body).toBe('shared-blob-body');
    expect(currentReadResponse.headers['x-amz-version-id']).toBe(secondVersionId);

    const digest = createHash('sha256').update(body).digest('hex');
    const blobPath = `/.webdavtos3-blobs/sha256/${digest.slice(0, 2)}/${digest.slice(2, 4)}/${digest}`;
    const rawBlob = await fetch(`${webdav.endpoint}${blobPath}`);
    expect(rawBlob.status).toBe(200);
    expect(await rawBlob.text()).toBe('shared-blob-body');
  });

  it('garbage-collects only unreferenced SQLite content blobs', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const tempDir = await mkdtemp(join(tmpdir(), 'webdavtos3-blob-gc-'));
    tempDirs.push(tempDir);

    const metadataPath = join(tempDir, 'metadata.sqlite');
    const registry = new TenantRegistry();
    registry.add(createTenant(webdav.endpoint));
    const app = buildApp({
      tenantRegistry: registry,
      adminKey: 'test-admin-key',
      metadata: { driver: 'sqlite', path: metadataPath },
    });
    apps.push(app);

    const host = '127.0.0.1';
    const versioningPath = '/uniid';
    const versioningQuery = 'versioning=';
    const versioningBody = Buffer.from('<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>');
    const enableVersioningResponse = await app.inject({
      method: 'PUT',
      url: `${versioningPath}?${versioningQuery}`,
      payload: versioningBody,
      headers: signRequest({
        method: 'PUT',
        pathname: versioningPath,
        queryString: versioningQuery,
        host,
        payloadHash: createHash('sha256').update(versioningBody).digest('hex'),
        extraHeaders: {
          'content-length': String(versioningBody.length),
          'content-type': 'application/xml',
        },
      }),
    });
    expect(enableVersioningResponse.statusCode).toBe(200);

    const versionedPath = '/uniid/gc-versioned.txt';
    const versionBodyOne = Buffer.from('gc-version-one');
    const putVersionOneResponse = await app.inject({
      method: 'PUT',
      url: versionedPath,
      payload: versionBodyOne,
      headers: signRequest({
        method: 'PUT',
        pathname: versionedPath,
        host,
        payloadHash: createHash('sha256').update(versionBodyOne).digest('hex'),
        extraHeaders: {
          'content-length': String(versionBodyOne.length),
          'content-type': 'text/plain',
        },
      }),
    });
    expect(putVersionOneResponse.statusCode).toBe(200);
    const versionOneId = putVersionOneResponse.headers['x-amz-version-id'] as string;

    const versionBodyTwo = Buffer.from('gc-version-two');
    const putVersionTwoResponse = await app.inject({
      method: 'PUT',
      url: versionedPath,
      payload: versionBodyTwo,
      headers: signRequest({
        method: 'PUT',
        pathname: versionedPath,
        host,
        payloadHash: createHash('sha256').update(versionBodyTwo).digest('hex'),
        extraHeaders: {
          'content-length': String(versionBodyTwo.length),
          'content-type': 'text/plain',
        },
      }),
    });
    expect(putVersionTwoResponse.statusCode).toBe(200);
    const versionTwoId = putVersionTwoResponse.headers['x-amz-version-id'] as string;
    expect(versionTwoId).not.toBe(versionOneId);

    const stalePath = '/archive/gc-stale.txt';
    const staleBody = Buffer.from('gc-stale-body');
    const putStaleResponse = await app.inject({
      method: 'PUT',
      url: stalePath,
      payload: staleBody,
      headers: signRequest({
        method: 'PUT',
        pathname: stalePath,
        host,
        payloadHash: createHash('sha256').update(staleBody).digest('hex'),
        extraHeaders: {
          'content-length': String(staleBody.length),
          'content-type': 'text/plain',
        },
      }),
    });
    expect(putStaleResponse.statusCode).toBe(200);

    const deleteStaleResponse = await app.inject({
      method: 'DELETE',
      url: stalePath,
      headers: signRequest({ method: 'DELETE', pathname: stalePath, host }),
    });
    expect(deleteStaleResponse.statusCode).toBe(204);

    const versionOneDigest = createHash('sha256').update(versionBodyOne).digest('hex');
    const versionOneBlobPath = `/.webdavtos3-blobs/sha256/${versionOneDigest.slice(0, 2)}/${versionOneDigest.slice(2, 4)}/${versionOneDigest}`;
    const versionTwoDigest = createHash('sha256').update(versionBodyTwo).digest('hex');
    const versionTwoBlobPath = `/.webdavtos3-blobs/sha256/${versionTwoDigest.slice(0, 2)}/${versionTwoDigest.slice(2, 4)}/${versionTwoDigest}`;
    const staleDigest = createHash('sha256').update(staleBody).digest('hex');
    const staleBlobPath = `/.webdavtos3-blobs/sha256/${staleDigest.slice(0, 2)}/${staleDigest.slice(2, 4)}/${staleDigest}`;
    expect((await fetch(`${webdav.endpoint}${versionOneBlobPath}`)).status).toBe(200);
    expect((await fetch(`${webdav.endpoint}${versionTwoBlobPath}`)).status).toBe(200);
    expect((await fetch(`${webdav.endpoint}${staleBlobPath}`)).status).toBe(200);

    const lifecycleFactory = createStorageBackendFactory({ metadata: { driver: 'sqlite', path: metadataPath } });
    try {
      const result = await runLifecycleOnce(registry, {
        enabled: true,
        intervalMs: 1000,
        gcUnreferencedBlobs: true,
      }, lifecycleFactory);
      expect(result.scannedBlobs).toBe(3);
      expect(result.removedBlobs).toBe(1);
    } finally {
      lifecycleFactory.close();
    }

    expect((await fetch(`${webdav.endpoint}${versionOneBlobPath}`)).status).toBe(200);
    expect((await fetch(`${webdav.endpoint}${versionTwoBlobPath}`)).status).toBe(200);
    expect((await fetch(`${webdav.endpoint}${staleBlobPath}`)).status).toBe(404);

    const readVersionOneQuery = `versionId=${encodeURIComponent(versionOneId)}`;
    const readVersionOneResponse = await app.inject({
      method: 'GET',
      url: `${versionedPath}?${readVersionOneQuery}`,
      headers: signRequest({ method: 'GET', pathname: versionedPath, queryString: readVersionOneQuery, host }),
    });
    expect(readVersionOneResponse.statusCode).toBe(200);
    expect(readVersionOneResponse.body).toBe('gc-version-one');

    const readCurrentResponse = await app.inject({
      method: 'GET',
      url: versionedPath,
      headers: signRequest({ method: 'GET', pathname: versionedPath, host }),
    });
    expect(readCurrentResponse.statusCode).toBe(200);
    expect(readCurrentResponse.headers['x-amz-version-id']).toBe(versionTwoId);
    expect(readCurrentResponse.body).toBe('gc-version-two');
  });

  it('cleans multipart part blobs on abort and complete', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const tempDir = await mkdtemp(join(tmpdir(), 'webdavtos3-multipart-recovery-'));
    tempDirs.push(tempDir);
    const app = createSqliteApp(webdav.endpoint, join(tempDir, 'metadata.sqlite'));
    apps.push(app);

    const host = '127.0.0.1';

    const abortPath = '/uniid/recovery-abort.txt';
    const abortCreateQuery = 'uploads=';
    const abortCreateResponse = await app.inject({
      method: 'POST',
      url: `${abortPath}?${abortCreateQuery}`,
      headers: signRequest({ method: 'POST', pathname: abortPath, queryString: abortCreateQuery, host }),
    });
    expect(abortCreateResponse.statusCode).toBe(200);
    const abortUploadId = abortCreateResponse.body.match(/<UploadId>([^<]+)<\/UploadId>/)?.[1];
    expect(abortUploadId).toBeTruthy();

    const abortPartBody = Buffer.from('abort-part');
    const abortPartQuery = `partNumber=1&uploadId=${encodeURIComponent(abortUploadId!)}`;
    const abortPartResponse = await app.inject({
      method: 'PUT',
      url: `${abortPath}?${abortPartQuery}`,
      payload: abortPartBody,
      headers: signRequest({
        method: 'PUT',
        pathname: abortPath,
        queryString: abortPartQuery,
        host,
        payloadHash: createHash('sha256').update(abortPartBody).digest('hex'),
        extraHeaders: { 'content-length': String(abortPartBody.length) },
      }),
    });
    expect(abortPartResponse.statusCode).toBe(200);
    const abortPartPath = `/.webdavtos3-system/buckets/uniid/multipart/${encodeURIComponent(abortUploadId!)}/parts/1`;
    expect((await fetch(`${webdav.endpoint}${abortPartPath}`)).status).toBe(200);

    const abortResponse = await app.inject({
      method: 'DELETE',
      url: `${abortPath}?uploadId=${encodeURIComponent(abortUploadId!)}&x-id=AbortMultipartUpload`,
      headers: signRequest({
        method: 'DELETE',
        pathname: abortPath,
        queryString: `uploadId=${encodeURIComponent(abortUploadId!)}&x-id=AbortMultipartUpload`,
        host,
      }),
    });
    expect(abortResponse.statusCode).toBe(204);
    expect((await fetch(`${webdav.endpoint}${abortPartPath}`)).status).toBe(404);

    const abortReadResponse = await app.inject({
      method: 'GET',
      url: abortPath,
      headers: signRequest({ method: 'GET', pathname: abortPath, host }),
    });
    expect(abortReadResponse.statusCode).toBe(404);

    const completePath = '/uniid/recovery-complete.txt';
    const completeCreateQuery = 'uploads=';
    const completeCreateResponse = await app.inject({
      method: 'POST',
      url: `${completePath}?${completeCreateQuery}`,
      headers: signRequest({ method: 'POST', pathname: completePath, queryString: completeCreateQuery, host }),
    });
    expect(completeCreateResponse.statusCode).toBe(200);
    const completeUploadId = completeCreateResponse.body.match(/<UploadId>([^<]+)<\/UploadId>/)?.[1];
    expect(completeUploadId).toBeTruthy();

    const partOne = Buffer.from('hello ');
    const partTwo = Buffer.from('world');
    for (const [partNumber, body] of [[1, partOne], [2, partTwo]] as const) {
      const queryString = `partNumber=${partNumber}&uploadId=${encodeURIComponent(completeUploadId!)}`;
      const response = await app.inject({
        method: 'PUT',
        url: `${completePath}?${queryString}`,
        payload: body,
        headers: signRequest({
          method: 'PUT',
          pathname: completePath,
          queryString,
          host,
          payloadHash: createHash('sha256').update(body).digest('hex'),
          extraHeaders: { 'content-length': String(body.length) },
        }),
      });
      expect(response.statusCode).toBe(200);
    }

    const partPathOne = `/.webdavtos3-system/buckets/uniid/multipart/${encodeURIComponent(completeUploadId!)}/parts/1`;
    const partPathTwo = `/.webdavtos3-system/buckets/uniid/multipart/${encodeURIComponent(completeUploadId!)}/parts/2`;
    expect((await fetch(`${webdav.endpoint}${partPathOne}`)).status).toBe(200);
    expect((await fetch(`${webdav.endpoint}${partPathTwo}`)).status).toBe(200);

    const completeResponse = await app.inject({
      method: 'POST',
      url: `${completePath}?uploadId=${encodeURIComponent(completeUploadId!)}`,
      payload: Buffer.alloc(0),
      headers: signRequest({
        method: 'POST',
        pathname: completePath,
        queryString: `uploadId=${encodeURIComponent(completeUploadId!)}`,
        host,
      }),
    });
    expect(completeResponse.statusCode).toBe(200);

    expect((await fetch(`${webdav.endpoint}${partPathOne}`)).status).toBe(404);
    expect((await fetch(`${webdav.endpoint}${partPathTwo}`)).status).toBe(404);

    const completeReadResponse = await app.inject({
      method: 'GET',
      url: completePath,
      headers: signRequest({ method: 'GET', pathname: completePath, host }),
    });
    expect(completeReadResponse.statusCode).toBe(200);
    expect(completeReadResponse.body).toBe('hello world');
  });

  it('keeps SQLite version metadata consistent across concurrent writes', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const tempDir = await mkdtemp(join(tmpdir(), 'webdavtos3-concurrent-versions-'));
    tempDirs.push(tempDir);
    const app = createSqliteApp(webdav.endpoint, join(tempDir, 'metadata.sqlite'));
    apps.push(app);

    const host = '127.0.0.1';
    const versioningPath = '/uniid';
    const versioningQuery = 'versioning=';
    const versioningBody = Buffer.from('<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>');
    const enableVersioningResponse = await app.inject({
      method: 'PUT',
      url: `${versioningPath}?${versioningQuery}`,
      payload: versioningBody,
      headers: signRequest({
        method: 'PUT',
        pathname: versioningPath,
        queryString: versioningQuery,
        host,
        payloadHash: createHash('sha256').update(versioningBody).digest('hex'),
        extraHeaders: {
          'content-length': String(versioningBody.length),
          'content-type': 'application/xml',
        },
      }),
    });
    expect(enableVersioningResponse.statusCode).toBe(200);

    const pathname = '/uniid/concurrent-versioned.txt';
    const bodies = Array.from({ length: 6 }, (_, index) => Buffer.from(`concurrent-version-${index}`));
    const putResponses = await Promise.all(bodies.map((body) => app.inject({
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
          'content-type': 'text/plain',
        },
      }),
    })));

    for (const response of putResponses) expect(response.statusCode).toBe(200);
    const versionIds = putResponses.map((response) => response.headers['x-amz-version-id'] as string);
    expect(new Set(versionIds).size).toBe(bodies.length);

    await Promise.all(versionIds.map(async (versionId, index) => {
      const queryString = `versionId=${encodeURIComponent(versionId)}`;
      const response = await app.inject({
        method: 'GET',
        url: `${pathname}?${queryString}`,
        headers: signRequest({ method: 'GET', pathname, queryString, host }),
      });
      expect(response.statusCode).toBe(200);
      expect(response.headers['x-amz-version-id']).toBe(versionId);
      expect(response.body).toBe(bodies[index]!.toString('utf-8'));
    }));

    const listVersionsQuery = 'versions=&prefix=concurrent-versioned.txt';
    const listVersionsResponse = await app.inject({
      method: 'GET',
      url: `/uniid?${listVersionsQuery}`,
      headers: signRequest({ method: 'GET', pathname: '/uniid', queryString: listVersionsQuery, host }),
    });
    expect(listVersionsResponse.statusCode).toBe(200);
    for (const versionId of versionIds) expect(listVersionsResponse.body).toContain(`<VersionId>${versionId}</VersionId>`);

    const currentResponse = await app.inject({
      method: 'GET',
      url: pathname,
      headers: signRequest({ method: 'GET', pathname, host }),
    });
    expect(currentResponse.statusCode).toBe(200);
    expect(versionIds).toContain(currentResponse.headers['x-amz-version-id']);
    expect(bodies.map((body) => body.toString('utf-8'))).toContain(currentResponse.body);

    expect((await fetch(`${webdav.endpoint}${pathname}`)).status).toBe(404);
    for (const body of bodies) expect((await fetch(`${webdav.endpoint}${contentBlobPath(body)}`)).status).toBe(200);
  });

  it('keeps multipart state recoverable after invalid complete and stores large SQLite multipart bodies as content blobs', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const tempDir = await mkdtemp(join(tmpdir(), 'webdavtos3-large-multipart-'));
    tempDirs.push(tempDir);

    const metadataPath = join(tempDir, 'metadata.sqlite');
    const registry = new TenantRegistry();
    registry.add(createTenant(webdav.endpoint));
    const app = buildApp({
      tenantRegistry: registry,
      adminKey: 'test-admin-key',
      metadata: { driver: 'sqlite', path: metadataPath },
    });
    apps.push(app);

    const host = '127.0.0.1';
    const pathname = '/uniid/large-recoverable-multipart.bin';
    const createQuery = 'uploads=';
    const createResponse = await app.inject({
      method: 'POST',
      url: `${pathname}?${createQuery}`,
      headers: signRequest({ method: 'POST', pathname, queryString: createQuery, host }),
    });
    expect(createResponse.statusCode).toBe(200);
    const uploadId = createResponse.body.match(/<UploadId>([^<]+)<\/UploadId>/)?.[1];
    expect(uploadId).toBeTruthy();

    const partOne = Buffer.alloc(128 * 1024, 'a');
    const partTwo = Buffer.alloc(192 * 1024, 'b');
    for (const [partNumber, body] of [[1, partOne], [2, partTwo]] as const) {
      const queryString = `partNumber=${partNumber}&uploadId=${encodeURIComponent(uploadId!)}`;
      const response = await app.inject({
        method: 'PUT',
        url: `${pathname}?${queryString}`,
        payload: body,
        headers: signRequest({
          method: 'PUT',
          pathname,
          queryString,
          host,
          payloadHash: createHash('sha256').update(body).digest('hex'),
          extraHeaders: { 'content-length': String(body.length) },
        }),
      });
      expect(response.statusCode).toBe(200);
    }

    const partPathOne = `/.webdavtos3-system/buckets/uniid/multipart/${encodeURIComponent(uploadId!)}/parts/1`;
    const partPathTwo = `/.webdavtos3-system/buckets/uniid/multipart/${encodeURIComponent(uploadId!)}/parts/2`;
    expect((await fetch(`${webdav.endpoint}${partPathOne}`)).status).toBe(200);
    expect((await fetch(`${webdav.endpoint}${partPathTwo}`)).status).toBe(200);

    const invalidCompleteBody = Buffer.from('<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part><Part><PartNumber>3</PartNumber></Part></CompleteMultipartUpload>');
    const completeQuery = `uploadId=${encodeURIComponent(uploadId!)}`;
    const invalidCompleteResponse = await app.inject({
      method: 'POST',
      url: `${pathname}?${completeQuery}`,
      payload: invalidCompleteBody,
      headers: signRequest({
        method: 'POST',
        pathname,
        queryString: completeQuery,
        host,
        payloadHash: createHash('sha256').update(invalidCompleteBody).digest('hex'),
        extraHeaders: { 'content-length': String(invalidCompleteBody.length) },
      }),
    });
    expect(invalidCompleteResponse.statusCode).toBe(400);
    expect(invalidCompleteResponse.body).toContain('InvalidPart');

    const listPartsResponse = await app.inject({
      method: 'GET',
      url: `${pathname}?${completeQuery}`,
      headers: signRequest({ method: 'GET', pathname, queryString: completeQuery, host }),
    });
    expect(listPartsResponse.statusCode).toBe(200);
    expect(listPartsResponse.body).toContain('<PartNumber>1</PartNumber>');
    expect(listPartsResponse.body).toContain('<PartNumber>2</PartNumber>');
    expect((await fetch(`${webdav.endpoint}${partPathOne}`)).status).toBe(200);
    expect((await fetch(`${webdav.endpoint}${partPathTwo}`)).status).toBe(200);

    const validCompleteBody = Buffer.from('<CompleteMultipartUpload><Part><PartNumber>1</PartNumber></Part><Part><PartNumber>2</PartNumber></Part></CompleteMultipartUpload>');
    const completeResponse = await app.inject({
      method: 'POST',
      url: `${pathname}?${completeQuery}`,
      payload: validCompleteBody,
      headers: signRequest({
        method: 'POST',
        pathname,
        queryString: completeQuery,
        host,
        payloadHash: createHash('sha256').update(validCompleteBody).digest('hex'),
        extraHeaders: { 'content-length': String(validCompleteBody.length) },
      }),
    });
    expect(completeResponse.statusCode).toBe(200);

    expect((await fetch(`${webdav.endpoint}${partPathOne}`)).status).toBe(404);
    expect((await fetch(`${webdav.endpoint}${partPathTwo}`)).status).toBe(404);
    expect((await fetch(`${webdav.endpoint}${pathname}`)).status).toBe(404);

    const finalBody = Buffer.concat([partOne, partTwo]);
    const finalBlobPath = contentBlobPath(finalBody);
    const finalRawBlob = await fetch(`${webdav.endpoint}${finalBlobPath}`);
    expect(finalRawBlob.status).toBe(200);
    expect((await finalRawBlob.arrayBuffer()).byteLength).toBe(finalBody.length);

    const readResponse = await app.inject({
      method: 'GET',
      url: pathname,
      headers: signRequest({ method: 'GET', pathname, host }),
    });
    expect(readResponse.statusCode).toBe(200);
    expect(readResponse.headers['content-length']).toBe(String(finalBody.length));
    expect(readResponse.body).toBe(finalBody.toString('utf-8'));

    const lifecycleFactory = createStorageBackendFactory({ metadata: { driver: 'sqlite', path: metadataPath } });
    try {
      const result = await runLifecycleOnce(registry, {
        enabled: true,
        intervalMs: 1000,
        gcUnreferencedBlobs: true,
      }, lifecycleFactory);
      expect(result.scannedBlobs).toBe(1);
      expect(result.removedBlobs).toBe(0);
    } finally {
      lifecycleFactory.close();
    }
    expect((await fetch(`${webdav.endpoint}${finalBlobPath}`)).status).toBe(200);
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

  it('preserves object metadata, checksums, tags, conditions, response overrides, and cross-bucket copy', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);

    const host = '127.0.0.1';
    const pathname = '/uniid/object-semantics.txt';
    const body = Buffer.from('object-semantics-body');
    const checksum = createHash('sha256').update(body).digest('base64');
    const contentMd5 = createHash('md5').update(body).digest('base64');
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
          'content-md5': contentMd5,
          'content-type': 'text/plain',
          'cache-control': 'max-age=60',
          'x-amz-checksum-sha256': checksum,
          'x-amz-meta-owner': 'qa',
          'x-amz-meta-purpose': 'object-semantics',
          'x-amz-tagging': 'project=compat&stage=test',
        },
      }),
    });
    expect(putResponse.statusCode).toBe(200);
    const etag = putResponse.headers.etag as string;
    expect(etag).toBeTruthy();

    const headResponse = await app.inject({
      method: 'HEAD',
      url: pathname,
      headers: signRequest({ method: 'HEAD', pathname, host }),
    });
    expect(headResponse.statusCode).toBe(200);
    expect(headResponse.headers['content-type']).toBe('text/plain');
    expect(headResponse.headers['content-length']).toBe(String(body.length));
    expect(headResponse.headers['x-amz-meta-owner']).toBe('qa');
    expect(headResponse.headers['x-amz-meta-purpose']).toBe('object-semantics');
    expect(headResponse.headers['x-amz-checksum-sha256']).toBe(checksum);

    const notModifiedResponse = await app.inject({
      method: 'GET',
      url: pathname,
      headers: signRequest({
        method: 'GET',
        pathname,
        host,
        extraHeaders: {
          'if-none-match': etag,
        },
      }),
    });
    expect(notModifiedResponse.statusCode).toBe(304);

    const preconditionFailedResponse = await app.inject({
      method: 'GET',
      url: pathname,
      headers: signRequest({
        method: 'GET',
        pathname,
        host,
        extraHeaders: {
          'if-match': '"missing-etag"',
        },
      }),
    });
    expect(preconditionFailedResponse.statusCode).toBe(412);

    const overrideQuery = 'response-content-type=application%2Fjson&response-cache-control=no-cache';
    const overrideResponse = await app.inject({
      method: 'GET',
      url: `${pathname}?${overrideQuery}`,
      headers: signRequest({ method: 'GET', pathname, queryString: overrideQuery, host }),
    });
    expect(overrideResponse.statusCode).toBe(200);
    expect(overrideResponse.headers['content-type']).toBe('application/json');
    expect(overrideResponse.headers['cache-control']).toBe('no-cache');
    expect(overrideResponse.body).toBe('object-semantics-body');

    const getTaggingResponse = await app.inject({
      method: 'GET',
      url: `${pathname}?tagging=`,
      headers: signRequest({ method: 'GET', pathname, queryString: 'tagging=', host }),
    });
    expect(getTaggingResponse.statusCode).toBe(200);
    expect(getTaggingResponse.body).toContain('<Key>project</Key><Value>compat</Value>');
    expect(getTaggingResponse.body).toContain('<Key>stage</Key><Value>test</Value>');

    const replaceTaggingBody = Buffer.from('<Tagging><TagSet><Tag><Key>stage</Key><Value>copied</Value></Tag></TagSet></Tagging>');
    const putTaggingResponse = await app.inject({
      method: 'PUT',
      url: `${pathname}?tagging=`,
      payload: replaceTaggingBody,
      headers: signRequest({
        method: 'PUT',
        pathname,
        queryString: 'tagging=',
        host,
        payloadHash: createHash('sha256').update(replaceTaggingBody).digest('hex'),
        extraHeaders: {
          'content-length': String(replaceTaggingBody.length),
        },
      }),
    });
    expect(putTaggingResponse.statusCode).toBe(200);

    const copyPathname = '/archive/copied-object.txt';
    const copyResponse = await app.inject({
      method: 'PUT',
      url: copyPathname,
      headers: signRequest({
        method: 'PUT',
        pathname: copyPathname,
        host,
        extraHeaders: {
          'x-amz-copy-source': '/uniid/object-semantics.txt',
          'x-amz-copy-source-if-match': etag,
          'x-amz-metadata-directive': 'REPLACE',
          'x-amz-meta-owner': 'archive',
          'x-amz-tagging-directive': 'REPLACE',
          'x-amz-tagging': 'archive=yes',
        },
      }),
    });
    expect(copyResponse.statusCode).toBe(200);
    expect(copyResponse.body).toContain('<CopyObjectResult');

    const copiedHeadResponse = await app.inject({
      method: 'HEAD',
      url: copyPathname,
      headers: signRequest({ method: 'HEAD', pathname: copyPathname, host }),
    });
    expect(copiedHeadResponse.statusCode).toBe(200);
    expect(copiedHeadResponse.headers['x-amz-meta-owner']).toBe('archive');
    expect(copiedHeadResponse.headers['x-amz-meta-purpose']).toBeUndefined();

    const copiedTaggingResponse = await app.inject({
      method: 'GET',
      url: `${copyPathname}?tagging=`,
      headers: signRequest({ method: 'GET', pathname: copyPathname, queryString: 'tagging=', host }),
    });
    expect(copiedTaggingResponse.statusCode).toBe(200);
    expect(copiedTaggingResponse.body).toContain('<Key>archive</Key><Value>yes</Value>');
  });

  it('tracks object versions and delete markers when bucket versioning is enabled', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);

    const host = '127.0.0.1';
    const versioningPath = '/uniid';
    const versioningQuery = 'versioning=';
    const versioningBody = Buffer.from('<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>');
    const enableVersioningResponse = await app.inject({
      method: 'PUT',
      url: `${versioningPath}?${versioningQuery}`,
      payload: versioningBody,
      headers: signRequest({
        method: 'PUT',
        pathname: versioningPath,
        queryString: versioningQuery,
        host,
        payloadHash: createHash('sha256').update(versioningBody).digest('hex'),
        extraHeaders: {
          'content-length': String(versioningBody.length),
          'content-type': 'application/xml',
        },
      }),
    });
    expect(enableVersioningResponse.statusCode).toBe(200);

    const pathname = '/uniid/versioned-object.txt';
    const firstBody = Buffer.from('version-one');
    const firstPutResponse = await app.inject({
      method: 'PUT',
      url: pathname,
      payload: firstBody,
      headers: signRequest({
        method: 'PUT',
        pathname,
        host,
        payloadHash: createHash('sha256').update(firstBody).digest('hex'),
        extraHeaders: {
          'content-length': String(firstBody.length),
        },
      }),
    });
    expect(firstPutResponse.statusCode).toBe(200);
    const firstVersionId = firstPutResponse.headers['x-amz-version-id'] as string;
    expect(firstVersionId).toBeTruthy();

    const secondBody = Buffer.from('version-two');
    const secondPutResponse = await app.inject({
      method: 'PUT',
      url: pathname,
      payload: secondBody,
      headers: signRequest({
        method: 'PUT',
        pathname,
        host,
        payloadHash: createHash('sha256').update(secondBody).digest('hex'),
        extraHeaders: {
          'content-length': String(secondBody.length),
        },
      }),
    });
    expect(secondPutResponse.statusCode).toBe(200);
    const secondVersionId = secondPutResponse.headers['x-amz-version-id'] as string;
    expect(secondVersionId).toBeTruthy();
    expect(secondVersionId).not.toBe(firstVersionId);

    const readFirstVersionQuery = `versionId=${encodeURIComponent(firstVersionId)}`;
    const readFirstVersionResponse = await app.inject({
      method: 'GET',
      url: `${pathname}?${readFirstVersionQuery}`,
      headers: signRequest({ method: 'GET', pathname, queryString: readFirstVersionQuery, host }),
    });
    expect(readFirstVersionResponse.statusCode).toBe(200);
    expect(readFirstVersionResponse.headers['x-amz-version-id']).toBe(firstVersionId);
    expect(readFirstVersionResponse.body).toBe('version-one');

    const deleteResponse = await app.inject({
      method: 'DELETE',
      url: pathname,
      headers: signRequest({ method: 'DELETE', pathname, host }),
    });
    expect(deleteResponse.statusCode).toBe(204);
    expect(deleteResponse.headers['x-amz-delete-marker']).toBe('true');
    const deleteMarkerVersionId = deleteResponse.headers['x-amz-version-id'] as string;
    expect(deleteMarkerVersionId).toBeTruthy();

    const currentReadResponse = await app.inject({
      method: 'GET',
      url: pathname,
      headers: signRequest({ method: 'GET', pathname, host }),
    });
    expect(currentReadResponse.statusCode).toBe(404);

    const listVersionsQuery = 'versions=';
    const listVersionsResponse = await app.inject({
      method: 'GET',
      url: `${versioningPath}?${listVersionsQuery}`,
      headers: signRequest({ method: 'GET', pathname: versioningPath, queryString: listVersionsQuery, host }),
    });
    expect(listVersionsResponse.statusCode).toBe(200);
    expect(listVersionsResponse.body).toContain(`<VersionId>${firstVersionId}</VersionId>`);
    expect(listVersionsResponse.body).toContain(`<VersionId>${secondVersionId}</VersionId>`);
    expect(listVersionsResponse.body).toContain(`<VersionId>${deleteMarkerVersionId}</VersionId>`);
    expect(listVersionsResponse.body).toContain('<DeleteMarker>');

    const deleteDeleteMarkerQuery = `versionId=${encodeURIComponent(deleteMarkerVersionId)}`;
    const deleteDeleteMarkerResponse = await app.inject({
      method: 'DELETE',
      url: `${pathname}?${deleteDeleteMarkerQuery}`,
      headers: signRequest({ method: 'DELETE', pathname, queryString: deleteDeleteMarkerQuery, host }),
    });
    expect(deleteDeleteMarkerResponse.statusCode).toBe(204);
    expect(deleteDeleteMarkerResponse.headers['x-amz-delete-marker']).toBe('true');
    expect(deleteDeleteMarkerResponse.headers['x-amz-version-id']).toBe(deleteMarkerVersionId);

    const currentAfterMarkerDelete = await app.inject({
      method: 'GET',
      url: pathname,
      headers: signRequest({ method: 'GET', pathname, host }),
    });
    expect(currentAfterMarkerDelete.statusCode).toBe(200);
    expect(currentAfterMarkerDelete.headers['x-amz-version-id']).toBe(secondVersionId);
    expect(currentAfterMarkerDelete.body).toBe('version-two');

    const deleteSecondVersionQuery = `versionId=${encodeURIComponent(secondVersionId)}`;
    const deleteSecondVersionResponse = await app.inject({
      method: 'DELETE',
      url: `${pathname}?${deleteSecondVersionQuery}`,
      headers: signRequest({ method: 'DELETE', pathname, queryString: deleteSecondVersionQuery, host }),
    });
    expect(deleteSecondVersionResponse.statusCode).toBe(204);
    expect(deleteSecondVersionResponse.headers['x-amz-version-id']).toBe(secondVersionId);

    const currentAfterSecondDelete = await app.inject({
      method: 'GET',
      url: pathname,
      headers: signRequest({ method: 'GET', pathname, host }),
    });
    expect(currentAfterSecondDelete.statusCode).toBe(200);
    expect(currentAfterSecondDelete.headers['x-amz-version-id']).toBe(firstVersionId);
    expect(currentAfterSecondDelete.body).toBe('version-one');

    const deleteFirstVersionQuery = `versionId=${encodeURIComponent(firstVersionId)}`;
    const deleteFirstVersionResponse = await app.inject({
      method: 'DELETE',
      url: `${pathname}?${deleteFirstVersionQuery}`,
      headers: signRequest({ method: 'DELETE', pathname, queryString: deleteFirstVersionQuery, host }),
    });
    expect(deleteFirstVersionResponse.statusCode).toBe(204);
    expect(deleteFirstVersionResponse.headers['x-amz-version-id']).toBe(firstVersionId);

    const readDeletedVersionResponse = await app.inject({
      method: 'GET',
      url: `${pathname}?${readFirstVersionQuery}`,
      headers: signRequest({ method: 'GET', pathname, queryString: readFirstVersionQuery, host }),
    });
    expect(readDeletedVersionResponse.statusCode).toBe(404);

    const currentAfterAllVersionsDeleted = await app.inject({
      method: 'GET',
      url: pathname,
      headers: signRequest({ method: 'GET', pathname, host }),
    });
    expect(currentAfterAllVersionsDeleted.statusCode).toBe(404);
  });

  it('blocks overwrite and delete when object legal hold or retention is active', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);

    const host = '127.0.0.1';
    const pathname = '/uniid/locked-object.txt';
    const body = Buffer.from('locked-body');
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

    const legalHoldQuery = 'legal-hold=';
    const legalHoldBody = Buffer.from('<LegalHold><Status>ON</Status></LegalHold>');
    const legalHoldResponse = await app.inject({
      method: 'PUT',
      url: `${pathname}?${legalHoldQuery}`,
      payload: legalHoldBody,
      headers: signRequest({
        method: 'PUT',
        pathname,
        queryString: legalHoldQuery,
        host,
        payloadHash: createHash('sha256').update(legalHoldBody).digest('hex'),
        extraHeaders: {
          'content-length': String(legalHoldBody.length),
          'content-type': 'application/xml',
        },
      }),
    });
    expect(legalHoldResponse.statusCode).toBe(200);

    const getLegalHoldResponse = await app.inject({
      method: 'GET',
      url: `${pathname}?${legalHoldQuery}`,
      headers: signRequest({ method: 'GET', pathname, queryString: legalHoldQuery, host }),
    });
    expect(getLegalHoldResponse.statusCode).toBe(200);
    expect(getLegalHoldResponse.body).toContain('<Status>ON</Status>');

    const overwriteResponse = await app.inject({
      method: 'PUT',
      url: pathname,
      payload: Buffer.from('new-body'),
      headers: signRequest({
        method: 'PUT',
        pathname,
        host,
        payloadHash: createHash('sha256').update('new-body').digest('hex'),
        extraHeaders: {
          'content-length': String(Buffer.byteLength('new-body')),
        },
      }),
    });
    expect(overwriteResponse.statusCode).toBe(403);

    const deleteResponse = await app.inject({
      method: 'DELETE',
      url: pathname,
      headers: signRequest({ method: 'DELETE', pathname, host }),
    });
    expect(deleteResponse.statusCode).toBe(403);

    const releaseLegalHoldBody = Buffer.from('<LegalHold><Status>OFF</Status></LegalHold>');
    const releaseLegalHoldResponse = await app.inject({
      method: 'PUT',
      url: `${pathname}?${legalHoldQuery}`,
      payload: releaseLegalHoldBody,
      headers: signRequest({
        method: 'PUT',
        pathname,
        queryString: legalHoldQuery,
        host,
        payloadHash: createHash('sha256').update(releaseLegalHoldBody).digest('hex'),
        extraHeaders: {
          'content-length': String(releaseLegalHoldBody.length),
          'content-type': 'application/xml',
        },
      }),
    });
    expect(releaseLegalHoldResponse.statusCode).toBe(200);

    const retentionQuery = 'retention=';
    const retainUntilDate = new Date(Date.now() + 60_000).toISOString();
    const retentionBody = Buffer.from(`<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>${retainUntilDate}</RetainUntilDate></Retention>`);
    const retentionResponse = await app.inject({
      method: 'PUT',
      url: `${pathname}?${retentionQuery}`,
      payload: retentionBody,
      headers: signRequest({
        method: 'PUT',
        pathname,
        queryString: retentionQuery,
        host,
        payloadHash: createHash('sha256').update(retentionBody).digest('hex'),
        extraHeaders: {
          'content-length': String(retentionBody.length),
          'content-type': 'application/xml',
        },
      }),
    });
    expect(retentionResponse.statusCode).toBe(200);

    const getRetentionResponse = await app.inject({
      method: 'GET',
      url: `${pathname}?${retentionQuery}`,
      headers: signRequest({ method: 'GET', pathname, queryString: retentionQuery, host }),
    });
    expect(getRetentionResponse.statusCode).toBe(200);
    expect(getRetentionResponse.body).toContain('<Mode>GOVERNANCE</Mode>');

    const retentionDeleteResponse = await app.inject({
      method: 'DELETE',
      url: pathname,
      headers: signRequest({ method: 'DELETE', pathname, host }),
    });
    expect(retentionDeleteResponse.statusCode).toBe(403);
  });

  it('expires noncurrent versions through lifecycle scans', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);

    const registry = new TenantRegistry();
    registry.add(createTenant(webdav.endpoint));

    const host = '127.0.0.1';
    const versioningPath = '/uniid';
    const versioningQuery = 'versioning=';
    const versioningBody = Buffer.from('<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>');
    const enableVersioningResponse = await app.inject({
      method: 'PUT',
      url: `${versioningPath}?${versioningQuery}`,
      payload: versioningBody,
      headers: signRequest({
        method: 'PUT',
        pathname: versioningPath,
        queryString: versioningQuery,
        host,
        payloadHash: createHash('sha256').update(versioningBody).digest('hex'),
        extraHeaders: {
          'content-length': String(versioningBody.length),
          'content-type': 'application/xml',
        },
      }),
    });
    expect(enableVersioningResponse.statusCode).toBe(200);

    const pathname = '/uniid/lifecycle-object.txt';
    const firstBody = Buffer.from('lifecycle-one');
    const firstPutResponse = await app.inject({
      method: 'PUT',
      url: pathname,
      payload: firstBody,
      headers: signRequest({
        method: 'PUT',
        pathname,
        host,
        payloadHash: createHash('sha256').update(firstBody).digest('hex'),
        extraHeaders: {
          'content-length': String(firstBody.length),
        },
      }),
    });
    expect(firstPutResponse.statusCode).toBe(200);
    const firstVersionId = firstPutResponse.headers['x-amz-version-id'] as string;
    expect(firstVersionId).toBeTruthy();

    const secondBody = Buffer.from('lifecycle-two');
    const secondPutResponse = await app.inject({
      method: 'PUT',
      url: pathname,
      payload: secondBody,
      headers: signRequest({
        method: 'PUT',
        pathname,
        host,
        payloadHash: createHash('sha256').update(secondBody).digest('hex'),
        extraHeaders: {
          'content-length': String(secondBody.length),
        },
      }),
    });
    expect(secondPutResponse.statusCode).toBe(200);

    const result = await runLifecycleOnce(registry, {
      enabled: true,
      intervalMs: 1000,
      expireNoncurrentVersionsAfterMs: 0,
    });
    expect(result.scannedBuckets).toBeGreaterThan(0);
    expect(result.removedVersions).toBeGreaterThan(0);

    const readExpiredVersionQuery = `versionId=${encodeURIComponent(firstVersionId)}`;
    const readExpiredVersionResponse = await app.inject({
      method: 'GET',
      url: `${pathname}?${readExpiredVersionQuery}`,
      headers: signRequest({ method: 'GET', pathname, queryString: readExpiredVersionQuery, host }),
    });
    expect(readExpiredVersionResponse.statusCode).toBe(404);
  });

  it('runs common AWS SDK S3 commands against a real local endpoint', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);
    const running = await startS3App(app);
    const client = createAwsSdkClient(running.endpoint);

    const key = 'sdk/basic-object.txt';
    await client.send(new PutObjectCommand({
      Bucket: 'uniid',
      Key: key,
      Body: Buffer.from('sdk-basic-body'),
      ContentType: 'text/plain',
      Metadata: {
        source: 'aws-sdk',
      },
      Tagging: 'suite=compat',
    }));

    const head = await client.send(new HeadObjectCommand({ Bucket: 'uniid', Key: key }));
    expect(head.ContentType).toBe('text/plain');
    expect(head.Metadata?.source).toBe('aws-sdk');

    const get = await client.send(new GetObjectCommand({ Bucket: 'uniid', Key: key }));
    expect(await streamToString(get.Body)).toBe('sdk-basic-body');

    const list = await client.send(new ListObjectsV2Command({ Bucket: 'uniid', Prefix: 'sdk/' }));
    expect(list.Contents?.some((item) => item.Key === key)).toBe(true);

    await client.send(new DeleteObjectCommand({ Bucket: 'uniid', Key: key }));
    await expect(client.send(new GetObjectCommand({ Bucket: 'uniid', Key: key }))).rejects.toMatchObject({ name: 'NoSuchKey' });

    running.close = () => Promise.resolve();
    client.destroy();
  });

  it('accepts browser-style presigned PUT and GET against a real local endpoint', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);
    const running = await startS3App(app);
    const endpoint = new URL(running.endpoint);
    const host = endpoint.host;
    const key = 'sdk/presigned-roundtrip.txt';
    const pathname = `/uniid/${key}`;
    const body = 'presigned-real-endpoint-body';

    const putQuery = createPresignedQuery({
      method: 'PUT',
      pathname,
      host,
      extraQuery: 'x-id=PutObject',
    });
    const putResponse = await fetch(`${running.endpoint}${pathname}?${putQuery}`, {
      method: 'PUT',
      body,
      headers: {
        'content-type': 'text/plain',
      },
    });
    expect(putResponse.status).toBe(200);

    const getQuery = createPresignedQuery({
      method: 'GET',
      pathname,
      host,
      extraQuery: 'x-id=GetObject',
    });
    const getResponse = await fetch(`${running.endpoint}${pathname}?${getQuery}`);
    expect(getResponse.status).toBe(200);
    expect(getResponse.headers.get('content-type')).toBe('text/plain');
    expect(await getResponse.text()).toBe(body);

    running.close = () => Promise.resolve();
  });

  it.runIf(AWS_CLI_AVAILABLE)('runs AWS CLI s3 cp, ls, and rm against a real local endpoint', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);
    const running = await startS3App(app);
    const workdir = await mkdtemp(join(tmpdir(), 'webdavtos3-aws-cli-'));
    const sourcePath = join(workdir, 'source.txt');
    const downloadPath = join(workdir, 'download.txt');
    const key = 'cli/roundtrip.txt';

    try {
      await writeFile(sourcePath, 'aws-cli-roundtrip-body');
      runAwsCli(['s3', 'cp', sourcePath, `s3://uniid/${key}`, '--endpoint-url', running.endpoint]);
      const list = runAwsCli(['s3', 'ls', 's3://uniid/cli/', '--endpoint-url', running.endpoint]);
      expect(list.stdout).toContain('roundtrip.txt');

      runAwsCli(['s3', 'cp', `s3://uniid/${key}`, downloadPath, '--endpoint-url', running.endpoint]);
      expect(await readFile(downloadPath, 'utf-8')).toBe('aws-cli-roundtrip-body');

      runAwsCli(['s3', 'rm', `s3://uniid/${key}`, '--endpoint-url', running.endpoint]);
      const afterRemove = runAwsCli(['s3', 'ls', 's3://uniid/cli/', '--endpoint-url', running.endpoint]);
      expect(afterRemove.stdout).not.toContain('roundtrip.txt');
    } finally {
      await rm(workdir, { recursive: true, force: true });
      running.close = () => Promise.resolve();
    }
  });

  it('runs AWS SDK multipart upload commands against a real local endpoint', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);
    const running = await startS3App(app);
    const client = createAwsSdkClient(running.endpoint);

    const key = 'sdk/multipart-object.txt';
    const create = await client.send(new CreateMultipartUploadCommand({ Bucket: 'uniid', Key: key }));
    expect(create.UploadId).toBeTruthy();

    const partOne = await client.send(new UploadPartCommand({
      Bucket: 'uniid',
      Key: key,
      UploadId: create.UploadId,
      PartNumber: 1,
      Body: Buffer.from('sdk-multipart-'),
    }));
    const partTwo = await client.send(new UploadPartCommand({
      Bucket: 'uniid',
      Key: key,
      UploadId: create.UploadId,
      PartNumber: 2,
      Body: Buffer.from('body'),
    }));

    await client.send(new CompleteMultipartUploadCommand({
      Bucket: 'uniid',
      Key: key,
      UploadId: create.UploadId,
      MultipartUpload: {
        Parts: [
          { ETag: partOne.ETag, PartNumber: 1 },
          { ETag: partTwo.ETag, PartNumber: 2 },
        ],
      },
    }));

    const get = await client.send(new GetObjectCommand({ Bucket: 'uniid', Key: key }));
    expect(await streamToString(get.Body)).toBe('sdk-multipart-body');

    running.close = () => Promise.resolve();
    client.destroy();
  });

  it('runs every implemented S3 operation through official AWS SDK packages', async () => {
    const webdav = await startMemoryWebdav();
    webdavs.push(webdav);
    const app = createApp(webdav.endpoint);
    apps.push(app);
    const running = await startS3App(app);
    const client = createAwsSdkClient(running.endpoint);
    const bucket = 'uniid';

    const buckets = await client.send(new ListBucketsCommand({}));
    expect(buckets.Buckets?.map((item) => item.Name)).toContain(bucket);
    await client.send(new HeadBucketCommand({ Bucket: bucket }));
    await client.send(new CreateBucketCommand({ Bucket: bucket }));
    await expect(client.send(new DeleteBucketCommand({ Bucket: bucket }))).rejects.toMatchObject({ name: 'BucketNotEmpty' });

    const location = await client.send(new GetBucketLocationCommand({ Bucket: bucket }));
    expect([REGION, undefined]).toContain(location.LocationConstraint);

    await client.send(new PutBucketAclCommand({ Bucket: bucket, ACL: 'private' }));
    const acl = await client.send(new GetBucketAclCommand({ Bucket: bucket }));
    expect(acl.Owner?.ID).toBe('webdavtos3');

    await client.send(new PutBucketPolicyCommand({
      Bucket: bucket,
      Policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: `arn:aws:s3:::${bucket}/*` }],
      }),
    }));
    const policy = await client.send(new GetBucketPolicyCommand({ Bucket: bucket }));
    expect(policy.Policy).toContain('2012-10-17');
    await client.send(new DeleteBucketPolicyCommand({ Bucket: bucket }));
    await expect(client.send(new GetBucketPolicyCommand({ Bucket: bucket }))).rejects.toMatchObject({ name: 'NoSuchConfiguration' });

    await client.send(new PutBucketCorsCommand({
      Bucket: bucket,
      CORSConfiguration: {
        CORSRules: [{
          ID: 'sdk-cors',
          AllowedMethods: ['GET', 'PUT'],
          AllowedOrigins: ['*'],
          AllowedHeaders: ['*'],
          ExposeHeaders: ['etag'],
          MaxAgeSeconds: 60,
        }],
      },
    }));
    const cors = await client.send(new GetBucketCorsCommand({ Bucket: bucket }));
    expect(cors.CORSRules?.[0]?.AllowedMethods).toEqual(expect.arrayContaining(['GET', 'PUT']));
    await client.send(new DeleteBucketCorsCommand({ Bucket: bucket }));

    await client.send(new PutBucketTaggingCommand({
      Bucket: bucket,
      Tagging: { TagSet: [{ Key: 'suite', Value: 'aws-sdk' }] },
    }));
    const bucketTagging = await client.send(new GetBucketTaggingCommand({ Bucket: bucket }));
    expect(bucketTagging.TagSet).toContainEqual({ Key: 'suite', Value: 'aws-sdk' });
    await client.send(new DeleteBucketTaggingCommand({ Bucket: bucket }));
    const emptyBucketTagging = await client.send(new GetBucketTaggingCommand({ Bucket: bucket }));
    expect(emptyBucketTagging.TagSet ?? []).toHaveLength(0);

    await client.send(new PutBucketLifecycleConfigurationCommand({
      Bucket: bucket,
      LifecycleConfiguration: {
        Rules: [{
          ID: 'expire-temp',
          Status: 'Enabled',
          Filter: { Prefix: 'tmp/' },
          Expiration: { Days: 1 },
        }],
      },
    }));
    const lifecycle = await client.send(new GetBucketLifecycleConfigurationCommand({ Bucket: bucket }));
    expect(lifecycle.Rules?.[0]?.ID).toBe('expire-temp');
    await client.send(new DeleteBucketLifecycleCommand({ Bucket: bucket }));

    await client.send(new PutBucketEncryptionCommand({
      Bucket: bucket,
      ServerSideEncryptionConfiguration: {
        Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'AES256' } }],
      },
    }));
    const encryption = await client.send(new GetBucketEncryptionCommand({ Bucket: bucket }));
    expect(encryption.ServerSideEncryptionConfiguration?.Rules?.[0]?.ApplyServerSideEncryptionByDefault?.SSEAlgorithm).toBe('AES256');
    await client.send(new DeleteBucketEncryptionCommand({ Bucket: bucket }));

    await client.send(new PutPublicAccessBlockCommand({
      Bucket: bucket,
      PublicAccessBlockConfiguration: {
        BlockPublicAcls: true,
        IgnorePublicAcls: true,
        BlockPublicPolicy: true,
        RestrictPublicBuckets: true,
      },
    }));
    const publicAccessBlock = await client.send(new GetPublicAccessBlockCommand({ Bucket: bucket }));
    expect(publicAccessBlock.PublicAccessBlockConfiguration?.BlockPublicAcls).toBe(true);
    await client.send(new DeletePublicAccessBlockCommand({ Bucket: bucket }));

    const baseKey = 'sdk/all/base.txt';
    await client.send(new PutObjectCommand({
      Bucket: bucket,
      Key: baseKey,
      Body: Buffer.from('all-ops-body'),
      ContentType: 'text/plain',
      Metadata: { suite: 'all-ops' },
      Tagging: 'phase=initial',
    }));
    const head = await client.send(new HeadObjectCommand({ Bucket: bucket, Key: baseKey }));
    expect(head.ContentType).toBe('text/plain');
    expect(head.Metadata?.suite).toBe('all-ops');
    const get = await client.send(new GetObjectCommand({ Bucket: bucket, Key: baseKey }));
    expect(await streamToString(get.Body)).toBe('all-ops-body');

    const listV1 = await client.send(new ListObjectsCommand({ Bucket: bucket, Prefix: 'sdk/all/' }));
    expect(listV1.Contents?.some((item) => item.Key === baseKey)).toBe(true);
    const listV2 = await client.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: 'sdk/all/' }));
    expect(listV2.Contents?.some((item) => item.Key === baseKey)).toBe(true);

    await client.send(new PutObjectTaggingCommand({
      Bucket: bucket,
      Key: baseKey,
      Tagging: { TagSet: [{ Key: 'phase', Value: 'updated' }] },
    }));
    const objectTags = await client.send(new GetObjectTaggingCommand({ Bucket: bucket, Key: baseKey }));
    expect(objectTags.TagSet).toContainEqual({ Key: 'phase', Value: 'updated' });
    await client.send(new DeleteObjectTaggingCommand({ Bucket: bucket, Key: baseKey }));
    const emptyObjectTags = await client.send(new GetObjectTaggingCommand({ Bucket: bucket, Key: baseKey }));
    expect(emptyObjectTags.TagSet ?? []).toHaveLength(0);

    const copyKey = 'sdk/all/copied.txt';
    await client.send(new CopyObjectCommand({ Bucket: 'archive', Key: copyKey, CopySource: `/${bucket}/${baseKey}` }));
    const copied = await client.send(new GetObjectCommand({ Bucket: 'archive', Key: copyKey }));
    expect(await streamToString(copied.Body)).toBe('all-ops-body');

    const lockedKey = 'sdk/all/locked.txt';
    await client.send(new PutObjectCommand({ Bucket: bucket, Key: lockedKey, Body: Buffer.from('locked') }));
    await client.send(new PutObjectLegalHoldCommand({ Bucket: bucket, Key: lockedKey, LegalHold: { Status: 'ON' } }));
    const legalHold = await client.send(new GetObjectLegalHoldCommand({ Bucket: bucket, Key: lockedKey }));
    expect(legalHold.LegalHold?.Status).toBe('ON');
    await expect(client.send(new PutObjectCommand({ Bucket: bucket, Key: lockedKey, Body: Buffer.from('blocked') }))).rejects.toMatchObject({ name: 'AccessDenied' });
    await client.send(new PutObjectLegalHoldCommand({ Bucket: bucket, Key: lockedKey, LegalHold: { Status: 'OFF' } }));
    const retainUntilDate = new Date(Date.now() + 60_000);
    await client.send(new PutObjectRetentionCommand({ Bucket: bucket, Key: lockedKey, Retention: { Mode: 'GOVERNANCE', RetainUntilDate: retainUntilDate } }));
    const retention = await client.send(new GetObjectRetentionCommand({ Bucket: bucket, Key: lockedKey }));
    expect(retention.Retention?.Mode).toBe('GOVERNANCE');
    await expect(client.send(new DeleteObjectCommand({ Bucket: bucket, Key: lockedKey }))).rejects.toMatchObject({ name: 'AccessDenied' });

    await client.send(new PutBucketVersioningCommand({ Bucket: bucket, VersioningConfiguration: { Status: 'Enabled' } }));
    const versioning = await client.send(new GetBucketVersioningCommand({ Bucket: bucket }));
    expect(versioning.Status).toBe('Enabled');
    const versionedKey = 'sdk/all/versioned.txt';
    const versionOne = await client.send(new PutObjectCommand({ Bucket: bucket, Key: versionedKey, Body: Buffer.from('v1') }));
    const versionTwo = await client.send(new PutObjectCommand({ Bucket: bucket, Key: versionedKey, Body: Buffer.from('v2') }));
    expect(versionOne.VersionId).toBeTruthy();
    expect(versionTwo.VersionId).toBeTruthy();
    const oldVersion = await client.send(new GetObjectCommand({ Bucket: bucket, Key: versionedKey, VersionId: versionOne.VersionId }));
    expect(await streamToString(oldVersion.Body)).toBe('v1');
    await client.send(new HeadObjectCommand({ Bucket: bucket, Key: versionedKey, VersionId: versionTwo.VersionId }));
    const versions = await client.send(new ListObjectVersionsCommand({ Bucket: bucket, Prefix: versionedKey }));
    expect(versions.Versions?.length).toBeGreaterThanOrEqual(2);
    await client.send(new DeleteObjectCommand({ Bucket: bucket, Key: versionedKey, VersionId: versionOne.VersionId }));
    await expect(client.send(new GetObjectCommand({ Bucket: bucket, Key: versionedKey, VersionId: versionOne.VersionId }))).rejects.toMatchObject({ name: 'NoSuchVersion' });
    await client.send(new PutBucketVersioningCommand({ Bucket: bucket, VersioningConfiguration: { Status: 'Suspended' } }));

    const deleteManyKeys = ['sdk/all/delete-many-a.txt', 'sdk/all/delete-many-b.txt'];
    await Promise.all(deleteManyKeys.map((key) => client.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: Buffer.from(key) }))));
    const deleteManyResult = await client.send(new DeleteObjectsCommand({
      Bucket: bucket,
      Delete: { Objects: deleteManyKeys.map((Key) => ({ Key })) },
    }));
    expect(deleteManyResult.Deleted?.map((item) => item.Key)).toEqual(expect.arrayContaining(deleteManyKeys));
    await expect(client.send(new HeadObjectCommand({ Bucket: bucket, Key: deleteManyKeys[0] }))).rejects.toMatchObject({ name: 'NotFound' });

    const abortKey = 'sdk/all/abort-multipart.txt';
    const abortUpload = await client.send(new CreateMultipartUploadCommand({ Bucket: bucket, Key: abortKey }));
    expect(abortUpload.UploadId).toBeTruthy();
    const abortUploads = await client.send(new ListMultipartUploadsCommand({ Bucket: bucket }));
    expect(abortUploads.Uploads?.some((item) => item.UploadId === abortUpload.UploadId)).toBe(true);
    await client.send(new AbortMultipartUploadCommand({ Bucket: bucket, Key: abortKey, UploadId: abortUpload.UploadId }));

    const multipartKey = 'sdk/all/complete-multipart.txt';
    const multipart = await client.send(new CreateMultipartUploadCommand({ Bucket: bucket, Key: multipartKey }));
    const part = await client.send(new UploadPartCommand({ Bucket: bucket, Key: multipartKey, UploadId: multipart.UploadId, PartNumber: 1, Body: Buffer.from('part-body') }));
    const parts = await client.send(new ListPartsCommand({ Bucket: bucket, Key: multipartKey, UploadId: multipart.UploadId }));
    expect(parts.Parts?.[0]?.PartNumber).toBe(1);
    await client.send(new CompleteMultipartUploadCommand({
      Bucket: bucket,
      Key: multipartKey,
      UploadId: multipart.UploadId,
      MultipartUpload: { Parts: [{ ETag: part.ETag, PartNumber: 1 }] },
    }));
    const completedMultipart = await client.send(new GetObjectCommand({ Bucket: bucket, Key: multipartKey }));
    expect(await streamToString(completedMultipart.Body)).toBe('part-body');

    const presignedKey = 'sdk/all/official-presigner.txt';
    const presignedPut = await getSignedUrl(client, new PutObjectCommand({ Bucket: bucket, Key: presignedKey }), { expiresIn: 300 });
    const presignedPutResponse = await fetch(presignedPut, { method: 'PUT', body: 'official-presigner-body' });
    expect(presignedPutResponse.status).toBe(200);
    const presignedGet = await getSignedUrl(client, new GetObjectCommand({ Bucket: bucket, Key: presignedKey }), { expiresIn: 300 });
    const presignedGetResponse = await fetch(presignedGet);
    expect(presignedGetResponse.status).toBe(200);
    expect(await presignedGetResponse.text()).toBe('official-presigner-body');

    running.close = () => Promise.resolve();
    client.destroy();
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