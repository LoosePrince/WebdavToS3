import { FastifyRequest, FastifyReply } from 'fastify';
import { verifySigV4 } from './auth/sigv4.js';
import { TenantRegistry, type BucketBinding } from '../tenancy/tenant-registry.js';
import { WebdavClient } from '../webdav/client.js';
import { parsePathStyleUrl } from '../utils/path-mapper.js';
import { S3ErrorResponse } from './errors.js';
import {
  getObject,
  putObject,
  headObject,
  deleteObject,
  copyObject,
  listObjectsV2,
  listBuckets,
  headBucket,
  S3OperationError,
} from './operations/index.js';
import {
  listBucketsXml,
  listObjectsV2Xml,
  copyObjectXml,
  locationXml,
  XML_HEADERS,
} from './xml/serializer.js';
import { getRequestId } from '../observability/request-context.js';

export async function handleS3Request(
  req: FastifyRequest,
  reply: FastifyReply,
  tenantRegistry: TenantRegistry,
): Promise<void> {
  const pathname = req.url.split('?')[0];
  const query = req.query as Record<string, string | undefined>;
  const method = req.method.toUpperCase();
  const headers = req.headers as Record<string, string>;
  const requestId = getRequestId();

  // Special routes
  if (pathname === '/' && method === 'GET') {
    // ListAllMyBuckets
    const authResult = authenticateRequest(headers, method, '/', tenantRegistry);
    if (!authResult.ok) {
      return sendS3Error(reply, authResult.code!, authResult.message!, 403, requestId);
    }

    const tenant = tenantRegistry.findByAccessKey(authResult.accessKey!);
    if (!tenant) {
      return sendS3Error(reply, 'AccessDenied', 'Tenant not found', 403, requestId);
    }

    const result = listBuckets(tenant);
    const xml = listBucketsXml(result);
    return reply.status(200).headers(XML_HEADERS).send(xml);
  }

  // Parse bucket/key from path-style URL
  const allBucketNames = new Set<string>();
  for (const t of tenantRegistry.allTenants) {
    for (const b of t.buckets.keys()) {
      allBucketNames.add(b);
    }
  }

  const parsed = parsePathStyleUrl(pathname, allBucketNames);
  if (!parsed) {
    return sendS3Error(reply, 'NoSuchBucket', 'The specified bucket does not exist', 404, requestId);
  }

  const { bucket: bucketName, key } = parsed;

  // Find the tenant that owns this bucket
  const ownerTenant = findTenantByBucket(tenantRegistry, bucketName);
  if (!ownerTenant) {
    return sendS3Error(reply, 'NoSuchBucket', 'The specified bucket does not exist', 404, requestId);
  }

  const bucketBinding = ownerTenant.buckets.get(bucketName)!;
  const upstream = ownerTenant.upstreams.get(bucketBinding.upstreamId);
  if (!upstream) {
    return sendS3Error(reply, 'InternalError', 'Upstream configuration not found', 500, requestId);
  }

  // Auth
  const authResult = authenticateRequest(headers, method, pathname, tenantRegistry);
  if (!authResult.ok) {
    return sendS3Error(reply, authResult.code!, authResult.message!, 403, requestId);
  }
  if (authResult.accessKey !== ownerTenant.accessKeyId) {
    return sendS3Error(reply, 'AccessDenied', 'Access denied', 403, requestId);
  }

  const client = new WebdavClient({
    endpoint: upstream.endpoint,
    username: upstream.username,
    password: upstream.password,
    rejectUnauthorized: upstream.rejectUnauthorized,
    connectTimeoutMs: upstream.connectTimeoutMs,
    requestTimeoutMs: upstream.requestTimeoutMs,
  });

  try {
    switch (true) {
      // --- Bucket-level operations ---
      case method === 'HEAD' && !key:
        return handleHeadBucket(reply, bucketBinding, requestId);

      // --- Object operations ---
      case method === 'GET' && !key && query['location'] !== undefined:
        return reply.status(200).headers(XML_HEADERS).send(locationXml(bucketBinding.region));

      case method === 'GET' && !!key:
        return handleGetObject(req, reply, client, bucketBinding, key, requestId);

      case method === 'HEAD' && !!key:
        return handleHeadObject(reply, client, bucketBinding, key, requestId);

      case method === 'PUT' && !!key:
        return handlePutObject(req, reply, client, bucketBinding, key, requestId);

      case method === 'DELETE' && !!key:
        return handleDeleteObject(reply, client, bucketBinding, key, requestId);

      case method === 'COPY' && !!key:
        return handleCopyObject(req, reply, client, bucketBinding, key, requestId);

      case method === 'GET' && !key && query['list-type'] === '2':
        return handleListObjectsV2(req, reply, client, bucketBinding, query, requestId);

      case method === 'GET' && !key:
        return handleListObjectsV2(req, reply, client, bucketBinding, { ...query, 'list-type': '1' }, requestId);

      default:
        return sendS3Error(reply, 'NotImplemented', 'Operation not implemented', 501, requestId);
    }
  } catch (err) {
    if (err instanceof S3OperationError) {
      return sendS3Error(reply, err.code, err.message, err.httpStatus, requestId);
    }
    return sendS3Error(reply, 'InternalError', String(err), 500, requestId);
  }
}

// --- Operation handlers ---

async function handleGetObject(
  req: FastifyRequest,
  reply: FastifyReply,
  client: WebdavClient,
  bucket: BucketBinding,
  key: string,
  requestId: string,
) {
  const rangeHeader = req.headers['range'] as string | undefined;
  const result = await getObject(client, bucket, key, rangeHeader);
  return reply
    .status(result.statusCode)
    .headers({ ...result.headers, 'x-amz-request-id': requestId })
    .send(result.body);
}

async function handleHeadObject(
  reply: FastifyReply,
  client: WebdavClient,
  bucket: BucketBinding,
  key: string,
  requestId: string,
) {
  const result = await headObject(client, bucket, key);
  return reply
    .status(result.statusCode)
    .headers(result.headers)
    .send();
}

async function handlePutObject(
  req: FastifyRequest,
  reply: FastifyReply,
  client: WebdavClient,
  bucket: BucketBinding,
  key: string,
  requestId: string,
) {
  const contentLength = req.headers['content-length']
    ? parseInt(req.headers['content-length'], 10)
    : undefined;
  const result = await putObject(client, bucket, key, req.body as NodeJS.ReadableStream, contentLength);
  return reply
    .status(200)
    .header('etag', result.etag)
    .header('x-amz-request-id', requestId)
    .send();
}

async function handleDeleteObject(
  reply: FastifyReply,
  client: WebdavClient,
  bucket: BucketBinding,
  key: string,
  requestId: string,
) {
  await deleteObject(client, bucket, key);
  return reply.status(204).header('x-amz-request-id', requestId).send();
}

async function handleCopyObject(
  req: FastifyRequest,
  reply: FastifyReply,
  client: WebdavClient,
  bucket: BucketBinding,
  destKey: string,
  requestId: string,
) {
  const sourceHeader = req.headers['x-amz-copy-source'] as string;
  if (!sourceHeader) {
    return sendS3Error(reply, 'InvalidRequest', 'Missing x-amz-copy-source header', 400, requestId);
  }
  // x-amz-copy-source format: /bucket/key
  const sourcePath = sourceHeader.replace(/^\//, '');
  const parts = sourcePath.split('/');
  const sourceBucket = parts[0];
  const sourceKey = parts.slice(1).join('/');

  if (sourceBucket !== bucket.name) {
    return sendS3Error(reply, 'InvalidRequest', 'Cross-bucket copy not yet supported', 400, requestId);
  }

  const result = await copyObject(client, bucket, sourceKey, destKey);
  const xml = copyObjectXml({ etag: result.etag, lastModified: result.lastModified });
  return reply.status(200).headers(XML_HEADERS).send(xml);
}

async function handleHeadBucket(
  reply: FastifyReply,
  bucket: BucketBinding,
  requestId: string,
) {
  return reply
    .status(200)
    .header('x-amz-bucket-region', bucket.region)
    .header('x-amz-request-id', requestId)
    .send();
}

async function handleListObjectsV2(
  req: FastifyRequest,
  reply: FastifyReply,
  client: WebdavClient,
  bucket: BucketBinding,
  query: Record<string, string | undefined>,
  requestId: string,
) {
  const result = await listObjectsV2(client, bucket, {
    prefix: query['prefix'],
    delimiter: query['delimiter'],
    maxKeys: query['max-keys'] ? parseInt(query['max-keys'], 10) : undefined,
    continuationToken: query['continuation-token'],
  });
  const xml = listObjectsV2Xml(result);
  return reply.status(200).headers(XML_HEADERS).send(xml);
}

// --- Auth helpers ---

interface AuthResult {
  ok: boolean;
  code?: string;
  message?: string;
  accessKey?: string;
}

function authenticateRequest(
  headers: Record<string, string>,
  method: string,
  pathname: string,
  registry: TenantRegistry,
): AuthResult {
  const authHeader = headers['authorization'];
  if (!authHeader) {
    return { ok: false, code: 'AccessDenied', message: 'Missing Authorization header' };
  }

  // Extract access key from auth header
  const match = authHeader.match(/Credential=([^/]+)/);
  if (!match) {
    return { ok: false, code: 'AccessDenied', message: 'Malformed Authorization header' };
  }

  const accessKey = match[1];
  const tenant = registry.findByAccessKey(accessKey);
  if (!tenant) {
    return { ok: false, code: 'InvalidAccessKeyId', message: 'The AWS Access Key Id you provided does not exist in our records.' };
  }

  const result = verifySigV4({
    method,
    pathname,
    headers,
    body: null,
    secretAccessKey: tenant.secretAccessKey,
  });

  if (!result.ok) {
    return { ok: false, code: result.code, message: result.message };
  }

  return { ok: true, accessKey };
}

// --- Helpers ---

function findTenantByBucket(registry: TenantRegistry, bucketName: string) {
  for (const t of registry.allTenants) {
    if (t.buckets.has(bucketName)) return t;
  }
  return undefined;
}

function sendS3Error(reply: FastifyReply, code: string, message: string, status: number, requestId: string) {
  const err = new S3ErrorResponse(code, message, status);
  return reply.status(status).headers({ ...XML_HEADERS, 'x-amz-request-id': requestId }).send(err.toXml(requestId));
}