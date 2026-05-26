import { FastifyRequest, FastifyReply } from 'fastify';
import { verifySigV4, extractSigV4AccessKey } from './auth/sigv4.js';
import { TenantRegistry, type BucketBinding, type Tenant } from '../tenancy/tenant-registry.js';
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
  S3OperationError,
} from './operations/index.js';
import {
  listBucketsXml,
  listObjectsV2Xml,
  copyObjectXml,
  locationXml,
  XML_HEADERS,
  escapeXml,
} from './xml/serializer.js';
import { getRequestId } from '../observability/request-context.js';
import { S3StateStore, type BucketState, type MultipartUploadState } from './state/store.js';

interface AuthResult {
  ok: boolean;
  code?: string;
  message?: string;
  accessKey?: string;
}

interface S3RequestContext {
  req: FastifyRequest;
  reply: FastifyReply;
  registry: TenantRegistry;
  requestId: string;
  method: string;
  pathname: string;
  rawQueryString: string;
  query: Record<string, string | undefined>;
  headers: Record<string, string>;
  bucketName?: string;
  key: string;
  ownerTenant?: Tenant;
  bucket?: BucketBinding;
  client?: WebdavClient;
  state?: S3StateStore;
}

export async function handleS3Request(
  req: FastifyRequest,
  reply: FastifyReply,
  tenantRegistry: TenantRegistry,
): Promise<void> {
  const ctx = buildContext(req, reply, tenantRegistry);

  if (ctx.method === 'OPTIONS') {
    return sendCorsPreflight(reply, ctx.requestId);
  }

  if (ctx.pathname === '/' && ctx.method === 'GET') {
    const auth = authenticateRequest(ctx.headers, ctx.method, '/', ctx.rawQueryString, tenantRegistry);
    if (!auth.ok) return sendS3Error(reply, auth.code!, auth.message!, 403, ctx.requestId);
    const tenant = tenantRegistry.findByAccessKey(auth.accessKey!);
    if (!tenant) return sendS3Error(reply, 'AccessDenied', 'Tenant not found', 403, ctx.requestId);
    return reply.status(200).headers(XML_HEADERS).send(listBucketsXml(listBuckets(tenant)));
  }

  if (!ctx.bucketName || !ctx.bucket) {
    return sendS3Error(reply, 'NoSuchBucket', 'The specified bucket does not exist', 404, ctx.requestId);
  }

  const auth = authenticateRequest(ctx.headers, ctx.method, ctx.pathname, ctx.rawQueryString, tenantRegistry);
  if (!auth.ok) return sendS3Error(reply, auth.code!, auth.message!, 403, ctx.requestId);
  if (auth.accessKey !== ctx.ownerTenant?.accessKeyId) {
    return sendS3Error(reply, 'AccessDenied', 'Access denied', 403, ctx.requestId);
  }

  try {
    switch (resolveOperation(ctx)) {
      case 'HeadBucket':
        return handleHeadBucket(ctx);
      case 'CreateBucket':
        return handleCreateBucket(ctx);
      case 'DeleteBucket':
        return handleDeleteBucket(ctx);
      case 'GetBucketLocation':
        return ctx.reply.status(200).headers(XML_HEADERS).send(locationXml(ctx.bucket.region));
      case 'ListObjects':
        return handleListObjects(ctx);
      case 'ListObjectVersions':
        return sendXml(ctx, 200, versionsXml(ctx.bucket.name));
      case 'GetBucketAcl':
        return sendXml(ctx, 200, aclXml());
      case 'PutBucketAcl':
        return sendEmpty(ctx, 200);
      case 'GetBucketVersioning':
        return handleGetBucketVersioning(ctx);
      case 'PutBucketVersioning':
        return handlePutBucketVersioning(ctx);
      case 'GetBucketPolicy':
        return handleGetJsonControl(ctx, 'policy');
      case 'PutBucketPolicy':
        return handlePutJsonControl(ctx, 'policy');
      case 'DeleteBucketPolicy':
        return handleDeleteJsonControl(ctx, 'policy');
      case 'GetBucketCors':
        return handleGetXmlControl(ctx, 'cors', corsXml());
      case 'PutBucketCors':
        return handlePutJsonControl(ctx, 'cors');
      case 'DeleteBucketCors':
        return handleDeleteJsonControl(ctx, 'cors');
      case 'GetBucketTagging':
        return handleGetBucketTagging(ctx);
      case 'PutBucketTagging':
        return handlePutJsonControl(ctx, 'tagging');
      case 'DeleteBucketTagging':
        return handleDeleteJsonControl(ctx, 'tagging');
      case 'GetBucketLifecycle':
        return handleGetXmlControl(ctx, 'lifecycle', lifecycleXml());
      case 'PutBucketLifecycle':
        return handlePutJsonControl(ctx, 'lifecycle');
      case 'DeleteBucketLifecycle':
        return handleDeleteJsonControl(ctx, 'lifecycle');
      case 'GetBucketEncryption':
        return handleGetXmlControl(ctx, 'encryption', encryptionXml());
      case 'PutBucketEncryption':
        return handlePutJsonControl(ctx, 'encryption');
      case 'DeleteBucketEncryption':
        return handleDeleteJsonControl(ctx, 'encryption');
      case 'GetPublicAccessBlock':
        return handleGetXmlControl(ctx, 'publicAccessBlock', publicAccessBlockXml());
      case 'PutPublicAccessBlock':
        return handlePutJsonControl(ctx, 'publicAccessBlock');
      case 'DeletePublicAccessBlock':
        return handleDeleteJsonControl(ctx, 'publicAccessBlock');
      case 'CreateMultipartUpload':
        return handleCreateMultipartUpload(ctx);
      case 'UploadPart':
        return handleUploadPart(ctx);
      case 'CompleteMultipartUpload':
        return handleCompleteMultipartUpload(ctx);
      case 'AbortMultipartUpload':
        return handleAbortMultipartUpload(ctx);
      case 'ListParts':
        return handleListParts(ctx);
      case 'ListMultipartUploads':
        return sendXml(ctx, 200, multipartUploadsXml(ctx.bucket.name));
      case 'DeleteObjects':
        return sendXml(ctx, 200, '<?xml version="1.0" encoding="UTF-8"?>\n<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>');
      case 'GetObjectTagging':
        return sendXml(ctx, 200, taggingXml({}));
      case 'PutObjectTagging':
      case 'DeleteObjectTagging':
        return sendEmpty(ctx, 204);
      case 'GetObject':
        return handleGetObject(ctx);
      case 'HeadObject':
        return handleHeadObject(ctx);
      case 'PutObject':
        return handlePutObject(ctx);
      case 'DeleteObject':
        return handleDeleteObject(ctx);
      case 'CopyObject':
        return handleCopyObject(ctx);
      default:
        return sendS3Error(reply, 'NotImplemented', 'Operation not implemented', 501, ctx.requestId);
    }
  } catch (err) {
    if (err instanceof S3OperationError) {
      return sendS3Error(reply, err.code, err.message, err.httpStatus, ctx.requestId);
    }
    return sendS3Error(reply, 'InternalError', String(err), 500, ctx.requestId);
  }
}

function buildContext(req: FastifyRequest, reply: FastifyReply, registry: TenantRegistry): S3RequestContext {
  const pathname = req.url.split('?')[0];
  const rawQueryString = req.url.includes('?') ? req.url.slice(req.url.indexOf('?') + 1) : '';
  const query = req.query as Record<string, string | undefined>;
  const method = req.method.toUpperCase();
  const headers = req.headers as Record<string, string>;
  const requestId = getRequestId();
  const allBucketNames = new Set<string>(registry.allTenants.flatMap((tenant) => [...tenant.buckets.keys()]));
  const host = (headers.host ?? '').split(':')[0];
  const virtualBucket = [...allBucketNames].find((bucket) => host === bucket || host.startsWith(`${bucket}.`));
  const parsed = virtualBucket
    ? { bucket: virtualBucket, key: pathname.split('/').filter(Boolean).map(decodeURIComponent).join('/') }
    : parsePathStyleUrl(pathname, allBucketNames);

  const bucketName = parsed?.bucket;
  const ownerTenant = bucketName ? findTenantByBucket(registry, bucketName) : undefined;
  const bucket = bucketName ? ownerTenant?.buckets.get(bucketName) : undefined;
  const upstream = bucket ? ownerTenant?.upstreams.get(bucket.upstreamId) : undefined;
  const client = upstream
    ? new WebdavClient({
        endpoint: upstream.endpoint,
        username: upstream.username,
        password: upstream.password,
        rejectUnauthorized: upstream.rejectUnauthorized,
        connectTimeoutMs: upstream.connectTimeoutMs,
        requestTimeoutMs: upstream.requestTimeoutMs,
      })
    : undefined;

  return {
    req,
    reply,
    registry,
    requestId,
    method,
    pathname,
    rawQueryString,
    query,
    headers,
    bucketName,
    key: parsed?.key ?? '',
    ownerTenant,
    bucket,
    client,
    state: client ? new S3StateStore(client) : undefined,
  };
}

function resolveOperation(ctx: S3RequestContext): string {
  const q = ctx.query;
  const has = (name: string) => Object.prototype.hasOwnProperty.call(q, name);

  if (!ctx.key) {
    if (ctx.method === 'HEAD') return 'HeadBucket';
    if (ctx.method === 'PUT') return 'CreateBucket';
    if (ctx.method === 'DELETE') return 'DeleteBucket';
    if (ctx.method === 'POST' && has('delete')) return 'DeleteObjects';
    if (ctx.method === 'GET' && has('location')) return 'GetBucketLocation';
    if (ctx.method === 'GET' && has('versions')) return 'ListObjectVersions';
    if (ctx.method === 'GET' && has('uploads')) return 'ListMultipartUploads';
    if (ctx.method === 'GET' && has('acl')) return 'GetBucketAcl';
    if (ctx.method === 'PUT' && has('acl')) return 'PutBucketAcl';
    if (ctx.method === 'GET' && has('versioning')) return 'GetBucketVersioning';
    if (ctx.method === 'PUT' && has('versioning')) return 'PutBucketVersioning';
    if (ctx.method === 'GET' && has('policy')) return 'GetBucketPolicy';
    if (ctx.method === 'PUT' && has('policy')) return 'PutBucketPolicy';
    if (ctx.method === 'DELETE' && has('policy')) return 'DeleteBucketPolicy';
    if (ctx.method === 'GET' && has('cors')) return 'GetBucketCors';
    if (ctx.method === 'PUT' && has('cors')) return 'PutBucketCors';
    if (ctx.method === 'DELETE' && has('cors')) return 'DeleteBucketCors';
    if (ctx.method === 'GET' && has('tagging')) return 'GetBucketTagging';
    if (ctx.method === 'PUT' && has('tagging')) return 'PutBucketTagging';
    if (ctx.method === 'DELETE' && has('tagging')) return 'DeleteBucketTagging';
    if (ctx.method === 'GET' && (has('lifecycle') || has('lifecycleConfiguration'))) return 'GetBucketLifecycle';
    if (ctx.method === 'PUT' && (has('lifecycle') || has('lifecycleConfiguration'))) return 'PutBucketLifecycle';
    if (ctx.method === 'DELETE' && (has('lifecycle') || has('lifecycleConfiguration'))) return 'DeleteBucketLifecycle';
    if (ctx.method === 'GET' && has('encryption')) return 'GetBucketEncryption';
    if (ctx.method === 'PUT' && has('encryption')) return 'PutBucketEncryption';
    if (ctx.method === 'DELETE' && has('encryption')) return 'DeleteBucketEncryption';
    if (ctx.method === 'GET' && has('publicAccessBlock')) return 'GetPublicAccessBlock';
    if (ctx.method === 'PUT' && has('publicAccessBlock')) return 'PutPublicAccessBlock';
    if (ctx.method === 'DELETE' && has('publicAccessBlock')) return 'DeletePublicAccessBlock';
    if (ctx.method === 'GET') return 'ListObjects';
  }

  if (ctx.method === 'POST' && has('uploads')) return 'CreateMultipartUpload';
  if (ctx.method === 'PUT' && has('partNumber') && has('uploadId')) return 'UploadPart';
  if (ctx.method === 'POST' && has('uploadId')) return 'CompleteMultipartUpload';
  if (ctx.method === 'DELETE' && has('uploadId')) return 'AbortMultipartUpload';
  if (ctx.method === 'GET' && has('uploadId')) return 'ListParts';
  if (ctx.method === 'GET' && has('tagging')) return 'GetObjectTagging';
  if (ctx.method === 'PUT' && has('tagging')) return 'PutObjectTagging';
  if (ctx.method === 'DELETE' && has('tagging')) return 'DeleteObjectTagging';
  if (ctx.method === 'GET') return 'GetObject';
  if (ctx.method === 'HEAD') return 'HeadObject';
  if (ctx.method === 'PUT' && ctx.headers['x-amz-copy-source']) return 'CopyObject';
  if (ctx.method === 'PUT') return 'PutObject';
  if (ctx.method === 'DELETE') return 'DeleteObject';

  return 'NotImplemented';
}

async function handleGetObject(ctx: S3RequestContext) {
  const result = await getObject(ctx.client!, ctx.bucket!, ctx.key, ctx.headers['range']);
  const overrideHeaders = responseOverrideHeaders(ctx.query);
  return ctx.reply
    .status(result.statusCode)
    .headers({ ...result.headers, ...overrideHeaders, 'x-amz-request-id': ctx.requestId })
    .send(result.body);
}

async function handleHeadObject(ctx: S3RequestContext) {
  const result = await headObject(ctx.client!, ctx.bucket!, ctx.key);
  return ctx.reply.status(result.statusCode).headers({ ...result.headers, 'x-amz-request-id': ctx.requestId }).send();
}

async function handlePutObject(ctx: S3RequestContext) {
  const contentLength = ctx.headers['content-length'] ? parseInt(ctx.headers['content-length'], 10) : undefined;
  const result = await putObject(ctx.client!, ctx.bucket!, ctx.key, ctx.req.body as NodeJS.ReadableStream | Buffer, contentLength);
  return ctx.reply.status(200).header('etag', result.etag).header('x-amz-request-id', ctx.requestId).send();
}

async function handleDeleteObject(ctx: S3RequestContext) {
  await deleteObject(ctx.client!, ctx.bucket!, ctx.key);
  return ctx.reply.status(204).header('x-amz-request-id', ctx.requestId).send();
}

async function handleCopyObject(ctx: S3RequestContext) {
  const sourceHeader = ctx.headers['x-amz-copy-source'];
  if (!sourceHeader) return sendS3Error(ctx.reply, 'InvalidRequest', 'Missing x-amz-copy-source header', 400, ctx.requestId);
  const sourcePath = sourceHeader.replace(/^\//, '');
  const parts = sourcePath.split('/');
  const sourceBucket = decodeURIComponent(parts[0]);
  const sourceKey = parts.slice(1).map(decodeURIComponent).join('/');
  if (sourceBucket !== ctx.bucket!.name) {
    return sendS3Error(ctx.reply, 'InvalidRequest', 'Cross-bucket copy not yet supported', 400, ctx.requestId);
  }
  const result = await copyObject(ctx.client!, ctx.bucket!, sourceKey, ctx.key);
  return ctx.reply.status(200).headers(XML_HEADERS).send(copyObjectXml({ etag: result.etag, lastModified: result.lastModified }));
}

async function handleListObjects(ctx: S3RequestContext) {
  const result = await listObjectsV2(ctx.client!, ctx.bucket!, {
    prefix: ctx.query.prefix,
    delimiter: ctx.query.delimiter,
    maxKeys: ctx.query['max-keys'] ? parseInt(ctx.query['max-keys'], 10) : undefined,
    continuationToken: ctx.query['continuation-token'] ?? ctx.query.marker,
  });
  return ctx.reply.status(200).headers(XML_HEADERS).send(listObjectsV2Xml(result));
}

function handleHeadBucket(ctx: S3RequestContext) {
  return ctx.reply.status(200).header('x-amz-bucket-region', ctx.bucket!.region).header('x-amz-request-id', ctx.requestId).send();
}

function handleCreateBucket(ctx: S3RequestContext) {
  return ctx.reply.status(200).header('x-amz-request-id', ctx.requestId).send();
}

function handleDeleteBucket(ctx: S3RequestContext) {
  return sendS3Error(ctx.reply, 'BucketNotEmpty', 'Configured buckets cannot be deleted through this gateway', 409, ctx.requestId);
}

async function handleGetBucketVersioning(ctx: S3RequestContext) {
  const state = await ctx.state!.getBucketState(ctx.bucketName!);
  return sendXml(ctx, 200, versioningXml(state.versioning));
}

async function handlePutBucketVersioning(ctx: S3RequestContext) {
  const state = await ctx.state!.getBucketState(ctx.bucketName!);
  const body = await requestBodyText(ctx.req.body);
  state.versioning = body.includes('<Status>Enabled</Status>') ? 'Enabled' : body.includes('<Status>Suspended</Status>') ? 'Suspended' : state.versioning;
  await ctx.state!.putBucketState(state);
  return sendEmpty(ctx, 200);
}

async function handleGetJsonControl(ctx: S3RequestContext, key: keyof BucketState) {
  const state = await ctx.state!.getBucketState(ctx.bucketName!);
  const value = state[key];
  if (value === undefined) return sendS3Error(ctx.reply, 'NoSuchConfiguration', 'The requested configuration does not exist', 404, ctx.requestId);
  return ctx.reply.status(200).type('application/json').send(JSON.stringify(value));
}

async function handlePutJsonControl(ctx: S3RequestContext, key: keyof BucketState) {
  const state = await ctx.state!.getBucketState(ctx.bucketName!);
  const body = await requestBodyText(ctx.req.body);
  (state as unknown as Record<string, unknown>)[key] = body ? safeJsonParse(body) ?? body : {};
  await ctx.state!.putBucketState(state);
  return sendEmpty(ctx, 200);
}

async function handleDeleteJsonControl(ctx: S3RequestContext, key: keyof BucketState) {
  const state = await ctx.state!.getBucketState(ctx.bucketName!);
  delete (state as unknown as Record<string, unknown>)[key];
  await ctx.state!.putBucketState(state);
  return sendEmpty(ctx, 204);
}

async function handleGetXmlControl(ctx: S3RequestContext, key: keyof BucketState, fallbackXml: string) {
  const state = await ctx.state!.getBucketState(ctx.bucketName!);
  if (state[key] === undefined) return sendXml(ctx, 200, fallbackXml);
  return sendXml(ctx, 200, fallbackXml);
}

async function handleGetBucketTagging(ctx: S3RequestContext) {
  const state = await ctx.state!.getBucketState(ctx.bucketName!);
  return sendXml(ctx, 200, taggingXml(state.tagging ?? {}));
}

async function handleCreateMultipartUpload(ctx: S3RequestContext) {
  const state = await ctx.state!.createMultipartUpload({
    bucket: ctx.bucketName!,
    key: ctx.key,
    contentType: ctx.headers['content-type'],
    metadata: collectUserMetadata(ctx.headers),
  });
  return sendXml(ctx, 200, createMultipartUploadXml(ctx.bucketName!, ctx.key, state.uploadId));
}

async function handleUploadPart(ctx: S3RequestContext) {
  const uploadId = ctx.query.uploadId!;
  const partNumber = Number(ctx.query.partNumber);
  if (!Number.isInteger(partNumber) || partNumber < 1 || partNumber > 10000) {
    return sendS3Error(ctx.reply, 'InvalidArgument', 'Invalid partNumber', 400, ctx.requestId);
  }
  const state = await requireMultipart(ctx, uploadId);
  if (!state) return;
  const body = toBuffer(ctx.req.body);
  const path = ctx.state!.multipartPartPath(ctx.bucketName!, uploadId, partNumber);
  await ctx.client!.ensureCollection(path.slice(0, path.lastIndexOf('/')));
  const resp = await ctx.client!.put(path, body, body.length);
  if (![200, 201, 204].includes(resp.statusCode)) {
    return sendS3Error(ctx.reply, 'InternalError', `UploadPart failed: ${resp.statusCode}`, 500, ctx.requestId);
  }
  const etag = `"${createWeakEtag(body)}"`;
  state.parts = state.parts.filter((part) => part.partNumber !== partNumber).concat({ partNumber, etag, size: body.length, path });
  state.parts.sort((a, b) => a.partNumber - b.partNumber);
  await ctx.state!.putMultipartUpload(state);
  return ctx.reply.status(200).header('etag', etag).header('x-amz-request-id', ctx.requestId).send();
}

async function handleCompleteMultipartUpload(ctx: S3RequestContext) {
  const uploadId = ctx.query.uploadId!;
  const state = await requireMultipart(ctx, uploadId);
  if (!state) return;
  const requestedParts = parseCompleteMultipartBody(await requestBodyText(ctx.req.body));
  const parts = requestedParts.length > 0
    ? requestedParts.map((partNumber) => state.parts.find((part) => part.partNumber === partNumber)).filter(Boolean)
    : state.parts;
  if (parts.length === 0 || parts.length !== (requestedParts.length || state.parts.length)) {
    return sendS3Error(ctx.reply, 'InvalidPart', 'One or more of the specified parts could not be found', 400, ctx.requestId);
  }
  const buffers: Buffer[] = [];
  for (const part of parts) {
    const resp = await ctx.client!.get(part!.path);
    if (resp.statusCode >= 400) return sendS3Error(ctx.reply, 'InvalidPart', `Part ${part!.partNumber} is not readable`, 400, ctx.requestId);
    buffers.push(resp.body);
  }
  const finalBody = Buffer.concat(buffers);
  const result = await putObject(ctx.client!, ctx.bucket!, ctx.key, finalBody, finalBody.length);
  await ctx.state!.deleteMultipartUpload(ctx.bucketName!, uploadId);
  return sendXml(ctx, 200, completeMultipartUploadXml(ctx.bucketName!, ctx.key, result.etag));
}

async function handleAbortMultipartUpload(ctx: S3RequestContext) {
  const uploadId = ctx.query.uploadId!;
  await ctx.state!.deleteMultipartUpload(ctx.bucketName!, uploadId);
  return sendEmpty(ctx, 204);
}

async function handleListParts(ctx: S3RequestContext) {
  const uploadId = ctx.query.uploadId!;
  const state = await requireMultipart(ctx, uploadId);
  if (!state) return;
  return sendXml(ctx, 200, listPartsXml(ctx.bucketName!, ctx.key, uploadId, state));
}

async function requireMultipart(ctx: S3RequestContext, uploadId: string): Promise<MultipartUploadState | null> {
  const state = await ctx.state!.getMultipartUpload(ctx.bucketName!, uploadId);
  if (!state) {
    sendS3Error(ctx.reply, 'NoSuchUpload', 'The specified multipart upload does not exist', 404, ctx.requestId);
    return null;
  }
  return state;
}

function authenticateRequest(
  headers: Record<string, string>,
  method: string,
  pathname: string,
  queryString: string,
  registry: TenantRegistry,
): AuthResult {
  const accessKey = extractSigV4AccessKey(headers, queryString);
  if (!accessKey) return { ok: false, code: 'AccessDenied', message: 'Missing Authorization header' };

  const tenant = registry.findByAccessKey(accessKey);
  if (!tenant) {
    return { ok: false, code: 'InvalidAccessKeyId', message: 'The AWS Access Key Id you provided does not exist in our records.' };
  }

  const result = verifySigV4({ method, pathname, queryString, headers, body: null, secretAccessKey: tenant.secretAccessKey });
  if (!result.ok) return { ok: false, code: result.code, message: result.message };
  return { ok: true, accessKey };
}

function findTenantByBucket(registry: TenantRegistry, bucketName: string) {
  return registry.allTenants.find((tenant) => tenant.buckets.has(bucketName));
}

function sendS3Error(reply: FastifyReply, code: string, message: string, status: number, requestId: string) {
  const err = new S3ErrorResponse(code, message, status);
  return reply.status(status).headers({ ...XML_HEADERS, 'x-amz-request-id': requestId }).send(err.toXml(requestId));
}

function sendXml(ctx: S3RequestContext, status: number, xml: string) {
  return ctx.reply.status(status).headers({ ...XML_HEADERS, 'x-amz-request-id': ctx.requestId }).send(xml);
}

function sendEmpty(ctx: S3RequestContext, status: number) {
  return ctx.reply.status(status).header('x-amz-request-id', ctx.requestId).send();
}

function sendCorsPreflight(reply: FastifyReply, requestId: string) {
  return reply
    .status(200)
    .headers({
      'x-amz-request-id': requestId,
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET,PUT,POST,DELETE,HEAD,OPTIONS',
      'access-control-allow-headers': '*',
      'access-control-expose-headers': 'etag,x-amz-request-id,x-amz-version-id',
    })
    .send();
}

function responseOverrideHeaders(query: Record<string, string | undefined>): Record<string, string> {
  const mapping: Record<string, string> = {
    'response-content-type': 'content-type',
    'response-content-language': 'content-language',
    'response-expires': 'expires',
    'response-cache-control': 'cache-control',
    'response-content-disposition': 'content-disposition',
    'response-content-encoding': 'content-encoding',
  };
  return Object.fromEntries(
    Object.entries(mapping)
      .filter(([queryKey]) => query[queryKey] !== undefined)
      .map(([queryKey, headerName]) => [headerName, query[queryKey]!]),
  );
}

function collectUserMetadata(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(headers).filter(([key]) => key.startsWith('x-amz-meta-')));
}

function toBuffer(body: unknown): Buffer {
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === 'string') return Buffer.from(body);
  return Buffer.from([]);
}

async function requestBodyText(body: unknown): Promise<string> {
  return toBuffer(body).toString('utf-8');
}

function safeJsonParse(body: string): unknown | null {
  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
}

function parseCompleteMultipartBody(xml: string): number[] {
  return [...xml.matchAll(/<PartNumber>(\d+)<\/PartNumber>/g)].map((match) => Number(match[1]));
}

function createWeakEtag(body: Buffer): string {
  let hash = 0;
  for (const byte of body) hash = ((hash << 5) - hash + byte) | 0;
  return Math.abs(hash).toString(16).padStart(8, '0');
}

function createMultipartUploadXml(bucket: string, key: string, uploadId: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<InitiateMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>${escapeXml(bucket)}</Bucket>
  <Key>${escapeXml(key)}</Key>
  <UploadId>${escapeXml(uploadId)}</UploadId>
</InitiateMultipartUploadResult>`;
}

function completeMultipartUploadXml(bucket: string, key: string, etag: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<CompleteMultipartUploadResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Location>/${escapeXml(bucket)}/${escapeXml(key)}</Location>
  <Bucket>${escapeXml(bucket)}</Bucket>
  <Key>${escapeXml(key)}</Key>
  <ETag>${escapeXml(etag)}</ETag>
</CompleteMultipartUploadResult>`;
}

function listPartsXml(bucket: string, key: string, uploadId: string, state: MultipartUploadState): string {
  const parts = state.parts.map((part) => `  <Part><PartNumber>${part.partNumber}</PartNumber><ETag>${escapeXml(part.etag)}</ETag><Size>${part.size}</Size></Part>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<ListPartsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>${escapeXml(bucket)}</Bucket>
  <Key>${escapeXml(key)}</Key>
  <UploadId>${escapeXml(uploadId)}</UploadId>
${parts}
</ListPartsResult>`;
}

function multipartUploadsXml(bucket: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>${escapeXml(bucket)}</Bucket>
  <IsTruncated>false</IsTruncated>
</ListMultipartUploadsResult>`;
}

function versioningXml(status: BucketState['versioning']): string {
  const statusXml = status === 'Off' ? '' : `\n  <Status>${status}</Status>`;
  return `<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">${statusXml}
</VersioningConfiguration>`;
}

function versionsXml(bucket: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>${escapeXml(bucket)}</Name>
  <IsTruncated>false</IsTruncated>
</ListVersionsResult>`;
}

function aclXml(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<AccessControlPolicy xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Owner><ID>webdavtos3</ID><DisplayName>webdavtos3</DisplayName></Owner>
  <AccessControlList/>
</AccessControlPolicy>`;
}

function taggingXml(tags: Record<string, string>): string {
  const tagSet = Object.entries(tags).map(([key, value]) => `    <Tag><Key>${escapeXml(key)}</Key><Value>${escapeXml(value)}</Value></Tag>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<Tagging xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <TagSet>
${tagSet}
  </TagSet>
</Tagging>`;
}

function corsXml(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`;
}

function lifecycleXml(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`;
}

function encryptionXml(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"/>`;
}

function publicAccessBlockXml(): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <BlockPublicAcls>false</BlockPublicAcls>
  <IgnorePublicAcls>false</IgnorePublicAcls>
  <BlockPublicPolicy>false</BlockPublicPolicy>
  <RestrictPublicBuckets>false</RestrictPublicBuckets>
</PublicAccessBlockConfiguration>`;
}