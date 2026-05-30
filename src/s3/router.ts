import { createHash } from 'node:crypto';
import { FastifyRequest, FastifyReply } from 'fastify';
import {
  verifySigV4,
  extractSigV4AccessKey,
  verifyPostPolicySigV4,
  extractPostPolicyAccessKey,
} from './auth/sigv4.js';
import { TenantRegistry, type BucketBinding, type Tenant } from '../tenancy/tenant-registry.js';
import { parsePathStyleUrl } from '../utils/path-mapper.js';
import { S3ErrorResponse } from './errors.js';
import { listBuckets, S3OperationError } from './operations/index.js';
import {
  listBucketsXml,
  listObjectsV2Xml,
  copyObjectXml,
  locationXml,
  XML_HEADERS,
  escapeXml,
} from './xml/serializer.js';
import { getRequestId } from '../observability/request-context.js';
import type { BlobStore } from './blob-store.js';
import {
  type BucketState,
  type MetadataStore,
  type MultipartUploadState,
  type ObjectMetadataState,
  type ObjectVersionState,
} from './metadata-store.js';
import * as objectSemantics from './object-semantics.js';
import type { StorageBackendFactory } from './storage-backend.js';

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
  storageBackendFactory: StorageBackendFactory;
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
  blobStore?: BlobStore;
  state?: MetadataStore;
}

export async function handleS3Request(
  req: FastifyRequest,
  reply: FastifyReply,
  tenantRegistry: TenantRegistry,
  storageBackendFactory: StorageBackendFactory,
): Promise<void> {
  const ctx = buildContext(req, reply, tenantRegistry, storageBackendFactory);

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

  if (ctx.method === 'POST' && isPostPolicyUpload(ctx)) {
    const auth = authenticatePostPolicyRequest(ctx, tenantRegistry);
    if (!auth.ok) return sendS3Error(reply, auth.code!, auth.message!, 403, ctx.requestId);
    if (auth.accessKey !== ctx.ownerTenant?.accessKeyId) {
      return sendS3Error(reply, 'AccessDenied', 'Access denied', 403, ctx.requestId);
    }
    return await handlePostPolicyUpload(ctx);
  }

  const auth = authenticateRequest(ctx.headers, ctx.method, ctx.pathname, ctx.rawQueryString, tenantRegistry);
  if (!auth.ok) return sendS3Error(reply, auth.code!, auth.message!, 403, ctx.requestId);
  if (auth.accessKey !== ctx.ownerTenant?.accessKeyId) {
    return sendS3Error(reply, 'AccessDenied', 'Access denied', 403, ctx.requestId);
  }

  try {
    switch (resolveOperation(ctx)) {
      case 'HeadBucket':
        return await handleHeadBucket(ctx);
      case 'CreateBucket':
        return await handleCreateBucket(ctx);
      case 'DeleteBucket':
        return await handleDeleteBucket(ctx);
      case 'GetBucketLocation':
        return ctx.reply.status(200).headers(XML_HEADERS).send(locationXml(ctx.bucket.region));
      case 'ListObjects':
        return await handleListObjects(ctx);
      case 'ListObjectVersions':
        return await handleListObjectVersions(ctx);
      case 'GetBucketAcl':
        return sendXml(ctx, 200, aclXml());
      case 'PutBucketAcl':
        return sendEmpty(ctx, 200);
      case 'GetBucketVersioning':
        return await handleGetBucketVersioning(ctx);
      case 'PutBucketVersioning':
        return await handlePutBucketVersioning(ctx);
      case 'GetBucketPolicy':
        return await handleGetJsonControl(ctx, 'policy');
      case 'PutBucketPolicy':
        return await handlePutJsonControl(ctx, 'policy');
      case 'DeleteBucketPolicy':
        return await handleDeleteJsonControl(ctx, 'policy');
      case 'GetBucketCors':
        return await handleGetXmlControl(ctx, 'cors', corsXml());
      case 'PutBucketCors':
        return await handlePutXmlControl(ctx, 'cors');
      case 'DeleteBucketCors':
        return await handleDeleteJsonControl(ctx, 'cors');
      case 'GetBucketTagging':
        return await handleGetBucketTagging(ctx);
      case 'PutBucketTagging':
        return await handlePutBucketTagging(ctx);
      case 'DeleteBucketTagging':
        return await handleDeleteJsonControl(ctx, 'tagging');
      case 'GetBucketLifecycle':
        return await handleGetXmlControl(ctx, 'lifecycle', lifecycleXml());
      case 'PutBucketLifecycle':
        return await handlePutXmlControl(ctx, 'lifecycle');
      case 'DeleteBucketLifecycle':
        return await handleDeleteJsonControl(ctx, 'lifecycle');
      case 'GetBucketEncryption':
        return await handleGetXmlControl(ctx, 'encryption', encryptionXml());
      case 'PutBucketEncryption':
        return await handlePutXmlControl(ctx, 'encryption');
      case 'DeleteBucketEncryption':
        return await handleDeleteJsonControl(ctx, 'encryption');
      case 'GetPublicAccessBlock':
        return await handleGetXmlControl(ctx, 'publicAccessBlock', publicAccessBlockXml());
      case 'PutPublicAccessBlock':
        return await handlePutXmlControl(ctx, 'publicAccessBlock');
      case 'DeletePublicAccessBlock':
        return await handleDeleteJsonControl(ctx, 'publicAccessBlock');
      case 'CreateMultipartUpload':
        return await handleCreateMultipartUpload(ctx);
      case 'UploadPart':
        return await handleUploadPart(ctx);
      case 'CompleteMultipartUpload':
        return await handleCompleteMultipartUpload(ctx);
      case 'AbortMultipartUpload':
        return await handleAbortMultipartUpload(ctx);
      case 'ListParts':
        return await handleListParts(ctx);
      case 'ListMultipartUploads':
        return sendXml(ctx, 200, multipartUploadsXml(ctx.bucket.name, await ctx.state!.listMultipartUploads(ctx.bucketName!)));
      case 'DeleteObjects':
        return await handleDeleteObjects(ctx);
      case 'GetObjectTagging':
        return await handleGetObjectTagging(ctx);
      case 'PutObjectTagging':
        return await handlePutObjectTagging(ctx);
      case 'DeleteObjectTagging':
        return await handleDeleteObjectTagging(ctx);
      case 'GetObjectLegalHold':
        return await handleGetObjectLegalHold(ctx);
      case 'PutObjectLegalHold':
        return await handlePutObjectLegalHold(ctx);
      case 'GetObjectRetention':
        return await handleGetObjectRetention(ctx);
      case 'PutObjectRetention':
        return await handlePutObjectRetention(ctx);
      case 'GetObject':
        return await handleGetObject(ctx);
      case 'HeadObject':
        return await handleHeadObject(ctx);
      case 'PutObject':
        return await handlePutObject(ctx);
      case 'DeleteObject':
        return await handleDeleteObject(ctx);
      case 'CopyObject':
        return await handleCopyObject(ctx);
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

function buildContext(
  req: FastifyRequest,
  reply: FastifyReply,
  registry: TenantRegistry,
  storageBackendFactory: StorageBackendFactory,
): S3RequestContext {
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
  const backend = upstream ? storageBackendFactory.getBackend(upstream) : undefined;

  return {
    req,
    reply,
    registry,
    storageBackendFactory,
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
    blobStore: backend?.blobStore,
    state: backend?.metadataStore,
  };
}

function resolveOperation(ctx: S3RequestContext): string {
  const q = ctx.query;
  const has = (name: string) => Object.prototype.hasOwnProperty.call(q, name);

  if (!ctx.key) {
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
    if (ctx.method === 'HEAD') return 'HeadBucket';
    if (ctx.method === 'PUT') return 'CreateBucket';
    if (ctx.method === 'DELETE') return 'DeleteBucket';
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
  if (ctx.method === 'GET' && has('legal-hold')) return 'GetObjectLegalHold';
  if (ctx.method === 'PUT' && has('legal-hold')) return 'PutObjectLegalHold';
  if (ctx.method === 'GET' && has('retention')) return 'GetObjectRetention';
  if (ctx.method === 'PUT' && has('retention')) return 'PutObjectRetention';
  if (ctx.method === 'GET') return 'GetObject';
  if (ctx.method === 'HEAD') return 'HeadObject';
  if (ctx.method === 'PUT' && ctx.headers['x-amz-copy-source']) return 'CopyObject';
  if (ctx.method === 'PUT') return 'PutObject';
  if (ctx.method === 'DELETE') return 'DeleteObject';

  return 'NotImplemented';
}

async function handleGetObject(ctx: S3RequestContext) {
  const versionId = ctx.query.versionId;
  if (versionId) return await handleGetObjectVersion(ctx, versionId);

  const metadata = await ctx.state!.getObjectMetadata(ctx.bucketName!, ctx.key);
  if (metadata?.isDeleteMarker) {
    return sendS3Error(ctx.reply, 'NoSuchKey', 'The specified key does not exist.', 404, ctx.requestId);
  }
  const condition = objectSemantics.evaluateObjectConditions(ctx.headers, metadata);
  if (condition.status === 304) return ctx.reply.status(304).header('x-amz-request-id', ctx.requestId).send();
  if (condition.status === 412) return sendS3Error(ctx.reply, 'PreconditionFailed', 'At least one of the preconditions you specified did not hold', 412, ctx.requestId);

  if (metadata?.bodyPath) {
    return await handleGetStoredObject(ctx, metadata);
  }

  const result = await ctx.blobStore!.getObject(ctx.bucket!, ctx.key, ctx.headers['range']);
  const overrideHeaders = responseOverrideHeaders(ctx.query);
  return ctx.reply
    .status(result.statusCode)
    .headers({ ...result.headers, ...objectSemantics.metadataHeaders(metadata), ...overrideHeaders, 'x-amz-request-id': ctx.requestId })
    .send(result.body);
}

async function handleHeadObject(ctx: S3RequestContext) {
  const versionId = ctx.query.versionId;
  if (versionId) return await handleHeadObjectVersion(ctx, versionId);

  const metadata = await ctx.state!.getObjectMetadata(ctx.bucketName!, ctx.key);
  if (metadata?.isDeleteMarker) {
    return sendS3Error(ctx.reply, 'NoSuchKey', 'The specified key does not exist.', 404, ctx.requestId);
  }
  const condition = objectSemantics.evaluateObjectConditions(ctx.headers, metadata);
  if (condition.status === 304) return ctx.reply.status(304).header('x-amz-request-id', ctx.requestId).send();
  if (condition.status === 412) return sendS3Error(ctx.reply, 'PreconditionFailed', 'At least one of the preconditions you specified did not hold', 412, ctx.requestId);

  if (metadata?.bodyPath) {
    return ctx.reply.status(200).headers({ ...objectSemantics.metadataHeaders(metadata), 'x-amz-request-id': ctx.requestId }).send();
  }

  const result = await ctx.blobStore!.headObject(ctx.bucket!, ctx.key);
  return ctx.reply.status(result.statusCode).headers({ ...result.headers, ...objectSemantics.metadataHeaders(metadata), 'x-amz-request-id': ctx.requestId }).send();
}

async function handlePutObject(ctx: S3RequestContext) {
  const body = objectSemantics.decodeStreamingPayloadIfNeeded(ctx.headers, ctx.req.body);
  const contentLength = body.length || (ctx.headers['content-length'] ? parseInt(ctx.headers['content-length'], 10) : undefined);
  const checksumError = objectSemantics.validateChecksums(ctx.headers, body);
  if (checksumError) return sendS3Error(ctx.reply, checksumError.code, checksumError.message, 400, ctx.requestId);

  const bucketState = await ctx.state!.getBucketState(ctx.bucketName!);
  const existing = await ctx.state!.getObjectMetadata(ctx.bucketName!, ctx.key);
  if (objectSemantics.isObjectLocked(existing)) return sendS3Error(ctx.reply, 'AccessDenied', 'Object is protected by Object Lock', 403, ctx.requestId);
  const condition = objectSemantics.evaluateObjectConditions(ctx.headers, existing?.isDeleteMarker ? null : existing);
  if (condition.status === 412) return sendS3Error(ctx.reply, 'PreconditionFailed', 'At least one of the preconditions you specified did not hold', 412, ctx.requestId);

  const result = await putObjectBody(ctx, ctx.key, body, contentLength);
  const versionId = bucketState.versioning === 'Enabled' ? objectSemantics.createVersionId(ctx.bucketName!, ctx.key) : undefined;
  const metadata = {
    ...objectSemantics.buildObjectMetadata({
      bucket: ctx.bucketName!,
      key: ctx.key,
      headers: ctx.headers,
      etag: result.etag,
      size: body.length,
      tagging: existing?.isDeleteMarker
        ? objectSemantics.parseTaggingHeader(ctx.headers['x-amz-tagging'])
        : existing?.tagging ?? objectSemantics.parseTaggingHeader(ctx.headers['x-amz-tagging']),
      versionId,
    }),
    bodyPath: result.bodyPath,
  };
  await ctx.state!.putObjectMetadata(metadata);
  if (versionId) {
    const bodyPath = result.bodyPath ?? ctx.state!.versionBodyPath(ctx.bucketName!, ctx.key, versionId);
    if (!result.bodyPath) {
      await ctx.blobStore!.ensurePath(bodyPath.slice(0, bodyPath.lastIndexOf('/')));
      await ctx.blobStore!.putRaw(bodyPath, body, body.length);
    }
    await ctx.state!.putObjectVersion({ ...metadata, versionId, isLatest: true, bodyPath });
  }
  return ctx.reply
    .status(200)
    .header('etag', result.etag)
    .headers(versionId ? { 'x-amz-version-id': versionId } : {})
    .header('x-amz-request-id', ctx.requestId)
    .send();
}

interface PutObjectBodyResult {
  etag: string;
  bodyPath?: string;
}

async function putObjectBody(
  ctx: S3RequestContext,
  key: string,
  body: Buffer,
  contentLength?: number,
): Promise<PutObjectBodyResult> {
  if (!ctx.state!.listObjectMetadata) {
    return ctx.blobStore!.putObject(ctx.bucket!, key, body, contentLength);
  }

  const bodyPath = objectSemantics.contentAddressedBlobPath(body);
  await ctx.blobStore!.ensurePath(bodyPath.slice(0, bodyPath.lastIndexOf('/')));
  const resp = await ctx.blobStore!.putRaw(bodyPath, body, contentLength);
  if (![200, 201, 204].includes(resp.statusCode)) {
    throw new S3OperationError('InternalError', `Blob write failed: ${resp.statusCode}`, 500);
  }
  return { etag: objectSemantics.createContentEtag(body), bodyPath };
}

async function handleGetStoredObject(ctx: S3RequestContext, metadata: ObjectMetadataState) {
  const resp = await ctx.blobStore!.getRaw(metadata.bodyPath!, ctx.headers['range']);
  if (resp.statusCode === 404) return sendS3Error(ctx.reply, 'NoSuchKey', 'The specified key does not exist.', 404, ctx.requestId);
  if (resp.statusCode >= 400) return sendS3Error(ctx.reply, 'InternalError', `Blob read failed: ${resp.statusCode}`, 500, ctx.requestId);

  const overrideHeaders = responseOverrideHeaders(ctx.query);
  const rawHeaders = rawBlobResponseHeaders(resp);
  const statusCode = ctx.headers['range'] && resp.statusCode === 206 ? 206 : 200;
  return ctx.reply
    .status(statusCode)
    .headers({ ...objectSemantics.metadataHeaders(metadata), ...rawHeaders, ...overrideHeaders, 'x-amz-request-id': ctx.requestId })
    .send(resp.body);
}

function rawBlobResponseHeaders(resp: { headers: Record<string, string>; body: Buffer }): Record<string, string> {
  return {
    'content-length': resp.headers['content-length'] ?? String(resp.body.length),
    ...(resp.headers['content-range'] ? { 'content-range': resp.headers['content-range'] } : {}),
    ...(resp.headers['accept-ranges'] ? { 'accept-ranges': resp.headers['accept-ranges'] } : {}),
  };
}

async function handlePostPolicyUpload(ctx: S3RequestContext) {
  const form = parsePostPolicyForm(ctx.req.body);
  const key = form.fields.key;
  if (!key) return sendS3Error(ctx.reply, 'InvalidArgument', 'POST policy upload requires key field', 400, ctx.requestId);
  if (!form.file) return sendS3Error(ctx.reply, 'InvalidArgument', 'POST policy upload requires file field', 400, ctx.requestId);

  const result = await putObjectBody(ctx, key, form.file.body, form.file.body.length);
  await ctx.state!.putObjectMetadata({
    ...objectSemantics.buildObjectMetadata({
      bucket: ctx.bucketName!,
      key,
      headers: ctx.headers,
      etag: result.etag,
      size: form.file.body.length,
      tagging: objectSemantics.parseTaggingHeader(form.fields.tagging),
    }),
    bodyPath: result.bodyPath,
  });
  const status = form.fields.success_action_status ? Number(form.fields.success_action_status) : 204;
  if (status === 201) {
    return sendXml(ctx, 201, postPolicyUploadXml(ctx.bucketName!, key, result.etag));
  }
  return ctx.reply.status(Number.isFinite(status) ? status : 204).header('etag', result.etag).header('x-amz-request-id', ctx.requestId).send();
}

async function handleDeleteObject(ctx: S3RequestContext) {
  const versionId = ctx.query.versionId;
  if (versionId) {
    const version = await ctx.state!.getObjectVersion(ctx.bucketName!, ctx.key, versionId);
    if (objectSemantics.isObjectLocked(version)) return sendS3Error(ctx.reply, 'AccessDenied', 'Object is protected by Object Lock', 403, ctx.requestId);

    await ctx.state!.deleteObjectVersion(ctx.bucketName!, ctx.key, versionId);
    const current = await ctx.state!.getObjectMetadata(ctx.bucketName!, ctx.key);
    if (version && !current && !ctx.state!.listObjectMetadata) {
      await ctx.blobStore!.deleteObject(ctx.bucket!, ctx.key);
    }

    return ctx.reply
      .status(204)
      .headers({
        ...(version?.isDeleteMarker ? { 'x-amz-delete-marker': 'true' } : {}),
        'x-amz-version-id': versionId,
        'x-amz-request-id': ctx.requestId,
      })
      .send();
  }

  const bucketState = await ctx.state!.getBucketState(ctx.bucketName!);
  const existing = await ctx.state!.getObjectMetadata(ctx.bucketName!, ctx.key);
  if (objectSemantics.isObjectLocked(existing)) return sendS3Error(ctx.reply, 'AccessDenied', 'Object is protected by Object Lock', 403, ctx.requestId);
  if (bucketState.versioning === 'Enabled') {
    const deleteMarkerVersionId = objectSemantics.createVersionId(ctx.bucketName!, `${ctx.key}:delete`);
    const marker: ObjectVersionState = {
      bucket: ctx.bucketName!,
      key: ctx.key,
      etag: '',
      size: 0,
      lastModified: new Date().toISOString(),
      contentType: 'application/octet-stream',
      userMetadata: {},
      tagging: {},
      versionId: deleteMarkerVersionId,
      isLatest: true,
      isDeleteMarker: true,
    };
    await ctx.state!.putObjectMetadata(marker);
    await ctx.state!.putObjectVersion(marker);
    return ctx.reply
      .status(204)
      .header('x-amz-delete-marker', 'true')
      .header('x-amz-version-id', deleteMarkerVersionId)
      .header('x-amz-request-id', ctx.requestId)
      .send();
  }

  if (!existing?.bodyPath) {
    await ctx.blobStore!.deleteObject(ctx.bucket!, ctx.key);
  }
  await ctx.state!.deleteObjectMetadata(ctx.bucketName!, ctx.key);
  return ctx.reply.status(204).header('x-amz-request-id', ctx.requestId).send();
}

async function handleDeleteObjects(ctx: S3RequestContext) {
  const keys = objectSemantics.parseDeleteObjectsBody(await objectSemantics.requestBodyText(ctx.req.body));
  const bucketState = await ctx.state!.getBucketState(ctx.bucketName!);
  const deleted: Array<{ key: string; versionId?: string; deleteMarker?: boolean }> = [];
  const errors: Array<{ key: string; code: string; message: string }> = [];

  for (const key of keys) {
    const existing = await ctx.state!.getObjectMetadata(ctx.bucketName!, key);
    if (objectSemantics.isObjectLocked(existing)) {
      errors.push({ key, code: 'AccessDenied', message: 'Object is protected by Object Lock' });
      continue;
    }

    if (bucketState.versioning === 'Enabled') {
      const deleteMarkerVersionId = objectSemantics.createVersionId(ctx.bucketName!, `${key}:delete`);
      const marker: ObjectVersionState = {
        bucket: ctx.bucketName!,
        key,
        etag: '',
        size: 0,
        lastModified: new Date().toISOString(),
        contentType: 'application/octet-stream',
        userMetadata: {},
        tagging: {},
        versionId: deleteMarkerVersionId,
        isLatest: true,
        isDeleteMarker: true,
      };
      await ctx.state!.putObjectMetadata(marker);
      await ctx.state!.putObjectVersion(marker);
      deleted.push({ key, versionId: deleteMarkerVersionId, deleteMarker: true });
      continue;
    }

    try {
      if (!existing?.bodyPath) {
        await ctx.blobStore!.deleteObject(ctx.bucket!, key);
      }
      await ctx.state!.deleteObjectMetadata(ctx.bucketName!, key);
      deleted.push({ key });
    } catch (err) {
      errors.push({ key, code: 'InternalError', message: String(err) });
    }
  }

  return sendXml(ctx, 200, deleteObjectsXml(deleted, errors));
}

async function handleCopyObject(ctx: S3RequestContext) {
  const sourceHeader = ctx.headers['x-amz-copy-source'];
  if (!sourceHeader) return sendS3Error(ctx.reply, 'InvalidRequest', 'Missing x-amz-copy-source header', 400, ctx.requestId);
  const sourcePath = sourceHeader.replace(/^\//, '');
  const parts = sourcePath.split('/');
  const sourceBucket = decodeURIComponent(parts[0]);
  const sourceKey = parts.slice(1).map(decodeURIComponent).join('/');
  const sourceTenant = findTenantByBucket(ctx.registry, sourceBucket);
  const sourceBucketBinding = sourceTenant?.buckets.get(sourceBucket);
  const sourceUpstream = sourceBucketBinding ? sourceTenant?.upstreams.get(sourceBucketBinding.upstreamId) : undefined;
  if (!sourceTenant || !sourceBucketBinding || !sourceUpstream) {
    return sendS3Error(ctx.reply, 'NoSuchBucket', 'The source bucket does not exist', 404, ctx.requestId);
  }

  const sourceBackend = sourceBucket === ctx.bucket!.name ? undefined : ctx.storageBackendFactory.getBackend(sourceUpstream);
  const sourceBlobStore = sourceBucket === ctx.bucket!.name ? ctx.blobStore! : sourceBackend!.blobStore;
  const sourceState = sourceBucket === ctx.bucket!.name ? ctx.state! : sourceBackend!.metadataStore;
  const sourceMetadata = await sourceState.getObjectMetadata(sourceBucket, sourceKey);
  const condition = objectSemantics.evaluateCopySourceConditions(ctx.headers, sourceMetadata);
  if (condition.status === 412) return sendS3Error(ctx.reply, 'PreconditionFailed', 'At least one of the preconditions you specified did not hold', 412, ctx.requestId);

  let result: { etag: string; bodyPath?: string };
  let sourceSize = sourceMetadata?.size ?? 0;
  if (sourceMetadata?.bodyPath && sourceBlobStore === ctx.blobStore && ctx.state!.listObjectMetadata) {
    result = { etag: sourceMetadata.etag, bodyPath: sourceMetadata.bodyPath };
    sourceSize = sourceMetadata.size;
  } else {
    const sourceBody = sourceMetadata?.bodyPath
      ? (await sourceBlobStore.getRaw(sourceMetadata.bodyPath)).body
      : await objectSemantics.readableToBuffer((await sourceBlobStore.getObject(sourceBucketBinding, sourceKey)).body);
    sourceSize = sourceBody.length;
    result = await putObjectBody(ctx, ctx.key, sourceBody, sourceBody.length);
  }
  const directive = ctx.headers['x-amz-metadata-directive']?.toUpperCase();
  const taggingDirective = ctx.headers['x-amz-tagging-directive']?.toUpperCase();
  const metadata = {
    ...objectSemantics.buildObjectMetadata({
      bucket: ctx.bucketName!,
      key: ctx.key,
      headers: ctx.headers,
      etag: result.etag,
      size: sourceSize,
      tagging: taggingDirective === 'REPLACE' ? objectSemantics.parseTaggingHeader(ctx.headers['x-amz-tagging']) : sourceMetadata?.tagging ?? {},
      source: directive === 'REPLACE' ? undefined : sourceMetadata ?? undefined,
    }),
    bodyPath: result.bodyPath,
  };
  await ctx.state!.putObjectMetadata(metadata);
  return ctx.reply.status(200).headers(XML_HEADERS).send(copyObjectXml({ etag: result.etag, lastModified: metadata.lastModified }));
}

async function handleListObjects(ctx: S3RequestContext) {
  const params = {
    prefix: ctx.query.prefix,
    delimiter: ctx.query.delimiter,
    maxKeys: ctx.query['max-keys'] ? parseInt(ctx.query['max-keys'], 10) : undefined,
    continuationToken: ctx.query['continuation-token'] ?? ctx.query.marker,
  };
  const result = ctx.state!.listObjectMetadata
    ? {
      name: ctx.bucket!.name,
      prefix: params.prefix ?? '',
      maxKeys: Math.min(params.maxKeys ?? 1000, 1000),
      keyCount: 0,
      ...(await ctx.state!.listObjectMetadata(ctx.bucketName!, params)),
    }
    : await ctx.blobStore!.listObjects(ctx.bucket!, params);
  result.keyCount = result.contents.length;
  return ctx.reply.status(200).headers(XML_HEADERS).send(listObjectsV2Xml(result));
}

async function handleListObjectVersions(ctx: S3RequestContext) {
  const versions = await ctx.state!.listObjectVersions(ctx.bucketName!);
  return sendXml(ctx, 200, versionsXml(ctx.bucketName!, versions));
}

async function handleGetObjectVersion(ctx: S3RequestContext, versionId: string) {
  const version = await ctx.state!.getObjectVersion(ctx.bucketName!, ctx.key, versionId);
  if (!version) return sendS3Error(ctx.reply, 'NoSuchVersion', 'The specified version does not exist.', 404, ctx.requestId);
  if (version.isDeleteMarker) {
    return ctx.reply
      .status(405)
      .headers({ ...objectSemantics.metadataHeaders(version), 'x-amz-delete-marker': 'true', 'x-amz-version-id': version.versionId, 'x-amz-request-id': ctx.requestId })
      .send();
  }
  const bodyPath = version.bodyPath ?? ctx.state!.versionBodyPath(ctx.bucketName!, ctx.key, versionId);
  const resp = await ctx.blobStore!.getRaw(bodyPath, ctx.headers['range']);
  if (resp.statusCode >= 400) return sendS3Error(ctx.reply, 'NoSuchVersion', 'The specified version body does not exist.', 404, ctx.requestId);
  const rawHeaders = rawBlobResponseHeaders(resp);
  const statusCode = ctx.headers['range'] && resp.statusCode === 206 ? 206 : 200;
  return ctx.reply
    .status(statusCode)
    .headers({ ...objectSemantics.metadataHeaders(version), ...rawHeaders, 'x-amz-version-id': version.versionId, 'x-amz-request-id': ctx.requestId })
    .send(resp.body);
}

async function handleHeadObjectVersion(ctx: S3RequestContext, versionId: string) {
  const version = await ctx.state!.getObjectVersion(ctx.bucketName!, ctx.key, versionId);
  if (!version) return sendS3Error(ctx.reply, 'NoSuchVersion', 'The specified version does not exist.', 404, ctx.requestId);
  if (version.isDeleteMarker) {
    return ctx.reply
      .status(405)
      .headers({ ...objectSemantics.metadataHeaders(version), 'x-amz-delete-marker': 'true', 'x-amz-version-id': version.versionId, 'x-amz-request-id': ctx.requestId })
      .send();
  }
  return ctx.reply
    .status(200)
    .headers({ ...objectSemantics.metadataHeaders(version), 'x-amz-version-id': version.versionId, 'x-amz-request-id': ctx.requestId })
    .send();
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
  const body = await objectSemantics.requestBodyText(ctx.req.body);
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
  const body = await objectSemantics.requestBodyText(ctx.req.body);
  (state as unknown as Record<string, unknown>)[key] = body ? objectSemantics.safeJsonParse(body) ?? body : {};
  await ctx.state!.putBucketState(state);
  return sendEmpty(ctx, 200);
}

async function handlePutXmlControl(ctx: S3RequestContext, key: keyof BucketState) {
  const state = await ctx.state!.getBucketState(ctx.bucketName!);
  (state as unknown as Record<string, unknown>)[key] = await objectSemantics.requestBodyText(ctx.req.body);
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
  const value = state[key];
  if (typeof value === 'string' && value.trim()) return sendXml(ctx, 200, value);
  return sendXml(ctx, 200, fallbackXml);
}

async function handleGetBucketTagging(ctx: S3RequestContext) {
  const state = await ctx.state!.getBucketState(ctx.bucketName!);
  return sendXml(ctx, 200, taggingXml(state.tagging ?? {}));
}

async function handlePutBucketTagging(ctx: S3RequestContext) {
  const state = await ctx.state!.getBucketState(ctx.bucketName!);
  state.tagging = objectSemantics.parseTaggingXml(await objectSemantics.requestBodyText(ctx.req.body));
  await ctx.state!.putBucketState(state);
  return sendEmpty(ctx, 200);
}

async function handleGetObjectTagging(ctx: S3RequestContext) {
  const metadata = await ctx.state!.getObjectMetadata(ctx.bucketName!, ctx.key);
  return sendXml(ctx, 200, taggingXml(metadata?.tagging ?? {}));
}

async function handlePutObjectTagging(ctx: S3RequestContext) {
  const metadata = await requireObjectMetadata(ctx);
  if (!metadata) return;
  metadata.tagging = objectSemantics.parseTaggingXml(await objectSemantics.requestBodyText(ctx.req.body));
  await ctx.state!.putObjectMetadata(metadata);
  return sendEmpty(ctx, 200);
}

async function handleDeleteObjectTagging(ctx: S3RequestContext) {
  const metadata = await requireObjectMetadata(ctx);
  if (!metadata) return;
  metadata.tagging = {};
  await ctx.state!.putObjectMetadata(metadata);
  return sendEmpty(ctx, 204);
}

async function handleGetObjectLegalHold(ctx: S3RequestContext) {
  const metadata = await requireObjectMetadata(ctx);
  if (!metadata) return;
  return sendXml(ctx, 200, legalHoldXml(metadata.objectLock?.legalHold ?? 'OFF'));
}

async function handlePutObjectLegalHold(ctx: S3RequestContext) {
  const metadata = await requireObjectMetadata(ctx);
  if (!metadata) return;
  const body = await objectSemantics.requestBodyText(ctx.req.body);
  metadata.objectLock = {
    ...(metadata.objectLock ?? {}),
    legalHold: body.includes('<Status>ON</Status>') ? 'ON' : 'OFF',
  };
  await ctx.state!.putObjectMetadata(metadata);
  return sendEmpty(ctx, 200);
}

async function handleGetObjectRetention(ctx: S3RequestContext) {
  const metadata = await requireObjectMetadata(ctx);
  if (!metadata) return;
  return sendXml(ctx, 200, retentionXml(metadata.objectLock?.mode, metadata.objectLock?.retainUntilDate));
}

async function handlePutObjectRetention(ctx: S3RequestContext) {
  const metadata = await requireObjectMetadata(ctx);
  if (!metadata) return;
  const body = await objectSemantics.requestBodyText(ctx.req.body);
  metadata.objectLock = {
    ...(metadata.objectLock ?? {}),
    mode: objectSemantics.extractXmlValue(body, 'Mode') ?? metadata.objectLock?.mode ?? 'GOVERNANCE',
    retainUntilDate: objectSemantics.extractXmlValue(body, 'RetainUntilDate') ?? metadata.objectLock?.retainUntilDate,
  };
  await ctx.state!.putObjectMetadata(metadata);
  return sendEmpty(ctx, 200);
}

async function handleCreateMultipartUpload(ctx: S3RequestContext) {
  const state = await ctx.state!.createMultipartUpload({
    bucket: ctx.bucketName!,
    key: ctx.key,
    contentType: ctx.headers['content-type'],
    metadata: objectSemantics.collectUserMetadata(ctx.headers),
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
  const body = objectSemantics.toBuffer(ctx.req.body);
  const path = ctx.state!.multipartPartPath(ctx.bucketName!, uploadId, partNumber);
  await ctx.blobStore!.ensurePath(path.slice(0, path.lastIndexOf('/')));
  const resp = await ctx.blobStore!.putRaw(path, body, body.length);
  if (![200, 201, 204].includes(resp.statusCode)) {
    return sendS3Error(ctx.reply, 'InternalError', `UploadPart failed: ${resp.statusCode}`, 500, ctx.requestId);
  }
  const etag = `"${objectSemantics.createWeakEtag(body)}"`;
  state.parts = state.parts.filter((part) => part.partNumber !== partNumber).concat({ partNumber, etag, size: body.length, path });
  state.parts.sort((a, b) => a.partNumber - b.partNumber);
  await ctx.state!.putMultipartUpload(state);
  return ctx.reply.status(200).header('etag', etag).header('x-amz-request-id', ctx.requestId).send();
}

async function handleCompleteMultipartUpload(ctx: S3RequestContext) {
  const uploadId = ctx.query.uploadId!;
  const state = await requireMultipart(ctx, uploadId);
  if (!state) return;
  const requestedParts = objectSemantics.parseCompleteMultipartBody(await objectSemantics.requestBodyText(ctx.req.body));
  const parts = requestedParts.length > 0
    ? requestedParts.map((partNumber) => state.parts.find((part) => part.partNumber === partNumber)).filter(Boolean)
    : state.parts;
  if (parts.length === 0 || parts.length !== (requestedParts.length || state.parts.length)) {
    return sendS3Error(ctx.reply, 'InvalidPart', 'One or more of the specified parts could not be found', 400, ctx.requestId);
  }
  const buffers: Buffer[] = [];
  for (const part of parts) {
    const resp = await ctx.blobStore!.getRaw(part!.path);
    if (resp.statusCode >= 400) return sendS3Error(ctx.reply, 'InvalidPart', `Part ${part!.partNumber} is not readable`, 400, ctx.requestId);
    buffers.push(resp.body);
  }
  const finalBody = Buffer.concat(buffers);
  const result = await putObjectBody(ctx, ctx.key, finalBody, finalBody.length);
  const bucketState = await ctx.state!.getBucketState(ctx.bucketName!);
  const existing = await ctx.state!.getObjectMetadata(ctx.bucketName!, ctx.key);
  const versionId = bucketState.versioning === 'Enabled' ? objectSemantics.createVersionId(ctx.bucketName!, ctx.key) : undefined;
  const metadata: ObjectMetadataState = {
    bucket: ctx.bucketName!,
    key: ctx.key,
    etag: result.etag,
    size: finalBody.length,
    lastModified: new Date().toISOString(),
    contentType: state.contentType ?? 'application/octet-stream',
    userMetadata: state.metadata ?? {},
    tagging: existing?.isDeleteMarker ? {} : existing?.tagging ?? {},
    versionId,
    bodyPath: result.bodyPath,
  };
  await ctx.state!.putObjectMetadata(metadata);
  if (versionId) {
    const bodyPath = result.bodyPath ?? ctx.state!.versionBodyPath(ctx.bucketName!, ctx.key, versionId);
    if (!result.bodyPath) {
      await ctx.blobStore!.ensurePath(bodyPath.slice(0, bodyPath.lastIndexOf('/')));
      await ctx.blobStore!.putRaw(bodyPath, finalBody, finalBody.length);
    }
    await ctx.state!.putObjectVersion({ ...metadata, versionId, isLatest: true, bodyPath });
  }
  await cleanupMultipartPartBlobs(ctx, state.parts);
  await ctx.state!.deleteMultipartUpload(ctx.bucketName!, uploadId);
  return sendXml(ctx, 200, completeMultipartUploadXml(ctx.bucketName!, ctx.key, result.etag));
}

async function handleAbortMultipartUpload(ctx: S3RequestContext) {
  const uploadId = ctx.query.uploadId!;
  const state = await requireMultipart(ctx, uploadId);
  if (!state) return;
  await cleanupMultipartPartBlobs(ctx, state.parts);
  await ctx.state!.deleteMultipartUpload(ctx.bucketName!, uploadId);
  return sendEmpty(ctx, 204);
}

async function handleListParts(ctx: S3RequestContext) {
  const uploadId = ctx.query.uploadId!;
  const state = await requireMultipart(ctx, uploadId);
  if (!state) return;
  return sendXml(ctx, 200, listPartsXml(ctx.bucketName!, ctx.key, uploadId, state));
}

async function cleanupMultipartPartBlobs(ctx: S3RequestContext, parts: Array<{ path: string }>): Promise<void> {
  for (const part of parts) {
    await ctx.blobStore!.deleteRaw(part.path).catch(() => undefined);
  }
}

async function requireMultipart(ctx: S3RequestContext, uploadId: string): Promise<MultipartUploadState | null> {
  const state = await ctx.state!.getMultipartUpload(ctx.bucketName!, uploadId);
  if (!state || state.key !== ctx.key) {
    await sendS3Error(ctx.reply, 'NoSuchUpload', 'The specified multipart upload does not exist', 404, ctx.requestId);
    return null;
  }
  return state;
}

async function requireObjectMetadata(ctx: S3RequestContext): Promise<ObjectMetadataState | null> {
  const metadata = await ctx.state!.getObjectMetadata(ctx.bucketName!, ctx.key);
  if (metadata) return metadata;
  try {
    const head = await ctx.blobStore!.headObject(ctx.bucket!, ctx.key);
    return {
      bucket: ctx.bucketName!,
      key: ctx.key,
      etag: head.headers.etag ?? '',
      size: Number(head.headers['content-length'] ?? 0),
      lastModified: head.headers['last-modified'] ?? new Date().toISOString(),
      contentType: head.headers['content-type'] ?? 'application/octet-stream',
      userMetadata: {},
      tagging: {},
    };
  } catch {
    sendS3Error(ctx.reply, 'NoSuchKey', 'The specified key does not exist.', 404, ctx.requestId);
    return null;
  }
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

  const result = verifySigV4({
    method,
    pathname,
    queryString,
    headers,
    body: null,
    secretAccessKey: tenant.secretAccessKey,
    sessionToken: tenant.sessionToken,
  });
  if (!result.ok) return { ok: false, code: result.code, message: result.message };
  return { ok: true, accessKey };
}

function authenticatePostPolicyRequest(ctx: S3RequestContext, registry: TenantRegistry): AuthResult {
  const fields = parsePostPolicyFields(ctx.req.body);
  const accessKey = extractPostPolicyAccessKey(fields);
  if (!accessKey) return { ok: false, code: 'AccessDenied', message: 'Missing POST policy credential' };

  const tenant = registry.findByAccessKey(accessKey);
  if (!tenant) {
    return { ok: false, code: 'InvalidAccessKeyId', message: 'The AWS Access Key Id you provided does not exist in our records.' };
  }

  const result = verifyPostPolicySigV4({
    fields,
    secretAccessKey: tenant.secretAccessKey,
    sessionToken: tenant.sessionToken,
  });
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

function isPostPolicyUpload(ctx: S3RequestContext): boolean {
  const body = objectSemantics.toBuffer(ctx.req.body).toString('utf-8').toLowerCase();
  return ctx.headers['content-type']?.toLowerCase().includes('multipart/form-data') === true && body.includes('x-amz-credential');
}

function parsePostPolicyFields(body: unknown): Record<string, string | undefined> {
  return parsePostPolicyForm(body).fields;
}

function parsePostPolicyForm(body: unknown): { fields: Record<string, string>; file?: { filename?: string; body: Buffer } } {
  const buffer = objectSemantics.toBuffer(body);
  const fields: Record<string, string> = {};
  const marker = Buffer.from('\r\n\r\n');
  const segments = buffer.toString('binary').split(/\r\n--[^\r\n]+/g);

  for (const segment of segments) {
    const part = Buffer.from(segment, 'binary');
    const markerIndex = part.indexOf(marker);
    if (markerIndex === -1) continue;
    const rawHeaders = part.slice(0, markerIndex).toString('utf-8');
    const content = trimMultipartPartBody(part.slice(markerIndex + marker.length));
    const name = rawHeaders.match(/name="([^"]+)"/)?.[1];
    if (!name) continue;
    const filename = rawHeaders.match(/filename="([^"]*)"/)?.[1];
    if (filename !== undefined || name === 'file') {
      return { fields, file: { filename, body: content } };
    }
    fields[name] = content.toString('utf-8');
  }

  return { fields };
}

function trimMultipartPartBody(body: Buffer): Buffer {
  let end = body.length;
  while (end > 0 && (body[end - 1] === 10 || body[end - 1] === 13 || body[end - 1] === 45)) end -= 1;
  return body.slice(0, end);
}

function deleteObjectsXml(
  deleted: Array<{ key: string; versionId?: string; deleteMarker?: boolean }>,
  errors: Array<{ key: string; code: string; message: string }>,
): string {
  const deletedXml = deleted.map((item) => [
    '  <Deleted>',
    `    <Key>${escapeXml(item.key)}</Key>`,
    item.versionId ? `    <VersionId>${escapeXml(item.versionId)}</VersionId>` : '',
    item.deleteMarker ? '    <DeleteMarker>true</DeleteMarker>' : '',
    '  </Deleted>',
  ].filter(Boolean).join('\n')).join('\n');
  const errorsXml = errors.map((item) => [
    '  <Error>',
    `    <Key>${escapeXml(item.key)}</Key>`,
    `    <Code>${escapeXml(item.code)}</Code>`,
    `    <Message>${escapeXml(item.message)}</Message>`,
    '  </Error>',
  ].join('\n')).join('\n');
  const body = [deletedXml, errorsXml].filter(Boolean).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<DeleteResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
${body}
</DeleteResult>`;
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

function postPolicyUploadXml(bucket: string, key: string, etag: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<PostResponse>
  <Location>/${escapeXml(bucket)}/${escapeXml(key)}</Location>
  <Bucket>${escapeXml(bucket)}</Bucket>
  <Key>${escapeXml(key)}</Key>
  <ETag>${escapeXml(etag)}</ETag>
</PostResponse>`;
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

function multipartUploadsXml(bucket: string, uploads: MultipartUploadState[] = []): string {
  const uploadsXml = uploads.map((upload) => `  <Upload>
    <Key>${escapeXml(upload.key)}</Key>
    <UploadId>${escapeXml(upload.uploadId)}</UploadId>
    <StorageClass>STANDARD</StorageClass>
    <Initiated>${new Date(upload.initiatedAt).toISOString()}</Initiated>
  </Upload>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>${escapeXml(bucket)}</Bucket>
  <IsTruncated>false</IsTruncated>
${uploadsXml}
</ListMultipartUploadsResult>`;
}

function versioningXml(status: BucketState['versioning']): string {
  const statusXml = status === 'Off' ? '' : `\n  <Status>${status}</Status>`;
  return `<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">${statusXml}
</VersioningConfiguration>`;
}

function versionsXml(bucket: string, versions: ObjectVersionState[]): string {
  const entries = versions.map((version) => {
    const common = `
    <Key>${escapeXml(version.key)}</Key>
    <VersionId>${escapeXml(version.versionId)}</VersionId>
    <IsLatest>${version.isLatest ? 'true' : 'false'}</IsLatest>
    <LastModified>${new Date(version.lastModified).toISOString()}</LastModified>`;
    if (version.isDeleteMarker) {
      return `  <DeleteMarker>${common}
  </DeleteMarker>`;
    }
    return `  <Version>${common}
    <ETag>${escapeXml(version.etag)}</ETag>
    <Size>${version.size}</Size>
    <StorageClass>${escapeXml(version.storageClass ?? 'STANDARD')}</StorageClass>
  </Version>`;
  }).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>${escapeXml(bucket)}</Name>
  <IsTruncated>false</IsTruncated>
${entries}
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

function legalHoldXml(status: 'ON' | 'OFF'): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Status>${status}</Status>
</LegalHold>`;
}

function retentionXml(mode?: string, retainUntilDate?: string): string {
  const modeXml = mode ? `\n  <Mode>${escapeXml(mode)}</Mode>` : '';
  const dateXml = retainUntilDate ? `\n  <RetainUntilDate>${escapeXml(retainUntilDate)}</RetainUntilDate>` : '';
  return `<?xml version="1.0" encoding="UTF-8"?>
<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/">${modeXml}${dateXml}
</Retention>`;
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