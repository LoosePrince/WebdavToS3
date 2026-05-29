import { createHash } from 'node:crypto';
import { FastifyRequest, FastifyReply } from 'fastify';
import {
  verifySigV4,
  extractSigV4AccessKey,
  verifyPostPolicySigV4,
  extractPostPolicyAccessKey,
} from './auth/sigv4.js';
import { TenantRegistry, type BucketBinding, type Tenant } from '../tenancy/tenant-registry.js';
import { WebdavClient } from '../webdav/client.js';
import { parsePathStyleUrl } from '../utils/path-mapper.js';
import { S3ErrorResponse } from './errors.js';
import {
  getObject,
  putObject,
  headObject,
  deleteObject,
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
import { S3StateStore, type BucketState, type MultipartUploadState, type ObjectMetadataState, type ObjectVersionState } from './state/store.js';

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
  const condition = evaluateObjectConditions(ctx.headers, metadata);
  if (condition.status === 304) return ctx.reply.status(304).header('x-amz-request-id', ctx.requestId).send();
  if (condition.status === 412) return sendS3Error(ctx.reply, 'PreconditionFailed', 'At least one of the preconditions you specified did not hold', 412, ctx.requestId);

  const result = await getObject(ctx.client!, ctx.bucket!, ctx.key, ctx.headers['range']);
  const overrideHeaders = responseOverrideHeaders(ctx.query);
  return ctx.reply
    .status(result.statusCode)
    .headers({ ...result.headers, ...metadataHeaders(metadata), ...overrideHeaders, 'x-amz-request-id': ctx.requestId })
    .send(result.body);
}

async function handleHeadObject(ctx: S3RequestContext) {
  const versionId = ctx.query.versionId;
  if (versionId) return await handleHeadObjectVersion(ctx, versionId);

  const metadata = await ctx.state!.getObjectMetadata(ctx.bucketName!, ctx.key);
  if (metadata?.isDeleteMarker) {
    return sendS3Error(ctx.reply, 'NoSuchKey', 'The specified key does not exist.', 404, ctx.requestId);
  }
  const condition = evaluateObjectConditions(ctx.headers, metadata);
  if (condition.status === 304) return ctx.reply.status(304).header('x-amz-request-id', ctx.requestId).send();
  if (condition.status === 412) return sendS3Error(ctx.reply, 'PreconditionFailed', 'At least one of the preconditions you specified did not hold', 412, ctx.requestId);

  const result = await headObject(ctx.client!, ctx.bucket!, ctx.key);
  return ctx.reply.status(result.statusCode).headers({ ...result.headers, ...metadataHeaders(metadata), 'x-amz-request-id': ctx.requestId }).send();
}

async function handlePutObject(ctx: S3RequestContext) {
  const body = decodeStreamingPayloadIfNeeded(ctx.headers, ctx.req.body);
  const contentLength = body.length || (ctx.headers['content-length'] ? parseInt(ctx.headers['content-length'], 10) : undefined);
  const checksumError = validateChecksums(ctx.headers, body);
  if (checksumError) return sendS3Error(ctx.reply, checksumError.code, checksumError.message, 400, ctx.requestId);

  const bucketState = await ctx.state!.getBucketState(ctx.bucketName!);
  const existing = await ctx.state!.getObjectMetadata(ctx.bucketName!, ctx.key);
  if (isObjectLocked(existing)) return sendS3Error(ctx.reply, 'AccessDenied', 'Object is protected by Object Lock', 403, ctx.requestId);
  const condition = evaluateObjectConditions(ctx.headers, existing?.isDeleteMarker ? null : existing);
  if (condition.status === 412) return sendS3Error(ctx.reply, 'PreconditionFailed', 'At least one of the preconditions you specified did not hold', 412, ctx.requestId);

  const result = await putObject(ctx.client!, ctx.bucket!, ctx.key, body, contentLength);
  const versionId = bucketState.versioning === 'Enabled' ? createVersionId(ctx.bucketName!, ctx.key) : undefined;
  const metadata = buildObjectMetadata(ctx, result.etag, body.length, existing?.isDeleteMarker ? parseTaggingHeader(ctx.headers['x-amz-tagging']) : existing?.tagging ?? parseTaggingHeader(ctx.headers['x-amz-tagging']), undefined, versionId);
  await ctx.state!.putObjectMetadata(metadata);
  if (versionId) {
    const bodyPath = ctx.state!.versionBodyPath(ctx.bucketName!, ctx.key, versionId);
    await ctx.client!.ensureCollection(bodyPath.slice(0, bodyPath.lastIndexOf('/')));
    await ctx.client!.put(bodyPath, body, body.length);
    await ctx.state!.putObjectVersion({ ...metadata, versionId, isLatest: true, bodyPath });
  }
  return ctx.reply
    .status(200)
    .header('etag', result.etag)
    .headers(versionId ? { 'x-amz-version-id': versionId } : {})
    .header('x-amz-request-id', ctx.requestId)
    .send();
}

async function handlePostPolicyUpload(ctx: S3RequestContext) {
  const form = parsePostPolicyForm(ctx.req.body);
  const key = form.fields.key;
  if (!key) return sendS3Error(ctx.reply, 'InvalidArgument', 'POST policy upload requires key field', 400, ctx.requestId);
  if (!form.file) return sendS3Error(ctx.reply, 'InvalidArgument', 'POST policy upload requires file field', 400, ctx.requestId);

  const result = await putObject(ctx.client!, ctx.bucket!, key, form.file.body, form.file.body.length);
  await ctx.state!.putObjectMetadata(buildObjectMetadata({ ...ctx, key }, result.etag, form.file.body.length, parseTaggingHeader(form.fields.tagging)));
  const status = form.fields.success_action_status ? Number(form.fields.success_action_status) : 204;
  if (status === 201) {
    return sendXml(ctx, 201, postPolicyUploadXml(ctx.bucketName!, key, result.etag));
  }
  return ctx.reply.status(Number.isFinite(status) ? status : 204).header('etag', result.etag).header('x-amz-request-id', ctx.requestId).send();
}

async function handleDeleteObject(ctx: S3RequestContext) {
  const versionId = ctx.query.versionId;
  if (versionId) {
    await ctx.state!.deleteObjectVersion(ctx.bucketName!, ctx.key, versionId);
    return ctx.reply.status(204).header('x-amz-version-id', versionId).header('x-amz-request-id', ctx.requestId).send();
  }

  const bucketState = await ctx.state!.getBucketState(ctx.bucketName!);
  const existing = await ctx.state!.getObjectMetadata(ctx.bucketName!, ctx.key);
  if (isObjectLocked(existing)) return sendS3Error(ctx.reply, 'AccessDenied', 'Object is protected by Object Lock', 403, ctx.requestId);
  if (bucketState.versioning === 'Enabled') {
    const deleteMarkerVersionId = createVersionId(ctx.bucketName!, `${ctx.key}:delete`);
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

  await deleteObject(ctx.client!, ctx.bucket!, ctx.key);
  await ctx.state!.deleteObjectMetadata(ctx.bucketName!, ctx.key);
  return ctx.reply.status(204).header('x-amz-request-id', ctx.requestId).send();
}

async function handleDeleteObjects(ctx: S3RequestContext) {
  const keys = parseDeleteObjectsBody(await requestBodyText(ctx.req.body));
  const bucketState = await ctx.state!.getBucketState(ctx.bucketName!);
  const deleted: Array<{ key: string; versionId?: string; deleteMarker?: boolean }> = [];
  const errors: Array<{ key: string; code: string; message: string }> = [];

  for (const key of keys) {
    const existing = await ctx.state!.getObjectMetadata(ctx.bucketName!, key);
    if (isObjectLocked(existing)) {
      errors.push({ key, code: 'AccessDenied', message: 'Object is protected by Object Lock' });
      continue;
    }

    if (bucketState.versioning === 'Enabled') {
      const deleteMarkerVersionId = createVersionId(ctx.bucketName!, `${key}:delete`);
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
      await deleteObject(ctx.client!, ctx.bucket!, key);
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

  const sourceClient = sourceBucket === ctx.bucket!.name
    ? ctx.client!
    : new WebdavClient({
        endpoint: sourceUpstream.endpoint,
        username: sourceUpstream.username,
        password: sourceUpstream.password,
        rejectUnauthorized: sourceUpstream.rejectUnauthorized,
        connectTimeoutMs: sourceUpstream.connectTimeoutMs,
        requestTimeoutMs: sourceUpstream.requestTimeoutMs,
      });
  const sourceState = sourceBucket === ctx.bucket!.name ? ctx.state! : new S3StateStore(sourceClient);
  const sourceMetadata = await sourceState.getObjectMetadata(sourceBucket, sourceKey);
  const condition = evaluateCopySourceConditions(ctx.headers, sourceMetadata);
  if (condition.status === 412) return sendS3Error(ctx.reply, 'PreconditionFailed', 'At least one of the preconditions you specified did not hold', 412, ctx.requestId);

  const sourceObject = await getObject(sourceClient, sourceBucketBinding, sourceKey);
  const sourceBody = await readableToBuffer(sourceObject.body);
  const result = await putObject(ctx.client!, ctx.bucket!, ctx.key, sourceBody, sourceBody.length);
  const directive = ctx.headers['x-amz-metadata-directive']?.toUpperCase();
  const taggingDirective = ctx.headers['x-amz-tagging-directive']?.toUpperCase();
  const metadata = buildObjectMetadata(
    ctx,
    result.etag,
    sourceBody.length,
    taggingDirective === 'REPLACE' ? parseTaggingHeader(ctx.headers['x-amz-tagging']) : sourceMetadata?.tagging ?? {},
    directive === 'REPLACE' ? undefined : sourceMetadata ?? undefined,
  );
  await ctx.state!.putObjectMetadata(metadata);
  return ctx.reply.status(200).headers(XML_HEADERS).send(copyObjectXml({ etag: result.etag, lastModified: metadata.lastModified }));
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
      .headers({ ...metadataHeaders(version), 'x-amz-delete-marker': 'true', 'x-amz-version-id': version.versionId, 'x-amz-request-id': ctx.requestId })
      .send();
  }
  if (!version.bodyPath) return sendS3Error(ctx.reply, 'NoSuchVersion', 'The specified version body does not exist.', 404, ctx.requestId);
  const resp = await ctx.client!.get(version.bodyPath);
  if (resp.statusCode >= 400) return sendS3Error(ctx.reply, 'NoSuchVersion', 'The specified version body does not exist.', 404, ctx.requestId);
  return ctx.reply
    .status(200)
    .headers({ ...metadataHeaders(version), 'x-amz-version-id': version.versionId, 'x-amz-request-id': ctx.requestId })
    .send(resp.body);
}

async function handleHeadObjectVersion(ctx: S3RequestContext, versionId: string) {
  const version = await ctx.state!.getObjectVersion(ctx.bucketName!, ctx.key, versionId);
  if (!version) return sendS3Error(ctx.reply, 'NoSuchVersion', 'The specified version does not exist.', 404, ctx.requestId);
  if (version.isDeleteMarker) {
    return ctx.reply
      .status(405)
      .headers({ ...metadataHeaders(version), 'x-amz-delete-marker': 'true', 'x-amz-version-id': version.versionId, 'x-amz-request-id': ctx.requestId })
      .send();
  }
  return ctx.reply
    .status(200)
    .headers({ ...metadataHeaders(version), 'x-amz-version-id': version.versionId, 'x-amz-request-id': ctx.requestId })
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

async function handlePutXmlControl(ctx: S3RequestContext, key: keyof BucketState) {
  const state = await ctx.state!.getBucketState(ctx.bucketName!);
  (state as unknown as Record<string, unknown>)[key] = await requestBodyText(ctx.req.body);
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
  state.tagging = parseTaggingXml(await requestBodyText(ctx.req.body));
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
  metadata.tagging = parseTaggingXml(await requestBodyText(ctx.req.body));
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
  const body = await requestBodyText(ctx.req.body);
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
  const body = await requestBodyText(ctx.req.body);
  metadata.objectLock = {
    ...(metadata.objectLock ?? {}),
    mode: extractXmlValue(body, 'Mode') ?? metadata.objectLock?.mode ?? 'GOVERNANCE',
    retainUntilDate: extractXmlValue(body, 'RetainUntilDate') ?? metadata.objectLock?.retainUntilDate,
  };
  await ctx.state!.putObjectMetadata(metadata);
  return sendEmpty(ctx, 200);
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

async function requireObjectMetadata(ctx: S3RequestContext): Promise<ObjectMetadataState | null> {
  const metadata = await ctx.state!.getObjectMetadata(ctx.bucketName!, ctx.key);
  if (metadata) return metadata;
  try {
    const head = await headObject(ctx.client!, ctx.bucket!, ctx.key);
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

function collectUserMetadata(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers)
      .filter(([key]) => key.startsWith('x-amz-meta-'))
      .map(([key, value]) => [key.slice('x-amz-meta-'.length), value]),
  );
}

function buildObjectMetadata(
  ctx: S3RequestContext,
  etag: string,
  size: number,
  tagging: Record<string, string>,
  source?: ObjectMetadataState,
  versionId?: string,
): ObjectMetadataState {
  return {
    bucket: ctx.bucketName!,
    key: ctx.key,
    etag,
    size,
    lastModified: new Date().toISOString(),
    contentType: ctx.headers['content-type'] ?? source?.contentType ?? 'application/octet-stream',
    userMetadata: Object.keys(collectUserMetadata(ctx.headers)).length > 0 ? collectUserMetadata(ctx.headers) : source?.userMetadata ?? {},
    tagging,
    storageClass: ctx.headers['x-amz-storage-class'] ?? source?.storageClass,
    checksum: collectChecksums(ctx.headers),
    versionId: versionId ?? source?.versionId,
    objectLock: source?.objectLock,
  };
}

function metadataHeaders(metadata: ObjectMetadataState | null): Record<string, string> {
  if (!metadata) return {};
  return {
    'content-type': metadata.contentType,
    'content-length': String(metadata.size),
    etag: metadata.etag,
    'last-modified': new Date(metadata.lastModified).toUTCString(),
    ...(metadata.storageClass ? { 'x-amz-storage-class': metadata.storageClass } : {}),
    ...(metadata.versionId ? { 'x-amz-version-id': metadata.versionId } : {}),
    ...(metadata.isDeleteMarker ? { 'x-amz-delete-marker': 'true' } : {}),
    ...Object.fromEntries(Object.entries(metadata.userMetadata).map(([key, value]) => [`x-amz-meta-${key}`, value])),
    ...Object.fromEntries(Object.entries(metadata.checksum ?? {}).map(([key, value]) => [`x-amz-checksum-${key}`, value])),
  };
}

function evaluateObjectConditions(headers: Record<string, string>, metadata: ObjectMetadataState | null): { status?: 304 | 412 } {
  if (!metadata) return {};
  const etag = metadata.etag;
  const modifiedAt = new Date(metadata.lastModified).getTime();
  if (headers['if-match'] && !matchEtags(headers['if-match'], etag)) return { status: 412 };
  if (headers['if-none-match'] && matchEtags(headers['if-none-match'], etag)) return { status: headers['if-none-match'] ? 304 : 412 };
  if (headers['if-unmodified-since'] && modifiedAt > Date.parse(headers['if-unmodified-since'])) return { status: 412 };
  if (headers['if-modified-since'] && modifiedAt <= Date.parse(headers['if-modified-since'])) return { status: 304 };
  return {};
}

function evaluateCopySourceConditions(headers: Record<string, string>, metadata: ObjectMetadataState | null): { status?: 412 } {
  if (!metadata) return {};
  const etag = metadata.etag;
  const modifiedAt = new Date(metadata.lastModified).getTime();
  if (headers['x-amz-copy-source-if-match'] && !matchEtags(headers['x-amz-copy-source-if-match'], etag)) return { status: 412 };
  if (headers['x-amz-copy-source-if-none-match'] && matchEtags(headers['x-amz-copy-source-if-none-match'], etag)) return { status: 412 };
  if (headers['x-amz-copy-source-if-unmodified-since'] && modifiedAt > Date.parse(headers['x-amz-copy-source-if-unmodified-since'])) return { status: 412 };
  if (headers['x-amz-copy-source-if-modified-since'] && modifiedAt <= Date.parse(headers['x-amz-copy-source-if-modified-since'])) return { status: 412 };
  return {};
}

function isObjectLocked(metadata: ObjectMetadataState | null): boolean {
  if (!metadata?.objectLock) return false;
  if (metadata.objectLock.legalHold === 'ON') return true;
  if (!metadata.objectLock.retainUntilDate) return false;
  const retainUntil = Date.parse(metadata.objectLock.retainUntilDate);
  return Number.isFinite(retainUntil) && retainUntil > Date.now();
}

function matchEtags(condition: string, etag: string): boolean {
  return condition.split(',').map((item) => item.trim()).some((item) => item === '*' || item === etag || item.replace(/^W\//, '') === etag);
}

function validateChecksums(headers: Record<string, string>, body: Buffer): { code: string; message: string } | null {
  const contentMd5 = headers['content-md5'];
  if (contentMd5 && createHash('md5').update(body).digest('base64') !== contentMd5) {
    return { code: 'BadDigest', message: 'The Content-MD5 you specified did not match what we received' };
  }
  const sha256 = headers['x-amz-checksum-sha256'];
  if (sha256 && createHash('sha256').update(body).digest('base64') !== sha256) {
    return { code: 'BadDigest', message: 'The x-amz-checksum-sha256 you specified did not match what we received' };
  }
  return null;
}

function collectChecksums(headers: Record<string, string>): Record<string, string> | undefined {
  const entries = Object.entries(headers)
    .filter(([key]) => key.startsWith('x-amz-checksum-'))
    .map(([key, value]) => [key.slice('x-amz-checksum-'.length), value]);
  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}

function parseTaggingHeader(header: string | undefined): Record<string, string> {
  if (!header) return {};
  return Object.fromEntries(new URLSearchParams(header));
}

function parseTaggingXml(xml: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const match of xml.matchAll(/<Tag>\s*<Key>([\s\S]*?)<\/Key>\s*<Value>([\s\S]*?)<\/Value>\s*<\/Tag>/g)) {
    tags[unescapeXml(match[1])] = unescapeXml(match[2]);
  }
  return tags;
}

function unescapeXml(value: string): string {
  return value.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
}

function extractXmlValue(xml: string, tagName: string): string | undefined {
  const match = new RegExp(`<${tagName}>([\\s\\S]*?)</${tagName}>`).exec(xml);
  return match ? unescapeXml(match[1]) : undefined;
}

function isPostPolicyUpload(ctx: S3RequestContext): boolean {
  const body = toBuffer(ctx.req.body).toString('utf-8').toLowerCase();
  return ctx.headers['content-type']?.toLowerCase().includes('multipart/form-data') === true && body.includes('x-amz-credential');
}

function parsePostPolicyFields(body: unknown): Record<string, string | undefined> {
  return parsePostPolicyForm(body).fields;
}

function parsePostPolicyForm(body: unknown): { fields: Record<string, string>; file?: { filename?: string; body: Buffer } } {
  const buffer = toBuffer(body);
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

function decodeStreamingPayloadIfNeeded(headers: Record<string, string>, body: unknown): Buffer {
  const buffer = toBuffer(body);
  const payloadMarker = headers['x-amz-content-sha256'];
  if (!payloadMarker?.startsWith('STREAMING-AWS4-HMAC-SHA256-PAYLOAD')) return buffer;
  return decodeAwsChunkedBody(buffer);
}

function decodeAwsChunkedBody(body: Buffer): Buffer {
  const chunks: Buffer[] = [];
  let offset = 0;
  while (offset < body.length) {
    const lineEnd = body.indexOf('\r\n', offset, 'utf-8');
    if (lineEnd === -1) return body;
    const header = body.slice(offset, lineEnd).toString('utf-8');
    const sizeHex = header.split(';')[0];
    const size = parseInt(sizeHex, 16);
    if (!Number.isFinite(size)) return body;
    offset = lineEnd + 2;
    if (size === 0) break;
    chunks.push(body.slice(offset, offset + size));
    offset += size + 2;
  }
  return Buffer.concat(chunks);
}

function toBuffer(body: unknown): Buffer {
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === 'string') return Buffer.from(body);
  return Buffer.from([]);
}

async function requestBodyText(body: unknown): Promise<string> {
  return toBuffer(body).toString('utf-8');
}

async function readableToBuffer(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
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

function parseDeleteObjectsBody(xml: string): string[] {
  return [...xml.matchAll(/<Object>[\s\S]*?<Key>([\s\S]*?)<\/Key>[\s\S]*?<\/Object>/g)]
    .map((match) => unescapeXml(match[1] ?? ''))
    .filter((key) => key.length > 0);
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

function createWeakEtag(body: Buffer): string {
  let hash = 0;
  for (const byte of body) hash = ((hash << 5) - hash + byte) | 0;
  return Math.abs(hash).toString(16).padStart(8, '0');
}

function createVersionId(bucket: string, key: string): string {
  return createHash('sha256').update(`${bucket}/${key}/${Date.now()}/${Math.random()}`).digest('hex');
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