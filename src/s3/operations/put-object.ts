import { createHash } from 'node:crypto';
import { WebdavClient, WebdavError } from '../../webdav/client.js';
import { objectToWebdavPath } from '../../webdav/path-mapper.js';
import type { BucketBinding } from '../../tenancy/tenant-registry.js';
import { S3OperationError } from './get-object.js';

export interface PutObjectResult {
  statusCode: 200;
  etag: string;
}

export async function putObject(
  client: WebdavClient,
  bucket: BucketBinding,
  key: string,
  body: NodeJS.ReadableStream | Buffer,
  contentLength?: number,
): Promise<PutObjectResult> {
  const webdavPath = objectToWebdavPath(bucket.rootPath, key);

  // Ensure parent collection exists
  const parentPath = webdavPath.substring(0, webdavPath.lastIndexOf('/'));
  if (parentPath) {
    try {
      await client.ensureCollection(parentPath);
    } catch {
      // Best-effort; if MKCOL fails, PUT might still work
    }
  }

  try {
    const resp = await client.put(webdavPath, body, contentLength);

    const etag = resp.headers['etag'] ?? `"${createHash('md5').update('webs3').digest('hex')}"`;

    if (resp.statusCode === 201 || resp.statusCode === 204 || resp.statusCode === 200) {
      return { statusCode: 200, etag };
    }

    // 404 usually means parent directory doesn't exist — retry after creating parent
    if (resp.statusCode === 404 && parentPath) {
      try {
        await client.ensureCollection(parentPath);
      } catch {
        // ignore
      }
      const retryResp = await client.put(webdavPath, body, contentLength);
      const retryEtag = retryResp.headers['etag'] ?? `"${createHash('md5').update('webs3').digest('hex')}"`;
      if (retryResp.statusCode === 201 || retryResp.statusCode === 204 || retryResp.statusCode === 200) {
        return { statusCode: 200, etag: retryEtag };
      }
      throw new S3OperationError('InternalError', `Upstream returned ${retryResp.statusCode} after retry`, 500);
    }

    throw new S3OperationError('InternalError', `Unexpected upstream status: ${resp.statusCode}`, 500);
  } catch (err) {
    if (err instanceof WebdavError) {
      throw new S3OperationError('InternalError', err.message, 500);
    }
    if (err instanceof S3OperationError) throw err;
    throw new S3OperationError('InternalError', String(err), 500);
  }
}