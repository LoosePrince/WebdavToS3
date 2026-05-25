import { WebdavClient, WebdavError } from '../../webdav/client.js';
import { objectToWebdavPath } from '../../webdav/path-mapper.js';
import type { BucketBinding } from '../../tenancy/tenant-registry.js';
import { S3OperationError } from './get-object.js';
import { headObject } from './head-object.js';

export interface CopyObjectResult {
  statusCode: 200;
  etag: string;
  lastModified: string;
}

export async function copyObject(
  client: WebdavClient,
  bucket: BucketBinding,
  sourceKey: string,
  destKey: string,
): Promise<CopyObjectResult> {
  const srcPath = objectToWebdavPath(bucket.rootPath, sourceKey);
  const destPath = objectToWebdavPath(bucket.rootPath, destKey);

  // Ensure parent directory exists for destination
  const destParent = destPath.substring(0, destPath.lastIndexOf('/'));
  if (destParent) {
    try {
      await client.ensureCollection(destParent);
    } catch {
      // best-effort
    }
  }

  try {
    const resp = await client.copy(srcPath, destPath);

    if (resp.statusCode === 201 || resp.statusCode === 204 || resp.statusCode === 200) {
      // Fetch destination metadata for response
      const head = await headObject(client, bucket, destKey);
      return {
        statusCode: 200,
        etag: head.headers['etag'] ?? '',
        lastModified: head.headers['last-modified'] ?? new Date().toISOString(),
      };
    }

    throw new S3OperationError(
      'InternalError',
      `COPY failed: upstream returned ${resp.statusCode}`,
      500,
    );
  } catch (err) {
    if (err instanceof WebdavError) {
      throw new S3OperationError('InternalError', err.message, 500);
    }
    if (err instanceof S3OperationError) throw err;
    throw new S3OperationError('InternalError', String(err), 500);
  }
}