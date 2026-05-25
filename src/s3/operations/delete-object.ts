import { WebdavClient, WebdavError } from '../../webdav/client.js';
import { objectToWebdavPath } from '../../webdav/path-mapper.js';
import type { BucketBinding } from '../../tenancy/tenant-registry.js';
import { S3OperationError } from './get-object.js';

export interface DeleteObjectResult {
  statusCode: 204;
}

export async function deleteObject(
  client: WebdavClient,
  bucket: BucketBinding,
  key: string,
): Promise<DeleteObjectResult> {
  const webdavPath = objectToWebdavPath(bucket.rootPath, key);

  try {
    const resp = await client.delete(webdavPath);
    // WebDAV DELETE returns 204, 200, or 404 (not-found is ok for idempotent delete)
    if (resp.statusCode === 404) {
      return { statusCode: 204 };
    }
    return { statusCode: 204 };
  } catch (err) {
    if (err instanceof WebdavError) {
      if (err.statusCode === 404) return { statusCode: 204 };
      throw new S3OperationError('InternalError', err.message, 500);
    }
    throw new S3OperationError('InternalError', String(err), 500);
  }
}