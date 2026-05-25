import { WebdavClient, WebdavError } from '../../webdav/client.js';
import { objectToWebdavPath } from '../../webdav/path-mapper.js';
import type { BucketBinding } from '../../tenancy/tenant-registry.js';
import { S3OperationError } from './get-object.js';

export interface HeadObjectResult {
  statusCode: 200;
  headers: Record<string, string>;
}

export async function headObject(
  client: WebdavClient,
  bucket: BucketBinding,
  key: string,
): Promise<HeadObjectResult> {
  const webdavPath = objectToWebdavPath(bucket.rootPath, key);

  try {
    const stat = await client.stat(webdavPath);
    if (!stat.exists) {
      throw new S3OperationError('NoSuchKey', 'The specified key does not exist.', 404);
    }

    return {
      statusCode: 200,
      headers: {
        'content-length': String(stat.contentLength),
        'etag': stat.etag,
        'last-modified': stat.lastModified,
        'content-type': stat.contentType || 'application/octet-stream',
        'accept-ranges': 'bytes',
      },
    };
  } catch (err) {
    if (err instanceof S3OperationError) throw err;
    if (err instanceof WebdavError) {
      if (err.statusCode === 404) throw new S3OperationError('NoSuchKey', 'The specified key does not exist.', 404);
      throw new S3OperationError('InternalError', err.message, 500);
    }
    throw new S3OperationError('InternalError', String(err), 500);
  }
}