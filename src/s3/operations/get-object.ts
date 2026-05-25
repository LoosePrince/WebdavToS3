import { WebdavClient, WebdavError } from '../../webdav/client.js';
import { objectToWebdavPath } from '../../webdav/path-mapper.js';
import type { BucketBinding } from '../../tenancy/tenant-registry.js';

export interface GetObjectResult {
  statusCode: 200 | 206 | 304;
  headers: Record<string, string>;
  body: NodeJS.ReadableStream;
}

export async function getObject(
  client: WebdavClient,
  bucket: BucketBinding,
  key: string,
  rangeHeader?: string,
): Promise<GetObjectResult> {
  const webdavPath = objectToWebdavPath(bucket.rootPath, key);

  try {
    const headers: Record<string, string> = {};
    if (rangeHeader) headers['range'] = rangeHeader;

    const resp = await client.request('GET', webdavPath, { headers });

    const responseHeaders: Record<string, string> = {
      'content-type': resp.headers['content-type'] ?? 'application/octet-stream',
      'content-length': resp.headers['content-length'] ?? '',
      'etag': resp.headers['etag'] ?? '',
      'last-modified': resp.headers['last-modified'] ?? '',
      'x-amz-request-id': '',
    };

    const statusCode = (rangeHeader && resp.statusCode === 206)
      ? 206
      : (resp.statusCode === 200 ? 200 : resp.statusCode) as 200 | 206 | 304;

    if (resp.statusCode === 304) {
      // Not Modified
      return { statusCode: 304, headers: responseHeaders, body: resp.body };
    }

    return { statusCode, headers: responseHeaders, body: resp.body };
  } catch (err) {
    if (err instanceof WebdavError) {
      if (err.statusCode === 404) throw new S3OperationError('NoSuchKey', 'The specified key does not exist.', 404);
      throw new S3OperationError('InternalError', err.message, 500);
    }
    throw err;
  }
}

export class S3OperationError extends Error {
  constructor(
    public readonly code: string,
    msg: string,
    public readonly httpStatus: number,
  ) {
    super(msg);
    this.name = 'S3OperationError';
  }
}