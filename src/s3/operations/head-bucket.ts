import type { BucketBinding } from '../../tenancy/tenant-registry.js';

export interface HeadBucketResult {
  statusCode: 200 | 404;
}

export function headBucket(bucket: BucketBinding): HeadBucketResult {
  return { statusCode: 200 };
}