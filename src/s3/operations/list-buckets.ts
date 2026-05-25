import type { Tenant } from '../../tenancy/tenant-registry.js';
import type { ListAllMyBucketsResult } from '../xml/serializer.js';

export function listBuckets(tenant: Tenant): ListAllMyBucketsResult {
  const now = new Date();
  const creationDate = now.toISOString();

  const buckets = [...tenant.buckets.values()].map((b) => ({
    name: b.name,
    creationDate,
  }));

  return { buckets };
}