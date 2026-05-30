import { type TenantRegistry } from '../../tenancy/tenant-registry.js';
import { info, warn } from '../../observability/logger.js';
import { createStorageBackendFactory, type StorageBackendFactory } from '../storage-backend.js';

export interface LifecycleWorkerOptions {
  enabled: boolean;
  intervalMs: number;
  expireNoncurrentVersionsAfterMs?: number;
  expireDeleteMarkersAfterMs?: number;
}

export interface LifecycleRunResult {
  scannedBuckets: number;
  removedVersions: number;
}

export async function runLifecycleOnce(
  registry: TenantRegistry,
  options: LifecycleWorkerOptions,
  storageBackendFactory?: StorageBackendFactory,
): Promise<LifecycleRunResult> {
  if (!options.enabled) return { scannedBuckets: 0, removedVersions: 0 };

  const backendFactory = storageBackendFactory ?? createStorageBackendFactory();
  const ownsBackendFactory = storageBackendFactory === undefined;
  let scannedBuckets = 0;
  let removedVersions = 0;
  const now = Date.now();

  try {
    for (const tenant of registry.allTenants) {
      for (const bucket of tenant.buckets.values()) {
        const upstream = tenant.upstreams.get(bucket.upstreamId);
        if (!upstream) continue;
        scannedBuckets += 1;
        const backend = backendFactory.getBackend(upstream);
        const versions = await backend.metadataStore.listObjectVersions(bucket.name);
        for (const version of versions) {
          const ageMs = now - Date.parse(version.lastModified);
          const expiredNoncurrent = !version.isLatest
            && options.expireNoncurrentVersionsAfterMs !== undefined
            && ageMs >= options.expireNoncurrentVersionsAfterMs;
          const expiredDeleteMarker = version.isDeleteMarker === true
            && options.expireDeleteMarkersAfterMs !== undefined
            && ageMs >= options.expireDeleteMarkersAfterMs;
          if (!expiredNoncurrent && !expiredDeleteMarker) continue;
          await backend.metadataStore.deleteObjectVersion(bucket.name, version.key, version.versionId);
          if (version.bodyPath && typeof backend.metadataStore.listObjectMetadata !== 'function') {
            await backend.blobStore.deleteRaw(version.bodyPath).catch(() => undefined);
          }
          removedVersions += 1;
        }
      }
    }
  } finally {
    if (ownsBackendFactory) backendFactory.close();
  }

  return { scannedBuckets, removedVersions };
}

export function startLifecycleWorker(
  registry: TenantRegistry,
  options: LifecycleWorkerOptions,
  storageBackendFactory?: StorageBackendFactory,
): NodeJS.Timeout | null {
  if (!options.enabled) return null;
  const run = async () => {
    try {
      const result = await runLifecycleOnce(registry, options, storageBackendFactory);
      info('lifecycle scan completed', { ...result });
    } catch (err) {
      warn('lifecycle scan failed', { error: String(err) });
    }
  };
  const timer = setInterval(run, options.intervalMs);
  timer.unref();
  void run();
  return timer;
}