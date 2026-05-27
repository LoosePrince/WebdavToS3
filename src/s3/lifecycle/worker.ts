import { WebdavClient } from '../../webdav/client.js';
import { type TenantRegistry } from '../../tenancy/tenant-registry.js';
import { S3StateStore } from '../state/store.js';
import { info, warn } from '../../observability/logger.js';

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

export async function runLifecycleOnce(registry: TenantRegistry, options: LifecycleWorkerOptions): Promise<LifecycleRunResult> {
  if (!options.enabled) return { scannedBuckets: 0, removedVersions: 0 };

  let scannedBuckets = 0;
  let removedVersions = 0;
  const now = Date.now();

  for (const tenant of registry.allTenants) {
    for (const bucket of tenant.buckets.values()) {
      const upstream = tenant.upstreams.get(bucket.upstreamId);
      if (!upstream) continue;
      scannedBuckets += 1;
      const client = new WebdavClient({
        endpoint: upstream.endpoint,
        username: upstream.username,
        password: upstream.password,
        rejectUnauthorized: upstream.rejectUnauthorized,
        connectTimeoutMs: upstream.connectTimeoutMs,
        requestTimeoutMs: upstream.requestTimeoutMs,
      });
      const state = new S3StateStore(client);
      const versions = await state.listObjectVersions(bucket.name);
      for (const version of versions) {
        const ageMs = now - Date.parse(version.lastModified);
        const expiredNoncurrent = !version.isLatest
          && options.expireNoncurrentVersionsAfterMs !== undefined
          && ageMs >= options.expireNoncurrentVersionsAfterMs;
        const expiredDeleteMarker = version.isDeleteMarker === true
          && options.expireDeleteMarkersAfterMs !== undefined
          && ageMs >= options.expireDeleteMarkersAfterMs;
        if (!expiredNoncurrent && !expiredDeleteMarker) continue;
        await state.deleteObjectVersion(bucket.name, version.key, version.versionId);
        if (version.bodyPath) await client.delete(version.bodyPath).catch(() => undefined);
        removedVersions += 1;
      }
    }
  }

  return { scannedBuckets, removedVersions };
}

export function startLifecycleWorker(registry: TenantRegistry, options: LifecycleWorkerOptions): NodeJS.Timeout | null {
  if (!options.enabled) return null;
  const run = async () => {
    try {
      const result = await runLifecycleOnce(registry, options);
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