import { type TenantRegistry } from '../../tenancy/tenant-registry.js';
import { info, warn } from '../../observability/logger.js';
import { createStorageBackendFactory, type StorageBackend, type StorageBackendFactory } from '../storage-backend.js';

const CONTENT_BLOB_ROOT = '/.webdavtos3-blobs';

export interface LifecycleWorkerOptions {
  enabled: boolean;
  intervalMs: number;
  expireNoncurrentVersionsAfterMs?: number;
  expireDeleteMarkersAfterMs?: number;
  gcUnreferencedBlobs?: boolean;
}

export interface LifecycleRunResult {
  scannedBuckets: number;
  removedVersions: number;
  scannedBlobs: number;
  removedBlobs: number;
}

export async function runLifecycleOnce(
  registry: TenantRegistry,
  options: LifecycleWorkerOptions,
  storageBackendFactory?: StorageBackendFactory,
): Promise<LifecycleRunResult> {
  if (!options.enabled) return { scannedBuckets: 0, removedVersions: 0, scannedBlobs: 0, removedBlobs: 0 };

  const backendFactory = storageBackendFactory ?? createStorageBackendFactory();
  const ownsBackendFactory = storageBackendFactory === undefined;
  let scannedBuckets = 0;
  let removedVersions = 0;
  let scannedBlobs = 0;
  let removedBlobs = 0;
  const now = Date.now();
  const gcTargets = new Map<StorageBackend, Set<string>>();

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

        if (options.gcUnreferencedBlobs
          && typeof backend.metadataStore.listObjectMetadata === 'function'
          && typeof backend.blobStore.listRaw === 'function') {
          const buckets = gcTargets.get(backend) ?? new Set<string>();
          buckets.add(bucket.name);
          gcTargets.set(backend, buckets);
        }
      }
    }

    for (const [backend, buckets] of gcTargets) {
      const result = await removeUnreferencedContentBlobs(backend, [...buckets]);
      scannedBlobs += result.scannedBlobs;
      removedBlobs += result.removedBlobs;
    }
  } finally {
    if (ownsBackendFactory) backendFactory.close();
  }

  return { scannedBuckets, removedVersions, scannedBlobs, removedBlobs };
}

async function removeUnreferencedContentBlobs(
  backend: StorageBackend,
  buckets: string[],
): Promise<{ scannedBlobs: number; removedBlobs: number }> {
  const referenced = await collectReferencedBlobPaths(backend, buckets);
  const candidates = await listContentBlobPaths(backend);
  let removedBlobs = 0;

  for (const path of candidates) {
    if (referenced.has(path)) continue;
    const resp = await backend.blobStore.deleteRaw(path).catch(() => null);
    if (!resp || resp.statusCode >= 400 && resp.statusCode !== 404) continue;
    removedBlobs += 1;
  }

  return { scannedBlobs: candidates.length, removedBlobs };
}

async function collectReferencedBlobPaths(backend: StorageBackend, buckets: string[]): Promise<Set<string>> {
  const referenced = new Set<string>();

  for (const bucket of buckets) {
    let continuationToken: string | undefined;
    do {
      const page = await backend.metadataStore.listObjectMetadata!(bucket, { maxKeys: 1000, continuationToken });
      for (const item of page.contents) {
        const metadata = await backend.metadataStore.getObjectMetadata(bucket, item.key);
        addContentBlobReference(referenced, metadata?.bodyPath);
      }
      continuationToken = page.nextContinuationToken;
    } while (continuationToken);

    for (const version of await backend.metadataStore.listObjectVersions(bucket)) {
      addContentBlobReference(referenced, version.bodyPath);
    }

    for (const upload of await backend.metadataStore.listMultipartUploads(bucket)) {
      for (const part of upload.parts) addContentBlobReference(referenced, part.path);
    }
  }

  return referenced;
}

function addContentBlobReference(referenced: Set<string>, path: string | undefined): void {
  if (path?.startsWith(`${CONTENT_BLOB_ROOT}/`)) referenced.add(path);
}

async function listContentBlobPaths(backend: StorageBackend): Promise<string[]> {
  if (typeof backend.blobStore.listRaw !== 'function') return [];

  const files: string[] = [];
  const stack = [CONTENT_BLOB_ROOT];
  const visited = new Set<string>();

  while (stack.length > 0) {
    const current = stack.pop()!;
    if (visited.has(current)) continue;
    visited.add(current);

    const entries = await backend.blobStore.listRaw(current).catch(() => []);
    for (const entry of entries) {
      if (!entry.path.startsWith(`${CONTENT_BLOB_ROOT}/`)) continue;
      if (entry.isCollection) {
        stack.push(entry.path);
      } else {
        files.push(entry.path);
      }
    }
  }

  return files;
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