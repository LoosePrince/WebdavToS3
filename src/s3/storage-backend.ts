import type { UpstreamBinding } from '../tenancy/tenant-registry.js';
import { WebdavClient } from '../webdav/client.js';
import { createWebdavBlobStore, type BlobStore } from './blob-store.js';
import { createSqliteMetadataStore, type SqliteMetadataStore } from './sqlite-metadata-store.js';
import { createWebdavMetadataStore, type MetadataStore } from './metadata-store.js';

export interface StorageBackend {
  blobStore: BlobStore;
  metadataStore: MetadataStore;
}

export type MetadataBackendConfig =
  | { driver: 'webdav' }
  | { driver: 'sqlite'; path: string };

export interface StorageBackendFactoryOptions {
  metadata?: MetadataBackendConfig;
}

export interface StorageBackendFactory {
  getBackend(upstream: UpstreamBinding): StorageBackend;
  close(): void;
}

export function createStorageBackendFactory(options: StorageBackendFactoryOptions = {}): StorageBackendFactory {
  const metadataConfig = options.metadata ?? { driver: 'webdav' };
  const sqliteStore = metadataConfig.driver === 'sqlite'
    ? createSqliteMetadataStore({ path: metadataConfig.path })
    : undefined;
  const backends = new Map<string, StorageBackend>();

  return {
    getBackend(upstream: UpstreamBinding): StorageBackend {
      const cacheKey = `${upstream.id}:${upstream.endpoint}:${upstream.username}`;
      const cached = backends.get(cacheKey);
      if (cached) return cached;
      const backend = createWebdavStorageBackend(upstream, sqliteStore);
      backends.set(cacheKey, backend);
      return backend;
    },
    close(): void {
      sqliteStore?.close();
    },
  };
}

export function createWebdavStorageBackend(upstream: UpstreamBinding, metadataStore?: MetadataStore): StorageBackend {
  const client = new WebdavClient({
    endpoint: upstream.endpoint,
    username: upstream.username,
    password: upstream.password,
    rejectUnauthorized: upstream.rejectUnauthorized,
    connectTimeoutMs: upstream.connectTimeoutMs,
    requestTimeoutMs: upstream.requestTimeoutMs,
  });

  return {
    blobStore: createWebdavBlobStore(client),
    metadataStore: metadataStore ?? createWebdavMetadataStore(client),
  };
}