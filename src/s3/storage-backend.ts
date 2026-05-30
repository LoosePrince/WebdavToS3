import type { UpstreamBinding } from '../tenancy/tenant-registry.js';
import { WebdavClient } from '../webdav/client.js';
import { createWebdavBlobStore, type BlobStore } from './blob-store.js';
import { createWebdavMetadataStore, type MetadataStore } from './metadata-store.js';

export interface StorageBackend {
  blobStore: BlobStore;
  metadataStore: MetadataStore;
}

export function createWebdavStorageBackend(upstream: UpstreamBinding): StorageBackend {
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
    metadataStore: createWebdavMetadataStore(client),
  };
}