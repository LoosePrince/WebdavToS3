import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SqliteMetadataStore } from '../src/s3/sqlite-metadata-store.js';
import type { ObjectMetadataState } from '../src/s3/metadata-store.js';

const stores = new Set<SqliteMetadataStore>();
const tempDirs = new Set<string>();

function trackStore(store: SqliteMetadataStore): SqliteMetadataStore {
  stores.add(store);
  return store;
}

function closeStore(store: SqliteMetadataStore): void {
  store.close();
  stores.delete(store);
}

async function createStore(): Promise<{ store: SqliteMetadataStore; dbPath: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'webdavtos3-sqlite-'));
  tempDirs.add(dir);
  const dbPath = join(dir, 'metadata.sqlite');
  return { store: trackStore(new SqliteMetadataStore({ path: dbPath })), dbPath };
}

function objectMetadata(key: string, overrides: Partial<ObjectMetadataState> = {}): ObjectMetadataState {
  return {
    bucket: 'demo',
    key,
    etag: `"${key}"`,
    size: key.length,
    lastModified: '2024-01-01T00:00:00.000Z',
    contentType: 'text/plain',
    userMetadata: {},
    tagging: {},
    ...overrides,
  };
}

afterEach(async () => {
  for (const store of stores) {
    try {
      store.close();
    } catch {
      // already closed in the test
    }
  }
  stores.clear();

  await Promise.all([...tempDirs].map((dir) => rm(dir, { recursive: true, force: true })));
  tempDirs.clear();
});

describe('SqliteMetadataStore', () => {
  it('persists bucket controls, object index, versions, and multipart state', async () => {
    const { store, dbPath } = await createStore();

    const bucket = await store.getBucketState('demo');
    await store.putBucketState({
      ...bucket,
      versioning: 'Enabled',
      policy: { Version: '2012-10-17' },
      tagging: { suite: 'sqlite' },
      lifecycle: '<LifecycleConfiguration/>',
      publicAccessBlock: '<PublicAccessBlockConfiguration/>',
    });

    await store.putObjectMetadata(objectMetadata('a.txt'));
    await store.putObjectMetadata(objectMetadata('b.txt'));
    await store.putObjectMetadata(objectMetadata('dir/c.txt'));
    await store.putObjectMetadata(objectMetadata('deleted.txt', { isDeleteMarker: true }));

    const rootList = await store.listObjectMetadata('demo', { prefix: '', delimiter: '/', maxKeys: 1000 });
    expect(rootList.contents.map((item) => item.key)).toEqual(['a.txt', 'b.txt']);
    expect(rootList.commonPrefixes).toEqual(['dir/']);

    const pageOne = await store.listObjectMetadata('demo', { prefix: '', maxKeys: 1 });
    expect(pageOne.contents.map((item) => item.key)).toEqual(['a.txt']);
    expect(pageOne.isTruncated).toBe(true);
    expect(pageOne.nextContinuationToken).toBe('a.txt');

    const pageTwo = await store.listObjectMetadata('demo', {
      prefix: '',
      maxKeys: 1,
      continuationToken: pageOne.nextContinuationToken,
    });
    expect(pageTwo.contents.map((item) => item.key)).toEqual(['b.txt']);

    await store.putObjectVersion({ ...objectMetadata('versioned.txt'), versionId: 'v1', isLatest: true, bodyPath: '/versions/v1' });
    await store.putObjectVersion({ ...objectMetadata('versioned.txt'), versionId: 'v2', isLatest: true, bodyPath: '/versions/v2' });
    const versions = await store.listObjectVersions('demo');
    expect(versions.map((version) => [version.versionId, version.isLatest])).toEqual([
      ['v2', true],
      ['v1', false],
    ]);

    const upload = await store.createMultipartUpload({
      bucket: 'demo',
      key: 'multipart.txt',
      contentType: 'text/plain',
      metadata: { source: 'unit-test' },
    });
    upload.parts = [
      { partNumber: 1, etag: '"part-1"', size: 5, path: '/parts/1' },
      { partNumber: 2, etag: '"part-2"', size: 5, path: '/parts/2' },
    ];
    await store.putMultipartUpload(upload);

    const loadedUpload = await store.getMultipartUpload('demo', upload.uploadId);
    expect(loadedUpload?.metadata).toEqual({ source: 'unit-test' });
    expect(loadedUpload?.parts.map((part) => part.partNumber)).toEqual([1, 2]);
    expect((await store.listMultipartUploads('demo')).map((item) => item.uploadId)).toContain(upload.uploadId);

    await store.deleteMultipartUpload('demo', upload.uploadId);
    expect(await store.getMultipartUpload('demo', upload.uploadId)).toBeNull();

    closeStore(store);
    const reopened = trackStore(new SqliteMetadataStore({ path: dbPath }));
    const persistedBucket = await reopened.getBucketState('demo');
    expect(persistedBucket.versioning).toBe('Enabled');
    expect(persistedBucket.policy).toEqual({ Version: '2012-10-17' });
    expect((await reopened.getObjectMetadata('demo', 'a.txt'))?.etag).toBe('"a.txt"');
  });
});