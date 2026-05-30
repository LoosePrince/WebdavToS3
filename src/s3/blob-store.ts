import type { BucketBinding } from '../tenancy/tenant-registry.js';
import type { WebdavClient, WebdavResponse } from '../webdav/client.js';
import { copyObject, deleteObject, getObject, headObject, listObjectsV2, putObject } from './operations/index.js';
import type { CopyObjectResult } from './operations/copy-object.js';
import type { DeleteObjectResult } from './operations/delete-object.js';
import type { GetObjectResult } from './operations/get-object.js';
import type { HeadObjectResult } from './operations/head-object.js';
import type { PutObjectResult } from './operations/put-object.js';
import type { ListObjectsV2Result } from './xml/serializer.js';

export interface BlobStore {
  getObject(bucket: BucketBinding, key: string, rangeHeader?: string): Promise<GetObjectResult>;
  headObject(bucket: BucketBinding, key: string): Promise<HeadObjectResult>;
  putObject(bucket: BucketBinding, key: string, body: NodeJS.ReadableStream | Buffer, contentLength?: number): Promise<PutObjectResult>;
  deleteObject(bucket: BucketBinding, key: string): Promise<DeleteObjectResult>;
  copyObject(bucket: BucketBinding, sourceKey: string, destKey: string): Promise<CopyObjectResult>;
  listObjects(
    bucket: BucketBinding,
    params: {
      prefix?: string;
      delimiter?: string;
      maxKeys?: number;
      continuationToken?: string;
    },
  ): Promise<ListObjectsV2Result>;
  getRaw(path: string, rangeHeader?: string): Promise<WebdavResponse>;
  putRaw(path: string, body: NodeJS.ReadableStream | Buffer, contentLength?: number): Promise<WebdavResponse>;
  deleteRaw(path: string): Promise<WebdavResponse>;
  ensurePath(path: string): Promise<void>;
}

export class WebdavBlobStore implements BlobStore {
  constructor(private readonly client: WebdavClient) {}

  getObject(bucket: BucketBinding, key: string, rangeHeader?: string): Promise<GetObjectResult> {
    return getObject(this.client, bucket, key, rangeHeader);
  }

  headObject(bucket: BucketBinding, key: string): Promise<HeadObjectResult> {
    return headObject(this.client, bucket, key);
  }

  putObject(bucket: BucketBinding, key: string, body: NodeJS.ReadableStream | Buffer, contentLength?: number): Promise<PutObjectResult> {
    return putObject(this.client, bucket, key, body, contentLength);
  }

  deleteObject(bucket: BucketBinding, key: string): Promise<DeleteObjectResult> {
    return deleteObject(this.client, bucket, key);
  }

  copyObject(bucket: BucketBinding, sourceKey: string, destKey: string): Promise<CopyObjectResult> {
    return copyObject(this.client, bucket, sourceKey, destKey);
  }

  listObjects(
    bucket: BucketBinding,
    params: {
      prefix?: string;
      delimiter?: string;
      maxKeys?: number;
      continuationToken?: string;
    },
  ): Promise<ListObjectsV2Result> {
    return listObjectsV2(this.client, bucket, params);
  }

  getRaw(path: string, rangeHeader?: string): Promise<WebdavResponse> {
    const headers = rangeHeader ? { range: rangeHeader } : undefined;
    return this.client.request('GET', path, { headers });
  }

  putRaw(path: string, body: NodeJS.ReadableStream | Buffer, contentLength?: number): Promise<WebdavResponse> {
    return this.client.put(path, body, contentLength);
  }

  deleteRaw(path: string): Promise<WebdavResponse> {
    return this.client.delete(path);
  }

  ensurePath(path: string): Promise<void> {
    return this.client.ensureCollection(path);
  }
}

export function createWebdavBlobStore(client: WebdavClient): BlobStore {
  return new WebdavBlobStore(client);
}