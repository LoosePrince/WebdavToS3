import type { WebdavClient } from '../webdav/client.js';
import {
  S3StateStore,
  type BucketState,
  type MultipartUploadState,
  type ObjectMetadataState,
  type ObjectVersionState,
} from './state/store.js';

export type { BucketState, MultipartUploadState, ObjectMetadataState, ObjectVersionState };

export interface ListObjectMetadataParams {
  prefix?: string;
  delimiter?: string;
  maxKeys?: number;
  continuationToken?: string;
}

export interface ListObjectMetadataResult {
  contents: Array<{
    key: string;
    lastModified: string;
    etag: string;
    size: number;
    storageClass: string;
  }>;
  commonPrefixes?: string[];
  isTruncated: boolean;
  nextContinuationToken?: string;
}

export interface MetadataStore {
  getBucketState(bucketName: string): Promise<BucketState>;
  putBucketState(state: BucketState): Promise<void>;
  createMultipartUpload(params: {
    bucket: string;
    key: string;
    contentType?: string;
    metadata?: Record<string, string>;
  }): Promise<MultipartUploadState>;
  getMultipartUpload(bucket: string, uploadId: string): Promise<MultipartUploadState | null>;
  listMultipartUploads(bucket: string): Promise<MultipartUploadState[]>;
  putMultipartUpload(state: MultipartUploadState): Promise<void>;
  deleteMultipartUpload(bucket: string, uploadId: string): Promise<void>;
  getObjectMetadata(bucket: string, key: string): Promise<ObjectMetadataState | null>;
  listObjectMetadata?(bucket: string, params: ListObjectMetadataParams): Promise<ListObjectMetadataResult>;
  putObjectMetadata(state: ObjectMetadataState): Promise<void>;
  deleteObjectMetadata(bucket: string, key: string): Promise<void>;
  listObjectVersions(bucket: string): Promise<ObjectVersionState[]>;
  getObjectVersion(bucket: string, key: string, versionId: string): Promise<ObjectVersionState | null>;
  putObjectVersion(version: ObjectVersionState): Promise<void>;
  deleteObjectVersion(bucket: string, key: string, versionId: string): Promise<void>;
  versionBodyPath(bucket: string, key: string, versionId: string): string;
  multipartPartPath(bucket: string, uploadId: string, partNumber: number): string;
}

export class WebdavMetadataStore implements MetadataStore {
  constructor(private readonly store: S3StateStore) {}

  getBucketState(bucketName: string): Promise<BucketState> {
    return this.store.getBucketState(bucketName);
  }

  putBucketState(state: BucketState): Promise<void> {
    return this.store.putBucketState(state);
  }

  createMultipartUpload(params: {
    bucket: string;
    key: string;
    contentType?: string;
    metadata?: Record<string, string>;
  }): Promise<MultipartUploadState> {
    return this.store.createMultipartUpload(params);
  }

  getMultipartUpload(bucket: string, uploadId: string): Promise<MultipartUploadState | null> {
    return this.store.getMultipartUpload(bucket, uploadId);
  }

  listMultipartUploads(bucket: string): Promise<MultipartUploadState[]> {
    return this.store.listMultipartUploads(bucket);
  }

  putMultipartUpload(state: MultipartUploadState): Promise<void> {
    return this.store.putMultipartUpload(state);
  }

  deleteMultipartUpload(bucket: string, uploadId: string): Promise<void> {
    return this.store.deleteMultipartUpload(bucket, uploadId);
  }

  getObjectMetadata(bucket: string, key: string): Promise<ObjectMetadataState | null> {
    return this.store.getObjectMetadata(bucket, key);
  }

  putObjectMetadata(state: ObjectMetadataState): Promise<void> {
    return this.store.putObjectMetadata(state);
  }

  deleteObjectMetadata(bucket: string, key: string): Promise<void> {
    return this.store.deleteObjectMetadata(bucket, key);
  }

  listObjectVersions(bucket: string): Promise<ObjectVersionState[]> {
    return this.store.listObjectVersions(bucket);
  }

  getObjectVersion(bucket: string, key: string, versionId: string): Promise<ObjectVersionState | null> {
    return this.store.getObjectVersion(bucket, key, versionId);
  }

  putObjectVersion(version: ObjectVersionState): Promise<void> {
    return this.store.putObjectVersion(version);
  }

  deleteObjectVersion(bucket: string, key: string, versionId: string): Promise<void> {
    return this.store.deleteObjectVersion(bucket, key, versionId);
  }

  versionBodyPath(bucket: string, key: string, versionId: string): string {
    return this.store.versionBodyPath(bucket, key, versionId);
  }

  multipartPartPath(bucket: string, uploadId: string, partNumber: number): string {
    return this.store.multipartPartPath(bucket, uploadId, partNumber);
  }
}

export function createWebdavMetadataStore(client: WebdavClient): MetadataStore {
  return new WebdavMetadataStore(new S3StateStore(client));
}