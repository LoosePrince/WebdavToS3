import { createHash } from 'node:crypto';
import { WebdavClient, WebdavError } from '../../webdav/client.js';

const SYSTEM_ROOT = '/.webdavtos3-system';

export interface BucketState {
  name: string;
  createdAt: string;
  acl: string;
  versioning: 'Off' | 'Enabled' | 'Suspended';
  policy?: unknown;
  cors?: unknown;
  tagging?: Record<string, string>;
  lifecycle?: unknown;
  encryption?: unknown;
  publicAccessBlock?: unknown;
}

export interface MultipartUploadState {
  bucket: string;
  key: string;
  uploadId: string;
  initiatedAt: string;
  contentType?: string;
  metadata: Record<string, string>;
  parts: Array<{ partNumber: number; etag: string; size: number; path: string }>;
}

export interface ObjectMetadataState {
  bucket: string;
  key: string;
  etag: string;
  size: number;
  lastModified: string;
  contentType: string;
  userMetadata: Record<string, string>;
  tagging: Record<string, string>;
  storageClass?: string;
  checksum?: Record<string, string>;
  versionId?: string;
  isDeleteMarker?: boolean;
  objectLock?: {
    mode?: string;
    retainUntilDate?: string;
    legalHold?: 'ON' | 'OFF';
  };
}

export interface ObjectVersionState extends ObjectMetadataState {
  versionId: string;
  isLatest: boolean;
  isDeleteMarker?: boolean;
  bodyPath?: string;
}

export interface BucketVersionIndex {
  bucket: string;
  entries: ObjectVersionState[];
}

export class S3StateStore {
  private readonly cache = new Map<string, unknown>();

  constructor(private readonly client: WebdavClient) {}

  async getBucketState(bucketName: string): Promise<BucketState> {
    const path = this.bucketStatePath(bucketName);
    const existing = await this.readJson<BucketState>(path);
    if (existing) return existing;

    const created: BucketState = {
      name: bucketName,
      createdAt: new Date().toISOString(),
      acl: 'private',
      versioning: 'Off',
    };
    await this.writeJson(path, created);
    return created;
  }

  async putBucketState(state: BucketState): Promise<void> {
    await this.writeJson(this.bucketStatePath(state.name), state);
  }

  async createMultipartUpload(params: {
    bucket: string;
    key: string;
    contentType?: string;
    metadata?: Record<string, string>;
  }): Promise<MultipartUploadState> {
    const uploadId = createHash('sha256')
      .update(`${params.bucket}/${params.key}/${Date.now()}/${Math.random()}`)
      .digest('hex');
    const state: MultipartUploadState = {
      bucket: params.bucket,
      key: params.key,
      uploadId,
      initiatedAt: new Date().toISOString(),
      contentType: params.contentType,
      metadata: params.metadata ?? {},
      parts: [],
    };
    await this.writeJson(this.multipartStatePath(params.bucket, uploadId), state);
    return state;
  }

  async getMultipartUpload(bucket: string, uploadId: string): Promise<MultipartUploadState | null> {
    return this.readJson<MultipartUploadState>(this.multipartStatePath(bucket, uploadId));
  }

  async putMultipartUpload(state: MultipartUploadState): Promise<void> {
    await this.writeJson(this.multipartStatePath(state.bucket, state.uploadId), state);
  }

  async deleteMultipartUpload(bucket: string, uploadId: string): Promise<void> {
    await this.deleteQuietly(this.multipartStatePath(bucket, uploadId));
  }

  async getObjectMetadata(bucket: string, key: string): Promise<ObjectMetadataState | null> {
    return this.readJson<ObjectMetadataState>(this.objectMetadataPath(bucket, key));
  }

  async putObjectMetadata(state: ObjectMetadataState): Promise<void> {
    await this.writeJson(this.objectMetadataPath(state.bucket, state.key), state);
  }

  async deleteObjectMetadata(bucket: string, key: string): Promise<void> {
    await this.deleteQuietly(this.objectMetadataPath(bucket, key));
  }

  async listObjectVersions(bucket: string): Promise<ObjectVersionState[]> {
    const index = await this.readJson<BucketVersionIndex>(this.versionIndexPath(bucket));
    return index?.entries ?? [];
  }

  async getObjectVersion(bucket: string, key: string, versionId: string): Promise<ObjectVersionState | null> {
    const entries = await this.listObjectVersions(bucket);
    return entries.find((entry) => entry.key === key && entry.versionId === versionId) ?? null;
  }

  async putObjectVersion(version: ObjectVersionState): Promise<void> {
    const path = this.versionIndexPath(version.bucket);
    const index = await this.readJson<BucketVersionIndex>(path) ?? { bucket: version.bucket, entries: [] };
    const entries = index.entries
      .filter((entry) => !(entry.key === version.key && entry.versionId === version.versionId))
      .map((entry) => entry.key === version.key ? { ...entry, isLatest: false } : entry);
    entries.unshift(version);
    await this.writeJson(path, { bucket: version.bucket, entries });
  }

  async deleteObjectVersion(bucket: string, key: string, versionId: string): Promise<void> {
    const path = this.versionIndexPath(bucket);
    const index = await this.readJson<BucketVersionIndex>(path);
    if (!index) return;
    const entries = index.entries.filter((entry) => !(entry.key === key && entry.versionId === versionId));
    await this.writeJson(path, { bucket, entries });
  }

  versionBodyPath(bucket: string, key: string, versionId: string): string {
    return `${SYSTEM_ROOT}/buckets/${encodeURIComponent(bucket)}/versions/data/${encodeURIComponent(versionId)}/${createHash('sha256').update(key).digest('hex')}`;
  }

  multipartPartPath(bucket: string, uploadId: string, partNumber: number): string {
    return `${SYSTEM_ROOT}/buckets/${encodeURIComponent(bucket)}/multipart/${encodeURIComponent(uploadId)}/parts/${partNumber}`;
  }

  private bucketStatePath(bucketName: string): string {
    return `${SYSTEM_ROOT}/buckets/${encodeURIComponent(bucketName)}/bucket.json`;
  }

  private multipartStatePath(bucket: string, uploadId: string): string {
    return `${SYSTEM_ROOT}/buckets/${encodeURIComponent(bucket)}/multipart/${encodeURIComponent(uploadId)}/upload.json`;
  }

  private objectMetadataPath(bucket: string, key: string): string {
    return `${SYSTEM_ROOT}/buckets/${encodeURIComponent(bucket)}/objects/${createHash('sha256').update(key).digest('hex')}.json`;
  }

  private versionIndexPath(bucket: string): string {
    return `${SYSTEM_ROOT}/buckets/${encodeURIComponent(bucket)}/versions/index.json`;
  }

  private async readJson<T>(path: string): Promise<T | null> {
    const cached = this.cache.get(path) as T | undefined;
    if (cached) return cached;

    try {
      const resp = await this.client.get(path);
      if (resp.statusCode === 404) return null;
      if (resp.statusCode >= 400) throw new WebdavError(`state read failed: ${resp.statusCode}`, resp.statusCode);
      const parsed = JSON.parse(resp.body.toString('utf-8')) as T;
      this.cache.set(path, parsed);
      return parsed;
    } catch (err) {
      if (err instanceof WebdavError && err.statusCode === 404) return null;
      return null;
    }
  }

  private async writeJson(path: string, value: unknown): Promise<void> {
    const parent = path.slice(0, path.lastIndexOf('/'));
    await this.client.ensureCollection(parent);
    const body = Buffer.from(JSON.stringify(value, null, 2));
    const resp = await this.client.put(path, body, body.length);
    if (![200, 201, 204].includes(resp.statusCode)) {
      throw new WebdavError(`state write failed: ${resp.statusCode}`, resp.statusCode);
    }
    this.cache.set(path, value);
  }

  private async deleteQuietly(path: string): Promise<void> {
    this.cache.delete(path);
    try {
      await this.client.delete(path);
    } catch {
      // idempotent cleanup
    }
  }
}