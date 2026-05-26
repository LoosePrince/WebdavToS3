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

  multipartPartPath(bucket: string, uploadId: string, partNumber: number): string {
    return `${SYSTEM_ROOT}/buckets/${encodeURIComponent(bucket)}/multipart/${encodeURIComponent(uploadId)}/parts/${partNumber}`;
  }

  private bucketStatePath(bucketName: string): string {
    return `${SYSTEM_ROOT}/buckets/${encodeURIComponent(bucketName)}/bucket.json`;
  }

  private multipartStatePath(bucket: string, uploadId: string): string {
    return `${SYSTEM_ROOT}/buckets/${encodeURIComponent(bucket)}/multipart/${encodeURIComponent(uploadId)}/upload.json`;
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