import { createHash } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import type { DatabaseSync as DatabaseSyncType } from 'node:sqlite';
import type {
  BucketState,
  ListObjectMetadataParams,
  ListObjectMetadataResult,
  MetadataStore,
  MultipartUploadState,
  ObjectMetadataState,
  ObjectVersionState,
} from './metadata-store.js';

const SYSTEM_ROOT = '/.webdavtos3-system';

export interface SqliteMetadataStoreOptions {
  path: string;
}

interface JsonRow {
  state_json: string;
}

interface MultipartUploadRow {
  bucket: string;
  object_key: string;
  upload_id: string;
  initiated_at: string;
  content_type: string | null;
  metadata_json: string;
}

interface MultipartPartRow {
  part_number: number;
  etag: string;
  size: number;
  path: string;
}

interface ObjectVersionRow extends JsonRow {
  is_latest: number;
  is_delete_marker: number;
  body_path: string | null;
}

interface ObjectVersionRecordRow extends ObjectVersionRow {
  id: number;
}

export class SqliteMetadataStore implements MetadataStore {
  private readonly db: DatabaseSyncType;

  constructor(options: SqliteMetadataStoreOptions) {
    const dbPath = normalizeSqlitePath(options.path);
    ensureSqliteParent(dbPath);
    this.db = new (getDatabaseSync())(dbPath);
    this.initialize();
  }

  close(): void {
    this.db.close();
  }

  async getBucketState(bucketName: string): Promise<BucketState> {
    const row = this.db.prepare('SELECT state_json FROM bucket_states WHERE bucket = ?').get(bucketName) as JsonRow | undefined;
    if (row) return parseJson<BucketState>(row.state_json);

    const created: BucketState = {
      name: bucketName,
      createdAt: new Date().toISOString(),
      acl: 'private',
      versioning: 'Off',
    };
    await this.putBucketState(created);
    return created;
  }

  async putBucketState(state: BucketState): Promise<void> {
    const now = new Date().toISOString();
    this.db.prepare(`
      INSERT INTO bucket_states (bucket, state_json, created_at, updated_at)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(bucket) DO UPDATE SET
        state_json = excluded.state_json,
        updated_at = excluded.updated_at
    `).run(state.name, stringifyJson(state), state.createdAt ?? now, now);
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
    await this.putMultipartUpload(state);
    return state;
  }

  async getMultipartUpload(bucket: string, uploadId: string): Promise<MultipartUploadState | null> {
    const upload = this.db.prepare(`
      SELECT bucket, object_key, upload_id, initiated_at, content_type, metadata_json
      FROM multipart_uploads
      WHERE bucket = ? AND upload_id = ?
    `).get(bucket, uploadId) as MultipartUploadRow | undefined;
    if (!upload) return null;

    const parts = this.db.prepare(`
      SELECT part_number, etag, size, path
      FROM multipart_parts
      WHERE bucket = ? AND upload_id = ?
      ORDER BY part_number ASC
    `).all(bucket, uploadId) as unknown as MultipartPartRow[];

    return {
      bucket: upload.bucket,
      key: upload.object_key,
      uploadId: upload.upload_id,
      initiatedAt: upload.initiated_at,
      contentType: upload.content_type ?? undefined,
      metadata: parseJson<Record<string, string>>(upload.metadata_json),
      parts: parts.map((part) => ({
        partNumber: part.part_number,
        etag: part.etag,
        size: part.size,
        path: part.path,
      })),
    };
  }

  async listMultipartUploads(bucket: string): Promise<MultipartUploadState[]> {
    const rows = this.db.prepare(`
      SELECT upload_id
      FROM multipart_uploads
      WHERE bucket = ?
      ORDER BY initiated_at ASC
    `).all(bucket) as Array<{ upload_id: string }>;
    const uploads = await Promise.all(rows.map((row) => this.getMultipartUpload(bucket, row.upload_id)));
    return uploads.filter((upload): upload is MultipartUploadState => upload !== null);
  }

  async putMultipartUpload(state: MultipartUploadState): Promise<void> {
    const metadataJson = stringifyJson(state.metadata ?? {});
    const upsertUpload = this.db.prepare(`
      INSERT INTO multipart_uploads (bucket, upload_id, object_key, initiated_at, content_type, metadata_json, state_json, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(bucket, upload_id) DO UPDATE SET
        object_key = excluded.object_key,
        initiated_at = excluded.initiated_at,
        content_type = excluded.content_type,
        metadata_json = excluded.metadata_json,
        state_json = excluded.state_json,
        updated_at = excluded.updated_at
    `);
    const deleteParts = this.db.prepare('DELETE FROM multipart_parts WHERE bucket = ? AND upload_id = ?');
    const insertPart = this.db.prepare(`
      INSERT INTO multipart_parts (bucket, upload_id, part_number, etag, size, path)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    this.withTransaction(() => {
      upsertUpload.run(
        state.bucket,
        state.uploadId,
        state.key,
        state.initiatedAt,
        state.contentType ?? null,
        metadataJson,
        stringifyJson(state),
        new Date().toISOString(),
      );
      deleteParts.run(state.bucket, state.uploadId);
      for (const part of state.parts) {
        insertPart.run(state.bucket, state.uploadId, part.partNumber, part.etag, part.size, part.path);
      }
    });
  }

  async deleteMultipartUpload(bucket: string, uploadId: string): Promise<void> {
    this.withTransaction(() => {
      this.db.prepare('DELETE FROM multipart_parts WHERE bucket = ? AND upload_id = ?').run(bucket, uploadId);
      this.db.prepare('DELETE FROM multipart_uploads WHERE bucket = ? AND upload_id = ?').run(bucket, uploadId);
    });
  }

  async getObjectMetadata(bucket: string, key: string): Promise<ObjectMetadataState | null> {
    const row = this.db.prepare(`
      SELECT state_json
      FROM object_metadata
      WHERE bucket = ? AND object_key = ?
    `).get(bucket, key) as JsonRow | undefined;
    return row ? parseJson<ObjectMetadataState>(row.state_json) : null;
  }

  async listObjectMetadata(bucket: string, params: ListObjectMetadataParams): Promise<ListObjectMetadataResult> {
    const prefix = params.prefix ?? '';
    const delimiter = params.delimiter ?? '';
    const maxKeys = Math.min(params.maxKeys ?? 1000, 1000);
    const continuationToken = params.continuationToken;
    const rows = this.queryObjectMetadataRows(bucket, prefix);
    const contents: ListObjectMetadataResult['contents'] = [];
    const commonPrefixes = new Set<string>();
    let scanned = 0;
    let lastReturnedToken: string | undefined;
    let nextContinuationToken: string | undefined;

    for (const row of rows) {
      const metadata = parseJson<ObjectMetadataState>(row.state_json);
      if (metadata.isDeleteMarker) continue;
      if (continuationToken && metadata.key <= continuationToken) continue;

      const remaining = metadata.key.slice(prefix.length);
      if (delimiter) {
        const delimiterIndex = remaining.indexOf(delimiter);
        if (delimiterIndex >= 0) {
          const commonPrefix = prefix + remaining.slice(0, delimiterIndex + delimiter.length);
          if (continuationToken && commonPrefix <= continuationToken) continue;
          if (!commonPrefixes.has(commonPrefix)) {
            scanned += 1;
            if (scanned > maxKeys) {
              nextContinuationToken = lastReturnedToken ?? metadata.key;
              break;
            }
            commonPrefixes.add(commonPrefix);
            lastReturnedToken = commonPrefix;
          }
          continue;
        }
      }

      scanned += 1;
      if (scanned > maxKeys) {
        nextContinuationToken = lastReturnedToken;
        break;
      }
      contents.push({
        key: metadata.key,
        lastModified: metadata.lastModified,
        etag: metadata.etag,
        size: metadata.size,
        storageClass: metadata.storageClass ?? 'STANDARD',
      });
      lastReturnedToken = metadata.key;
    }

    return {
      contents,
      commonPrefixes: delimiter ? [...commonPrefixes].sort() : undefined,
      isTruncated: nextContinuationToken !== undefined,
      nextContinuationToken,
    };
  }

  async putObjectMetadata(state: ObjectMetadataState): Promise<void> {
    this.db.prepare(`
      INSERT INTO object_metadata (bucket, object_key, state_json, last_modified, updated_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(bucket, object_key) DO UPDATE SET
        state_json = excluded.state_json,
        last_modified = excluded.last_modified,
        updated_at = excluded.updated_at
    `).run(state.bucket, state.key, stringifyJson(state), state.lastModified, new Date().toISOString());
  }

  async deleteObjectMetadata(bucket: string, key: string): Promise<void> {
    this.db.prepare('DELETE FROM object_metadata WHERE bucket = ? AND object_key = ?').run(bucket, key);
  }

  async listObjectVersions(bucket: string): Promise<ObjectVersionState[]> {
    const rows = this.db.prepare(`
      SELECT state_json, is_latest, is_delete_marker, body_path
      FROM object_versions
      WHERE bucket = ?
      ORDER BY id DESC
    `).all(bucket) as unknown as ObjectVersionRow[];
    return rows.map(parseObjectVersionRow);
  }

  async getObjectVersion(bucket: string, key: string, versionId: string): Promise<ObjectVersionState | null> {
    const row = this.db.prepare(`
      SELECT state_json, is_latest, is_delete_marker, body_path
      FROM object_versions
      WHERE bucket = ? AND object_key = ? AND version_id = ?
    `).get(bucket, key, versionId) as ObjectVersionRow | undefined;
    return row ? parseObjectVersionRow(row) : null;
  }

  async putObjectVersion(version: ObjectVersionState): Promise<void> {
    const markNonLatest = this.db.prepare('UPDATE object_versions SET is_latest = 0 WHERE bucket = ? AND object_key = ?');
    const deleteExisting = this.db.prepare('DELETE FROM object_versions WHERE bucket = ? AND object_key = ? AND version_id = ?');
    const insertVersion = this.db.prepare(`
      INSERT INTO object_versions (
        bucket,
        object_key,
        version_id,
        is_latest,
        is_delete_marker,
        last_modified,
        body_path,
        state_json,
        created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    this.withTransaction(() => {
      markNonLatest.run(version.bucket, version.key);
      deleteExisting.run(version.bucket, version.key, version.versionId);
      insertVersion.run(
        version.bucket,
        version.key,
        version.versionId,
        version.isLatest ? 1 : 0,
        version.isDeleteMarker ? 1 : 0,
        version.lastModified,
        version.bodyPath ?? null,
        stringifyJson(version),
        new Date().toISOString(),
      );
    });
  }

  async deleteObjectVersion(bucket: string, key: string, versionId: string): Promise<void> {
    const target = this.db.prepare(`
      SELECT id, state_json, is_latest, is_delete_marker, body_path
      FROM object_versions
      WHERE bucket = ? AND object_key = ? AND version_id = ?
    `).get(bucket, key, versionId) as ObjectVersionRecordRow | undefined;
    if (!target) return;

    const deleteVersion = this.db.prepare('DELETE FROM object_versions WHERE bucket = ? AND object_key = ? AND version_id = ?');
    const findPromoted = this.db.prepare(`
      SELECT id, state_json, is_latest, is_delete_marker, body_path
      FROM object_versions
      WHERE bucket = ? AND object_key = ?
      ORDER BY id DESC
      LIMIT 1
    `);
    const markNonLatest = this.db.prepare('UPDATE object_versions SET is_latest = 0 WHERE bucket = ? AND object_key = ?');
    const markLatest = this.db.prepare('UPDATE object_versions SET is_latest = 1 WHERE id = ?');
    const deleteCurrent = this.db.prepare('DELETE FROM object_metadata WHERE bucket = ? AND object_key = ?');
    const upsertCurrent = this.db.prepare(`
      INSERT INTO object_metadata (bucket, object_key, state_json, last_modified, updated_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(bucket, object_key) DO UPDATE SET
        state_json = excluded.state_json,
        last_modified = excluded.last_modified,
        updated_at = excluded.updated_at
    `);

    this.withTransaction(() => {
      deleteVersion.run(bucket, key, versionId);
      const promotedRow = findPromoted.get(bucket, key) as ObjectVersionRecordRow | undefined;
      markNonLatest.run(bucket, key);

      if (!promotedRow) {
        deleteCurrent.run(bucket, key);
        return;
      }

      markLatest.run(promotedRow.id);
      const promoted = parseObjectVersionRow({ ...promotedRow, is_latest: 1 });
      const { isLatest: _isLatest, ...metadata } = promoted;
      upsertCurrent.run(bucket, key, stringifyJson(metadata), metadata.lastModified, new Date().toISOString());
    });
  }

  private queryObjectMetadataRows(bucket: string, prefix: string): JsonRow[] {
    if (!prefix) {
      return this.db.prepare(`
        SELECT state_json
        FROM object_metadata
        WHERE bucket = ?
        ORDER BY object_key ASC
      `).all(bucket) as unknown as JsonRow[];
    }
    return this.db.prepare(`
      SELECT state_json
      FROM object_metadata
      WHERE bucket = ? AND object_key LIKE ? ESCAPE '\\'
      ORDER BY object_key ASC
    `).all(bucket, `${escapeSqlLike(prefix)}%`) as unknown as JsonRow[];
  }

  versionBodyPath(bucket: string, key: string, versionId: string): string {
    return `${SYSTEM_ROOT}/buckets/${encodeURIComponent(bucket)}/versions/data/${encodeURIComponent(versionId)}/${createHash('sha256').update(key).digest('hex')}`;
  }

  multipartPartPath(bucket: string, uploadId: string, partNumber: number): string {
    return `${SYSTEM_ROOT}/buckets/${encodeURIComponent(bucket)}/multipart/${encodeURIComponent(uploadId)}/parts/${partNumber}`;
  }

  private withTransaction(callback: () => void): void {
    this.db.exec('BEGIN');
    try {
      callback();
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  private initialize(): void {
    this.db.exec(`
      PRAGMA foreign_keys = ON;
      PRAGMA journal_mode = WAL;

      CREATE TABLE IF NOT EXISTS tenants (
        id TEXT PRIMARY KEY,
        state_json TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS bucket_states (
        bucket TEXT PRIMARY KEY,
        state_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS object_metadata (
        bucket TEXT NOT NULL,
        object_key TEXT NOT NULL,
        state_json TEXT NOT NULL,
        last_modified TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (bucket, object_key)
      );

      CREATE INDEX IF NOT EXISTS idx_object_metadata_bucket_key
        ON object_metadata(bucket, object_key);

      CREATE TABLE IF NOT EXISTS object_versions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bucket TEXT NOT NULL,
        object_key TEXT NOT NULL,
        version_id TEXT NOT NULL,
        is_latest INTEGER NOT NULL,
        is_delete_marker INTEGER NOT NULL DEFAULT 0,
        last_modified TEXT NOT NULL,
        body_path TEXT,
        state_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(bucket, object_key, version_id)
      );

      CREATE INDEX IF NOT EXISTS idx_object_versions_bucket_order
        ON object_versions(bucket, id DESC);

      CREATE INDEX IF NOT EXISTS idx_object_versions_bucket_key
        ON object_versions(bucket, object_key, id DESC);

      CREATE TABLE IF NOT EXISTS blobs (
        blob_ref TEXT PRIMARY KEY,
        digest_algorithm TEXT,
        digest TEXT,
        size INTEGER,
        storage_backend TEXT NOT NULL DEFAULT 'webdav',
        path TEXT,
        etag TEXT,
        ref_count INTEGER NOT NULL DEFAULT 0,
        state_json TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS multipart_uploads (
        bucket TEXT NOT NULL,
        upload_id TEXT NOT NULL,
        object_key TEXT NOT NULL,
        initiated_at TEXT NOT NULL,
        content_type TEXT,
        metadata_json TEXT NOT NULL,
        state_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (bucket, upload_id)
      );

      CREATE INDEX IF NOT EXISTS idx_multipart_uploads_bucket_order
        ON multipart_uploads(bucket, initiated_at ASC);

      CREATE TABLE IF NOT EXISTS multipart_parts (
        bucket TEXT NOT NULL,
        upload_id TEXT NOT NULL,
        part_number INTEGER NOT NULL,
        etag TEXT NOT NULL,
        size INTEGER NOT NULL,
        path TEXT NOT NULL,
        PRIMARY KEY (bucket, upload_id, part_number),
        FOREIGN KEY (bucket, upload_id) REFERENCES multipart_uploads(bucket, upload_id) ON DELETE CASCADE
      );

      CREATE TABLE IF NOT EXISTS object_locks (
        bucket TEXT NOT NULL,
        object_key TEXT NOT NULL,
        version_id TEXT,
        state_json TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (bucket, object_key, version_id)
      );

      CREATE TABLE IF NOT EXISTS lifecycle_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bucket TEXT NOT NULL,
        job_type TEXT NOT NULL,
        state_json TEXT NOT NULL,
        run_after TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS gc_jobs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        blob_ref TEXT,
        path TEXT,
        state_json TEXT NOT NULL,
        run_after TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      );
    `);
  }
}

export function createSqliteMetadataStore(options: SqliteMetadataStoreOptions): SqliteMetadataStore {
  return new SqliteMetadataStore(options);
}

type DatabaseSyncConstructor = new (path: string) => DatabaseSyncType;

let databaseSyncConstructor: DatabaseSyncConstructor | undefined;

function getDatabaseSync(): DatabaseSyncConstructor {
  if (databaseSyncConstructor) return databaseSyncConstructor;
  const require = createRequire(import.meta.url);
  databaseSyncConstructor = (require('node:sqlite') as { DatabaseSync: DatabaseSyncConstructor }).DatabaseSync;
  return databaseSyncConstructor;
}

function normalizeSqlitePath(path: string): string {
  if (path === ':memory:') return path;
  return resolve(process.cwd(), path);
}

function ensureSqliteParent(path: string): void {
  if (path === ':memory:') return;
  mkdirSync(dirname(path), { recursive: true });
}

function stringifyJson(value: unknown): string {
  return JSON.stringify(value);
}

function parseJson<T>(value: string): T {
  return JSON.parse(value) as T;
}

function parseObjectVersionRow(row: ObjectVersionRow): ObjectVersionState {
  const version = parseJson<ObjectVersionState>(row.state_json);
  return {
    ...version,
    isLatest: row.is_latest === 1,
    isDeleteMarker: row.is_delete_marker === 1 || version.isDeleteMarker,
    bodyPath: row.body_path ?? version.bodyPath,
  };
}

function escapeSqlLike(value: string): string {
  return value.replace(/[\\%_]/g, (char) => `\\${char}`);
}