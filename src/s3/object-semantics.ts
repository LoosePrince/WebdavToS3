import { createHash } from 'node:crypto';
import type { ObjectMetadataState } from './metadata-store.js';

export function collectUserMetadata(headers: Record<string, string>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers)
      .filter(([key]) => key.startsWith('x-amz-meta-'))
      .map(([key, value]) => [key.slice('x-amz-meta-'.length), value]),
  );
}

export function validateChecksums(headers: Record<string, string>, body: Buffer): { code: string; message: string } | null {
  const contentMd5 = headers['content-md5'];
  if (contentMd5 && createHash('md5').update(body).digest('base64') !== contentMd5) {
    return { code: 'BadDigest', message: 'The Content-MD5 you specified did not match what we received' };
  }
  const sha256 = headers['x-amz-checksum-sha256'];
  if (sha256 && createHash('sha256').update(body).digest('base64') !== sha256) {
    return { code: 'BadDigest', message: 'The x-amz-checksum-sha256 you specified did not match what we received' };
  }
  return null;
}

export function collectChecksums(headers: Record<string, string>): Record<string, string> | undefined {
  const entries = Object.entries(headers)
    .filter(([key]) => key.startsWith('x-amz-checksum-'))
    .map(([key, value]) => [key.slice('x-amz-checksum-'.length), value]);
  return entries.length > 0 ? Object.fromEntries(entries) : undefined;
}

export function parseTaggingHeader(header: string | undefined): Record<string, string> {
  if (!header) return {};
  return Object.fromEntries(new URLSearchParams(header));
}

export function parseTaggingXml(xml: string): Record<string, string> {
  const tags: Record<string, string> = {};
  for (const match of xml.matchAll(/<Tag>\s*<Key>([\s\S]*?)<\/Key>\s*<Value>([\s\S]*?)<\/Value>\s*<\/Tag>/g)) {
    tags[unescapeXml(match[1])] = unescapeXml(match[2]);
  }
  return tags;
}

export function buildObjectMetadata(params: {
  bucket: string;
  key: string;
  headers: Record<string, string>;
  etag: string;
  size: number;
  tagging: Record<string, string>;
  source?: ObjectMetadataState;
  versionId?: string;
}): ObjectMetadataState {
  const { bucket, key, headers, etag, size, tagging, source, versionId } = params;
  return {
    bucket,
    key,
    etag,
    size,
    lastModified: new Date().toISOString(),
    contentType: headers['content-type'] ?? source?.contentType ?? 'application/octet-stream',
    userMetadata: Object.keys(collectUserMetadata(headers)).length > 0 ? collectUserMetadata(headers) : source?.userMetadata ?? {},
    tagging,
    storageClass: headers['x-amz-storage-class'] ?? source?.storageClass,
    checksum: collectChecksums(headers),
    versionId: versionId ?? source?.versionId,
    objectLock: source?.objectLock,
  };
}

export function metadataHeaders(metadata: ObjectMetadataState | null): Record<string, string> {
  if (!metadata) return {};
  return {
    'content-type': metadata.contentType,
    'content-length': String(metadata.size),
    etag: metadata.etag,
    'last-modified': new Date(metadata.lastModified).toUTCString(),
    ...(metadata.storageClass ? { 'x-amz-storage-class': metadata.storageClass } : {}),
    ...(metadata.versionId ? { 'x-amz-version-id': metadata.versionId } : {}),
    ...(metadata.isDeleteMarker ? { 'x-amz-delete-marker': 'true' } : {}),
    ...Object.fromEntries(Object.entries(metadata.userMetadata).map(([key, value]) => [`x-amz-meta-${key}`, value])),
    ...Object.fromEntries(Object.entries(metadata.checksum ?? {}).map(([key, value]) => [`x-amz-checksum-${key}`, value])),
  };
}

export function evaluateObjectConditions(headers: Record<string, string>, metadata: ObjectMetadataState | null): { status?: 304 | 412 } {
  if (!metadata) return {};
  const etag = metadata.etag;
  const modifiedAt = new Date(metadata.lastModified).getTime();
  if (headers['if-match'] && !matchEtags(headers['if-match'], etag)) return { status: 412 };
  if (headers['if-none-match'] && matchEtags(headers['if-none-match'], etag)) return { status: headers['if-none-match'] ? 304 : 412 };
  if (headers['if-unmodified-since'] && modifiedAt > Date.parse(headers['if-unmodified-since'])) return { status: 412 };
  if (headers['if-modified-since'] && modifiedAt <= Date.parse(headers['if-modified-since'])) return { status: 304 };
  return {};
}

export function evaluateCopySourceConditions(headers: Record<string, string>, metadata: ObjectMetadataState | null): { status?: 412 } {
  if (!metadata) return {};
  const etag = metadata.etag;
  const modifiedAt = new Date(metadata.lastModified).getTime();
  if (headers['x-amz-copy-source-if-match'] && !matchEtags(headers['x-amz-copy-source-if-match'], etag)) return { status: 412 };
  if (headers['x-amz-copy-source-if-none-match'] && matchEtags(headers['x-amz-copy-source-if-none-match'], etag)) return { status: 412 };
  if (headers['x-amz-copy-source-if-unmodified-since'] && modifiedAt > Date.parse(headers['x-amz-copy-source-if-unmodified-since'])) return { status: 412 };
  if (headers['x-amz-copy-source-if-modified-since'] && modifiedAt <= Date.parse(headers['x-amz-copy-source-if-modified-since'])) return { status: 412 };
  return {};
}

export function isObjectLocked(metadata: ObjectMetadataState | null): boolean {
  if (!metadata?.objectLock) return false;
  if (metadata.objectLock.legalHold === 'ON') return true;
  if (!metadata.objectLock.retainUntilDate) return false;
  const retainUntil = Date.parse(metadata.objectLock.retainUntilDate);
  return Number.isFinite(retainUntil) && retainUntil > Date.now();
}

export function extractXmlValue(xml: string, tagName: string): string | undefined {
  const match = new RegExp(`<${tagName}>([\\s\\S]*?)<\/${tagName}>`).exec(xml);
  return match ? unescapeXml(match[1]) : undefined;
}

export function unescapeXml(value: string): string {
  return value.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
}

export function decodeStreamingPayloadIfNeeded(headers: Record<string, string>, body: unknown): Buffer {
  const buffer = toBuffer(body);
  const payloadMarker = headers['x-amz-content-sha256'];
  if (!payloadMarker?.startsWith('STREAMING-AWS4-HMAC-SHA256-PAYLOAD')) return buffer;
  return decodeAwsChunkedBody(buffer);
}

export function decodeAwsChunkedBody(body: Buffer): Buffer {
  const chunks: Buffer[] = [];
  let offset = 0;
  while (offset < body.length) {
    const lineEnd = body.indexOf('\r\n', offset, 'utf-8');
    if (lineEnd === -1) return body;
    const header = body.slice(offset, lineEnd).toString('utf-8');
    const sizeHex = header.split(';')[0];
    const size = parseInt(sizeHex, 16);
    if (!Number.isFinite(size)) return body;
    offset = lineEnd + 2;
    if (size === 0) break;
    chunks.push(body.slice(offset, offset + size));
    offset += size + 2;
  }
  return Buffer.concat(chunks);
}

export function toBuffer(body: unknown): Buffer {
  if (Buffer.isBuffer(body)) return body;
  if (typeof body === 'string') return Buffer.from(body);
  return Buffer.from([]);
}

export async function requestBodyText(body: unknown): Promise<string> {
  return toBuffer(body).toString('utf-8');
}

export async function readableToBuffer(stream: NodeJS.ReadableStream): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of stream) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

export function safeJsonParse(body: string): unknown | null {
  try {
    return JSON.parse(body);
  } catch {
    return null;
  }
}

export function parseCompleteMultipartBody(xml: string): number[] {
  return [...xml.matchAll(/<PartNumber>(\d+)<\/PartNumber>/g)].map((match) => Number(match[1]));
}

export function parseDeleteObjectsBody(xml: string): string[] {
  return [...xml.matchAll(/<Object>[\s\S]*?<Key>([\s\S]*?)<\/Key>[\s\S]*?<\/Object>/g)]
    .map((match) => unescapeXml(match[1] ?? ''))
    .filter((key) => key.length > 0);
}

export function createWeakEtag(body: Buffer): string {
  let hash = 0;
  for (const byte of body) hash = ((hash << 5) - hash + byte) | 0;
  return Math.abs(hash).toString(16).padStart(8, '0');
}

export function createVersionId(bucket: string, key: string): string {
  return createHash('sha256').update(`${bucket}/${key}/${Date.now()}/${Math.random()}`).digest('hex');
}

function matchEtags(condition: string, etag: string): boolean {
  return condition.split(',').map((item) => item.trim()).some((item) => item === '*' || item === etag || item.replace(/^W\//, '') === etag);
}