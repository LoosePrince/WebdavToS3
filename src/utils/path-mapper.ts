import { resolve, sep } from 'node:path';

/**
 * S3 object key -> WebDAV resource path under a given root.
 *
 * Security invariants:
 * - Reject any key containing ".." segments or null bytes.
 * - Normalise forward/back slashes.
 * - Ensure the final path stays within the tenant root.
 */
export function mapObjectKeyToWebdavPath(
  rootPath: string,
  key: string,
): string {
  // Reject traversal
  if (key.includes('..')) {
    throw new PathTraversalError(`Key must not contain "..": ${key}`);
  }
  if (key.includes('\0')) {
    throw new PathTraversalError(`Key must not contain null bytes`);
  }

  // Normalise separators
  const normalisedKey = key.replace(/\\/g, '/');

  // Ensure root starts with /
  const normalRoot = rootPath.startsWith('/') ? rootPath : '/' + rootPath;
  // Ensure root ends with /
  const rootWithSlash = normalRoot.endsWith('/') ? normalRoot : normalRoot + '/';

  const full = rootWithSlash + normalisedKey;
  const resolved = resolve('/', full);
  let resolvedStr = resolved.replace(/\\/g, '/');
  // Strip Windows drive letter prefix (e.g., "D:") from WebDAV paths
  resolvedStr = resolvedStr.replace(/^[a-zA-Z]:/, '');

  // Verify it's still under the root
  let rootCanonical = resolve('/', rootWithSlash).replace(/\\/g, '/');
  rootCanonical = rootCanonical.replace(/^[a-zA-Z]:/, '') + '/';
  if (!resolvedStr.startsWith(rootCanonical) && resolvedStr + '/' !== rootCanonical) {
    throw new PathTraversalError(`Resolved path escapes tenant root`);
  }

  // Encode each path segment for URL safety
  const segments = resolvedStr.split('/').filter(Boolean);
  const encoded = segments.map((s) => encodeURIComponent(s)).join('/');
  return '/' + encoded;
}

/**
 * Extract bucket and key from a path-style S3 URL: /bucket/key
 */
export function parsePathStyleUrl(
  pathname: string,
  tenantBuckets: Set<string>,
): { bucket: string; key: string } | null {
  const parts = pathname.split('/').filter(Boolean);
  if (parts.length === 0) return null;

  const bucket = decodeURIComponent(parts[0]);
  if (!tenantBuckets.has(bucket)) return null;

  const key = parts.slice(1).map(decodeURIComponent).join('/');
  return { bucket, key };
}

export class PathTraversalError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'PathTraversalError';
  }
}