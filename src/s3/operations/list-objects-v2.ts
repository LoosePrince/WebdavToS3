import { WebdavClient } from '../../webdav/client.js';
import { webdavHrefToObjectKey } from '../../webdav/path-mapper.js';
import type { BucketBinding } from '../../tenancy/tenant-registry.js';
import type { ListObjectsV2Result } from '../xml/serializer.js';

export async function listObjectsV2(
  client: WebdavClient,
  bucket: BucketBinding,
  params: {
    prefix?: string;
    delimiter?: string;
    maxKeys?: number;
    continuationToken?: string;
  },
): Promise<ListObjectsV2Result> {
  const prefix = params.prefix || '';
  const delimiter = params.delimiter || '';
  const maxKeys = Math.min(params.maxKeys || 1000, 1000);

  // Determine WebDAV path: list from the prefix root
  const rootPath = bucket.rootPath;
  const listPath = prefix
    ? rootPath.replace(/\/+$/, '') + '/' + prefix.split('/').filter(Boolean).join('/')
    : (rootPath.startsWith('/') ? rootPath : '/' + rootPath);

  const cleanListPath = listPath || '/';

  const entries = await client.list(cleanListPath);

  // Convert WebDAV entries to S3 contents
  const contents: ListObjectsV2Result['contents'] = [];
  const commonPrefixes = new Set<string>();

  for (const entry of entries) {
    if (entry.isCollection) {
      // Skip the root collection itself
      const href = decodeURIComponent(entry.href).replace(/\/+$/, '');
      const cleanRoot = rootPath.replace(/\/+$/, '');
      if (href === cleanRoot || href === cleanRoot + '/') continue;

      const objectKey = webdavHrefToObjectKey(entry.href, rootPath);

      // If delimiter is / and this is a "directory", add as common prefix
      if (delimiter === '/' && objectKey.endsWith('/')) {
        commonPrefixes.add(objectKey);
        continue;
      }
    }

    const objectKey = webdavHrefToObjectKey(entry.href, rootPath);
    if (!objectKey) continue;

    // Apply prefix filter
    if (prefix && !objectKey.startsWith(prefix)) continue;

    // Apply delimiter filter
    if (delimiter) {
      const remaining = objectKey.slice(prefix.length);
      const delimIdx = remaining.indexOf(delimiter);
      if (delimIdx >= 0) {
        commonPrefixes.add(prefix + remaining.slice(0, delimIdx + delimiter.length));
        continue;
      }
    }

    // Skip root self-reference
    if (objectKey === '') continue;

    contents.push({
      key: objectKey,
      lastModified: entry.lastModified || new Date().toISOString(),
      etag: entry.etag || '',
      size: entry.contentLength,
      storageClass: 'STANDARD',
    });
  }

  // Sort contents by key (S3 convention)
  contents.sort((a, b) => a.key.localeCompare(b.key));

  // Apply maxKeys truncation with continuation token simulation
  const effectiveMaxKeys = Math.min(maxKeys || 1000, 1000);
  const totalItems = contents.length + commonPrefixes.size;
  const isTruncated = totalItems > effectiveMaxKeys;

  let slicedContents = contents;
  let slicedPrefixes = [...commonPrefixes].sort();

  if (isTruncated) {
    // Simple truncation: keep only up to maxKeys contents
    slicedContents = contents.slice(0, effectiveMaxKeys);
    // Recalculate prefixes based on remaining contents
    slicedPrefixes = [...commonPrefixes]
      .filter((cp) => slicedContents.some((c) => c.key.startsWith(cp)))
      .sort();
  }

  return {
    name: bucket.name,
    prefix,
    maxKeys: effectiveMaxKeys,
    isTruncated,
    keyCount: slicedContents.length,
    contents: slicedContents,
    commonPrefixes: delimiter ? slicedPrefixes : undefined,
  };
}