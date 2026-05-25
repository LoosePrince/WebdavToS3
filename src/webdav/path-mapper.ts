import { mapObjectKeyToWebdavPath } from '../utils/path-mapper.js';

/**
 * Build the WebDAV resource path from bucket root + object key.
 */
export function objectToWebdavPath(rootPath: string, key: string): string {
  return mapObjectKeyToWebdavPath(rootPath, key);
}

/**
 * Build the WebDAV directory path for a given object key prefix.
 * Used for PROPFIND listing.
 */
export function prefixToWebdavPath(rootPath: string, prefix: string): string {
  if (!prefix) return rootPath.startsWith('/') ? rootPath : '/' + rootPath;
  return mapObjectKeyToWebdavPath(rootPath, prefix.replace(/\/$/, '')) + '/';
}

/**
 * Convert a WebDAV href back to an S3 key, given the rootPath.
 */
export function webdavHrefToObjectKey(href: string, rootPath: string): string {
  const decoded = decodeURIComponent(href);
  const normalizedRoot = rootPath.replace(/\/+$/, '');
  const normalizedHref = decoded.replace(/\/+$/, '');

  if (normalizedHref === normalizedRoot) return ''; // root itself

  const prefix = normalizedRoot.endsWith('/') ? normalizedRoot : normalizedRoot + '/';
  if (!normalizedHref.startsWith(prefix)) {
    // Fallback: try to find the root in the href
    const idx = normalizedHref.indexOf(normalizedRoot.replace(/^\/+/, '/'));
    if (idx === -1) return normalizedHref;
    return normalizedHref.slice(idx + normalizedRoot.length + 1);
  }

  return normalizedHref.slice(prefix.length);
}