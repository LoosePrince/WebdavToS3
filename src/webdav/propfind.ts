/**
 * Parse WebDAV PROPFIND (multistatus XML) response into a list of resource entries.
 */

import { XMLParser } from 'fast-xml-parser';

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  isArray: (name) => name === 'response' || name === 'D\\:response',
});

export interface PropfindResource {
  href: string;
  isCollection: boolean;
  contentLength: number;
  lastModified: string;
  etag: string;
}

/**
 * Parse a `multistatus` XML body from WebDAV PROPFIND.
 * Returns resources sorted by href.
 */
export function parsePropfindResponse(xml: string, basePath: string): PropfindResource[] {
  const doc = parser.parse(xml);
  const ms = doc['multistatus'] ?? doc['D:multistatus'] ?? doc['d:multistatus'];
  if (!ms) return [];

  const responses = ms.response ?? ms['D:response'] ?? ms['d:response'] ?? [];
  if (!Array.isArray(responses)) return [];

  const bp = basePath.replace(/\/+$/, '');

  return responses
    .map((r: Record<string, unknown>): PropfindResource | null => {
      const href: string = extractHref(r);
      if (!href) return null;

      // Access nested XML properties via bracket notation and explicit casts
      const propstatRecord = r['propstat'] as Record<string, unknown> | undefined;
      const dPropstatRecord = r['D:propstat'] as Record<string, unknown> | undefined;
      const props: Record<string, unknown> = (propstatRecord?.prop ?? dPropstatRecord?.prop ?? {}) as Record<string, unknown>;

      const resourceType = props['resourcetype'] as Record<string, unknown> | undefined;
      const dResourceType = props['D:resourcetype'] as Record<string, unknown> | undefined;
      const isCollection =
        resourceType?.['collection'] !== undefined ||
        dResourceType?.['D:collection'] !== undefined;

      const clRaw =
        props.getcontentlength?.toString() ??
        props['D:getcontentlength']?.toString() ??
        '0';
      const contentLength = Number(clRaw) || 0;

      const lastModified =
        props.getlastmodified?.toString() ??
        props['D:getlastmodified']?.toString() ??
        new Date(0).toISOString();

      const etag =
        props.getetag?.toString() ??
        props['D:getetag']?.toString() ??
        '';

      /**
       * Filter out the directory itself (rootPath), keep only children.
       */
      const normHref = href.replace(/\/+$/, '');
      // if (normHref === bp || normHref === bp + '/') return null;

      return { href: normHref, isCollection, contentLength, lastModified, etag };
    })
    .filter((r: PropfindResource | null): r is PropfindResource => r !== null)
    .sort((a: PropfindResource, b: PropfindResource) => a.href.localeCompare(b.href));
}

function extractHref(r: Record<string, unknown>): string {
  const raw = r.href ?? r['D:href'] ?? r['d:href'] ?? '';
  if (typeof raw === 'string') return decodeURI(raw);
  return '';
}

/** Format a lastModified string to ISO 8601 used by S3. */
export function formatLastModified(davDate: string): string {
  const d = new Date(davDate);
  return isNaN(d.getTime()) ? new Date(0).toISOString() : d.toISOString();
}

/** Strip quotes from ETag if present. */
export function cleanEtag(raw: string): string {
  return raw.replace(/^"/, '').replace(/"$/, '');
}