export const XML_HEADERS: Record<string, string> = {
  'content-type': 'application/xml',
};

const ESCAPE_MAP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&apos;',
};

export function escapeXml(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => ESCAPE_MAP[ch] ?? ch);
}

function tag(name: string, value: string, indent = 2): string {
  const spaces = ' '.repeat(indent);
  if (value === '') return `${spaces}<${name}/>`;
  return `${spaces}<${name}>${escapeXml(value)}</${name}>`;
}

function tagRaw(name: string, innerXml: string, indent = 2): string {
  const spaces = ' '.repeat(indent);
  return `${spaces}<${name}>\n${innerXml}\n${spaces}</${name}>`;
}

export interface ListAllMyBucketsResult {
  buckets: Array<{ name: string; creationDate: string }>;
}

export function listBucketsXml(result: ListAllMyBucketsResult): string {
  const items = result.buckets
    .map(
      (b) =>
        tagRaw(
          'Bucket',
          `${tag('Name', b.name)}\n${tag('CreationDate', b.creationDate)}`,
          4,
        ),
    )
    .join('\n');
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    tagRaw('ListAllMyBucketsResult', `${tagRaw('Buckets', items, 2)}`, 0)
  );
}

export interface ListObjectsV2Result {
  name: string;
  prefix: string;
  maxKeys: number;
  isTruncated: boolean;
  continuationToken?: string;
  nextContinuationToken?: string;
  keyCount: number;
  contents: Array<{
    key: string;
    lastModified: string;
    etag: string;
    size: number;
    storageClass: string;
  }>;
  commonPrefixes?: string[];
}

export function listObjectsV2Xml(result: ListObjectsV2Result): string {
  const entries = result.contents
    .map((c) =>
      tagRaw(
        'Contents',
        [
          tag('Key', c.key),
          tag('LastModified', c.lastModified),
          tag('ETag', c.etag),
          tag('Size', String(c.size)),
          tag('StorageClass', c.storageClass),
        ].join('\n'),
        4,
      ),
    )
    .join('\n');

  const prefixes = (result.commonPrefixes ?? [])
    .map((p) => tag('CommonPrefixes', tag('Prefix', p, 4)))
    .join('\n');

  const fields: string[] = [
    tag('Name', result.name),
    tag('Prefix', result.prefix),
    tag('MaxKeys', String(result.maxKeys)),
    tag('IsTruncated', String(result.isTruncated)),
    tag('KeyCount', String(result.keyCount)),
  ];

  if (result.continuationToken) {
    fields.push(tag('ContinuationToken', result.continuationToken));
  }
  if (result.nextContinuationToken) {
    fields.push(tag('NextContinuationToken', result.nextContinuationToken));
  }

  fields.push(entries);
  if (prefixes) fields.push(prefixes);

  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    tagRaw('ListBucketResult', fields.join('\n'), 0)
  );
}

export interface CopyObjectResult {
  etag: string;
  lastModified: string;
}

export function copyObjectXml(result: CopyObjectResult): string {
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    tagRaw(
      'CopyObjectResult',
      [tag('ETag', result.etag), tag('LastModified', result.lastModified)].join('\n'),
      0,
    )
  );
}

export function locationXml(region: string): string {
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    tagRaw('LocationConstraint', region, 0)
  );
}