import { XMLParser } from 'fast-xml-parser';

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  textNodeName: '#text',
  parseTagValue: false,
});

export interface ParsedMultipartComplete {
  parts: Array<{ partNumber: number; etag: string }>;
}

export function parseCompleteMultipartBody(xml: string): ParsedMultipartComplete {
  const doc = parser.parse(xml);
  const rawParts = doc?.CompleteMultipartUpload?.Part;
  const partsList = Array.isArray(rawParts) ? rawParts : rawParts ? [rawParts] : [];

  const parts = partsList.map((p: Record<string, unknown>) => ({
    partNumber: Number(p.PartNumber ?? 0),
    etag: String(p.ETag ?? ''),
  }));

  return { parts };
}