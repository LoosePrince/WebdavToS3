import S3Errors from 'fast-xml-parser'; // just for namespace — we use plain JS

export class S3ErrorResponse {
  constructor(
    public readonly code: string,
    public readonly message: string,
    public readonly httpStatus: number,
    public readonly resource?: string,
  ) {}

  toXml(requestId?: string): string {
    return [
      '<?xml version="1.0" encoding="UTF-8"?>',
      '<Error>',
      `  <Code>${escapeXml(this.code)}</Code>`,
      `  <Message>${escapeXml(this.message)}</Message>`,
      `  <Resource>${escapeXml(this.resource ?? '/')}</Resource>`,
      `  <RequestId>${escapeXml(requestId ?? 'unknown')}</RequestId>`,
      '</Error>',
    ].join('\n');
  }
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}