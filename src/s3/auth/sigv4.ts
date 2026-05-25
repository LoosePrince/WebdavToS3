import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const SigV4Algorithm = 'AWS4-HMAC-SHA256';
const ServiceName = 's3';
const ClockSkewMs = 15 * 60 * 1000; // 15 minutes

/**
 * Minimal SigV4 header signature verification.
 *
 * Header-based signatures only. No presigned URL, streaming/chunked, or security-token support yet.
 */
export function verifySigV4(params: SigV4Params): SigV4Result {
  const { method, pathname, headers, secretAccessKey } = params;

  const authHeader = headers['authorization'];
  if (!authHeader) {
    return { ok: false, code: 'AccessDenied', message: 'Missing Authorization header' };
  }

  const parsed = parseAuthHeader(authHeader);
  if (!parsed) {
    return { ok: false, code: 'AccessDenied', message: 'Malformed Authorization header' };
  }

  if (parsed.algorithm !== SigV4Algorithm) {
    return { ok: false, code: 'SignatureDoesNotMatch', message: 'Unsupported algorithm' };
  }

  // Validate time with clock skew allowance
  const dateHeader = (headers['x-amz-date'] || headers['date'] || '') as string;
  if (!dateHeader) {
    return { ok: false, code: 'AccessDenied', message: 'Missing x-amz-date or Date header' };
  }

  const trimmedDate = dateHeader.trim();
  const isIso8601 = trimmedDate.includes('T');
  const parsedTime = new Date(isIso8601 ? `${trimmedDate}Z` : trimmedDate);
  if (isNaN(parsedTime.getTime())) {
    return { ok: false, code: 'AccessDenied', message: 'Invalid date format' };
  }
  const now = Date.now();
  if (Math.abs(parsedTime.getTime() - now) > ClockSkewMs) {
    return { ok: false, code: 'RequestTimeTooSkewed', message: 'The difference between the request time and the current time is too large' };
  }

  // Build date stamp from x-amz-date
  const dateStamp = parsedTime.toISOString().slice(0, 10).replace(/-/g, '');
  const timeStr = parsedTime.toISOString().slice(11, 19).replace(/:/g, '');

  const region = parsed.region;
  const signedHeaders = parsed.signedHeaders;

  // Canonical request
  const canonicalHeaders = buildCanonicalHeaders(headers, signedHeaders);
  const signedHeadersStr = signedHeaders.join(';');
  const payloadHash =
    (headers['x-amz-content-sha256'] as string) ||
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  const canonicalRequest = [
    method.toUpperCase(),
    pathname,
    '',
    canonicalHeaders,
    signedHeadersStr,
    payloadHash,
  ].join('\n');

  const hashedCanonical = hashHex(canonicalRequest);

  // String to sign
  const credentialScope = `${dateStamp}/${region}/${ServiceName}/aws4_request`;
  const stringToSign = [
    SigV4Algorithm,
    `${dateStamp}T${timeStr}Z`,
    credentialScope,
    hashedCanonical,
  ].join('\n');

  // Compute expected signature
  const signingKey = deriveSigningKey(secretAccessKey, dateStamp, region);
  const expectedSignature = hmacHex(signingKey, stringToSign);

  // Constant-time compare
  const sigBuf = Buffer.from(parsed.signature, 'hex');
  const expectedBuf = Buffer.from(expectedSignature, 'hex');
  if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) {
    return { ok: false, code: 'SignatureDoesNotMatch', message: 'The request signature we calculated does not match' };
  }

  return { ok: true, code: 'OK', message: '' };
}

// --- Parsing ---

interface ParsedAuth {
  algorithm: string;
  accessKey: string;
  dateStr: string;
  region: string;
  signedHeaders: string[];
  signature: string;
}

function parseAuthHeader(auth: string): ParsedAuth | null {
  const parts = auth.split(', ').map((s) => s.trim());
  if (parts.length === 0) return null;

  const first = parts[0].split(' ');
  if (first.length < 2) return null;
  const algorithm = first[0];

  const credPart = parts.find((p) => p.startsWith('Credential='));
  if (!credPart) return null;
  const credValue = credPart.slice('Credential='.length);
  const credSegments = credValue.split('/');
  if (credSegments.length < 5) return null;
  const accessKey = credSegments[0];
  const dateStr = credSegments[1];
  const region = credSegments[2];
  if (credSegments[3] !== ServiceName) return null;

  const shPart = parts.find((p) => p.startsWith('SignedHeaders='));
  if (!shPart) return null;
  const signedHeaders = shPart.slice('SignedHeaders='.length).split(';');

  const sigPart = parts.find((p) => p.startsWith('Signature='));
  if (!sigPart) return null;
  const signature = sigPart.slice('Signature='.length);

  return { algorithm, accessKey, dateStr, region, signedHeaders, signature };
}

// --- Helpers ---

function hashHex(data: string): string {
  return createHash('sha256').update(data, 'utf-8').digest('hex');
}

function hmacHex(key: Buffer, data: string): string {
  return createHmac('sha256', key).update(data, 'utf-8').digest('hex');
}

function deriveSigningKey(secret: string, dateStamp: string, region: string): Buffer {
  const kDate = createHmac('sha256', `AWS4${secret}`).update(dateStamp, 'utf-8').digest();
  const kRegion = createHmac('sha256', kDate).update(region, 'utf-8').digest();
  const kService = createHmac('sha256', kRegion).update(ServiceName, 'utf-8').digest();
  const kSigning = createHmac('sha256', kService).update('aws4_request', 'utf-8').digest();
  return kSigning;
}

function buildCanonicalHeaders(
  headers: Record<string, string | undefined>,
  signedHeaders: string[],
): string {
  return signedHeaders
    .map((h) => {
      const lower = h.toLowerCase();
      const val = (headers[lower] || headers[h] || '').trim();
      return `${lower}:${val}\n`;
    })
    .join('');
}

// --- Types ---

export interface SigV4Params {
  method: string;
  pathname: string;
  headers: Record<string, string | undefined>;
  body: Buffer | null;
  secretAccessKey: string;
  /** Access key found during parse (for tenant lookup) */
  accessKey?: string;
}

export interface SigV4Result {
  ok: boolean;
  code: string;
  message: string;
}