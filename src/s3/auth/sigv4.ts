import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

const SigV4Algorithm = 'AWS4-HMAC-SHA256';
const ServiceName = 's3';
const ClockSkewMs = 15 * 60 * 1000;

export function verifySigV4(params: SigV4Params): SigV4Result {
  const { queryString = '', headers } = params;
  if (isPresignedRequest(queryString)) {
    return verifyPresignedSigV4(params);
  }

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

  const tokenResult = validateSessionToken(params.sessionToken, headers['x-amz-security-token']);
  if (!tokenResult.ok) return tokenResult;

  const dateHeader = (headers['x-amz-date'] || headers['date'] || '') as string;
  if (!dateHeader) {
    return { ok: false, code: 'AccessDenied', message: 'Missing x-amz-date or Date header' };
  }

  const timeResult = validateRequestTime(dateHeader, ClockSkewMs);
  if (!timeResult.ok) return timeResult;

  const dateStamp = parsed.dateStr || dateHeader.slice(0, 8);
  const amzDate = normalizeAmzDate(dateHeader);
  if (!amzDate) {
    return { ok: false, code: 'AccessDenied', message: 'Invalid date format' };
  }

  const payloadHash =
    (headers['x-amz-content-sha256'] as string) ||
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

  const canonicalRequest = buildCanonicalRequest({
    method: params.method,
    pathname: params.pathname,
    queryString,
    headers,
    signedHeaders: parsed.signedHeaders,
    payloadHash,
  });

  const credentialScope = `${dateStamp}/${parsed.region}/${ServiceName}/aws4_request`;
  const expectedSignature = signCanonicalRequest({
    secretAccessKey: params.secretAccessKey,
    dateStamp,
    region: parsed.region,
    amzDate,
    credentialScope,
    canonicalRequest,
  });

  if (!safeSignatureEquals(parsed.signature, expectedSignature)) {
    return { ok: false, code: 'SignatureDoesNotMatch', message: 'The request signature we calculated does not match' };
  }

  return { ok: true, code: 'OK', message: '', accessKey: parsed.accessKey, region: parsed.region };
}

function verifyPresignedSigV4(params: SigV4Params): SigV4Result {
  const search = new URLSearchParams(params.queryString ?? '');
  const algorithm = search.get('X-Amz-Algorithm');
  const credential = search.get('X-Amz-Credential');
  const amzDate = search.get('X-Amz-Date');
  const expires = search.get('X-Amz-Expires');
  const signedHeadersValue = search.get('X-Amz-SignedHeaders');
  const signature = search.get('X-Amz-Signature');

  if (!algorithm || !credential || !amzDate || !expires || !signedHeadersValue || !signature) {
    return { ok: false, code: 'AccessDenied', message: 'Missing presigned URL query parameters' };
  }
  if (algorithm !== SigV4Algorithm) {
    return { ok: false, code: 'SignatureDoesNotMatch', message: 'Unsupported algorithm' };
  }

  const cred = parseCredentialValue(credential);
  if (!cred) {
    return { ok: false, code: 'AccessDenied', message: 'Malformed X-Amz-Credential' };
  }

  const tokenResult = validateSessionToken(params.sessionToken, search.get('X-Amz-Security-Token') ?? undefined);
  if (!tokenResult.ok) return tokenResult;

  const expiresSeconds = Number(expires);
  if (!Number.isFinite(expiresSeconds) || expiresSeconds < 0) {
    return { ok: false, code: 'AccessDenied', message: 'Invalid X-Amz-Expires' };
  }

  const timeResult = validateRequestTime(amzDate, Math.max(ClockSkewMs, expiresSeconds * 1000 + ClockSkewMs));
  if (!timeResult.ok) return timeResult;

  const signedAt = parseAmzDate(amzDate);
  if (!signedAt) {
    return { ok: false, code: 'AccessDenied', message: 'Invalid X-Amz-Date' };
  }
  if (Date.now() > signedAt.getTime() + expiresSeconds * 1000) {
    return { ok: false, code: 'AccessDenied', message: 'Request has expired' };
  }

  const signedHeaders = signedHeadersValue.split(';').filter(Boolean);
  const payloadHash = search.get('X-Amz-Content-Sha256') || 'UNSIGNED-PAYLOAD';
  const canonicalRequest = buildCanonicalRequest({
    method: params.method,
    pathname: params.pathname,
    queryString: params.queryString ?? '',
    headers: params.headers,
    signedHeaders,
    payloadHash,
    excludedQueryKeys: new Set(['X-Amz-Signature']),
  });

  const credentialScope = `${cred.dateStr}/${cred.region}/${ServiceName}/aws4_request`;
  const expectedSignature = signCanonicalRequest({
    secretAccessKey: params.secretAccessKey,
    dateStamp: cred.dateStr,
    region: cred.region,
    amzDate,
    credentialScope,
    canonicalRequest,
  });

  if (!safeSignatureEquals(signature, expectedSignature)) {
    return { ok: false, code: 'SignatureDoesNotMatch', message: 'The request signature we calculated does not match' };
  }

  return { ok: true, code: 'OK', message: '', accessKey: cred.accessKey, region: cred.region };
}

export function extractSigV4AccessKey(headers: Record<string, string | undefined>, queryString = ''): string | undefined {
  const presignedCredential = new URLSearchParams(queryString).get('X-Amz-Credential');
  if (presignedCredential) {
    return parseCredentialValue(presignedCredential)?.accessKey;
  }

  const authHeader = headers['authorization'];
  if (!authHeader) return undefined;
  return parseAuthHeader(authHeader)?.accessKey;
}

export function extractPostPolicyAccessKey(fields: Record<string, string | undefined>): string | undefined {
  const credential = fields['x-amz-credential'] ?? fields['X-Amz-Credential'];
  return credential ? parseCredentialValue(credential)?.accessKey : undefined;
}

export function verifyPostPolicySigV4(params: PostPolicySigV4Params): SigV4Result {
  const fields = normalizeFieldNames(params.fields);
  const algorithm = fields['x-amz-algorithm'];
  const credential = fields['x-amz-credential'];
  const amzDate = fields['x-amz-date'];
  const policy = fields.policy;
  const signature = fields['x-amz-signature'];

  if (!algorithm || !credential || !amzDate || !policy || !signature) {
    return { ok: false, code: 'AccessDenied', message: 'Missing POST policy fields' };
  }
  if (algorithm !== SigV4Algorithm) {
    return { ok: false, code: 'SignatureDoesNotMatch', message: 'Unsupported algorithm' };
  }

  const cred = parseCredentialValue(credential);
  if (!cred) {
    return { ok: false, code: 'AccessDenied', message: 'Malformed x-amz-credential' };
  }

  const tokenResult = validateSessionToken(params.sessionToken, fields['x-amz-security-token']);
  if (!tokenResult.ok) return tokenResult;

  const timeResult = validateRequestTime(amzDate, ClockSkewMs);
  if (!timeResult.ok) return timeResult;

  const policyResult = validatePostPolicy(policy, params.now ?? new Date());
  if (!policyResult.ok) return policyResult;

  const expectedSignature = hmacHex(deriveSigningKey(params.secretAccessKey, cred.dateStr, cred.region), policy);
  if (!safeSignatureEquals(signature, expectedSignature)) {
    return { ok: false, code: 'SignatureDoesNotMatch', message: 'The POST policy signature does not match' };
  }

  return { ok: true, code: 'OK', message: '', accessKey: cred.accessKey, region: cred.region };
}

function isPresignedRequest(queryString: string): boolean {
  if (!queryString) return false;
  const search = new URLSearchParams(queryString);
  return search.has('X-Amz-Algorithm') || search.has('X-Amz-Signature');
}

interface ParsedAuth {
  algorithm: string;
  accessKey: string;
  dateStr: string;
  region: string;
  signedHeaders: string[];
  signature: string;
}

function parseAuthHeader(auth: string): ParsedAuth | null {
  const parts = auth.split(',').map((s) => s.trim());
  if (parts.length === 0) return null;

  const first = parts[0].split(' ');
  if (first.length < 2) return null;
  const algorithm = first[0];
  const credFull = first[1];
  if (!credFull.startsWith('Credential=')) return null;

  const credential = parseCredentialValue(credFull.slice('Credential='.length));
  if (!credential) return null;

  const shPart = parts.find((p) => p.startsWith('SignedHeaders='));
  if (!shPart) return null;
  const signedHeaders = shPart.slice('SignedHeaders='.length).split(';').filter(Boolean);

  const sigPart = parts.find((p) => p.startsWith('Signature='));
  if (!sigPart) return null;
  const signature = sigPart.slice('Signature='.length);

  return { algorithm, ...credential, signedHeaders, signature };
}

function parseCredentialValue(value: string): Pick<ParsedAuth, 'accessKey' | 'dateStr' | 'region'> | null {
  const segments = value.split('/');
  if (segments.length < 5) return null;
  if (segments[3] !== ServiceName || segments[4] !== 'aws4_request') return null;
  return { accessKey: segments[0], dateStr: segments[1], region: segments[2] };
}

function buildCanonicalRequest(params: {
  method: string;
  pathname: string;
  queryString: string;
  headers: Record<string, string | undefined>;
  signedHeaders: string[];
  payloadHash: string;
  excludedQueryKeys?: Set<string>;
}): string {
  return [
    params.method.toUpperCase(),
    normalizeCanonicalPath(params.pathname),
    buildCanonicalQueryString(params.queryString, params.excludedQueryKeys),
    buildCanonicalHeaders(params.headers, params.signedHeaders),
    params.signedHeaders.map((h) => h.toLowerCase()).sort().join(';'),
    params.payloadHash,
  ].join('\n');
}

function signCanonicalRequest(params: {
  secretAccessKey: string;
  dateStamp: string;
  region: string;
  amzDate: string;
  credentialScope: string;
  canonicalRequest: string;
}): string {
  const stringToSign = [
    SigV4Algorithm,
    params.amzDate,
    params.credentialScope,
    hashHex(params.canonicalRequest),
  ].join('\n');
  const signingKey = deriveSigningKey(params.secretAccessKey, params.dateStamp, params.region);
  return hmacHex(signingKey, stringToSign);
}

function validateRequestTime(dateValue: string, allowedSkewMs: number): SigV4Result {
  const parsed = parseAmzDate(dateValue) ?? new Date(dateValue.trim());
  if (isNaN(parsed.getTime())) {
    return { ok: false, code: 'AccessDenied', message: 'Invalid date format' };
  }
  if (Math.abs(parsed.getTime() - Date.now()) > allowedSkewMs) {
    return { ok: false, code: 'RequestTimeTooSkewed', message: 'The difference between the request time and the current time is too large' };
  }
  return { ok: true, code: 'OK', message: '' };
}

function validateSessionToken(expected: string | undefined, actual: string | undefined): SigV4Result {
  if (!expected) return { ok: true, code: 'OK', message: '' };
  if (!actual) return { ok: false, code: 'AccessDenied', message: 'Missing security token' };
  if (actual !== expected) return { ok: false, code: 'InvalidToken', message: 'The provided token is malformed or otherwise invalid' };
  return { ok: true, code: 'OK', message: '' };
}

function validatePostPolicy(policy: string, now: Date): SigV4Result {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(policy, 'base64').toString('utf-8'));
  } catch {
    return { ok: false, code: 'AccessDenied', message: 'Malformed POST policy' };
  }
  if (!parsed || typeof parsed !== 'object' || !('expiration' in parsed)) {
    return { ok: false, code: 'AccessDenied', message: 'POST policy is missing expiration' };
  }
  const expiration = new Date(String((parsed as { expiration: unknown }).expiration));
  if (isNaN(expiration.getTime())) {
    return { ok: false, code: 'AccessDenied', message: 'POST policy has invalid expiration' };
  }
  if (now.getTime() > expiration.getTime()) {
    return { ok: false, code: 'AccessDenied', message: 'POST policy has expired' };
  }
  return { ok: true, code: 'OK', message: '' };
}

function normalizeFieldNames(fields: Record<string, string | undefined>): Record<string, string | undefined> {
  return Object.fromEntries(Object.entries(fields).map(([key, value]) => [key.toLowerCase(), value]));
}

function parseAmzDate(value: string): Date | null {
  const match = value.trim().match(/^(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z$/);
  if (!match) return null;
  return new Date(`${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}Z`);
}

function normalizeAmzDate(value: string): string | null {
  const trimmed = value.trim();
  if (/^\d{8}T\d{6}Z$/.test(trimmed)) return trimmed;
  const parsed = new Date(trimmed);
  if (isNaN(parsed.getTime())) return null;
  return parsed.toISOString().replace(/[:-]/g, '').split('.')[0] + 'Z';
}

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
  return createHmac('sha256', kService).update('aws4_request', 'utf-8').digest();
}

function buildCanonicalHeaders(headers: Record<string, string | undefined>, signedHeaders: string[]): string {
  return [...signedHeaders]
    .map((h) => h.toLowerCase())
    .sort()
    .map((lower) => `${lower}:${normalizeHeaderValue(headers[lower] || headers[lower.toUpperCase()] || '')}\n`)
    .join('');
}

function normalizeHeaderValue(value: string): string {
  return value.trim().replace(/\s+/g, ' ');
}

function compareCanonicalComponent(left: string, right: string): number {
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

function buildCanonicalQueryString(queryString: string, excludedKeys = new Set<string>()): string {
  if (!queryString) return '';

  const pairs: Array<{ key: string; value: string }> = [];
  for (const segment of queryString.split('&')) {
    if (!segment) continue;
    const eqIndex = segment.indexOf('=');
    const rawKey = eqIndex === -1 ? segment : segment.slice(0, eqIndex);
    const rawValue = eqIndex === -1 ? '' : segment.slice(eqIndex + 1);
    const decodedKey = decodeQueryComponent(rawKey);
    if (excludedKeys.has(decodedKey)) continue;
    pairs.push({
      key: encodeRfc3986(decodedKey),
      value: encodeRfc3986(decodeQueryComponent(rawValue)),
    });
  }

  return pairs
    .sort((a, b) => (a.key === b.key ? compareCanonicalComponent(a.value, b.value) : compareCanonicalComponent(a.key, b.key)))
    .map(({ key, value }) => `${key}=${value}`)
    .join('&');
}

function decodeQueryComponent(value: string): string {
  try {
    return decodeURIComponent(value.replace(/\+/g, '%20'));
  } catch {
    return value;
  }
}

function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}

function normalizeCanonicalPath(pathname: string): string {
  return pathname || '/';
}

function safeSignatureEquals(actual: string, expected: string): boolean {
  const actualBuf = Buffer.from(actual, 'hex');
  const expectedBuf = Buffer.from(expected, 'hex');
  return actualBuf.length === expectedBuf.length && timingSafeEqual(actualBuf, expectedBuf);
}

export interface SigV4Params {
  method: string;
  pathname: string;
  queryString?: string;
  headers: Record<string, string | undefined>;
  body: Buffer | null;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface PostPolicySigV4Params {
  fields: Record<string, string | undefined>;
  secretAccessKey: string;
  sessionToken?: string;
  now?: Date;
}

export interface SigV4Result {
  ok: boolean;
  code: string;
  message: string;
  accessKey?: string;
  region?: string;
}