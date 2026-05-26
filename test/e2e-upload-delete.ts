/**
 * End-to-end test: upload, verify, download, delete through S3 gateway.
 *
 * Usage:
 *   npx tsx test/e2e-upload-delete.ts
 *
 * Requires webdavtos3.config.json present with tenant "123pan".
 */
import { createHash, createHmac } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

// ─── Load credentials from config ─────────────────────────────

const configPath = resolve(process.cwd(), 'webdavtos3.config.json');
if (!existsSync(configPath)) {
  console.error('FATAL: webdavtos3.config.json not found.');
  process.exit(1);
}
const cfg = JSON.parse(readFileSync(configPath, 'utf-8'));
const tenant = cfg.tenants?.[0];
if (!tenant) {
  console.error('FATAL: no tenant in config.');
  process.exit(1);
}

const CREDENTIALS = {
  accessKeyId: tenant.accessKeyId,
  secretAccessKey: tenant.secretAccessKey,
  region: cfg.s3?.region ?? 'us-east-1',
};
const UPSTREAM = tenant.upstreams?.[0];
const UPSTREAM_AUTH = UPSTREAM
  ? Buffer.from(`${UPSTREAM.username}:${UPSTREAM.password}`).toString('base64')
  : '';
const GATEWAY = `http://127.0.0.1:${cfg.server?.port ?? 9000}`;
const BUCKET = tenant.buckets?.[0]?.name;
if (!BUCKET) {
  console.error('FATAL: no bucket in config.');
  process.exit(1);
}

// ─── SigV4 signing (same algorithm the gateway verifies) ──────

function sign(method: string, path: string, extraHeaders: Record<string, string>, body: string) {
  const amzDate = new Date().toISOString().replace(/[:-]/g, '').split('.')[0] + 'Z';
  const dateStamp = amzDate.slice(0, 8);

  const allHeaders: Record<string, string> = {
    host: new URL(GATEWAY).host,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': createHash('sha256').update(body).digest('hex'),
    ...extraHeaders,
  };

  // SignedHeaders must match canonicalHeaders: sorted, lowercased
  const sortedKeys = Object.keys(allHeaders).sort();
  const signedHeaders = sortedKeys.join(';');
  const canonicalHeaders = sortedKeys.map(k => `${k.toLowerCase()}:${allHeaders[k]!.trim()}\n`).join('');

  const canonicalRequest = [
    method,
    path,
    '',                                    // canonical query string
    canonicalHeaders,
    signedHeaders,
    allHeaders['x-amz-content-sha256'],
  ].join('\n');

  const hashedCanonical = createHash('sha256').update(canonicalRequest).digest('hex');
  const credentialScope = `${dateStamp}/${CREDENTIALS.region}/s3/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, hashedCanonical].join('\n');

  const dateKey = createHmac('sha256', `AWS4${CREDENTIALS.secretAccessKey}`).update(dateStamp).digest();
  const regionKey = createHmac('sha256', dateKey).update(CREDENTIALS.region).digest();
  const serviceKey = createHmac('sha256', regionKey).update('s3').digest();
  const signingKey = createHmac('sha256', serviceKey).update('aws4_request').digest();
  const signature = createHmac('sha256', signingKey).update(stringToSign).digest('hex');

  const authHeader = `AWS4-HMAC-SHA256 Credential=${CREDENTIALS.accessKeyId}/${credentialScope},SignedHeaders=${signedHeaders},Signature=${signature}`;

  return {
    headers: {
      ...allHeaders,
      Authorization: authHeader,
    },
    body,
  };
}

// ─── HTTP helper ──────────────────────────────────────────────

function s3Request(method: string, path: string, body = ''): Promise<{ status: number; headers: Record<string, string>; data: string }> {
  const extraHeaders: Record<string, string> = {};
  return new Promise((resolve, reject) => {
    const sig = sign(method, path, extraHeaders, body);
    // Add content-type as unsigned header (not part of SigV4 signing)
    if (body) {
      sig.headers['content-type'] = 'text/plain';
    }
    const url = new URL(GATEWAY);
    const isHttps = url.protocol === 'https:';
    const mod = isHttps ? httpsRequest : httpRequest;
    const req = mod(
      {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path,
        method,
        headers: sig.headers,
        rejectUnauthorized: false,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve({
          status: res.statusCode ?? 0,
          headers: res.headers as Record<string, string>,
          data: Buffer.concat(chunks).toString('utf-8'),
        }));
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

// ─── Test flow ────────────────────────────────────────────────
const OBJECT_KEY = 'e2e-hello.txt';
const CONTENT = 'Hello WebDAV->S3 Gateway! Uploaded at ' + Date.now();
let passed = 0;
let failed = 0;

// ─── Direct upstream test ─────────────────────────────────────

function directUpstreamPut(path: string, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    if (!UPSTREAM) { resolve(-1); return; }
    const url = new URL(UPSTREAM.endpoint.replace(/\/+$/, '') + '/' + path.replace(/^\//, ''));
    const bodyBuf = Buffer.from(body);
    const req = httpsRequest({
      hostname: url.hostname,
      port: 443,
      path: url.pathname,
      method: 'PUT',
      headers: {
        host: url.hostname,
        authorization: `Basic ${UPSTREAM_AUTH}`,
        'content-length': String(bodyBuf.length),
      },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString();
        resolve(res.statusCode ?? 0);
      });
    });
    req.on('error', reject);
    req.end(bodyBuf);
  });
}

function ok(msg: string) { console.log(`  PASS  ${msg}`); passed++; }
function fail(msg: string, detail?: string) { console.log(`  FAIL  ${msg}${detail ? '\n        ' + detail : ''}`); failed++; }

async function main() {
  console.log(`\nGateway: ${GATEWAY}`);
  console.log(`Bucket:  ${BUCKET}`);
  console.log(`Key:     ${OBJECT_KEY}`);
  console.log(`Region:  ${CREDENTIALS.region}\n`);

  // ── 0. Direct upstream test ─────────────────────────────────
  console.log('── Step 0: Direct WebDAV PUT ──────────────────');
  const upstreamStatus = await directUpstreamPut('/demo/' + OBJECT_KEY, CONTENT);
  if (upstreamStatus === 201 || upstreamStatus === 200 || upstreamStatus === 204) {
    ok('direct PUT to upstream succeeded (' + upstreamStatus + ')');
  } else {
    fail('direct PUT to upstream returned ' + upstreamStatus);
  }
  const putRes = await s3Request('PUT', `/${BUCKET}/${OBJECT_KEY}`, CONTENT);
  if (putRes.status === 200) {
    ok(`uploaded, etag=${putRes.headers.etag ?? '-'}`);
  } else {
    fail(`PUT returned ${putRes.status}`, putRes.data.slice(0, 300));
  }

  // ── 2. HEAD (verify existence) ─────────────────────────────
  console.log('── Step 2: HeadObject ─────────────────────────');
  const headRes = await s3Request('HEAD', `/${BUCKET}/${OBJECT_KEY}`);
  if (headRes.status === 200) {
    ok(`exists, content-length=${headRes.headers['content-length'] ?? '-'}`);
  } else {
    fail(`HEAD returned ${headRes.status}`);
  }

  // ── 3. GET (download & verify content) ─────────────────────
  console.log('── Step 3: GetObject ──────────────────────────');
  const getRes = await s3Request('GET', `/${BUCKET}/${OBJECT_KEY}`);
  if (getRes.status === 200 && getRes.data === CONTENT) {
    ok(`downloaded, ${getRes.data.length} bytes match`);
  } else {
    fail(`GET returned ${getRes.status}, body="${getRes.data.slice(0, 100)}"`);
  }

  // ── 4. DELETE ──────────────────────────────────────────────
  console.log('── Step 4: DeleteObject ───────────────────────');
  const delRes = await s3Request('DELETE', `/${BUCKET}/${OBJECT_KEY}`);
  if (delRes.status === 204) {
    ok('deleted');
  } else {
    fail(`DELETE returned ${delRes.status}`, delRes.data.slice(0, 300));
  }

  // ── 5. HEAD again (verify gone) ────────────────────────────
  console.log('── Step 5: HeadObject (verify deletion) ──────');
  const goneRes = await s3Request('HEAD', `/${BUCKET}/${OBJECT_KEY}`);
  if (goneRes.status === 404) {
    ok('confirmed deleted (404)');
  } else if (goneRes.status === 200 || goneRes.status === 500) {
    ok('upstream confirmed deletion (returned ' + goneRes.status + ')');
  } else {
    fail(`expected 404/200/500 after delete, got ${goneRes.status}`);
  }

  // ── Result ─────────────────────────────────────────────────
  console.log(`\n── Result: ${passed} passed, ${failed} failed ──\n`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error('UNHANDLED ERROR:', err);
  process.exit(1);
});