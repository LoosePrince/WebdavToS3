/**
 * S3 通道端到端测试：上传 → 验证 → 下载 → 删除 → 验证删除
 *
 * 用法：npx tsx test/s3-upload-delete.ts
 * 前置条件：服务已运行（config 中配置了 123pan 租户）
 */

import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand, DeleteObjectCommand, NoSuchKey } from '@aws-sdk/client-s3';
import { randomBytes } from 'node:crypto';
import { createWriteSheet, unlinkSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const ENDPOINT = 'http://127.0.0.1:9000';
const REGION = 'us-east-1';
const BUCKET = '123pan';
const ACCESS_KEY = 'AKIA123PAN001';
const SECRET_KEY = 'm0ckS3cr3tK3yF0r123P4nD4vC0nn3ct';

// ─── helpers ──────────────────────────────────────────────────

function assert(cond: boolean, msg: string): asserts cond {
  if (!cond) throw new Error('ASSERT FAIL: ' + msg);
}

let pass = 0;
let fail = 0;

function ok(label: string) {
  pass++;
  console.log(`  ✓ ${label}`);
}

function err(label: string, e: unknown) {
  fail++;
  const m = e instanceof Error ? e.message : String(e);
  console.log(`  ✗ ${label}: ${m}`);
}

// ─── main ─────────────────────────────────────────────────────

const s3 = new S3Client({
  endpoint: ENDPOINT,
  region: REGION,
  credentials: { accessKeyId: ACCESS_KEY, secretAccessKey: SECRET_KEY },
  forcePathStyle: true,
});

// Generate a unique test key so runs don't collide
const testId = randomBytes(4).toString('hex');
const testKey = `__s3test_${testId}.bin`;
const tmpFile = join(tmpdir(), testKey);

// Small content
const content = Buffer.from(`WebDAV-to-S3 test ${testId} at ${new Date().toISOString()}`);
const largeContent = randomBytes(64 * 1024); // 64 KB

async function main() {
  console.log(`\nS3 Gateway Test — endpoint=${ENDPOINT} bucket=${BUCKET}`);
  console.log(`Test key: ${testKey}\n`);

  // ── 1. PutObject (small) ───────────────────────────────────
  console.log('1. PutObject (small file)');
  try {
    await s3.send(new PutObjectCommand({
      Bucket: BUCKET,
      Key: testKey,
      Body: content,
      ContentType: 'text/plain',
    }));
    ok('uploaded');
  } catch (e) { err('upload', e); }

  // ── 2. HeadObject ──────────────────────────────────────────
  console.log('2. HeadObject');
  try {
    const h = await s3.send(new HeadObjectCommand({ Bucket: BUCKET, Key: testKey }));
    assert(h.ContentLength === content.length, `length ${h.ContentLength} !== ${content.length}`);
    ok(`exists, size=${h.ContentLength} etag=${h.ETag}`);
  } catch (e) { err('head', e); }

  // ── 3. GetObject ───────────────────────────────────────────
  console.log('3. GetObject');
  try {
    const g = await s3.send(new GetObjectCommand({ Bucket: BUCKET, Key: testKey }));
    const body = await streamToBuffer(g.Body as any);
    assert(body.length === content.length, `body length mismatch`);
    assert(body.toString() === content.toString(), 'body content mismatch');
    ok(`downloaded, size=${body.length}`);
  } catch (e) { err('get', e); }

  // ── 4. PutObject (64 KB) ───────────────────────────────────
  console.log('4. PutObject (64 KB file)');
  try {
    await s3.send(new PutObjectCommand({
      Bucket: BUCKET,
      Key: testKey + '_large',
      Body: largeContent,
    }));
    ok('uploaded 64 KB');
  } catch (e) { err('upload large', e); }

  // ── 5. HeadObject (large) ──────────────────────────────────
  console.log('5. HeadObject (large)');
  try {
    const h = await s3.send(new HeadObjectCommand({ Bucket: BUCKET, Key: testKey + '_large' }));
    assert(h.ContentLength === largeContent.length, `size ${h.ContentLength} !== ${largeContent.length}`);
    ok(`exists, size=${h.ContentLength}`);
  } catch (e) { err('head large', e); }

  // ── 6. DeleteObject (large) ────────────────────────────────
  console.log('6. DeleteObject (large)');
  try {
    await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: testKey + '_large' }));
    ok('deleted large');
  } catch (e) { err('delete large', e); }

  // ── 7. HeadObject after delete → 404 ───────────────────────
  console.log('7. HeadObject after delete (expect 404)');
  try {
    await s3.send(new HeadObjectCommand({ Bucket: BUCKET, Key: testKey + '_large' }));
    err('large still exists after delete', 'expected NotFound');
  } catch (e: any) {
    if (e.name === 'NotFound' || e.name === 'NoSuchKey') {
      ok('confirmed deleted (NotFound)');
    } else {
      err('head after delete', e);
    }
  }

  // ── 8. DeleteObject (small) ────────────────────────────────
  console.log('8. DeleteObject (small)');
  try {
    await s3.send(new DeleteObjectCommand({ Bucket: BUCKET, Key: testKey }));
    ok('deleted');
  } catch (e) { err('delete', e); }

  // ── 9. HeadObject after all deletes ────────────────────────
  console.log('9. HeadObject after delete (expect 404)');
  try {
    await s3.send(new HeadObjectCommand({ Bucket: BUCKET, Key: testKey }));
    err('still exists after delete', 'expected NotFound');
  } catch (e: any) {
    if (e.name === 'NotFound' || e.name === 'NoSuchKey') {
      ok('confirmed deleted (NotFound)');
    } else {
      err('head after delete', e);
    }
  }

  // ── Result ─────────────────────────────────────────────────
  const total = pass + fail;
  console.log(`\n━━━━━━━━━━━━━━━━━━━━━━━`);
  console.log(`  ${pass}/${total} passed`);
  if (fail > 0) console.log(`  ${fail} FAILURES`);
  console.log(`━━━━━━━━━━━━━━━━━━━━━━━\n`);
  process.exit(fail > 0 ? 1 : 0);
}

function streamToBuffer(stream: any): Promise<Buffer> {
  const chunks: Buffer[] = [];
  return new Promise((resolve, reject) => {
    stream.on('data', (c: Buffer) => chunks.push(c));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

main().catch((e) => {
  console.error('FATAL:', e);
  process.exit(1);
});