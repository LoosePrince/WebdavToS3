import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

export function hmacSha256(key: Buffer | string, data: string): Buffer {
  return createHmac('sha256', key).update(data, 'utf-8').digest();
}

export function sha256Hex(data: string): string {
  return createHash('sha256').update(data, 'utf-8').digest('hex');
}

export function constantTimeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf-8');
  const bufB = Buffer.from(b, 'utf-8');
  if (bufA.length !== bufB.length) {
    // Do a comparison anyway to avoid leaking length difference
    timingSafeEqual(bufA, bufA);
    return false;
  }
  return timingSafeEqual(bufA, bufB);
}