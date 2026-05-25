import { randomBytes } from 'node:crypto';

export function generateAdminKey(): string {
  return randomBytes(16).toString('hex');
}