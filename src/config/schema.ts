import { z } from 'zod';

const WebdavUpstreamSchema = z.object({
  id: z.string().min(1),
  endpoint: z.string().url(),
  username: z.string().min(1),
  password: z.string().min(1),
  rejectUnauthorized: z.boolean().default(true),
  connectTimeoutMs: z.number().positive().default(10000),
  requestTimeoutMs: z.number().positive().default(120000),
});

const BucketBindingSchema = z.object({
  name: z.string().min(1),
  upstreamId: z.string().min(1),
  rootPath: z.string().min(1),
  region: z.string().default('us-east-1'),
});

const TenantConfigSchema = z.object({
  id: z.string().min(1),
  accessKeyId: z.string().min(1),
  secretAccessKey: z.string().min(1),
  sessionToken: z.string().min(1).optional(),
  upstreams: z.array(WebdavUpstreamSchema).min(1),
  buckets: z.array(BucketBindingSchema).min(1),
});

const ServerConfigSchema = z.object({
  host: z.string().default('0.0.0.0'),
  port: z.number().int().positive().default(9000),
  trustProxy: z.boolean().default(true),
  maxObjectSizeBytes: z.number().positive().default(5 * 1024 ** 3),
  requestTimeoutMs: z.number().positive().default(300000),
});

const S3ConfigSchema = z.object({
  region: z.string().default('us-east-1'),
});

const LifecycleConfigSchema = z.object({
  enabled: z.boolean().default(false),
  intervalMs: z.number().positive().default(3600000),
  expireNoncurrentVersionsAfterMs: z.number().positive().optional(),
  expireDeleteMarkersAfterMs: z.number().positive().optional(),
});

export const AppConfigSchema = z.object({
  server: ServerConfigSchema.optional().default({
    host: '0.0.0.0',
    port: 9000,
    trustProxy: true,
    maxObjectSizeBytes: 5 * 1024 ** 3,
    requestTimeoutMs: 300000,
  }),
  s3: S3ConfigSchema.optional().default({ region: 'us-east-1' }),
  lifecycle: LifecycleConfigSchema.optional().default({ enabled: false, intervalMs: 3600000 }),
  tenants: z.array(TenantConfigSchema).min(1),
});

export type AppConfig = z.infer<typeof AppConfigSchema>;
export type TenantConfig = z.infer<typeof TenantConfigSchema>;
export type WebdavUpstreamConfig = z.infer<typeof WebdavUpstreamSchema>;
export type BucketBindingConfig = z.infer<typeof BucketBindingSchema>;