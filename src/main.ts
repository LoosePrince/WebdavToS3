import { buildApp } from './http/app.js';
import { loadConfig } from './config/index.js';
import { generateAdminKey } from './admin/key.js';
import {
  TenantRegistry,
  type Tenant,
  type UpstreamBinding,
  type BucketBinding,
} from './tenancy/tenant-registry.js';
import { info, error } from './observability/logger.js';
import { startLifecycleWorker } from './s3/lifecycle/worker.js';
import { createStorageBackendFactory } from './s3/storage-backend.js';

function buildTenantRegistry(): TenantRegistry {
  const config = loadConfig();
  const registry = new TenantRegistry();

  for (const tc of config.tenants) {
    const upstreams = new Map<string, UpstreamBinding>();
    for (const uc of tc.upstreams) {
      upstreams.set(uc.id, {
        id: uc.id,
        endpoint: uc.endpoint,
        username: uc.username,
        password: uc.password,
        rejectUnauthorized: uc.rejectUnauthorized,
        connectTimeoutMs: uc.connectTimeoutMs,
        requestTimeoutMs: uc.requestTimeoutMs,
      });
    }

    const buckets = new Map<string, BucketBinding>();
    for (const bc of tc.buckets) {
      buckets.set(bc.name, {
        name: bc.name,
        upstreamId: bc.upstreamId,
        rootPath: bc.rootPath,
        region: bc.region,
      });
    }

    const tenant: Tenant = {
      id: tc.id,
      accessKeyId: tc.accessKeyId,
      secretAccessKey: tc.secretAccessKey,
      sessionToken: tc.sessionToken,
      upstreams,
      buckets,
    };

    registry.add(tenant);
    info('tenant registered', { tenantId: tenant.id, buckets: tenant.buckets.size });
  }

  return registry;
}

async function main() {
  try {
    const config = loadConfig();
    const tenantRegistry = buildTenantRegistry();
    const adminKey = generateAdminKey();

    const storageBackendFactory = createStorageBackendFactory({ metadata: config.metadata });
    const app = buildApp({ tenantRegistry, adminKey, storageBackendFactory });
    startLifecycleWorker(tenantRegistry, config.lifecycle, storageBackendFactory);

    await app.listen({
      host: config.server.host,
      port: config.server.port,
    });

    info('server started', {
      host: config.server.host,
      port: config.server.port,
      tenants: tenantRegistry.allTenants.length,
      adminUrl: `http://${config.server.host === '0.0.0.0' ? '127.0.0.1' : config.server.host}:${config.server.port}/admin/${adminKey}`,
    });
  } catch (err) {
    error('failed to start server', { error: String(err) });
    process.exit(1);
  }
}

main();