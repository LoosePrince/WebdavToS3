export interface Tenant {
  id: string;
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  upstreams: Map<string, UpstreamBinding>;
  buckets: Map<string, BucketBinding>;
}

export interface UpstreamBinding {
  id: string;
  endpoint: string;
  username: string;
  password: string;
  rejectUnauthorized: boolean;
  connectTimeoutMs: number;
  requestTimeoutMs: number;
}

export interface BucketBinding {
  name: string;
  upstreamId: string;
  rootPath: string;
  region: string;
}

export class TenantRegistry {
  private readonly _byAccessKey = new Map<string, Tenant>();

  add(tenant: Tenant) {
    this._byAccessKey.set(tenant.accessKeyId, tenant);
  }

  findByAccessKey(accessKey: string): Tenant | undefined {
    return this._byAccessKey.get(accessKey);
  }

  get allTenants(): Tenant[] {
    return [...this._byAccessKey.values()];
  }

  clear() {
    this._byAccessKey.clear();
  }
}