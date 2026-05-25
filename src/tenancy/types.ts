export interface UpstreamBinding {
  id: string;
  endpoint: string;
  username: string;
  password: string;
  rejectUnauthorized: boolean;
}

export interface BucketBinding {
  name: string;
  upstreamId: string;
  rootPath: string;
  region: string;
}

export interface Tenant {
  id: string;
  accessKeyId: string;
  secretAccessKey: string;
  upstreams: UpstreamBinding[];
  buckets: BucketBinding[];
}

export interface ResolvedBucket {
  tenant: Tenant;
  bucket: BucketBinding;
  upstream: UpstreamBinding;
}