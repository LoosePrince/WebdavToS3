import { request, Dispatcher } from 'undici';

export interface WebdavResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: NodeJS.ReadableStream;
}

export interface WebdavStat {
  exists: boolean;
  etag: string;
  lastModified: string;
  contentLength: number;
  contentType: string;
}

export interface WebdavEntry {
  href: string;
  etag: string;
  lastModified: string;
  contentLength: number;
  isCollection: boolean;
}

export interface WebdavClientOptions {
  endpoint: string;
  username: string;
  password: string;
  rejectUnauthorized: boolean;
  connectTimeoutMs: number;
  requestTimeoutMs: number;
}

export class WebdavClient {
  private readonly baseUrl: URL;

  constructor(private readonly opts: WebdavClientOptions) {
    this.baseUrl = new URL(opts.endpoint);
  }

  /** Full URL for a resource path */
  url(resourcePath: string): string {
    const base = this.baseUrl.toString().replace(/\/+$/, '');
    const path = resourcePath.startsWith('/') ? resourcePath : '/' + resourcePath;
    return base + path;
  }

  async get(resourcePath: string): Promise<WebdavResponse> {
    return this.request('GET', resourcePath);
  }

  async put(resourcePath: string, body: NodeJS.ReadableStream | Buffer, contentLength?: number): Promise<WebdavResponse> {
    return this.request('PUT', resourcePath, { body, contentLength });
  }

  async delete(resourcePath: string): Promise<WebdavResponse> {
    return this.request('DELETE', resourcePath);
  }

  async head(resourcePath: string): Promise<WebdavResponse> {
    return this.request('HEAD', resourcePath);
  }

  async copy(resourcePath: string, destinationPath: string): Promise<WebdavResponse> {
    return this.request('COPY', resourcePath, {
      headers: { Destination: this.url(destinationPath), Overwrite: 'T' },
    });
  }

  async propfind(resourcePath: string, depth: '0' | '1' = '1'): Promise<WebdavResponse> {
    return this.request('PROPFIND', resourcePath, {
      headers: { Depth: depth, 'Content-Type': 'application/xml' },
      body: this.defaultPropfindBody(),
    });
  }

  async mkcol(resourcePath: string): Promise<WebdavResponse> {
    return this.request('MKCOL', resourcePath);
  }

  /** Public: allow operations to pass arbitrary headers */
  async request(
    method: string,
    resourcePath: string,
    opts?: { body?: NodeJS.ReadableStream | Buffer; headers?: Record<string, string>; contentLength?: number },
  ): Promise<WebdavResponse> {
    const url = this.url(resourcePath);
    const headers: Record<string, string> = {
      ...(opts?.headers ?? {}),
    };
    if (opts?.contentLength !== undefined) {
      headers['content-length'] = String(opts.contentLength);
    }

    // Basic auth
    const auth = Buffer.from(`${this.opts.username}:${this.opts.password}`).toString('base64');
    headers['authorization'] = `Basic ${auth}`;

    const resp = await request(url, {
      method: method as Dispatcher.HttpMethod,
      headers,
      body: opts?.body as any,
      headersTimeout: this.opts.requestTimeoutMs,
      bodyTimeout: this.opts.requestTimeoutMs,
    });

    return {
      statusCode: resp.statusCode,
      headers: Object.fromEntries(
        Object.entries(resp.headers).map(([k, v]) => [k.toLowerCase(), String(v ?? '')]),
      ),
      body: resp.body,
    };
  }

  async ensureCollection(resourcePath: string): Promise<void> {
    const resp = await this.mkcol(resourcePath);
    if (resp.statusCode === 201 || resp.statusCode === 405) return;
    if (resp.statusCode === 409) {
      const parent = resourcePath.replace(/\/[^/]+$/, '');
      if (parent && parent !== resourcePath) {
        await this.ensureCollection(parent);
        const retry = await this.mkcol(resourcePath);
        if (retry.statusCode !== 201 && retry.statusCode !== 405) {
          throw new WebdavError(`MKCOL failed: ${retry.statusCode}`, retry.statusCode);
        }
      }
    }
  }

  async stat(resourcePath: string): Promise<WebdavStat> {
    const resp = await this.propfind(resourcePath, '0');
    if (resp.statusCode === 404) {
      return { exists: false, etag: '', lastModified: '', contentLength: 0, contentType: '' };
    }
    if (resp.statusCode >= 400) {
      throw new WebdavError(`PROPFIND stat failed: ${resp.statusCode}`, resp.statusCode);
    }
    const body = await collectBody(resp.body);
    const entries = parsePropfindResponse(body);
    const entry = entries[0];
    if (!entry) {
      return { exists: false, etag: '', lastModified: '', contentLength: 0, contentType: '' };
    }
    return {
      exists: true,
      etag: entry.etag,
      lastModified: entry.lastModified,
      contentLength: entry.contentLength,
      contentType: '',
    };
  }

  async list(resourcePath: string): Promise<WebdavEntry[]> {
    const resp = await this.propfind(resourcePath, '1');
    if (resp.statusCode === 404) return [];
    if (resp.statusCode >= 400) {
      throw new WebdavError(`PROPFIND list failed: ${resp.statusCode}`, resp.statusCode);
    }
    const body = await collectBody(resp.body);
    return parsePropfindResponse(body);
  }

  private defaultPropfindBody(): Buffer {
    return Buffer.from(
      '<?xml version="1.0" encoding="utf-8"?>' +
        '<d:propfind xmlns:d="DAV:">' +
        '<d:prop><d:displayname/><d:getcontentlength/><d:getcontenttype/>' +
        '<d:getetag/><d:getlastmodified/><d:resourcetype/></d:prop>' +
        '</d:propfind>',
    );
  }
}

export class WebdavError extends Error {
  constructor(
    msg: string,
    public readonly statusCode: number,
  ) {
    super(msg);
    this.name = 'WebdavError';
  }
}

// --- PROPFIND response parser ---

function parsePropfindResponse(xml: string): WebdavEntry[] {
  const entries: WebdavEntry[] = [];
  const responseRegex = /<d:response[^>]*>([\s\S]*?)<\/d:response>/gi;
  let match: RegExpExecArray | null;

  while ((match = responseRegex.exec(xml)) !== null) {
    const block = match[1];
    const href = extractTag(block, 'd:href') || '';
    const etag = extractTag(block, 'd:getetag') || '';
    const lastModified = extractTag(block, 'd:getlastmodified') || '';
    const contentLength = parseInt(extractTag(block, 'd:getcontentlength') || '0', 10);
    const isCollection = block.includes('d:collection');
    entries.push({ href, etag, lastModified, contentLength, isCollection });
  }
  return entries;
}

function extractTag(xml: string, tagName: string): string {
  const regex = new RegExp(`<${tagName}[^>]*>([^<]*)</${tagName}>`, 'i');
  const m = regex.exec(xml);
  return m ? m[1].trim() : '';
}

function collectBody(stream: NodeJS.ReadableStream): Promise<string> {
  const chunks: Buffer[] = [];
  return new Promise((resolve, reject) => {
    stream.on('data', (chunk: Buffer) => chunks.push(chunk));
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf-8')));
    stream.on('error', reject);
  });
}