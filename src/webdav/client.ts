import * as http from 'node:http';
import * as https from 'node:https';

export interface WebdavResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: Buffer;
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
    const urlStr = this.url(resourcePath);
    const parsedUrl = new URL(urlStr);
    const isHttps = parsedUrl.protocol === 'https:';

    const headers: Record<string, string> = {
      host: parsedUrl.hostname,
      ...(opts?.headers ?? {}),
    };
    if (opts?.contentLength !== undefined) {
      headers['content-length'] = String(opts.contentLength);
    }

    // Basic auth
    const auth = Buffer.from(`${this.opts.username}:${this.opts.password}`).toString('base64');
    headers['authorization'] = `Basic ${auth}`;

    const mod = isHttps ? https : http;

    const doRequest = (url: URL, redirectCount = 0): Promise<WebdavResponse> => {
      const targetIsHttps = url.protocol === 'https:';
      const targetMod = targetIsHttps ? https : http;

      return new Promise((resolve, reject) => {
        const authHeader = headers['authorization'] ?? `Basic ${Buffer.from(`${this.opts.username}:${this.opts.password}`).toString('base64')}`;
        const reqHeaders: Record<string, string> = { ...headers, host: url.hostname };
        if (opts?.contentLength !== undefined) {
          reqHeaders['content-length'] = String(opts.contentLength);
        }

        const req = targetMod.request(
          {
            hostname: url.hostname,
            port: targetIsHttps ? 443 : 80,
            path: url.pathname + url.search,
            method,
            headers: reqHeaders,
            rejectUnauthorized: this.opts.rejectUnauthorized,
            timeout: this.opts.requestTimeoutMs,
          },
          (res) => {
            const status = res.statusCode ?? 0;
            // Follow redirects (up to 5 hops)
            if ((status === 301 || status === 302 || status === 307 || status === 308) && redirectCount < 5) {
              const location = res.headers['location'];
              if (location) {
                const redirectUrl = location.startsWith('http') ? new URL(location) : new URL(url.origin + location);
                resolve(doRequest(redirectUrl, redirectCount + 1));
                return;
              }
            }
            const chunks: Buffer[] = [];
            res.on('data', (c: Buffer) => chunks.push(c));
            res.on('end', () => {
              resolve({
                statusCode: status,
                headers: Object.fromEntries(
                  Object.entries(res.headers).map(([k, v]) => [k.toLowerCase(), String(v ?? '')]),
                ),
                body: Buffer.concat(chunks),
              });
            });
          },
        );
        req.on('error', reject);

        if (opts?.body) {
          if (Buffer.isBuffer(opts.body)) {
            req.end(opts.body);
          } else {
            (opts.body as NodeJS.ReadableStream).pipe(req);
          }
        } else {
          req.end();
        }
      });
    };

    return doRequest(parsedUrl);
  }

  async ensureCollection(resourcePath: string): Promise<void> {
    const resp = await this.mkcol(resourcePath);
    if (resp.statusCode === 201 || resp.statusCode === 405) return;
    if (resp.statusCode === 409 || resp.statusCode === 404) {
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
    const body = collectBody(resp.body);
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

function collectBody(body: Buffer): string {
  return body.toString('utf-8');
}