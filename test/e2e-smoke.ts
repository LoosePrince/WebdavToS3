/**
 * Quick end-to-end test: send a SigV4-signed request to our gateway.
 *
 * Usage: npx tsx test/e2e-smoke.ts
 */
import { createHash, createHmac } from "node:crypto";
import { request } from "node:http";

const GATEWAY = "http://127.0.0.1:9000";

const credentials = {
  accessKeyId: "test-access-key",
  secretAccessKey: "test-secret-key",
  region: "us-east-1",
};

function sign(method: string, path: string, headers: Record<string, string>, body: string) {
  const amzDate = new Date().toISOString().replace(/[:-]/g, "").split(".")[0] + "Z";
  const dateStamp = amzDate.slice(0, 8);

  const allHeaders: Record<string, string> = {
    host: "127.0.0.1:9000",
    "x-amz-date": amzDate,
    "x-amz-content-sha256": createHash("sha256").update(body).digest("hex"),
    ...headers,
  };

  const signedHeaders = Object.keys(allHeaders).sort().map(h => h.toLowerCase()).join(";");

  const canonicalHeaders = Object.keys(allHeaders)
    .sort()
    .map(k => `${k.toLowerCase()}:${allHeaders[k]!.trim()}\n`)
    .join("");

  const canonicalRequest = [
    method,
    path,
    "",
    canonicalHeaders,
    signedHeaders,
    allHeaders["x-amz-content-sha256"],
  ].join("\n");

  const hashedCanonical = createHash("sha256").update(canonicalRequest).digest("hex");

  const credentialScope = `${dateStamp}/${credentials.region}/s3/aws4_request`;

  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    hashedCanonical,
  ].join("\n");

  const dateKey = createHmac("sha256", `AWS4${credentials.secretAccessKey}`).update(dateStamp).digest();
  const regionKey = createHmac("sha256", dateKey).update(credentials.region).digest();
  const serviceKey = createHmac("sha256", regionKey).update("s3").digest();
  const signingKey = createHmac("sha256", serviceKey).update("aws4_request").digest();
  const signature = createHmac("sha256", signingKey).update(stringToSign).digest("hex");

  const authHeader = `AWS4-HMAC-SHA256 Credential=${credentials.accessKeyId}/${credentialScope},SignedHeaders=${signedHeaders},Signature=${signature}`;

  return {
    headers: { ...allHeaders, Authorization: authHeader },
    body,
  };
}

function requestPromise(method: string, path: string, body: string): Promise<{ status: number; headers: Record<string, string>; data: string }> {
  return new Promise((resolve, reject) => {
    const sig = sign(method, path, {}, body);
    const url = new URL(GATEWAY);
    const req = request(
      {
        hostname: url.hostname,
        port: Number(url.port),
        path,
        method,
        headers: sig.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode ?? 0,
            headers: res.headers as Record<string, string>,
            data: Buffer.concat(chunks).toString("utf-8"),
          });
        });
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

async function main() {
  console.log("\n=== ListBuckets (GET /) ===");
  let res = await requestPromise("GET", "/", "");
  console.log(`Status: ${res.status}`);
  console.log(`Body: ${res.data.slice(0, 500)}\n`);

  if (res.status !== 200) {
    console.log("ListBuckets failed - aborting.");
    process.exit(1);
  }

  console.log("=== HeadBucket ===");
  res = await requestPromise("HEAD", "/test-bucket", "");
  console.log(`Status: ${res.status}\n`);

  console.log("=== ListObjectsV2 ===");
  res = await requestPromise("GET", "/test-bucket?list-type=2", "");
  console.log(`Status: ${res.status}`);
  console.log(`Body: ${res.data.slice(0, 500)}\n`);

  console.log("=== HeadObject ===");
  res = await requestPromise("HEAD", "/test-bucket/some-key.txt", "");
  console.log(`Status: ${res.status}\n`);

  console.log("\n=== All smoke tests completed ===");
}

main().catch(console.error);