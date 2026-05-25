import type { FastifyReply } from "fastify";
import { AppError } from "./app-error.js";

export function s3ErrorXml(httpStatus: number, code: string, message: string, resource: string | null, requestId: string): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>${escapeXml(code)}</Code>
  <Message>${escapeXml(message)}</Message>
  ${resource ? `  <Resource>${escapeXml(resource)}</Resource>\n` : ""}  <RequestId>${escapeXml(requestId)}</RequestId>
</Error>`;
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

export function sendS3Error(reply: FastifyReply, error: AppError, requestId: string): void {
  const body = s3ErrorXml(error.httpStatus, error.s3Code, error.message, error.resource, requestId);
  reply.status(error.httpStatus).type("application/xml").send(body);
}