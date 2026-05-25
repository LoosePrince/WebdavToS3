export interface S3ErrorCode {
  httpStatus: number;
  code: string;
}

const ERROR_CODES: Record<string, S3ErrorCode> = {
  AccessDenied: { httpStatus: 403, code: "AccessDenied" },
  NoSuchBucket: { httpStatus: 404, code: "NoSuchBucket" },
  NoSuchKey: { httpStatus: 404, code: "NoSuchKey" },
  NotFound: { httpStatus: 404, code: "NotFound" },
  InvalidRequest: { httpStatus: 400, code: "InvalidRequest" },
  InvalidRange: { httpStatus: 416, code: "InvalidRange" },
  SignatureDoesNotMatch: { httpStatus: 403, code: "SignatureDoesNotMatch" },
  PreconditionFailed: { httpStatus: 412, code: "PreconditionFailed" },
  MethodNotAllowed: { httpStatus: 405, code: "MethodNotAllowed" },
  InternalError: { httpStatus: 500, code: "InternalError" },
  NotImplemented: { httpStatus: 501, code: "NotImplemented" },
  SlowDown: { httpStatus: 503, code: "SlowDown" },
  BucketNotEmpty: { httpStatus: 409, code: "BucketNotEmpty" },
};

export class AppError extends Error {
  readonly httpStatus: number;
  readonly s3Code: string;
  readonly resource: string | null;

  constructor(opts: {
    code: keyof typeof ERROR_CODES;
    message?: string;
    resource?: string;
    httpStatus?: number;
  }) {
    const def = ERROR_CODES[opts.code] ?? ERROR_CODES.InternalError;
    super(opts.message ?? def.code);
    this.httpStatus = opts.httpStatus ?? def.httpStatus;
    this.s3Code = def.code;
    this.resource = opts.resource ?? null;
    this.name = "AppError";
  }
}

// Fast path to create error then map upstream's HTTP status
export function fromUpstreamStatus(
  httpStatus: number,
  resource?: string,
): AppError {
  switch (httpStatus) {
    case 401:
    case 403:
      return new AppError({ code: "AccessDenied", resource });
    case 404:
      return new AppError({ code: "NoSuchKey", resource });
    case 409:
      return new AppError({ code: "BucketNotEmpty", resource });
    case 412:
      return new AppError({ code: "PreconditionFailed", resource });
    case 507:
      return new AppError({ code: "SlowDown", resource });
    default:
      if (httpStatus >= 500)
        return new AppError({ code: "InternalError", resource });
      return new AppError({
        code: "InternalError",
        message: `Upstream returned ${httpStatus}`,
        resource,
      });
  }
}