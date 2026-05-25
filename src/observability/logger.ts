/* eslint-disable no-console */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

let _minLevel: LogLevel = (process.env.LOG_LEVEL as LogLevel) || 'info';

export function setLogLevel(level: LogLevel) {
  _minLevel = level;
}

function shouldLog(level: LogLevel): boolean {
  return LOG_LEVELS[level] >= LOG_LEVELS[_minLevel];
}

export interface LogEntry {
  level: LogLevel;
  msg: string;
  requestId?: string;
  tenantId?: string;
  s3Operation?: string;
  bucket?: string;
  key?: string;
  method?: string;
  statusCode?: number;
  durationMs?: number;
  upstreamMethod?: string;
  upstreamStatusCode?: number;
  upstreamDurationMs?: number;
  errorCode?: string;
  bytesIn?: number;
  bytesOut?: number;
  [key: string]: unknown;
}

function writeLog(entry: LogEntry) {
  const timestamp = new Date().toISOString();
  const line = JSON.stringify({ timestamp, ...entry });
  const dest = entry.level === 'error' ? process.stderr : process.stdout;
  dest.write(line + '\n');
}

export function debug(msg: string, meta?: Partial<LogEntry>) {
  if (shouldLog('debug')) writeLog({ level: 'debug', msg, ...meta });
}

export function info(msg: string, meta?: Partial<LogEntry>) {
  if (shouldLog('info')) writeLog({ level: 'info', msg, ...meta });
}

export function warn(msg: string, meta?: Partial<LogEntry>) {
  if (shouldLog('warn')) writeLog({ level: 'warn', msg, ...meta });
}

export function error(msg: string, meta?: Partial<LogEntry>) {
  if (shouldLog('error')) writeLog({ level: 'error', msg, ...meta });
}