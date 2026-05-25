import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { AppConfigSchema, type AppConfig } from './schema.js';

const CONFIG_ENV_VAR = 'WEBDAVTOS3_CONFIG';
const DEFAULT_CONFIG_PATH = 'webdavtos3.config.json';

function resolveConfigPath(): string {
  const envPath = process.env[CONFIG_ENV_VAR];
  if (envPath) return resolve(process.cwd(), envPath);
  return resolve(process.cwd(), DEFAULT_CONFIG_PATH);
}

let _cachedConfig: AppConfig | null = null;

export function loadConfig(forceReload = false): AppConfig {
  if (_cachedConfig && !forceReload) return _cachedConfig;

  const configPath = resolveConfigPath();
  if (!existsSync(configPath)) {
    throw new Error(
      `Config file not found: ${configPath}\n` +
        `Set ${CONFIG_ENV_VAR} env var or create ${DEFAULT_CONFIG_PATH} in the working directory.\n` +
        `See webdavtos3.config.example.json for a template.`,
    );
  }

  const raw = JSON.parse(readFileSync(configPath, 'utf-8'));
  const parsed = AppConfigSchema.parse(raw);
  _cachedConfig = parsed;
  return parsed;
}

export function getConfig(): AppConfig {
  if (!_cachedConfig) return loadConfig();
  return _cachedConfig;
}

export { type AppConfig } from './schema.js';