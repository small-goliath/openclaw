import type { DatabaseSync } from "node:sqlite";
import {
  getEncryptionService,
  getOrInitEncryption,
  createEncryptionConfigFromEnv,
  type EncryptedData,
} from "../security/encryption.js";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("memory/schema");

/**
 * Initialize encryption service for memory operations
 */
function ensureEncryptionService() {
  let service = getEncryptionService();
  if (!service) {
    const config = createEncryptionConfigFromEnv();
    service = getOrInitEncryption(config);
  }
  return service;
}

/**
 * Check if encryption is enabled for memory data
 */
export function isMemoryEncryptionEnabled(): boolean {
  const service = ensureEncryptionService();
  return service.isEnabled();
}

/**
 * Encrypt text content for storage in SQLite.
 * Returns encrypted wrapper if encryption is enabled, otherwise returns original text.
 */
export async function encryptMemoryText(text: string): Promise<string | { encrypted: true; data: EncryptedData }> {
  const service = ensureEncryptionService();
  if (!service.isEnabled()) {
    return text;
  }

  try {
    const result = await service.encryptObject(text);
    // If encryption returned the same object (disabled), return as string
    if (typeof result === "string" || !(result as { encrypted?: boolean }).encrypted) {
      return text;
    }
    return result as { encrypted: true; data: EncryptedData };
  } catch (err) {
    log.warn("failed to encrypt memory text", { err });
    return text;
  }
}

/**
 * Decrypt text content from SQLite storage.
 * Handles both encrypted and plaintext data (backward compatible).
 */
export async function decryptMemoryText(
  stored: string | { encrypted?: boolean; data?: EncryptedData }
): Promise<string> {
  // Fast path: if it's just a string, return it
  if (typeof stored === "string") {
    return stored;
  }

  const service = ensureEncryptionService();

  try {
    const decrypted = await service.decryptObject<string>(stored);
    return decrypted;
  } catch (err) {
    log.warn("failed to decrypt memory text", { err });
    // Return original if decryption fails
    return typeof stored === "string" ? stored : JSON.stringify(stored);
  }
}

/**
 * Serialize encrypted data for SQLite storage.
 * Encrypted data is stored as JSON string.
 */
export function serializeMemoryValue(value: string | { encrypted: true; data: EncryptedData }): string {
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value);
}

/**
 * Deserialize memory value from SQLite storage.
 * Attempts to parse JSON for encrypted data.
 */
export function deserializeMemoryValue(stored: string): string | { encrypted: true; data: EncryptedData } {
  // Fast path: try to detect if it's encrypted JSON
  if (!stored.startsWith('{"encrypted":')) {
    return stored;
  }

  try {
    const parsed = JSON.parse(stored);
    if (parsed.encrypted && parsed.data) {
      return parsed as { encrypted: true; data: EncryptedData };
    }
    return stored;
  } catch {
    return stored;
  }
}

export function ensureMemoryIndexSchema(params: {
  db: DatabaseSync;
  embeddingCacheTable: string;
  ftsTable: string;
  ftsEnabled: boolean;
  enableEncryption?: boolean;
}): { ftsAvailable: boolean; ftsError?: string; encryptionEnabled: boolean } {
  params.db.exec(`
    CREATE TABLE IF NOT EXISTS meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
  `);
  params.db.exec(`
    CREATE TABLE IF NOT EXISTS files (
      path TEXT PRIMARY KEY,
      source TEXT NOT NULL DEFAULT 'memory',
      hash TEXT NOT NULL,
      mtime INTEGER NOT NULL,
      size INTEGER NOT NULL
    );
  `);
  params.db.exec(`
    CREATE TABLE IF NOT EXISTS chunks (
      id TEXT PRIMARY KEY,
      path TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'memory',
      start_line INTEGER NOT NULL,
      end_line INTEGER NOT NULL,
      hash TEXT NOT NULL,
      model TEXT NOT NULL,
      text TEXT NOT NULL,
      embedding TEXT NOT NULL,
      updated_at INTEGER NOT NULL
    );
  `);
  params.db.exec(`
    CREATE TABLE IF NOT EXISTS ${params.embeddingCacheTable} (
      provider TEXT NOT NULL,
      model TEXT NOT NULL,
      provider_key TEXT NOT NULL,
      hash TEXT NOT NULL,
      embedding TEXT NOT NULL,
      dims INTEGER,
      updated_at INTEGER NOT NULL,
      PRIMARY KEY (provider, model, provider_key, hash)
    );
  `);
  params.db.exec(
    `CREATE INDEX IF NOT EXISTS idx_embedding_cache_updated_at ON ${params.embeddingCacheTable}(updated_at);`,
  );

  let ftsAvailable = false;
  let ftsError: string | undefined;
  if (params.ftsEnabled) {
    try {
      params.db.exec(
        `CREATE VIRTUAL TABLE IF NOT EXISTS ${params.ftsTable} USING fts5(\n` +
          `  text,\n` +
          `  id UNINDEXED,\n` +
          `  path UNINDEXED,\n` +
          `  source UNINDEXED,\n` +
          `  model UNINDEXED,\n` +
          `  start_line UNINDEXED,\n` +
          `  end_line UNINDEXED\n` +
          `);`,
      );
      ftsAvailable = true;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      ftsAvailable = false;
      ftsError = message;
    }
  }

  ensureColumn(params.db, "files", "source", "TEXT NOT NULL DEFAULT 'memory'");
  ensureColumn(params.db, "chunks", "source", "TEXT NOT NULL DEFAULT 'memory'");
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_chunks_path ON chunks(path);`);
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_chunks_source ON chunks(source);`);

  // Check if encryption is enabled
  const encryptionEnabled = params.enableEncryption ?? isMemoryEncryptionEnabled();
  if (encryptionEnabled) {
    log.info("memory encryption is enabled");
  }

  return { ftsAvailable, ...(ftsError ? { ftsError } : {}), encryptionEnabled };
}

function ensureColumn(
  db: DatabaseSync,
  table: "files" | "chunks",
  column: string,
  definition: string,
): void {
  const rows = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
  if (rows.some((row) => row.name === column)) {
    return;
  }
  db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
}
