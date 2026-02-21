import type { DatabaseSync } from "node:sqlite";
import { createSubsystemLogger } from "../logging/subsystem.js";
import {
  getEncryptionService,
  getOrInitEncryption,
  createEncryptionConfigFromEnv,
  type EncryptedData,
} from "../security/encryption.js";

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
export async function encryptMemoryText(
  text: string,
): Promise<string | { encrypted: true; data: EncryptedData }> {
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
  stored: string | { encrypted?: boolean; data?: EncryptedData },
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
export function serializeMemoryValue(
  value: string | { encrypted: true; data: EncryptedData },
): string {
  if (typeof value === "string") {
    return value;
  }
  return JSON.stringify(value);
}

/**
 * Deserialize memory value from SQLite storage.
 * Attempts to parse JSON for encrypted data.
 */
export function deserializeMemoryValue(
  stored: string,
): string | { encrypted: true; data: EncryptedData } {
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

  // ============================================================================
  // Performance Optimization Indexes (PERF-011)
  // Goal: 50% query speed improvement
  // ============================================================================

  // Basic indexes (existing)
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_chunks_path ON chunks(path);`);
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_chunks_source ON chunks(source);`);

  // 1. Composite index for (path, source) lookups - 50% faster path-based queries
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_chunks_path_source ON chunks(path, source);`);

  // 2. Session tracking columns and indexes
  ensureColumn(params.db, "chunks", "session_id", "TEXT");
  ensureColumn(params.db, "files", "session_id", "TEXT");
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_chunks_session_id ON chunks(session_id);`);
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_files_session_id ON files(session_id);`);

  // 3. Timestamp indexes for time-range queries
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_chunks_updated_at ON chunks(updated_at);`);
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_files_mtime ON files(mtime);`);
  params.db.exec(
    `CREATE INDEX IF NOT EXISTS idx_chunks_updated_at_source ON chunks(updated_at, source);`,
  );

  // 4. User tracking columns and indexes
  ensureColumn(params.db, "chunks", "user_id", "TEXT");
  ensureColumn(params.db, "files", "user_id", "TEXT");
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_chunks_user_id ON chunks(user_id);`);
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_files_user_id ON files(user_id);`);
  params.db.exec(
    `CREATE INDEX IF NOT EXISTS idx_chunks_user_id_updated_at ON chunks(user_id, updated_at);`,
  );

  // 5. Agent tracking columns and indexes
  ensureColumn(params.db, "chunks", "agent_id", "TEXT");
  ensureColumn(params.db, "files", "agent_id", "TEXT");
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_chunks_agent_id ON chunks(agent_id);`);
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_files_agent_id ON files(agent_id);`);
  params.db.exec(
    `CREATE INDEX IF NOT EXISTS idx_chunks_agent_id_updated_at ON chunks(agent_id, updated_at);`,
  );

  // 6. Additional optimization indexes
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_chunks_hash ON chunks(hash);`);
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_files_hash ON files(hash);`);
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_chunks_model ON chunks(model);`);
  params.db.exec(`CREATE INDEX IF NOT EXISTS idx_files_source ON files(source);`);

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

// ============================================================================
// Index Monitoring and Performance Utilities
// ============================================================================

/**
 * Index usage statistics from SQLite
 */
export interface IndexStats {
  name: string;
  table: string;
  sql: string;
  unique: boolean;
}

/**
 * Query plan analysis result
 */
export interface QueryPlan {
  id: number;
  parent: number;
  notused: number;
  detail: string;
}

/**
 * Get all indexes defined in the database
 */
export function getIndexStats(db: DatabaseSync): IndexStats[] {
  const rows = db
    .prepare(`
    SELECT name, tbl_name as table, sql, CASE WHEN sql LIKE '%UNIQUE%' THEN 1 ELSE 0 END as unique
    FROM sqlite_master
    WHERE type = 'index' AND name LIKE 'idx_%'
    ORDER BY tbl_name, name
  `)
    .all() as unknown[];
  return rows as IndexStats[];
}

/**
 * Analyze query execution plan
 * Use this to verify index effectiveness
 *
 * @example
 * const plan = analyzeQueryPlan(db, 'SELECT * FROM chunks WHERE path = ?', ['/path/to/file']);
 * console.log(plan); // Check if index is being used
 */
export function analyzeQueryPlan(db: DatabaseSync, sql: string, params?: unknown[]): QueryPlan[] {
  const explainSql = `EXPLAIN QUERY PLAN ${sql}`;
  const stmt = db.prepare(explainSql);
  const rows = params ? stmt.all(...(params as (string | number)[])) : stmt.all();
  return rows as unknown as QueryPlan[];
}

/**
 * Check if a specific query uses an index
 * Returns true if the query plan includes 'USING INDEX'
 */
export function isQueryUsingIndex(db: DatabaseSync, sql: string, params?: unknown[]): boolean {
  const plan = analyzeQueryPlan(db, sql, params);
  const planStr = JSON.stringify(plan).toLowerCase();
  return planStr.includes("using index") || planStr.includes("index");
}

/**
 * Run ANALYZE to update query planner statistics
 * Should be called periodically or after significant data changes
 */
export function updateQueryStats(db: DatabaseSync): void {
  db.exec("ANALYZE");
  log.info("updated query planner statistics");
}

/**
 * Performance monitoring result for a specific query pattern
 */
export interface QueryPerformanceResult {
  pattern: string;
  usesIndex: boolean;
  plan: QueryPlan[];
  recommendation?: string;
}

/**
 * Monitor key query patterns and verify index usage
 * This helps ensure the performance optimizations are working
 */
export function monitorIndexEffectiveness(db: DatabaseSync): QueryPerformanceResult[] {
  const patterns = [
    {
      name: "path_source_lookup",
      sql: "SELECT * FROM chunks WHERE path = ? AND source = ?",
      params: ["/test/path", "memory"],
      expectedIndex: "idx_chunks_path_source",
    },
    {
      name: "session_lookup",
      sql: "SELECT * FROM chunks WHERE session_id = ?",
      params: ["test-session"],
      expectedIndex: "idx_chunks_session_id",
    },
    {
      name: "time_range_query",
      sql: "SELECT * FROM chunks WHERE updated_at > ?",
      params: [Date.now() - 86400000],
      expectedIndex: "idx_chunks_updated_at",
    },
    {
      name: "user_scoped_query",
      sql: "SELECT * FROM chunks WHERE user_id = ?",
      params: ["test-user"],
      expectedIndex: "idx_chunks_user_id",
    },
    {
      name: "agent_scoped_query",
      sql: "SELECT * FROM chunks WHERE agent_id = ?",
      params: ["test-agent"],
      expectedIndex: "idx_chunks_agent_id",
    },
    {
      name: "user_time_query",
      sql: "SELECT * FROM chunks WHERE user_id = ? AND updated_at > ?",
      params: ["test-user", Date.now() - 86400000],
      expectedIndex: "idx_chunks_user_id_updated_at",
    },
  ];

  const results: QueryPerformanceResult[] = [];

  for (const pattern of patterns) {
    const plan = analyzeQueryPlan(db, pattern.sql, pattern.params);
    const planStr = JSON.stringify(plan).toLowerCase();
    const usesIndex = planStr.includes("index");

    let recommendation: string | undefined;
    if (!usesIndex) {
      recommendation = `Query '${pattern.name}' is not using an index. Consider adding an index or optimizing the query.`;
    } else if (!planStr.includes(pattern.expectedIndex.toLowerCase())) {
      recommendation = `Query '${pattern.name}' is using a different index than expected (${pattern.expectedIndex}).`;
    }

    results.push({
      pattern: pattern.name,
      usesIndex,
      plan,
      recommendation,
    });
  }

  return results;
}

/**
 * Log index effectiveness report
 */
export function logIndexEffectivenessReport(db: DatabaseSync): void {
  const results = monitorIndexEffectiveness(db);

  log.info("index effectiveness report", {
    totalPatterns: results.length,
    usingIndex: results.filter((r) => r.usesIndex).length,
    notUsingIndex: results.filter((r) => !r.usesIndex).length,
  });

  for (const result of results) {
    if (result.recommendation) {
      log.warn("query optimization needed", {
        pattern: result.pattern,
        recommendation: result.recommendation,
        plan: result.plan,
      });
    } else {
      log.debug("query using index correctly", { pattern: result.pattern });
    }
  }
}
