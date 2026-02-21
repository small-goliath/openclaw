/**
 * CSRF Token Storage Adapters
 *
 * Provides pluggable storage backends for CSRF tokens:
 * - Memory: In-memory Map (default, volatile)
 * - SQLite: Persistent SQLite database (recommended)
 * - Redis: Redis-backed storage (distributed deployments)
 *
 * @module src/security/csrf-store
 */

import type { Database } from "better-sqlite3";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("security/csrf-store");

/** CSRF token entry */
export interface CsrfTokenEntry {
  /** Session identifier */
  sessionId: string;
  /** CSRF token value */
  token: string;
  /** Expiration timestamp */
  expiresAt: number;
}

/** CSRF token storage interface */
export interface CsrfTokenStore {
  /** Store name for logging */
  readonly name: string;

  /**
   * Get token entry for a session
   * @param sessionId - Session identifier
   * @returns Token entry or null if not found/expired
   */
  get(sessionId: string): Promise<CsrfTokenEntry | null>;

  /**
   * Store token entry for a session
   * @param entry - Token entry to store
   */
  set(entry: CsrfTokenEntry): Promise<void>;

  /**
   * Delete token entry for a session
   * @param sessionId - Session identifier
   */
  delete(sessionId: string): Promise<void>;

  /**
   * Check if token exists and is valid
   * @param sessionId - Session identifier
   * @param token - Token to validate
   * @returns true if valid, false otherwise
   */
  validate(sessionId: string, token: string): Promise<boolean>;

  /**
   * Clean up expired tokens
   * @returns Number of tokens removed
   */
  cleanup(): Promise<number>;

  /**
   * Close the store and release resources
   */
  close(): Promise<void>;
}

// ============================================================================
// In-Memory Store (Default, Volatile)
// ============================================================================

/**
 * In-memory CSRF token store
 * Fast but tokens are lost on server restart
 */
export class MemoryCsrfStore implements CsrfTokenStore {
  readonly name = "memory";
  private store = new Map<string, CsrfTokenEntry>();

  async get(sessionId: string): Promise<CsrfTokenEntry | null> {
    const entry = this.store.get(sessionId);
    if (!entry) {
      return null;
    }

    // Check expiration
    if (entry.expiresAt <= Date.now()) {
      this.store.delete(sessionId);
      return null;
    }

    return entry;
  }

  async set(entry: CsrfTokenEntry): Promise<void> {
    this.store.set(entry.sessionId, entry);
  }

  async delete(sessionId: string): Promise<void> {
    this.store.delete(sessionId);
  }

  async validate(sessionId: string, token: string): Promise<boolean> {
    const entry = await this.get(sessionId);
    if (!entry) {
      return false;
    }

    // Use timing-safe comparison
    try {
      const storedBuf = Buffer.from(entry.token);
      const providedBuf = Buffer.from(token);

      if (storedBuf.length !== providedBuf.length) {
        return false;
      }
      return crypto.timingSafeEqual(storedBuf, providedBuf);
    } catch {
      return false;
    }
  }

  async cleanup(): Promise<number> {
    const now = Date.now();
    let removed = 0;

    for (const [sessionId, entry] of this.store.entries()) {
      if (entry.expiresAt <= now) {
        this.store.delete(sessionId);
        removed++;
      }
    }

    return removed;
  }

  async close(): Promise<void> {
    this.store.clear();
  }

  /** Get store size (for testing/monitoring) */
  size(): number {
    return this.store.size;
  }
}

// ============================================================================
// SQLite Store (Persistent)
// ============================================================================

/**
 * SQLite-backed CSRF token store
 * Tokens persist across server restarts
 */
export class SqliteCsrfStore implements CsrfTokenStore {
  readonly name = "sqlite";
  private db: Database | null = null;
  private dbPath: string;

  constructor(dbPath: string) {
    this.dbPath = dbPath;
  }

  /**
   * Initialize the SQLite database
   */
  async init(): Promise<void> {
    try {
      // Dynamic import to avoid dependency issues
      const { default: Database } = await import("better-sqlite3");
      this.db = new Database(this.dbPath);

      // Create table if not exists
      this.db.exec(`
        CREATE TABLE IF NOT EXISTS csrf_tokens (
          session_id TEXT PRIMARY KEY,
          token TEXT NOT NULL,
          expires_at INTEGER NOT NULL,
          created_at INTEGER DEFAULT (unixepoch() * 1000)
        );
      `);

      // Create index for expiration queries
      this.db.exec(`
        CREATE INDEX IF NOT EXISTS idx_csrf_expires 
        ON csrf_tokens(expires_at);
      `);

      log.info("SQLite CSRF store initialized", { path: this.dbPath });
    } catch (err) {
      log.error("Failed to initialize SQLite CSRF store", { err, path: this.dbPath });
      throw err;
    }
  }

  async get(sessionId: string): Promise<CsrfTokenEntry | null> {
    if (!this.db) {
      throw new Error("Store not initialized");
    }

    const row = this.db.prepare("SELECT * FROM csrf_tokens WHERE session_id = ?").get(sessionId) as
      | { session_id: string; token: string; expires_at: number }
      | undefined;

    if (!row) {
      return null;
    }

    // Check expiration and delete if expired
    if (row.expires_at <= Date.now()) {
      this.delete(sessionId);
      return null;
    }

    return {
      sessionId: row.session_id,
      token: row.token,
      expiresAt: row.expires_at,
    };
  }

  async set(entry: CsrfTokenEntry): Promise<void> {
    if (!this.db) {
      throw new Error("Store not initialized");
    }

    this.db
      .prepare(
        `
        INSERT INTO csrf_tokens (session_id, token, expires_at)
        VALUES (?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET
          token = excluded.token,
          expires_at = excluded.expires_at
      `,
      )
      .run(entry.sessionId, entry.token, entry.expiresAt);
  }

  async delete(sessionId: string): Promise<void> {
    if (!this.db) {
      throw new Error("Store not initialized");
    }

    this.db.prepare("DELETE FROM csrf_tokens WHERE session_id = ?").run(sessionId);
  }

  async validate(sessionId: string, token: string): Promise<boolean> {
    const entry = await this.get(sessionId);
    if (!entry) {
      return false;
    }

    try {
      const storedBuf = Buffer.from(entry.token);
      const providedBuf = Buffer.from(token);

      if (storedBuf.length !== providedBuf.length) {
        return false;
      }
      return crypto.timingSafeEqual(storedBuf, providedBuf);
    } catch {
      return false;
    }
  }

  async cleanup(): Promise<number> {
    if (!this.db) {
      throw new Error("Store not initialized");
    }

    const result = this.db.prepare("DELETE FROM csrf_tokens WHERE expires_at <= ?").run(Date.now());

    const removed = result.changes;
    if (removed > 0) {
      log.debug("Cleaned up expired CSRF tokens", { removed });
    }

    return removed;
  }

  async close(): Promise<void> {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }

  /**
   * Get statistics about the store
   */
  getStats(): { total: number; expired: number } {
    if (!this.db) {
      throw new Error("Store not initialized");
    }

    const total = (
      this.db.prepare("SELECT COUNT(*) as count FROM csrf_tokens").get() as { count: number }
    ).count;

    const expired = (
      this.db
        .prepare("SELECT COUNT(*) as count FROM csrf_tokens WHERE expires_at <= ?")
        .get(Date.now()) as {
        count: number;
      }
    ).count;

    return { total, expired };
  }
}

// ============================================================================
// Redis Store (Distributed)
// ============================================================================

/** Redis client interface */
interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options?: { EX?: number }): Promise<string | null>;
  del(key: string): Promise<number>;
  keys(pattern: string): Promise<string[]>;
}

/**
 * Redis-backed CSRF token store
 * For distributed deployments with multiple server instances
 */
export class RedisCsrfStore implements CsrfTokenStore {
  readonly name = "redis";
  private client: RedisClient | null = null;
  private keyPrefix: string;

  constructor(client: RedisClient, keyPrefix = "csrf:") {
    this.client = client;
    this.keyPrefix = keyPrefix;
  }

  private getKey(sessionId: string): string {
    return `${this.keyPrefix}${sessionId}`;
  }

  async get(sessionId: string): Promise<CsrfTokenEntry | null> {
    if (!this.client) {
      throw new Error("Redis client not available");
    }

    const key = this.getKey(sessionId);
    const data = await this.client.get(key);

    if (!data) {
      return null;
    }

    try {
      const entry = JSON.parse(data) as CsrfTokenEntry;

      // Check expiration (Redis might not have expired yet)
      if (entry.expiresAt <= Date.now()) {
        await this.delete(sessionId);
        return null;
      }

      return entry;
    } catch {
      return null;
    }
  }

  async set(entry: CsrfTokenEntry): Promise<void> {
    if (!this.client) {
      throw new Error("Redis client not available");
    }

    const key = this.getKey(entry.sessionId);
    const ttlSeconds = Math.ceil((entry.expiresAt - Date.now()) / 1000);

    await this.client.set(key, JSON.stringify(entry), {
      EX: Math.max(1, ttlSeconds),
    });
  }

  async delete(sessionId: string): Promise<void> {
    if (!this.client) {
      throw new Error("Redis client not available");
    }

    await this.client.del(this.getKey(sessionId));
  }

  async validate(sessionId: string, token: string): Promise<boolean> {
    const entry = await this.get(sessionId);
    if (!entry) {
      return false;
    }

    try {
      const storedBuf = Buffer.from(entry.token);
      const providedBuf = Buffer.from(token);

      if (storedBuf.length !== providedBuf.length) {
        return false;
      }
      return crypto.timingSafeEqual(storedBuf, providedBuf);
    } catch {
      return false;
    }
  }

  async cleanup(): Promise<number> {
    // Redis handles expiration automatically via TTL
    // This method is mostly for compatibility
    log.debug("Redis CSRF store cleanup (TTL handles expiration automatically)");
    return 0;
  }

  async close(): Promise<void> {
    // Redis connection is managed externally
    this.client = null;
  }
}

// ============================================================================
// Store Factory
// ============================================================================

/** Store configuration options */
export interface CsrfStoreConfig {
  /** Store type */
  type: "memory" | "sqlite" | "redis";
  /** SQLite database path (for sqlite type) */
  sqlitePath?: string;
  /** Redis client (for redis type) */
  redisClient?: RedisClient;
  /** Redis key prefix (for redis type) */
  redisKeyPrefix?: string;
}

/**
 * Create a CSRF token store based on configuration
 * @param config - Store configuration
 * @returns Configured CSRF token store
 */
export async function createCsrfStore(config: CsrfStoreConfig): Promise<CsrfTokenStore> {
  switch (config.type) {
    case "memory":
      log.info("Using in-memory CSRF token store (tokens will be lost on restart)");
      return new MemoryCsrfStore();

    case "sqlite": {
      const path = config.sqlitePath;
      if (!path) {
        throw new Error("sqlitePath is required for SQLite CSRF store");
      }
      const store = new SqliteCsrfStore(path);
      await store.init();
      log.info("Using SQLite CSRF token store", { path });
      return store;
    }

    case "redis": {
      if (!config.redisClient) {
        throw new Error("redisClient is required for Redis CSRF store");
      }
      log.info("Using Redis CSRF token store");
      return new RedisCsrfStore(config.redisClient, config.redisKeyPrefix);
    }

    default:
      throw new Error(`Unknown CSRF store type: ${config.type}`);
  }
}

/**
 * Create CSRF store from environment configuration
 * @returns Configured CSRF token store
 */
export async function createCsrfStoreFromEnv(): Promise<CsrfTokenStore> {
  const storeType =
    (process.env.OPENCLAW_CSRF_STORE_TYPE as "memory" | "sqlite" | "redis") || "sqlite";

  switch (storeType) {
    case "memory":
      return createCsrfStore({ type: "memory" });

    case "sqlite": {
      const { resolveStateDir } = await import("../config/paths.js");
      const path = await import("node:path");
      const sqlitePath =
        process.env.OPENCLAW_CSRF_SQLITE_PATH ||
        path.default.join(resolveStateDir(), "csrf-tokens.db");
      return createCsrfStore({ type: "sqlite", sqlitePath });
    }

    case "redis": {
      // Redis client must be provided externally
      throw new Error(
        "Redis CSRF store requires explicit Redis client configuration. " +
          "Please use createCsrfStore() with redisClient option.",
      );
    }

    default:
      throw new Error(`Unknown CSRF store type: ${storeType}`);
  }
}

// Import crypto for timingSafeEqual
import crypto from "node:crypto";
