/**
 * SQLite Prepared Statement Cache
 *
 * Features:
 * - LRU eviction for prepared statements
 * - Max statement limit (memory protection)
 * - Cache hit/miss statistics
 * - Automatic cleanup on connection close
 * - Statement lifecycle management
 *
 * @module memory/sqlite-cache
 */

import type { DatabaseSync, StatementSync } from "node:sqlite";

export interface PreparedStatementCacheStats {
  hits: number;
  misses: number;
  hitRate: number;
  size: number;
  maxSize: number;
  evictions: number;
}

export interface PreparedStatementCacheOptions {
  maxSize: number;
  enableStats?: boolean;
}

interface CachedStatement {
  statement: StatementSync;
  sql: string;
  createdAt: number;
  lastAccessed: number;
  accessCount: number;
}

/**
 * Prepared Statement Cache for SQLite DatabaseSync
 *
 * Wraps DatabaseSync to provide transparent prepared statement caching.
 * Frequently used queries are cached to avoid re-preparation overhead.
 *
 * @example
 * ```typescript
 * const db = new (requireNodeSqlite().DatabaseSync)(":memory:");
 * const cache = new PreparedStatementCache(db, { maxSize: 50 });
 *
 * // First call prepares the statement
 * const stmt1 = cache.prepare("SELECT * FROM users WHERE id = ?");
 *
 * // Second call returns cached statement
 * const stmt2 = cache.prepare("SELECT * FROM users WHERE id = ?");
 * // stmt1 === stmt2
 *
 * // Get statistics
 * console.log(cache.getStats());
 *
 * // Cleanup on connection close
 * cache.close();
 * ```
 */
export class PreparedStatementCache {
  private db: DatabaseSync;
  private cache: Map<string, CachedStatement>;
  private maxSize: number;
  private enableStats: boolean;

  // Statistics
  private hits = 0;
  private misses = 0;
  private evictions = 0;

  constructor(db: DatabaseSync, options: PreparedStatementCacheOptions) {
    this.db = db;
    this.maxSize = options.maxSize;
    this.enableStats = options.enableStats ?? true;
    this.cache = new Map();
  }

  /**
   * Prepare a SQL statement (with caching)
   *
   * @param sql - SQL query string
   * @returns Prepared StatementSync object
   */
  prepare(sql: string): StatementSync {
    // Normalize SQL for consistent cache keys
    const normalizedSql = this.normalizeSql(sql);

    const cached = this.cache.get(normalizedSql);
    if (cached) {
      // Update access metadata
      cached.lastAccessed = Date.now();
      cached.accessCount++;

      // Move to end (most recently used)
      this.cache.delete(normalizedSql);
      this.cache.set(normalizedSql, cached);

      this.recordHit();
      return cached.statement;
    }

    this.recordMiss();

    // Prepare new statement
    const statement = this.db.prepare(sql);

    // Evict oldest entries if at capacity
    while (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        const entry = this.cache.get(firstKey);
        if (entry) {
          // Finalize the statement to free resources
          try {
            // StatementSync doesn't have explicit finalize in node:sqlite
            // It will be garbage collected when no longer referenced
          } catch {
            // best-effort
          }
        }
        this.cache.delete(firstKey);
        this.evictions++;
      } else {
        break;
      }
    }

    const now = Date.now();
    const entry: CachedStatement = {
      statement,
      sql: normalizedSql,
      createdAt: now,
      lastAccessed: now,
      accessCount: 1,
    };

    this.cache.set(normalizedSql, entry);

    return statement;
  }

  /**
   * Execute a SQL query directly (without caching)
   *
   * @param sql - SQL query string
   * @returns Query results
   */
  exec(sql: string): ReturnType<DatabaseSync["exec"]> {
    return this.db.exec(sql);
  }

  /**
   * Get a cached statement without preparing a new one
   *
   * @param sql - SQL query string
   * @returns Cached statement or undefined
   */
  getCached(sql: string): StatementSync | undefined {
    const normalizedSql = this.normalizeSql(sql);
    const cached = this.cache.get(normalizedSql);

    if (cached) {
      cached.lastAccessed = Date.now();
      cached.accessCount++;
      this.recordHit();
      return cached.statement;
    }

    return undefined;
  }

  /**
   * Check if a statement is cached
   *
   * @param sql - SQL query string
   * @returns true if statement is cached
   */
  has(sql: string): boolean {
    const normalizedSql = this.normalizeSql(sql);
    return this.cache.has(normalizedSql);
  }

  /**
   * Remove a specific statement from cache
   *
   * @param sql - SQL query string
   * @returns true if statement was found and removed
   */
  delete(sql: string): boolean {
    const normalizedSql = this.normalizeSql(sql);
    return this.cache.delete(normalizedSql);
  }

  /**
   * Clear all cached statements
   */
  clear(): void {
    this.cache.clear();
    this.resetStats();
  }

  /**
   * Close the cache and clean up resources
   *
   * This should be called when the database connection is closed.
   */
  close(): void {
    this.clear();
  }

  /**
   * Get cache statistics
   *
   * @returns PreparedStatementCacheStats object
   */
  getStats(): PreparedStatementCacheStats {
    const total = this.hits + this.misses;
    return {
      hits: this.hits,
      misses: this.misses,
      hitRate: total > 0 ? this.hits / total : 0,
      size: this.cache.size,
      maxSize: this.maxSize,
      evictions: this.evictions,
    };
  }

  /**
   * Reset statistics counters
   */
  resetStats(): void {
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
  }

  /**
   * Get the current size of the cache
   */
  get size(): number {
    return this.cache.size;
  }

  /**
   * Get all cached SQL statements (for debugging)
   */
  getCachedStatements(): string[] {
    return Array.from(this.cache.keys());
  }

  /**
   * Get detailed info about a cached statement (for debugging)
   */
  getStatementInfo(sql: string): Omit<CachedStatement, "statement"> | undefined {
    const normalizedSql = this.normalizeSql(sql);
    const cached = this.cache.get(normalizedSql);
    if (!cached) {
      return undefined;
    }

    const { statement, ...info } = cached;
    return info;
  }

  /**
   * Normalize SQL for consistent cache keys
   *
   * Removes extra whitespace and converts to lowercase
   * for case-insensitive matching.
   */
  private normalizeSql(sql: string): string {
    return sql.replace(/\s+/g, " ").trim().toLowerCase();
  }

  private recordHit(): void {
    if (this.enableStats) {
      this.hits++;
    }
  }

  private recordMiss(): void {
    if (this.enableStats) {
      this.misses++;
    }
  }
}

/**
 * Environment-based prepared statement cache configuration
 */
export function resolvePreparedStatementCacheConfig(env: NodeJS.ProcessEnv): {
  enabled: boolean;
  maxSize: number;
} {
  const enabled = !env.OPENCLAW_DISABLE_STMT_CACHE?.trim();
  const maxSize = parseInt(env.OPENCLAW_STMT_CACHE_SIZE?.trim() ?? "50", 10);

  return {
    enabled,
    maxSize: Number.isFinite(maxSize) && maxSize > 0 ? maxSize : 50,
  };
}

/**
 * Wrap a DatabaseSync with prepared statement caching
 *
 * @param db - DatabaseSync instance
 * @param env - Environment variables
 * @returns PreparedStatementCache instance or null if disabled
 */
export function createStatementCache(
  db: DatabaseSync,
  env: NodeJS.ProcessEnv = process.env,
): PreparedStatementCache | null {
  const config = resolvePreparedStatementCacheConfig(env);

  if (!config.enabled) {
    return null;
  }

  return new PreparedStatementCache(db, {
    maxSize: config.maxSize,
    enableStats: true,
  });
}
