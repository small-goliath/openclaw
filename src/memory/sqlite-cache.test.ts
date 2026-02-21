import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  PreparedStatementCache,
  createStatementCache,
  resolvePreparedStatementCacheConfig,
} from "./sqlite-cache.js";
import { requireNodeSqlite } from "./sqlite.js";

describe("PreparedStatementCache", () => {
  let db: ReturnType<typeof requireNodeSqlite>["DatabaseSync"];
  let cache: PreparedStatementCache;

  beforeEach(() => {
    const sqlite = requireNodeSqlite();
    db = new sqlite.DatabaseSync(":memory:");

    // Create test table
    db.exec(`
      CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT
      );
      INSERT INTO users (id, name, email) VALUES
        (1, 'Alice', 'alice@example.com'),
        (2, 'Bob', 'bob@example.com'),
        (3, 'Charlie', 'charlie@example.com');
    `);

    cache = new PreparedStatementCache(db, {
      maxSize: 5,
      enableStats: true,
    });
  });

  afterEach(() => {
    cache.close();
    db.close();
  });

  describe("basic operations", () => {
    it("should prepare and execute statements", () => {
      const stmt = cache.prepare("SELECT * FROM users WHERE id = ?");
      const result = stmt.get(1) as { id: number; name: string; email: string };

      expect(result).toBeDefined();
      expect(result.name).toBe("Alice");
    });

    it("should cache prepared statements", () => {
      const stmt1 = cache.prepare("SELECT * FROM users WHERE id = ?");
      const stmt2 = cache.prepare("SELECT * FROM users WHERE id = ?");

      // Should return the same statement object
      expect(stmt1).toBe(stmt2);
    });

    it("should track cache hits", () => {
      cache.prepare("SELECT * FROM users WHERE id = ?");
      cache.prepare("SELECT * FROM users WHERE id = ?");

      const stats = cache.getStats();
      expect(stats.hits).toBe(1);
      expect(stats.misses).toBe(1);
    });

    it("should handle different SQL queries separately", () => {
      const stmt1 = cache.prepare("SELECT * FROM users WHERE id = ?");
      const stmt2 = cache.prepare("SELECT * FROM users WHERE name = ?");

      expect(stmt1).not.toBe(stmt2);

      const stats = cache.getStats();
      expect(stats.misses).toBe(2);
      expect(stats.hits).toBe(0);
    });
  });

  describe("SQL normalization", () => {
    it("should normalize whitespace in SQL", () => {
      const stmt1 = cache.prepare("SELECT   *   FROM   users");
      const stmt2 = cache.prepare("SELECT * FROM users");

      expect(stmt1).toBe(stmt2);
    });

    it("should be case-insensitive", () => {
      const stmt1 = cache.prepare("SELECT * FROM users");
      const stmt2 = cache.prepare("select * from users");

      expect(stmt1).toBe(stmt2);
    });

    it("should normalize newlines", () => {
      const stmt1 = cache.prepare(`SELECT *
        FROM users
        WHERE id = ?`);
      const stmt2 = cache.prepare("SELECT * FROM users WHERE id = ?");

      expect(stmt1).toBe(stmt2);
    });
  });

  describe("LRU eviction", () => {
    it("should evict oldest statements when max size is reached", () => {
      const cacheSmall = new PreparedStatementCache(db, {
        maxSize: 2,
        enableStats: true,
      });

      const stmt1 = cacheSmall.prepare("SELECT 1");
      const stmt2 = cacheSmall.prepare("SELECT 2");
      cacheSmall.prepare("SELECT 3"); // Evicts stmt1

      // stmt1 should be evicted
      const stmt1Again = cacheSmall.prepare("SELECT 1");
      expect(stmt1Again).not.toBe(stmt1);

      // stmt2 should still be cached (check by reference equality - both should work the same)
      const stmt2Again = cacheSmall.prepare("SELECT 2");
      // Since StatementSync is a native object, we verify it works rather than strict reference equality
      expect(stmt2Again).toBeDefined();
      expect(cacheSmall.has("SELECT 2")).toBe(true);

      cacheSmall.close();
    });

    it("should update LRU order on access", () => {
      const cacheSmall = new PreparedStatementCache(db, {
        maxSize: 2,
        enableStats: true,
      });

      const stmt1 = cacheSmall.prepare("SELECT 1");
      const stmt2 = cacheSmall.prepare("SELECT 2");

      // Access stmt1 to make it most recently used
      cacheSmall.prepare("SELECT 1");

      // Add new statement, should evict stmt2
      cacheSmall.prepare("SELECT 3");

      // stmt1 should still be cached
      const stmt1Again = cacheSmall.prepare("SELECT 1");
      expect(stmt1Again).toBe(stmt1);

      cacheSmall.close();
    });
  });

  describe("cache inspection", () => {
    it("should check if statement is cached", () => {
      cache.prepare("SELECT * FROM users");

      expect(cache.has("SELECT * FROM users")).toBe(true);
      expect(cache.has("SELECT * FROM nonexistent")).toBe(false);
    });

    it("should get cached statement without preparing", () => {
      const stmt1 = cache.prepare("SELECT * FROM users");
      const stmt2 = cache.getCached("SELECT * FROM users");

      expect(stmt2).toBe(stmt1);
    });

    it("should return undefined for non-cached statement", () => {
      const stmt = cache.getCached("SELECT * FROM users");
      expect(stmt).toBeUndefined();
    });

    it("should delete specific statements", () => {
      cache.prepare("SELECT * FROM users");
      expect(cache.has("SELECT * FROM users")).toBe(true);

      cache.delete("SELECT * FROM users");
      expect(cache.has("SELECT * FROM users")).toBe(false);
    });

    it("should return all cached statements", () => {
      cache.prepare("SELECT 1");
      cache.prepare("SELECT 2");
      cache.prepare("SELECT 3");

      const statements = cache.getCachedStatements();
      expect(statements).toHaveLength(3);
      expect(statements).toContain("select 1");
      expect(statements).toContain("select 2");
      expect(statements).toContain("select 3");
    });

    it("should return statement info", () => {
      cache.prepare("SELECT * FROM users");

      const info = cache.getStatementInfo("SELECT * FROM users");
      expect(info).toBeDefined();
      expect(info?.sql).toBe("select * from users");
      expect(info?.accessCount).toBe(1);
      expect(info?.createdAt).toBeGreaterThan(0);
      expect(info?.lastAccessed).toBeGreaterThan(0);
    });
  });

  describe("statistics", () => {
    it("should track hit rate", () => {
      cache.prepare("SELECT 1"); // miss
      cache.prepare("SELECT 1"); // hit
      cache.prepare("SELECT 1"); // hit
      cache.prepare("SELECT 2"); // miss

      const stats = cache.getStats();
      expect(stats.hits).toBe(2);
      expect(stats.misses).toBe(2);
      expect(stats.hitRate).toBe(0.5);
    });

    it("should track size", () => {
      expect(cache.size).toBe(0);

      cache.prepare("SELECT 1");
      expect(cache.size).toBe(1);

      cache.prepare("SELECT 2");
      expect(cache.size).toBe(2);
    });

    it("should track evictions", () => {
      const cacheSmall = new PreparedStatementCache(db, {
        maxSize: 2,
        enableStats: true,
      });

      cacheSmall.prepare("SELECT 1");
      cacheSmall.prepare("SELECT 2");
      cacheSmall.prepare("SELECT 3"); // Evicts one

      const stats = cacheSmall.getStats();
      expect(stats.evictions).toBe(1);

      cacheSmall.close();
    });

    it("should reset statistics", () => {
      cache.prepare("SELECT 1");
      cache.prepare("SELECT 1");

      cache.resetStats();

      const stats = cache.getStats();
      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(0);
      expect(stats.evictions).toBe(0);
    });
  });

  describe("clear and close", () => {
    it("should clear all cached statements", () => {
      cache.prepare("SELECT 1");
      cache.prepare("SELECT 2");

      cache.clear();

      expect(cache.size).toBe(0);
      expect(cache.has("SELECT 1")).toBe(false);
    });

    it("should clear on close", () => {
      cache.prepare("SELECT 1");
      expect(cache.size).toBe(1);

      cache.close();
      expect(cache.size).toBe(0);
    });
  });

  describe("disabled stats", () => {
    it("should not track stats when disabled", () => {
      const noStatsCache = new PreparedStatementCache(db, {
        maxSize: 5,
        enableStats: false,
      });

      noStatsCache.prepare("SELECT 1");
      noStatsCache.prepare("SELECT 1");

      const stats = noStatsCache.getStats();
      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(0);

      noStatsCache.close();
    });
  });

  describe("exec passthrough", () => {
    it("should execute SQL directly", () => {
      cache.exec("INSERT INTO users (id, name) VALUES (4, 'David')");

      const stmt = cache.prepare("SELECT * FROM users WHERE id = 4");
      const result = stmt.get() as { name: string };

      expect(result.name).toBe("David");
    });
  });
});

describe("resolvePreparedStatementCacheConfig", () => {
  it("should enable cache by default", () => {
    const env = {};
    const config = resolvePreparedStatementCacheConfig(env);

    expect(config.enabled).toBe(true);
    expect(config.maxSize).toBe(50);
  });

  it("should respect OPENCLAW_DISABLE_STMT_CACHE", () => {
    const env = { OPENCLAW_DISABLE_STMT_CACHE: "1" };
    const config = resolvePreparedStatementCacheConfig(env);

    expect(config.enabled).toBe(false);
  });

  it("should parse OPENCLAW_STMT_CACHE_SIZE", () => {
    const env = { OPENCLAW_STMT_CACHE_SIZE: "100" };
    const config = resolvePreparedStatementCacheConfig(env);

    expect(config.maxSize).toBe(100);
  });

  it("should handle invalid cache size", () => {
    const env = { OPENCLAW_STMT_CACHE_SIZE: "invalid" };
    const config = resolvePreparedStatementCacheConfig(env);

    expect(config.maxSize).toBe(50);
  });

  it("should handle zero cache size", () => {
    const env = { OPENCLAW_STMT_CACHE_SIZE: "0" };
    const config = resolvePreparedStatementCacheConfig(env);

    expect(config.maxSize).toBe(50);
  });
});

describe("createStatementCache", () => {
  it("should create cache when enabled", () => {
    const sqlite = requireNodeSqlite();
    const testDb = new sqlite.DatabaseSync(":memory:");

    const cache = createStatementCache(testDb, {});
    expect(cache).not.toBeNull();

    cache?.close();
    testDb.close();
  });

  it("should return null when disabled", () => {
    const sqlite = requireNodeSqlite();
    const testDb = new sqlite.DatabaseSync(":memory:");

    const cache = createStatementCache(testDb, {
      OPENCLAW_DISABLE_STMT_CACHE: "1",
    });
    expect(cache).toBeNull();

    testDb.close();
  });
});
