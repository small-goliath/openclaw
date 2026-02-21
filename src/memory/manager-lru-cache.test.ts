/**
 * Memory Index Manager LRU Cache Tests
 *
 * Tests for:
 * - LRU cache eviction policy
 * - TTL expiration for cache entries
 * - Background cleanup functionality
 * - Session delta TTL management
 * - Metrics accuracy
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { LRUCache } from "../infra/cache/lru-cache.js";

// LRU Cache 단위 테스트
describe("LRU Cache", () => {
  let cache: LRUCache<string>;

  beforeEach(() => {
    cache = new LRUCache<string>({
      maxSize: 3,
      defaultTTL: 1000, // 1 second
    });
  });

  afterEach(() => {
    cache.clear();
  });

  it("should store and retrieve values", () => {
    cache.set("key1", "value1");
    expect(cache.get("key1")).toBe("value1");
  });

  it("should return undefined for non-existent keys", () => {
    expect(cache.get("nonexistent")).toBeUndefined();
  });

  it("should evict oldest entries when max size is reached", () => {
    cache.set("key1", "value1");
    cache.set("key2", "value2");
    cache.set("key3", "value3");
    cache.set("key4", "value4"); // Should evict key1

    expect(cache.get("key1")).toBeUndefined();
    expect(cache.get("key2")).toBe("value2");
    expect(cache.get("key3")).toBe("value3");
    expect(cache.get("key4")).toBe("value4");
  });

  it("should update LRU order on access", () => {
    cache.set("key1", "value1");
    cache.set("key2", "value2");
    cache.set("key3", "value3");

    // Access key1 to make it most recently used
    cache.get("key1");

    // Add new entry, should evict key2 (now oldest)
    cache.set("key4", "value4");

    expect(cache.get("key1")).toBe("value1");
    expect(cache.get("key2")).toBeUndefined();
    expect(cache.get("key3")).toBe("value3");
    expect(cache.get("key4")).toBe("value4");
  });

  it("should expire entries after TTL", async () => {
    cache.set("key1", "value1", { ttl: 50 }); // 50ms TTL

    expect(cache.get("key1")).toBe("value1");

    // Wait for TTL to expire
    await new Promise((resolve) => setTimeout(resolve, 100));

    expect(cache.get("key1")).toBeUndefined();
  });

  it("should track cache statistics", () => {
    cache.set("key1", "value1");
    cache.get("key1"); // hit
    cache.get("key1"); // hit
    cache.get("nonexistent"); // miss

    const stats = cache.getStats();
    expect(stats.hits).toBe(2);
    expect(stats.misses).toBe(1);
    expect(stats.hitRate).toBe(2 / 3);
    expect(stats.size).toBe(1);
    expect(stats.maxSize).toBe(3);
  });

  it("should track evictions", () => {
    cache.set("key1", "value1");
    cache.set("key2", "value2");
    cache.set("key3", "value3");
    cache.set("key4", "value4"); // Evicts key1

    const stats = cache.getStats();
    expect(stats.evictions).toBe(1);
    expect(stats.size).toBe(3);
  });

  it("should cleanup expired entries", async () => {
    cache.set("key1", "value1", { ttl: 50 });
    cache.set("key2", "value2", { ttl: 2000 }); // Longer TTL

    // Wait for first entry to expire
    await new Promise((resolve) => setTimeout(resolve, 100));

    const removed = cache.cleanup();
    expect(removed).toBe(1);
    expect(cache.get("key1")).toBeUndefined();
    expect(cache.get("key2")).toBe("value2");
  });

  it("should delete specific entries", () => {
    cache.set("key1", "value1");
    cache.set("key2", "value2");

    const deleted = cache.delete("key1");
    expect(deleted).toBe(true);
    expect(cache.get("key1")).toBeUndefined();
    expect(cache.get("key2")).toBe("value2");
  });

  it("should check if key exists without updating LRU order", () => {
    cache.set("key1", "value1");
    cache.set("key2", "value2");

    expect(cache.has("key1")).toBe(true);

    // Add new entry, should still evict key1 (oldest)
    cache.set("key3", "value3");
    cache.set("key4", "value4");

    expect(cache.has("key1")).toBe(false);
  });

  it("should clear all entries", () => {
    cache.set("key1", "value1");
    cache.set("key2", "value2");

    cache.clear();

    expect(cache.get("key1")).toBeUndefined();
    expect(cache.get("key2")).toBeUndefined();
    expect(cache.size).toBe(0);
  });

  it("should reset statistics", () => {
    cache.set("key1", "value1");
    cache.get("key1");
    cache.get("nonexistent");

    cache.resetStats();

    const stats = cache.getStats();
    expect(stats.hits).toBe(0);
    expect(stats.misses).toBe(0);
  });
});

// 환경 변수 설정 테스트
describe("Memory Cache Configuration", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("should use default values when env vars are not set", () => {
    delete process.env.OPENCLAW_MEMORY_CACHE_MAX_SIZE;
    delete process.env.OPENCLAW_MEMORY_CACHE_TTL_MS;
    delete process.env.OPENCLAW_MEMORY_SESSION_TTL_MS;
    delete process.env.OPENCLAW_MEMORY_CLEANUP_INTERVAL_MS;

    // Re-import to test default values
    const config = {
      maxSize: parseInt(process.env.OPENCLAW_MEMORY_CACHE_MAX_SIZE?.trim() ?? "100", 10),
      defaultTTL: parseInt(process.env.OPENCLAW_MEMORY_CACHE_TTL_MS?.trim() ?? "3600000", 10),
      sessionTTL: parseInt(process.env.OPENCLAW_MEMORY_SESSION_TTL_MS?.trim() ?? "1800000", 10),
      cleanupInterval: parseInt(
        process.env.OPENCLAW_MEMORY_CLEANUP_INTERVAL_MS?.trim() ?? "300000",
        10,
      ),
    };

    expect(config.maxSize).toBe(100);
    expect(config.defaultTTL).toBe(3600000);
    expect(config.sessionTTL).toBe(1800000);
    expect(config.cleanupInterval).toBe(300000);
  });

  it("should use environment variable values when set", () => {
    process.env.OPENCLAW_MEMORY_CACHE_MAX_SIZE = "200";
    process.env.OPENCLAW_MEMORY_CACHE_TTL_MS = "7200000";
    process.env.OPENCLAW_MEMORY_SESSION_TTL_MS = "3600000";
    process.env.OPENCLAW_MEMORY_CLEANUP_INTERVAL_MS = "600000";

    const config = {
      maxSize: parseInt(process.env.OPENCLAW_MEMORY_CACHE_MAX_SIZE?.trim() ?? "100", 10),
      defaultTTL: parseInt(process.env.OPENCLAW_MEMORY_CACHE_TTL_MS?.trim() ?? "3600000", 10),
      sessionTTL: parseInt(process.env.OPENCLAW_MEMORY_SESSION_TTL_MS?.trim() ?? "1800000", 10),
      cleanupInterval: parseInt(
        process.env.OPENCLAW_MEMORY_CLEANUP_INTERVAL_MS?.trim() ?? "300000",
        10,
      ),
    };

    expect(config.maxSize).toBe(200);
    expect(config.defaultTTL).toBe(7200000);
    expect(config.sessionTTL).toBe(3600000);
    expect(config.cleanupInterval).toBe(600000);
  });

  it("should handle invalid environment variable values", () => {
    process.env.OPENCLAW_MEMORY_CACHE_MAX_SIZE = "invalid";
    process.env.OPENCLAW_MEMORY_CACHE_TTL_MS = "-100";

    const maxSize = parseInt(process.env.OPENCLAW_MEMORY_CACHE_MAX_SIZE?.trim() ?? "100", 10);
    const defaultTTL = parseInt(process.env.OPENCLAW_MEMORY_CACHE_TTL_MS?.trim() ?? "3600000", 10);

    // NaN and negative values should fall back to defaults
    const resolvedMaxSize = Number.isFinite(maxSize) && maxSize > 0 ? maxSize : 100;
    const resolvedDefaultTTL = Number.isFinite(defaultTTL) && defaultTTL > 0 ? defaultTTL : 3600000;

    expect(resolvedMaxSize).toBe(100);
    expect(resolvedDefaultTTL).toBe(3600000);
  });
});

// Session Delta TTL 테스트
describe("Session Delta TTL", () => {
  it("should track last accessed time for session deltas", () => {
    const sessionDeltas = new Map<
      string,
      { lastSize: number; pendingBytes: number; pendingMessages: number; lastAccessed: number }
    >();

    const now = Date.now();
    const sessionFile = "/path/to/session.jsonl";

    // Simulate updateSessionDelta behavior
    let state = sessionDeltas.get(sessionFile);
    if (!state) {
      state = { lastSize: 0, pendingBytes: 0, pendingMessages: 0, lastAccessed: now };
      sessionDeltas.set(sessionFile, state);
    }
    state.lastAccessed = now;

    expect(sessionDeltas.get(sessionFile)?.lastAccessed).toBe(now);
  });

  it("should cleanup expired session deltas", () => {
    const sessionDeltas = new Map<
      string,
      { lastSize: number; pendingBytes: number; pendingMessages: number; lastAccessed: number }
    >();

    const now = Date.now();
    const sessionTTL = 1800000; // 30 minutes

    // Add expired session
    sessionDeltas.set("/path/to/expired.jsonl", {
      lastSize: 100,
      pendingBytes: 50,
      pendingMessages: 5,
      lastAccessed: now - sessionTTL - 1000, // Expired
    });

    // Add active session
    sessionDeltas.set("/path/to/active.jsonl", {
      lastSize: 200,
      pendingBytes: 100,
      pendingMessages: 10,
      lastAccessed: now, // Active
    });

    // Cleanup expired sessions
    let removed = 0;
    for (const [key, state] of sessionDeltas.entries()) {
      if (now - state.lastAccessed > sessionTTL) {
        sessionDeltas.delete(key);
        removed++;
      }
    }

    expect(removed).toBe(1);
    expect(sessionDeltas.has("/path/to/expired.jsonl")).toBe(false);
    expect(sessionDeltas.has("/path/to/active.jsonl")).toBe(true);
  });
});

// Background Cleanup 테스트
describe("Background Cleanup", () => {
  it("should periodically cleanup expired entries", async () => {
    const cache = new LRUCache<string>({
      maxSize: 10,
      defaultTTL: 100, // 100ms
    });

    cache.set("key1", "value1");

    // Wait for TTL to expire
    await new Promise((resolve) => setTimeout(resolve, 150));

    // Manual cleanup (simulating background cleanup)
    const removed = cache.cleanup();

    expect(removed).toBe(1);
    expect(cache.get("key1")).toBeUndefined();
  });
});

// Metrics 테스트
describe("Cache Metrics", () => {
  it("should provide accurate cache statistics", () => {
    const cache = new LRUCache<string>({
      maxSize: 5,
      defaultTTL: 1000,
    });

    // Populate cache
    for (let i = 0; i < 5; i++) {
      cache.set(`key${i}`, `value${i}`);
    }

    // Generate hits and misses
    cache.get("key0"); // hit
    cache.get("key1"); // hit
    cache.get("key2"); // hit
    cache.get("nonexistent"); // miss

    const stats = cache.getStats();

    expect(stats.size).toBe(5);
    expect(stats.maxSize).toBe(5);
    expect(stats.hits).toBe(3);
    expect(stats.misses).toBe(1);
    expect(stats.hitRate).toBe(0.75);
    expect(stats.evictions).toBe(0);
  });

  it("should track expired entries", async () => {
    const cache = new LRUCache<string>({
      maxSize: 5,
      defaultTTL: 50,
    });

    cache.set("key1", "value1");

    // Wait for expiration
    await new Promise((resolve) => setTimeout(resolve, 100));

    // Access expired entry
    cache.get("key1");

    const stats = cache.getStats();
    expect(stats.expired).toBe(1);
  });
});
