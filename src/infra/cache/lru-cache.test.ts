import { describe, it, expect, beforeEach } from "vitest";
import { LRUCache, createFileCacheKey, resolveCacheConfigFromEnv } from "./lru-cache.js";

describe("LRUCache", () => {
  let cache: LRUCache<string>;

  beforeEach(() => {
    cache = new LRUCache<string>({
      maxSize: 3,
      defaultTTL: 1000, // 1 second
      enableStats: true,
    });
  });

  describe("basic operations", () => {
    it("should store and retrieve values", () => {
      cache.set("key1", "value1");
      expect(cache.get("key1")).toBe("value1");
    });

    it("should return undefined for non-existent keys", () => {
      expect(cache.get("nonexistent")).toBeUndefined();
    });

    it("should check if key exists", () => {
      cache.set("key1", "value1");
      expect(cache.has("key1")).toBe(true);
      expect(cache.has("key2")).toBe(false);
    });

    it("should delete specific keys", () => {
      cache.set("key1", "value1");
      expect(cache.delete("key1")).toBe(true);
      expect(cache.delete("key1")).toBe(false);
      expect(cache.get("key1")).toBeUndefined();
    });

    it("should clear all entries", () => {
      cache.set("key1", "value1");
      cache.set("key2", "value2");
      cache.clear();
      expect(cache.get("key1")).toBeUndefined();
      expect(cache.get("key2")).toBeUndefined();
      expect(cache.size).toBe(0);
    });
  });

  describe("LRU eviction", () => {
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

      // Add new entry, should evict key2 (now least recently used)
      cache.set("key4", "value4");

      expect(cache.get("key1")).toBe("value1"); // Still there
      expect(cache.get("key2")).toBeUndefined(); // Evicted
      expect(cache.get("key3")).toBe("value3");
      expect(cache.get("key4")).toBe("value4");
    });

    it("should update LRU order on set (existing key)", () => {
      cache.set("key1", "value1");
      cache.set("key2", "value2");
      cache.set("key3", "value3");

      // Update key1 to make it most recently used
      cache.set("key1", "updated");

      // Add new entry, should evict key2
      cache.set("key4", "value4");

      expect(cache.get("key1")).toBe("updated");
      expect(cache.get("key2")).toBeUndefined();
    });
  });

  describe("TTL expiration", () => {
    it("should expire entries after TTL", async () => {
      cache = new LRUCache<string>({
        maxSize: 3,
        defaultTTL: 50, // 50ms TTL
        enableStats: true,
      });

      cache.set("key1", "value1");
      expect(cache.get("key1")).toBe("value1");

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(cache.get("key1")).toBeUndefined();
    });

    it("should use default TTL when not specified", async () => {
      cache = new LRUCache<string>({
        maxSize: 3,
        defaultTTL: 50,
        enableStats: true,
      });

      cache.set("key1", "value1");
      expect(cache.get("key1")).toBe("value1");

      // Wait for expiration
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(cache.get("key1")).toBeUndefined();
    });

    it("should allow custom TTL per entry", async () => {
      cache = new LRUCache<string>({
        maxSize: 3,
        defaultTTL: 60000, // Long default TTL
        enableStats: true,
      });

      cache.set("key1", "value1", { ttl: 5000 }); // Long TTL
      cache.set("key2", "value2", { ttl: 50 }); // Short TTL

      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(cache.get("key1")).toBe("value1"); // Still valid
      expect(cache.get("key2")).toBeUndefined(); // Expired
    });
  });

  describe("mtime-based invalidation", () => {
    it("should invalidate entry when mtime is newer", () => {
      const oldMtime = 1000;
      const newMtime = 2000;

      cache.set("key1", "value1", { mtime: oldMtime });
      expect(cache.get("key1", { mtime: oldMtime })).toBe("value1");

      // File was modified
      expect(cache.get("key1", { mtime: newMtime })).toBeUndefined();
    });

    it("should return cached value when mtime matches", () => {
      const mtime = 1000;

      cache.set("key1", "value1", { mtime });
      expect(cache.get("key1", { mtime })).toBe("value1");
      expect(cache.get("key1", { mtime: mtime - 1 })).toBe("value1");
    });

    it("should handle entries without mtime", () => {
      cache.set("key1", "value1"); // No mtime
      expect(cache.get("key1", { mtime: 2000 })).toBe("value1");
      expect(cache.get("key1")).toBe("value1");
    });
  });

  describe("statistics", () => {
    it("should track hits and misses", () => {
      cache.set("key1", "value1");

      // First access - hit
      cache.get("key1");

      // Second access - hit
      cache.get("key1");

      // Miss
      cache.get("nonexistent");

      const stats = cache.getStats();
      expect(stats.hits).toBe(2);
      expect(stats.misses).toBe(1);
      expect(stats.hitRate).toBe(2 / 3);
    });

    it("should track evictions", () => {
      cache.set("key1", "value1");
      cache.set("key2", "value2");
      cache.set("key3", "value3");
      cache.set("key4", "value4"); // Evicts key1

      const stats = cache.getStats();
      expect(stats.evictions).toBe(1);
    });

    it("should track expired entries", async () => {
      cache = new LRUCache<string>({
        maxSize: 3,
        defaultTTL: 50,
        enableStats: true,
      });

      cache.set("key1", "value1");
      await new Promise((resolve) => setTimeout(resolve, 100));

      cache.get("key1"); // Should trigger expiration

      const stats = cache.getStats();
      expect(stats.expired).toBeGreaterThanOrEqual(1);
    });

    it("should reset statistics", () => {
      cache.set("key1", "value1");
      cache.get("key1");
      cache.get("nonexistent");

      cache.resetStats();

      const stats = cache.getStats();
      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(0);
      expect(stats.evictions).toBe(0);
    });

    it("should report correct size", () => {
      expect(cache.size).toBe(0);
      cache.set("key1", "value1");
      expect(cache.size).toBe(1);
      cache.set("key2", "value2");
      expect(cache.size).toBe(2);
    });
  });

  describe("cleanup", () => {
    it("should remove expired entries on cleanup", async () => {
      cache = new LRUCache<string>({
        maxSize: 10,
        defaultTTL: 50,
        enableStats: true,
      });

      cache.set("key1", "value1");
      cache.set("key2", "value2");

      await new Promise((resolve) => setTimeout(resolve, 100));

      const removed = cache.cleanup();
      expect(removed).toBe(2);
      expect(cache.size).toBe(0);
    });

    it("should not remove valid entries on cleanup", () => {
      cache.set("key1", "value1", { ttl: 5000 });
      cache.set("key2", "value2", { ttl: 5000 });

      const removed = cache.cleanup();
      expect(removed).toBe(0);
      expect(cache.size).toBe(2);
    });
  });

  describe("keys", () => {
    it("should return all keys", () => {
      cache.set("key1", "value1");
      cache.set("key2", "value2");

      const keys = cache.keys();
      expect(keys).toContain("key1");
      expect(keys).toContain("key2");
      expect(keys).toHaveLength(2);
    });
  });

  describe("disabled stats", () => {
    it("should not track stats when disabled", () => {
      const noStatsCache = new LRUCache<string>({
        maxSize: 3,
        defaultTTL: 1000,
        enableStats: false,
      });

      noStatsCache.set("key1", "value1");
      noStatsCache.get("key1");
      noStatsCache.get("nonexistent");

      const stats = noStatsCache.getStats();
      expect(stats.hits).toBe(0);
      expect(stats.misses).toBe(0);
    });
  });
});

describe("createFileCacheKey", () => {
  it("should create consistent cache keys", () => {
    const key1 = createFileCacheKey("/path/to/file.json", 1234567890);
    const key2 = createFileCacheKey("/path/to/file.json", 1234567890);

    expect(key1).toBe(key2);
    expect(key1).toBe("/path/to/file.json:1234567890");
  });

  it("should create different keys for different mtimes", () => {
    const key1 = createFileCacheKey("/path/to/file.json", 1234567890);
    const key2 = createFileCacheKey("/path/to/file.json", 9876543210);

    expect(key1).not.toBe(key2);
  });
});

describe("resolveCacheConfigFromEnv", () => {
  it("should use default values when env vars are not set", () => {
    const env = {};
    const config = resolveCacheConfigFromEnv(env);

    expect(config.maxSize).toBe(100);
    expect(config.defaultTTL).toBe(60000);
  });

  it("should parse env vars correctly", () => {
    const env = {
      OPENCLAW_CACHE_MAX_SIZE: "200",
      OPENCLAW_CACHE_TTL_MS: "30000",
    };
    const config = resolveCacheConfigFromEnv(env);

    expect(config.maxSize).toBe(200);
    expect(config.defaultTTL).toBe(30000);
  });

  it("should handle invalid values gracefully", () => {
    const env = {
      OPENCLAW_CACHE_MAX_SIZE: "invalid",
      OPENCLAW_CACHE_TTL_MS: "-1",
    };
    const config = resolveCacheConfigFromEnv(env);

    expect(config.maxSize).toBe(100);
    expect(config.defaultTTL).toBe(60000);
  });

  it("should handle zero and negative values", () => {
    const env = {
      OPENCLAW_CACHE_MAX_SIZE: "0",
      OPENCLAW_CACHE_TTL_MS: "0",
    };
    const config = resolveCacheConfigFromEnv(env);

    expect(config.maxSize).toBe(100);
    expect(config.defaultTTL).toBe(60000);
  });
});
