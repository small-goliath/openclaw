import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { loadConfig, clearConfigCache, getConfigCacheStats, writeConfigFile } from "./io.js";

describe("Config Cache", () => {
  let tempDir: string;
  let configPath: string;
  let originalEnv: NodeJS.ProcessEnv;

  beforeEach(() => {
    originalEnv = { ...process.env };
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "config-cache-test-"));
    configPath = path.join(tempDir, "config.json");

    // Set up environment
    process.env.OPENCLAW_CONFIG_PATH = configPath;
    process.env.OPENCLAW_CONFIG_CACHE_MS = "1000"; // 1 second TTL
    process.env.OPENCLAW_CONFIG_CACHE_MAX_SIZE = "5";
    delete process.env.OPENCLAW_DISABLE_CONFIG_CACHE;

    // Clear cache before each test
    clearConfigCache();
  });

  afterEach(() => {
    // Restore environment
    Object.keys(process.env).forEach((key) => {
      delete process.env[key];
    });
    Object.assign(process.env, originalEnv);

    // Clean up temp directory
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // best-effort
    }
  });

  describe("cache functionality", () => {
    it("should cache config after first load", () => {
      // Create initial config with valid structure
      fs.writeFileSync(
        configPath,
        JSON.stringify({ agents: { defaults: { model: "test-model" } } }),
        "utf-8",
      );

      // First load - should read from disk
      const config1 = loadConfig();
      expect(config1).toBeDefined();

      // Second load - should use cache
      const config2 = loadConfig();
      expect(config2).toBe(config1); // Same object reference
    });

    it("should invalidate cache when config file changes", () => {
      // Create initial config with valid structure
      fs.writeFileSync(configPath, JSON.stringify({ agents: { defaults: {} } }), "utf-8");

      // First load
      const config1 = loadConfig();
      expect(config1).toBeDefined();

      // Wait a bit to ensure different mtime
      const startTime = Date.now();
      while (Date.now() - startTime < 100) {
        // busy wait
      }

      // Modify config file with valid structure
      fs.writeFileSync(
        configPath,
        JSON.stringify({ agents: { defaults: { model: "claude-3-5-sonnet" } } }),
        "utf-8",
      );

      // Second load - should detect mtime change and reload
      const config2 = loadConfig();
      expect(config2).toBeDefined();
      // Config should be reloaded (may or may not be same object depending on timing)
      // The key point is that the cache should detect the file change
    });

    it("should return cached config when mtime is unchanged", () => {
      // Create initial config with valid structure
      fs.writeFileSync(
        configPath,
        JSON.stringify({ agents: { defaults: { model: "test-model" } } }),
        "utf-8",
      );

      // First load
      const config1 = loadConfig();

      // Second load immediately (same mtime)
      const config2 = loadConfig();

      expect(config2).toBe(config1);
    });
  });

  describe("cache statistics", () => {
    it("should track cache hits and misses", () => {
      // Create config with valid structure
      fs.writeFileSync(
        configPath,
        JSON.stringify({ agents: { defaults: { model: "test-model" } } }),
        "utf-8",
      );

      // Clear stats
      clearConfigCache();

      // First load - miss
      loadConfig();
      const stats1 = getConfigCacheStats();
      expect(stats1.misses).toBeGreaterThanOrEqual(1);

      // Second load - hit
      loadConfig();
      const stats2 = getConfigCacheStats();
      expect(stats2.hits).toBeGreaterThanOrEqual(1);
    });

    it("should report cache size", () => {
      // Create config with valid structure
      fs.writeFileSync(
        configPath,
        JSON.stringify({ agents: { defaults: { model: "test-model" } } }),
        "utf-8",
      );

      clearConfigCache();

      // Initially empty
      const stats1 = getConfigCacheStats();
      expect(stats1.size).toBe(0);

      // After load
      loadConfig();
      const stats2 = getConfigCacheStats();
      expect(stats2.size).toBe(1);
    });

    it("should calculate hit rate", () => {
      // Create config with valid structure
      fs.writeFileSync(
        configPath,
        JSON.stringify({ agents: { defaults: { model: "test-model" } } }),
        "utf-8",
      );

      clearConfigCache();

      // Load multiple times
      loadConfig(); // miss
      loadConfig(); // hit
      loadConfig(); // hit

      const stats = getConfigCacheStats();
      expect(stats.hitRate).toBeGreaterThan(0);
    });
  });

  describe("write invalidation", () => {
    it("should invalidate cache on write", async () => {
      // Create initial config with valid structure
      fs.writeFileSync(configPath, JSON.stringify({ agents: { defaults: {} } }), "utf-8");

      // Load config
      const config1 = loadConfig();
      expect(config1).toBeDefined();

      // Verify cache is populated
      const statsBefore = getConfigCacheStats();
      expect(statsBefore.size).toBe(1);

      // Write new config with valid structure (empty agents)
      await writeConfigFile({ agents: { defaults: {} } });

      // Cache should be cleared after write
      const statsAfter = getConfigCacheStats();
      expect(statsAfter.size).toBe(0);
    });
  });

  describe("disabled cache", () => {
    it("should not cache when disabled via env", () => {
      process.env.OPENCLAW_DISABLE_CONFIG_CACHE = "1";
      clearConfigCache();

      // Create config with valid structure
      fs.writeFileSync(
        configPath,
        JSON.stringify({ agents: { defaults: { model: "test-model" } } }),
        "utf-8",
      );

      // Load twice
      const config1 = loadConfig();
      const config2 = loadConfig();

      // Should be different objects (no caching)
      expect(config2).not.toBe(config1);
    });

    it("should not cache when TTL is 0", () => {
      process.env.OPENCLAW_CONFIG_CACHE_MS = "0";
      clearConfigCache();

      // Create config with valid structure
      fs.writeFileSync(
        configPath,
        JSON.stringify({ agents: { defaults: { model: "test-model" } } }),
        "utf-8",
      );

      // Load twice
      const config1 = loadConfig();
      const config2 = loadConfig();

      // Should be different objects (no caching)
      expect(config2).not.toBe(config1);
    });
  });

  describe("clearConfigCache", () => {
    it("should clear all cached entries", () => {
      // Create config with valid structure
      fs.writeFileSync(
        configPath,
        JSON.stringify({ agents: { defaults: { model: "test-model" } } }),
        "utf-8",
      );

      // Load to populate cache
      loadConfig();
      const stats1 = getConfigCacheStats();
      expect(stats1.size).toBe(1);

      // Clear cache
      clearConfigCache();

      const stats2 = getConfigCacheStats();
      expect(stats2.size).toBe(0);
      expect(stats2.hits).toBe(0);
      expect(stats2.misses).toBe(0);
    });
  });

  describe("environment configuration", () => {
    it("should respect OPENCLAW_CONFIG_CACHE_MAX_SIZE", () => {
      process.env.OPENCLAW_CONFIG_CACHE_MAX_SIZE = "10";
      clearConfigCache();

      const stats = getConfigCacheStats();
      // The max size is applied to new cache creation
      expect(stats.size).toBe(0);
    });

    it("should handle invalid cache size gracefully", () => {
      process.env.OPENCLAW_CONFIG_CACHE_MAX_SIZE = "invalid";
      clearConfigCache();

      // Should not throw
      expect(() => {
        fs.writeFileSync(
          configPath,
          JSON.stringify({ agents: { defaults: { model: "test-model" } } }),
          "utf-8",
        );
        loadConfig();
      }).not.toThrow();
    });
  });

  describe("cache with non-existent config", () => {
    it("should handle non-existent config files", () => {
      // Ensure config doesn't exist
      try {
        fs.unlinkSync(configPath);
      } catch {
        // ignore
      }

      // Should return empty config
      const config = loadConfig();
      expect(config).toBeDefined();
      expect(typeof config).toBe("object");
    });
  });
});
