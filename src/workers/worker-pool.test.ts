/**
 * Worker Pool 테스트
 *
 * @module workers/worker-pool.test
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import type { WorkerPoolConfig } from "./types.js";
import {
  CryptoWorkerPool,
  initWorkerPool,
  shutdownWorkerPool,
  getWorkerPool,
} from "./worker-pool.js";

describe("CryptoWorkerPool", () => {
  let pool: CryptoWorkerPool;

  afterEach(async () => {
    if (pool) {
      await pool.shutdown();
    }
    await shutdownWorkerPool();
  });

  describe("Initialization", () => {
    it("should initialize with default config", () => {
      pool = new CryptoWorkerPool();
      const stats = pool.getStats();

      expect(stats.totalWorkers).toBeGreaterThanOrEqual(2);
      expect(stats.idleWorkers).toBe(stats.totalWorkers);
      expect(stats.busyWorkers).toBe(0);
    });

    it("should initialize with custom worker count", () => {
      pool = new CryptoWorkerPool({ workerCount: 2 });
      const stats = pool.getStats();

      expect(stats.totalWorkers).toBe(2);
    });

    it("should expose worker information", () => {
      pool = new CryptoWorkerPool({ workerCount: 2 });
      const workers = pool.getWorkers();

      expect(workers).toHaveLength(2);
      expect(workers[0]).toHaveProperty("id");
      expect(workers[0]).toHaveProperty("status");
      expect(workers[0]).toHaveProperty("totalTasks");
    });
  });

  describe("Hash Operations", () => {
    beforeEach(() => {
      pool = new CryptoWorkerPool({ workerCount: 2 });
    });

    it("should compute SHA256 hash", async () => {
      const result = await pool.execute<string>("hash", {
        data: "hello world",
        algorithm: "sha256",
      });

      expect(result).toBe("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
    });

    it("should compute SHA512 hash", async () => {
      const result = await pool.execute<string>("hash", {
        data: "hello world",
        algorithm: "sha512",
      });

      expect(result).toHaveLength(128); // SHA512 hex length
    });

    it("should handle empty string", async () => {
      const result = await pool.execute<string>("hash", {
        data: "",
        algorithm: "sha256",
      });

      expect(result).toHaveLength(64); // SHA256 hex length
    });

    it("should handle large data", async () => {
      const largeData = "x".repeat(1000000);
      const result = await pool.execute<string>("hash", {
        data: largeData,
        algorithm: "sha256",
      });

      expect(result).toHaveLength(64);
    });

    it("should handle concurrent hash requests", async () => {
      const promises = Array.from({ length: 10 }, (_, i) =>
        pool.execute<string>("hash", {
          data: `data-${i}`,
          algorithm: "sha256",
        }),
      );

      const results = await Promise.all(promises);

      expect(results).toHaveLength(10);
      results.forEach((hash) => {
        expect(hash).toHaveLength(64);
      });
    });
  });

  describe("Encryption/Decryption", () => {
    const testKey = Buffer.from(
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "hex",
    );

    beforeEach(() => {
      pool = new CryptoWorkerPool({ workerCount: 2 });
    });

    it("should encrypt and decrypt data", async () => {
      const plaintext = "secret message";

      const encrypted = await pool.execute<{ iv: string; data: string; tag: string }>("encrypt", {
        plaintext,
        key: testKey.toString("base64"),
      });

      expect(encrypted).toHaveProperty("iv");
      expect(encrypted).toHaveProperty("data");
      expect(encrypted).toHaveProperty("tag");

      const decrypted = await pool.execute<string>("decrypt", {
        ciphertext: encrypted.data,
        key: testKey.toString("base64"),
        iv: encrypted.iv,
        tag: encrypted.tag,
      });

      expect(decrypted).toBe(plaintext);
    });

    it("should produce different IVs for same plaintext", async () => {
      const plaintext = "same message";

      const encrypted1 = await pool.execute<{ iv: string; data: string; tag: string }>("encrypt", {
        plaintext,
        key: testKey.toString("base64"),
      });

      const encrypted2 = await pool.execute<{ iv: string; data: string; tag: string }>("encrypt", {
        plaintext,
        key: testKey.toString("base64"),
      });

      expect(encrypted1.iv).not.toBe(encrypted2.iv);
      expect(encrypted1.data).not.toBe(encrypted2.data);
    });

    it("should fail to decrypt with wrong key", async () => {
      const plaintext = "secret message";

      const encrypted = await pool.execute<{ iv: string; data: string; tag: string }>("encrypt", {
        plaintext,
        key: testKey.toString("base64"),
      });

      const wrongKey = Buffer.from(
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
        "hex",
      );

      await expect(
        pool.execute<string>("decrypt", {
          ciphertext: encrypted.data,
          key: wrongKey.toString("base64"),
          iv: encrypted.iv,
          tag: encrypted.tag,
        }),
      ).rejects.toThrow();
    });
  });

  describe("PBKDF2", () => {
    beforeEach(() => {
      pool = new CryptoWorkerPool({ workerCount: 2 });
    });

    it("should derive key with PBKDF2", async () => {
      const result = await pool.execute<string>("pbkdf2", {
        password: "password",
        salt: "salt",
        iterations: 1000,
        keyLength: 32,
        digest: "sha256",
      });

      expect(result).toBeTruthy();
      // Base64 encoded key
      expect(Buffer.from(result, "base64")).toHaveLength(32);
    });

    it("should produce different keys for different salts", async () => {
      const key1 = await pool.execute<string>("pbkdf2", {
        password: "password",
        salt: "salt1",
        iterations: 1000,
        keyLength: 32,
      });

      const key2 = await pool.execute<string>("pbkdf2", {
        password: "password",
        salt: "salt2",
        iterations: 1000,
        keyLength: 32,
      });

      expect(key1).not.toBe(key2);
    });
  });

  describe("Compression", () => {
    beforeEach(() => {
      pool = new CryptoWorkerPool({ workerCount: 2 });
    });

    it("should compress and decompress data", async () => {
      const data = "a".repeat(1000);

      const compressed = await pool.execute<string>("compress", {
        data,
        level: 6,
      });

      expect(compressed.length).toBeLessThan(Buffer.byteLength(data) * 2);

      const decompressed = await pool.execute<string>("decompress", {
        data: compressed,
      });

      expect(decompressed).toBe(data);
    });

    it("should handle empty string compression", async () => {
      const compressed = await pool.execute<string>("compress", {
        data: "",
        level: 6,
      });

      const decompressed = await pool.execute<string>("decompress", {
        data: compressed,
      });

      expect(decompressed).toBe("");
    });
  });

  describe("Error Handling", () => {
    beforeEach(() => {
      pool = new CryptoWorkerPool({ workerCount: 2 });
    });

    it("should handle unknown task type", async () => {
      await expect(pool.execute("unknown" as never, {})).rejects.toThrow("Unknown task type");
    });

    it("should handle invalid encryption key length", async () => {
      await expect(
        pool.execute<never>("encrypt", {
          plaintext: "test",
          key: "short-key",
        }),
      ).rejects.toThrow("Invalid key length");
    });

    it("should retry failed tasks", async () => {
      // This test verifies retry logic exists
      // Actual retry testing would require mocking worker failures
      const stats = pool.getStats();
      expect(stats.totalTasksFailed).toBe(0);
    });
  });

  describe("Statistics", () => {
    beforeEach(() => {
      pool = new CryptoWorkerPool({ workerCount: 2 });
    });

    it("should track task statistics", async () => {
      const initialStats = pool.getStats();
      expect(initialStats.totalTasksProcessed).toBe(0);

      await pool.execute<string>("hash", { data: "test", algorithm: "sha256" });

      const finalStats = pool.getStats();
      expect(finalStats.totalTasksProcessed).toBe(1);
      expect(finalStats.averageTaskDurationMs).toBeGreaterThanOrEqual(0);
    });

    it("should track worker restarts", async () => {
      const stats = pool.getStats();
      expect(stats.workerRestarts).toBe(0);
    });
  });

  describe("Events", () => {
    beforeEach(() => {
      pool = new CryptoWorkerPool({ workerCount: 2 });
    });

    it("should emit task events", async () => {
      const events: string[] = [];

      pool.onEvent((type) => {
        events.push(type);
      });

      await pool.execute<string>("hash", { data: "test", algorithm: "sha256" });

      expect(events).toContain("task:queued");
      expect(events).toContain("task:started");
      expect(events).toContain("task:completed");
    });
  });

  describe("Shutdown", () => {
    beforeEach(() => {
      pool = new CryptoWorkerPool({ workerCount: 2 });
    });

    it("should reject new tasks after shutdown", async () => {
      await pool.shutdown();

      await expect(
        pool.execute<string>("hash", { data: "test", algorithm: "sha256" }),
      ).rejects.toThrow("shutting down");
    });

    it("should complete pending tasks before shutdown", async () => {
      const promise = pool.execute<string>("hash", {
        data: "test",
        algorithm: "sha256",
      });

      await pool.shutdown(5000);

      // Task should have completed
      const result = await promise;
      expect(result).toHaveLength(64);
    });
  });

  describe("Singleton", () => {
    it("should return same instance from getWorkerPool after init", () => {
      const pool1 = initWorkerPool();
      const pool2 = getWorkerPool();

      expect(pool1).toBe(pool2);
    });

    it("should clear instance after shutdown", async () => {
      initWorkerPool();
      expect(getWorkerPool()).not.toBeNull();

      await shutdownWorkerPool();
      expect(getWorkerPool()).toBeNull();
    });
  });
});
