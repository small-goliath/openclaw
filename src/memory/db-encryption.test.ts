/**
 * Tests for database encryption module
 */

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { initEncryption } from "../security/encryption.js";
import {
  DatabaseEncryptionManager,
  EncryptedDatabaseConnection,
  createDbEncryptionConfigFromEnv,
  getDatabaseEncryptionManager,
} from "./db-encryption.js";

describe("Database Encryption", () => {
  let tempDir: string;
  let manager: DatabaseEncryptionManager;

  beforeEach(async () => {
    // Create temp directory for tests
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "db-encryption-test-"));

    // Initialize encryption service with file fallback for tests
    initEncryption({
      provider: "local",
      enabled: true,
      allowFileFallback: true,
    });

    // Get fresh manager instance
    manager = new DatabaseEncryptionManager();
  });

  afterEach(() => {
    // Cleanup temp directory
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe("DatabaseEncryptionManager", () => {
    describe("createEncryptedDatabase", () => {
      it("should create a new encrypted database", async () => {
        const dbPath = path.join(tempDir, "test.db");
        const config = {
          enabled: true,
          keyProvider: "master-key" as const,
        };

        const result = await manager.createEncryptedDatabase(dbPath, config);

        expect(result.success).toBe(true);
        expect(result.isNew).toBe(true);
        expect(fs.existsSync(dbPath)).toBe(true);
        expect(manager.isEncryptedFile(dbPath)).toBe(true);
      });

      it("should encrypt an existing database", async () => {
        const dbPath = path.join(tempDir, "existing.db");

        // Create an unencrypted database file
        fs.writeFileSync(dbPath, "SQLite format 3\0");

        const config = {
          enabled: true,
          keyProvider: "master-key" as const,
        };

        const result = await manager.createEncryptedDatabase(dbPath, config);

        expect(result.success).toBe(true);
        expect(fs.existsSync(dbPath)).toBe(true);
        expect(manager.isEncryptedFile(dbPath)).toBe(true);
      });

      it("should return success when encryption is disabled", async () => {
        const dbPath = path.join(tempDir, "test.db");
        const config = {
          enabled: false,
          keyProvider: "master-key" as const,
        };

        const result = await manager.createEncryptedDatabase(dbPath, config);

        // When disabled, it should succeed but not encrypt
        expect(result.success).toBe(true);
        expect(result.isNew).toBe(true);
      });
    });

    describe("isEncryptedFile", () => {
      it("should detect encrypted files", async () => {
        const dbPath = path.join(tempDir, "encrypted.db");
        const config = {
          enabled: true,
          keyProvider: "master-key" as const,
        };

        await manager.createEncryptedDatabase(dbPath, config);

        expect(manager.isEncryptedFile(dbPath)).toBe(true);
      });

      it("should return false for non-encrypted files", () => {
        const plainPath = path.join(tempDir, "plain.txt");
        fs.writeFileSync(plainPath, "Hello, World!");

        expect(manager.isEncryptedFile(plainPath)).toBe(false);
      });

      it("should return false for non-existent files", () => {
        const nonExistent = path.join(tempDir, "non-existent.db");

        expect(manager.isEncryptedFile(nonExistent)).toBe(false);
      });
    });

    describe("encryptExistingDatabase", () => {
      it("should encrypt an existing database file", async () => {
        const dbPath = path.join(tempDir, "to-encrypt.db");
        fs.writeFileSync(dbPath, "SQLite format 3\0Some data here");

        const config = {
          enabled: true,
          keyProvider: "master-key" as const,
        };

        const result = await manager.encryptExistingDatabase(dbPath, undefined, config);

        expect(result.success).toBe(true);
        expect(manager.isEncryptedFile(dbPath)).toBe(true);
      });

      it("should skip already encrypted files", async () => {
        const dbPath = path.join(tempDir, "already-encrypted.db");
        const config = {
          enabled: true,
          keyProvider: "master-key" as const,
        };

        await manager.createEncryptedDatabase(dbPath, config);

        const result = await manager.encryptExistingDatabase(dbPath, undefined, config);

        expect(result.success).toBe(true);
      });

      it("should return error for non-existent files", async () => {
        const dbPath = path.join(tempDir, "non-existent.db");

        const result = await manager.encryptExistingDatabase(dbPath);

        expect(result.success).toBe(false);
        expect(result.error).toContain("does not exist");
      });
    });

    describe("migrateUnencryptedToEncrypted", () => {
      it("should migrate unencrypted to encrypted", async () => {
        const sourcePath = path.join(tempDir, "source.db");
        const targetPath = path.join(tempDir, "target.db");
        fs.writeFileSync(sourcePath, "SQLite format 3\0Data");

        const config = {
          enabled: true,
          keyProvider: "master-key" as const,
        };

        const result = await manager.migrateUnencryptedToEncrypted(
          sourcePath,
          targetPath,
          undefined,
          config,
        );

        expect(result.success).toBe(true);
        expect(fs.existsSync(targetPath)).toBe(true);
        expect(manager.isEncryptedFile(targetPath)).toBe(true);
      });

      it("should copy already encrypted files", async () => {
        const sourcePath = path.join(tempDir, "source.db");
        const targetPath = path.join(tempDir, "target.db");

        const config = {
          enabled: true,
          keyProvider: "master-key" as const,
        };

        await manager.createEncryptedDatabase(sourcePath, config);

        const result = await manager.migrateUnencryptedToEncrypted(
          sourcePath,
          targetPath,
          undefined,
          config,
        );

        expect(result.success).toBe(true);
        expect(fs.existsSync(targetPath)).toBe(true);
      });

      it("should return error for non-existent source", async () => {
        const sourcePath = path.join(tempDir, "non-existent.db");
        const targetPath = path.join(tempDir, "target.db");

        const result = await manager.migrateUnencryptedToEncrypted(sourcePath, targetPath);

        expect(result.success).toBe(false);
        expect(result.error).toContain("does not exist");
      });
    });

    describe("verifyIntegrity", () => {
      it("should verify encrypted database integrity", async () => {
        const dbPath = path.join(tempDir, "test.db");
        const config = {
          enabled: true,
          keyProvider: "master-key" as const,
        };

        await manager.createEncryptedDatabase(dbPath, config);

        const result = await manager.verifyIntegrity(dbPath, undefined, config);

        expect(result.valid).toBe(true);
        expect(result.details?.encrypted).toBe(true);
      });

      it("should verify unencrypted database", async () => {
        const dbPath = path.join(tempDir, "plain.db");
        fs.writeFileSync(dbPath, "SQLite format 3\0");

        const result = await manager.verifyIntegrity(dbPath);

        expect(result.valid).toBe(true);
        expect(result.details?.encrypted).toBe(false);
      });

      it("should return error for non-existent file", async () => {
        const dbPath = path.join(tempDir, "non-existent.db");

        const result = await manager.verifyIntegrity(dbPath);

        expect(result.valid).toBe(false);
        expect(result.error).toContain("does not exist");
      });
    });

    describe("key caching", () => {
      it("should cache and clear keys", async () => {
        const config = {
          enabled: true,
          keyProvider: "master-key" as const,
        };

        // First call should cache the key
        const key1 = await manager.getDatabaseKey(config);
        const key2 = await manager.getDatabaseKey(config);

        expect(key1).toEqual(key2);

        // Clear cache
        manager.clearCache();

        // After clearing, should get new key
        const key3 = await manager.getDatabaseKey(config);
        expect(key3).not.toBeNull();
      });
    });
  });

  describe("EncryptedDatabaseConnection", () => {
    it("should open and close encrypted database", async () => {
      const dbPath = path.join(tempDir, "conn-test.db");
      const config = {
        enabled: true,
        keyProvider: "master-key" as const,
      };

      // Use singleton manager to ensure key is cached
      const singletonManager = getDatabaseEncryptionManager();

      // Create encrypted database first
      const createResult = await singletonManager.createEncryptedDatabase(dbPath, config);
      expect(createResult.success).toBe(true);

      // Get the key for the connection (this caches it)
      const key = await singletonManager.getDatabaseKey(config);
      expect(key).not.toBeNull();

      // Open connection
      const conn = new EncryptedDatabaseConnection(dbPath, config);
      const openResult = await conn.open();

      expect(openResult.success).toBe(true);
      expect(conn.isConnectionOpen()).toBe(true);
      expect(openResult.tempPath).toBeDefined();

      // Close connection
      const closeResult = await conn.close();
      expect(closeResult.success).toBe(true);
      expect(conn.isConnectionOpen()).toBe(false);
    });

    it("should handle unencrypted database", async () => {
      const dbPath = path.join(tempDir, "plain-conn.db");
      fs.writeFileSync(dbPath, "SQLite format 3\0");

      const config = {
        enabled: true,
        keyProvider: "master-key" as const,
      };

      const conn = new EncryptedDatabaseConnection(dbPath, config);
      const openResult = await conn.open();

      expect(openResult.success).toBe(true);
      expect(openResult.tempPath).toBe(dbPath); // Should return same path for unencrypted

      await conn.close();
    });
  });

  describe("createDbEncryptionConfigFromEnv", () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it("should create config from environment variables", () => {
      process.env.OPENCLAW_DB_ENCRYPTION_ENABLED = "true";
      process.env.OPENCLAW_DB_KEY_PROVIDER = "aws-kms";
      process.env.OPENCLAW_DB_KEY_ID = "test-key-id";
      process.env.OPENCLAW_DB_PAGE_SIZE = "8192";
      process.env.OPENCLAW_DB_KDF_ITER = "100000";
      process.env.OPENCLAW_DB_VERIFY_INTEGRITY = "false";

      const config = createDbEncryptionConfigFromEnv();

      expect(config.enabled).toBe(true);
      expect(config.keyProvider).toBe("aws-kms");
      expect(config.keyId).toBe("test-key-id");
      expect(config.pageSize).toBe(8192);
      expect(config.kdfIter).toBe(100000);
      expect(config.verifyIntegrity).toBe(false);
    });

    it("should use default values when env vars not set", () => {
      delete process.env.OPENCLAW_DB_ENCRYPTION_ENABLED;
      delete process.env.OPENCLAW_DB_KEY_PROVIDER;

      const config = createDbEncryptionConfigFromEnv();

      expect(config.enabled).toBe(false);
      expect(config.keyProvider).toBe("master-key");
      expect(config.pageSize).toBe(4096);
      expect(config.kdfIter).toBe(256000);
      expect(config.verifyIntegrity).toBe(true);
    });
  });

  describe("getDatabaseEncryptionManager", () => {
    it("should return singleton instance", () => {
      const instance1 = getDatabaseEncryptionManager();
      const instance2 = getDatabaseEncryptionManager();

      expect(instance1).toBe(instance2);
    });
  });
});
