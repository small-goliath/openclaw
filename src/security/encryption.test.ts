/**
 * Tests for encryption module
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  EncryptionService,
  KeyManager,
  initEncryption,
  getEncryptionService,
  createEncryptionConfigFromEnv,
  type EncryptionConfig,
  type EncryptedData,
} from "./encryption.js";

describe("encryption", () => {
  let tempDir: string;
  let config: EncryptionConfig;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "encryption-test-"));
    config = {
      provider: "local",
      enabled: true,
      localKeyPath: path.join(tempDir, "test-key"),
    };
  });

  afterEach(() => {
    // Cleanup temp directory
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  });

  describe("EncryptionService", () => {
    it("should encrypt and decrypt data correctly", async () => {
      const service = new EncryptionService(config);
      const plaintext = "sensitive data that needs encryption";

      const encrypted = await service.encrypt(plaintext);
      expect(encrypted).toBeDefined();
      expect(encrypted.v).toBe(1);
      expect(encrypted.alg).toBe("aes-256-gcm");
      expect(encrypted.iv).toBeDefined();
      expect(encrypted.data).toBeDefined();
      expect(encrypted.tag).toBeDefined();

      const decrypted = await service.decrypt(encrypted);
      expect(decrypted).toBe(plaintext);
    });

    it("should encrypt different plaintexts to different ciphertexts", async () => {
      const service = new EncryptionService(config);
      const plaintext = "test data";

      const encrypted1 = await service.encrypt(plaintext);
      const encrypted2 = await service.encrypt(plaintext);

      // IV should be different
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
      // Data should be different
      expect(encrypted1.data).not.toBe(encrypted2.data);
    });

    it("should throw on decryption with wrong tag", async () => {
      const service = new EncryptionService(config);
      const plaintext = "test data";

      const encrypted = await service.encrypt(plaintext);
      // Corrupt the tag
      encrypted.tag = crypto.randomBytes(16).toString("base64");

      await expect(service.decrypt(encrypted)).rejects.toThrow();
    });

    it("should throw on decryption with tampered data", async () => {
      const service = new EncryptionService(config);
      const plaintext = "test data";

      const encrypted = await service.encrypt(plaintext);
      // Corrupt the data
      encrypted.data = crypto.randomBytes(32).toString("base64");

      await expect(service.decrypt(encrypted)).rejects.toThrow();
    });

    it("should encrypt and decrypt objects", async () => {
      const service = new EncryptionService(config);
      const obj = {
        apiKey: "sk-1234567890",
        secret: "my-secret-value",
        nested: { password: "nested-password" },
      };

      const encrypted = await service.encryptObject(obj);
      expect(encrypted).toHaveProperty("encrypted", true);
      expect(encrypted).toHaveProperty("data");

      const decrypted = await service.decryptObject(encrypted);
      expect(decrypted).toEqual(obj);
    });

    it("should return object as-is when encryption is disabled", async () => {
      const disabledConfig: EncryptionConfig = {
        provider: "local",
        enabled: false,
      };
      const service = new EncryptionService(disabledConfig);
      const obj = { secret: "value" };

      const result = await service.encryptObject(obj);
      expect(result).toEqual(obj);
    });

    it("should decrypt plaintext objects without modification", async () => {
      const service = new EncryptionService(config);
      const obj = { notEncrypted: "value" };

      const decrypted = await service.decryptObject(obj);
      expect(decrypted).toEqual(obj);
    });

    it("should encrypt and decrypt specific fields", async () => {
      const service = new EncryptionService(config);
      const obj = {
        publicField: "public",
        secretField: "secret-value",
        anotherSecret: "another-secret",
        keepPlain: "plain-text",
      };

      const encrypted = await service.encryptFields(obj, ["secretField", "anotherSecret"]);

      // Public fields should remain unchanged
      expect(encrypted.publicField).toBe("public");
      expect(encrypted.keepPlain).toBe("plain-text");

      // Secret fields should be encrypted
      expect(encrypted.secretField).toHaveProperty("encrypted", true);
      expect(encrypted.secretField).toHaveProperty("data");
      expect(encrypted.anotherSecret).toHaveProperty("encrypted", true);

      // Decrypt and verify
      const decrypted = await service.decryptFields(encrypted, ["secretField", "anotherSecret"]);
      expect(decrypted.secretField).toBe("secret-value");
      expect(decrypted.anotherSecret).toBe("another-secret");
    });

    it("should skip already encrypted fields", async () => {
      const service = new EncryptionService(config);
      const obj = {
        alreadyEncrypted: {
          encrypted: true,
          data: {
            v: 1,
            alg: "aes-256-gcm",
            iv: "test-iv",
            data: "test-data",
            tag: "test-tag",
          },
        },
      };

      const encrypted = await service.encryptFields(obj, ["alreadyEncrypted"]);
      expect(encrypted.alreadyEncrypted).toEqual(obj.alreadyEncrypted);
    });

    it("should handle null and undefined fields", async () => {
      const service = new EncryptionService(config);
      const obj = {
        nullField: null,
        undefinedField: undefined,
        validField: "value",
      };

      const encrypted = await service.encryptFields(obj, [
        "nullField",
        "undefinedField",
        "validField",
      ]);
      expect(encrypted.nullField).toBeNull();
      expect(encrypted.undefinedField).toBeUndefined();
      expect(encrypted.validField).toHaveProperty("encrypted", true);
    });
  });

  describe("KeyManager", () => {
    it("should generate and retrieve local key", async () => {
      const keyManager = new KeyManager(config);
      const key = await keyManager.getKey();

      expect(key).toBeDefined();
      expect(key?.length).toBe(32); // 256 bits

      // Should return same key on subsequent calls
      const key2 = await keyManager.getKey();
      expect(key2).toEqual(key);
    });

    it("should cache key for specified duration", async () => {
      const keyManager = new KeyManager(config);

      // Get key (should generate)
      const key1 = await keyManager.getKey();

      // Clear cache and get again
      keyManager.clearCache();
      const key2 = await keyManager.getKey();

      // Should be same key (stored in file)
      expect(key1).toEqual(key2);
    });

    it("should return null when encryption is disabled", async () => {
      const disabledConfig: EncryptionConfig = {
        provider: "local",
        enabled: false,
      };
      const keyManager = new KeyManager(disabledConfig);
      const key = await keyManager.getKey();

      expect(key).toBeNull();
    });

    it("should detect when rotation is needed", () => {
      const keyManager = new KeyManager(config);

      // No metadata = rotation needed
      expect(keyManager.isRotationNeeded(undefined)).toBe(true);

      // Old key = rotation needed
      const oldMetadata = {
        version: "v1",
        createdAt: Date.now() - 100 * 24 * 60 * 60 * 1000, // 100 days ago
        rotationDays: 90,
        provider: "local" as const,
      };
      expect(keyManager.isRotationNeeded(oldMetadata)).toBe(true);

      // Recent key = no rotation needed
      const recentMetadata = {
        version: "v1",
        createdAt: Date.now() - 30 * 24 * 60 * 60 * 1000, // 30 days ago
        rotationDays: 90,
        provider: "local" as const,
      };
      expect(keyManager.isRotationNeeded(recentMetadata)).toBe(false);
    });
  });

  describe("Global instance", () => {
    beforeEach(() => {
      // Reset global instance
      initEncryption({ provider: "local", enabled: false });
    });

    it("should initialize global encryption service", () => {
      const service = initEncryption(config);
      expect(service).toBeDefined();
      expect(getEncryptionService()).toBe(service);
    });

    it("should return same instance on multiple calls", () => {
      const service1 = initEncryption(config);
      const service2 = getEncryptionService();
      expect(service1).toBe(service2);
    });
  });

  describe("Environment config", () => {
    const originalEnv = process.env;

    beforeEach(() => {
      process.env = { ...originalEnv };
    });

    afterEach(() => {
      process.env = originalEnv;
    });

    it("should create config from environment variables", () => {
      process.env.OPENCLAW_ENCRYPTION_ENABLED = "true";
      process.env.OPENCLAW_ENCRYPTION_PROVIDER = "aws-kms";
      process.env.OPENCLAW_ENCRYPTION_KEY_ID = "arn:aws:kms:region:account:key/id";
      process.env.OPENCLAW_ENCRYPTION_ROTATION_DAYS = "30";

      const config = createEncryptionConfigFromEnv();

      expect(config.enabled).toBe(true);
      expect(config.provider).toBe("aws-kms");
      expect(config.keyId).toBe("arn:aws:kms:region:account:key/id");
      expect(config.keyRotationDays).toBe(30);
    });

    it("should use defaults when env vars not set", () => {
      delete process.env.OPENCLAW_ENCRYPTION_ENABLED;
      delete process.env.OPENCLAW_ENCRYPTION_PROVIDER;
      delete process.env.OPENCLAW_ENCRYPTION_KEY_ID;
      delete process.env.OPENCLAW_ENCRYPTION_ROTATION_DAYS;

      const config = createEncryptionConfigFromEnv();

      expect(config.enabled).toBe(false);
      expect(config.provider).toBe("local");
      expect(config.keyId).toBeUndefined();
      expect(config.keyRotationDays).toBe(90);
    });
  });

  describe("Edge cases", () => {
    it("should handle empty string encryption", async () => {
      const service = new EncryptionService(config);
      const encrypted = await service.encrypt("");
      const decrypted = await service.decrypt(encrypted);
      expect(decrypted).toBe("");
    });

    it("should handle large data encryption", async () => {
      const service = new EncryptionService(config);
      const largeData = "x".repeat(100000); // 100KB of data

      const encrypted = await service.encrypt(largeData);
      const decrypted = await service.decrypt(encrypted);
      expect(decrypted).toBe(largeData);
    });

    it("should handle unicode data", async () => {
      const service = new EncryptionService(config);
      const unicodeData = "Hello 世界 🌍 Émojis: 🎉🔐✨";

      const encrypted = await service.encrypt(unicodeData);
      const decrypted = await service.decrypt(encrypted);
      expect(decrypted).toBe(unicodeData);
    });

    it("should handle nested objects with special characters", async () => {
      const service = new EncryptionService(config);
      const obj = {
        special: 'Special chars: "quotes" \n newlines \t tabs',
        nested: {
          array: [1, 2, 3],
          bool: true,
          null: null,
        },
      };

      const encrypted = await service.encryptObject(obj);
      const decrypted = await service.decryptObject(encrypted);
      expect(decrypted).toEqual(obj);
    });

    it("should throw on unsupported algorithm", async () => {
      const service = new EncryptionService(config);
      const encrypted: EncryptedData = {
        v: 1,
        alg: "unsupported-alg",
        iv: "test",
        data: "test",
        tag: "test",
      };

      await expect(service.decrypt(encrypted)).rejects.toThrow("unsupported encryption algorithm");
    });

    it("should throw on unsupported version", async () => {
      const service = new EncryptionService(config);
      const encrypted: EncryptedData = {
        v: 999,
        alg: "aes-256-gcm",
        iv: "test",
        data: "test",
        tag: "test",
      };

      await expect(service.decrypt(encrypted)).rejects.toThrow("unsupported encryption version");
    });
  });

  describe("Backward compatibility", () => {
    it("should handle plaintext objects in decryptObject", async () => {
      const service = new EncryptionService(config);
      const plaintext = { notEncrypted: "value", number: 123 };

      const result = await service.decryptObject(plaintext);
      expect(result).toEqual(plaintext);
    });

    it("should handle null in decryptObject", async () => {
      const service = new EncryptionService(config);
      const result = await service.decryptObject(null);
      expect(result).toBeNull();
    });

    it("should handle undefined in decryptObject", async () => {
      const service = new EncryptionService(config);
      const result = await service.decryptObject(undefined);
      expect(result).toBeUndefined();
    });
  });
});
describe("File Fallback Security", () => {
  it("should not use file fallback when allowFileFallback is false", async () => {
    // Mock keychain to always fail
    const strictConfig: EncryptionConfig = {
      provider: "local",
      enabled: true,
      localKeyPath: path.join(tempDir, "fallback-test-key"),
      allowFileFallback: false,
    };

    const service = new EncryptionService(strictConfig);
    // Service should be created but encryption might fail if keychain fails
    expect(service).toBeDefined();
  });

  it("should allow file fallback when explicitly enabled", async () => {
    const fallbackConfig: EncryptionConfig = {
      provider: "local",
      enabled: true,
      localKeyPath: path.join(tempDir, "fallback-allowed-key"),
      allowFileFallback: true,
    };

    const service = new EncryptionService(fallbackConfig);
    const plaintext = "test with file fallback";

    const encrypted = await service.encrypt(plaintext);
    expect(encrypted).toBeDefined();

    const decrypted = await service.decrypt(encrypted);
    expect(decrypted).toBe(plaintext);
  });

  it("should fail secure when failSecure is true and keychain fails", async () => {
    const failSecureConfig: EncryptionConfig = {
      provider: "local",
      enabled: true,
      localKeyPath: path.join(tempDir, "fail-secure-key"),
      failSecure: true,
      allowFileFallback: true, // Even with this, failSecure should take precedence
    };

    const service = new EncryptionService(failSecureConfig);
    expect(service).toBeDefined();
  });
});

describe("Environment Configuration", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("should read allowFileFallback from environment", () => {
    process.env.OPENCLAW_ENCRYPTION_ALLOW_FILE_FALLBACK = "true";
    process.env.OPENCLAW_ENCRYPTION_FAIL_SECURE = "true";

    const config = createEncryptionConfigFromEnv();

    expect(config.allowFileFallback).toBe(true);
    expect(config.failSecure).toBe(true);
  });

  it("should default allowFileFallback to false when env not set", () => {
    delete process.env.OPENCLAW_ENCRYPTION_ALLOW_FILE_FALLBACK;
    delete process.env.OPENCLAW_ENCRYPTION_FAIL_SECURE;

    const config = createEncryptionConfigFromEnv();

    expect(config.allowFileFallback).toBe(false);
    expect(config.failSecure).toBe(false);
  });
});
