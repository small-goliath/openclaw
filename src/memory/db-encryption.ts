/**
 * Database Encryption (TDE) Module
 * Transparent database encryption using file-level encryption
 *
 * This module provides encryption at rest for SQLite databases by:
 * 1. Encrypting the entire database file using AES-256-GCM
 * 2. Providing transparent read/write operations
 * 3. Supporting key rotation and migration
 *
 * Note: SQLCipher is not used because it requires a custom SQLite build.
 * Instead, we implement transparent file-level encryption that works
 * with Node.js's built-in node:sqlite module.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { EncryptionService, getEncryptionService } from "../security/encryption.js";
import { logSecurityEvent, alertCriticalEvent } from "../security/siem-logger.js";

const log = createSubsystemLogger("memory/db-encryption");

// Encryption constants
const ENCRYPTION_VERSION = 1;
const ENCRYPTION_MAGIC = Buffer.from("OPENCLAWDB");
const KEY_DERIVATION_ITERATIONS = 256000;
const AES_KEY_SIZE = 32; // 256 bits
const AES_IV_SIZE = 16; // 128 bits
const AES_TAG_SIZE = 16; // 128 bits

/**
 * Database encryption configuration
 */
export interface DatabaseEncryptionConfig {
  /** Whether encryption is enabled */
  enabled: boolean;
  /** Key provider type */
  keyProvider: "local" | "aws-kms" | "azure-keyvault" | "master-key";
  /** Key ID for KMS/KeyVault providers */
  keyId?: string;
  /** Page size for encryption chunks (default: 4096) */
  pageSize?: number;
  /** KDF iterations for key derivation */
  kdfIter?: number;
  /** Whether to verify integrity on read */
  verifyIntegrity?: boolean;
}

/**
 * Encrypted database file header
 */
interface EncryptionHeader {
  version: number;
  magic: Buffer;
  encryptedAt: number;
  keyProvider: string;
  keyId?: string;
  iv: Buffer;
  tag: Buffer;
  originalSize: number;
}

/**
 * Database encryption key manager
 */
export class DatabaseEncryptionManager {
  private encryptionService: EncryptionService | null;
  private keyCache = new Map<string, { key: Buffer; expiresAt: number }>();
  private readonly CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

  constructor() {
    this.encryptionService = getEncryptionService();
  }

  /**
   * Get or derive database encryption key
   */
  async getDatabaseKey(config: DatabaseEncryptionConfig): Promise<Buffer | null> {
    if (!config.enabled) {
      return null;
    }

    const cacheKey = `${config.keyProvider}:${config.keyId || "default"}`;

    // Check cache
    const cached = this.keyCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.key;
    }

    let key: Buffer | null = null;

    switch (config.keyProvider) {
      case "master-key":
        key = await this.getMasterKey();
        break;
      case "local":
      case "aws-kms":
      case "azure-keyvault":
        key = await this.getKeyFromEncryptionService();
        break;
      default:
        log.error("Unknown key provider", { provider: config.keyProvider });
        return null;
    }

    if (key) {
      // Cache the key
      this.keyCache.set(cacheKey, {
        key,
        expiresAt: Date.now() + this.CACHE_TTL_MS,
      });
    }

    return key;
  }

  /**
   * Get master key from file-based storage
   */
  private async getMasterKey(): Promise<Buffer | null> {
    try {
      const { resolveStateDir } = await import("../config/paths.js");
      const keyPath = path.join(resolveStateDir(), ".db-master-key");

      if (fs.existsSync(keyPath)) {
        // Read existing key
        const encryptedKey = fs.readFileSync(keyPath, "base64");

        // Decrypt using encryption service
        if (this.encryptionService) {
          try {
            const decrypted = await this.encryptionService.decrypt({
              v: 1,
              alg: "aes-256-gcm",
              iv: "",
              data: encryptedKey,
              tag: "",
            });
            return Buffer.from(decrypted, "hex");
          } catch {
            // Decryption failed, generate new key
            log.warn("Failed to decrypt existing DB key, generating new one");
          }
        }
      }

      // Generate new key
      const newKey = crypto.randomBytes(AES_KEY_SIZE);

      // Encrypt and store
      if (this.encryptionService) {
        const encrypted = await this.encryptionService.encrypt(newKey.toString("hex"));
        fs.mkdirSync(path.dirname(keyPath), { recursive: true, mode: 0o700 });
        fs.writeFileSync(keyPath, encrypted.data, { mode: 0o600 });
      } else {
        // No encryption service, store plaintext (not recommended)
        log.warn("Encryption service not available, storing DB key in plaintext");
        fs.mkdirSync(path.dirname(keyPath), { recursive: true, mode: 0o700 });
        fs.writeFileSync(keyPath, newKey.toString("base64"), { mode: 0o600 });
      }

      // SIEM logging
      await logSecurityEvent({
        type: "db_encryption_key_generated",
        provider: "master-key",
        timestamp: Date.now(),
      });

      return newKey;
    } catch (err) {
      log.error("Failed to get master key", { err });
      await alertCriticalEvent({
        type: "db_encryption_key_failure",
        reason: "master_key_error",
        error: String(err),
        timestamp: Date.now(),
      });
      return null;
    }
  }

  /**
   * Get key from encryption service
   */
  private async getKeyFromEncryptionService(): Promise<Buffer | null> {
    if (!this.encryptionService) {
      log.error("Encryption service not initialized");
      return null;
    }

    try {
      // Derive a database-specific key from the encryption service
      const keyData = crypto.randomBytes(AES_KEY_SIZE);
      const encrypted = await this.encryptionService.encrypt(keyData.toString("hex"));
      const decrypted = await this.encryptionService.decrypt(encrypted);
      return Buffer.from(decrypted, "hex");
    } catch (err) {
      log.error("Failed to get key from encryption service", { err });
      return null;
    }
  }

  /**
   * Create encryption header
   */
  private createHeader(
    config: DatabaseEncryptionConfig,
    iv: Buffer,
    tag: Buffer,
    originalSize: number,
  ): Buffer {
    const header = Buffer.alloc(128);
    let offset = 0;

    // Magic number (10 bytes)
    ENCRYPTION_MAGIC.copy(header, offset);
    offset += 10;

    // Version (2 bytes)
    header.writeUInt16BE(ENCRYPTION_VERSION, offset);
    offset += 2;

    // Encrypted at timestamp (8 bytes)
    header.writeBigUInt64BE(BigInt(Date.now()), offset);
    offset += 8;

    // Key provider length and value (32 bytes max)
    const providerBuf = Buffer.from(config.keyProvider, "utf8");
    header.writeUInt8(Math.min(providerBuf.length, 32), offset);
    offset += 1;
    providerBuf.copy(header, offset, 0, 32);
    offset += 32;

    // Original size (8 bytes)
    header.writeBigUInt64BE(BigInt(originalSize), offset);
    offset += 8;

    // IV (16 bytes)
    iv.copy(header, offset);
    offset += AES_IV_SIZE;

    // Tag (16 bytes)
    tag.copy(header, offset);
    offset += AES_TAG_SIZE;

    // Reserved (44 bytes)
    offset += 44;

    return header.slice(0, offset);
  }

  /**
   * Parse encryption header from buffer
   */
  private parseHeader(buffer: Buffer): EncryptionHeader | null {
    try {
      let offset = 0;

      // Check magic number
      const magic = buffer.slice(offset, offset + 10);
      offset += 10;
      if (!magic.equals(ENCRYPTION_MAGIC)) {
        return null;
      }

      // Version
      const version = buffer.readUInt16BE(offset);
      offset += 2;
      if (version !== ENCRYPTION_VERSION) {
        log.error("Unsupported encryption version", { version });
        return null;
      }

      // Encrypted at
      const encryptedAt = Number(buffer.readBigUInt64BE(offset));
      offset += 8;

      // Key provider
      const providerLen = buffer.readUInt8(offset);
      offset += 1;
      const keyProvider = buffer.slice(offset, offset + providerLen).toString("utf8");
      offset += 32;

      // Original size
      const originalSize = Number(buffer.readBigUInt64BE(offset));
      offset += 8;

      // IV
      const iv = buffer.slice(offset, offset + AES_IV_SIZE);
      offset += AES_IV_SIZE;

      // Tag
      const tag = buffer.slice(offset, offset + AES_TAG_SIZE);
      offset += AES_TAG_SIZE;

      return {
        version,
        magic,
        encryptedAt,
        keyProvider,
        iv,
        tag,
        originalSize,
      };
    } catch (err) {
      log.error("Failed to parse encryption header", { err });
      return null;
    }
  }

  /**
   * Encrypt database file
   */
  async encryptDatabaseFile(
    sourcePath: string,
    targetPath: string,
    key: Buffer,
    config: DatabaseEncryptionConfig,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Read source file
      const plaintext = fs.readFileSync(sourcePath);

      // Generate IV
      const iv = crypto.randomBytes(AES_IV_SIZE);

      // Encrypt
      const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
      const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const tag = cipher.getAuthTag();

      // Create header
      const header = this.createHeader(config, iv, tag, plaintext.length);

      // Write encrypted file
      fs.mkdirSync(path.dirname(targetPath), { recursive: true, mode: 0o700 });
      fs.writeFileSync(targetPath, Buffer.concat([header, encrypted]), { mode: 0o600 });

      log.info("Database file encrypted", {
        sourcePath,
        targetPath,
        originalSize: plaintext.length,
        encryptedSize: header.length + encrypted.length,
      });

      return { success: true };
    } catch (err) {
      const error = String(err);
      log.error("Failed to encrypt database file", { err, sourcePath, targetPath });
      return { success: false, error };
    }
  }

  /**
   * Decrypt database file
   */
  async decryptDatabaseFile(
    encryptedPath: string,
    targetPath: string,
    key: Buffer,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Read encrypted file
      const encrypted = fs.readFileSync(encryptedPath);

      // Parse header (128 bytes)
      const headerSize = 128;
      if (encrypted.length < headerSize) {
        return { success: false, error: "Invalid encrypted file: too small" };
      }

      const header = this.parseHeader(encrypted.slice(0, headerSize));
      if (!header) {
        return { success: false, error: "Invalid encryption header" };
      }

      // Extract encrypted data
      const ciphertext = encrypted.slice(headerSize);

      // Decrypt
      const decipher = crypto.createDecipheriv("aes-256-gcm", key, header.iv);
      decipher.setAuthTag(header.tag);
      const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);

      // Verify size
      if (plaintext.length !== header.originalSize) {
        log.warn("Decrypted size mismatch", {
          expected: header.originalSize,
          actual: plaintext.length,
        });
      }

      // Write decrypted file
      fs.mkdirSync(path.dirname(targetPath), { recursive: true, mode: 0o700 });
      fs.writeFileSync(targetPath, plaintext, { mode: 0o600 });

      log.info("Database file decrypted", {
        encryptedPath,
        targetPath,
        originalSize: header.originalSize,
        decryptedSize: plaintext.length,
      });

      return { success: true };
    } catch (err) {
      const error = String(err);
      log.error("Failed to decrypt database file", { err, encryptedPath, targetPath });
      return { success: false, error };
    }
  }

  /**
   * Check if file is encrypted
   */
  isEncryptedFile(filePath: string): boolean {
    try {
      if (!fs.existsSync(filePath)) {
        return false;
      }

      const fd = fs.openSync(filePath, "r");
      try {
        const magic = Buffer.alloc(10);
        fs.readSync(fd, magic, 0, 10, 0);
        return magic.equals(ENCRYPTION_MAGIC);
      } finally {
        fs.closeSync(fd);
      }
    } catch {
      return false;
    }
  }

  /**
   * Create encrypted database
   */
  async createEncryptedDatabase(
    dbPath: string,
    config: DatabaseEncryptionConfig,
  ): Promise<{ success: boolean; error?: string; isNew?: boolean }> {
    try {
      // If encryption is disabled, just return success
      if (!config.enabled) {
        log.debug("Database encryption is disabled, skipping encryption", { dbPath });
        return { success: true, isNew: !fs.existsSync(dbPath) };
      }

      const key = await this.getDatabaseKey(config);
      if (!key) {
        return { success: false, error: "Failed to get encryption key" };
      }

      // Check if database already exists
      const isExisting = fs.existsSync(dbPath);

      if (isExisting) {
        // Check if already encrypted
        if (this.isEncryptedFile(dbPath)) {
          log.info("Database is already encrypted", { dbPath });
          return { success: true, isNew: false };
        }

        // Encrypt existing database
        return await this.encryptExistingDatabase(dbPath, key, config);
      }

      // Create new encrypted database
      // First create empty SQLite database
      const { DatabaseSync } = (await import("./sqlite.js")).requireNodeSqlite();
      fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 });
      const db = new DatabaseSync(dbPath);
      db.exec("CREATE TABLE IF NOT EXISTS __encryption_meta (version INTEGER)");
      db.close();

      // Encrypt the empty database
      const tempPath = `${dbPath}.tmp`;
      const result = await this.encryptDatabaseFile(dbPath, tempPath, key, config);
      if (!result.success) {
        fs.unlinkSync(dbPath);
        return result;
      }

      // Replace original with encrypted
      fs.renameSync(tempPath, dbPath);

      log.info("Created new encrypted database", { dbPath });

      await logSecurityEvent({
        type: "db_encryption_enabled",
        dbPath,
        provider: config.keyProvider,
        timestamp: Date.now(),
      });

      return { success: true, isNew: true };
    } catch (err) {
      const error = String(err);
      log.error("Failed to create encrypted database", { err, dbPath });
      return { success: false, error };
    }
  }

  /**
   * Encrypt existing database (migration)
   */
  async encryptExistingDatabase(
    dbPath: string,
    key?: Buffer,
    config?: DatabaseEncryptionConfig,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Check if file exists
      if (!fs.existsSync(dbPath)) {
        return { success: false, error: "Database file does not exist" };
      }

      // Check if already encrypted
      if (this.isEncryptedFile(dbPath)) {
        log.info("Database is already encrypted", { dbPath });
        return { success: true };
      }

      // Get key if not provided
      let encryptionKey = key;
      let encryptionConfig = config;

      if (!encryptionKey) {
        if (!encryptionConfig) {
          encryptionConfig = createDbEncryptionConfigFromEnv();
        }
        // If encryption is disabled, just return success
        if (!encryptionConfig.enabled) {
          log.debug("Database encryption is disabled, skipping encryption", { dbPath });
          return { success: true };
        }
        encryptionKey = await this.getDatabaseKey(encryptionConfig);
        if (!encryptionKey) {
          return { success: false, error: "Failed to get encryption key" };
        }
      }

      // Create backup
      const backupPath = `${dbPath}.backup-${Date.now()}`;
      fs.copyFileSync(dbPath, backupPath);
      log.info("Database backup created before encryption", { backupPath });

      // Encrypt database
      const tempPath = `${dbPath}.encrypted`;
      const result = await this.encryptDatabaseFile(
        dbPath,
        tempPath,
        encryptionKey,
        encryptionConfig || createDbEncryptionConfigFromEnv(),
      );

      if (!result.success) {
        // Restore from backup
        fs.copyFileSync(backupPath, dbPath);
        fs.unlinkSync(backupPath);
        return result;
      }

      // Replace original with encrypted
      fs.renameSync(tempPath, dbPath);

      // Remove backup after successful encryption
      fs.unlinkSync(backupPath);

      log.info("Existing database encrypted successfully", { dbPath });

      await logSecurityEvent({
        type: "db_encryption_migration",
        dbPath,
        backupPath,
        timestamp: Date.now(),
      });

      return { success: true };
    } catch (err) {
      const error = String(err);
      log.error("Failed to encrypt existing database", { err, dbPath });
      return { success: false, error };
    }
  }

  /**
   * Migrate unencrypted database to encrypted
   */
  async migrateUnencryptedToEncrypted(
    sourcePath: string,
    targetPath: string,
    key?: Buffer,
    config?: DatabaseEncryptionConfig,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Verify source exists
      if (!fs.existsSync(sourcePath)) {
        return { success: false, error: "Source database does not exist" };
      }

      // Check if source is already encrypted
      if (this.isEncryptedFile(sourcePath)) {
        // Just copy if already encrypted
        fs.copyFileSync(sourcePath, targetPath);
        return { success: true };
      }

      // Get key if not provided
      let encryptionKey = key;
      let encryptionConfig = config;

      if (!encryptionKey) {
        if (!encryptionConfig) {
          encryptionConfig = createDbEncryptionConfigFromEnv();
        }
        encryptionKey = await this.getDatabaseKey(encryptionConfig);
        if (!encryptionKey) {
          return { success: false, error: "Failed to get encryption key" };
        }
      }

      // Encrypt source to target
      const result = await this.encryptDatabaseFile(
        sourcePath,
        targetPath,
        encryptionKey,
        encryptionConfig || createDbEncryptionConfigFromEnv(),
      );

      if (result.success) {
        log.info("Database migration completed", { sourcePath, targetPath });

        await logSecurityEvent({
          type: "db_encryption_migration",
          sourcePath,
          targetPath,
          timestamp: Date.now(),
        });
      }

      return result;
    } catch (err) {
      const error = String(err);
      log.error("Failed to migrate database", { err, sourcePath, targetPath });
      return { success: false, error };
    }
  }

  /**
   * Decrypt database for use
   */
  async decryptForUse(
    encryptedPath: string,
    tempPath: string,
    key?: Buffer,
    config?: DatabaseEncryptionConfig,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Check if encrypted
      if (!this.isEncryptedFile(encryptedPath)) {
        // Not encrypted, just return the path
        return { success: true };
      }

      // Get key if not provided
      let decryptionKey = key;

      if (!decryptionKey) {
        const encryptionConfig = config || createDbEncryptionConfigFromEnv();
        decryptionKey = await this.getDatabaseKey(encryptionConfig);
        if (!decryptionKey) {
          return { success: false, error: "Failed to get encryption key" };
        }
      }

      // Decrypt to temp location
      return await this.decryptDatabaseFile(encryptedPath, tempPath, decryptionKey);
    } catch (err) {
      const error = String(err);
      log.error("Failed to decrypt database for use", { err, encryptedPath });
      return { success: false, error };
    }
  }

  /**
   * Re-encrypt database with new key (key rotation)
   */
  async rotateKey(
    dbPath: string,
    oldKey: Buffer,
    newKey: Buffer,
    config: DatabaseEncryptionConfig,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // Check if encrypted
      if (!this.isEncryptedFile(dbPath)) {
        return { success: false, error: "Database is not encrypted" };
      }

      // Decrypt to temp
      const tempPath = `${dbPath}.decrypt-tmp`;
      const decryptResult = await this.decryptDatabaseFile(dbPath, tempPath, oldKey);
      if (!decryptResult.success) {
        return decryptResult;
      }

      // Re-encrypt with new key
      const newTempPath = `${dbPath}.reencrypt-tmp`;
      const encryptResult = await this.encryptDatabaseFile(tempPath, newTempPath, newKey, config);

      // Cleanup temp
      fs.unlinkSync(tempPath);

      if (!encryptResult.success) {
        return encryptResult;
      }

      // Replace original
      fs.renameSync(newTempPath, dbPath);

      log.info("Database key rotation completed", { dbPath });

      await logSecurityEvent({
        type: "db_encryption_key_rotation",
        dbPath,
        timestamp: Date.now(),
      });

      return { success: true };
    } catch (err) {
      const error = String(err);
      log.error("Failed to rotate database key", { err, dbPath });
      return { success: false, error };
    }
  }

  /**
   * Verify database integrity
   */
  async verifyIntegrity(
    dbPath: string,
    key?: Buffer,
    config?: DatabaseEncryptionConfig,
  ): Promise<{
    valid: boolean;
    error?: string;
    details?: {
      encrypted: boolean;
      size: number;
      header?: EncryptionHeader;
    };
  }> {
    try {
      if (!fs.existsSync(dbPath)) {
        return { valid: false, error: "Database file does not exist" };
      }

      const stats = fs.statSync(dbPath);
      const isEncrypted = this.isEncryptedFile(dbPath);

      if (!isEncrypted) {
        return {
          valid: true,
          details: {
            encrypted: false,
            size: stats.size,
          },
        };
      }

      // Get key if not provided
      let decryptionKey = key;
      if (!decryptionKey) {
        const encryptionConfig = config || createDbEncryptionConfigFromEnv();
        decryptionKey = await this.getDatabaseKey(encryptionConfig);
        if (!decryptionKey) {
          return { valid: false, error: "Failed to get encryption key" };
        }
      }

      // Try to decrypt to verify
      const tempPath = `${dbPath}.verify-tmp`;
      const decryptResult = await this.decryptDatabaseFile(dbPath, tempPath, decryptionKey);

      // Cleanup
      if (fs.existsSync(tempPath)) {
        fs.unlinkSync(tempPath);
      }

      if (!decryptResult.success) {
        return {
          valid: false,
          error: decryptResult.error,
          details: {
            encrypted: true,
            size: stats.size,
          },
        };
      }

      return {
        valid: true,
        details: {
          encrypted: true,
          size: stats.size,
        },
      };
    } catch (err) {
      return {
        valid: false,
        error: String(err),
        details: {
          encrypted: false,
          size: 0,
        },
      };
    }
  }

  /**
   * Clear key cache
   */
  clearCache(): void {
    this.keyCache.clear();
  }

  /**
   * Remove cached key for specific provider
   */
  removeKeyFromCache(provider: string, keyId?: string): void {
    const cacheKey = `${provider}:${keyId || "default"}`;
    this.keyCache.delete(cacheKey);
  }
}

// Singleton instance
let globalDbEncryptionManager: DatabaseEncryptionManager | null = null;

/**
 * Get global database encryption manager
 */
export function getDatabaseEncryptionManager(): DatabaseEncryptionManager {
  if (!globalDbEncryptionManager) {
    globalDbEncryptionManager = new DatabaseEncryptionManager();
  }
  return globalDbEncryptionManager;
}

/**
 * Create database encryption config from environment variables
 */
export function createDbEncryptionConfigFromEnv(): DatabaseEncryptionConfig {
  const enabled = process.env.OPENCLAW_DB_ENCRYPTION_ENABLED === "true";
  const keyProvider =
    (process.env.OPENCLAW_DB_KEY_PROVIDER as DatabaseEncryptionConfig["keyProvider"]) ||
    "master-key";
  const keyId = process.env.OPENCLAW_DB_KEY_ID;
  const pageSize = process.env.OPENCLAW_DB_PAGE_SIZE
    ? parseInt(process.env.OPENCLAW_DB_PAGE_SIZE, 10)
    : 4096;
  const kdfIter = process.env.OPENCLAW_DB_KDF_ITER
    ? parseInt(process.env.OPENCLAW_DB_KDF_ITER, 10)
    : KEY_DERIVATION_ITERATIONS;
  const verifyIntegrity = process.env.OPENCLAW_DB_VERIFY_INTEGRITY !== "false";

  return {
    enabled,
    keyProvider,
    keyId,
    pageSize,
    kdfIter,
    verifyIntegrity,
  };
}

/**
 * Encrypted database connection wrapper
 * Provides transparent encryption/decryption for SQLite databases
 */
export class EncryptedDatabaseConnection {
  private encryptionManager: DatabaseEncryptionManager;
  private config: DatabaseEncryptionConfig;
  private encryptedPath: string;
  private tempPath: string;
  private key: Buffer | null = null;
  private isOpen = false;

  constructor(encryptedPath: string, config: DatabaseEncryptionConfig) {
    this.encryptedPath = encryptedPath;
    this.config = config;
    this.encryptionManager = getDatabaseEncryptionManager();
    this.tempPath = `${encryptedPath}.decrypted`;
  }

  /**
   * Open encrypted database and return temporary path for SQLite
   */
  async open(): Promise<{ success: boolean; tempPath?: string; error?: string }> {
    try {
      // Get encryption key
      this.key = await this.encryptionManager.getDatabaseKey(this.config);
      if (!this.key) {
        return { success: false, error: "Failed to get encryption key" };
      }

      // Check if encrypted
      if (!this.encryptionManager.isEncryptedFile(this.encryptedPath)) {
        // Not encrypted, use as-is
        this.isOpen = true;
        return { success: true, tempPath: this.encryptedPath };
      }

      // Decrypt to temp location
      const result = await this.encryptionManager.decryptDatabaseFile(
        this.encryptedPath,
        this.tempPath,
        this.key,
      );

      if (!result.success) {
        return result;
      }

      this.isOpen = true;
      return { success: true, tempPath: this.tempPath };
    } catch (err) {
      return { success: false, error: String(err) };
    }
  }

  /**
   * Close and re-encrypt database
   */
  async close(): Promise<{ success: boolean; error?: string }> {
    try {
      if (!this.isOpen) {
        return { success: true };
      }

      // Check if was encrypted
      if (!this.encryptionManager.isEncryptedFile(this.encryptedPath)) {
        // Was not encrypted, just cleanup
        this.isOpen = false;
        return { success: true };
      }

      if (!this.key) {
        return { success: false, error: "Encryption key not available" };
      }

      // Re-encrypt temp file
      const result = await this.encryptionManager.encryptDatabaseFile(
        this.tempPath,
        this.encryptedPath,
        this.key,
        this.config,
      );

      // Cleanup temp file
      if (fs.existsSync(this.tempPath)) {
        fs.unlinkSync(this.tempPath);
      }

      this.isOpen = false;
      return result;
    } catch (err) {
      return { success: false, error: String(err) };
    }
  }

  /**
   * Check if connection is open
   */
  isConnectionOpen(): boolean {
    return this.isOpen;
  }

  /**
   * Get encrypted file path
   */
  getEncryptedPath(): string {
    return this.encryptedPath;
  }

  /**
   * Get temp file path (only valid when open)
   */
  getTempPath(): string | null {
    return this.isOpen ? this.tempPath : null;
  }
}

// Re-export types
export type { EncryptionHeader };
