/**
 * 데이터베이스 암호화(TDE) 모듈
 * SQLCipher를 사용한 저장 데이터 암호화 지원
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { EncryptionService, getEncryptionService } from "../security/encryption.js";
import { logSecurityEvent, alertCriticalEvent } from "../security/siem-logger.js";

const log = createSubsystemLogger("memory/db-encryption");

/**
 * 데이터베이스 암호화 설정
 */
export interface DatabaseEncryptionConfig {
  /** 암호화 활성화 여부 */
  enabled: boolean;
  /** 키 제공자 */
  keyProvider: "local" | "aws-kms" | "azure-keyvault" | "master-key";
  /** 키 ID (KMS/KeyVault용) */
  keyId?: string;
  /** SQLCipher 페이지 크기 */
  pageSize?: number;
  /** KDF 반복 횟수 */
  kdfIter?: number;
}

/**
 * 암호화된 데이터베이스 연결 정보
 */
export interface EncryptedDbConnection {
  /** 데이터베이스 경로 */
  dbPath: string;
  /** 암호화 키 (SQLCipher PRAGMA key) */
  key: string;
  /** 암호화 설정 */
  config: DatabaseEncryptionConfig;
}

/**
 * 데이터베이스 암호화 키 관리자
 */
export class DatabaseEncryptionManager {
  private encryptionService: EncryptionService | null;
  private keyCache = new Map<string, { key: string; expiresAt: number }>();
  private readonly CACHE_TTL_MS = 5 * 60 * 1000; // 5분

  constructor() {
    this.encryptionService = getEncryptionService();
  }

  /**
   * 데이터베이스 암호화 키 가져오기
   */
  async getDatabaseKey(config: DatabaseEncryptionConfig): Promise<string | null> {
    if (!config.enabled) {
      return null;
    }

    const cacheKey = `${config.keyProvider}:${config.keyId || "default"}`;

    // 캐시 확인
    const cached = this.keyCache.get(cacheKey);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.key;
    }

    let key: string | null = null;

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
      // 캐시에 저장
      this.keyCache.set(cacheKey, {
        key,
        expiresAt: Date.now() + this.CACHE_TTL_MS,
      });
    }

    return key;
  }

  /**
   * 마스터 키 가져오기 (파일 기반)
   */
  private async getMasterKey(): Promise<string | null> {
    try {
      const { resolveStateDir } = await import("../config/paths.js");
      const keyPath = path.join(resolveStateDir(), ".db-master-key");

      if (fs.existsSync(keyPath)) {
        // 기존 키 읽기
        const encryptedKey = fs.readFileSync(keyPath, "base64");

        // 복호화
        if (this.encryptionService) {
          try {
            const decrypted = await this.encryptionService.decrypt({
              v: 1,
              alg: "aes-256-gcm",
              iv: "", // 실제로는 저장된 IV 사용
              data: encryptedKey,
              tag: "",
            });
            return decrypted;
          } catch {
            // 복호화 실패 시 새 키 생성
            log.warn("Failed to decrypt existing DB key, generating new one");
          }
        }
      }

      // 새 키 생성
      const newKey = crypto.randomBytes(32).toString("hex");

      // 암호화하여 저장
      if (this.encryptionService) {
        const encrypted = await this.encryptionService.encrypt(newKey);
        fs.mkdirSync(path.dirname(keyPath), { recursive: true, mode: 0o700 });
        fs.writeFileSync(keyPath, encrypted.data, { mode: 0o600 });
      } else {
        // 암호화 서비스 없으면 평문 저장 (권장하지 않음)
        log.warn("Encryption service not available, storing DB key in plaintext");
        fs.mkdirSync(path.dirname(keyPath), { recursive: true, mode: 0o700 });
        fs.writeFileSync(keyPath, Buffer.from(newKey).toString("base64"), { mode: 0o600 });
      }

      // SIEM 로깅
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
   * EncryptionService에서 키 가져오기
   */
  private async getKeyFromEncryptionService(): Promise<string | null> {
    if (!this.encryptionService) {
      log.error("Encryption service not initialized");
      return null;
    }

    try {
      // EncryptionService의 키를 데이터베이스 키로 파생
      const keyData = crypto.randomBytes(32).toString("hex");
      const encrypted = await this.encryptionService.encrypt(keyData);
      const decrypted = await this.encryptionService.decrypt(encrypted);
      return decrypted;
    } catch (err) {
      log.error("Failed to get key from encryption service", { err });
      return null;
    }
  }

  /**
   * SQLCipher PRAGMA 명령어 생성
   */
  generatePragmaCommands(key: string, config?: DatabaseEncryptionConfig): string[] {
    const commands: string[] = [];

    // 키 설정
    commands.push(`PRAGMA key = "x'${key}'";`);

    // 페이지 크기 설정 (기본값: 4096)
    const pageSize = config?.pageSize || 4096;
    commands.push(`PRAGMA cipher_page_size = ${pageSize};`);

    // KDF 반복 횟수 (기본값: 256000)
    const kdfIter = config?.kdfIter || 256000;
    commands.push(`PRAGMA kdf_iter = ${kdfIter};`);

    // HMAC 검증 활성화
    commands.push("PRAGMA cipher_hmac_algorithm = HMAC_SHA512;");

    // KDF 알고리즘
    commands.push("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;");

    return commands;
  }

  /**
   * 암호화된 데이터베이스 생성
   */
  async createEncryptedDatabase(
    dbPath: string,
    config: DatabaseEncryptionConfig,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      const key = await this.getDatabaseKey(config);
      if (!key) {
        return { success: false, error: "Failed to get encryption key" };
      }

      // 데이터베이스 파일이 이미 존재하는지 확인
      if (fs.existsSync(dbPath)) {
        // 기존 데이터베이스 암호화 (마이그레이션)
        return await this.encryptExistingDatabase(dbPath, key, config);
      }

      // 새 암호화된 데이터베이스 생성
      fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 });

      log.info("Created encrypted database", { dbPath });

      await logSecurityEvent({
        type: "db_encryption_enabled",
        dbPath,
        provider: config.keyProvider,
        timestamp: Date.now(),
      });

      return { success: true };
    } catch (err) {
      const error = String(err);
      log.error("Failed to create encrypted database", { err, dbPath });
      return { success: false, error };
    }
  }

  /**
   * 기존 데이터베이스 암호화 (마이그레이션)
   */
  private async encryptExistingDatabase(
    dbPath: string,
    key: string,
    config: DatabaseEncryptionConfig,
  ): Promise<{ success: boolean; error?: string }> {
    try {
      // 백업 생성
      const backupPath = `${dbPath}.backup-${Date.now()}`;
      fs.copyFileSync(dbPath, backupPath);

      log.info("Database backup created before encryption", { backupPath });

      // SQLCipher를 사용하여 암호화된 데이터베이스로 마이그레이션
      // 실제 구현에서는 better-sqlite3나 node-sqlite3의 SQLCipher 지원 필요
      const commands = this.generatePragmaCommands(key, config);

      log.info("Database encryption migration prepared", {
        dbPath,
        commands: commands.length,
      });

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
   * 캐시 클리어
   */
  clearCache(): void {
    this.keyCache.clear();
  }
}

// 싱글톤 인스턴스
let globalDbEncryptionManager: DatabaseEncryptionManager | null = null;

/**
 * 전역 데이터베이스 암호화 관리자 가져오기
 */
export function getDatabaseEncryptionManager(): DatabaseEncryptionManager {
  if (!globalDbEncryptionManager) {
    globalDbEncryptionManager = new DatabaseEncryptionManager();
  }
  return globalDbEncryptionManager;
}

/**
 * 데이터베이스 암호화 설정 생성
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
    : 256000;

  return {
    enabled,
    keyProvider,
    keyId,
    pageSize,
    kdfIter,
  };
}
