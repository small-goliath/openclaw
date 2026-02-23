/**
 * Static data encryption module for OpenClaw
 *
 * Provides encryption/decryption services for sensitive data:
 * - Session records
 * - Auth profiles
 * - Channel credentials
 * - Memory embeddings
 * - Config files
 *
 * Supports multiple key providers:
 * - local: OS keychain/keyring integration
 * - aws-kms: AWS KMS integration (TODO)
 * - azure-keyvault: Azure Key Vault integration (TODO)
 */

import { spawnSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { resolveStateDir } from "../config/paths.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { getOrInitWorkerPool, type CryptoWorkerPool } from "../workers/worker-pool.js";
import { logSecurityEvent, alertCriticalEvent } from "./siem-logger.js";

const log = createSubsystemLogger("security/encryption");

// ============================================================================
// Types
// ============================================================================

export type EncryptionProvider = "local" | "aws-kms" | "azure-keyvault";

export interface EncryptionConfig {
  /** Encryption provider type */
  provider: EncryptionProvider;
  /** Whether encryption is enabled */
  enabled: boolean;
  /** Key ID for KMS/KeyVault providers */
  keyId?: string;
  /** Key rotation period in days (default: 90) */
  keyRotationDays?: number;
  /** Path to local key file (local provider only, for fallback) */
  localKeyPath?: string;
  /**
   * Allow file-based fallback when OS keychain fails.
   * SECURITY WARNING: Only enable this if OS keychain is unavailable.
   * File-based storage is less secure than OS keychain.
   * Set via OPENCLAW_ENCRYPTION_ALLOW_FILE_FALLBACK environment variable.
   * @default false
   */
  allowFileFallback?: boolean;
  /**
   * Fail-secure mode: throw error instead of falling back to file storage.
   * When true and OS keychain fails, encryption will be disabled rather than
   * using file fallback (even if allowFileFallback is true).
   * Set via OPENCLAW_ENCRYPTION_FAIL_SECURE environment variable.
   * @default false
   */
  failSecure?: boolean;
}

export interface EncryptedData {
  /** Encryption format version */
  v: number;
  /** Algorithm used */
  alg: "aes-256-gcm";
  /** Base64-encoded initialization vector */
  iv: string;
  /** Base64-encoded encrypted data */
  data: string;
  /** Base64-encoded GCM authentication tag */
  tag: string;
  /** Key version identifier */
  keyVersion?: string;
  /** Timestamp when encrypted */
  encryptedAt?: number;
}

export interface KeyMetadata {
  /** Key version identifier */
  version: string;
  /** Key creation timestamp */
  createdAt: number;
  /** Key rotation period in days */
  rotationDays: number;
  /** Provider type */
  provider: EncryptionProvider;
}

// ============================================================================
// Constants
// ============================================================================

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32; // 256 bits
const IV_LENGTH = 16; // 128 bits
const TAG_LENGTH = 16; // 128 bits
const KEY_VERSION = 1;
const DEFAULT_ROTATION_DAYS = 90;

// OS Keychain constants
const KEYCHAIN_SERVICE = "openclaw-encryption";
const KEYCHAIN_ACCOUNT = "master-key";
const KEYCHAIN_VERSION_ACCOUNT = "key-metadata";

// ============================================================================
// Utility Functions
// ============================================================================

function generateRandomBytes(length: number): Buffer {
  return crypto.randomBytes(length);
}

function base64Encode(buffer: Buffer): string {
  return buffer.toString("base64");
}

function base64Decode(str: string): Buffer {
  return Buffer.from(str, "base64");
}

function isEncryptedData(obj: unknown): obj is EncryptedData {
  if (!obj || typeof obj !== "object") {
    return false;
  }
  const data = obj as Record<string, unknown>;
  return (
    data.v === KEY_VERSION &&
    data.alg === ALGORITHM &&
    typeof data.iv === "string" &&
    typeof data.data === "string" &&
    typeof data.tag === "string"
  );
}

// ============================================================================
// OS Keychain Integration
// ============================================================================

class KeychainManager {
  private platform: NodeJS.Platform;

  constructor() {
    this.platform = process.platform;
  }

  /**
   * Store a secret in the OS keychain/keyring
   */
  storeSecret(service: string, account: string, secret: string): boolean {
    try {
      switch (this.platform) {
        case "darwin":
          return this.storeMacOSKeychain(service, account, secret);
        case "linux":
          return this.storeLinuxSecret(service, account, secret);
        case "win32":
          return this.storeWindowsCredential(service, account, secret);
        default:
          log.warn("unsupported platform for keychain storage", { platform: this.platform });
          return false;
      }
    } catch (err) {
      log.warn("failed to store secret in keychain", { err, platform: this.platform });
      return false;
    }
  }

  /**
   * Retrieve a secret from the OS keychain/keyring
   */
  retrieveSecret(service: string, account: string): string | null {
    try {
      switch (this.platform) {
        case "darwin":
          return this.retrieveMacOSKeychain(service, account);
        case "linux":
          return this.retrieveLinuxSecret(service, account);
        case "win32":
          return this.retrieveWindowsCredential(service, account);
        default:
          log.warn("unsupported platform for keychain retrieval", { platform: this.platform });
          return null;
      }
    } catch (err) {
      log.warn("failed to retrieve secret from keychain", { err, platform: this.platform });
      return null;
    }
  }

  /**
   * Delete a secret from the OS keychain/keyring
   */
  deleteSecret(service: string, account: string): boolean {
    try {
      switch (this.platform) {
        case "darwin":
          return this.deleteMacOSKeychain(service, account);
        case "linux":
          return this.deleteLinuxSecret(service, account);
        case "win32":
          return this.deleteWindowsCredential(service, account);
        default:
          return false;
      }
    } catch (err) {
      log.warn("failed to delete secret from keychain", { err });
      return false;
    }
  }

  // macOS Keychain
  private storeMacOSKeychain(service: string, account: string, secret: string): boolean {
    const result = spawnSync(
      "security",
      ["add-generic-password", "-s", service, "-a", account, "-w", secret, "-U"],
      { encoding: "utf-8" },
    );
    if (result.status !== 0) {
      log.warn("macOS keychain store failed", { stderr: result.stderr });
      return false;
    }
    return true;
  }

  private retrieveMacOSKeychain(service: string, account: string): string | null {
    const result = spawnSync(
      "security",
      ["find-generic-password", "-s", service, "-a", account, "-w"],
      { encoding: "utf-8" },
    );
    if (result.status !== 0) {
      // Item not found is expected for first run
      if (result.stderr?.includes("could not be found")) {
        return null;
      }
      log.warn("macOS keychain retrieve failed", { stderr: result.stderr });
      return null;
    }
    return result.stdout.trim();
  }

  private deleteMacOSKeychain(service: string, account: string): boolean {
    const result = spawnSync(
      "security",
      ["delete-generic-password", "-s", service, "-a", account],
      { encoding: "utf-8" },
    );
    return result.status === 0;
  }

  // Linux Secret Service (libsecret)
  private storeLinuxSecret(service: string, account: string, secret: string): boolean {
    // Try secret-tool first (libsecret CLI)
    const result = spawnSync(
      "secret-tool",
      ["store", "--label", `${service} ${account}`, "service", service, "account", account],
      { input: secret, encoding: "utf-8" },
    );
    if (result.status !== 0) {
      log.warn("secret-tool store failed", { stderr: result.stderr });
      return false;
    }
    return true;
  }

  private retrieveLinuxSecret(service: string, account: string): string | null {
    const result = spawnSync("secret-tool", ["lookup", "service", service, "account", account], {
      encoding: "utf-8",
    });
    if (result.status !== 0) {
      return null;
    }
    return result.stdout.trim();
  }

  private deleteLinuxSecret(service: string, account: string): boolean {
    const result = spawnSync("secret-tool", ["clear", "service", service, "account", account], {
      encoding: "utf-8",
    });
    return result.status === 0;
  }

  // Windows Credential Manager
  private storeWindowsCredential(service: string, account: string, secret: string): boolean {
    // Use PowerShell to store credential
    const target = `${service}:${account}`;
    const psScript = `
      $secure = ConvertTo-SecureString "${secret.replace(/"/g, '`"')}" -AsPlainText -Force
      New-StoredCredential -Target "${target}" -SecurePassword $secure -Type Generic -Persist LocalMachine
    `;
    const result = spawnSync("powershell.exe", ["-Command", psScript], { encoding: "utf-8" });
    if (result.status !== 0) {
      log.warn("Windows credential store failed", { stderr: result.stderr });
      return false;
    }
    return true;
  }

  private retrieveWindowsCredential(service: string, account: string): string | null {
    const target = `${service}:${account}`;
    const psScript = `
      $cred = Get-StoredCredential -Target "${target}"
      if ($cred) { $cred.GetNetworkCredential().Password }
    `;
    const result = spawnSync("powershell.exe", ["-Command", psScript], { encoding: "utf-8" });
    if (result.status !== 0 || !result.stdout.trim()) {
      return null;
    }
    return result.stdout.trim();
  }

  private deleteWindowsCredential(service: string, account: string): boolean {
    const target = `${service}:${account}`;
    const psScript = `Remove-StoredCredential -Target "${target}"`;
    const result = spawnSync("powershell.exe", ["-Command", psScript], { encoding: "utf-8" });
    return result.status === 0;
  }
}

// ============================================================================
// Key Manager
// ============================================================================

export class KeyManager {
  private keychain: KeychainManager;
  private config: EncryptionConfig;
  private cacheKey: Buffer | null = null;
  private cacheExpiry: number = 0;
  private readonly CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

  constructor(config: EncryptionConfig) {
    this.config = config;
    this.keychain = new KeychainManager();
  }

  /**
   * Get or create the encryption key
   */
  async getKey(): Promise<Buffer | null> {
    // Check cache first
    if (this.cacheKey && Date.now() < this.cacheExpiry) {
      return this.cacheKey;
    }

    if (!this.config.enabled) {
      return null;
    }

    let key: Buffer | null = null;

    switch (this.config.provider) {
      case "local":
        key = await this.getLocalKey();
        break;
      case "aws-kms":
        key = await this.getAwsKmsKey();
        break;
      case "azure-keyvault":
        key = await this.getAzureKeyVaultKey();
        break;
      default:
        log.error("unknown encryption provider", { provider: this.config.provider });
        return null;
    }

    // Cache the key
    if (key) {
      this.cacheKey = key;
      this.cacheExpiry = Date.now() + this.CACHE_TTL_MS;
    }

    return key;
  }

  /**
   * Clear the key cache
   */
  clearCache(): void {
    this.cacheKey = null;
    this.cacheExpiry = 0;
  }

  /**
   * Check if key rotation is needed
   */
  isRotationNeeded(metadata?: KeyMetadata): boolean {
    if (!metadata) {
      return true;
    }

    const rotationDays = metadata.rotationDays || DEFAULT_ROTATION_DAYS;
    const rotationMs = rotationDays * 24 * 60 * 60 * 1000;
    const nextRotation = metadata.createdAt + rotationMs;

    return Date.now() >= nextRotation;
  }

  /**
   * Get key metadata
   */
  getKeyMetadata(): KeyMetadata | null {
    const metadataJson = this.keychain.retrieveSecret(KEYCHAIN_SERVICE, KEYCHAIN_VERSION_ACCOUNT);
    if (!metadataJson) {
      return null;
    }

    try {
      return JSON.parse(metadataJson) as KeyMetadata;
    } catch {
      return null;
    }
  }

  /**
   * Store key metadata
   */
  private storeKeyMetadata(metadata: KeyMetadata): boolean {
    return this.keychain.storeSecret(
      KEYCHAIN_SERVICE,
      KEYCHAIN_VERSION_ACCOUNT,
      JSON.stringify(metadata),
    );
  }

  private async getLocalKey(): Promise<Buffer | null> {
    // Try to retrieve existing key from keychain
    const existingKey = this.keychain.retrieveSecret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);

    if (existingKey) {
      try {
        return base64Decode(existingKey);
      } catch (err) {
        log.warn("failed to decode existing key, generating new key", { err });
      }
    }

    // Generate new key
    const newKey = generateRandomBytes(KEY_LENGTH);
    const keyBase64 = base64Encode(newKey);

    // Try to store in keychain
    const stored = this.keychain.storeSecret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, keyBase64);

    if (!stored) {
      // Check fail-secure mode first
      if (this.config.failSecure) {
        log.error(
          "SECURITY: OS keychain storage failed and fail-secure mode is enabled. " +
            "Encryption will be disabled. Please configure OS keychain or disable fail-secure mode.",
        );
        await this.notifyKeychainFailure("fail_secure_mode");
        return null;
      }

      // Check if file fallback is explicitly allowed
      const allowFileFallback = this.config.allowFileFallback === true;

      if (!allowFileFallback) {
        log.error(
          "SECURITY: Failed to store encryption key in OS keychain. " +
            "File-based fallback is disabled by default for security reasons. " +
            "To enable file fallback (NOT RECOMMENDED for production), set: " +
            "OPENCLAW_ENCRYPTION_ALLOW_FILE_FALLBACK=true",
        );
        log.error(
          "Alternatively, please ensure OS keychain is available: " +
            "- macOS: Keychain Access should be accessible\n" +
            "- Linux: secret-tool (libsecret) should be installed\n" +
            "- Windows: Credential Manager should be accessible",
        );
        await this.notifyKeychainFailure("fallback_disabled");
        return null;
      }

      // File fallback with enhanced security
      return await this.handleKeychainFailure(keyBase64, newKey);
    }

    // Store metadata
    const metadata: KeyMetadata = {
      version: `v${KEY_VERSION}`,
      createdAt: Date.now(),
      rotationDays: this.config.keyRotationDays || DEFAULT_ROTATION_DAYS,
      provider: "local",
    };
    this.storeKeyMetadata(metadata);

    log.info("generated new encryption key", { provider: "local" });
    return newKey;
  }

  /**
   * 키체인 실패 처리 - 파일 폴팩 (강화된 보안)
   */
  private async handleKeychainFailure(keyBase64: string, newKey: Buffer): Promise<Buffer | null> {
    // Critical 보안 알림
    await alertCriticalEvent({
      id: crypto.randomUUID(),
      eventType: "SUSPICIOUS_ACTIVITY",
      severity: "critical",
      timestamp: new Date().toISOString(),
      correlationId: crypto.randomUUID(),
      source: {
        component: "encryption",
        host: "localhost",
        version: "1.0.0",
      },
      details: {
        activityType: "unusual_api_usage",
        description: "OS keychain storage failed, falling back to file-based storage",
        riskScore: 75,
        indicators: ["keychain_failure", "file_fallback"],
      },
    });

    log.warn(
      "SECURITY WARNING: OS keychain storage failed. Falling back to file-based storage. " +
        "This is LESS SECURE than OS keychain as the key may be accessible to other processes.",
    );
    log.warn(
      "To improve security, please:\n" +
        "1. Ensure OS keychain service is running\n" +
        "2. Check application permissions for keychain access\n" +
        "3. Consider using AWS KMS or Azure Key Vault for production",
    );

    const keyPath = this.config.localKeyPath || this.getDefaultKeyPath();
    try {
      // 디렉토리 생성 (안전한 권한)
      await fs.promises.mkdir(path.dirname(keyPath), { recursive: true, mode: 0o700 });

      // 키 파일 저장 (600 권한)
      await fs.promises.writeFile(keyPath, keyBase64, { mode: 0o600 });

      // 권한 검증
      const stats = await fs.promises.stat(keyPath);
      const mode = stats.mode & 0o777;

      if (mode !== 0o600) {
        log.error(
          `SECURITY: Key file permissions ${mode.toString(8)} != 600. Attempting to fix...`,
        );
        await fs.promises.chmod(keyPath, 0o600);
      }

      // 체크섬 생성 (무결성 검증)
      const checksum = crypto.createHash("sha256").update(keyBase64).digest("hex");
      const checksumPath = `${keyPath}.checksum`;
      await fs.promises.writeFile(checksumPath, checksum, { mode: 0o600 });

      // SIEM 로깅
      await logSecurityEvent({
        id: crypto.randomUUID(),
        eventType: "CONFIG_CHANGE",
        severity: "high",
        timestamp: new Date().toISOString(),
        correlationId: crypto.randomUUID(),
        source: {
          component: "encryption",
          host: "localhost",
          version: "1.0.0",
        },
        details: {
          changeType: "create",
          configPath: keyPath,
          changedBy: "system",
        },
      });

      // Log file storage details for audit
      log.info("SECURITY: Encryption key stored to FILE (fallback mode)", {
        keyPath,
        permissions: "600",
        owner: stats.uid,
        warning: "File storage is less secure than OS keychain",
      });

      return newKey;
    } catch (err) {
      log.error("failed to store encryption key to file", { err, keyPath });
      await this.notifyKeychainFailure("file_storage_failed");
      return null;
    }
  }

  /**
   * 키체인 실패 알림
   */
  private async notifyKeychainFailure(reason: string): Promise<void> {
    await alertCriticalEvent({
      id: crypto.randomUUID(),
      eventType: "SUSPICIOUS_ACTIVITY",
      severity: "critical",
      timestamp: new Date().toISOString(),
      correlationId: crypto.randomUUID(),
      source: {
        component: "encryption",
        host: "localhost",
        version: "1.0.0",
      },
      details: {
        activityType: "unusual_api_usage",
        description: `Keychain failure: ${reason}`,
        riskScore: 90,
        indicators: ["keychain_failure", reason],
      },
    });
  }

  /**
   * 키 파일 무결성 검증
   */
  async verifyKeyFileIntegrity(): Promise<boolean> {
    const keyPath = this.config.localKeyPath || this.getDefaultKeyPath();
    const checksumPath = `${keyPath}.checksum`;

    try {
      if (!fs.existsSync(keyPath) || !fs.existsSync(checksumPath)) {
        return false;
      }

      const keyContent = fs.readFileSync(keyPath, "utf-8");
      const storedChecksum = fs.readFileSync(checksumPath, "utf-8").trim();
      const computedChecksum = crypto.createHash("sha256").update(keyContent).digest("hex");

      if (storedChecksum !== computedChecksum) {
        log.error("SECURITY: Key file integrity check failed!");
        await alertCriticalEvent({
          id: crypto.randomUUID(),
          eventType: "SUSPICIOUS_ACTIVITY",
          severity: "critical",
          timestamp: new Date().toISOString(),
          correlationId: crypto.randomUUID(),
          source: {
            component: "encryption",
            host: "localhost",
            version: "1.0.0",
          },
          details: {
            activityType: "data_scraping",
            description: `Key file integrity check failed: ${keyPath}`,
            riskScore: 95,
            indicators: ["integrity_failure", keyPath],
          },
        });
        return false;
      }

      return true;
    } catch (err) {
      log.warn("Key file integrity verification failed", { err });
      return false;
    }
  }

  private async getAwsKmsKey(): Promise<Buffer | null> {
    try {
      // 동적 import로 AWS SDK 로드
      const { KMSClient, GenerateDataKeyCommand, DecryptCommand } =
        await import("@aws-sdk/client-kms");

      const keyId = this.config.keyId || process.env.AWS_KMS_KEY_ID;
      if (!keyId) {
        log.error("AWS KMS Key ID not configured");
        await alertCriticalEvent({
          id: crypto.randomUUID(),
          eventType: "SUSPICIOUS_ACTIVITY",
          severity: "critical",
          timestamp: new Date().toISOString(),
          correlationId: crypto.randomUUID(),
          source: {
            component: "encryption",
            host: "localhost",
            version: "1.0.0",
          },
          details: {
            activityType: "unusual_api_usage",
            description: "AWS KMS Key ID not configured",
            riskScore: 80,
            indicators: ["aws_kms", "key_id_missing"],
          },
        });
        return null;
      }

      const region = process.env.AWS_REGION || "us-east-1";
      const client = new KMSClient({ region });

      // 먼저 저장된 암호화된 데이터 키가 있는지 확인
      const encryptedKeyPath = this.getAwsEncryptedKeyPath();
      if (fs.existsSync(encryptedKeyPath)) {
        try {
          const encryptedKey = fs.readFileSync(encryptedKeyPath, "base64");
          const decryptCommand = new DecryptCommand({
            CiphertextBlob: Buffer.from(encryptedKey, "base64"),
          });
          const decryptResponse = (await client.send(decryptCommand)) as { Plaintext?: Uint8Array };

          const plaintext = decryptResponse.Plaintext;
          if (plaintext instanceof Uint8Array) {
            log.info("AWS KMS: decrypted existing data key");
            return Buffer.from(plaintext);
          }
        } catch (err) {
          log.warn("AWS KMS: failed to decrypt existing key, generating new one", { err });
        }
      }

      // 새 데이터 키 생성 (Envelope Encryption)
      const command = new GenerateDataKeyCommand({
        KeyId: keyId,
        KeySpec: "AES_256",
      });

      const response = (await client.send(command)) as {
        Plaintext?: Uint8Array;
        CiphertextBlob?: Uint8Array;
      };

      const responsePlaintext = response.Plaintext;
      const responseCiphertextBlob = response.CiphertextBlob;
      if (
        !(responsePlaintext instanceof Uint8Array) ||
        !(responseCiphertextBlob instanceof Uint8Array)
      ) {
        throw new Error("KMS GenerateDataKey returned empty response");
      }

      // 암호화된 데이터 키 저장 (나중에 복호화용)
      const encryptedKey = Buffer.from(responseCiphertextBlob).toString("base64");
      fs.mkdirSync(path.dirname(encryptedKeyPath), { recursive: true, mode: 0o700 });
      fs.writeFileSync(encryptedKeyPath, encryptedKey, { mode: 0o600 });

      // 평문 데이터 키 반환 (메모리에만 유지)
      const plaintextKey = Buffer.from(responsePlaintext);

      log.info("AWS KMS: generated new data key", { keyId });

      // SIEM 로깅
      await logSecurityEvent({
        id: crypto.randomUUID(),
        eventType: "CONFIG_CHANGE",
        severity: "info",
        timestamp: new Date().toISOString(),
        correlationId: crypto.randomUUID(),
        source: {
          component: "encryption",
          host: "localhost",
          version: "1.0.0",
        },
        details: {
          changeType: "create",
          configPath: `aws-kms://${keyId}`,
          changedBy: "system",
        },
      });

      return plaintextKey;
    } catch (err) {
      log.error("AWS KMS operation failed", { err });
      await alertCriticalEvent({
        id: crypto.randomUUID(),
        eventType: "SUSPICIOUS_ACTIVITY",
        severity: "critical",
        timestamp: new Date().toISOString(),
        correlationId: crypto.randomUUID(),
        source: {
          component: "encryption",
          host: "localhost",
          version: "1.0.0",
        },
        details: {
          activityType: "unusual_api_usage",
          description: `AWS KMS operation failed: ${String(err)}`,
          riskScore: 85,
          indicators: ["aws_kms", "operation_failed"],
        },
      });
      return null;
    }
  }

  private getAwsEncryptedKeyPath(): string {
    return path.join(resolveStateDir(), ".aws-kms-encrypted-key");
  }

  private async getAzureKeyVaultKey(): Promise<Buffer | null> {
    try {
      // 동적 import로 Azure SDK 로드
      const { KeyClient, CryptographyClient } = await import("@azure/keyvault-keys");
      const { DefaultAzureCredential } = await import("@azure/identity");

      const vaultUrl = process.env.AZURE_KEY_VAULT_URL;
      const keyName = this.config.keyId || process.env.AZURE_KEY_NAME;

      if (!vaultUrl || !keyName) {
        log.error("Azure Key Vault configuration missing");
        await alertCriticalEvent({
          id: crypto.randomUUID(),
          eventType: "SUSPICIOUS_ACTIVITY",
          severity: "critical",
          timestamp: new Date().toISOString(),
          correlationId: crypto.randomUUID(),
          source: {
            component: "encryption",
            host: "localhost",
            version: "1.0.0",
          },
          details: {
            activityType: "unusual_api_usage",
            description: "Azure Key Vault configuration missing",
            riskScore: 80,
            indicators: ["azure_keyvault", "configuration_missing"],
          },
        });
        return null;
      }

      // Azure AD 인증 (DefaultAzureCredential 사용)
      const credential = new DefaultAzureCredential();
      const keyClient = new KeyClient(vaultUrl, credential);

      // 먼저 저장된 래핑된 키가 있는지 확인
      const wrappedKeyPath = this.getAzureWrappedKeyPath();
      if (fs.existsSync(wrappedKeyPath)) {
        try {
          const wrappedKey = fs.readFileSync(wrappedKeyPath, "base64");

          // 키 가져오기
          const key = await keyClient.getKey(keyName);
          const cryptoClient = new CryptographyClient(key, credential);

          // 키 언래핑
          const unwrapResult = await cryptoClient.unwrapKey(
            "RSA-OAEP",
            Buffer.from(wrappedKey, "base64"),
          );

          if (unwrapResult.result) {
            log.info("Azure Key Vault: unwrapped existing data key");
            return Buffer.from(unwrapResult.result);
          }
        } catch (err) {
          log.warn("Azure Key Vault: failed to unwrap existing key, generating new one", { err });
        }
      }

      // 새 데이터 키 생성 (로컬) 및 래핑
      const dataKey = generateRandomBytes(KEY_LENGTH);

      // 키 가져오기 또는 생성
      let key;
      try {
        key = await keyClient.getKey(keyName);
      } catch {
        log.info("Azure Key Vault: creating new RSA key", { keyName });
        key = await keyClient.createRsaKey(keyName, { keySize: 4096 });
      }

      const cryptoClient = new CryptographyClient(key, credential);

      // 데이터 키 래핑
      const wrapResult = await cryptoClient.wrapKey("RSA-OAEP", dataKey);

      // 래핑된 키 저장
      const wrappedKey = Buffer.from(wrapResult.result).toString("base64");
      fs.mkdirSync(path.dirname(wrappedKeyPath), { recursive: true, mode: 0o700 });
      fs.writeFileSync(wrappedKeyPath, wrappedKey, { mode: 0o600 });

      log.info("Azure Key Vault: generated and wrapped new data key", { keyName });

      // SIEM 로깅
      await logSecurityEvent({
        id: crypto.randomUUID(),
        eventType: "CONFIG_CHANGE",
        severity: "info",
        timestamp: new Date().toISOString(),
        correlationId: crypto.randomUUID(),
        source: {
          component: "encryption",
          host: "localhost",
          version: "1.0.0",
        },
        details: {
          changeType: "create",
          configPath: `azure-keyvault://${keyName}`,
          changedBy: "system",
        },
      });

      return dataKey;
    } catch (err) {
      log.error("Azure Key Vault operation failed", { err });
      await alertCriticalEvent({
        id: crypto.randomUUID(),
        eventType: "SUSPICIOUS_ACTIVITY",
        severity: "critical",
        timestamp: new Date().toISOString(),
        correlationId: crypto.randomUUID(),
        source: {
          component: "encryption",
          host: "localhost",
          version: "1.0.0",
        },
        details: {
          activityType: "unusual_api_usage",
          description: `Azure Key Vault operation failed: ${String(err)}`,
          riskScore: 85,
          indicators: ["azure_keyvault", "operation_failed"],
        },
      });
      return null;
    }
  }

  private getAzureWrappedKeyPath(): string {
    return path.join(resolveStateDir(), ".azure-keyvault-wrapped-key");
  }

  private getDefaultKeyPath(): string {
    return path.join(resolveStateDir(), ".encryption-key");
  }
}

// ============================================================================
// Key Rotation Manager
// ============================================================================

export interface RotationResult {
  success: boolean;
  oldVersion?: string;
  newVersion?: string;
  rotatedAt?: number;
  error?: string;
}

export interface DataMigrationItem {
  id: string;
  encryptedData: EncryptedData;
  decrypt: (data: EncryptedData) => Promise<string>;
  encrypt: (plaintext: string) => Promise<EncryptedData>;
  update: (id: string, newData: EncryptedData) => Promise<void>;
}

export class KeyRotationManager {
  private rotationTimer: NodeJS.Timeout | null = null;
  private keyManager: KeyManager;
  private config: EncryptionConfig;
  private isRotating: boolean = false;
  private readonly ROTATION_CHECK_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

  constructor(keyManager: KeyManager, config: EncryptionConfig) {
    this.keyManager = keyManager;
    this.config = config;
  }

  /**
   * Start automatic key rotation scheduler
   * Checks every day if rotation is needed based on rotationDays configuration
   */
  startAutoRotation(): void {
    if (this.rotationTimer) {
      log.warn("Key rotation scheduler already running");
      return;
    }

    if (!this.config.enabled) {
      log.info("Encryption is disabled, key rotation scheduler not started");
      return;
    }

    log.info("Starting automatic key rotation scheduler", {
      checkIntervalHours: 24,
      rotationDays: this.config.keyRotationDays || DEFAULT_ROTATION_DAYS,
    });

    // Log security event for scheduler start
    logSecurityEvent({
      id: crypto.randomUUID(),
      eventType: "CONFIG_CHANGE",
      severity: "info",
      timestamp: new Date().toISOString(),
      correlationId: crypto.randomUUID(),
      source: {
        component: "encryption",
        host: "localhost",
        version: "1.0.0",
      },
      details: {
        changeType: "update",
        configPath: `key-rotation-scheduler?rotationDays=${this.config.keyRotationDays || DEFAULT_ROTATION_DAYS}`,
        changedBy: "system",
      },
    }).catch(() => {});

    // Check immediately on start
    this.checkAndRotateIfNeeded().catch((err) => {
      log.error("Initial rotation check failed", { err });
    });

    // Schedule periodic checks
    this.rotationTimer = setInterval(() => {
      this.checkAndRotateIfNeeded().catch((err) => {
        log.error("Scheduled rotation check failed", { err });
      });
    }, this.ROTATION_CHECK_INTERVAL_MS);
  }

  /**
   * Stop automatic key rotation scheduler
   */
  stopAutoRotation(): void {
    if (this.rotationTimer) {
      clearInterval(this.rotationTimer);
      this.rotationTimer = null;
      log.info("Key rotation scheduler stopped");

      // Log security event for scheduler stop
      logSecurityEvent({
        id: crypto.randomUUID(),
        eventType: "CONFIG_CHANGE",
        severity: "info",
        timestamp: new Date().toISOString(),
        correlationId: crypto.randomUUID(),
        source: {
          component: "encryption",
          host: "localhost",
          version: "1.0.0",
        },
        details: {
          changeType: "delete",
          configPath: "key-rotation-scheduler",
          changedBy: "system",
        },
      }).catch(() => {});
    }
  }

  /**
   * Check if rotation is needed and perform rotation if necessary
   */
  private async checkAndRotateIfNeeded(): Promise<void> {
    const metadata = this.keyManager.getKeyMetadata();

    if (!this.keyManager.isRotationNeeded(metadata ?? undefined)) {
      log.debug("Key rotation not needed yet", {
        nextRotation: metadata
          ? new Date(metadata.createdAt + metadata.rotationDays * 24 * 60 * 60 * 1000).toISOString()
          : "unknown",
      });
      return;
    }

    log.info("Key rotation is needed, initiating rotation");
    await this.rotateKey();
  }

  /**
   * Check if a rotation is currently in progress
   */
  isRotationInProgress(): boolean {
    return this.isRotating;
  }

  /**
   * Perform key rotation
   * This is a placeholder implementation that generates a new key.
   * In a full implementation, this would:
   * 1. Generate new key
   * 2. Decrypt all existing encrypted data with old key
   * 3. Re-encrypt with new key
   * 4. Store new key and metadata
   * 5. Log rotation event
   *
   * Note: Data migration requires integration with the specific storage layer
   * (database, config files, etc.) that holds the encrypted data.
   */
  async rotateKey(): Promise<RotationResult> {
    if (this.isRotating) {
      return {
        success: false,
        error: "Rotation already in progress",
      };
    }

    if (!this.config.enabled) {
      return {
        success: false,
        error: "Encryption is disabled",
      };
    }

    this.isRotating = true;
    const startTime = Date.now();

    try {
      // Get current metadata before rotation
      const oldMetadata = this.keyManager.getKeyMetadata();
      const oldVersion = oldMetadata?.version || "unknown";

      log.info("Starting key rotation", {
        oldVersion,
        provider: this.config.provider,
      });

      // Clear key cache to force key regeneration
      this.keyManager.clearCache();

      // Generate new key by clearing and re-initializing
      // For local provider: delete old key from keychain to force new key generation
      // For KMS providers: generate new data key
      const newKey = await this.generateNewKey();

      if (!newKey) {
        throw new Error("Failed to generate new encryption key");
      }

      // Create new metadata
      const newMetadata: KeyMetadata = {
        version: this.generateNewVersion(oldVersion),
        createdAt: Date.now(),
        rotationDays: this.config.keyRotationDays || DEFAULT_ROTATION_DAYS,
        provider: this.config.provider,
      };

      // Store new metadata
      await this.storeNewMetadata(newMetadata);

      // Log successful rotation
      const duration = Date.now() - startTime;
      log.info("Key rotation completed successfully", {
        oldVersion,
        newVersion: newMetadata.version,
        durationMs: duration,
      });

      // Log security event
      await logSecurityEvent({
        id: crypto.randomUUID(),
        eventType: "CONFIG_CHANGE",
        severity: "info",
        timestamp: new Date().toISOString(),
        correlationId: crypto.randomUUID(),
        source: {
          component: "encryption",
          host: "localhost",
          version: "1.0.0",
        },
        details: {
          changeType: "update",
          configPath: `encryption-key?action=rotate&oldVersion=${oldVersion}&newVersion=${newMetadata.version}&durationMs=${duration}`,
          changedBy: "system",
        },
      });

      // Clear cache again to ensure new key is used
      this.keyManager.clearCache();

      return {
        success: true,
        oldVersion,
        newVersion: newMetadata.version,
        rotatedAt: Date.now(),
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      log.error("Key rotation failed", { error: errorMessage });

      // Log critical security event
      await alertCriticalEvent({
        id: crypto.randomUUID(),
        eventType: "SUSPICIOUS_ACTIVITY",
        severity: "critical",
        timestamp: new Date().toISOString(),
        correlationId: crypto.randomUUID(),
        source: {
          component: "encryption",
          host: "localhost",
          version: "1.0.0",
        },
        details: {
          activityType: "unusual_api_usage",
          description: `Key rotation failed: ${errorMessage}`,
          riskScore: 70,
          indicators: ["key_rotation_failure"],
        },
      });

      return {
        success: false,
        error: errorMessage,
      };
    } finally {
      this.isRotating = false;
    }
  }

  /**
   * Generate a new encryption key
   * Implementation varies by provider
   */
  private async generateNewKey(): Promise<Buffer | null> {
    switch (this.config.provider) {
      case "local":
        return this.generateNewLocalKey();
      case "aws-kms":
        return this.generateNewAwsKmsKey();
      case "azure-keyvault":
        return this.generateNewAzureKeyVaultKey();
      default:
        log.error("Unknown provider for key generation", { provider: this.config.provider });
        return null;
    }
  }

  /**
   * Generate new local key by deleting old key and creating new one
   */
  private async generateNewLocalKey(): Promise<Buffer | null> {
    const keychain = new KeychainManager();

    // Delete old key from keychain
    const deleted = keychain.deleteSecret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT);
    if (deleted) {
      log.info("Deleted old key from keychain");
    }

    // Generate new random key
    const newKey = generateRandomBytes(KEY_LENGTH);
    const keyBase64 = base64Encode(newKey);

    // Store new key in keychain
    const stored = keychain.storeSecret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT, keyBase64);

    if (!stored) {
      // Try file fallback if keychain fails
      if (this.config.allowFileFallback) {
        return await this.storeKeyToFile(newKey, keyBase64);
      }
      return null;
    }

    return newKey;
  }

  /**
   * Store key to file as fallback
   */
  private async storeKeyToFile(newKey: Buffer, keyBase64: string): Promise<Buffer | null> {
    const keyPath = this.config.localKeyPath || path.join(resolveStateDir(), ".encryption-key");

    try {
      await fs.promises.mkdir(path.dirname(keyPath), { recursive: true, mode: 0o700 });
      await fs.promises.writeFile(keyPath, keyBase64, { mode: 0o600 });

      // Update checksum
      const checksum = crypto.createHash("sha256").update(keyBase64).digest("hex");
      await fs.promises.writeFile(`${keyPath}.checksum`, checksum, { mode: 0o600 });

      log.warn("New key stored to file (fallback mode)", { keyPath });
      return newKey;
    } catch (err) {
      log.error("Failed to store new key to file", { err });
      return null;
    }
  }

  /**
   * Generate new AWS KMS data key
   */
  private async generateNewAwsKmsKey(): Promise<Buffer | null> {
    try {
      const { KMSClient, GenerateDataKeyCommand } = await import("@aws-sdk/client-kms");

      const keyId = this.config.keyId || process.env.AWS_KMS_KEY_ID;
      if (!keyId) {
        throw new Error("AWS KMS Key ID not configured");
      }

      const region = process.env.AWS_REGION || "us-east-1";
      const client = new KMSClient({ region });

      const command = new GenerateDataKeyCommand({
        KeyId: keyId,
        KeySpec: "AES_256",
      });

      const response = (await client.send(command)) as {
        Plaintext?: Uint8Array;
        CiphertextBlob?: Uint8Array;
      };

      const responsePlaintext = response.Plaintext;
      const responseCiphertextBlob = response.CiphertextBlob;

      if (
        !(responsePlaintext instanceof Uint8Array) ||
        !(responseCiphertextBlob instanceof Uint8Array)
      ) {
        throw new Error("KMS GenerateDataKey returned empty response");
      }

      // Store encrypted key
      const encryptedKeyPath = path.join(resolveStateDir(), ".aws-kms-encrypted-key");
      const encryptedKey = Buffer.from(responseCiphertextBlob).toString("base64");
      await fs.promises.mkdir(path.dirname(encryptedKeyPath), { recursive: true, mode: 0o700 });
      await fs.promises.writeFile(encryptedKeyPath, encryptedKey, { mode: 0o600 });

      log.info("Generated new AWS KMS data key", { keyId });
      return Buffer.from(responsePlaintext);
    } catch (err) {
      log.error("Failed to generate new AWS KMS key", { err });
      return null;
    }
  }

  /**
   * Generate new Azure Key Vault wrapped key
   */
  private async generateNewAzureKeyVaultKey(): Promise<Buffer | null> {
    try {
      const { KeyClient, CryptographyClient } = await import("@azure/keyvault-keys");
      const { DefaultAzureCredential } = await import("@azure/identity");

      const vaultUrl = process.env.AZURE_KEY_VAULT_URL;
      const keyName = this.config.keyId || process.env.AZURE_KEY_NAME;

      if (!vaultUrl || !keyName) {
        throw new Error("Azure Key Vault configuration missing");
      }

      const credential = new DefaultAzureCredential();
      const keyClient = new KeyClient(vaultUrl, credential);

      // Generate new data key locally
      const dataKey = generateRandomBytes(KEY_LENGTH);

      // Get or create key
      let key;
      try {
        key = await keyClient.getKey(keyName);
      } catch {
        key = await keyClient.createRsaKey(keyName, { keySize: 4096 });
      }

      const cryptoClient = new CryptographyClient(key, credential);
      const wrapResult = await cryptoClient.wrapKey("RSA-OAEP", dataKey);

      // Store wrapped key
      const wrappedKeyPath = path.join(resolveStateDir(), ".azure-keyvault-wrapped-key");
      const wrappedKey = Buffer.from(wrapResult.result).toString("base64");
      await fs.promises.mkdir(path.dirname(wrappedKeyPath), { recursive: true, mode: 0o700 });
      await fs.promises.writeFile(wrappedKeyPath, wrappedKey, { mode: 0o600 });

      log.info("Generated and wrapped new Azure Key Vault data key", { keyName });
      return dataKey;
    } catch (err) {
      log.error("Failed to generate new Azure Key Vault key", { err });
      return null;
    }
  }

  /**
   * Generate new version string based on old version
   */
  private generateNewVersion(oldVersion: string): string {
    // Parse version number (e.g., "v1" -> 1)
    const match = oldVersion.match(/v(\d+)/);
    const versionNum = match ? parseInt(match[1], 10) : 0;
    return `v${versionNum + 1}`;
  }

  /**
   * Store new key metadata
   */
  private async storeNewMetadata(metadata: KeyMetadata): Promise<boolean> {
    const keychain = new KeychainManager();
    return keychain.storeSecret(
      KEYCHAIN_SERVICE,
      KEYCHAIN_VERSION_ACCOUNT,
      JSON.stringify(metadata),
    );
  }

  /**
   * Get next scheduled rotation time
   */
  getNextRotationTime(): Date | null {
    const metadata = this.keyManager.getKeyMetadata();
    if (!metadata) {
      return null;
    }

    const rotationDays = metadata.rotationDays || DEFAULT_ROTATION_DAYS;
    const rotationMs = rotationDays * 24 * 60 * 60 * 1000;
    return new Date(metadata.createdAt + rotationMs);
  }

  /**
   * Get time until next rotation in milliseconds
   */
  getTimeUntilRotation(): number | null {
    const nextRotation = this.getNextRotationTime();
    if (!nextRotation) {
      return null;
    }
    return Math.max(0, nextRotation.getTime() - Date.now());
  }
}

// ============================================================================
// Encryption Service
// ============================================================================

export class EncryptionService {
  private keyManager: KeyManager;
  private config: EncryptionConfig;
  private workerPool: CryptoWorkerPool | null = null;
  private useWorkers: boolean;
  private keyRotationManager: KeyRotationManager;

  constructor(config: EncryptionConfig, useWorkers: boolean = true) {
    this.config = config;
    this.keyManager = new KeyManager(config);
    this.keyRotationManager = new KeyRotationManager(this.keyManager, config);
    this.useWorkers = useWorkers && process.env.OPENCLAW_CRYPTO_WORKERS !== "disabled";

    // Worker Pool 초기화 (지연 로딩)
    if (this.useWorkers) {
      try {
        this.workerPool = getOrInitWorkerPool();
      } catch (error) {
        log.warn("Failed to initialize worker pool, falling back to main thread", {
          error: String(error),
        });
        this.useWorkers = false;
      }
    }
  }

  /**
   * Get the key rotation manager instance
   */
  getKeyRotationManager(): KeyRotationManager {
    return this.keyRotationManager;
  }

  /**
   * Start automatic key rotation
   */
  startKeyRotation(): void {
    this.keyRotationManager.startAutoRotation();
  }

  /**
   * Stop automatic key rotation
   */
  stopKeyRotation(): void {
    this.keyRotationManager.stopAutoRotation();
  }

  /**
   * Manually trigger key rotation
   */
  async rotateKey(): Promise<RotationResult> {
    return this.keyRotationManager.rotateKey();
  }

  /**
   * Check if key rotation is in progress
   */
  isKeyRotationInProgress(): boolean {
    return this.keyRotationManager.isRotationInProgress();
  }

  /**
   * Get next scheduled rotation time
   */
  getNextKeyRotationTime(): Date | null {
    return this.keyRotationManager.getNextRotationTime();
  }

  /**
   * Get time until next rotation in milliseconds
   */
  getTimeUntilKeyRotation(): number | null {
    return this.keyRotationManager.getTimeUntilRotation();
  }

  /**
   * Worker Pool 사용 여부 확인
   */
  isUsingWorkers(): boolean {
    return this.useWorkers && this.workerPool !== null;
  }

  /**
   * Check if encryption is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled;
  }

  /**
   * Encrypt plaintext data
   * PERF-005: Worker Thread를 사용하여 event loop blocking 방지
   */
  async encrypt(plaintext: string): Promise<EncryptedData> {
    const key = await this.keyManager.getKey();
    if (!key) {
      throw new Error("encryption key not available");
    }

    // Worker Pool을 사용하여 암호화 수행
    if (this.useWorkers && this.workerPool) {
      try {
        const result = await this.workerPool.execute<{ iv: string; data: string; tag: string }>(
          "encrypt",
          {
            plaintext,
            key: base64Encode(key),
          },
        );

        const metadata = this.keyManager.getKeyMetadata();
        return {
          v: KEY_VERSION,
          alg: ALGORITHM,
          iv: result.iv,
          data: result.data,
          tag: result.tag,
          keyVersion: metadata?.version,
          encryptedAt: Date.now(),
        };
      } catch (error) {
        log.warn("Worker encryption failed, falling back to main thread", { error: String(error) });
        // Fallback to main thread
      }
    }

    // Main thread fallback
    const iv = generateRandomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);

    let encrypted = cipher.update(plaintext, "utf-8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const tag = cipher.getAuthTag();
    const metadata = this.keyManager.getKeyMetadata();

    return {
      v: KEY_VERSION,
      alg: ALGORITHM,
      iv: base64Encode(iv),
      data: base64Encode(encrypted),
      tag: base64Encode(tag),
      keyVersion: metadata?.version,
      encryptedAt: Date.now(),
    };
  }

  /**
   * Decrypt encrypted data
   * PERF-005: Worker Thread를 사용하여 event loop blocking 방지
   */
  async decrypt(encryptedData: EncryptedData): Promise<string> {
    const key = await this.keyManager.getKey();
    if (!key) {
      throw new Error("encryption key not available");
    }

    // Verify algorithm
    if (encryptedData.alg !== ALGORITHM) {
      throw new Error(`unsupported encryption algorithm: ${encryptedData.alg}`);
    }

    // Verify version
    if (encryptedData.v !== KEY_VERSION) {
      throw new Error(`unsupported encryption version: ${encryptedData.v}`);
    }

    // Worker Pool을 사용하여 복호화 수행
    if (this.useWorkers && this.workerPool) {
      try {
        const result = await this.workerPool.execute<string>("decrypt", {
          ciphertext: encryptedData.data,
          key: base64Encode(key),
          iv: encryptedData.iv,
          tag: encryptedData.tag,
        });
        return result;
      } catch (error) {
        log.warn("Worker decryption failed, falling back to main thread", { error: String(error) });
        // Fallback to main thread
      }
    }

    // Main thread fallback
    const iv = base64Decode(encryptedData.iv);
    const encrypted = base64Decode(encryptedData.data);
    const tag = base64Decode(encryptedData.tag);

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
    decipher.setAuthTag(tag);

    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString("utf-8");
  }

  /**
   * Encrypt an object, returning encrypted wrapper
   */
  async encryptObject<T>(obj: T): Promise<{ encrypted: true; data: EncryptedData } | T> {
    if (!this.config.enabled) {
      return obj;
    }

    const plaintext = JSON.stringify(obj);
    const encrypted = await this.encrypt(plaintext);

    return {
      encrypted: true as const,
      data: encrypted,
    };
  }

  /**
   * Decrypt an object (handles both encrypted and plaintext)
   */
  async decryptObject<T>(obj: unknown): Promise<T> {
    // If it's encrypted data, decrypt it
    if (isEncryptedData(obj)) {
      const plaintext = await this.decrypt(obj);
      return JSON.parse(plaintext) as T;
    }

    // If it's an encrypted wrapper
    const wrapper = obj as { encrypted?: boolean; data?: EncryptedData } | undefined;
    if (wrapper?.encrypted && wrapper.data) {
      const plaintext = await this.decrypt(wrapper.data);
      return JSON.parse(plaintext) as T;
    }

    // Return as-is (plaintext)
    return obj as T;
  }

  /**
   * Encrypt specific fields of an object
   */
  async encryptFields<T extends Record<string, unknown>>(
    obj: T,
    fields: Array<keyof T>,
  ): Promise<T> {
    if (!this.config.enabled) {
      return obj;
    }

    const result = { ...obj };

    for (const field of fields) {
      const value = obj[field];
      if (value === undefined || value === null) {
        continue;
      }

      // Skip already encrypted fields
      if (isEncryptedData(value) || (value as { encrypted?: boolean })?.encrypted) {
        continue;
      }

      const plaintext = JSON.stringify(value);
      const encrypted = await this.encrypt(plaintext);
      (result[field] as unknown) = {
        encrypted: true as const,
        data: encrypted,
      };
    }

    return result;
  }

  /**
   * Decrypt specific fields of an object
   */
  async decryptFields<T extends Record<string, unknown>>(
    obj: T,
    fields: Array<keyof T>,
  ): Promise<T> {
    const result = { ...obj };

    for (const field of fields) {
      const value = obj[field];
      if (value === undefined || value === null) {
        continue;
      }

      // Check if it's encrypted
      const wrapper = value as { encrypted?: boolean; data?: EncryptedData } | undefined;
      if (wrapper?.encrypted && wrapper.data) {
        try {
          const plaintext = await this.decrypt(wrapper.data);
          (result[field] as unknown) = JSON.parse(plaintext);
        } catch (err) {
          log.warn("failed to decrypt field", { field: String(field), err });
          // Keep original value on decryption failure
        }
      }
    }

    return result;
  }

  /**
   * Check if data is encrypted
   */
  static isEncrypted(data: unknown): boolean {
    return isEncryptedData(data);
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

let globalEncryptionService: EncryptionService | null = null;

/**
 * Initialize the global encryption service
 */
export function initEncryption(config: EncryptionConfig): EncryptionService {
  globalEncryptionService = new EncryptionService(config);
  return globalEncryptionService;
}

/**
 * Get the global encryption service
 */
export function getEncryptionService(): EncryptionService | null {
  return globalEncryptionService;
}

/**
 * Get or initialize encryption service with default config
 */
export function getOrInitEncryption(config?: EncryptionConfig): EncryptionService {
  if (globalEncryptionService) {
    return globalEncryptionService;
  }

  const defaultConfig: EncryptionConfig = config || {
    provider: "local",
    enabled: true,
    keyRotationDays: 90,
  };

  return initEncryption(defaultConfig);
}

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Encrypt data using the global service
 */
export async function encrypt(plaintext: string): Promise<EncryptedData> {
  const service = getEncryptionService();
  if (!service) {
    throw new Error("encryption service not initialized");
  }
  return service.encrypt(plaintext);
}

/**
 * Decrypt data using the global service
 */
export async function decrypt(encryptedData: EncryptedData): Promise<string> {
  const service = getEncryptionService();
  if (!service) {
    throw new Error("encryption service not initialized");
  }
  return service.decrypt(encryptedData);
}

/**
 * Encrypt an object using the global service
 */
export async function encryptObject<T>(
  obj: T,
): Promise<{ encrypted: true; data: EncryptedData } | T> {
  const service = getEncryptionService();
  if (!service) {
    return obj;
  }
  return service.encryptObject(obj);
}

/**
 * Decrypt an object using the global service
 */
export async function decryptObject<T>(obj: unknown): Promise<T> {
  const service = getEncryptionService();
  if (!service) {
    return obj as T;
  }
  return service.decryptObject<T>(obj);
}

/**
 * Create default encryption config from environment
 */
export function createEncryptionConfigFromEnv(): EncryptionConfig {
  const enabled = process.env.OPENCLAW_ENCRYPTION_ENABLED === "true";
  const provider = (process.env.OPENCLAW_ENCRYPTION_PROVIDER as EncryptionProvider) || "local";
  const keyId = process.env.OPENCLAW_ENCRYPTION_KEY_ID;
  const rotationDays = process.env.OPENCLAW_ENCRYPTION_ROTATION_DAYS
    ? parseInt(process.env.OPENCLAW_ENCRYPTION_ROTATION_DAYS, 10)
    : DEFAULT_ROTATION_DAYS;
  const allowFileFallback = process.env.OPENCLAW_ENCRYPTION_ALLOW_FILE_FALLBACK === "true";
  const failSecure = process.env.OPENCLAW_ENCRYPTION_FAIL_SECURE === "true";

  return {
    provider,
    enabled,
    keyId,
    keyRotationDays: rotationDays,
    allowFileFallback,
    failSecure,
  };
}
