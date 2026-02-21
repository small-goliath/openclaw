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
      type: "encryption_key_file_fallback",
      severity: "high",
      message: "OS keychain storage failed, falling back to file-based storage",
      timestamp: Date.now(),
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
        type: "key_file_fallback_used",
        keyPath,
        permissions: mode,
        checksum,
        timestamp: Date.now(),
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
      type: "keychain_failure",
      reason,
      timestamp: Date.now(),
      severity: "critical",
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
          type: "encryption_key_integrity_failure",
          keyPath,
          timestamp: Date.now(),
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
          type: "encryption_key_failure",
          provider: "aws-kms",
          reason: "key_id_missing",
          timestamp: Date.now(),
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
          const decryptResponse = await client.send(decryptCommand);

          if (decryptResponse.Plaintext) {
            log.info("AWS KMS: decrypted existing data key");
            return Buffer.from(decryptResponse.Plaintext);
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

      const response = await client.send(command);

      if (!response.Plaintext || !response.CiphertextBlob) {
        throw new Error("KMS GenerateDataKey returned empty response");
      }

      // 암호화된 데이터 키 저장 (나중에 복호화용)
      const encryptedKey = Buffer.from(response.CiphertextBlob).toString("base64");
      fs.mkdirSync(path.dirname(encryptedKeyPath), { recursive: true, mode: 0o700 });
      fs.writeFileSync(encryptedKeyPath, encryptedKey, { mode: 0o600 });

      // 평문 데이터 키 반환 (메모리에만 유지)
      const plaintextKey = Buffer.from(response.Plaintext);

      log.info("AWS KMS: generated new data key", { keyId });

      // SIEM 로깅
      await logSecurityEvent({
        type: "encryption_key_generated",
        provider: "aws-kms",
        keyId,
        timestamp: Date.now(),
      });

      return plaintextKey;
    } catch (err) {
      log.error("AWS KMS operation failed", { err });
      await alertCriticalEvent({
        type: "encryption_key_failure",
        provider: "aws-kms",
        reason: "operation_failed",
        error: String(err),
        timestamp: Date.now(),
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
          type: "encryption_key_failure",
          provider: "azure-keyvault",
          reason: "configuration_missing",
          timestamp: Date.now(),
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
        type: "encryption_key_generated",
        provider: "azure-keyvault",
        keyName,
        timestamp: Date.now(),
      });

      return dataKey;
    } catch (err) {
      log.error("Azure Key Vault operation failed", { err });
      await alertCriticalEvent({
        type: "encryption_key_failure",
        provider: "azure-keyvault",
        reason: "operation_failed",
        error: String(err),
        timestamp: Date.now(),
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
// Encryption Service
// ============================================================================

export class EncryptionService {
  private keyManager: KeyManager;
  private config: EncryptionConfig;
  private workerPool: CryptoWorkerPool | null = null;
  private useWorkers: boolean;

  constructor(config: EncryptionConfig, useWorkers: boolean = true) {
    this.config = config;
    this.keyManager = new KeyManager(config);
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
    enabled: false,
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
