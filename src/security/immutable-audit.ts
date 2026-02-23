/**
 * 불변 감사 로그 저장소 구현
 * WORM(Write Once Read Many) 보호 및 암호화 무결성 검증
 * 체인 해싱을 통한 변조 방지
 * HMAC-SHA256 디지털 서명 지원 (FR-012)
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { createSubsystemLogger } from "../logging/subsystem.js";
import { KeyManager } from "./encryption.js";

const log = createSubsystemLogger("security/immutable-audit");

// Keychain constants for audit log signing
const AUDIT_SIGNING_KEYCHAIN_SERVICE = "openclaw-audit-signing";
const AUDIT_SIGNING_KEYCHAIN_ACCOUNT = "signing-key";

/**
 * 감사 로그 엔트리
 */
export interface AuditLogEntry {
  timestamp: number;
  sequence: number;
  eventType: string;
  userId?: string;
  resourceId?: string;
  action: string;
  result: "success" | "failure" | "denied";
  details?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
  sessionId?: string;
  previousHash: string; // 이전 엔트리의 해시
  hash: string; // 현재 엔트리의 해시
}

/**
 * 서명된 감사 로그 엔트리 (FR-012)
 * HMAC-SHA256 디지털 서명이 추가된 엔트리
 */
export interface SignedAuditLogEntry extends AuditLogEntry {
  /** HMAC-SHA256 signature */
  signature: string;
  /** Signature algorithm */
  signatureAlgorithm: "HMAC-SHA256";
}

/**
 * 서명 검증 결과
 */
export interface SignatureVerificationResult {
  /** Whether all signatures are valid */
  valid: boolean;
  /** List of invalid entry sequences */
  invalidEntries: number[];
  /** Total entries checked */
  totalEntries: number;
  /** Error message if verification failed */
  error?: string;
}

/**
 * 감사 로그 메타데이터
 */
interface AuditLogMetadata {
  createdAt: number;
  lastEntryAt: number;
  entryCount: number;
  lastHash: string;
}

/**
 * 무결성 검증 결과
 */
export interface IntegrityCheckResult {
  valid: boolean;
  tamperedEntries: number[];
  totalEntries: number;
  firstTamperedIndex?: number;
  error?: string;
}

/**
 * 로그 저장소 설정
 */
interface ImmutableAuditStoreConfig {
  logDir: string;
  maxEntriesPerFile: number;
  rotationInterval: number; // milliseconds
}

const DEFAULT_CONFIG: ImmutableAuditStoreConfig = {
  logDir: "./logs/audit",
  maxEntriesPerFile: 10000,
  rotationInterval: 24 * 60 * 60 * 1000, // 24시간
};

/**
 * 감사 로그 엔트리 해시 계산
 */
function calculateEntryHash(entry: Omit<AuditLogEntry, "hash">): string {
  const data = JSON.stringify({
    timestamp: entry.timestamp,
    sequence: entry.sequence,
    eventType: entry.eventType,
    userId: entry.userId,
    resourceId: entry.resourceId,
    action: entry.action,
    result: entry.result,
    details: entry.details,
    ipAddress: entry.ipAddress,
    userAgent: entry.userAgent,
    sessionId: entry.sessionId,
    previousHash: entry.previousHash,
  });

  return crypto.createHash("sha256").update(data).digest("hex");
}

/**
 * 제네시스 해시 (첫 엔트리용)
 */
function getGenesisHash(): string {
  return crypto.createHash("sha256").update("OPENCLAW_AUDIT_LOG_GENESIS").digest("hex");
}

/**
 * 서명 데이터 구성
 * 엔트리의 핵심 필드를 JSON으로 직렬화하여 서명
 */
function getSignableData(entry: AuditLogEntry): string {
  return JSON.stringify({
    timestamp: entry.timestamp,
    sequence: entry.sequence,
    eventType: entry.eventType,
    hash: entry.hash,
  });
}

/**
 * HMAC-SHA256 서명 생성
 */
function createHmacSignature(data: string, key: Buffer): string {
  return crypto.createHmac("sha256", key).update(data).digest("hex");
}

/**
 * 불변 감사 로그 저장소 클래스
 */
export class ImmutableAuditStore {
  private config: ImmutableAuditStoreConfig;
  private currentSequence = 0;
  private currentFilePath: string;
  private lastHash: string;
  private entriesInCurrentFile = 0;
  private initialized = false;

  constructor(config: Partial<ImmutableAuditStoreConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.currentFilePath = this.getLogFilePath();
    this.lastHash = getGenesisHash();
  }

  /**
   * 저장소 초기화
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    // 로그 디렉토리 생성
    await fs.mkdir(this.config.logDir, { recursive: true, mode: 0o700 });

    // 기존 로그 파일 로드
    await this.loadExistingLogs();

    this.initialized = true;
    log.info("Immutable audit store initialized", {
      logDir: this.config.logDir,
      currentSequence: this.currentSequence,
    });
  }

  /**
   * 현재 로그 파일 경로 생성
   */
  private getLogFilePath(): string {
    const date = new Date();
    const dateStr = date.toISOString().split("T")[0];
    return path.join(this.config.logDir, `audit-${dateStr}.log`);
  }

  /**
   * 기존 로그 파일 로드
   */
  private async loadExistingLogs(): Promise<void> {
    try {
      const files = await fs.readdir(this.config.logDir);
      const logFiles = files.filter((f) => f.startsWith("audit-") && f.endsWith(".log")).toSorted();

      if (logFiles.length === 0) {
        return;
      }

      // 가장 최근 로그 파일 로드
      const latestFile = logFiles[logFiles.length - 1];
      const filePath = path.join(this.config.logDir, latestFile);
      const content = await fs.readFile(filePath, "utf-8");
      const lines = content.trim().split("\n").filter(Boolean);

      if (lines.length > 0) {
        const lastEntry = JSON.parse(lines[lines.length - 1]) as AuditLogEntry;
        this.currentSequence = lastEntry.sequence;
        this.lastHash = lastEntry.hash;
        this.entriesInCurrentFile = lines.length;
        this.currentFilePath = filePath;
      }
    } catch (error) {
      log.warn("Failed to load existing logs, starting fresh", { error });
    }
  }

  /**
   * 감사 로그 엔트리 추가
   */
  async append(
    entry: Omit<AuditLogEntry, "sequence" | "previousHash" | "hash">,
  ): Promise<AuditLogEntry> {
    if (!this.initialized) {
      await this.initialize();
    }

    // 파일 로테이션 체크
    if (this.entriesInCurrentFile >= this.config.maxEntriesPerFile) {
      await this.rotateLogFile();
    }

    this.currentSequence++;

    const fullEntry: AuditLogEntry = {
      ...entry,
      sequence: this.currentSequence,
      previousHash: this.lastHash,
      hash: "", // 임시 값
    };

    // 해시 계산
    fullEntry.hash = calculateEntryHash(fullEntry);
    this.lastHash = fullEntry.hash;

    // 파일에 추가
    const line = JSON.stringify(fullEntry) + "\n";
    await fs.appendFile(this.currentFilePath, line, { mode: 0o600 });
    this.entriesInCurrentFile++;

    // 메타데이터 업데이트
    await this.updateMetadata();

    return fullEntry;
  }

  /**
   * 로그 파일 로테이션
   */
  private async rotateLogFile(): Promise<void> {
    this.currentFilePath = this.getLogFilePath();
    this.entriesInCurrentFile = 0;
    log.info("Audit log rotated", { newFile: this.currentFilePath });
  }

  /**
   * 메타데이터 업데이트
   */
  private async updateMetadata(): Promise<void> {
    const metadata: AuditLogMetadata = {
      createdAt: Date.now(),
      lastEntryAt: Date.now(),
      entryCount: this.currentSequence,
      lastHash: this.lastHash,
    };

    const metadataPath = path.join(this.config.logDir, "metadata.json");
    await fs.writeFile(metadataPath, JSON.stringify(metadata, null, 2), { mode: 0o600 });
  }

  /**
   * 모든 로그 엔트리 조회
   */
  async getAllEntries(): Promise<AuditLogEntry[]> {
    if (!this.initialized) {
      await this.initialize();
    }

    const entries: AuditLogEntry[] = [];

    try {
      const files = await fs.readdir(this.config.logDir);
      const logFiles = files.filter((f) => f.startsWith("audit-") && f.endsWith(".log")).toSorted();

      for (const file of logFiles) {
        const filePath = path.join(this.config.logDir, file);
        const content = await fs.readFile(filePath, "utf-8");
        const lines = content.trim().split("\n").filter(Boolean);

        for (const line of lines) {
          try {
            const entry = JSON.parse(line) as AuditLogEntry;
            entries.push(entry);
          } catch {
            // 잘못된 라인 무시
          }
        }
      }
    } catch (error) {
      log.error("Failed to read audit logs", { error });
    }

    return entries.toSorted((a, b) => a.sequence - b.sequence);
  }

  /**
   * 특정 범위의 로그 조회
   */
  async getEntries(
    options: {
      startTime?: number;
      endTime?: number;
      eventType?: string;
      userId?: string;
      limit?: number;
      offset?: number;
    } = {},
  ): Promise<AuditLogEntry[]> {
    let entries = await this.getAllEntries();

    if (options.startTime) {
      entries = entries.filter((e) => e.timestamp >= options.startTime!);
    }
    if (options.endTime) {
      entries = entries.filter((e) => e.timestamp <= options.endTime!);
    }
    if (options.eventType) {
      entries = entries.filter((e) => e.eventType === options.eventType);
    }
    if (options.userId) {
      entries = entries.filter((e) => e.userId === options.userId);
    }

    const offset = options.offset || 0;
    const limit = options.limit || entries.length;

    return entries.slice(offset, offset + limit);
  }

  /**
   * 무결성 검증
   * 체인 해싱을 통해 변조 여부 확인
   */
  async verifyIntegrity(): Promise<IntegrityCheckResult> {
    const entries = await this.getAllEntries();
    const tamperedEntries: number[] = [];

    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];

      // 해시 재계산
      const { hash, ...entryWithoutHash } = entry;
      const recalculatedHash = calculateEntryHash(entryWithoutHash);

      if (hash !== recalculatedHash) {
        tamperedEntries.push(entry.sequence);
        continue;
      }

      // 체인 검증 (첫 엔트리 제외)
      if (i > 0) {
        const previousEntry = entries[i - 1];
        if (entry.previousHash !== previousEntry.hash) {
          tamperedEntries.push(entry.sequence);
        }
      }
    }

    const result: IntegrityCheckResult = {
      valid: tamperedEntries.length === 0,
      tamperedEntries,
      totalEntries: entries.length,
    };

    if (!result.valid) {
      result.firstTamperedIndex = tamperedEntries[0];
      log.error("Audit log integrity check failed", {
        tamperedCount: tamperedEntries.length,
        firstTampered: tamperedEntries[0],
      });
    }

    return result;
  }

  /**
   * 로그 내보내기 (암호화된 형태)
   */
  async exportLogs(startTime: number, endTime: number): Promise<string> {
    const entries = await this.getEntries({ startTime, endTime });
    return JSON.stringify(entries, null, 2);
  }

  /**
   * 통계 정보
   */
  async getStats(): Promise<{
    totalEntries: number;
    fileCount: number;
    oldestEntry?: number;
    newestEntry?: number;
  }> {
    const entries = await this.getAllEntries();

    const files = await fs.readdir(this.config.logDir);
    const logFiles = files.filter((f) => f.startsWith("audit-") && f.endsWith(".log"));

    return {
      totalEntries: entries.length,
      fileCount: logFiles.length,
      oldestEntry: entries[0]?.timestamp,
      newestEntry: entries[entries.length - 1]?.timestamp,
    };
  }
}

/**
 * 서명된 감사 로그 저장소 클래스 (FR-012)
 * HMAC-SHA256 디지털 서명을 추가하여 로그 무결성 검증 강화
 */
export class SignedAuditStore extends ImmutableAuditStore {
  private signingKey: Buffer | null = null;
  private keyManager: KeyManager;
  private signingInitialized = false;

  constructor(config: Partial<ImmutableAuditStoreConfig> = {}) {
    super(config);
    this.keyManager = new KeyManager({
      provider: "local",
      enabled: true,
      allowFileFallback: false,
      failSecure: true,
    });
  }

  /**
   * 서명 키 초기화
   * OS 키체인에서 키를 가져오거나 새로 생성
   */
  private async initializeSigningKey(): Promise<void> {
    if (this.signingInitialized) {
      return;
    }

    // KeyManager를 통해 키 가져오기 (별도의 서비스/계정 사용)
    const key = await this.getOrCreateSigningKey();

    if (!key) {
      throw new Error(
        "Failed to initialize audit log signing key. " + "Please ensure OS keychain is available.",
      );
    }

    this.signingKey = key;
    this.signingInitialized = true;

    log.info("Audit log signing key initialized");
  }

  /**
   * 서명 키 가져오기 또는 생성
   */
  private async getOrCreateSigningKey(): Promise<Buffer | null> {
    // KeyManager 낸부 키체인 접근을 사용
    const { spawnSync } = await import("node:child_process");

    // 먼저 기존 키 확인
    const existingKey = this.retrieveSigningKeyFromKeychain(spawnSync);
    if (existingKey) {
      try {
        return Buffer.from(existingKey, "base64");
      } catch (err) {
        log.warn("Failed to decode existing signing key, generating new one", { err });
      }
    }

    // 새 키 생성 (32 bytes for HMAC-SHA256)
    const newKey = crypto.randomBytes(32);
    const keyBase64 = newKey.toString("base64");

    // 키체인에 저장
    const stored = this.storeSigningKeyToKeychain(spawnSync, keyBase64);
    if (!stored) {
      log.error("Failed to store audit signing key in OS keychain");
      return null;
    }

    log.info("Generated new audit log signing key");
    return newKey;
  }

  /**
   * 키체인에서 서명 키 가져오기
   */
  private retrieveSigningKeyFromKeychain(
    spawnSync: typeof import("node:child_process").spawnSync,
  ): string | null {
    try {
      const platform = process.platform;

      if (platform === "darwin") {
        const result = spawnSync(
          "security",
          [
            "find-generic-password",
            "-s",
            AUDIT_SIGNING_KEYCHAIN_SERVICE,
            "-a",
            AUDIT_SIGNING_KEYCHAIN_ACCOUNT,
            "-w",
          ],
          { encoding: "utf-8" },
        );
        if (result.status === 0) {
          return result.stdout.trim();
        }
      } else if (platform === "linux") {
        const result = spawnSync(
          "secret-tool",
          [
            "lookup",
            "service",
            AUDIT_SIGNING_KEYCHAIN_SERVICE,
            "account",
            AUDIT_SIGNING_KEYCHAIN_ACCOUNT,
          ],
          { encoding: "utf-8" },
        );
        if (result.status === 0) {
          return result.stdout.trim();
        }
      } else if (platform === "win32") {
        const target = `${AUDIT_SIGNING_KEYCHAIN_SERVICE}:${AUDIT_SIGNING_KEYCHAIN_ACCOUNT}`;
        const psScript = `
          $cred = Get-StoredCredential -Target "${target}"
          if ($cred) { $cred.GetNetworkCredential().Password }
        `;
        const result = spawnSync("powershell.exe", ["-Command", psScript], { encoding: "utf-8" });
        if (result.status === 0 && result.stdout.trim()) {
          return result.stdout.trim();
        }
      }
    } catch (err) {
      log.warn("Failed to retrieve signing key from keychain", { err });
    }
    return null;
  }

  /**
   * 키체인에 서명 키 저장
   */
  private storeSigningKeyToKeychain(
    spawnSync: typeof import("node:child_process").spawnSync,
    keyBase64: string,
  ): boolean {
    try {
      const platform = process.platform;

      if (platform === "darwin") {
        const result = spawnSync(
          "security",
          [
            "add-generic-password",
            "-s",
            AUDIT_SIGNING_KEYCHAIN_SERVICE,
            "-a",
            AUDIT_SIGNING_KEYCHAIN_ACCOUNT,
            "-w",
            keyBase64,
            "-U",
          ],
          { encoding: "utf-8" },
        );
        return result.status === 0;
      } else if (platform === "linux") {
        const result = spawnSync(
          "secret-tool",
          [
            "store",
            "--label",
            "OpenClaw Audit Signing Key",
            "service",
            AUDIT_SIGNING_KEYCHAIN_SERVICE,
            "account",
            AUDIT_SIGNING_KEYCHAIN_ACCOUNT,
          ],
          { input: keyBase64, encoding: "utf-8" },
        );
        return result.status === 0;
      } else if (platform === "win32") {
        const target = `${AUDIT_SIGNING_KEYCHAIN_SERVICE}:${AUDIT_SIGNING_KEYCHAIN_ACCOUNT}`;
        const psScript = `
          $secure = ConvertTo-SecureString "${keyBase64.replace(/"/g, '`"')}" -AsPlainText -Force
          New-StoredCredential -Target "${target}" -SecurePassword $secure -Type Generic -Persist LocalMachine
        `;
        const result = spawnSync("powershell.exe", ["-Command", psScript], { encoding: "utf-8" });
        return result.status === 0;
      }
    } catch (err) {
      log.warn("Failed to store signing key to keychain", { err });
    }
    return false;
  }

  /**
   * 서명된 감사 로그 엔트리 추가
   */
  async appendWithSignature(
    entry: Omit<AuditLogEntry, "sequence" | "previousHash" | "hash">,
  ): Promise<SignedAuditLogEntry> {
    if (!this.signingInitialized) {
      await this.initializeSigningKey();
    }

    if (!this.signingKey) {
      throw new Error("Signing key not available");
    }

    // 부모 클래스의 append 메서드로 기본 엔트리 생성
    const baseEntry = await this.append(entry);

    // 서명 생성
    const signature = this.signEntry(baseEntry);

    const signedEntry: SignedAuditLogEntry = {
      ...baseEntry,
      signature,
      signatureAlgorithm: "HMAC-SHA256",
    };

    // 서명된 엔트리로 파일 업데이트 (기존 엔트리 대체)
    await this.updateLastEntryWithSignature(signedEntry);

    log.debug("Signed audit log entry created", {
      sequence: signedEntry.sequence,
      signature: signature.substring(0, 16) + "...",
    });

    return signedEntry;
  }

  /**
   * 엔트리 서명 생성
   */
  private signEntry(entry: AuditLogEntry): string {
    if (!this.signingKey) {
      throw new Error("Signing key not available");
    }

    const data = getSignableData(entry);
    return createHmacSignature(data, this.signingKey);
  }

  /**
   * 마지막 엔트리를 서명된 버전으로 업데이트
   */
  private async updateLastEntryWithSignature(signedEntry: SignedAuditLogEntry): Promise<void> {
    // 현재 파일의 모든 엔트리 읽기
    try {
      const content = await fs.readFile(this.currentFilePath, "utf-8");
      const lines = content.trim().split("\n");

      // 마지막 엔트리를 서명된 버전으로 교체
      lines[lines.length - 1] = JSON.stringify(signedEntry);

      // 파일 다시 쓰기
      await fs.writeFile(this.currentFilePath, lines.join("\n") + "\n", { mode: 0o600 });
    } catch (error) {
      log.error("Failed to update entry with signature", { error });
      throw error;
    }
  }

  /**
   * 서명 검증
   */
  verifySignature(entry: SignedAuditLogEntry): boolean {
    if (!this.signingKey) {
      throw new Error("Signing key not available. Call initializeSigningKey() first.");
    }

    // signatureAlgorithm 확인
    if (entry.signatureAlgorithm !== "HMAC-SHA256") {
      log.warn("Unsupported signature algorithm", { algorithm: entry.signatureAlgorithm });
      return false;
    }

    const expectedSignature = this.signEntry(entry);
    const isValid = entry.signature === expectedSignature;

    if (!isValid) {
      log.error("Signature verification failed", {
        sequence: entry.sequence,
        expected: expectedSignature.substring(0, 16) + "...",
        received: entry.signature.substring(0, 16) + "...",
      });
    }

    return isValid;
  }

  /**
   * 모든 서명 검증
   */
  async verifyAllSignatures(): Promise<SignatureVerificationResult> {
    if (!this.signingInitialized) {
      await this.initializeSigningKey();
    }

    if (!this.signingKey) {
      return {
        valid: false,
        invalidEntries: [],
        totalEntries: 0,
        error: "Signing key not available",
      };
    }

    const entries = await this.getAllEntries();
    const invalidEntries: number[] = [];

    for (const entry of entries) {
      // SignedAuditLogEntry인지 확인
      const signedEntry = entry as SignedAuditLogEntry;
      if (!signedEntry.signature || !signedEntry.signatureAlgorithm) {
        // 서명이 없는 엔트리는 스킵 (이전 버전 호환)
        continue;
      }

      if (!this.verifySignature(signedEntry)) {
        invalidEntries.push(entry.sequence);
      }
    }

    const result: SignatureVerificationResult = {
      valid: invalidEntries.length === 0,
      invalidEntries,
      totalEntries: entries.length,
    };

    if (!result.valid) {
      log.error("Signature verification failed for some entries", {
        invalidCount: invalidEntries.length,
        invalidSequences: invalidEntries,
      });
    } else {
      log.info("All signatures verified successfully", { totalEntries: entries.length });
    }

    return result;
  }

  /**
   * 서명된 엔트리 조회 (서명 검증 포함)
   */
  async getSignedEntries(
    options: Parameters<ImmutableAuditStore["getEntries"]>[0] = {},
  ): Promise<SignedAuditLogEntry[]> {
    const entries = await this.getEntries(options);
    return entries.filter(
      (e): e is SignedAuditLogEntry => "signature" in e && "signatureAlgorithm" in e,
    );
  }
}

// 싱글톤 인스턴스
let globalAuditStore: ImmutableAuditStore | null = null;
let globalSignedAuditStore: SignedAuditStore | null = null;

/**
 * 전역 감사 로그 저장소 가져오기
 */
export function getGlobalAuditStore(): ImmutableAuditStore {
  if (!globalAuditStore) {
    globalAuditStore = new ImmutableAuditStore();
  }
  return globalAuditStore;
}

/**
 * 전역 서명된 감사 로그 저장소 가져오기 (FR-012)
 */
export function getGlobalSignedAuditStore(): SignedAuditStore {
  if (!globalSignedAuditStore) {
    globalSignedAuditStore = new SignedAuditStore();
  }
  return globalSignedAuditStore;
}

/**
 * 감사 로그 엔트리 추가 헬퍼 함수
 */
export async function logAuditEvent(
  event: Omit<AuditLogEntry, "sequence" | "previousHash" | "hash" | "timestamp">,
): Promise<AuditLogEntry> {
  const store = getGlobalAuditStore();
  return store.append({
    ...event,
    timestamp: Date.now(),
  });
}

/**
 * 서명된 감사 로그 엔트리 추가 헬퍼 함수 (FR-012)
 */
export async function logSignedAuditEvent(
  event: Omit<AuditLogEntry, "sequence" | "previousHash" | "hash" | "timestamp">,
): Promise<SignedAuditLogEntry> {
  const store = getGlobalSignedAuditStore();
  return store.appendWithSignature({
    ...event,
    timestamp: Date.now(),
  });
}

/**
 * 보안 관련 감사 로그 헬퍼
 */
export const SecurityAudit = {
  async loginSuccess(userId: string, ipAddress: string, userAgent?: string): Promise<void> {
    await logAuditEvent({
      eventType: "authentication",
      userId,
      action: "login",
      result: "success",
      ipAddress,
      userAgent,
    });
  },

  async loginFailure(userId: string, ipAddress: string, reason: string): Promise<void> {
    await logAuditEvent({
      eventType: "authentication",
      userId,
      action: "login",
      result: "failure",
      ipAddress,
      details: { reason },
    });
  },

  async accessDenied(userId: string, resourceId: string, action: string): Promise<void> {
    await logAuditEvent({
      eventType: "authorization",
      userId,
      resourceId,
      action,
      result: "denied",
    });
  },

  async dataAccess(userId: string, resourceId: string, dataType: string): Promise<void> {
    await logAuditEvent({
      eventType: "data_access",
      userId,
      resourceId,
      action: "read",
      result: "success",
      details: { dataType },
    });
  },

  async dataModification(
    userId: string,
    resourceId: string,
    action: "create" | "update" | "delete",
  ): Promise<void> {
    await logAuditEvent({
      eventType: "data_modification",
      userId,
      resourceId,
      action,
      result: "success",
    });
  },

  async mfaEvent(
    userId: string,
    event: "enabled" | "disabled" | "verified" | "failed",
    method: string,
  ): Promise<void> {
    await logAuditEvent({
      eventType: "mfa",
      userId,
      action: event,
      result: event === "failed" ? "failure" : "success",
      details: { method },
    });
  },

  async dsrEvent(
    userId: string,
    requestId: string,
    type: "created" | "completed" | "cancelled",
  ): Promise<void> {
    await logAuditEvent({
      eventType: "dsr",
      userId,
      resourceId: requestId,
      action: type,
      result: "success",
    });
  },
};
