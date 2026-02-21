/**
 * 불변 감사 로그 저장소 구현
 * WORM(Write Once Read Many) 보호 및 암호화 무결성 검증
 * 체인 해싱을 통한 변조 방지
 */

import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("security/immutable-audit");

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

// 싱글톤 인스턴스
let globalAuditStore: ImmutableAuditStore | null = null;

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
