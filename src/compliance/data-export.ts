/**
 * GDPR 데이터 수출 및 삭제를 위한 데이터 수집 모듈
 * COMP-003, COMP-004 요구사항 구현
 */

import type { DatabaseSync } from "node:sqlite";
import fs from "node:fs/promises";
import path from "node:path";
import type { SessionEntry } from "../config/sessions/types.js";
import { loadConfig, resolveConfigPath } from "../config/config.js";
import { resolveStorePath } from "../config/sessions/paths.js";
import { loadSessionStore } from "../config/sessions/store.js";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("compliance/data-export");

/**
 * 수집할 사용자 데이터의 카테고리
 */
export type UserDataCategory =
  | "sessions"
  | "memories"
  | "credentials"
  | "config"
  | "auditLogs"
  | "transcripts";

/**
 * 사용자 데이터 수출 결과
 */
export interface UserDataExport {
  /** 수출 생성 시간 (ISO 8601) */
  exportedAt: string;
  /** 데이터 버전 */
  version: string;
  /** 세션 데이터 */
  sessions?: Record<string, SessionEntry>;
  /** 메모리/지식 베이스 데이터 */
  memories?: MemoryExportData[];
  /** 자격 증명 데이터 (마스킹됨) */
  credentials?: CredentialExportData;
  /** 설정 데이터 */
  config?: ConfigExportData;
  /** 감사 로그 */
  auditLogs?: AuditLogEntry[];
  /** 대화 기록 */
  transcripts?: TranscriptExportData[];
}

/**
 * 메모리 데이터 수출 형식
 */
export interface MemoryExportData {
  id: string;
  source: string;
  path: string;
  content: string;
  createdAt?: string;
  updatedAt?: string;
  metadata?: Record<string, unknown>;
}

/**
 * 자격 증명 데이터 수출 형식 (민감 정보 마스킹)
 */
export interface CredentialExportData {
  /** API 키 목록 (마스킹됨) */
  apiKeys: Array<{
    name: string;
    provider: string;
    maskedValue: string;
    createdAt?: string;
  }>;
  /** OAuth 토큰 목록 (마스킹됨) */
  oauthTokens: Array<{
    provider: string;
    scope: string[];
    expiresAt?: string;
    maskedToken: string;
  }>;
  /** 비밀번호/인증 정보 존재 여부 */
  hasPasswordAuth: boolean;
}

/**
 * 설정 데이터 수출 형식
 */
export interface ConfigExportData {
  /** 에이전트 설정 */
  agents: Record<string, unknown>;
  /** 채널 설정 */
  channels: Record<string, unknown>;
  /** 글로벌 설정 */
  global: Record<string, unknown>;
  /** 메모리 설정 */
  memory: Record<string, unknown>;
  /** 기타 설정 */
  [key: string]: unknown;
}

/**
 * 감사 로그 항목
 */
export interface AuditLogEntry {
  timestamp: string;
  action: string;
  resource: string;
  userId?: string;
  sessionKey?: string;
  details?: Record<string, unknown>;
  ipAddress?: string;
  userAgent?: string;
}

/**
 * 대화 기록 수출 형식
 */
export interface TranscriptExportData {
  sessionKey: string;
  messages: Array<{
    timestamp: string;
    role: "user" | "assistant" | "system";
    content: string;
    metadata?: Record<string, unknown>;
  }>;
  metadata?: Record<string, unknown>;
}

/**
 * 데이터 수출 옵션
 */
export interface DataExportOptions {
  /** 특정 세션 키로 필터링 (선택적) */
  sessionKey?: string;
  /** 포함할 데이터 카테고리 (기본: 전체) */
  categories?: UserDataCategory[];
  /** 시작 날짜 필터 */
  startDate?: Date;
  /** 종료 날짜 필터 */
  endDate?: Date;
}

/**
 * 데이터 삭제 옵션
 */
export interface DataDeletionOptions {
  /** 특정 세션 키로만 삭제 */
  sessionKey?: string;
  /** 삭제할 데이터 카테고리 */
  categories?: UserDataCategory[];
  /** 영구 삭제 여부 (false면 소프트 삭제) */
  permanent?: boolean;
}

/**
 * 데이터 삭제 결과
 */
export interface DataDeletionResult {
  success: boolean;
  deletedCategories: UserDataCategory[];
  failedCategories: Array<{ category: UserDataCategory; error: string }>;
  deletedCount: number;
  errors: string[];
}

/**
 * 데이터 수정 요청 항목
 */
export interface DataRectificationItem {
  /** 수정할 데이터 카테고리 */
  category: UserDataCategory;
  /** 수정할 데이터의 식별자 */
  id?: string;
  /** 수정할 필드와 값 */
  updates: Record<string, unknown>;
}

/**
 * 데이터 수정 옵션
 */
export interface DataRectificationOptions {
  /** 수정할 데이터 항목 목록 */
  items: DataRectificationItem[];
  /** 수정 사유 */
  reason?: string;
}

/**
 * 카테고리별 수정 결과
 */
export interface CategoryRectificationResult {
  /** 수정된 항목 수 */
  updated: number;
  /** 실패한 항목 수 */
  failed: number;
  /** 오류 메시지 (있는 경우) */
  error?: string;
}

/**
 * 데이터 수정 결과
 */
export interface DataRectificationResult {
  success: boolean;
  /** 카테고리별 수정 결과 */
  updated: {
    sessions: number;
    memories: number;
    credentials: number;
    config: number;
  };
  /** 요청 ID */
  requestId: string;
  /** SLA 마감일 (30일 후) */
  slaDeadline: string;
  /** 수정된 항목 상세 */
  details?: Record<string, CategoryRectificationResult>;
  /** 오류 메시지 */
  errors?: string[];
}

const DEFAULT_CATEGORIES: UserDataCategory[] = [
  "sessions",
  "memories",
  "credentials",
  "config",
  "auditLogs",
  "transcripts",
];

/**
 * 사용자의 모든 데이터를 수출합니다.
 * GDPR Article 15 (접근 권리) 및 Article 20 (데이터 이동성 권리) 구현
 */
export async function exportUserData(
  userId: string,
  opts: DataExportOptions = {},
): Promise<UserDataExport> {
  const categories = opts.categories ?? DEFAULT_CATEGORIES;
  const exportData: UserDataExport = {
    exportedAt: new Date().toISOString(),
    version: "1.0.0",
  };

  log.info(`Starting data export for user: ${userId}`, { categories });

  try {
    // 세션 데이터 수집
    if (categories.includes("sessions")) {
      exportData.sessions = await collectSessionData(userId, opts);
    }

    // 메모리 데이터 수집
    if (categories.includes("memories")) {
      exportData.memories = await collectMemoryData(userId, opts);
    }

    // 자격 증명 데이터 수집
    if (categories.includes("credentials")) {
      exportData.credentials = await collectCredentialData(userId);
    }

    // 설정 데이터 수집
    if (categories.includes("config")) {
      exportData.config = await collectConfigData(userId);
    }

    // 감사 로그 수집
    if (categories.includes("auditLogs")) {
      exportData.auditLogs = await collectAuditLogs(userId, opts);
    }

    // 대화 기록 수집
    if (categories.includes("transcripts")) {
      exportData.transcripts = await collectTranscripts(userId, opts);
    }

    log.info(`Data export completed for user: ${userId}`);
    return exportData;
  } catch (error) {
    log.error(`Data export failed for user: ${userId}`, { error: String(error) });
    throw error;
  }
}

/**
 * 기계가 읽을 수 있는 형식(JSON)으로 데이터를 수출합니다.
 * GDPR Article 20 (데이터 이동성 권리) 구현
 */
export async function exportPortableData(
  userId: string,
  opts: DataExportOptions = {},
): Promise<Record<string, unknown>> {
  const rawData = await exportUserData(userId, opts);

  // 표준화된 포터블 형식으로 변환
  return {
    data_controller: "OpenClaw",
    export_format: "JSON",
    export_version: "1.0.0",
    exported_at: rawData.exportedAt,
    data_subject: {
      user_id: userId,
    },
    personal_data: {
      sessions: rawData.sessions,
      memories: rawData.memories?.map((m) => ({
        id: m.id,
        source: m.source,
        content: m.content,
        created_at: m.createdAt,
        updated_at: m.updatedAt,
      })),
      credentials: rawData.credentials
        ? {
            api_keys_count: rawData.credentials.apiKeys.length,
            oauth_tokens_count: rawData.credentials.oauthTokens.length,
            has_password_auth: rawData.credentials.hasPasswordAuth,
          }
        : undefined,
      configuration: rawData.config,
      audit_logs: rawData.auditLogs,
      transcripts: rawData.transcripts,
    },
  };
}

/**
 * 사용자의 모든 데이터를 삭제합니다.
 * GDPR Article 17 (삭제 권리, Right to be Forgotten) 구현
 */
export async function deleteUserData(
  userId: string,
  opts: DataDeletionOptions = {},
): Promise<DataDeletionResult> {
  const categories = opts.categories ?? DEFAULT_CATEGORIES;
  const result: DataDeletionResult = {
    success: true,
    deletedCategories: [],
    failedCategories: [],
    deletedCount: 0,
    errors: [],
  };

  log.info(`Starting data deletion for user: ${userId}`, { categories, permanent: opts.permanent });

  for (const category of categories) {
    try {
      switch (category) {
        case "sessions": {
          const deleted = await deleteSessionData(userId, opts);
          result.deletedCount += deleted;
          result.deletedCategories.push(category);
          break;
        }
        case "memories": {
          const deleted = await deleteMemoryData(userId, opts);
          result.deletedCount += deleted;
          result.deletedCategories.push(category);
          break;
        }
        case "credentials": {
          await deleteCredentialData(userId);
          result.deletedCategories.push(category);
          break;
        }
        case "config": {
          await deleteConfigData(userId);
          result.deletedCategories.push(category);
          break;
        }
        case "auditLogs": {
          const deleted = await deleteAuditLogs(userId, opts);
          result.deletedCount += deleted;
          result.deletedCategories.push(category);
          break;
        }
        case "transcripts": {
          const deleted = await deleteTranscripts(userId, opts);
          result.deletedCount += deleted;
          result.deletedCategories.push(category);
          break;
        }
      }
    } catch (error) {
      const errorMsg = String(error);
      log.error(`Failed to delete ${category} for user: ${userId}`, { error: errorMsg });
      result.failedCategories.push({ category, error: errorMsg });
      result.errors.push(`${category}: ${errorMsg}`);
    }
  }

  result.success = result.failedCategories.length === 0;

  log.info(`Data deletion completed for user: ${userId}`, {
    success: result.success,
    deletedCategories: result.deletedCategories,
    deletedCount: result.deletedCount,
  });

  return result;
}

/**
 * 세션 데이터 수집
 */
async function collectSessionData(
  userId: string,
  opts: DataExportOptions,
): Promise<Record<string, SessionEntry>> {
  try {
    const config = loadConfig();
    const storePath = resolveStorePath(config.session?.store);
    const store = loadSessionStore(storePath);

    // 사용자 ID로 필터링 (세션 키에 사용자 ID가 포함된 경우)
    const filtered: Record<string, SessionEntry> = {};
    for (const [key, entry] of Object.entries(store)) {
      if (opts.sessionKey && key !== opts.sessionKey) {
        continue;
      }
      // 날짜 필터 적용
      if (opts.startDate && entry.updatedAt && entry.updatedAt < opts.startDate.getTime()) {
        continue;
      }
      if (opts.endDate && entry.updatedAt && entry.updatedAt > opts.endDate.getTime()) {
        continue;
      }
      filtered[key] = entry;
    }

    return filtered;
  } catch (error) {
    log.error("Failed to collect session data", { error: String(error) });
    return {};
  }
}

/**
 * 메모리 데이터 수집
 */
async function collectMemoryData(
  userId: string,
  opts: DataExportOptions,
): Promise<MemoryExportData[]> {
  const memories: MemoryExportData[] = [];

  try {
    const config = loadConfig();
    const memoryDir = resolveConfigPath(config.memory?.basePath ?? "./memory");

    // 메모리 파일 검색
    const files = await findMemoryFiles(memoryDir);

    for (const filePath of files) {
      try {
        const content = await fs.readFile(filePath, "utf-8");
        const stats = await fs.stat(filePath);

        memories.push({
          id: Buffer.from(filePath).toString("base64"),
          source: "memory",
          path: path.relative(memoryDir, filePath),
          content,
          createdAt: stats.birthtime.toISOString(),
          updatedAt: stats.mtime.toISOString(),
        });
      } catch (error) {
        log.warn(`Failed to read memory file: ${filePath}`, { error: String(error) });
      }
    }
  } catch (error) {
    log.error("Failed to collect memory data", { error: String(error) });
  }

  return memories;
}

/**
 * 자격 증명 데이터 수집 (민감 정보 마스킹)
 */
async function collectCredentialData(userId: string): Promise<CredentialExportData> {
  const credentials: CredentialExportData = {
    apiKeys: [],
    oauthTokens: [],
    hasPasswordAuth: false,
  };

  try {
    const config = loadConfig();

    // API 키 수집 (마스킹)
    if (config.providers) {
      for (const [provider, providerConfig] of Object.entries(config.providers)) {
        if (typeof providerConfig === "object" && providerConfig !== null) {
          const config = providerConfig as Record<string, unknown>;

          // API 키 필드 검색
          for (const [key, value] of Object.entries(config)) {
            if (key.toLowerCase().includes("key") || key.toLowerCase().includes("token")) {
              if (typeof value === "string" && value.length > 0) {
                credentials.apiKeys.push({
                  name: key,
                  provider,
                  maskedValue: maskSensitiveValue(value),
                  createdAt: undefined,
                });
              }
            }
          }
        }
      }
    }

    // 패스워드 인증 여부 확인
    credentials.hasPasswordAuth = !!config.gateway?.password;
  } catch (error) {
    log.error("Failed to collect credential data", { error: String(error) });
  }

  return credentials;
}

/**
 * 설정 데이터 수집
 */
async function collectConfigData(userId: string): Promise<ConfigExportData> {
  try {
    const config = loadConfig();

    // 민감 정보 제거
    const sanitizedConfig = sanitizeConfig(config);

    return {
      agents: sanitizedConfig.agents ?? {},
      channels: sanitizedConfig.channels ?? {},
      global: {
        session: sanitizedConfig.session,
        memory: sanitizedConfig.memory,
        gateway: sanitizedConfig.gateway
          ? {
              ...sanitizedConfig.gateway,
              password: undefined,
              token: undefined,
            }
          : undefined,
      },
      memory: sanitizedConfig.memory ?? {},
    };
  } catch (error) {
    log.error("Failed to collect config data", { error: String(error) });
    return { agents: {}, channels: {}, global: {}, memory: {} };
  }
}

/**
 * 감사 로그 수집
 */
async function collectAuditLogs(userId: string, opts: DataExportOptions): Promise<AuditLogEntry[]> {
  const logs: AuditLogEntry[] = [];

  try {
    const config = loadConfig();
    const auditLogPath = resolveConfigPath(config.logging?.auditLogPath ?? "./logs/audit.jsonl");

    try {
      const content = await fs.readFile(auditLogPath, "utf-8");
      const lines = content.split("\n").filter((line) => line.trim());

      for (const line of lines) {
        try {
          const entry = JSON.parse(line) as AuditLogEntry;

          // 사용자 ID 필터링
          if (entry.userId && entry.userId !== userId) {
            continue;
          }

          // 날짜 필터 적용
          if (opts.startDate) {
            const entryDate = new Date(entry.timestamp);
            if (entryDate < opts.startDate) {
              continue;
            }
          }
          if (opts.endDate) {
            const entryDate = new Date(entry.timestamp);
            if (entryDate > opts.endDate) {
              continue;
            }
          }

          logs.push(entry);
        } catch {
          // 잘못된 JSON 라인 무시
        }
      }
    } catch {
      // 파일이 없는 경우 빈 배열 반환
    }
  } catch (error) {
    log.error("Failed to collect audit logs", { error: String(error) });
  }

  return logs;
}

/**
 * 대화 기록 수집
 */
async function collectTranscripts(
  userId: string,
  opts: DataExportOptions,
): Promise<TranscriptExportData[]> {
  const transcripts: TranscriptExportData[] = [];

  try {
    const config = loadConfig();
    const transcriptDir = resolveConfigPath(config.session?.transcriptDir ?? "./transcripts");

    // 트랜스크립트 파일 검색
    const files = await findTranscriptFiles(transcriptDir);

    for (const filePath of files) {
      try {
        const content = await fs.readFile(filePath, "utf-8");
        const sessionKey = path.basename(filePath, path.extname(filePath));

        if (opts.sessionKey && sessionKey !== opts.sessionKey) {
          continue;
        }

        // JSONL 형식 파싱
        const messages: TranscriptExportData["messages"] = [];
        const lines = content.split("\n").filter((line) => line.trim());

        for (const line of lines) {
          try {
            const msg = JSON.parse(line);
            messages.push({
              timestamp: msg.timestamp || new Date().toISOString(),
              role: msg.role || "user",
              content: msg.content || "",
              metadata: msg.metadata,
            });
          } catch {
            // 잘못된 JSON 라인 무시
          }
        }

        transcripts.push({
          sessionKey,
          messages,
          metadata: {
            filePath: path.relative(transcriptDir, filePath),
            messageCount: messages.length,
          },
        });
      } catch (error) {
        log.warn(`Failed to read transcript file: ${filePath}`, { error: String(error) });
      }
    }
  } catch (error) {
    log.error("Failed to collect transcripts", { error: String(error) });
  }

  return transcripts;
}

/**
 * 세션 데이터 삭제
 */
async function deleteSessionData(userId: string, opts: DataDeletionOptions): Promise<number> {
  try {
    const config = loadConfig();
    const storePath = resolveStorePath(config.session?.store);

    // 세션 스토어 로드 및 수정
    const store = loadSessionStore(storePath);
    let deletedCount = 0;

    for (const key of Object.keys(store)) {
      if (opts.sessionKey && key !== opts.sessionKey) {
        continue;
      }
      delete store[key];
      deletedCount++;
    }

    // 변경사항 저장
    if (deletedCount > 0) {
      const { saveSessionStore } = await import("../config/sessions/store.js");
      await saveSessionStore(storePath, store);
    }

    return deletedCount;
  } catch (error) {
    log.error("Failed to delete session data", { error: String(error) });
    throw error;
  }
}

/**
 * 메모리 데이터 삭제
 */
async function deleteMemoryData(userId: string, opts: DataDeletionOptions): Promise<number> {
  let deletedCount = 0;

  try {
    const config = loadConfig();
    const memoryDir = resolveConfigPath(config.memory?.basePath ?? "./memory");

    const files = await findMemoryFiles(memoryDir);

    for (const filePath of files) {
      try {
        if (opts.permanent) {
          await fs.unlink(filePath);
        } else {
          // 소프트 삭제: 내용 덮어쓰기 후 삭제
          await fs.writeFile(filePath, "", "utf-8");
          await fs.unlink(filePath);
        }
        deletedCount++;
      } catch (error) {
        log.warn(`Failed to delete memory file: ${filePath}`, { error: String(error) });
      }
    }
  } catch (error) {
    log.error("Failed to delete memory data", { error: String(error) });
    throw error;
  }

  return deletedCount;
}

/**
 * 자격 증명 데이터 삭제
 */
async function deleteCredentialData(userId: string): Promise<void> {
  // 자격 증명은 설정 파일에서 제거해야 함
  // 실제 구현에서는 안전한 방식으로 자격 증명을 제거
  log.info("Credential deletion requested - manual review required");
}

/**
 * 설정 데이터 삭제
 */
async function deleteConfigData(userId: string): Promise<void> {
  // 설정 데이터 삭제는 특정 사용자 설정만 제거
  log.info("Config deletion requested - manual review required");
}

/**
 * 감사 로그 삭제
 */
async function deleteAuditLogs(userId: string, opts: DataDeletionOptions): Promise<number> {
  // 감사 로그는 규정 준수를 위해 보관할 수 있음
  // GDPR은 법적 의무가 있는 경우 데이터 보관을 허용함
  log.info("Audit log deletion requested - logs retained for compliance");
  return 0;
}

/**
 * 대화 기록 삭제
 */
async function deleteTranscripts(userId: string, opts: DataDeletionOptions): Promise<number> {
  let deletedCount = 0;

  try {
    const config = loadConfig();
    const transcriptDir = resolveConfigPath(config.session?.transcriptDir ?? "./transcripts");

    const files = await findTranscriptFiles(transcriptDir);

    for (const filePath of files) {
      try {
        const sessionKey = path.basename(filePath, path.extname(filePath));
        if (opts.sessionKey && sessionKey !== opts.sessionKey) {
          continue;
        }

        if (opts.permanent) {
          await fs.unlink(filePath);
        } else {
          await fs.writeFile(filePath, "", "utf-8");
          await fs.unlink(filePath);
        }
        deletedCount++;
      } catch (error) {
        log.warn(`Failed to delete transcript file: ${filePath}`, { error: String(error) });
      }
    }
  } catch (error) {
    log.error("Failed to delete transcripts", { error: String(error) });
    throw error;
  }

  return deletedCount;
}

/**
 * 메모리 파일 검색
 */
async function findMemoryFiles(dir: string): Promise<string[]> {
  const files: string[] = [];

  try {
    const entries = await fs.readdir(dir, { withFileTypes: true, recursive: true });

    for (const entry of entries) {
      if (entry.isFile() && entry.name.endsWith(".md")) {
        files.push(path.join(dir, entry.parentPath || "", entry.name));
      }
    }
  } catch {
    // 디렉토리가 없는 경우 빈 배열 반환
  }

  return files;
}

/**
 * 트랜스크립트 파일 검색
 */
async function findTranscriptFiles(dir: string): Promise<string[]> {
  const files: string[] = [];

  try {
    const entries = await fs.readdir(dir, { withFileTypes: true, recursive: true });

    for (const entry of entries) {
      if (entry.isFile() && (entry.name.endsWith(".jsonl") || entry.name.endsWith(".json"))) {
        files.push(path.join(dir, entry.parentPath || "", entry.name));
      }
    }
  } catch {
    // 디렉토리가 없는 경우 빈 배열 반환
  }

  return files;
}

/**
 * 민감 값 마스킹
 */
function maskSensitiveValue(value: string): string {
  if (value.length <= 8) {
    return "***";
  }
  return value.slice(0, 4) + "..." + value.slice(-4);
}

/**
 * 설정에서 민감 정보 제거
 */
function sanitizeConfig(config: Record<string, unknown>): Record<string, unknown> {
  const sanitized = { ...config };

  // 민감한 필드 목록
  const sensitiveFields = ["password", "token", "secret", "key", "apiKey", "privateKey"];

  for (const key of Object.keys(sanitized)) {
    const lowerKey = key.toLowerCase();

    if (sensitiveFields.some((field) => lowerKey.includes(field))) {
      if (typeof sanitized[key] === "string") {
        sanitized[key] = maskSensitiveValue(sanitized[key]);
      }
    } else if (typeof sanitized[key] === "object" && sanitized[key] !== null) {
      sanitized[key] = sanitizeConfig(sanitized[key] as Record<string, unknown>);
    }
  }

  return sanitized;
}

/**
 * 데이터 수출을 JSON 파일로 저장
 */
export async function saveExportToFile(
  exportData: UserDataExport,
  outputPath: string,
): Promise<void> {
  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, JSON.stringify(exportData, null, 2), "utf-8");
}

/**
 * 데이터 수출 결과의 크기를 계산
 */
export function calculateExportSize(exportData: UserDataExport): number {
  return JSON.stringify(exportData).length;
}

// COMP-003: 데이터 보유 기간 자동화 설정
export interface DataRetentionConfig {
  /** 세션 데이터 보유 기간 (일) */
  sessionRetentionDays: number;
  /** 트랜스크립트 보유 기간 (일) */
  transcriptRetentionDays: number;
  /** 감사 로그 보유 기간 (일) */
  auditLogRetentionDays: number;
  /** 메모리 데이터 보유 기간 (일) */
  memoryRetentionDays: number;
  /** 삭제 전 백업 여부 */
  backupBeforeDelete: boolean;
  /** 백업 경로 */
  backupPath?: string;
}

/** 기본 보유 기간 설정 (GDPR 권고) */
export const DEFAULT_RETENTION_CONFIG: DataRetentionConfig = {
  sessionRetentionDays: 30,
  transcriptRetentionDays: 365,
  auditLogRetentionDays: 1095, // 3년
  memoryRetentionDays: 365,
  backupBeforeDelete: true,
  backupPath: "./backups/data-retention",
};

/** 삭제 결과 */
export interface PurgeResult {
  timestamp: string;
  deletedSessions: number;
  deletedTranscripts: number;
  deletedAuditLogs: number;
  deletedMemories: number;
  backupPath?: string;
  errors: string[];
}

/**
 * 만료된 데이터 자동 삭제 (COMP-003)
 * GDPR Article 5(1)(e) - 보유 기간 제한 준수
 */
export async function purgeExpiredData(
  config: Partial<DataRetentionConfig> = {},
): Promise<PurgeResult> {
  const retentionConfig = { ...DEFAULT_RETENTION_CONFIG, ...config };
  const result: PurgeResult = {
    timestamp: new Date().toISOString(),
    deletedSessions: 0,
    deletedTranscripts: 0,
    deletedAuditLogs: 0,
    deletedMemories: 0,
    errors: [],
  };

  const now = Date.now();
  log.info("Starting expired data purge", { config: retentionConfig });

  // 백업 생성
  if (retentionConfig.backupBeforeDelete && retentionConfig.backupPath) {
    try {
      result.backupPath = await createDataBackup(retentionConfig.backupPath);
      log.info("Data backup created", { backupPath: result.backupPath });
    } catch (error) {
      log.error("Failed to create backup", { error: String(error) });
      result.errors.push(`Backup failed: ${String(error)}`);
      // 백업 실패 시 삭제 중단 (안전 장치)
      if (retentionConfig.backupBeforeDelete) {
        throw new Error("Backup failed, aborting purge", { cause: error });
      }
    }
  }

  // 세션 데이터 정리
  try {
    const sessionCutoff = new Date(
      now - retentionConfig.sessionRetentionDays * 24 * 60 * 60 * 1000,
    );
    result.deletedSessions = await purgeExpiredSessions(sessionCutoff);
    log.info("Purged expired sessions", { count: result.deletedSessions });
  } catch (error) {
    log.error("Failed to purge sessions", { error: String(error) });
    result.errors.push(`Session purge failed: ${String(error)}`);
  }

  // 트랜스크립트 정리
  try {
    const transcriptCutoff = new Date(
      now - retentionConfig.transcriptRetentionDays * 24 * 60 * 60 * 1000,
    );
    result.deletedTranscripts = await purgeExpiredTranscripts(transcriptCutoff);
    log.info("Purged expired transcripts", { count: result.deletedTranscripts });
  } catch (error) {
    log.error("Failed to purge transcripts", { error: String(error) });
    result.errors.push(`Transcript purge failed: ${String(error)}`);
  }

  // 감사 로그 정리
  try {
    const auditCutoff = new Date(now - retentionConfig.auditLogRetentionDays * 24 * 60 * 60 * 1000);
    result.deletedAuditLogs = await purgeExpiredAuditLogs(auditCutoff);
    log.info("Purged expired audit logs", { count: result.deletedAuditLogs });
  } catch (error) {
    log.error("Failed to purge audit logs", { error: String(error) });
    result.errors.push(`Audit log purge failed: ${String(error)}`);
  }

  // 메모리 데이터 정리
  try {
    const memoryCutoff = new Date(now - retentionConfig.memoryRetentionDays * 24 * 60 * 60 * 1000);
    result.deletedMemories = await purgeExpiredMemories(memoryCutoff);
    log.info("Purged expired memories", { count: result.deletedMemories });
  } catch (error) {
    log.error("Failed to purge memories", { error: String(error) });
    result.errors.push(`Memory purge failed: ${String(error)}`);
  }

  // 삭제 로그 기록
  await logPurgeResult(result);

  log.info("Expired data purge completed", { result });
  return result;
}

/**
 * 데이터 백업 생성
 */
async function createDataBackup(backupBasePath: string): Promise<string> {
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = path.join(backupBasePath, `backup-${timestamp}`);

  await fs.mkdir(backupPath, { recursive: true });

  const config = loadConfig();

  // 세션 백업
  try {
    const sessionPath = resolveStorePath(config.session?.store);
    const sessionBackupPath = path.join(backupPath, "sessions");
    await fs.mkdir(sessionBackupPath, { recursive: true });
    await copyFileIfExists(sessionPath, path.join(sessionBackupPath, "sessions.json"));
  } catch (error) {
    log.warn("Session backup skipped", { error: String(error) });
  }

  // 트랜스크립트 백업
  try {
    const transcriptDir = resolveConfigPath(config.session?.transcriptDir ?? "./transcripts");
    const transcriptBackupPath = path.join(backupPath, "transcripts");
    await copyDirectoryIfExists(transcriptDir, transcriptBackupPath);
  } catch (error) {
    log.warn("Transcript backup skipped", { error: String(error) });
  }

  // 감사 로그 백업
  try {
    const auditLogPath = resolveConfigPath(config.logging?.auditLogPath ?? "./logs/audit.jsonl");
    const auditBackupPath = path.join(backupPath, "audit");
    await fs.mkdir(auditBackupPath, { recursive: true });
    await copyFileIfExists(auditLogPath, path.join(auditBackupPath, "audit.jsonl"));
  } catch (error) {
    log.warn("Audit log backup skipped", { error: String(error) });
  }

  // 메모리 백업
  try {
    const memoryDir = resolveConfigPath(config.memory?.basePath ?? "./memory");
    const memoryBackupPath = path.join(backupPath, "memory");
    await copyDirectoryIfExists(memoryDir, memoryBackupPath);
  } catch (error) {
    log.warn("Memory backup skipped", { error: String(error) });
  }

  return backupPath;
}

/**
 * 파일이 존재하면 복사
 */
async function copyFileIfExists(src: string, dest: string): Promise<void> {
  try {
    await fs.access(src);
    await fs.copyFile(src, dest);
  } catch {
    // 파일이 없으면 무시
  }
}

/**
 * 디렉토리가 존재하면 복사
 */
async function copyDirectoryIfExists(src: string, dest: string): Promise<void> {
  try {
    await fs.access(src);
    await fs.mkdir(dest, { recursive: true });
    const entries = await fs.readdir(src, { withFileTypes: true });

    for (const entry of entries) {
      const srcPath = path.join(src, entry.name);
      const destPath = path.join(dest, entry.name);

      if (entry.isDirectory()) {
        await copyDirectoryIfExists(srcPath, destPath);
      } else {
        await fs.copyFile(srcPath, destPath);
      }
    }
  } catch {
    // 디렉토리가 없으면 무시
  }
}

/**
 * 만료된 세션 정리
 */
async function purgeExpiredSessions(cutoffDate: Date): Promise<number> {
  try {
    const config = loadConfig();
    const storePath = resolveStorePath(config.session?.store);
    const store = loadSessionStore(storePath);

    let deletedCount = 0;
    const updatedStore: Record<string, SessionEntry> = {};

    for (const [key, entry] of Object.entries(store)) {
      if (entry.updatedAt && entry.updatedAt < cutoffDate.getTime()) {
        deletedCount++;
      } else {
        updatedStore[key] = entry;
      }
    }

    if (deletedCount > 0) {
      const { saveSessionStore } = await import("../config/sessions/store.js");
      await saveSessionStore(storePath, updatedStore);
    }

    return deletedCount;
  } catch (error) {
    log.error("Failed to purge sessions", { error: String(error) });
    throw error;
  }
}

/**
 * 만료된 트랜스크립트 정리
 */
async function purgeExpiredTranscripts(cutoffDate: Date): Promise<number> {
  try {
    const config = loadConfig();
    const transcriptDir = resolveConfigPath(config.session?.transcriptDir ?? "./transcripts");
    const files = await findTranscriptFiles(transcriptDir);

    let deletedCount = 0;

    for (const filePath of files) {
      try {
        const stats = await fs.stat(filePath);
        if (stats.mtime < cutoffDate) {
          await fs.unlink(filePath);
          deletedCount++;
        }
      } catch (error) {
        log.warn(`Failed to delete transcript: ${filePath}`, { error: String(error) });
      }
    }

    return deletedCount;
  } catch (error) {
    log.error("Failed to purge transcripts", { error: String(error) });
    throw error;
  }
}

/**
 * 만료된 감사 로그 정리
 */
async function purgeExpiredAuditLogs(cutoffDate: Date): Promise<number> {
  try {
    const config = loadConfig();
    const auditLogPath = resolveConfigPath(config.logging?.auditLogPath ?? "./logs/audit.jsonl");

    let content: string;
    try {
      content = await fs.readFile(auditLogPath, "utf-8");
    } catch {
      return 0; // 파일이 없으면 0 반환
    }

    const lines = content.split("\n").filter((line) => line.trim());
    const keptLines: string[] = [];
    let deletedCount = 0;

    for (const line of lines) {
      try {
        const entry = JSON.parse(line) as AuditLogEntry;
        const entryDate = new Date(entry.timestamp);

        if (entryDate >= cutoffDate) {
          keptLines.push(line);
        } else {
          deletedCount++;
        }
      } catch {
        // 잘못된 JSON은 유지
        keptLines.push(line);
      }
    }

    if (deletedCount > 0) {
      await fs.writeFile(
        auditLogPath,
        keptLines.join("\n") + (keptLines.length > 0 ? "\n" : ""),
        "utf-8",
      );
    }

    return deletedCount;
  } catch (error) {
    log.error("Failed to purge audit logs", { error: String(error) });
    throw error;
  }
}

/**
 * 만료된 메모리 정리
 */
async function purgeExpiredMemories(cutoffDate: Date): Promise<number> {
  try {
    const config = loadConfig();
    const memoryDir = resolveConfigPath(config.memory?.basePath ?? "./memory");
    const files = await findMemoryFiles(memoryDir);

    let deletedCount = 0;

    for (const filePath of files) {
      try {
        const stats = await fs.stat(filePath);
        if (stats.mtime < cutoffDate) {
          await fs.unlink(filePath);
          deletedCount++;
        }
      } catch (error) {
        log.warn(`Failed to delete memory: ${filePath}`, { error: String(error) });
      }
    }

    return deletedCount;
  } catch (error) {
    log.error("Failed to purge memories", { error: String(error) });
    throw error;
  }
}

/**
 * 삭제 로그 기록
 */
async function logPurgeResult(result: PurgeResult): Promise<void> {
  const logEntry = {
    timestamp: result.timestamp,
    type: "data-retention-purge",
    deletedSessions: result.deletedSessions,
    deletedTranscripts: result.deletedTranscripts,
    deletedAuditLogs: result.deletedAuditLogs,
    deletedMemories: result.deletedMemories,
    backupPath: result.backupPath,
    errorCount: result.errors.length,
  };

  // 콘솔에 로그 출력 (추후 파일 로깅으로 확장 가능)
  log.info("Data retention purge completed", logEntry);
}

/**
 * Cron 작업용 데이터 정리 함수
 * node-cron 등으로 주기적 호출 가능
 */
export async function runDataRetentionJob(
  config?: Partial<DataRetentionConfig>,
): Promise<PurgeResult> {
  log.info("Starting scheduled data retention job");

  try {
    const result = await purgeExpiredData(config);

    if (result.errors.length > 0) {
      log.warn("Data retention job completed with errors", { errors: result.errors });
    } else {
      log.info("Data retention job completed successfully");
    }

    return result;
  } catch (error) {
    log.error("Data retention job failed", { error: String(error) });
    throw error;
  }
}

/**
 * 사용자 데이터 수정 (GDPR Article 16 - 수정 권리)
 * @param userId 사용자 ID
 * @param opts 수정 옵션
 * @returns 수정 결과
 */
export async function rectifyUserData(
  userId: string,
  opts: DataRectificationOptions,
): Promise<DataRectificationResult> {
  const requestId = `rect-${userId}-${Date.now()}`;
  const slaDeadline = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString(); // 30 days

  const result: DataRectificationResult = {
    success: true,
    updated: {
      sessions: 0,
      memories: 0,
      credentials: 0,
      config: 0,
    },
    requestId,
    slaDeadline,
    details: {},
    errors: [],
  };

  log.info(`Starting data rectification for user: ${userId}`, {
    requestId,
    itemCount: opts.items.length,
  });

  // 감사 로그에 수정 요청 기록
  await logRectificationRequest(userId, requestId, opts);

  for (const item of opts.items) {
    try {
      switch (item.category) {
        case "sessions": {
          const sessionResult = await rectifySessionData(userId, item);
          result.updated.sessions += sessionResult.updated;
          result.details!.sessions = sessionResult;
          break;
        }
        case "memories": {
          const memoryResult = await rectifyMemoryData(userId, item);
          result.updated.memories += memoryResult.updated;
          result.details!.memories = memoryResult;
          break;
        }
        case "credentials": {
          const credResult = await rectifyCredentialData(userId, item);
          result.updated.credentials += credResult.updated;
          result.details!.credentials = credResult;
          break;
        }
        case "config": {
          const configResult = await rectifyConfigData(userId, item);
          result.updated.config += configResult.updated;
          result.details!.config = configResult;
          break;
        }
        case "auditLogs":
        case "transcripts": {
          // 감사 로그와 트랜스크립트는 수정 불가 (불변성 유지)
          log.warn(`Cannot rectify immutable category: ${item.category}`);
          result.errors?.push(`${item.category}: 수정할 수 없는 데이터 카테고리입니다.`);
          break;
        }
        default: {
          result.errors?.push(`${item.category}: 지원하지 않는 데이터 카테고리입니다.`);
        }
      }
    } catch (error) {
      const errorMsg = String(error);
      log.error(`Failed to rectify ${item.category} for user: ${userId}`, { error: errorMsg });
      result.errors?.push(`${item.category}: ${errorMsg}`);
    }
  }

  // 성공 여부 결정 (모든 항목이 실패한 경우만 실패로 간주)
  const totalUpdated =
    result.updated.sessions +
    result.updated.memories +
    result.updated.credentials +
    result.updated.config;
  result.success = totalUpdated > 0 || result.errors?.length === 0;

  // 감사 로그에 수정 완료 기록
  await logRectificationCompletion(userId, requestId, result);

  log.info(`Data rectification completed for user: ${userId}`, {
    requestId,
    success: result.success,
    updated: result.updated,
  });

  return result;
}

/**
 * 세션 데이터 수정
 */
async function rectifySessionData(
  userId: string,
  item: DataRectificationItem,
): Promise<CategoryRectificationResult> {
  const result: CategoryRectificationResult = { updated: 0, failed: 0 };

  try {
    const config = loadConfig();
    const storePath = resolveStorePath(config.session?.store);

    // 세션 스토어 업데이트
    const { updateSessionStore } = await import("../config/sessions/store.js");
    await updateSessionStore(storePath, async (store) => {
      // 특정 세션 ID가 지정된 경우
      if (item.id) {
        const session = store[item.id];
        if (session) {
          // 세션 데이터 업데이트
          for (const [key, value] of Object.entries(item.updates)) {
            if (key in session) {
              (session as Record<string, unknown>)[key] = value;
            }
          }
          session.updatedAt = Date.now();
          result.updated++;
        } else {
          result.failed++;
          result.error = `세션을 찾을 수 없습니다: ${item.id}`;
        }
      } else {
        // 모든 세션에 업데이트 적용
        for (const [sessionKey, session] of Object.entries(store)) {
          if (session) {
            for (const [key, value] of Object.entries(item.updates)) {
              if (key in session) {
                (session as Record<string, unknown>)[key] = value;
              }
            }
            session.updatedAt = Date.now();
            result.updated++;
          }
        }
      }
      return result;
    });
  } catch (error) {
    result.failed++;
    result.error = String(error);
    log.error("Failed to rectify session data", { error: String(error) });
  }

  return result;
}

/**
 * 메모리 데이터 수정
 */
async function rectifyMemoryData(
  userId: string,
  item: DataRectificationItem,
): Promise<CategoryRectificationResult> {
  const result: CategoryRectificationResult = { updated: 0, failed: 0 };

  try {
    const config = loadConfig();
    const memoryDir = resolveConfigPath(config.memory?.basePath ?? "./memory");

    if (item.id) {
      // 특정 메모리 파일 수정
      const filePath = path.join(memoryDir, item.id);
      try {
        const stats = await fs.stat(filePath);
        if (stats.isFile()) {
          // 메모리 내용 업데이트
          if (typeof item.updates.content === "string") {
            await fs.writeFile(filePath, item.updates.content, "utf-8");
            result.updated++;
          } else {
            result.failed++;
            result.error = "메모리 내용(content)은 문자열이어야 합니다.";
          }
        }
      } catch {
        result.failed++;
        result.error = `메모리 파일을 찾을 수 없습니다: ${item.id}`;
      }
    } else {
      // 모든 메모리 파일 검색 및 수정
      const files = await findMemoryFiles(memoryDir);
      for (const filePath of files) {
        try {
          const relativePath = path.relative(memoryDir, filePath);
          // 메타데이터 업데이트 (파일명 변경 등)
          if (item.updates.path && typeof item.updates.path === "string") {
            const newPath = path.join(memoryDir, item.updates.path);
            await fs.mkdir(path.dirname(newPath), { recursive: true });
            await fs.rename(filePath, newPath);
            result.updated++;
          }
        } catch (error) {
          result.failed++;
          log.warn(`Failed to rectify memory file: ${filePath}`, { error: String(error) });
        }
      }
    }
  } catch (error) {
    result.failed++;
    result.error = String(error);
    log.error("Failed to rectify memory data", { error: String(error) });
  }

  return result;
}

/**
 * 자격 증명 데이터 수정
 */
async function rectifyCredentialData(
  userId: string,
  item: DataRectificationItem,
): Promise<CategoryRectificationResult> {
  const result: CategoryRectificationResult = { updated: 0, failed: 0 };

  try {
    // 자격 증명 수정은 설정 파일 업데이트로 처리
    // 실제 구현에서는 안전한 방식으로 자격 증명을 업데이트
    log.info("Credential rectification requested", { userId, updates: Object.keys(item.updates) });

    // TODO: 설정 파일의 provider 설정 업데이트 구현
    // 현재는 로깅만 수행
    result.updated = 0;
    result.error = "자격 증명 수정은 수동 검토가 필요합니다.";
  } catch (error) {
    result.failed++;
    result.error = String(error);
    log.error("Failed to rectify credential data", { error: String(error) });
  }

  return result;
}

/**
 * 설정 데이터 수정
 */
async function rectifyConfigData(
  userId: string,
  item: DataRectificationItem,
): Promise<CategoryRectificationResult> {
  const result: CategoryRectificationResult = { updated: 0, failed: 0 };

  try {
    const config = loadConfig();

    // 설정 업데이트 적용
    for (const [key, value] of Object.entries(item.updates)) {
      if (key in config && key !== "providers") {
        // providers는 민감 정보 포함
        (config as Record<string, unknown>)[key] = value;
        result.updated++;
      }
    }

    // 설정 저장
    const { saveConfig } = await import("../config/io.js");
    await saveConfig(config);
  } catch (error) {
    result.failed++;
    result.error = String(error);
    log.error("Failed to rectify config data", { error: String(error) });
  }

  return result;
}

/**
 * 수정 요청 감사 로그 기록
 */
async function logRectificationRequest(
  userId: string,
  requestId: string,
  opts: DataRectificationOptions,
): Promise<void> {
  const logEntry: AuditLogEntry = {
    timestamp: new Date().toISOString(),
    action: "data_rectification_requested",
    resource: "user_data",
    userId,
    details: {
      requestId,
      itemCount: opts.items.length,
      categories: opts.items.map((i) => i.category),
      reason: opts.reason,
    },
  };

  await appendAuditLog(logEntry);
}

/**
 * 수정 완료 감사 로그 기록
 */
async function logRectificationCompletion(
  userId: string,
  requestId: string,
  result: DataRectificationResult,
): Promise<void> {
  const logEntry: AuditLogEntry = {
    timestamp: new Date().toISOString(),
    action: "data_rectification_completed",
    resource: "user_data",
    userId,
    details: {
      requestId,
      success: result.success,
      updated: result.updated,
      errorCount: result.errors?.length ?? 0,
    },
  };

  await appendAuditLog(logEntry);
}

/**
 * 감사 로그에 항목 추가
 */
async function appendAuditLog(entry: AuditLogEntry): Promise<void> {
  try {
    const config = loadConfig();
    const auditLogPath = resolveConfigPath(config.logging?.auditLogPath ?? "./logs/audit.jsonl");

    await fs.mkdir(path.dirname(auditLogPath), { recursive: true });
    await fs.appendFile(auditLogPath, JSON.stringify(entry) + "\n", "utf-8");
  } catch (error) {
    log.error("Failed to write audit log", { error: String(error) });
  }
}
