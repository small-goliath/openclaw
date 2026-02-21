/**
 * 데이터 보존 및 자동 삭제 구현
 * SOC 2 CC8.1 준수
 */

import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("security/data-retention");

/**
 * 데이터 유형별 보존 정책
 */
export interface RetentionPolicy {
  dataType: string;
  retentionPeriod: number; // milliseconds
  description: string;
  autoDelete: boolean;
  archiveBeforeDelete?: boolean;
  legalHold?: boolean;
}

/**
 * 기본 보존 정책
 */
export const DEFAULT_RETENTION_POLICIES: RetentionPolicy[] = [
  {
    dataType: "auth_log",
    retentionPeriod: 365 * 24 * 60 * 60 * 1000, // 1년
    description: "인증 로그",
    autoDelete: true,
  },
  {
    dataType: "activity_log",
    retentionPeriod: 2 * 365 * 24 * 60 * 60 * 1000, // 2년
    description: "활동 로그",
    autoDelete: true,
  },
  {
    dataType: "chat_message",
    retentionPeriod: 0, // 사용자 요청 시 삭제
    description: "채팅 메시지",
    autoDelete: false,
  },
  {
    dataType: "session_data",
    retentionPeriod: 30 * 24 * 60 * 60 * 1000, // 30일
    description: "세션 데이터",
    autoDelete: true,
  },
  {
    dataType: "backup_code",
    retentionPeriod: 0, // 사용 후 즉시 삭제
    description: "MFA 백업 코드",
    autoDelete: true,
  },
  {
    dataType: "temp_file",
    retentionPeriod: 7 * 24 * 60 * 60 * 1000, // 7일
    description: "임시 파일",
    autoDelete: true,
  },
  {
    dataType: "audit_log",
    retentionPeriod: 7 * 365 * 24 * 60 * 60 * 1000, // 7년
    description: "감사 로그",
    autoDelete: false, // 법적 요구사항으로 보관
    legalHold: true,
  },
  {
    dataType: "deleted_user_data",
    retentionPeriod: 30 * 24 * 60 * 60 * 1000, // 30일 (복구 기간)
    description: "삭제된 사용자 데이터 (복구 기간)",
    autoDelete: true,
    archiveBeforeDelete: true,
  },
];

/**
 * 삭제 대상 데이터 항목
 */
export interface DeletionTarget {
  id: string;
  dataType: string;
  createdAt: number;
  lastAccessedAt?: number;
  userId?: string;
  metadata?: Record<string, unknown>;
}

/**
 * 삭제 작업 결과
 */
export interface DeletionResult {
  success: boolean;
  deletedCount: number;
  failedCount: number;
  errors: Array<{ id: string; error: string }>;
  archivedCount?: number;
}

/**
 * 삭제 작업 로그
 */
export interface DeletionJobLog {
  jobId: string;
  startedAt: number;
  completedAt?: number;
  policy: RetentionPolicy;
  result: DeletionResult;
  triggeredBy: "scheduled" | "manual" | "user_request";
}

// 메모리 저장소
const policies = new Map<string, RetentionPolicy>();
const deletionLogs: DeletionJobLog[] = [];
let scheduledJob: NodeJS.Timeout | null = null;

/**
 * 보존 정책 초기화
 */
export function initializeRetentionPolicies(): void {
  for (const policy of DEFAULT_RETENTION_POLICIES) {
    policies.set(policy.dataType, policy);
  }
  log.info("Retention policies initialized", { count: policies.size });
}

/**
 * 보존 정책 조회
 */
export function getRetentionPolicy(dataType: string): RetentionPolicy | undefined {
  return policies.get(dataType);
}

/**
 * 모든 보존 정책 조회
 */
export function getAllRetentionPolicies(): RetentionPolicy[] {
  return Array.from(policies.values());
}

/**
 * 보존 정책 업데이트
 */
export function updateRetentionPolicy(
  dataType: string,
  updates: Partial<Omit<RetentionPolicy, "dataType">>
): RetentionPolicy | undefined {
  const existing = policies.get(dataType);
  if (!existing) {
    return undefined;
  }

  const updated = { ...existing, ...updates };
  policies.set(dataType, updated);

  log.info("Retention policy updated", { dataType, updates });
  return updated;
}

/**
 * 삭제 대상 식별
 */
export function identifyDeletionTargets<T extends DeletionTarget>(
  items: T[],
  dataType: string
): T[] {
  const policy = policies.get(dataType);
  if (!policy || !policy.autoDelete || policy.retentionPeriod === 0) {
    return [];
  }

  const now = Date.now();
  const cutoffDate = now - policy.retentionPeriod;

  return items.filter((item) => {
    // 법적 보류 중인 데이터는 삭제하지 않음
    if (policy.legalHold) {
      return false;
    }

    // 생성일 기준 삭제
    if (item.createdAt < cutoffDate) {
      return true;
    }

    // 마지막 접근일 기준 삭제 (있는 경우)
    if (item.lastAccessedAt && item.lastAccessedAt < cutoffDate) {
      return true;
    }

    return false;
  });
}

/**
 * 데이터 삭제 실행
 */
export async function executeDeletion<T extends DeletionTarget>(
  targets: T[],
  dataType: string,
  options: {
    archiveHandler?: (item: T) => Promise<void>;
    deleteHandler: (item: T) => Promise<void>;
    triggeredBy?: "scheduled" | "manual" | "user_request";
  }
): Promise<DeletionResult> {
  const policy = policies.get(dataType);
  const jobId = `del-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  const startTime = Date.now();

  const result: DeletionResult = {
    success: true,
    deletedCount: 0,
    failedCount: 0,
    errors: [],
    archivedCount: 0,
  };

  log.info("Deletion job started", {
    jobId,
    dataType,
    targetCount: targets.length,
  });

  for (const target of targets) {
    try {
      // 아카이브 (필요한 경우)
      if (policy?.archiveBeforeDelete && options.archiveHandler) {
        await options.archiveHandler(target);
        result.archivedCount = (result.archivedCount || 0) + 1;
      }

      // 삭제 실행
      await options.deleteHandler(target);
      result.deletedCount++;

      log.debug("Item deleted", {
        jobId,
        itemId: target.id,
        dataType,
      });
    } catch (error) {
      result.failedCount++;
      result.errors.push({
        id: target.id,
        error: error instanceof Error ? error.message : String(error),
      });

      log.error("Failed to delete item", {
        jobId,
        itemId: target.id,
        dataType,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  result.success = result.failedCount === 0;

  // 로그 기록
  const jobLog: DeletionJobLog = {
    jobId,
    startedAt: startTime,
    completedAt: Date.now(),
    policy: policy || {
      dataType,
      retentionPeriod: 0,
      description: "Unknown",
      autoDelete: true,
    },
    result,
    triggeredBy: options.triggeredBy || "scheduled",
  };
  deletionLogs.push(jobLog);

  log.info("Deletion job completed", {
    jobId,
    dataType,
    deletedCount: result.deletedCount,
    failedCount: result.failedCount,
    duration: Date.now() - startTime,
  });

  return result;
}

/**
 * 예약 삭제 작업 실행
 */
export async function runScheduledDeletion(
  dataType: string,
  fetchItems: () => Promise<DeletionTarget[]>,
  deleteHandler: (item: DeletionTarget) => Promise<void>,
  archiveHandler?: (item: DeletionTarget) => Promise<void>
): Promise<DeletionResult> {
  const items = await fetchItems();
  const targets = identifyDeletionTargets(items, dataType);

  if (targets.length === 0) {
    return {
      success: true,
      deletedCount: 0,
      failedCount: 0,
      errors: [],
    };
  }

  return executeDeletion(targets, dataType, {
    deleteHandler,
    archiveHandler,
    triggeredBy: "scheduled",
  });
}

/**
 * 자동 삭제 스케줄러 시작
 */
export function startAutoDeletionScheduler(
  jobs: Array<{
    dataType: string;
    fetchItems: () => Promise<DeletionTarget[]>;
    deleteHandler: (item: DeletionTarget) => Promise<void>;
    archiveHandler?: (item: DeletionTarget) => Promise<void>;
  }>,
  intervalMs: number = 24 * 60 * 60 * 1000 // 24시간
): void {
  if (scheduledJob) {
    clearInterval(scheduledJob);
  }

  scheduledJob = setInterval(async () => {
    log.info("Running scheduled deletion jobs", { jobCount: jobs.length });

    for (const job of jobs) {
      try {
        await runScheduledDeletion(
          job.dataType,
          job.fetchItems,
          job.deleteHandler,
          job.archiveHandler
        );
      } catch (error) {
        log.error("Scheduled deletion job failed", {
          dataType: job.dataType,
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }
  }, intervalMs);

  log.info("Auto-deletion scheduler started", { intervalMs, jobCount: jobs.length });
}

/**
 * 스케줄러 중지
 */
export function stopAutoDeletionScheduler(): void {
  if (scheduledJob) {
    clearInterval(scheduledJob);
    scheduledJob = null;
    log.info("Auto-deletion scheduler stopped");
  }
}

/**
 * 삭제 작업 로그 조회
 */
export function getDeletionLogs(
  options: {
    dataType?: string;
    startDate?: number;
    endDate?: number;
    limit?: number;
  } = {}
): DeletionJobLog[] {
  let logs = [...deletionLogs];

  if (options.dataType) {
    logs = logs.filter((log) => log.policy.dataType === options.dataType);
  }

  if (options.startDate) {
    logs = logs.filter((log) => log.startedAt >= options.startDate!);
  }

  if (options.endDate) {
    logs = logs.filter((log) => log.startedAt <= options.endDate!);
  }

  // 최신 순으로 정렬
  logs.sort((a, b) => b.startedAt - a.startedAt);

  if (options.limit) {
    logs = logs.slice(0, options.limit);
  }

  return logs;
}

/**
 * 보존 정책 준수율 계산
 */
export function calculateComplianceRate(): {
  overall: number;
  byDataType: Record<string, number>;
} {
  const byDataType: Record<string, number> = {};
  let totalCompliant = 0;
  let totalPolicies = 0;

  for (const policy of policies.values()) {
    if (!policy.autoDelete) {
      continue;
    }

    totalPolicies++;

    // 해당 데이터 유형의 삭제 로그 확인
    const logs = deletionLogs.filter((log) => log.policy.dataType === policy.dataType);
    const recentLogs = logs.filter(
      (log) => log.completedAt && Date.now() - log.completedAt < 30 * 24 * 60 * 60 * 1000
    );

    // 최근 30일 내 삭제 작업이 있으면 준수로 간주
    const compliant = recentLogs.length > 0;
    byDataType[policy.dataType] = compliant ? 100 : 0;

    if (compliant) {
      totalCompliant++;
    }
  }

  return {
    overall: totalPolicies > 0 ? (totalCompliant / totalPolicies) * 100 : 100,
    byDataType,
  };
}

/**
 * GDPR 삭제 요청 처리
 */
export async function processGdprDeletionRequest(
  userId: string,
  options: {
    findUserData: (userId: string) => Promise<DeletionTarget[]>;
    deleteHandler: (item: DeletionTarget) => Promise<void>;
    archiveHandler?: (item: DeletionTarget) => Promise<void>;
  }
): Promise<DeletionResult> {
  log.info("Processing GDPR deletion request", { userId });

  const items = await options.findUserData(userId);

  return executeDeletion(items, "user_data", {
    deleteHandler: options.deleteHandler,
    archiveHandler: options.archiveHandler,
    triggeredBy: "user_request",
  });
}
