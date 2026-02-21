/**
 * GDPR 데이터 주체 요청(DSR) 추적 시스템
 * 30일 SLA 모니터링 및 감사 로깅
 */

import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("security/dsr");

/**
 * DSR 요청 유형
 */
export type DsrType = "access" | "deletion" | "portability" | "rectification" | "restriction";

/**
 * DSR 요청 상태
 */
export type DsrStatus =
  | "pending"
  | "in_review"
  | "processing"
  | "awaiting_verification"
  | "completed"
  | "rejected"
  | "cancelled";

/**
 * DSR 요청 데이터
 */
export interface DsrRequest {
  id: string;
  userId: string;
  email: string;
  type: DsrType;
  status: DsrStatus;
  description?: string;
  createdAt: number;
  updatedAt: number;
  completedAt?: number;
  deadlineAt: number; // 30일 SLA 기준
  assignedTo?: string;
  verificationMethod?: string;
  verificationCompletedAt?: number;
  dataCategories?: string[];
  rejectionReason?: string;
  notes?: string[];
}

/**
 * DSR 통계
 */
export interface DsrStats {
  total: number;
  byStatus: Record<DsrStatus, number>;
  byType: Record<DsrType, number>;
  avgProcessingTime: number; // milliseconds
  slaComplianceRate: number; // percentage
  overdueCount: number;
}

// 메모리 저장소 (실제 구현에서는 데이터베이스 사용)
const dsrStore = new Map<string, DsrRequest>();

/**
 * DSR ID 생성
 */
function generateDsrId(): string {
  const timestamp = Date.now().toString(36).toUpperCase();
  const random = Math.random().toString(36).substring(2, 6).toUpperCase();
  return `DSR-${timestamp}-${random}`;
}

/**
 * SLA 마감일 계산 (30일)
 */
function calculateDeadline(createdAt: number): number {
  return createdAt + 30 * 24 * 60 * 60 * 1000; // 30일
}

/**
 * DSR 요청 생성
 */
export function createDsrRequest(params: {
  userId: string;
  email: string;
  type: DsrType;
  description?: string;
  dataCategories?: string[];
}): DsrRequest {
  const now = Date.now();
  const request: DsrRequest = {
    id: generateDsrId(),
    userId: params.userId,
    email: params.email,
    type: params.type,
    status: "pending",
    description: params.description,
    createdAt: now,
    updatedAt: now,
    deadlineAt: calculateDeadline(now),
    dataCategories: params.dataCategories,
    notes: [],
  };

  dsrStore.set(request.id, request);

  log.info("DSR request created", {
    dsrId: request.id,
    userId: params.userId,
    type: params.type,
    deadline: new Date(request.deadlineAt).toISOString(),
  });

  // TODO: 알림 발송 (이메일, Slack 등)

  return request;
}

/**
 * DSR 요청 조회
 */
export function getDsrRequest(id: string): DsrRequest | undefined {
  return dsrStore.get(id);
}

/**
 * 사용자별 DSR 요청 조회
 */
export function getDsrRequestsByUser(userId: string): DsrRequest[] {
  return Array.from(dsrStore.values()).filter((req) => req.userId === userId);
}

/**
 * DSR 상태 업데이트
 */
export function updateDsrStatus(
  id: string,
  status: DsrStatus,
  options?: {
    assignedTo?: string;
    note?: string;
    rejectionReason?: string;
  },
): DsrRequest | undefined {
  const request = dsrStore.get(id);
  if (!request) {
    return undefined;
  }

  const oldStatus = request.status;
  request.status = status;
  request.updatedAt = Date.now();

  if (status === "completed") {
    request.completedAt = Date.now();
  }

  if (options?.assignedTo) {
    request.assignedTo = options.assignedTo;
  }

  if (options?.note) {
    request.notes = request.notes || [];
    request.notes.push(`[${new Date().toISOString()}] ${options.note}`);
  }

  if (options?.rejectionReason) {
    request.rejectionReason = options.rejectionReason;
  }

  dsrStore.set(id, request);

  log.info("DSR status updated", {
    dsrId: id,
    oldStatus,
    newStatus: status,
    userId: request.userId,
  });

  return request;
}

/**
 * DSR 검증 완료 표시
 */
export function verifyDsrRequest(
  id: string,
  method: string,
  verifiedBy: string,
): DsrRequest | undefined {
  const request = dsrStore.get(id);
  if (!request) {
    return undefined;
  }

  request.verificationMethod = method;
  request.verificationCompletedAt = Date.now();
  request.updatedAt = Date.now();

  if (request.status === "pending") {
    request.status = "in_review";
  }

  dsrStore.set(id, request);

  log.info("DSR request verified", {
    dsrId: id,
    method,
    verifiedBy,
  });

  return request;
}

/**
 * SLA 위반 여부 확인
 */
export function isSlaBreached(request: DsrRequest): boolean {
  return request.status !== "completed" && Date.now() > request.deadlineAt;
}

/**
 * SLA 잔여 시간 계산 (milliseconds)
 */
export function getRemainingSlaTime(request: DsrRequest): number {
  if (request.status === "completed") {
    return 0;
  }
  return Math.max(0, request.deadlineAt - Date.now());
}

/**
 * SLA 임박 알림 (7일, 3일, 1일 전)
 */
export function checkSlaAlerts(): DsrRequest[] {
  const now = Date.now();
  const alerts: DsrRequest[] = [];

  for (const request of dsrStore.values()) {
    if (request.status === "completed" || request.status === "cancelled") {
      continue;
    }

    const remaining = request.deadlineAt - now;
    const daysRemaining = Math.floor(remaining / (24 * 60 * 60 * 1000));

    // 7일, 3일, 1일 전 알림
    if (daysRemaining <= 7 && daysRemaining > 6) {
      log.warn("DSR SLA alert: 7 days remaining", {
        dsrId: request.id,
        userId: request.userId,
        daysRemaining,
      });
      alerts.push(request);
    } else if (daysRemaining <= 3 && daysRemaining > 2) {
      log.warn("DSR SLA alert: 3 days remaining", {
        dsrId: request.id,
        userId: request.userId,
        daysRemaining,
      });
      alerts.push(request);
    } else if (daysRemaining <= 1 && daysRemaining > 0) {
      log.error("DSR SLA alert: 1 day remaining", {
        dsrId: request.id,
        userId: request.userId,
        daysRemaining,
      });
      alerts.push(request);
    } else if (remaining <= 0) {
      log.error("DSR SLA BREACHED", {
        dsrId: request.id,
        userId: request.userId,
        daysOverdue: Math.abs(daysRemaining),
      });
      alerts.push(request);
    }
  }

  return alerts;
}

/**
 * DSR 통계 계산
 */
export function calculateDsrStats(): DsrStats {
  const requests = Array.from(dsrStore.values());
  const now = Date.now();

  const byStatus: Record<DsrStatus, number> = {
    pending: 0,
    in_review: 0,
    processing: 0,
    awaiting_verification: 0,
    completed: 0,
    rejected: 0,
    cancelled: 0,
  };

  const byType: Record<DsrType, number> = {
    access: 0,
    deletion: 0,
    portability: 0,
    rectification: 0,
    restriction: 0,
  };

  let totalProcessingTime = 0;
  let completedCount = 0;
  let slaCompliantCount = 0;
  let overdueCount = 0;

  for (const req of requests) {
    byStatus[req.status]++;
    byType[req.type]++;

    if (req.status === "completed" && req.completedAt) {
      completedCount++;
      const processingTime = req.completedAt - req.createdAt;
      totalProcessingTime += processingTime;

      if (req.completedAt <= req.deadlineAt) {
        slaCompliantCount++;
      }
    }

    if (isSlaBreached(req)) {
      overdueCount++;
    }
  }

  return {
    total: requests.length,
    byStatus,
    byType,
    avgProcessingTime: completedCount > 0 ? totalProcessingTime / completedCount : 0,
    slaComplianceRate: completedCount > 0 ? (slaCompliantCount / completedCount) * 100 : 100,
    overdueCount,
  };
}

/**
 * 모든 DSR 요청 조회 (필터링 및 정렬 지원)
 */
export function listDsrRequests(options?: {
  status?: DsrStatus;
  type?: DsrType;
  sortBy?: "createdAt" | "deadlineAt" | "updatedAt";
  sortOrder?: "asc" | "desc";
  limit?: number;
  offset?: number;
}): DsrRequest[] {
  let requests = Array.from(dsrStore.values());

  // 필터링
  if (options?.status) {
    requests = requests.filter((req) => req.status === options.status);
  }
  if (options?.type) {
    requests = requests.filter((req) => req.type === options.type);
  }

  // 정렬
  const sortBy = options?.sortBy || "createdAt";
  const sortOrder = options?.sortOrder || "desc";
  requests.sort((a, b) => {
    const aVal = a[sortBy];
    const bVal = b[sortBy];
    return sortOrder === "asc" ? (aVal || 0) - (bVal || 0) : (bVal || 0) - (aVal || 0);
  });

  // 페이지네이션
  const offset = options?.offset || 0;
  const limit = options?.limit || requests.length;
  return requests.slice(offset, offset + limit);
}

/**
 * DSR 보고서 생성
 */
export function generateDsrReport(
  startDate: number,
  endDate: number,
): {
  period: { start: string; end: string };
  stats: DsrStats;
  requests: DsrRequest[];
} {
  const requests = Array.from(dsrStore.values()).filter(
    (req) => req.createdAt >= startDate && req.createdAt <= endDate,
  );

  // 임시 저장소 백업 및 복원
  const backup = new Map(dsrStore);
  dsrStore.clear();
  for (const req of requests) {
    dsrStore.set(req.id, req);
  }
  const stats = calculateDsrStats();
  dsrStore.clear();
  for (const [id, req] of backup) {
    dsrStore.set(id, req);
  }

  return {
    period: {
      start: new Date(startDate).toISOString(),
      end: new Date(endDate).toISOString(),
    },
    stats,
    requests,
  };
}

/**
 * DSR 요청 취소
 */
export function cancelDsrRequest(
  id: string,
  reason: string,
  cancelledBy: string,
): DsrRequest | undefined {
  const request = dsrStore.get(id);
  if (!request) {
    return undefined;
  }

  if (request.status === "completed" || request.status === "cancelled") {
    return undefined;
  }

  request.status = "cancelled";
  request.updatedAt = Date.now();
  request.notes = request.notes || [];
  request.notes.push(`[${new Date().toISOString()}] Cancelled by ${cancelledBy}: ${reason}`);

  dsrStore.set(id, request);

  log.info("DSR request cancelled", {
    dsrId: id,
    reason,
    cancelledBy,
  });

  return request;
}

/**
 * 주기적 SLA 체크 (Cron 작업에서 호출)
 */
export function startSlaMonitoring(): void {
  // 즉시 한 번 실행
  checkSlaAlerts();

  // 24시간마다 실행
  setInterval(
    () => {
      checkSlaAlerts();
    },
    24 * 60 * 60 * 1000,
  );

  log.info("DSR SLA monitoring started");
}
