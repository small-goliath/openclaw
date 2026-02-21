/**
 * Security Events Schema for SIEM Integration
 *
 * SIEM (Security Information and Event Management) 연동을 위한
 * 보안 이벤트 스키마 정의
 *
 * @module security/security-events
 */

import { randomUUID } from "node:crypto";
import { hostname } from "node:os";

/**
 * 보안 이벤트 유형
 */
export type SecurityEventType =
  | "AUTH_FAILURE" // 인증 실패
  | "AUTH_SUCCESS" // 인증 성공
  | "ACCESS_VIOLATION" // 접근 위반
  | "SUSPICIOUS_ACTIVITY" // 의심스러운 활동
  | "RATE_LIMIT_HIT" // 속도 제한 초과
  | "CONFIG_CHANGE" // 설정 변경
  | "PERMISSION_CHANGE" // 권한 변경
  | "SECURITY_AUDIT_FINDING" // 보안 감사 발견
  | "SESSION_ANOMALY" // 세션 이상
  | "DATA_EXFILTRATION_ATTEMPT"; // 데이터 유출 시도

/**
 * 보안 이벤트 심각도 레벨
 */
export type SecuritySeverity = "critical" | "high" | "medium" | "low" | "info";

/**
 * 인증 이벤트 상세 정보
 */
export interface AuthEventDetails {
  authMethod: "token" | "password" | "oauth" | "api_key" | "tailscale" | "unknown";
  success: boolean;
  userId?: string;
  ipAddress?: string;
  userAgent?: string;
  failureReason?:
    | "invalid_credentials"
    | "expired_token"
    | "missing_credentials"
    | "account_locked"
    | "ip_blocked"
    | "rate_limited"
    | string;
  attemptCount?: number;
  remainingAttempts?: number;
}

/**
 * 접근 위반 상세 정보
 */
export interface AccessViolationDetails {
  resource: string;
  action: string;
  userId?: string;
  violationType:
    | "unauthorized_access"
    | "privilege_escalation"
    | "forbidden_resource"
    | "invalid_permission"
    | "sandbox_escape_attempt"
    | string;
  requiredPermission?: string;
  actualPermission?: string;
  resourceType?: "file" | "api" | "tool" | "config" | "session" | string;
}

/**
 * 의심스러운 활동 상세 정보
 */
export interface SuspiciousActivityDetails {
  activityType:
    | "unusual_login_pattern"
    | "brute_force_attempt"
    | "privilege_escalation_attempt"
    | "data_scraping"
    | "command_injection_attempt"
    | "path_traversal_attempt"
    | "ssrf_attempt"
    | "unusual_api_usage"
    | string;
  description: string;
  riskScore: number; // 0-100
  indicators: string[];
  relatedEvents?: string[]; // 관련 이벤트 ID들
}

/**
 * 속도 제한 초과 상세 정보
 */
export interface RateLimitDetails {
  limitType: "auth" | "api" | "gateway" | string;
  maxAttempts: number;
  windowMs: number;
  currentAttempts: number;
  userId?: string;
  ipAddress?: string;
  endpoint?: string;
  lockoutDurationMs?: number;
}

/**
 * 설정 변경 상세 정보
 */
export interface ConfigChangeDetails {
  changeType: "create" | "update" | "delete";
  configPath: string;
  previousValueHash?: string; // 보안을 위해 실제 값 대신 해시 저장
  newValueHash?: string;
  changedBy: string;
  changeReason?: string;
}

/**
 * 권한 변경 상세 정보
 */
export interface PermissionChangeDetails {
  changeType: "grant" | "revoke" | "modify";
  targetUserId?: string;
  targetGroupId?: string;
  permission: string;
  resource: string;
  changedBy: string;
  previousState?: string;
  newState?: string;
}

/**
 * 보안 감사 발견 상세 정보
 */
export interface SecurityAuditFindingDetails {
  checkId: string;
  severity: SecuritySeverity;
  title: string;
  detail: string;
  remediation?: string;
  category?:
    | "filesystem"
    | "gateway"
    | "browser"
    | "logging"
    | "elevated"
    | "channel"
    | "plugin"
    | string;
}

/**
 * 세션 이상 상세 정보
 */
export interface SessionAnomalyDetails {
  anomalyType:
    | "concurrent_sessions"
    | "impossible_travel"
    | "session_hijacking"
    | "inactive_session_activity"
    | "session_duration_anomaly"
    | string;
  sessionId: string;
  userId?: string;
  description: string;
  previousLocation?: string;
  currentLocation?: string;
  timeDeltaMinutes?: number;
}

/**
 * 데이터 유출 시도 상세 정보
 */
export interface DataExfiltrationDetails {
  attemptType: "bulk_download" | "unusual_export" | "unauthorized_access" | string;
  dataType: string;
  recordsAffected?: number;
  destination?: string;
  detectionMethod: string;
}

/**
 * 이벤트 상세 정보 유니온 타입
 */
export type SecurityEventDetails =
  | AuthEventDetails
  | AccessViolationDetails
  | SuspiciousActivityDetails
  | RateLimitDetails
  | ConfigChangeDetails
  | PermissionChangeDetails
  | SecurityAuditFindingDetails
  | SessionAnomalyDetails
  | DataExfiltrationDetails;

/**
 * 보안 이벤트 기본 인터페이스
 */
export interface SecurityEvent {
  /** 이벤트 고유 ID (UUID v4) */
  id: string;

  /** 이벤트 발생 시간 (ISO 8601) */
  timestamp: string;

  /** 요청 추적용 상관관계 ID */
  correlationId: string;

  /** 이벤트 유형 */
  eventType: SecurityEventType;

  /** 이벤트 심각도 */
  severity: SecuritySeverity;

  /** 이벤트 소스 정보 */
  source: {
    /** 컴포넌트명 (예: gateway, audit, auth) */
    component: string;

    /** 호스트명 */
    host: string;

    /** 애플리케이션 버전 */
    version: string;
  };

  /** 이벤트 컨텍스트 */
  context?: {
    /** 사용자 ID */
    userId?: string;

    /** 세션 ID */
    sessionId?: string;

    /** IP 주소 */
    ipAddress?: string;

    /** User-Agent */
    userAgent?: string;

    /** 요청 ID */
    requestId?: string;

    /** 추가 메타데이터 */
    [key: string]: unknown;
  };

  /** 이벤트별 상세 정보 */
  details: SecurityEventDetails;

  /** 태그 (검색/필터링용) */
  tags?: string[];
}

/**
 * SIEM 출력 설정 기본 인터페이스
 */
export interface SiemOutputConfig {
  /** 출력 유형 */
  type: "http" | "syslog" | "file";

  /** 출력 활성화 여부 */
  enabled: boolean;

  /** 최소 심각도 레벨 (이 레벨 이상만 전송) */
  minSeverity?: SecuritySeverity;

  /** 이벤트 유형 필터 (비어있으면 모든 유형) */
  eventTypes?: SecurityEventType[];
}

/**
 * HTTP 출력 설정
 */
export interface HttpSiemConfig extends SiemOutputConfig {
  type: "http";

  /** SIEM 엔드포인트 URL */
  url: string;

  /** HTTP 헤더 */
  headers?: Record<string, string>;

  /** 타임아웃 (밀리초) */
  timeout?: number;

  /** 인증 설정 */
  auth?: {
    type: "bearer" | "basic" | "api_key";
    token?: string;
    username?: string;
    password?: string;
    apiKey?: string;
    apiKeyHeader?: string;
  };

  /** SSL/TLS 검증 비활성화 (개발 환경용, 프로덕션에서는 사용 금지) */
  rejectUnauthorized?: boolean;
}

/**
 * Syslog 출력 설정
 */
export interface SyslogSiemConfig extends SiemOutputConfig {
  type: "syslog";

  /** Syslog 서버 호스트 */
  host: string;

  /** Syslog 서버 포트 */
  port: number;

  /** 프로토콜 */
  protocol: "udp" | "tcp";

  /** Syslog facility */
  facility?: number;

  /** TLS 사용 여부 (TCP only) */
  useTls?: boolean;
}

/**
 * 파일 출력 설정
 */
export interface FileSiemConfig extends SiemOutputConfig {
  type: "file";

  /** 로그 파일 경로 */
  path: string;

  /** 파일 로테이션 활성화 */
  rotate?: boolean;

  /** 최대 파일 크기 (바이트) */
  maxSize?: number;

  /** 보관할 최대 파일 수 */
  maxFiles?: number;
}

/**
 * SIEM 전체 설정
 */
export interface SiemConfig {
  /** SIEM 연동 활성화 여부 */
  enabled: boolean;

  /** 버퍼 크기 (이 크기에 도달하면 플러시) */
  bufferSize: number;

  /** 플러시 간격 (밀리초) */
  flushIntervalMs: number;

  /** 최대 재시도 횟수 */
  maxRetries: number;

  /** 재시도 지연 시간 (밀리초, exponential backoff) */
  retryDelayMs: number;

  /** 출력 설정 목록 */
  outputs: (HttpSiemConfig | SyslogSiemConfig | FileSiemConfig)[];

  /** 기본 태그 (모든 이벤트에 추가) */
  defaultTags?: string[];
}

/**
 * 기본 SIEM 설정
 */
export const DEFAULT_SIEM_CONFIG: SiemConfig = {
  enabled: false,
  bufferSize: 100,
  flushIntervalMs: 5000,
  maxRetries: 3,
  retryDelayMs: 1000,
  outputs: [],
  defaultTags: ["openclaw"],
};

/**
 * 심각도 레벨 숫자 매핑 (비교용)
 */
export const SEVERITY_LEVELS: Record<SecuritySeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/**
 * 심각도 비교 함수
 * @param a 비교할 심각도 A
 * @param b 비교할 심각도 B
 * @returns a가 b보다 심각하면 1, 같으면 0, 덜 심각하면 -1
 */
export function compareSeverity(a: SecuritySeverity, b: SecuritySeverity): number {
  return SEVERITY_LEVELS[a] - SEVERITY_LEVELS[b];
}

/**
 * 심각도가 임계값 이상인지 확인
 * @param severity 확인할 심각도
 * @param threshold 임계값
 * @returns 임계값 이상이면 true
 */
export function isSeverityAtLeast(
  severity: SecuritySeverity,
  threshold: SecuritySeverity,
): boolean {
  return SEVERITY_LEVELS[severity] >= SEVERITY_LEVELS[threshold];
}

/**
 * 보안 이벤트 생성 옵션
 */
export interface CreateSecurityEventOptions {
  eventType: SecurityEventType;
  severity: SecuritySeverity;
  details: SecurityEventDetails;
  component: string;
  correlationId?: string;
  context?: SecurityEvent["context"];
  tags?: string[];
}

/**
 * 보안 이벤트 생성 함수
 * @param options 이벤트 생성 옵션
 * @param appVersion 애플리케이션 버전
 * @returns 생성된 보안 이벤트
 */
export function createSecurityEvent(
  options: CreateSecurityEventOptions,
  appVersion: string = "unknown",
): SecurityEvent {
  return {
    id: randomUUID(),
    timestamp: new Date().toISOString(),
    correlationId: options.correlationId ?? randomUUID(),
    eventType: options.eventType,
    severity: options.severity,
    source: {
      component: options.component,
      host: hostname(),
      version: appVersion,
    },
    context: options.context,
    details: options.details,
    tags: options.tags,
  };
}

/**
 * 인증 실패 이벤트 생성 헬퍼
 */
export function createAuthFailureEvent(
  details: Omit<AuthEventDetails, "success">,
  options?: Omit<CreateSecurityEventOptions, "eventType" | "severity" | "details">,
): SecurityEvent {
  return createSecurityEvent({
    eventType: "AUTH_FAILURE",
    severity: details.failureReason === "brute_force_detected" ? "critical" : "high",
    details: { ...details, success: false },
    component: options?.component ?? "auth",
    ...options,
  });
}

/**
 * 접근 위반 이벤트 생성 헬퍼
 */
export function createAccessViolationEvent(
  details: AccessViolationDetails,
  options?: Omit<CreateSecurityEventOptions, "eventType" | "severity" | "details">,
): SecurityEvent {
  const severity: SecuritySeverity =
    details.violationType === "sandbox_escape_attempt"
      ? "critical"
      : details.violationType === "privilege_escalation"
        ? "high"
        : "medium";

  return createSecurityEvent({
    eventType: "ACCESS_VIOLATION",
    severity,
    details,
    component: options?.component ?? "access-control",
    ...options,
  });
}

/**
 * 의심스러운 활동 이벤트 생성 헬퍼
 */
export function createSuspiciousActivityEvent(
  details: SuspiciousActivityDetails,
  options?: Omit<CreateSecurityEventOptions, "eventType" | "severity" | "details">,
): SecurityEvent {
  const severity: SecuritySeverity =
    details.riskScore >= 80 ? "critical" : details.riskScore >= 60 ? "high" : "medium";

  return createSecurityEvent({
    eventType: "SUSPICIOUS_ACTIVITY",
    severity,
    details,
    component: options?.component ?? "security-monitor",
    ...options,
  });
}

/**
 * 보안 감사 발견 이벤트 생성 헬퍼
 */
export function createSecurityAuditFindingEvent(
  details: SecurityAuditFindingDetails,
  options?: Omit<CreateSecurityEventOptions, "eventType" | "severity" | "details">,
): SecurityEvent {
  return createSecurityEvent({
    eventType: "SECURITY_AUDIT_FINDING",
    severity: details.severity,
    details,
    component: options?.component ?? "audit",
    ...options,
  });
}

/**
 * 이벤트를 JSON 문자열로 직렬화
 * @param event 보안 이벤트
 * @returns JSON 문자열
 */
export function serializeSecurityEvent(event: SecurityEvent): string {
  return JSON.stringify(event);
}

/**
 * 이벤트를 CEF (Common Event Format)로 변환
 * @param event 보안 이벤트
 * @returns CEF 형식 문자열
 */
export function toCEFFormat(event: SecurityEvent): string {
  const severityMap: Record<SecuritySeverity, string> = {
    critical: "10",
    high: "8",
    medium: "5",
    low: "3",
    info: "1",
  };

  const extensions: string[] = [
    `rt=${new Date(event.timestamp).getTime()}`,
    `cs1=${event.eventType} cs1Label=eventType`,
    `cs2=${event.source.component} cs2Label=component`,
    `cs3=${event.correlationId} cs3Label=correlationId`,
  ];

  if (event.context?.ipAddress) {
    extensions.push(`src=${event.context.ipAddress}`);
  }

  if (event.context?.userId) {
    extensions.push(`suser=${event.context.userId}`);
  }

  // 상세 정보를 JSON으로 인코딩하여 확장 필드에 추가
  extensions.push(`cs4=${JSON.stringify(event.details).replace(/\|/g, "\\|")} cs4Label=details`);

  return `CEF:0|OpenClaw|${event.source.component}|${event.source.version}|${event.eventType}|${event.eventType}|${severityMap[event.severity]}|${extensions.join(" ")}`;
}

/**
 * 이벤트를 Syslog 형식으로 변환
 * @param event 보안 이벤트
 * @returns Syslog 형식 문자열
 */
export function toSyslogFormat(event: SecurityEvent): string {
  const priority = getSyslogPriority(event.severity, event.eventType);
  const timestamp = new Date(event.timestamp).toISOString();
  const hostname_val = event.source.host;
  const appName = event.source.component;
  const msgId = event.id;

  // Structured data (RFC 5424)
  const structuredData = `[@openclaw eventType="${event.eventType}" correlationId="${event.correlationId}" severity="${event.severity}"]`;

  return `<${priority}>1 ${timestamp} ${hostname_val} ${appName} - ${msgId} ${structuredData} ${JSON.stringify(event.details)}`;
}

/**
 * Syslog 우선순위 계산
 * @param severity 보안 심각도
 * @param eventType 이벤트 유형
 * @returns Syslog priority 값
 */
function getSyslogPriority(severity: SecuritySeverity, eventType: SecurityEventType): number {
  // Facility: 16 (local use)
  const facility = 16;

  // Severity mapping
  const severityMap: Record<SecuritySeverity, number> = {
    critical: 2, // crit
    high: 3, // err
    medium: 4, // warning
    low: 5, // notice
    info: 6, // info
  };

  // Critical security events get higher priority
  if (eventType === "AUTH_FAILURE" || eventType === "ACCESS_VIOLATION") {
    return facility * 8 + Math.min(severityMap[severity] - 1, 0);
  }

  return facility * 8 + severityMap[severity];
}
