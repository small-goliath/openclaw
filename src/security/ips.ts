/**
 * 실시간 침입 탐지 시스템 (Intrusion Prevention System)
 * 실시간 로그 분석 및 규칙 기반 이상 행위 감지
 */

import { createSubsystemLogger } from "../logging/subsystem.js";
import { logSecurityEvent, alertCriticalEvent } from "./siem-logger.js";

const log = createSubsystemLogger("security/ips");

/**
 * 보안 이벤트 타입
 */
export interface SecurityEvent {
  timestamp: number;
  type: string;
  source: string;
  userId?: string;
  ip?: string;
  sessionId?: string;
  metadata: Record<string, unknown>;
}

/**
 * IPS 규칙 인터페이스
 */
export interface IpsRule {
  id: string;
  name: string;
  severity: "low" | "medium" | "high" | "critical";
  condition: (event: SecurityEvent, context: IpsContext) => boolean;
  action: "log" | "alert" | "block";
  description?: string;
}

/**
 * IPS 컨텍스트
 */
export interface IpsContext {
  eventBuffer: SecurityEvent[];
  blockList: Set<string>;
  stats: Map<string, number>;
}

/**
 * IPS 탐지 결과
 */
export interface IpsDetectionResult {
  ruleId: string;
  ruleName: string;
  severity: string;
  action: string;
  event: SecurityEvent;
  timestamp: number;
}

/**
 * 실시간 침입 탐지 시스템
 */
export class IntrusionPreventionSystem {
  private rules: IpsRule[] = [];
  private eventBuffer: SecurityEvent[] = [];
  private blockList = new Set<string>();
  private stats = new Map<string, number>();
  private maxBufferSize = 10000;
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    this.initializeDefaultRules();
    this.startCleanupTimer();
  }

  /**
   * 기본 규칙 초기화
   */
  private initializeDefaultRules(): void {
    // 규칙 1: 반복적인 인증 실패 (Brute Force)
    this.rules.push({
      id: "ips.auth.brute_force",
      name: "Brute Force Attack Detected",
      severity: "high",
      condition: (event, context) => {
        if (event.type !== "auth_failure") {
          return false;
        }

        const windowMs = 5 * 60 * 1000; // 5분
        const threshold = 10;

        const recentFailures = context.eventBuffer.filter(
          (e) =>
            e.type === "auth_failure" && e.ip === event.ip && e.timestamp > Date.now() - windowMs,
        );

        return recentFailures.length >= threshold;
      },
      action: "block",
      description: "Detects repeated authentication failures from same IP",
    });

    // 규칙 2: 비정상적인 시간대 접근
    this.rules.push({
      id: "ips.access.unusual_hours",
      name: "Unusual Access Hours",
      severity: "medium",
      condition: (event) => {
        if (event.type !== "login_success") {
          return false;
        }

        const hour = new Date(event.timestamp).getHours();
        // 새벽 1시 ~ 5시를 비정상 시간으로 간주
        return hour >= 1 && hour <= 5;
      },
      action: "alert",
      description: "Detects logins during unusual hours (1 AM - 5 AM)",
    });

    // 규칙 3: 권한 상승 명령어 실행
    this.rules.push({
      id: "ips.privilege.elevated_command",
      name: "Elevated Command Execution",
      severity: "high",
      condition: (event) => {
        if (event.type !== "elevated_exec") {
          return false;
        }

        const dangerousCommands = [
          "rm -rf",
          "mkfs",
          "dd if=",
          ":(){ :|:& };:", // fork bomb
          "chmod -R 777",
        ];

        const command = String(event.metadata?.command || "").toLowerCase();
        return dangerousCommands.some((cmd) => command.includes(cmd.toLowerCase()));
      },
      action: "alert",
      description: "Detects potentially dangerous elevated commands",
    });

    // 규칙 4: 빠른 연속 요청 (Rate Anomaly)
    this.rules.push({
      id: "ips.rate.anomaly",
      name: "Request Rate Anomaly",
      severity: "medium",
      condition: (event, context) => {
        if (!event.ip) {
          return false;
        }

        const windowMs = 60 * 1000; // 1분
        const threshold = 1000;

        const recentRequests = context.eventBuffer.filter(
          (e) => e.ip === event.ip && e.timestamp > Date.now() - windowMs,
        );

        return recentRequests.length >= threshold;
      },
      action: "block",
      description: "Detects abnormally high request rates",
    });

    // 규칙 5: 세션 하이재킹 시도
    this.rules.push({
      id: "ips.session.hijacking",
      name: "Session Hijacking Attempt",
      severity: "critical",
      condition: (event) => {
        if (event.type !== "session_validation_failed") {
          return false;
        }

        // 세션 검증 실패가 반복되는 경우
        return event.metadata?.reason === "session_invalidated_or_expired";
      },
      action: "block",
      description: "Detects potential session hijacking attempts",
    });

    // 규칙 6: 신규 IP에서의 민감 작업
    this.rules.push({
      id: "ips.access.new_ip_sensitive",
      name: "Sensitive Operation from New IP",
      severity: "high",
      condition: (event, context) => {
        if (event.type !== "sensitive_operation") {
          return false;
        }
        if (!event.ip) {
          return false;
        }

        // 해당 IP에서 이전 성공 로그인 기록이 없는 경우
        const hasPreviousLogin = context.eventBuffer.some(
          (e) =>
            e.type === "login_success" &&
            e.ip === event.ip &&
            e.timestamp < event.timestamp - 24 * 60 * 60 * 1000, // 24시간 이전
        );

        return !hasPreviousLogin;
      },
      action: "alert",
      description: "Detects sensitive operations from new IP addresses",
    });

    log.info("IPS default rules initialized", { count: this.rules.length });
  }

  /**
   * 보안 이벤트 처리
   */
  async processEvent(event: SecurityEvent): Promise<IpsDetectionResult | null> {
    // 이벤트 버퍼에 추가
    this.eventBuffer.push(event);
    this.cleanupBuffer();

    // 통계 업데이트
    const statsKey = `${event.type}:${event.ip || "unknown"}`;
    this.stats.set(statsKey, (this.stats.get(statsKey) || 0) + 1);

    const context: IpsContext = {
      eventBuffer: this.eventBuffer,
      blockList: this.blockList,
      stats: this.stats,
    };

    // 규칙 검사
    for (const rule of this.rules) {
      if (rule.condition(event, context)) {
        return await this.triggerAction(rule, event);
      }
    }

    return null;
  }

  /**
   * 규칙 트리거 액션 실행
   */
  private async triggerAction(rule: IpsRule, event: SecurityEvent): Promise<IpsDetectionResult> {
    const result: IpsDetectionResult = {
      ruleId: rule.id,
      ruleName: rule.name,
      severity: rule.severity,
      action: rule.action,
      event,
      timestamp: Date.now(),
    };

    switch (rule.action) {
      case "log":
        log.warn(`IPS Detection [${rule.severity}]: ${rule.name}`, {
          ruleId: rule.id,
          event,
        });
        await logSecurityEvent({
          type: "ips_detection",
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          event,
          timestamp: Date.now(),
        });
        break;

      case "alert":
        log.error(`IPS Alert [${rule.severity}]: ${rule.name}`, {
          ruleId: rule.id,
          event,
        });
        await alertCriticalEvent({
          type: "ips_alert",
          ruleId: rule.id,
          ruleName: rule.name,
          severity: rule.severity,
          event,
          timestamp: Date.now(),
        });
        break;

      case "block":
        if (event.ip) {
          this.blockList.add(event.ip);
          log.error(`IPS Block [${rule.severity}]: ${rule.name} - IP ${event.ip} blocked`, {
            ruleId: rule.id,
            event,
          });
          await alertCriticalEvent({
            type: "ips_block",
            ruleId: rule.id,
            ruleName: rule.name,
            severity: rule.severity,
            ip: event.ip,
            event,
            timestamp: Date.now(),
          });
        }
        break;
    }

    return result;
  }

  /**
   * IP 차단 여부 확인
   */
  isBlocked(ip: string): boolean {
    return this.blockList.has(ip);
  }

  /**
   * IP 차단 해제
   */
  unblock(ip: string): void {
    this.blockList.delete(ip);
    log.info(`IP unblocked: ${ip}`);
  }

  /**
   * 차단 목록 조회
   */
  getBlockedIps(): string[] {
    return Array.from(this.blockList);
  }

  /**
   * 커스텀 규칙 추가
   */
  addRule(rule: IpsRule): void {
    this.rules.push(rule);
    log.info(`IPS rule added: ${rule.id}`);
  }

  /**
   * 규칙 제거
   */
  removeRule(ruleId: string): boolean {
    const index = this.rules.findIndex((r) => r.id === ruleId);
    if (index >= 0) {
      this.rules.splice(index, 1);
      log.info(`IPS rule removed: ${ruleId}`);
      return true;
    }
    return false;
  }

  /**
   * 규칙 목록 조회
   */
  getRules(): IpsRule[] {
    return [...this.rules];
  }

  /**
   * 통계 조회
   */
  getStats(): Record<string, number> {
    return Object.fromEntries(this.stats);
  }

  /**
   * 이벤트 버퍼 정리
   */
  private cleanupBuffer(): void {
    // 오래된 이벤트 제거 (24시간 이상)
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    this.eventBuffer = this.eventBuffer.filter((e) => e.timestamp > cutoff);

    // 버퍼 크기 제한
    if (this.eventBuffer.length > this.maxBufferSize) {
      this.eventBuffer = this.eventBuffer.slice(-this.maxBufferSize);
    }
  }

  /**
   * 주기적 정리 타이머 시작
   */
  private startCleanupTimer(): void {
    this.cleanupInterval = setInterval(
      () => {
        this.cleanupBuffer();

        // 차단 목록에서 오래된 항목 제거 (24시간)
        // 실제로는 차단 시점을 기록해야 하지만 여기서는 단순화
      },
      60 * 60 * 1000,
    ); // 1시간마다

    if (this.cleanupInterval.unref) {
      this.cleanupInterval.unref();
    }
  }

  /**
   * 리소스 정리
   */
  dispose(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.eventBuffer = [];
    this.blockList.clear();
    this.stats.clear();
  }
}

// 싱글톤 인스턴스
let globalIPS: IntrusionPreventionSystem | null = null;

/**
 * 전역 IPS 인스턴스 가져오기
 */
export function getIPS(): IntrusionPreventionSystem {
  if (!globalIPS) {
    globalIPS = new IntrusionPreventionSystem();
  }
  return globalIPS;
}

/**
 * 전역 IPS 인스턴스 설정
 */
export function setIPS(ips: IntrusionPreventionSystem): void {
  globalIPS = ips;
}

/**
 * IPS 이벤트 생성 헬퍼
 */
export function createSecurityEvent(
  type: string,
  source: string,
  metadata: Record<string, unknown> = {},
  options?: {
    userId?: string;
    ip?: string;
    sessionId?: string;
  },
): SecurityEvent {
  return {
    timestamp: Date.now(),
    type,
    source,
    metadata,
    ...options,
  };
}
