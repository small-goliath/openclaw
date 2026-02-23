/**
 * GDPR 동의 관리 시스템
 * COMP-002, COMP-003, COMP-004, SEC-4.2, SEC-7.3 요구사항 구현
 *
 * 기능:
 * - 세분화된 동의 관리 (necessary, functional, analytics, marketing)
 * - 동의 로깅 및 감사 추적
 * - 동의 철회 메커니즘
 * - 데이터 처리 목적 문서화
 * - IP 주소 해싱 (GDPR Article 5(1)(c) 준수)
 */

import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("compliance/consent-store");

// COMP-002: IP 해싱용 salt (애플리케이션 시작 시 생성)
const IP_HASH_SALT = crypto.randomUUID();

/**
 * IP 주소를 안전하게 해싱
 * GDPR Article 5(1)(c) - 데이터 최소화 원칙 준수
 * @param ip - 원본 IP 주소
 * @returns 해싱된 IP 주소 (SHA-256 + salt)
 */
export async function hashIpAddress(ip: string): Promise<string> {
  try {
    const data = new TextEncoder().encode(ip + IP_HASH_SALT);
    const hashBuffer = await crypto.subtle.digest("SHA-256", data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    // 처음 16바이트만 사용하여 반환 (32자 hex)
    return hashArray
      .slice(0, 16)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  } catch (error) {
    log.error("IP hashing failed", { error: String(error) });
    return "hash-error";
  }
}

/**
 * 동의 유형
 */
export type ConsentType = "necessary" | "functional" | "analytics" | "marketing";

/**
 * 동의 상태
 */
export type ConsentState = "granted" | "denied" | "pending";

/**
 * 동의 설정 인터페이스
 */
export interface ConsentPreferences {
  /** 필수 쿠키 (항상 true, 사용자 변경 불가) */
  necessary: boolean;
  /** 기능성 쿠키 (사용자 설정 저장 등) */
  functional: boolean;
  /** 분석 쿠키 (사용자 행동 분석) */
  analytics: boolean;
  /** 마케팅 쿠키 (광고 타겟팅) */
  marketing: boolean;
}

/**
 * 동의 기록 항목
 */
export interface ConsentLogEntry {
  /** 타임스탬프 (ISO 8601) */
  timestamp: string;
  /** 동의 유형 */
  type: ConsentType;
  /** 동의 상태 */
  state: ConsentState;
  /** 동의 버전 */
  consentVersion: string;
  /** 개인정보 처리방침 버전 */
  privacyPolicyVersion: string;
  /** 처리 목적 */
  purposes: string[];
  /** 사용자 에이전트 */
  userAgent?: string;
  /** IP 주소 (해시됨) */
  ipHash?: string;
  /** 세션 ID */
  sessionId?: string;
}

/**
 * 동의 저장소 설정
 */
export interface ConsentStoreConfig {
  /** 로컬 스토리지 키 접두사 */
  storageKeyPrefix: string;
  /** 동의 버전 */
  consentVersion: string;
  /** 개인정보 처리방침 버전 */
  privacyPolicyVersion: string;
  /** 동의 만료일 (일) */
  consentExpiryDays: number;
  /** 처리 목적 정의 */
  purposes: Record<ConsentType, string[]>;
}

/**
 * 기본 설정
 */
const DEFAULT_CONFIG: ConsentStoreConfig = {
  storageKeyPrefix: "openclaw-consent",
  consentVersion: "1.0.0",
  privacyPolicyVersion: "1.0.0",
  consentExpiryDays: 365,
  purposes: {
    necessary: [
      "서비스 제공을 위한 필수 기능",
      "보안 및 인증",
      "사용자 세션 관리",
      "서비스 가용성 유지",
    ],
    functional: [
      "사용자 설정 저장",
      "언어 및 지역 설정",
      "테마 및 디스플레이 설정",
      "사용자 편의 기능",
    ],
    analytics: ["서비스 사용 현황 분석", "성능 모니터링", "오류 추적 및 개선", "사용자 경험 개선"],
    marketing: [
      "맞춤형 광고 제공",
      "마케팅 캠페인 효과 측정",
      "사용자 세그먼트 분석",
      "제품 개선을 위한 피드백 수집",
    ],
  },
};

/**
 * 동의 저장소 클래스
 */
export class ConsentStore {
  private config: ConsentStoreConfig;
  private preferences: ConsentPreferences;
  private log: ConsentLogEntry[];
  private initialized = false;
  private listeners: Set<(preferences: ConsentPreferences) => void> = new Set();

  constructor(config: Partial<ConsentStoreConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.preferences = this.getDefaultPreferences();
    this.log = [];
  }

  /**
   * 저장소 초기화
   */
  initialize(): void {
    if (this.initialized) {
      return;
    }

    try {
      // 저장된 동의 설정 로드
      const savedPreferences = this.loadFromStorage<ConsentPreferences>("preferences");
      if (savedPreferences) {
        // 버전 확인
        const savedVersion = this.loadFromStorage<string>("version");
        if (savedVersion === this.config.consentVersion) {
          this.preferences = { ...this.getDefaultPreferences(), ...savedPreferences };
        } else {
          // 버전 변경 시 재동의 필요
          log.info("Consent version changed, requiring re-consent");
          this.preferences = this.getDefaultPreferences();
          this.preferences.necessary = true; // 필수는 항상 true
        }
      }

      // 저장된 동의 로그 로드
      const savedLog = this.loadFromStorage<ConsentLogEntry[]>("log");
      if (savedLog) {
        this.log = savedLog;
      }

      this.initialized = true;
      this.emitChange();

      log.info("Consent store initialized", { preferences: this.preferences });
    } catch (error) {
      log.error("Failed to initialize consent store", { error: String(error) });
      // 오류 시 기본값 사용
      this.preferences = this.getDefaultPreferences();
      this.initialized = true;
    }
  }

  /**
   * 기본 동의 설정 반환
   */
  private getDefaultPreferences(): ConsentPreferences {
    return {
      necessary: true, // 필수는 항상 true
      functional: false,
      analytics: false,
      marketing: false,
    };
  }

  /**
   * 로컬 스토리지에서 데이터 로드
   */
  private loadFromStorage<T>(key: string): T | null {
    try {
      // 브라우저 환경 확인
      if (typeof localStorage === "undefined") {
        return null;
      }

      const fullKey = `${this.config.storageKeyPrefix}-${key}`;
      const data = localStorage.getItem(fullKey);
      if (!data) {
        return null;
      }

      // 만료 확인
      const expiryKey = `${fullKey}-expiry`;
      const expiry = localStorage.getItem(expiryKey);
      if (expiry && new Date(expiry) < new Date()) {
        localStorage.removeItem(fullKey);
        localStorage.removeItem(expiryKey);
        return null;
      }

      return JSON.parse(data) as T;
    } catch (error) {
      log.warn(`Failed to load from storage: ${key}`, { error: String(error) });
      return null;
    }
  }

  /**
   * 로컬 스토리지에 데이터 저장
   */
  private saveToStorage<T>(key: string, data: T): void {
    try {
      // 브라우저 환경 확인
      if (typeof localStorage === "undefined") {
        return;
      }

      const fullKey = `${this.config.storageKeyPrefix}-${key}`;
      localStorage.setItem(fullKey, JSON.stringify(data));

      // 만료일 설정
      const expiryKey = `${fullKey}-expiry`;
      const expiryDate = new Date();
      expiryDate.setDate(expiryDate.getDate() + this.config.consentExpiryDays);
      localStorage.setItem(expiryKey, expiryDate.toISOString());
    } catch (error) {
      log.warn(`Failed to save to storage: ${key}`, { error: String(error) });
    }
  }

  /**
   * 동의 설정 조회
   */
  getPreferences(): ConsentPreferences {
    return { ...this.preferences };
  }

  /**
   * 특정 동의 유형의 상태 조회
   */
  getConsent(type: ConsentType): ConsentState {
    if (type === "necessary") {
      return "granted";
    }
    return this.preferences[type] ? "granted" : "denied";
  }

  /**
   * 특정 동의 유형이 granted인지 확인
   */
  hasConsent(type: ConsentType): boolean {
    if (type === "necessary") {
      return true;
    }
    return this.preferences[type];
  }

  /**
   * 모든 동의가 완료되었는지 확인
   */
  hasAllConsents(): boolean {
    return (
      this.preferences.necessary &&
      this.preferences.functional &&
      this.preferences.analytics &&
      this.preferences.marketing
    );
  }

  /**
   * 동의가 필요한지 확인 (초기화되지 않았거나 버전 변경)
   */
  needsConsent(): boolean {
    if (!this.initialized) {
      return true;
    }

    // 저장된 버전 확인
    const savedVersion = this.loadFromStorage<string>("version");
    if (savedVersion !== this.config.consentVersion) {
      return true;
    }

    // 모든 동의가 기본값인지 확인
    return (
      !this.preferences.functional && !this.preferences.analytics && !this.preferences.marketing
    );
  }

  /**
   * 동의 설정 업데이트
   */
  setConsent(type: ConsentType, granted: boolean): void {
    if (type === "necessary") {
      // 필수 동의는 변경 불가
      return;
    }

    const oldState = this.preferences[type];
    this.preferences[type] = granted;

    // 변경 시에만 로그 기록 및 저장
    if (oldState !== granted) {
      this.logConsentChange(type, granted ? "granted" : "denied");
      this.savePreferences();
      this.emitChange();

      log.info(`Consent ${type} changed to ${granted}`);
    }
  }

  /**
   * 여러 동의 설정 업데이트
   */
  setMultipleConsents(preferences: Partial<Omit<ConsentPreferences, "necessary">>): void {
    let changed = false;

    for (const [type, granted] of Object.entries(preferences)) {
      const consentType = type as Exclude<ConsentType, "necessary">;
      const oldState = this.preferences[consentType];
      this.preferences[consentType] = granted;

      if (oldState !== granted) {
        this.logConsentChange(consentType, granted ? "granted" : "denied");
        changed = true;
      }
    }

    if (changed) {
      this.savePreferences();
      this.emitChange();

      log.info("Multiple consents updated", { preferences });
    }
  }

  /**
   * 모든 동의 수락
   */
  acceptAll(): void {
    this.setMultipleConsents({
      functional: true,
      analytics: true,
      marketing: true,
    });
  }

  /**
   * 필수 동의만 수락 (나머지 거부)
   */
  acceptNecessaryOnly(): void {
    this.setMultipleConsents({
      functional: false,
      analytics: false,
      marketing: false,
    });
  }

  /**
   * 모든 동의 철회
   */
  revokeAllConsents(): void {
    this.setMultipleConsents({
      functional: false,
      analytics: false,
      marketing: false,
    });

    log.info("All consents revoked");
  }

  /**
   * 동의 설정 저장
   */
  private savePreferences(): void {
    this.saveToStorage("preferences", this.preferences);
    this.saveToStorage("version", this.config.consentVersion);
    this.saveToStorage("privacyVersion", this.config.privacyPolicyVersion);
    this.saveToStorage("timestamp", new Date().toISOString());
  }

  /**
   * 동의 변경 로그 기록
   * COMP-002: IP 주소 해싱 적용
   */
  private async logConsentChange(
    type: ConsentType,
    state: ConsentState,
    clientIp?: string
  ): Promise<void> {
    // IP 주소 해싱 (비동기)
    let ipHash: string | undefined;
    try {
      if (clientIp) {
        ipHash = await hashIpAddress(clientIp);
      }
    } catch {
      ipHash = undefined;
    }

    const entry: ConsentLogEntry = {
      timestamp: new Date().toISOString(),
      type,
      state,
      consentVersion: this.config.consentVersion,
      privacyPolicyVersion: this.config.privacyPolicyVersion,
      purposes: this.config.purposes[type],
      userAgent: typeof navigator !== "undefined" ? navigator.userAgent : undefined,
      ipHash, // COMP-002: 해싱된 IP만 저장
      sessionId: this.generateSessionId(),
    };

    this.log.push(entry);

    // 로그 크기 제한 (최근 100개만 유지)
    if (this.log.length > 100) {
      this.log = this.log.slice(-100);
    }

    this.saveToStorage("log", this.log);
  }

  /**
   * 세션 ID 생성
   */
  private generateSessionId(): string {
    return `session-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
  }

  /**
   * 동의 로그 조회
   */
  getConsentLog(): ConsentLogEntry[] {
    return [...this.log];
  }

  /**
   * 동의 로그 수출 (감사용)
   */
  exportConsentLog(): {
    exportedAt: string;
    version: string;
    entries: ConsentLogEntry[];
    summary: {
      totalEntries: number;
      grantsByType: Record<ConsentType, number>;
      denialsByType: Record<ConsentType, number>;
      dateRange: { from: string; to: string } | null;
    };
  } {
    const grantsByType: Record<ConsentType, number> = {
      necessary: 0,
      functional: 0,
      analytics: 0,
      marketing: 0,
    };
    const denialsByType: Record<ConsentType, number> = {
      necessary: 0,
      functional: 0,
      analytics: 0,
      marketing: 0,
    };

    for (const entry of this.log) {
      if (entry.state === "granted") {
        grantsByType[entry.type]++;
      } else {
        denialsByType[entry.type]++;
      }
    }

    const timestamps = this.log.map((e) => new Date(e.timestamp).getTime());
    const dateRange =
      timestamps.length > 0
        ? {
            from: new Date(Math.min(...timestamps)).toISOString(),
            to: new Date(Math.max(...timestamps)).toISOString(),
          }
        : null;

    return {
      exportedAt: new Date().toISOString(),
      version: this.config.consentVersion,
      entries: [...this.log],
      summary: {
        totalEntries: this.log.length,
        grantsByType,
        denialsByType,
        dateRange,
      },
    };
  }

  /**
   * 처리 목적 조회
   */
  getPurposes(type: ConsentType): string[] {
    return [...this.config.purposes[type]];
  }

  /**
   * 모든 처리 목적 조회
   */
  getAllPurposes(): Record<ConsentType, string[]> {
    return {
      necessary: [...this.config.purposes.necessary],
      functional: [...this.config.purposes.functional],
      analytics: [...this.config.purposes.analytics],
      marketing: [...this.config.purposes.marketing],
    };
  }

  /**
   * 동의 버전 정보 조회
   */
  getVersionInfo(): {
    consentVersion: string;
    privacyPolicyVersion: string;
    expiryDays: number;
  } {
    return {
      consentVersion: this.config.consentVersion,
      privacyPolicyVersion: this.config.privacyPolicyVersion,
      expiryDays: this.config.consentExpiryDays,
    };
  }

  /**
   * 변경 리스너 등록
   */
  onChange(listener: (preferences: ConsentPreferences) => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  /**
   * 변경 이벤트 발생
   */
  private emitChange(): void {
    for (const listener of this.listeners) {
      try {
        listener({ ...this.preferences });
      } catch (error) {
        log.warn("Consent change listener failed", { error: String(error) });
      }
    }
  }

  /**
   * 저장소 정리 (테스트용)
   */
  clear(): void {
    this.preferences = this.getDefaultPreferences();
    this.log = [];

    try {
      if (typeof localStorage !== "undefined") {
        const keys = ["preferences", "version", "privacyVersion", "timestamp", "log"];
        for (const key of keys) {
          localStorage.removeItem(`${this.config.storageKeyPrefix}-${key}`);
          localStorage.removeItem(`${this.config.storageKeyPrefix}-${key}-expiry`);
        }
      }
    } catch (error) {
      log.warn("Failed to clear consent storage", { error: String(error) });
    }

    this.emitChange();
  }
}

/**
 * 전역 동의 저장소 인스턴스
 */
let globalConsentStore: ConsentStore | null = null;

/**
 * 동의 저장소 인스턴스 가져오기 (싱글톤)
 */
export function getConsentStore(config?: Partial<ConsentStoreConfig>): ConsentStore {
  if (!globalConsentStore) {
    globalConsentStore = new ConsentStore(config);
  }
  return globalConsentStore;
}

/**
 * 동의 저장소 초기화
 */
export function initializeConsentStore(config?: Partial<ConsentStoreConfig>): ConsentStore {
  globalConsentStore = new ConsentStore(config);
  globalConsentStore.initialize();
  return globalConsentStore;
}

/**
 * 동의 유틸리티 함수들
 */

/**
 * 스크립트 실행이 허용되는지 확인
 */
export function canExecuteScript(scriptType: ConsentType): boolean {
  const store = getConsentStore();
  return store.hasConsent(scriptType);
}

/**
 * 쿠키 설정이 허용되는지 확인
 */
export function canSetCookie(cookieType: ConsentType): boolean {
  const store = getConsentStore();
  return store.hasConsent(cookieType);
}

/**
 * 동의 배너를 표시해야 하는지 확인
 */
export function shouldShowConsentBanner(): boolean {
  const store = getConsentStore();
  return store.needsConsent();
}

/**
 * 동의 설정을 JSON으로 수출
 */
export function exportConsentSettings(): string {
  const store = getConsentStore();
  const preferences = store.getPreferences();
  const version = store.getVersionInfo();

  return JSON.stringify(
    {
      exportedAt: new Date().toISOString(),
      version,
      preferences,
    },
    null,
    2,
  );
}

/**
 * 동의 설정 가져오기 (API 응답용)
 */
export function getConsentStatus(): {
  initialized: boolean;
  needsConsent: boolean;
  preferences: ConsentPreferences;
  version: {
    consentVersion: string;
    privacyPolicyVersion: string;
  };
} {
  const store = getConsentStore();
  const version = store.getVersionInfo();

  return {
    initialized: true,
    needsConsent: store.needsConsent(),
    preferences: store.getPreferences(),
    version: {
      consentVersion: version.consentVersion,
      privacyPolicyVersion: version.privacyPolicyVersion,
    },
  };
}
