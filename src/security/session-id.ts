/**
 * 강력한 세션 ID 생성 구현
 * 예측 불가능한 세션 ID로 세션 고정 공격 방지
 */

import crypto from "node:crypto";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("security/session-id");

/**
 * 세션 ID 생성 옵션
 */
export interface SessionIdOptions {
  length?: number; // 바이트 길이 (기본값: 32)
  encoding?: "base64url" | "hex" | "base64";
  prefix?: string;
}

const DEFAULT_OPTIONS: Required<SessionIdOptions> = {
  length: 32,
  encoding: "base64url",
  prefix: "sess_",
};

/**
 * 암호학적으로 안전한 세션 ID 생성
 *
 * 보안 특성:
 * - 256비트 엔트로피 (32바이트)
 * - CSPRNG (Cryptographically Secure Pseudo-Random Number Generator)
 * - 예측 불가능한 값
 * - 충분한 길이로 brute-force 방지
 */
export function generateSessionId(options: SessionIdOptions = {}): string {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  // crypto.randomBytes는 CSPRNG 사용
  const bytes = crypto.randomBytes(opts.length);

  // 인코딩 선택
  let encoded: string;
  switch (opts.encoding) {
    case "hex":
      encoded = bytes.toString("hex");
      break;
    case "base64":
      encoded = bytes.toString("base64");
      break;
    case "base64url":
    default:
      encoded = bytes.toString("base64url");
      break;
  }

  // prefix 추가
  return opts.prefix + encoded;
}

/**
 * 세션 ID 검증
 */
export function validateSessionId(sessionId: string, options: SessionIdOptions = {}): boolean {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  if (!sessionId) {
    return false;
  }

  // prefix 확인
  if (opts.prefix && !sessionId.startsWith(opts.prefix)) {
    return false;
  }

  // prefix 제거
  const idWithoutPrefix = opts.prefix ? sessionId.slice(opts.prefix.length) : sessionId;

  // 길이 확인 (인코딩별)
  let expectedLength: number;
  switch (opts.encoding) {
    case "hex":
      expectedLength = opts.length * 2;
      break;
    case "base64":
      expectedLength = Math.ceil((opts.length * 4) / 3);
      break;
    case "base64url":
      expectedLength = Math.ceil((opts.length * 4) / 3);
      // base64url은 padding이 없을 수 있음
      expectedLength = expectedLength - (expectedLength % 4 === 0 ? 0 : 4 - (expectedLength % 4));
      break;
    default:
      return false;
  }

  // 길이 허용 범위 (padding 차이 고려)
  const minLength = expectedLength - 2;
  const maxLength = expectedLength + 2;

  if (idWithoutPrefix.length < minLength || idWithoutPrefix.length > maxLength) {
    return false;
  }

  // 문자셋 확인
  let validChars: RegExp;
  switch (opts.encoding) {
    case "hex":
      validChars = /^[a-f0-9]+$/i;
      break;
    case "base64":
      validChars = /^[A-Za-z0-9+/=]+$/;
      break;
    case "base64url":
      validChars = /^[A-Za-z0-9_-]+$/;
      break;
    default:
      return false;
  }

  return validChars.test(idWithoutPrefix);
}

/**
 * 세션 ID 엔트로피 계산 (bits)
 */
export function calculateEntropy(options: SessionIdOptions = {}): number {
  const opts = { ...DEFAULT_OPTIONS, ...options };
  // 각 바이트는 8비트 엔트로피
  return opts.length * 8;
}

/**
 * 세션 ID 생성 (고급 옵션)
 * 추가 메타데이터 포함
 */
export interface EnhancedSessionId {
  id: string;
  createdAt: number;
  expiresAt: number;
  metadata: {
    entropy: number;
    version: string;
  };
}

export function generateEnhancedSessionId(
  ttlMs: number = 24 * 60 * 60 * 1000, // 24시간
  options: SessionIdOptions = {},
): EnhancedSessionId {
  const now = Date.now();
  const id = generateSessionId(options);

  return {
    id,
    createdAt: now,
    expiresAt: now + ttlMs,
    metadata: {
      entropy: calculateEntropy(options),
      version: "1.0",
    },
  };
}

/**
 * 세션 ID 버전 확인
 * 향후 마이그레이션을 위한 버전 관리
 */
export function detectSessionVersion(sessionId: string): string {
  if (sessionId.startsWith("sess_v1_")) {
    return "1.0";
  }
  if (sessionId.startsWith("sess_")) {
    return "1.0";
  }
  return "unknown";
}

/**
 * 세션 ID 마이그레이션
 * 이전 버전의 세션 ID를 새 버전으로 업그레이드
 */
export function migrateSessionId(
  oldSessionId: string,
  options: SessionIdOptions = {},
): { newId: string; migrated: boolean } {
  const version = detectSessionVersion(oldSessionId);

  if (version === "1.0" && validateSessionId(oldSessionId, options)) {
    // 이미 최신 버전이고 유효함
    return { newId: oldSessionId, migrated: false };
  }

  // 새 세션 ID 생성
  const newId = generateSessionId(options);

  log.info("Session ID migrated", {
    oldVersion: version,
    newId: newId.substring(0, 10) + "...",
  });

  return { newId, migrated: true };
}

/**
 * 세션 ID 생성 통계
 */
interface SessionIdStats {
  totalGenerated: number;
  averageEntropy: number;
  encodingDistribution: Record<string, number>;
}

let generationStats = {
  totalGenerated: 0,
  totalEntropy: 0,
  encodingCounts: {} as Record<string, number>,
};

export function generateSessionIdWithStats(options: SessionIdOptions = {}): string {
  const id = generateSessionId(options);

  // 통계 업데이트
  generationStats.totalGenerated++;
  generationStats.totalEntropy += calculateEntropy(options);

  const encoding = options.encoding || DEFAULT_OPTIONS.encoding;
  generationStats.encodingCounts[encoding] = (generationStats.encodingCounts[encoding] || 0) + 1;

  return id;
}

export function getSessionIdStats(): SessionIdStats {
  return {
    totalGenerated: generationStats.totalGenerated,
    averageEntropy:
      generationStats.totalGenerated > 0
        ? generationStats.totalEntropy / generationStats.totalGenerated
        : 0,
    encodingDistribution: generationStats.encodingCounts,
  };
}

/**
 * 안전한 세션 ID 비교
 * 타이밍 공격 방지를 위해 constant-time 비교
 */
export function compareSessionIds(a: string, b: string): boolean {
  try {
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  } catch {
    // 길이가 다른 경우
    return false;
  }
}

/**
 * 세션 ID 회전
 * 주기적인 세션 ID 변경으로 세션 하이재킹 방지
 */
export function rotateSessionId(
  currentId: string,
  options: SessionIdOptions = {},
): { newId: string; rotatedAt: number } {
  const newId = generateSessionId(options);

  log.info("Session ID rotated", {
    oldId: currentId.substring(0, 10) + "...",
    newId: newId.substring(0, 10) + "...",
  });

  return {
    newId,
    rotatedAt: Date.now(),
  };
}

/**
 * 권장 설정
 */
export const RECOMMENDED_SETTINGS = {
  // 웹 애플리케이션용
  web: {
    length: 32,
    encoding: "base64url" as const,
    prefix: "sess_",
  },
  // API용
  api: {
    length: 32,
    encoding: "base64url" as const,
    prefix: "api_",
  },
  // 모바일용
  mobile: {
    length: 32,
    encoding: "base64url" as const,
    prefix: "mob_",
  },
  // 고보안용
  highSecurity: {
    length: 64,
    encoding: "base64url" as const,
    prefix: "hs_",
  },
};
