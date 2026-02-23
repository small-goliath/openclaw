/**
 * 안전한 비밀번호 해싱 모듈
 * Argon2id 사용 (OWASP 권고)
 * 기존 SHA-256 해시와의 하위 호환성 유지
 */

import crypto from "node:crypto";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("security/password-hash");

/** 해시 알고리즘 타입 */
export type HashAlgorithm = "sha256" | "argon2id";

/** 비밀번호 해시 결과 */
export interface PasswordHash {
  hash: string;
  algorithm: HashAlgorithm;
  salt?: string; // sha256 레거시용
}

/** Argon2 module type definition */
interface Argon2Module {
  hash(password: string | Buffer, options?: Argon2Options): Promise<string>;
  verify(digest: string, password: string | Buffer): Promise<boolean>;
  argon2d: 0;
  argon2i: 1;
  argon2id: 2;
}

/** Argon2id 옵션 */
interface Argon2Options {
  type?: 0 | 1 | 2;
  memoryCost?: number;
  timeCost?: number;
  parallelism?: number;
  hashLength?: number;
  saltLength?: number;
}

// Argon2id 기본 설정 (OWASP 권고값)
const ARGON2_DEFAULTS: Required<
  Pick<
    Argon2Options,
    "type" | "memoryCost" | "timeCost" | "parallelism" | "hashLength" | "saltLength"
  >
> = {
  type: 2, // argon2id
  memoryCost: 65536, // 64 MB
  timeCost: 3,
  parallelism: 4,
  hashLength: 32,
  saltLength: 16,
};

/**
 * 비밀번호 해시 생성 (Argon2id)
 * @param password 평문 비밀번호
 * @returns PasswordHash 객체
 */
export async function hashPassword(password: string): Promise<PasswordHash> {
  try {
    // Argon2 동적 import
    const argon2 = (await import("argon2")) as unknown as Argon2Module;

    const hash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: ARGON2_DEFAULTS.memoryCost,
      timeCost: ARGON2_DEFAULTS.timeCost,
      parallelism: ARGON2_DEFAULTS.parallelism,
      hashLength: ARGON2_DEFAULTS.hashLength,
    });

    return {
      hash,
      algorithm: "argon2id",
    };
  } catch (err) {
    log.error("Argon2 hashing failed, falling back to legacy", { err });
    // Argon2 실패 시 레거시 SHA-256 (권장하지 않음)
    return hashPasswordLegacy(password);
  }
}

/**
 * 레거시 SHA-256 해시 생성 (하위 호환성)
 * @deprecated Argon2id 사용 권장
 */
export function hashPasswordLegacy(password: string): PasswordHash {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.createHmac("sha256", salt).update(password).digest("hex");

  return {
    hash,
    algorithm: "sha256",
    salt,
  };
}

/**
 * 비밀번호 검증
 * @param password 평문 비밀번호
 * @param storedHash 저장된 해시
 * @returns 검증 결과
 */
export async function verifyPassword(password: string, storedHash: PasswordHash): Promise<boolean> {
  if (storedHash.algorithm === "argon2id") {
    try {
      const argon2 = (await import("argon2")) as unknown as Argon2Module;
      return await argon2.verify(storedHash.hash, password);
    } catch (err) {
      log.error("Argon2 verification failed", { err });
      return false;
    }
  }

  // 레거시 SHA-256 지원
  if (storedHash.algorithm === "sha256") {
    const hash = crypto
      .createHmac("sha256", storedHash.salt || "")
      .update(password)
      .digest("hex");

    // 타이밍 공격 방지를 위한 constant-time 비교
    return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(storedHash.hash, "hex"));
  }

  return false;
}

/**
 * 비밀번호 검증 및 자동 업그레이드
 * 레거시 해시로 검증 성공 시 자동으로 Argon2id로 업그레이드
 * @param password 평문 비밀번호
 * @param storedHash 저장된 해시
 * @returns { valid: boolean; upgraded?: PasswordHash }
 */
export async function verifyAndUpgradePassword(
  password: string,
  storedHash: PasswordHash,
): Promise<{ valid: boolean; upgraded?: PasswordHash }> {
  const valid = await verifyPassword(password, storedHash);

  if (valid && storedHash.algorithm !== "argon2id") {
    // 자동 업그레이드
    log.info("Upgrading password hash from legacy algorithm", {
      from: storedHash.algorithm,
      to: "argon2id",
    });
    const upgraded = await hashPassword(password);
    return { valid: true, upgraded };
  }

  return { valid };
}

/**
 * 비밀번호 강도 검증
 * @param password 검증할 비밀번호
 * @returns { valid: boolean; errors: string[] }
 */
export function validatePasswordStrength(password: string): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  if (password.length < 8) {
    errors.push("Password must be at least 8 characters long");
  }

  if (password.length > 128) {
    errors.push("Password must not exceed 128 characters");
  }

  if (!/[a-z]/.test(password)) {
    errors.push("Password must contain at least one lowercase letter");
  }

  if (!/[A-Z]/.test(password)) {
    errors.push("Password must contain at least one uppercase letter");
  }

  if (!/\d/.test(password)) {
    errors.push("Password must contain at least one digit");
  }

  if (!/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)) {
    errors.push("Password must contain at least one special character");
  }

  // 연속된 문자 체크
  if (/(.){3,}/.test(password)) {
    errors.push("Password must not contain 3 or more consecutive identical characters");
  }

  // 공통 패턴 체크
  const commonPatterns = ["password", "123456", "qwerty", "admin", "letmein", "welcome"];
  const lowerPassword = password.toLowerCase();
  for (const pattern of commonPatterns) {
    if (lowerPassword.includes(pattern)) {
      errors.push("Password contains a common pattern");
      break;
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * 해시 알고리즘 정보 반환
 */
export function getHashAlgorithmInfo(): {
  recommended: HashAlgorithm;
  legacy: HashAlgorithm[];
} {
  return {
    recommended: "argon2id",
    legacy: ["sha256"],
  };
}
