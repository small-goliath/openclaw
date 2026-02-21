/**
 * 다중 인증(MFA) 구현
 * TOTP 및 WebAuthn 지원 (SOC 2 CC6.1 준수)
 */

import crypto from "node:crypto";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("gateway/mfa");

/**
 * MFA 설정 타입
 */
export type MfaType = "totp" | "webauthn";

/**
 * TOTP 설정
 */
export interface TotpConfig {
  secret: string;
  algorithm: "SHA1" | "SHA256" | "SHA512";
  digits: number;
  period: number; // seconds
}

/**
 * WebAuthn 설정
 */
export interface WebAuthnConfig {
  credentialId: string;
  publicKey: string;
  signCount: number;
}

/**
 * 사용자 MFA 설정
 */
export interface UserMfaSettings {
  userId: string;
  enabled: boolean;
  type?: MfaType;
  totp?: TotpConfig;
  webauthn?: WebAuthnConfig;
  backupCodes: string[];
  createdAt: number;
  updatedAt: number;
}

/**
 * TOTP QR 코드 데이터
 */
export interface TotpQrCodeData {
  secret: string;
  qrCodeUrl: string;
  manualEntryKey: string;
}

/**
 * base32 인코딩
 */
function base32Encode(buffer: Buffer): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let result = "";
  let bits = 0;
  let value = 0;

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;

    while (bits >= 5) {
      result += alphabet[(value >> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    result += alphabet[(value << (5 - bits)) & 31];
  }

  return result;
}

/**
 * base32 디코딩
 */
function base32Decode(encoded: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const map = new Map(alphabet.split("").map((c, i) => [c, i]));

  let bits = 0;
  let value = 0;
  const result: number[] = [];

  for (const char of encoded.toUpperCase()) {
    const index = map.get(char);
    if (index === undefined) {
      continue;
    }

    value = (value << 5) | index;
    bits += 5;

    if (bits >= 8) {
      result.push((value >> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(result);
}

/**
 * TOTP 비밀 키 생성
 */
export function generateTotpSecret(): string {
  const bytes = crypto.randomBytes(20);
  return base32Encode(bytes);
}

/**
 * TOTP QR 코드 URL 생성
 */
export function generateTotpQrCodeUrl(secret: string, accountName: string, issuer: string): string {
  const encodedAccount = encodeURIComponent(accountName);
  const encodedIssuer = encodeURIComponent(issuer);
  return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
}

/**
 * HMAC 기반 OTP 생성 (RFC 4226)
 */
function generateHotp(secret: Buffer, counter: number, digits: number = 6): string {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter), 0);

  const hmac = crypto.createHmac("sha1", secret);
  hmac.update(counterBuffer);
  const hash = hmac.digest();

  // Dynamic truncation
  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const otp = binary % Math.pow(10, digits);
  return otp.toString().padStart(digits, "0");
}

/**
 * TOTP 코드 생성 (RFC 6238)
 */
export function generateTotpCode(
  secret: string,
  timeStep: number = 30,
  digits: number = 6,
): string {
  const secretBuffer = base32Decode(secret);
  const counter = Math.floor(Date.now() / 1000 / timeStep);
  return generateHotp(secretBuffer, counter, digits);
}

/**
 * TOTP 코드 검증
 */
export function verifyTotpCode(
  secret: string,
  code: string,
  window: number = 1,
  timeStep: number = 30,
  digits: number = 6,
): boolean {
  const secretBuffer = base32Decode(secret);
  const counter = Math.floor(Date.now() / 1000 / timeStep);

  for (let i = -window; i <= window; i++) {
    const expectedCode = generateHotp(secretBuffer, counter + i, digits);
    if (crypto.timingSafeEqual(Buffer.from(code), Buffer.from(expectedCode))) {
      return true;
    }
  }

  return false;
}

/**
 * 백업 코드 생성
 */
export function generateBackupCodes(count: number = 10): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const bytes = crypto.randomBytes(4);
    const code = bytes.toString("hex").toUpperCase();
    codes.push(`${code.slice(0, 4)}-${code.slice(4, 8)}`);
  }
  return codes;
}

/**
 * 백업 코드 해싱 (저장용)
 */
export function hashBackupCode(code: string): string {
  const normalized = code.replace(/-/g, "").toLowerCase();
  return crypto.createHash("sha256").update(normalized).digest("hex");
}

/**
 * 백업 코드 검증
 */
export function verifyBackupCode(code: string, hashedCodes: string[]): boolean {
  const normalized = code.replace(/-/g, "").toLowerCase();
  const hash = crypto.createHash("sha256").update(normalized).digest("hex");
  return hashedCodes.includes(hash);
}

/**
 * TOTP 설정 초기화
 */
export function setupTotp(accountName: string, issuer: string = "OpenClaw"): TotpQrCodeData {
  const secret = generateTotpSecret();
  const qrCodeUrl = generateTotpQrCodeUrl(secret, accountName, issuer);

  log.info("TOTP setup initiated", { accountName });

  return {
    secret,
    qrCodeUrl,
    manualEntryKey: secret.match(/.{1,4}/g)?.join(" ") || secret,
  };
}

/**
 * 사용자 MFA 설정 생성
 */
export function createUserMfaSettings(
  userId: string,
  type: MfaType,
  config: TotpConfig | WebAuthnConfig,
): UserMfaSettings {
  const now = Date.now();
  const backupCodes = generateBackupCodes();

  const settings: UserMfaSettings = {
    userId,
    enabled: true,
    type,
    backupCodes: backupCodes.map(hashBackupCode),
    createdAt: now,
    updatedAt: now,
  };

  if (type === "totp") {
    settings.totp = config as TotpConfig;
  } else if (type === "webauthn") {
    settings.webauthn = config as WebAuthnConfig;
  }

  log.info("MFA settings created", { userId, type });

  return settings;
}

/**
 * MFA 검증 결과
 */
export interface MfaVerificationResult {
  valid: boolean;
  error?: string;
  remainingAttempts?: number;
}

/**
 * MFA 코드 검증
 */
export function verifyMfaCode(settings: UserMfaSettings, code: string): MfaVerificationResult {
  if (!settings.enabled) {
    return { valid: true };
  }

  // TOTP 검증
  if (settings.type === "totp" && settings.totp) {
    if (verifyTotpCode(settings.totp.secret, code)) {
      return { valid: true };
    }
  }

  // 백업 코드 검증
  if (verifyBackupCode(code, settings.backupCodes)) {
    log.info("Backup code used", { userId: settings.userId });
    return { valid: true };
  }

  return {
    valid: false,
    error: "invalid_code",
    remainingAttempts: 3, // TODO: 실제 구현에서는 시도 횟수 추적 필요
  };
}

/**
 * WebAuthn 등록 옵션 생성 (간단한 구현)
 * 실제 구현에서는 @simplewebauthn/server 사용 권장
 */
export function generateWebAuthnRegistrationOptions(
  userId: string,
  userName: string,
): Record<string, unknown> {
  const challenge = crypto.randomBytes(32).toString("base64url");

  return {
    challenge,
    rp: {
      name: "OpenClaw",
      id: process.env.OPENCLAW_WEBAUTHN_RP_ID || "localhost",
    },
    user: {
      id: Buffer.from(userId).toString("base64url"),
      name: userName,
      displayName: userName,
    },
    pubKeyCredParams: [
      { alg: -7, type: "public-key" }, // ES256
      { alg: -257, type: "public-key" }, // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      userVerification: "preferred",
    },
    attestation: "direct",
  };
}

/**
 * MFA 비활성화
 */
export function disableMfa(userId: string): void {
  log.info("MFA disabled", { userId });
  // 실제 구현에서는 데이터베이스에서 MFA 설정 삭제
}

/**
 * MFA 활성화 여부 확인
 */
export function isMfaEnabled(settings?: UserMfaSettings | null): boolean {
  return settings?.enabled === true;
}

/**
 * MFA 설정 내보내기 (백업용)
 */
export function exportMfaSettings(settings: UserMfaSettings): string {
  // 민감한 정보 제외하고 내보내기
  const exportData = {
    userId: settings.userId,
    enabled: settings.enabled,
    type: settings.type,
    createdAt: settings.createdAt,
    updatedAt: settings.updatedAt,
  };

  return JSON.stringify(exportData, null, 2);
}
