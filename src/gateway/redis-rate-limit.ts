/**
 * Redis 기반 분산 Rate Limiter
 * 다중 인스턴스 환경에서 공유되는 Rate Limiting 지원
 */

import type { AuthRateLimiter, RateLimitCheckResult, RateLimitConfig } from "./auth-rate-limit.js";

// Web Crypto API for IP hashing (Node.js 20+ compatible)
const crypto = globalThis.crypto;

// Redis 클라이언트 타입 (동적 import용)
type RedisClient = {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, options?: { ex?: number }): Promise<string | null>;
  del(key: string): Promise<number>;
  multi(): RedisMulti;
  eval(script: string, keys: string[], args: string[]): Promise<unknown>;
};

type RedisMulti = {
  get(key: string): RedisMulti;
  set(key: string, value: string, options?: { ex?: number }): RedisMulti;
  exec(): Promise<unknown[]>;
};

// 슬라이딩 윈도우 Lua 스크립트
// KEYS[1]: rate limit key
// ARGV[1]: window size in milliseconds
// ARGV[2]: max attempts
// ARGV[3]: current timestamp in milliseconds
const SLIDING_WINDOW_SCRIPT = `
  local key = KEYS[1]
  local window = tonumber(ARGV[1])
  local maxAttempts = tonumber(ARGV[2])
  local now = tonumber(ARGV[3])
  local cutoff = now - window

  -- 현재 시도 기록
  redis.call('ZADD', key, now, now .. ':' .. math.random())

  -- 오래된 기록 제거 (슬라이딩 윈도우)
  redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)

  -- 현재 윈도우 내 시도 횟수
  local count = redis.call('ZCARD', key)

  -- TTL 설정 (윈도우 크기만큼)
  redis.call('EXPIRE', key, math.ceil(window / 1000))

  return count
`;

// 잠금 상태 확인 Lua 스크립트
// KEYS[1]: lockout key
// ARGV[1]: current timestamp
const CHECK_LOCKOUT_SCRIPT = `
  local key = KEYS[1]
  local now = tonumber(ARGV[1])
  local lockedUntil = redis.call('GET', key)

  if lockedUntil then
    lockedUntil = tonumber(lockedUntil)
    if now < lockedUntil then
      return lockedUntil - now
    else
      redis.call('DEL', key)
      return 0
    end
  end

  return 0
`;

export interface RedisRateLimiterConfig extends RateLimitConfig {
  /** Redis 연결 URL */
  redisUrl: string;
  /** Redis 키 접두사 (기본값: openclaw:ratelimit) */
  keyPrefix?: string;
}

/**
 * Redis 기반 Rate Limiter
 * 분산 환경에서도 일관된 Rate Limiting 제공
 */
export class RedisRateLimiter implements AuthRateLimiter {
  private redis: RedisClient;
  private config: Required<RateLimitConfig>;
  private keyPrefix: string;
  private failCloseCount: number = 0;
  private lastFailureTime: number | null = null;
  private isRedisHealthy: boolean = true;

  constructor(redis: RedisClient, config: RedisRateLimiterConfig) {
    this.redis = redis;
    this.config = {
      maxAttempts: config.maxAttempts ?? 10,
      windowMs: config.windowMs ?? 60000,
      lockoutMs: config.lockoutMs ?? 300000,
      exemptLoopback: config.exemptLoopback ?? true,
    };
    this.keyPrefix = config.keyPrefix ?? "openclaw:ratelimit";
  }

  /**
   * Rate limit 상태 확인
   */
  async check(ip: string | undefined, scope?: string): Promise<RateLimitCheckResult> {
    const { key, ip: normalizedIp } = this.resolveKey(ip, scope);

    // Loopback 예외 처리
    if (this.config.exemptLoopback && this.isLoopback(normalizedIp)) {
      return { allowed: true, remaining: this.config.maxAttempts, retryAfterMs: 0 };
    }

    const now = Date.now();

    try {
      // 잠금 상태 확인
      const lockoutKey = `${key}:lockout`;
      const lockoutResult = (await this.redis.eval(
        CHECK_LOCKOUT_SCRIPT,
        [lockoutKey],
        [now.toString()],
      )) as number;

      if (lockoutResult > 0) {
        return {
          allowed: false,
          remaining: 0,
          retryAfterMs: lockoutResult,
        };
      }

      // 현재 시도 횟수 확인
      const count = await this.getAttemptCount(key);
      const remaining = Math.max(0, this.config.maxAttempts - count);

      return {
        allowed: remaining > 0,
        remaining,
        retryAfterMs: 0,
      };
    } catch (err) {
      // Redis 오류 시 차단 (fail-close) 정책 - DoS 공격 방어
      // CRIT-003: Redis 장애 시에도 rate limiting이 무효화되지 않도록 함
      const errorType = this.classifyRedisError(err);
      const timestamp = new Date().toISOString();
      const clientIpHash = ip ? await this.hashIpForLogging(ip) : "unknown";

      console.error(`[${timestamp}] Redis rate limit check failed (${errorType}):`, err);
      console.error(`  Scope: ${scope ?? "default"}, IP Hash: ${clientIpHash}`);

      // 메트릭 업데이트
      this.failCloseCount++;
      this.lastFailureTime = Date.now();
      this.isRedisHealthy = false;

      // Fail-close: Redis 장애 시 요청 차단
      return {
        allowed: false,
        remaining: 0,
        retryAfterMs: this.config.lockoutMs,
      };
    }
  }

  /**
   * 실패 기록
   */
  async recordFailure(ip: string | undefined, scope?: string): Promise<void> {
    const { key, ip: normalizedIp } = this.resolveKey(ip, scope);

    // Loopback 예외 처리
    if (this.config.exemptLoopback && this.isLoopback(normalizedIp)) {
      return;
    }

    const now = Date.now();

    try {
      // 슬라이딩 윈도우로 시도 기록
      const count = (await this.redis.eval(
        SLIDING_WINDOW_SCRIPT,
        [key],
        [this.config.windowMs.toString(), this.config.maxAttempts.toString(), now.toString()],
      )) as number;

      // 최대 시도 횟수 초과 시 잠금
      if (count >= this.config.maxAttempts) {
        const lockoutKey = `${key}:lockout`;
        const lockoutUntil = now + this.config.lockoutMs;
        await this.redis.set(lockoutKey, lockoutUntil.toString(), {
          ex: Math.ceil(this.config.lockoutMs / 1000),
        });
      }
    } catch (err) {
      const errorType = this.classifyRedisError(err);
      const timestamp = new Date().toISOString();
      const clientIpHash = ip ? await this.hashIpForLogging(ip) : "unknown";

      console.error(`[${timestamp}] Redis rate limit record failure failed (${errorType}):`, err);
      console.error(`  Scope: ${scope ?? "default"}, IP Hash: ${clientIpHash}`);

      // 메트릭 업데이트
      this.isRedisHealthy = false;
    }
  }

  /**
   * Rate limit 상태 초기화
   */
  async reset(ip: string | undefined, scope?: string): Promise<void> {
    const { key } = this.resolveKey(ip, scope);

    try {
      await this.redis.del(key);
      await this.redis.del(`${key}:lockout`);
    } catch (err) {
      console.error("Redis rate limit reset failed:", err);
    }
  }

  /**
   * 현재 추적 중인 IP 수 (Redis에서는 정확한 카운트 불가)
   */
  size(): number {
    // Redis에서는 전체 키 카운트가 불가능하므로 0 반환
    return 0;
  }

  /**
   * 오래된 항목 정리 (Redis에서는 TTL로 자동 관리)
   */
  prune(): void {
    // Redis TTL로 자동 관리됨
  }

  /**
   * Redis 에러 분류
   */
  private classifyRedisError(err: unknown): string {
    if (err instanceof Error) {
      const message = err.message.toLowerCase();
      if (message.includes("econnrefused") || message.includes("connect")) {
        return "RedisConnectionError";
      }
      if (message.includes("timeout") || message.includes("etimedout")) {
        return "RedisTimeoutError";
      }
      if (message.includes("auth") || message.includes("noauth")) {
        return "RedisAuthError";
      }
      if (message.includes("oom") || message.includes("memory")) {
        return "RedisMemoryError";
      }
      return "RedisError";
    }
    return "UnknownError";
  }

  /**
   * 로깅용 IP 해시 (개인정보 보호)
   */
  private async hashIpForLogging(ip: string): Promise<string> {
    try {
      const data = new TextEncoder().encode(ip);
      const hashBuffer = await crypto.subtle.digest("SHA-256", data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      // 처음 16바이트만 사용하여 반환
      return hashArray
        .slice(0, 16)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
    } catch {
      return "hash-error";
    }
  }

  /**
   * 메트릭 조회 (모니터링용)
   */
  getMetrics(): {
    failCloseCount: number;
    lastFailureTime: number | null;
    isRedisHealthy: boolean;
    config: RateLimitConfig;
  } {
    return {
      failCloseCount: this.failCloseCount,
      lastFailureTime: this.lastFailureTime,
      isRedisHealthy: this.isRedisHealthy,
      config: { ...this.config },
    };
  }

  /**
   * Redis 상태 업데이트 (복구 시 호출)
   */
  markRedisHealthy(): void {
    this.isRedisHealthy = true;
  }

  /**
   * 리소스 해제
   */
  dispose(): void {
    // 외부에서 Redis 연결 관리
  }

  /**
   * 현재 시도 횟수 조회
   */
  private async getAttemptCount(key: string): Promise<number> {
    try {
      // ZCARD로 현재 윈도우 내 시도 횟수 조회
      const script = `
        local key = KEYS[1]
        local window = tonumber(ARGV[1])
        local now = tonumber(ARGV[2])
        local cutoff = now - window

        redis.call('ZREMRANGEBYSCORE', key, 0, cutoff)
        return redis.call('ZCARD', key)
      `;

      const count = (await this.redis.eval(
        script,
        [key],
        [this.config.windowMs.toString(), Date.now().toString()],
      )) as number;

      return count ?? 0;
    } catch {
      return 0;
    }
  }

  /**
   * 키 생성
   */
  private resolveKey(
    rawIp: string | undefined,
    rawScope: string | undefined,
  ): { key: string; ip: string } {
    const ip = (rawIp ?? "").trim() || "unknown";
    const scope = (rawScope ?? "default").trim() || "default";
    return { key: `${this.keyPrefix}:${scope}:${ip}`, ip };
  }

  /**
   * Loopback 주소 확인
   */
  private isLoopback(ip: string): boolean {
    return ip === "127.0.0.1" || ip === "::1" || ip === "localhost";
  }
}

/**
 * Redis Rate Limiter 팩토리 함수
 */
export async function createRedisRateLimiter(
  config: RedisRateLimiterConfig,
): Promise<RedisRateLimiter> {
  const { Redis } = await import("ioredis");
  const redis = new Redis(config.redisUrl);
  return new RedisRateLimiter(redis, config);
}
