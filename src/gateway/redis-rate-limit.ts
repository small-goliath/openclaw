/**
 * Redis 기반 분산 Rate Limiter
 * 다중 인스턴스 환경에서 공유되는 Rate Limiting 지원
 */

import type { AuthRateLimiter, RateLimitCheckResult, RateLimitConfig } from "./auth-rate-limit.js";

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
      // Redis 오류 시 허용 (fail-open) 또는 차단 (fail-close) 정책 선택 가능
      // 여기서는 fail-open으로 설정
      console.error("Redis rate limit check failed:", err);
      return { allowed: true, remaining: this.config.maxAttempts, retryAfterMs: 0 };
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
      console.error("Redis rate limit record failure failed:", err);
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
