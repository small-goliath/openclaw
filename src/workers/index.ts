/**
 * Worker Threads 모듈
 *
 * CPU 집약적인 작업을 Worker Thread로 오프로드하여
 * 메인 스레드의 event loop blocking을 방지합니다.
 *
 * @module workers
 * @see security/security.md section 5.4
 *
 * @example
 * ```typescript
 * import { hashText, encrypt, decrypt, workerPool } from './workers/index.js';
 *
 * // 비동기 해싱
 * const hash = await hashText('data to hash');
 *
 * // 비동기 암호화
 * const encrypted = await encrypt('plaintext', key);
 *
 * // Worker Pool 직접 사용
 * const result = await workerPool.execute('hash', { data: 'test', algorithm: 'sha256' });
 * ```
 */

import type {
  WorkerPoolConfig,
  WorkerPoolStats,
  WorkerInfo,
  WorkerPoolEventListener,
  HashPayload,
  EncryptPayload,
  DecryptPayload,
  Pbkdf2Payload,
  CompressPayload,
} from "./types.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import {
  CryptoWorkerPool,
  initWorkerPool,
  getWorkerPool,
  getOrInitWorkerPool,
  shutdownWorkerPool,
} from "./worker-pool.js";

const log = createSubsystemLogger("workers");

// Re-export types
export type {
  WorkerPoolConfig,
  WorkerPoolStats,
  WorkerInfo,
  WorkerPoolEventListener,
  WorkerTaskType,
  WorkerRequest,
  WorkerResponse,
  WorkerMetrics,
} from "./types.js";

// Re-export classes and functions
export { CryptoWorkerPool, initWorkerPool, getWorkerPool, getOrInitWorkerPool, shutdownWorkerPool };

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Worker Pool 인스턴스 (lazy initialization)
 */
let workerPoolInstance: CryptoWorkerPool | null = null;

/**
 * Worker Pool 인스턴스 가져오기
 * 환경 변수 OPENCLAW_CRYPTO_WORKERS가 'disabled'인 경우 null 반환
 */
function getPool(): CryptoWorkerPool | null {
  // 환경 변수로 Worker 사용 여부 확인
  if (process.env.OPENCLAW_CRYPTO_WORKERS === "disabled") {
    return null;
  }

  if (!workerPoolInstance) {
    try {
      workerPoolInstance = getOrInitWorkerPool();
    } catch (error) {
      log.warn("Failed to initialize worker pool, falling back to main thread", {
        error: String(error),
      });
      return null;
    }
  }

  return workerPoolInstance;
}

/**
 * SHA256 해싱 수행 (Worker Thread 사용)
 *
 * @param data 해싱할 문자열
 * @param algorithm 해싱 알고리즘 (기본값: sha256)
 * @returns 해시 값 (hex 문자열)
 *
 * @example
 * ```typescript
 * const hash = await hashText('hello world');
 * console.log(hash); // 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
 * ```
 */
export async function hashText(
  data: string,
  algorithm: HashPayload["algorithm"] = "sha256",
): Promise<string> {
  const pool = getPool();

  if (!pool) {
    // Fallback to main thread
    const crypto = await import("node:crypto");
    return crypto.createHash(algorithm).update(data).digest("hex");
  }

  return pool.execute<string>("hash", { data, algorithm });
}

/**
 * 데이터 암호화 (Worker Thread 사용)
 *
 * @param plaintext 암호화할 문자열
 * @param key 암호화 키 (Buffer 또는 base64 문자열)
 * @returns 암호화 결과
 *
 * @example
 * ```typescript
 * const key = crypto.randomBytes(32);
 * const encrypted = await encrypt('secret data', key);
 * console.log(encrypted.iv);    // 초기화 벡터
 * console.log(encrypted.data);  // 암호화된 데이터
 * console.log(encrypted.tag);   // 인증 태그
 * ```
 */
export async function encrypt(
  plaintext: string,
  key: Buffer | string,
): Promise<{ iv: string; data: string; tag: string }> {
  const pool = getPool();

  const keyBase64 = Buffer.isBuffer(key) ? key.toString("base64") : key;

  if (!pool) {
    // Fallback to main thread
    const crypto = await import("node:crypto");
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv("aes-256-gcm", Buffer.from(keyBase64, "base64"), iv);

    let encrypted = cipher.update(plaintext, "utf-8");
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    const tag = cipher.getAuthTag();

    return {
      iv: iv.toString("base64"),
      data: encrypted.toString("base64"),
      tag: tag.toString("base64"),
    };
  }

  return pool.execute<{ iv: string; data: string; tag: string }>("encrypt", {
    plaintext,
    key: keyBase64,
  });
}

/**
 * 데이터 복호화 (Worker Thread 사용)
 *
 * @param ciphertext 암호화된 데이터 (base64)
 * @param key 복호화 키 (Buffer 또는 base64 문자열)
 * @param iv 초기화 벡터 (base64)
 * @param tag 인증 태그 (base64)
 * @returns 복호화된 문자열
 *
 * @example
 * ```typescript
 * const decrypted = await decrypt(encrypted.data, key, encrypted.iv, encrypted.tag);
 * console.log(decrypted); // 'secret data'
 * ```
 */
export async function decrypt(
  ciphertext: string,
  key: Buffer | string,
  iv: string,
  tag: string,
): Promise<string> {
  const pool = getPool();

  const keyBase64 = Buffer.isBuffer(key) ? key.toString("base64") : key;

  if (!pool) {
    // Fallback to main thread
    const crypto = await import("node:crypto");
    const decipher = crypto.createDecipheriv(
      "aes-256-gcm",
      Buffer.from(keyBase64, "base64"),
      Buffer.from(iv, "base64"),
    );
    decipher.setAuthTag(Buffer.from(tag, "base64"));

    let decrypted = decipher.update(Buffer.from(ciphertext, "base64"));
    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString("utf-8");
  }

  return pool.execute<string>("decrypt", {
    ciphertext,
    key: keyBase64,
    iv,
    tag,
  });
}

/**
 * PBKDF2 키 파생 (Worker Thread 사용)
 *
 * @param password 비밀번호
 * @param salt 솔트
 * @param iterations 반복 횟수
 * @param keyLength 키 길이 (bytes)
 * @param digest 다이제스트 알고리즘
 * @returns 파생된 키 (base64)
 *
 * @example
 * ```typescript
 * const key = await pbkdf2('password', 'salt', 100000, 32);
 * ```
 */
export async function pbkdf2(
  password: string,
  salt: string,
  iterations: number,
  keyLength: number,
  digest: Pbkdf2Payload["digest"] = "sha256",
): Promise<string> {
  const pool = getPool();

  if (!pool) {
    // Fallback to main thread
    const crypto = await import("node:crypto");
    const { promisify } = await import("node:util");
    const pbkdf2Async = promisify(crypto.pbkdf2);
    const key = await pbkdf2Async(password, salt, iterations, keyLength, digest);
    return key.toString("base64");
  }

  return pool.execute<string>("pbkdf2", {
    password,
    salt,
    iterations,
    keyLength,
    digest,
  });
}

/**
 * 데이터 압축 (Worker Thread 사용)
 *
 * @param data 압축할 문자열
 * @param level 압축 레벨 (0-9, 기본값: 6)
 * @returns 압축된 데이터 (base64)
 *
 * @example
 * ```typescript
 * const compressed = await compress('large data...', 9);
 * ```
 */
export async function compress(data: string, level: number = 6): Promise<string> {
  const pool = getPool();

  if (!pool) {
    // Fallback to main thread
    const { createGzip, constants } = await import("node:zlib");
    const { pipeline } = await import("node:stream/promises");
    const { Readable } = await import("node:stream");

    const chunks: Buffer[] = [];
    const gzip = createGzip({ level });

    gzip.on("data", (chunk: Buffer) => chunks.push(chunk));

    const source = Readable.from([data]);
    await pipeline(source, gzip);

    return Buffer.concat(chunks).toString("base64");
  }

  return pool.execute<string>("compress", { data, level });
}

/**
 * 데이터 압축 해제 (Worker Thread 사용)
 *
 * @param data 압축된 데이터 (base64)
 * @returns 원본 문자열
 *
 * @example
 * ```typescript
 * const original = await decompress(compressed);
 * ```
 */
export async function decompress(data: string): Promise<string> {
  const pool = getPool();

  if (!pool) {
    // Fallback to main thread
    const { createGunzip } = await import("node:zlib");
    const { pipeline } = await import("node:stream/promises");
    const { Readable } = await import("node:stream");

    const chunks: Buffer[] = [];
    const gunzip = createGunzip();

    gunzip.on("data", (chunk: Buffer) => chunks.push(chunk));

    const source = Readable.from([Buffer.from(data, "base64")]);
    await pipeline(source, gunzip);

    return Buffer.concat(chunks).toString("utf-8");
  }

  return pool.execute<string>("decompress", { data });
}

/**
 * Worker Pool 통계 정보 가져오기
 */
export function getWorkerPoolStats(): WorkerPoolStats | null {
  const pool = getPool();
  return pool?.getStats() ?? null;
}

/**
 * Worker 정보 가져오기
 */
export function getWorkerInfo(): WorkerInfo[] {
  const pool = getPool();
  return pool?.getWorkers() ?? [];
}

/**
 * Worker Pool 이벤트 리스너 등록
 */
export function onWorkerPoolEvent(listener: WorkerPoolEventListener): () => void {
  const pool = getPool();
  return pool?.onEvent(listener) ?? (() => {});
}

/**
 * Worker Pool이 활성화되어 있는지 확인
 */
export function isWorkerPoolEnabled(): boolean {
  return getPool() !== null;
}

// ============================================================================
// Graceful Shutdown
// ============================================================================

/**
 * 애플리케이션 종료 시 Worker Pool 정리
 */
process.on("beforeExit", async () => {
  if (workerPoolInstance) {
    log.info("Shutting down worker pool on process exit");
    await workerPoolInstance.shutdown();
    workerPoolInstance = null;
  }
});

process.on("SIGINT", async () => {
  if (workerPoolInstance) {
    log.info("Shutting down worker pool on SIGINT");
    await workerPoolInstance.shutdown(5000);
    workerPoolInstance = null;
  }
  process.exit(0);
});

process.on("SIGTERM", async () => {
  if (workerPoolInstance) {
    log.info("Shutting down worker pool on SIGTERM");
    await workerPoolInstance.shutdown(5000);
    workerPoolInstance = null;
  }
  process.exit(0);
});
