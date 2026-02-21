/**
 * Crypto Worker Thread
 *
 * CPU 집약적인 암호화 작업을 처리하는 Worker Thread
 * 메인 스레드의 event loop blocking을 방지하기 위해 사용
 *
 * @module workers/crypto-worker
 * @see security/security.md section 5.4
 */

import crypto from "node:crypto";
import { promisify } from "node:util";
import { parentPort } from "node:worker_threads";
import { createGzip, createGunzip, constants } from "node:zlib";
import type {
  WorkerRequest,
  WorkerResponse,
  HashPayload,
  EncryptPayload,
  DecryptPayload,
  Pbkdf2Payload,
  CompressPayload,
} from "./types.js";

// ============================================================================
// Constants
// ============================================================================

const ALGORITHM = "aes-256-gcm";
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const TAG_LENGTH = 16;

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate UUID v4 for request tracking
 */
function generateId(): string {
  return crypto.randomUUID();
}

/**
 * Base64 encode buffer
 */
function base64Encode(buffer: Buffer): string {
  return buffer.toString("base64");
}

/**
 * Base64 decode string
 */
function base64Decode(str: string): Buffer {
  return Buffer.from(str, "base64");
}

// ============================================================================
// Crypto Operations
// ============================================================================

/**
 * SHA256 해싱 수행
 */
function performHash(payload: HashPayload): string {
  const { data, algorithm = "sha256" } = payload;
  return crypto.createHash(algorithm).update(data).digest("hex");
}

/**
 * AES-256-GCM 암호화 수행
 */
function performEncrypt(payload: EncryptPayload): {
  iv: string;
  data: string;
  tag: string;
} {
  const { plaintext, key, iv: providedIv } = payload;

  const keyBuffer = base64Decode(key);
  if (keyBuffer.length !== KEY_LENGTH) {
    throw new Error(`Invalid key length: expected ${KEY_LENGTH}, got ${keyBuffer.length}`);
  }

  const iv = providedIv ? base64Decode(providedIv) : crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, keyBuffer, iv);

  let encrypted = cipher.update(plaintext, "utf-8");
  encrypted = Buffer.concat([encrypted, cipher.final()]);

  const tag = cipher.getAuthTag();

  return {
    iv: base64Encode(iv),
    data: base64Encode(encrypted),
    tag: base64Encode(tag),
  };
}

/**
 * AES-256-GCM 복호화 수행
 */
function performDecrypt(payload: DecryptPayload): string {
  const { ciphertext, key, iv, tag } = payload;

  const keyBuffer = base64Decode(key);
  const ivBuffer = base64Decode(iv);
  const encryptedBuffer = base64Decode(ciphertext);
  const tagBuffer = base64Decode(tag);

  if (keyBuffer.length !== KEY_LENGTH) {
    throw new Error(`Invalid key length: expected ${KEY_LENGTH}, got ${keyBuffer.length}`);
  }

  const decipher = crypto.createDecipheriv(ALGORITHM, keyBuffer, ivBuffer);
  decipher.setAuthTag(tagBuffer);

  let decrypted = decipher.update(encryptedBuffer);
  decrypted = Buffer.concat([decrypted, decipher.final()]);

  return decrypted.toString("utf-8");
}

/**
 * PBKDF2 키 파생 수행
 */
async function performPbkdf2(payload: Pbkdf2Payload): Promise<string> {
  const { password, salt, iterations, keyLength, digest = "sha256" } = payload;

  const pbkdf2Async = promisify(crypto.pbkdf2);
  const derivedKey = await pbkdf2Async(password, salt, iterations, keyLength, digest);

  return base64Encode(derivedKey);
}

/**
 * 데이터 압축 수행
 */
async function performCompress(payload: CompressPayload): Promise<string> {
  const { data, level = 6 } = payload;

  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const gzip = createGzip({ level });

    gzip.on("data", (chunk: Buffer) => chunks.push(chunk));
    gzip.on("end", () => {
      const result = Buffer.concat(chunks);
      resolve(base64Encode(result));
    });
    gzip.on("error", reject);

    gzip.end(data);
  });
}

/**
 * 데이터 압축 해제 수행
 */
async function performDecompress(payload: { data: string }): Promise<string> {
  const { data } = payload;

  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    const gunzip = createGunzip();

    gunzip.on("data", (chunk: Buffer) => chunks.push(chunk));
    gunzip.on("end", () => {
      const result = Buffer.concat(chunks);
      resolve(result.toString("utf-8"));
    });
    gunzip.on("error", reject);

    gunzip.end(base64Decode(data));
  });
}

// ============================================================================
// Request Handler
// ============================================================================

/**
 * 작업 요청 처리
 */
async function handleRequest(request: WorkerRequest): Promise<WorkerResponse> {
  const startTime = performance.now();
  const startMemory = process.memoryUsage().heapUsed;

  try {
    let result: unknown;

    switch (request.type) {
      case "hash":
        result = performHash(request.payload as HashPayload);
        break;

      case "encrypt":
        result = performEncrypt(request.payload as EncryptPayload);
        break;

      case "decrypt":
        result = performDecrypt(request.payload as DecryptPayload);
        break;

      case "pbkdf2":
        result = await performPbkdf2(request.payload as Pbkdf2Payload);
        break;

      case "compress":
        result = await performCompress(request.payload as CompressPayload);
        break;

      case "decompress":
        result = await performDecompress(request.payload as { data: string });
        break;

      default:
        throw new Error(`Unknown task type: ${request.type}`);
    }

    const endTime = performance.now();
    const endMemory = process.memoryUsage().heapUsed;

    return {
      id: request.id,
      success: true,
      result,
      metrics: {
        durationMs: Math.round(endTime - startTime),
        memoryBytes: Math.max(0, endMemory - startMemory),
      },
      timestamp: Date.now(),
    };
  } catch (error) {
    const endTime = performance.now();

    return {
      id: request.id,
      success: false,
      error: error instanceof Error ? error.message : String(error),
      metrics: {
        durationMs: Math.round(endTime - startTime),
      },
      timestamp: Date.now(),
    };
  }
}

// ============================================================================
// Worker Entry Point
// ============================================================================

if (!parentPort) {
  throw new Error("This module must be run as a worker thread");
}

// Worker ready signal
parentPort.postMessage({ type: "ready", timestamp: Date.now() });

// Handle incoming messages
parentPort.on("message", async (request: WorkerRequest) => {
  const response = await handleRequest(request);
  parentPort!.postMessage(response);
});

// Handle errors
process.on("uncaughtException", (error) => {
  console.error("[CryptoWorker] Uncaught exception:", error);
  process.exit(1);
});

process.on("unhandledRejection", (reason) => {
  console.error("[CryptoWorker] Unhandled rejection:", reason);
  process.exit(1);
});
