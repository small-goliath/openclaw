/**
 * Crypto Worker 테스트
 *
 * @module workers/crypto-worker.test
 */

import path from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import { describe, it, expect } from "vitest";
import type { WorkerRequest, WorkerResponse } from "./types.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

describe("CryptoWorker", () => {
  const createWorker = (): Promise<Worker> => {
    return new Promise((resolve, reject) => {
      const worker = new Worker(path.join(__dirname, "crypto-worker.ts"), {
        execArgv: ["--import", "tsx/esm"],
      });

      worker.on("message", (msg) => {
        if (msg.type === "ready") {
          resolve(worker);
        }
      });

      worker.on("error", reject);
      worker.on("exit", (code) => {
        if (code !== 0) {
          reject(new Error(`Worker exited with code ${code}`));
        }
      });
    });
  };

  const sendRequest = <T>(worker: Worker, request: WorkerRequest): Promise<T> => {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        reject(new Error("Worker request timeout"));
      }, 10000);

      const handler = (response: WorkerResponse) => {
        if (response.id === request.id) {
          clearTimeout(timeout);
          worker.off("message", handler);

          if (response.success) {
            resolve(response.result as T);
          } else {
            reject(new Error(response.error || "Unknown error"));
          }
        }
      };

      worker.on("message", handler);
      worker.postMessage(request);
    });
  };

  describe("Hash Operations", () => {
    it("should compute SHA256 hash", async () => {
      const worker = await createWorker();

      try {
        const result = await sendRequest<string>(worker, {
          id: "test-hash-1",
          type: "hash",
          payload: {
            data: "hello world",
            algorithm: "sha256",
          },
          timestamp: Date.now(),
        });

        expect(result).toBe("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
      } finally {
        await worker.terminate();
      }
    });

    it("should compute SHA512 hash", async () => {
      const worker = await createWorker();

      try {
        const result = await sendRequest<string>(worker, {
          id: "test-hash-2",
          type: "hash",
          payload: {
            data: "hello world",
            algorithm: "sha512",
          },
          timestamp: Date.now(),
        });

        expect(result).toHaveLength(128);
      } finally {
        await worker.terminate();
      }
    });

    it("should handle empty string", async () => {
      const worker = await createWorker();

      try {
        const result = await sendRequest<string>(worker, {
          id: "test-hash-3",
          type: "hash",
          payload: {
            data: "",
            algorithm: "sha256",
          },
          timestamp: Date.now(),
        });

        expect(result).toHaveLength(64);
      } finally {
        await worker.terminate();
      }
    });
  });

  describe("Encryption/Decryption", () => {
    const testKey = Buffer.from(
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "hex",
    );

    it("should encrypt and decrypt data", async () => {
      const worker = await createWorker();

      try {
        const plaintext = "secret message";

        const encrypted = await sendRequest<{
          iv: string;
          data: string;
          tag: string;
        }>(worker, {
          id: "test-encrypt-1",
          type: "encrypt",
          payload: {
            plaintext,
            key: testKey.toString("base64"),
          },
          timestamp: Date.now(),
        });

        expect(encrypted).toHaveProperty("iv");
        expect(encrypted).toHaveProperty("data");
        expect(encrypted).toHaveProperty("tag");

        const decrypted = await sendRequest<string>(worker, {
          id: "test-decrypt-1",
          type: "decrypt",
          payload: {
            ciphertext: encrypted.data,
            key: testKey.toString("base64"),
            iv: encrypted.iv,
            tag: encrypted.tag,
          },
          timestamp: Date.now(),
        });

        expect(decrypted).toBe(plaintext);
      } finally {
        await worker.terminate();
      }
    });

    it("should fail to decrypt with wrong key", async () => {
      const worker = await createWorker();

      try {
        const plaintext = "secret message";

        const encrypted = await sendRequest<{
          iv: string;
          data: string;
          tag: string;
        }>(worker, {
          id: "test-encrypt-2",
          type: "encrypt",
          payload: {
            plaintext,
            key: testKey.toString("base64"),
          },
          timestamp: Date.now(),
        });

        const wrongKey = Buffer.from(
          "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
          "hex",
        );

        await expect(
          sendRequest<string>(worker, {
            id: "test-decrypt-2",
            type: "decrypt",
            payload: {
              ciphertext: encrypted.data,
              key: wrongKey.toString("base64"),
              iv: encrypted.iv,
              tag: encrypted.tag,
            },
            timestamp: Date.now(),
          }),
        ).rejects.toThrow();
      } finally {
        await worker.terminate();
      }
    });

    it("should fail with invalid key length", async () => {
      const worker = await createWorker();

      try {
        await expect(
          sendRequest<never>(worker, {
            id: "test-encrypt-3",
            type: "encrypt",
            payload: {
              plaintext: "test",
              key: "short-key",
            },
            timestamp: Date.now(),
          }),
        ).rejects.toThrow("Invalid key length");
      } finally {
        await worker.terminate();
      }
    });
  });

  describe("PBKDF2", () => {
    it("should derive key with PBKDF2", async () => {
      const worker = await createWorker();

      try {
        const result = await sendRequest<string>(worker, {
          id: "test-pbkdf2-1",
          type: "pbkdf2",
          payload: {
            password: "password",
            salt: "salt",
            iterations: 1000,
            keyLength: 32,
            digest: "sha256",
          },
          timestamp: Date.now(),
        });

        expect(result).toBeTruthy();
        expect(Buffer.from(result, "base64")).toHaveLength(32);
      } finally {
        await worker.terminate();
      }
    });
  });

  describe("Compression", () => {
    it("should compress and decompress data", async () => {
      const worker = await createWorker();

      try {
        const data = "a".repeat(1000);

        const compressed = await sendRequest<string>(worker, {
          id: "test-compress-1",
          type: "compress",
          payload: {
            data,
            level: 6,
          },
          timestamp: Date.now(),
        });

        expect(compressed.length).toBeLessThan(Buffer.byteLength(data) * 2);

        const decompressed = await sendRequest<string>(worker, {
          id: "test-decompress-1",
          type: "decompress",
          payload: {
            data: compressed,
          },
          timestamp: Date.now(),
        });

        expect(decompressed).toBe(data);
      } finally {
        await worker.terminate();
      }
    });
  });

  describe("Error Handling", () => {
    it("should handle unknown task type", async () => {
      const worker = await createWorker();

      try {
        await expect(
          sendRequest<never>(worker, {
            id: "test-error-1",
            type: "unknown" as never,
            payload: {},
            timestamp: Date.now(),
          }),
        ).rejects.toThrow("Unknown task type");
      } finally {
        await worker.terminate();
      }
    });

    it("should include metrics in response", async () => {
      const worker = await createWorker();

      try {
        const response = await new Promise<WorkerResponse>((resolve, reject) => {
          const timeout = setTimeout(() => {
            reject(new Error("Timeout"));
          }, 5000);

          const handler = (msg: WorkerResponse) => {
            if (msg.id === "test-metrics-1") {
              clearTimeout(timeout);
              worker.off("message", handler);
              resolve(msg);
            }
          };

          worker.on("message", handler);
          worker.postMessage({
            id: "test-metrics-1",
            type: "hash",
            payload: {
              data: "test",
              algorithm: "sha256",
            },
            timestamp: Date.now(),
          });
        });

        expect(response.metrics).toBeDefined();
        expect(response.metrics?.durationMs).toBeGreaterThanOrEqual(0);
      } finally {
        await worker.terminate();
      }
    });
  });
});
