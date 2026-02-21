/**
 * GDPR 데이터 수출 및 삭제 기능 테스트
 * COMP-003, COMP-004 요구사항 검증
 */

import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  exportUserData,
  exportPortableData,
  deleteUserData,
  calculateExportSize,
  saveExportToFile,
  type DataExportOptions,
  type DataDeletionOptions,
} from "./data-export.js";

// 모듈 모킹
vi.mock("../config/config.js", () => ({
  loadConfig: vi.fn(),
  resolveConfigPath: vi.fn((p: string) => p),
}));

vi.mock("../config/sessions/store.js", () => ({
  loadSessionStore: vi.fn(),
  saveSessionStore: vi.fn(),
}));

vi.mock("../config/sessions/paths.js", () => ({
  getSessionStorePath: vi.fn(() => "/tmp/test-sessions.json"),
}));

vi.mock("../logging/subsystem.js", () => ({
  createSubsystemLogger: vi.fn(() => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  })),
}));

import { loadConfig } from "../config/config.js";
import { loadSessionStore } from "../config/sessions/store.js";

describe("GDPR Data Export", () => {
  let tempDir: string;
  const mockLoadConfig = vi.mocked(loadConfig);
  const mockLoadSessionStore = vi.mocked(loadSessionStore);

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), "gdpr-test-"));

    // 기본 설정 모킹
    mockLoadConfig.mockReturnValue({
      memory: { basePath: path.join(tempDir, "memory") },
      session: { transcriptDir: path.join(tempDir, "transcripts") },
      logging: { auditLogPath: path.join(tempDir, "logs", "audit.jsonl") },
      gateway: {},
      providers: {},
    } as unknown as ReturnType<typeof loadConfig>);

    // 기본 세션 스토어 모킹
    mockLoadSessionStore.mockReturnValue({
      "session-1": {
        channel: "test",
        updatedAt: Date.now(),
      },
      "session-2": {
        channel: "test",
        updatedAt: Date.now() - 86400000, // 1일 전
      },
    });
  });

  afterEach(async () => {
    await fs.rm(tempDir, { recursive: true, force: true });
    vi.clearAllMocks();
  });

  describe("exportUserData", () => {
    it("should export all user data categories", async () => {
      const userId = "test-user";
      const exportData = await exportUserData(userId);

      expect(exportData).toHaveProperty("exportedAt");
      expect(exportData).toHaveProperty("version");
      expect(exportData.sessions).toBeDefined();
      expect(exportData.credentials).toBeDefined();
      expect(exportData.config).toBeDefined();
    });

    it("should filter by session key", async () => {
      const userId = "test-user";
      const opts: DataExportOptions = { sessionKey: "session-1" };

      const exportData = await exportUserData(userId, opts);

      expect(exportData.sessions).toBeDefined();
      expect(Object.keys(exportData.sessions!)).toHaveLength(1);
      expect(exportData.sessions).toHaveProperty("session-1");
    });

    it("should filter by date range", async () => {
      const userId = "test-user";
      const now = Date.now();
      const opts: DataExportOptions = {
        startDate: new Date(now - 3600000), // 1시간 전
        endDate: new Date(now + 3600000), // 1시간 후
      };

      mockLoadSessionStore.mockReturnValue({
        "old-session": {
          channel: "test",
          updatedAt: now - 86400000 * 2, // 2일 전
        },
        "new-session": {
          channel: "test",
          updatedAt: now,
        },
      });

      const exportData = await exportUserData(userId, opts);

      expect(exportData.sessions).toBeDefined();
      expect(Object.keys(exportData.sessions!)).toHaveLength(1);
      expect(exportData.sessions).toHaveProperty("new-session");
    });

    it("should filter by categories", async () => {
      const userId = "test-user";
      const opts: DataExportOptions = {
        categories: ["sessions"],
      };

      const exportData = await exportUserData(userId, opts);

      expect(exportData.sessions).toBeDefined();
      expect(exportData.memories).toBeUndefined();
      expect(exportData.credentials).toBeUndefined();
    });

    it("should mask sensitive credential data", async () => {
      mockLoadConfig.mockReturnValue({
        providers: {
          openai: {
            apiKey: "sk-test1234567890abcdef",
          },
        },
        gateway: { password: "secret123" },
      } as unknown as ReturnType<typeof loadConfig>);

      const userId = "test-user";
      const exportData = await exportUserData(userId, {
        categories: ["credentials"],
      });

      expect(exportData.credentials).toBeDefined();
      expect(exportData.credentials!.apiKeys).toHaveLength(1);
      expect(exportData.credentials!.apiKeys[0].maskedValue).toBe("sk-t...cdef");
      expect(exportData.credentials!.hasPasswordAuth).toBe(true);
    });
  });

  describe("exportPortableData", () => {
    it("should export data in portable format", async () => {
      const userId = "test-user";
      const portableData = await exportPortableData(userId);

      expect(portableData).toHaveProperty("data_controller", "OpenClaw");
      expect(portableData).toHaveProperty("export_format", "JSON");
      expect(portableData).toHaveProperty("data_subject");
      expect(portableData.data_subject).toHaveProperty("user_id", userId);
      expect(portableData).toHaveProperty("personal_data");
    });

    it("should include standardized fields", async () => {
      const userId = "test-user";
      const portableData = await exportPortableData(userId);

      expect(portableData).toHaveProperty("export_version");
      expect(portableData).toHaveProperty("exported_at");
      expect(portableData.personal_data).toHaveProperty("sessions");
      expect(portableData.personal_data).toHaveProperty("memories");
      expect(portableData.personal_data).toHaveProperty("credentials");
    });
  });

  describe("deleteUserData", () => {
    it("should delete user data by categories", async () => {
      const userId = "test-user";
      const opts: DataDeletionOptions = {
        categories: ["sessions"],
      };

      const result = await deleteUserData(userId, opts);

      expect(result.success).toBe(true);
      expect(result.deletedCategories).toContain("sessions");
      expect(result.deletedCount).toBeGreaterThan(0);
    });

    it("should handle partial deletion failures", async () => {
      const userId = "test-user";
      const opts: DataDeletionOptions = {
        categories: ["sessions", "memories"],
      };

      const result = await deleteUserData(userId, opts);

      // 메모리 디렉토리가 없으므로 실패할 수 있음
      expect(result.deletedCategories.length + result.failedCategories.length).toBe(2);
    });

    it("should filter by session key", async () => {
      const userId = "test-user";
      const opts: DataDeletionOptions = {
        categories: ["sessions"],
        sessionKey: "session-1",
      };

      const result = await deleteUserData(userId, opts);

      expect(result.success).toBe(true);
      expect(result.deletedCount).toBe(1);
    });

    it("should support permanent deletion flag", async () => {
      const userId = "test-user";
      const opts: DataDeletionOptions = {
        categories: ["sessions"],
        permanent: true,
      };

      const result = await deleteUserData(userId, opts);

      expect(result.success).toBe(true);
    });
  });

  describe("calculateExportSize", () => {
    it("should calculate export size correctly", () => {
      const exportData = {
        exportedAt: new Date().toISOString(),
        version: "1.0.0",
        sessions: { test: { channel: "test" } },
      };

      const size = calculateExportSize(
        exportData as unknown as Parameters<typeof calculateExportSize>[0],
      );

      expect(size).toBeGreaterThan(0);
      expect(size).toBe(JSON.stringify(exportData).length);
    });
  });

  describe("saveExportToFile", () => {
    it("should save export to file", async () => {
      const exportData = {
        exportedAt: new Date().toISOString(),
        version: "1.0.0",
        sessions: {},
      };

      const outputPath = path.join(tempDir, "export.json");
      await saveExportToFile(
        exportData as unknown as Parameters<typeof saveExportToFile>[0],
        outputPath,
      );

      const savedContent = await fs.readFile(outputPath, "utf-8");
      const parsed = JSON.parse(savedContent);

      expect(parsed).toEqual(exportData);
    });

    it("should create parent directories if needed", async () => {
      const exportData = {
        exportedAt: new Date().toISOString(),
        version: "1.0.0",
        sessions: {},
      };

      const outputPath = path.join(tempDir, "nested", "dir", "export.json");
      await saveExportToFile(
        exportData as unknown as Parameters<typeof saveExportToFile>[0],
        outputPath,
      );

      const stats = await fs.stat(outputPath);
      expect(stats.isFile()).toBe(true);
    });
  });
});
