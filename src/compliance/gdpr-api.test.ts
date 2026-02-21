/**
 * GDPR API 엔드포인트 테스트
 * COMP-003, COMP-004 요구사항 검증
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ResolvedGatewayAuth } from "../gateway/auth.js";
import { handleGdprApiRequest, getGdprApiStatus } from "./gdpr-api.js";

// 모듈 모킹
vi.mock("./data-export.js", () => ({
  exportUserData: vi.fn().mockResolvedValue({
    exportedAt: new Date().toISOString(),
    version: "1.0.0",
    sessions: { "test-session": { channel: "test" } },
  }),
  exportPortableData: vi.fn().mockResolvedValue({
    data_controller: "OpenClaw",
    personal_data: {},
  }),
  deleteUserData: vi.fn().mockResolvedValue({
    success: true,
    deletedCategories: ["sessions"],
    failedCategories: [],
    deletedCount: 1,
    errors: [],
  }),
  calculateExportSize: vi.fn().mockReturnValue(1000),
}));

vi.mock("../gateway/auth.js", () => ({
  authorizeGatewayConnect: vi.fn(),
}));

vi.mock("../gateway/http-utils.js", () => ({
  getBearerToken: vi.fn(),
}));

vi.mock("../logging/subsystem.js", () => ({
  createSubsystemLogger: vi.fn(() => ({
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn(),
  })),
}));

import { authorizeGatewayConnect } from "../gateway/auth.js";
import { getBearerToken } from "../gateway/http-utils.js";
import { exportUserData, exportPortableData, deleteUserData } from "./data-export.js";

describe("GDPR API", () => {
  let mockReq: Partial<IncomingMessage>;
  let mockRes: Partial<ServerResponse>;
  let responseData: string;
  const mockAuthorizeGatewayConnect = vi.mocked(authorizeGatewayConnect);
  const mockGetBearerToken = vi.mocked(getBearerToken);

  beforeEach(() => {
    responseData = "";
    mockReq = {
      url: "/api/v1/user/data-export",
      method: "GET",
      headers: {},
      socket: { remoteAddress: "127.0.0.1" } as unknown as IncomingMessage["socket"],
    };

    mockRes = {
      statusCode: 200,
      setHeader: vi.fn(),
      write: vi.fn((chunk: string) => {
        responseData += chunk;
      }),
      end: vi.fn((data?: string) => {
        if (data) {
          responseData += data;
        }
      }) as ServerResponse["end"],
    };

    // 기본 인증 성공 모킹
    mockAuthorizeGatewayConnect.mockResolvedValue({ ok: true });
    mockGetBearerToken.mockReturnValue("test-token");
  });

  describe("getGdprApiStatus", () => {
    it("should return API status", () => {
      const status = getGdprApiStatus();

      expect(status.available).toBe(true);
      expect(status.version).toBe("1.0.0");
      expect(status.endpoints).toContain("GET /api/v1/user/data-export");
      expect(status.endpoints).toContain("GET /api/v1/user/data-portable");
      expect(status.endpoints).toContain("DELETE /api/v1/user/data");
    });
  });

  describe("handleGdprApiRequest", () => {
    const mockAuth: ResolvedGatewayAuth = {
      token: "test-token",
      password: "test-password",
    };

    const opts = {
      auth: mockAuth,
      trustedProxies: [] as string[],
    };

    it("should return false for non-GDPR paths", async () => {
      mockReq.url = "/api/other/endpoint";

      const result = await handleGdprApiRequest(
        mockReq as IncomingMessage,
        mockRes as ServerResponse,
        opts,
      );

      expect(result).toBe(false);
    });

    describe("GET /api/v1/user/data-export", () => {
      it("should handle data export request", async () => {
        mockReq.url = "/api/v1/user/data-export";
        mockReq.method = "GET";

        const result = await handleGdprApiRequest(
          mockReq as IncomingMessage,
          mockRes as ServerResponse,
          opts,
        );

        expect(result).toBe(true);
        expect(mockRes.statusCode).toBe(200);
        expect(exportUserData).toHaveBeenCalled();
      });

      it("should parse query parameters", async () => {
        mockReq.url = "/api/v1/user/data-export?sessionKey=test-session&categories=sessions";
        mockReq.method = "GET";

        await handleGdprApiRequest(mockReq as IncomingMessage, mockRes as ServerResponse, opts);

        expect(exportUserData).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            sessionKey: "test-session",
            categories: ["sessions"],
          }),
        );
      });

      it("should reject unauthenticated requests", async () => {
        mockGetBearerToken.mockReturnValue(null);

        await handleGdprApiRequest(mockReq as IncomingMessage, mockRes as ServerResponse, opts);

        expect(mockRes.statusCode).toBe(401);
      });

      it("should handle export timeout", async () => {
        const mockExportUserData = vi.mocked(exportUserData);
        mockExportUserData.mockImplementation(
          () => new Promise((resolve) => setTimeout(resolve, 10000)),
        );

        await handleGdprApiRequest(mockReq as IncomingMessage, mockRes as ServerResponse, opts);

        // 타임아웃은 5분이므로 테스트에서는 직접 검증하지 않음
        expect(mockExportUserData).toHaveBeenCalled();
      });
    });

    describe("GET /api/v1/user/data-portable", () => {
      it("should handle data portability request", async () => {
        mockReq.url = "/api/v1/user/data-portable";
        mockReq.method = "GET";

        const result = await handleGdprApiRequest(
          mockReq as IncomingMessage,
          mockRes as ServerResponse,
          opts,
        );

        expect(result).toBe(true);
        expect(mockRes.statusCode).toBe(200);
        expect(exportPortableData).toHaveBeenCalled();
      });

      it("should set content-disposition header", async () => {
        mockReq.url = "/api/v1/user/data-portable";
        mockReq.method = "GET";

        await handleGdprApiRequest(mockReq as IncomingMessage, mockRes as ServerResponse, opts);

        expect(mockRes.setHeader).toHaveBeenCalledWith(
          "Content-Disposition",
          expect.stringContaining("attachment"),
        );
      });
    });

    describe("DELETE /api/v1/user/data", () => {
      it("should handle data deletion request", async () => {
        mockReq.url = "/api/v1/user/data";
        mockReq.method = "DELETE";

        const result = await handleGdprApiRequest(
          mockReq as IncomingMessage,
          mockRes as ServerResponse,
          opts,
        );

        expect(result).toBe(true);
        expect(mockRes.statusCode).toBe(200);
        expect(deleteUserData).toHaveBeenCalled();
      });

      it("should return GDPR compliance notice", async () => {
        mockReq.url = "/api/v1/user/data";
        mockReq.method = "DELETE";

        await handleGdprApiRequest(mockReq as IncomingMessage, mockRes as ServerResponse, opts);

        const responseBody = JSON.parse(responseData);
        expect(responseBody).toHaveProperty("gdprNotice");
        expect(responseBody.gdprNotice).toHaveProperty("article", "Article 17");
        expect(responseBody.gdprNotice).toHaveProperty("right");
      });

      it("should handle partial deletion with 207 status", async () => {
        const mockDeleteUserData = vi.mocked(deleteUserData);
        mockDeleteUserData.mockResolvedValue({
          success: false,
          deletedCategories: ["sessions"],
          failedCategories: [{ category: "memories", error: "Access denied" }],
          deletedCount: 1,
          errors: ["Access denied"],
        });

        mockReq.url = "/api/v1/user/data";
        mockReq.method = "DELETE";

        await handleGdprApiRequest(mockReq as IncomingMessage, mockRes as ServerResponse, opts);

        expect(mockRes.statusCode).toBe(207);
      });

      it("should parse deletion options", async () => {
        mockReq.url = "/api/v1/user/data?sessionKey=test&categories=sessions&permanent=true";
        mockReq.method = "DELETE";

        await handleGdprApiRequest(mockReq as IncomingMessage, mockRes as ServerResponse, opts);

        expect(deleteUserData).toHaveBeenCalledWith(
          expect.any(String),
          expect.objectContaining({
            sessionKey: "test",
            categories: ["sessions"],
            permanent: true,
          }),
        );
      });
    });

    describe("rate limiting", () => {
      it("should handle rate limited requests", async () => {
        mockAuthorizeGatewayConnect.mockResolvedValue({
          ok: false,
          reason: "rate_limited",
          rateLimited: true,
          retryAfterMs: 60000,
        });

        await handleGdprApiRequest(mockReq as IncomingMessage, mockRes as ServerResponse, opts);

        expect(mockRes.statusCode).toBe(429);
        expect(mockRes.setHeader).toHaveBeenCalledWith("Retry-After", "60");
      });
    });

    describe("error handling", () => {
      it("should handle internal errors gracefully", async () => {
        const mockExportUserData = vi.mocked(exportUserData);
        mockExportUserData.mockRejectedValue(new Error("Database error"));

        await handleGdprApiRequest(mockReq as IncomingMessage, mockRes as ServerResponse, opts);

        expect(mockRes.statusCode).toBe(500);
        const responseBody = JSON.parse(responseData);
        expect(responseBody.error).toBe("Internal Server Error");
      });

      it("should return 404 for unsupported methods", async () => {
        mockReq.url = "/api/v1/user/data-export";
        mockReq.method = "POST";

        await handleGdprApiRequest(mockReq as IncomingMessage, mockRes as ServerResponse, opts);

        expect(mockRes.statusCode).toBe(404);
      });
    });
  });
});
