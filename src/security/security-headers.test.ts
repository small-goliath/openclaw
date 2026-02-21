/**
 * Security Headers Tests
 *
 * 보안 헤더 모듈의 단위 테스트
 */

import type { Request, Response, NextFunction } from "express";
import type { ServerResponse } from "node:http";
import { describe, it, expect, vi } from "vitest";
import {
  applySecurityHeaders,
  getSecurityHeaders,
  securityHeadersMiddleware,
  type SecurityHeadersOptions,
} from "./security-headers.js";

describe("security-headers", () => {
  // Mock ServerResponse
  function createMockResponse(): ServerResponse {
    const headers: Record<string, string> = {};
    return {
      setHeader: vi.fn((name: string, value: string) => {
        headers[name] = value;
      }),
      getHeader: vi.fn((name: string) => headers[name]),
      getHeaders: vi.fn(() => headers),
    } as unknown as ServerResponse;
  }

  describe("applySecurityHeaders", () => {
    it("should apply all default security headers", () => {
      const res = createMockResponse();
      applySecurityHeaders(res);

      expect(res.setHeader).toHaveBeenCalledWith("X-Content-Type-Options", "nosniff");
      expect(res.setHeader).toHaveBeenCalledWith("X-Frame-Options", "DENY");
      expect(res.setHeader).toHaveBeenCalledWith("X-XSS-Protection", "1; mode=block");
      expect(res.setHeader).toHaveBeenCalledWith(
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
      );
    });

    it("should not apply HSTS header for non-secure connections", () => {
      const res = createMockResponse();
      applySecurityHeaders(res, { secure: false });

      expect(res.setHeader).not.toHaveBeenCalledWith(
        "Strict-Transport-Security",
        expect.any(String),
      );
    });

    it("should apply HSTS header for secure connections", () => {
      const res = createMockResponse();
      applySecurityHeaders(res, { secure: true });

      expect(res.setHeader).toHaveBeenCalledWith(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload",
      );
    });

    it("should apply Content-Security-Policy header", () => {
      const res = createMockResponse();
      applySecurityHeaders(res);

      expect(res.setHeader).toHaveBeenCalledWith(
        "Content-Security-Policy",
        expect.stringContaining("default-src 'self'"),
      );
    });

    it("should allow custom CSP policy", () => {
      const res = createMockResponse();
      const customCsp = "default-src 'none'; script-src 'self'";
      applySecurityHeaders(res, { contentSecurityPolicy: customCsp });

      expect(res.setHeader).toHaveBeenCalledWith("Content-Security-Policy", customCsp);
    });

    it("should apply Permissions-Policy header", () => {
      const res = createMockResponse();
      applySecurityHeaders(res);

      expect(res.setHeader).toHaveBeenCalledWith(
        "Permissions-Policy",
        expect.stringContaining("camera=()"),
      );
      expect(res.setHeader).toHaveBeenCalledWith(
        "Permissions-Policy",
        expect.stringContaining("microphone=()"),
      );
    });

    it("should allow custom Permissions-Policy", () => {
      const res = createMockResponse();
      const customPolicy = "camera=(self), microphone=()";
      applySecurityHeaders(res, { permissionsPolicy: customPolicy });

      expect(res.setHeader).toHaveBeenCalledWith("Permissions-Policy", customPolicy);
    });

    it("should include frame-ancestors in CSP to prevent clickjacking", () => {
      const res = createMockResponse();
      applySecurityHeaders(res);

      const cspCall = vi
        .mocked(res.setHeader)
        .mock.calls.find((call) => call[0] === "Content-Security-Policy");
      expect(cspCall?.[1]).toContain("frame-ancestors 'none'");
    });

    it("should include object-src none in CSP", () => {
      const res = createMockResponse();
      applySecurityHeaders(res);

      const cspCall = vi
        .mocked(res.setHeader)
        .mock.calls.find((call) => call[0] === "Content-Security-Policy");
      expect(cspCall?.[1]).toContain("object-src 'none'");
    });
  });

  describe("getSecurityHeaders", () => {
    it("should return all default headers as object", () => {
      const headers = getSecurityHeaders();

      expect(headers["X-Content-Type-Options"]).toBe("nosniff");
      expect(headers["X-Frame-Options"]).toBe("DENY");
      expect(headers["X-XSS-Protection"]).toBe("1; mode=block");
      expect(headers["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
    });

    it("should include HSTS when secure option is true", () => {
      const headers = getSecurityHeaders({ secure: true });

      expect(headers["Strict-Transport-Security"]).toBe(
        "max-age=31536000; includeSubDomains; preload",
      );
    });

    it("should not include HSTS when secure option is false", () => {
      const headers = getSecurityHeaders({ secure: false });

      expect(headers["Strict-Transport-Security"]).toBeUndefined();
    });

    it("should include CSP header", () => {
      const headers = getSecurityHeaders();

      expect(headers["Content-Security-Policy"]).toContain("default-src 'self'");
    });

    it("should include Permissions-Policy header", () => {
      const headers = getSecurityHeaders();

      expect(headers["Permissions-Policy"]).toContain("camera=()");
    });
  });

  describe("securityHeadersMiddleware", () => {
    it("should apply headers and call next", () => {
      const middleware = securityHeadersMiddleware();
      const req = {} as Request;
      const res = createMockResponse() as unknown as Response;
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      expect(res.setHeader).toHaveBeenCalledWith("X-Content-Type-Options", "nosniff");
      expect(res.setHeader).toHaveBeenCalledWith("X-Frame-Options", "DENY");
      expect(next).toHaveBeenCalled();
    });

    it("should pass options to applySecurityHeaders", () => {
      const middleware = securityHeadersMiddleware({ secure: true });
      const req = {} as Request;
      const res = createMockResponse() as unknown as Response;
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      expect(res.setHeader).toHaveBeenCalledWith(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload",
      );
      expect(next).toHaveBeenCalled();
    });

    it("should apply custom CSP through middleware", () => {
      const customCsp = "default-src 'none'";
      const middleware = securityHeadersMiddleware({ contentSecurityPolicy: customCsp });
      const req = {} as Request;
      const res = createMockResponse() as unknown as Response;
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      expect(res.setHeader).toHaveBeenCalledWith("Content-Security-Policy", customCsp);
    });
  });

  describe("security headers compliance", () => {
    it("should prevent MIME sniffing", () => {
      const headers = getSecurityHeaders();
      expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    });

    it("should prevent clickjacking with X-Frame-Options", () => {
      const headers = getSecurityHeaders();
      expect(headers["X-Frame-Options"]).toBe("DENY");
    });

    it("should enable XSS protection", () => {
      const headers = getSecurityHeaders();
      expect(headers["X-XSS-Protection"]).toBe("1; mode=block");
    });

    it("should restrict referrer information", () => {
      const headers = getSecurityHeaders();
      expect(headers["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
    });

    it("should have reasonable CSP that allows basic functionality", () => {
      const headers = getSecurityHeaders();
      const csp = headers["Content-Security-Policy"];

      // Should allow same-origin resources
      expect(csp).toContain("default-src 'self'");

      // Should allow inline scripts/styles for UI frameworks
      expect(csp).toContain("script-src 'self' 'unsafe-inline'");
      expect(csp).toContain("style-src 'self' 'unsafe-inline'");

      // Should allow images from various sources
      expect(csp).toContain("img-src 'self' data: https:");

      // Should allow WebSocket connections
      expect(csp).toContain("connect-src 'self' ws: wss:");

      // Should prevent embedding
      expect(csp).toContain("frame-ancestors 'none'");

      // Should prevent plugins
      expect(csp).toContain("object-src 'none'");
    });

    it("should disable all permissions by default", () => {
      const headers = getSecurityHeaders();
      const policy = headers["Permissions-Policy"];

      // All permissions should be disabled
      expect(policy).toContain("camera=()");
      expect(policy).toContain("microphone=()");
      expect(policy).toContain("geolocation=()");
      expect(policy).toContain("payment=()");
      expect(policy).toContain("usb=()");
    });
  });
});
