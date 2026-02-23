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
  cspMiddleware,
  hstsMiddleware,
  generateNonce,
  buildCspHeader,
  buildHstsHeader,
  type SecurityHeadersOptions,
  type HstsOptions,
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

  describe("generateNonce", () => {
    it("should generate a base64 encoded nonce", () => {
      const nonce = generateNonce();
      expect(nonce).toBeDefined();
      expect(nonce.length).toBeGreaterThan(0);
      // Base64 encoded 16 bytes should be around 24 characters
      expect(nonce.length).toBe(24);
    });

    it("should generate unique nonces", () => {
      const nonce1 = generateNonce();
      const nonce2 = generateNonce();
      expect(nonce1).not.toBe(nonce2);
    });
  });

  describe("buildCspHeader", () => {
    it("should build CSP with nonce for scripts and styles", () => {
      const nonce = "test-nonce-123";
      const csp = buildCspHeader(nonce);

      expect(csp).toContain(`script-src 'self' 'nonce-${nonce}'`);
      expect(csp).toContain(`style-src 'self' 'nonce-${nonce}'`);
    });

    it("should not contain unsafe-inline", () => {
      const csp = buildCspHeader("test-nonce");

      expect(csp).not.toContain("unsafe-inline");
    });

    it("should include default CSP directives", () => {
      const csp = buildCspHeader("test-nonce");

      expect(csp).toContain("default-src 'self'");
      expect(csp).toContain("object-src 'none'");
      expect(csp).toContain("frame-ancestors 'none'");
      expect(csp).toContain("base-uri 'self'");
      expect(csp).toContain("form-action 'self'");
    });

    it("should allow WebSocket connections by default", () => {
      const csp = buildCspHeader("test-nonce");

      expect(csp).toContain("connect-src 'self' ws: wss:");
    });

    it("should allow external images by default", () => {
      const csp = buildCspHeader("test-nonce");

      expect(csp).toContain("img-src 'self' data: https:");
    });

    it("should optionally disable WebSocket connections", () => {
      const csp = buildCspHeader("test-nonce", { allowWebSocket: false });

      expect(csp).toContain("connect-src 'self'");
      expect(csp).not.toContain("ws:");
    });

    it("should optionally disable external images", () => {
      const csp = buildCspHeader("test-nonce", { allowExternalImages: false });

      expect(csp).toContain("img-src 'self' data:");
      expect(csp).not.toContain("https:");
    });
  });

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

    it("should return nonce when applying headers", () => {
      const res = createMockResponse();
      const nonce = applySecurityHeaders(res);

      expect(nonce).toBeDefined();
      expect(nonce.length).toBeGreaterThan(0);
    });

    it("should use provided nonce when specified", () => {
      const res = createMockResponse();
      const customNonce = "custom-nonce-123";
      const returnedNonce = applySecurityHeaders(res, { nonce: customNonce });

      expect(returnedNonce).toBe(customNonce);
      expect(res.setHeader).toHaveBeenCalledWith(
        "Content-Security-Policy",
        expect.stringContaining(`nonce-${customNonce}`),
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
        "max-age=31536000; includeSubDomains",
      );
    });

    it("should apply Content-Security-Policy header with nonce", () => {
      const res = createMockResponse();
      applySecurityHeaders(res);

      const cspCall = vi
        .mocked(res.setHeader)
        .mock.calls.find((call) => call[0] === "Content-Security-Policy");
      expect(cspCall?.[1]).toContain("default-src 'self'");
      expect(cspCall?.[1]).toContain("nonce-");
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

    it("should not use nonce when useNonce is false", () => {
      const res = createMockResponse();
      applySecurityHeaders(res, { useNonce: false });

      const cspCalls = vi
        .mocked(res.setHeader)
        .mock.calls.filter((call) => call[0] === "Content-Security-Policy");
      expect(cspCalls.length).toBe(0);
    });
  });

  describe("getSecurityHeaders", () => {
    it("should return all default headers as object with nonce", () => {
      const { headers, nonce } = getSecurityHeaders();

      expect(headers["X-Content-Type-Options"]).toBe("nosniff");
      expect(headers["X-Frame-Options"]).toBe("DENY");
      expect(headers["X-XSS-Protection"]).toBe("1; mode=block");
      expect(headers["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
      expect(nonce).toBeDefined();
      expect(nonce.length).toBeGreaterThan(0);
    });

    it("should include HSTS when secure option is true", () => {
      const { headers } = getSecurityHeaders({ secure: true });

      expect(headers["Strict-Transport-Security"]).toBe("max-age=31536000; includeSubDomains");
    });

    it("should not include HSTS when secure option is false", () => {
      const { headers } = getSecurityHeaders({ secure: false });

      expect(headers["Strict-Transport-Security"]).toBeUndefined();
    });

    it("should include CSP header with nonce", () => {
      const { headers, nonce } = getSecurityHeaders();

      expect(headers["Content-Security-Policy"]).toContain("default-src 'self'");
      expect(headers["Content-Security-Policy"]).toContain(`nonce-${nonce}`);
    });

    it("should include Permissions-Policy header", () => {
      const { headers } = getSecurityHeaders();

      expect(headers["Permissions-Policy"]).toContain("camera=()");
    });

    it("should use provided nonce when specified", () => {
      const customNonce = "custom-test-nonce";
      const { headers, nonce } = getSecurityHeaders({ nonce: customNonce });

      expect(nonce).toBe(customNonce);
      expect(headers["Content-Security-Policy"]).toContain(`nonce-${customNonce}`);
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
        "max-age=31536000; includeSubDomains",
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

    it("should set cspNonce in res.locals", () => {
      const middleware = securityHeadersMiddleware();
      const req = {} as Request;
      const res = createMockResponse() as unknown as Response;
      res.locals = {};
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      expect(res.locals.cspNonce).toBeDefined();
      expect(res.locals.cspNonce.length).toBeGreaterThan(0);
    });
  });

  describe("cspMiddleware", () => {
    it("should set CSP header with generated nonce", () => {
      const middleware = cspMiddleware();
      const req = {} as Request;
      const res = createMockResponse() as unknown as Response;
      res.locals = {};
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      const cspCall = vi
        .mocked(res.setHeader)
        .mock.calls.find((call) => call[0] === "Content-Security-Policy");
      expect(cspCall?.[1]).toContain("nonce-");
      expect(cspCall?.[1]).not.toContain("unsafe-inline");
    });

    it("should use provided nonce when specified", () => {
      const customNonce = "custom-nonce-123";
      const middleware = cspMiddleware({ nonce: customNonce });
      const req = {} as Request;
      const res = createMockResponse() as unknown as Response;
      res.locals = {};
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      expect(res.setHeader).toHaveBeenCalledWith(
        "Content-Security-Policy",
        expect.stringContaining(`nonce-${customNonce}`),
      );
    });

    it("should set cspNonce in res.locals", () => {
      const middleware = cspMiddleware();
      const req = {} as Request;
      const res = createMockResponse() as unknown as Response;
      res.locals = {};
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      expect(res.locals.cspNonce).toBeDefined();
      expect(res.locals.cspNonce.length).toBe(24); // Base64 encoded 16 bytes
    });

    it("should call next() after setting headers", () => {
      const middleware = cspMiddleware();
      const req = {} as Request;
      const res = createMockResponse() as unknown as Response;
      res.locals = {};
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      expect(next).toHaveBeenCalled();
    });

    it("should allow disabling WebSocket in CSP", () => {
      const middleware = cspMiddleware({ allowWebSocket: false });
      const req = {} as Request;
      const res = createMockResponse() as unknown as Response;
      res.locals = {};
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      const cspCall = vi
        .mocked(res.setHeader)
        .mock.calls.find((call) => call[0] === "Content-Security-Policy");
      expect(cspCall?.[1]).toContain("connect-src 'self'");
      expect(cspCall?.[1]).not.toContain("ws:");
    });

    it("should allow disabling external images in CSP", () => {
      const middleware = cspMiddleware({ allowExternalImages: false });
      const req = {} as Request;
      const res = createMockResponse() as unknown as Response;
      res.locals = {};
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      const cspCall = vi
        .mocked(res.setHeader)
        .mock.calls.find((call) => call[0] === "Content-Security-Policy");
      expect(cspCall?.[1]).toContain("img-src 'self' data:");
      expect(cspCall?.[1]).not.toContain("https:");
    });
  });

  describe("security headers compliance", () => {
    it("should prevent MIME sniffing", () => {
      const { headers } = getSecurityHeaders();
      expect(headers["X-Content-Type-Options"]).toBe("nosniff");
    });

    it("should prevent clickjacking with X-Frame-Options", () => {
      const { headers } = getSecurityHeaders();
      expect(headers["X-Frame-Options"]).toBe("DENY");
    });

    it("should enable XSS protection", () => {
      const { headers } = getSecurityHeaders();
      expect(headers["X-XSS-Protection"]).toBe("1; mode=block");
    });

    it("should restrict referrer information", () => {
      const { headers } = getSecurityHeaders();
      expect(headers["Referrer-Policy"]).toBe("strict-origin-when-cross-origin");
    });

    it("should have reasonable CSP that allows basic functionality", () => {
      const { headers, nonce } = getSecurityHeaders();
      const csp = headers["Content-Security-Policy"];

      // Should allow same-origin resources
      expect(csp).toContain("default-src 'self'");

      // Should use nonce-based CSP instead of unsafe-inline
      expect(csp).toContain(`script-src 'self' 'nonce-${nonce}'`);
      expect(csp).toContain(`style-src 'self' 'nonce-${nonce}'`);
      expect(csp).not.toContain("unsafe-inline");

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
      const { headers } = getSecurityHeaders();
      const policy = headers["Permissions-Policy"];

      // All permissions should be disabled
      expect(policy).toContain("camera=()");
      expect(policy).toContain("microphone=()");
      expect(policy).toContain("geolocation=()");
      expect(policy).toContain("payment=()");
      expect(policy).toContain("usb=()");
    });
  });

  describe("buildHstsHeader", () => {
    it("should build HSTS header with default values", () => {
      const header = buildHstsHeader();

      expect(header).toBe("max-age=31536000; includeSubDomains");
    });

    it("should build HSTS header with custom maxAge", () => {
      const header = buildHstsHeader({ maxAge: 86400 }); // 1 day

      expect(header).toBe("max-age=86400; includeSubDomains");
    });

    it("should include preload directive when enabled", () => {
      const header = buildHstsHeader({ preload: true });

      expect(header).toBe("max-age=31536000; includeSubDomains; preload");
    });

    it("should exclude includeSubDomains when disabled", () => {
      const header = buildHstsHeader({ includeSubDomains: false });

      expect(header).toBe("max-age=31536000");
    });

    it("should build HSTS header with all custom options", () => {
      const header = buildHstsHeader({
        maxAge: 63072000, // 2 years
        includeSubDomains: true,
        preload: true,
      });

      expect(header).toBe("max-age=63072000; includeSubDomains; preload");
    });

    it("should build HSTS header with only max-age and preload", () => {
      const header = buildHstsHeader({
        maxAge: 63072000,
        includeSubDomains: false,
        preload: true,
      });

      expect(header).toBe("max-age=63072000; preload");
    });
  });

  describe("hstsMiddleware", () => {
    it("should set HSTS header for secure requests", () => {
      const middleware = hstsMiddleware();
      const req = { secure: true } as Request;
      const res = createMockResponse() as unknown as Response;
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      expect(res.setHeader).toHaveBeenCalledWith(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
      );
      expect(next).toHaveBeenCalled();
    });

    it("should set HSTS header when x-forwarded-proto is https", () => {
      const middleware = hstsMiddleware();
      const req = {
        secure: false,
        headers: { "x-forwarded-proto": "https" },
      } as unknown as Request;
      const res = createMockResponse() as unknown as Response;
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      expect(res.setHeader).toHaveBeenCalledWith(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
      );
      expect(next).toHaveBeenCalled();
    });

    it("should not set HSTS header for non-secure requests", () => {
      const middleware = hstsMiddleware();
      const req = {
        secure: false,
        headers: {},
      } as unknown as Request;
      const res = createMockResponse() as unknown as Response;
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      expect(res.setHeader).not.toHaveBeenCalledWith(
        "Strict-Transport-Security",
        expect.any(String),
      );
      expect(next).toHaveBeenCalled();
    });

    it("should pass custom HSTS options to middleware", () => {
      const middleware = hstsMiddleware({
        maxAge: 63072000,
        includeSubDomains: true,
        preload: true,
      });
      const req = { secure: true } as Request;
      const res = createMockResponse() as unknown as Response;
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      expect(res.setHeader).toHaveBeenCalledWith(
        "Strict-Transport-Security",
        "max-age=63072000; includeSubDomains; preload",
      );
    });

    it("should handle x-forwarded-proto with uppercase HTTPS", () => {
      const middleware = hstsMiddleware();
      const req = {
        secure: false,
        headers: { "x-forwarded-proto": "HTTPS" },
      } as unknown as Request;
      const res = createMockResponse() as unknown as Response;
      const next = vi.fn() as NextFunction;

      middleware(req, res, next);

      expect(res.setHeader).toHaveBeenCalledWith(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains",
      );
    });
  });

  describe("HSTS configuration via applySecurityHeaders", () => {
    it("should apply custom HSTS maxAge", () => {
      const res = createMockResponse();
      applySecurityHeaders(res, {
        secure: true,
        hsts: { maxAge: 86400 },
      });

      expect(res.setHeader).toHaveBeenCalledWith(
        "Strict-Transport-Security",
        "max-age=86400; includeSubDomains",
      );
    });

    it("should apply HSTS with preload", () => {
      const res = createMockResponse();
      applySecurityHeaders(res, {
        secure: true,
        hsts: { preload: true },
      });

      expect(res.setHeader).toHaveBeenCalledWith(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload",
      );
    });

    it("should apply HSTS without includeSubDomains", () => {
      const res = createMockResponse();
      applySecurityHeaders(res, {
        secure: true,
        hsts: { includeSubDomains: false },
      });

      expect(res.setHeader).toHaveBeenCalledWith("Strict-Transport-Security", "max-age=31536000");
    });
  });
});
