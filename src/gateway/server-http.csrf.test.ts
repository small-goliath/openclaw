/**
 * CSRF Protection Integration Tests for HTTP Server
 *
 * Tests for SEC-004: CSRF protection in gateway HTTP server
 * OWASP A01:2021 - Broken Access Control
 */

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { CSRF_COOKIE_NAME, CSRF_HEADER_NAME } from "../security/csrf.js";
import { getFreePort, startGatewayServer, installGatewayTestHooks } from "./test-helpers.js";

installGatewayTestHooks({ scope: "suite" });

describe("gateway HTTP server CSRF protection", () => {
  let server: Awaited<ReturnType<typeof startGatewayServer>>;
  let port: number;
  let baseUrl: string;

  beforeAll(async () => {
    port = await getFreePort();
    server = await startGatewayServer(port);
    baseUrl = `http://127.0.0.1:${port}`;
  });

  afterAll(async () => {
    await server.close();
  });

  describe("safe HTTP methods", () => {
    it("should allow GET requests without CSRF token", async () => {
      const response = await fetch(`${baseUrl}/nonexistent`);
      // 404 is expected since the path doesn't exist, but CSRF should not block it
      expect(response.status).toBe(404);
    });

    it("should allow HEAD requests without CSRF token", async () => {
      const response = await fetch(`${baseUrl}/nonexistent`, { method: "HEAD" });
      expect(response.status).toBe(404);
    });

    it("should allow OPTIONS requests without CSRF token", async () => {
      const response = await fetch(`${baseUrl}/nonexistent`, { method: "OPTIONS" });
      // 404 is expected since OPTIONS might not be implemented for all routes
      expect([200, 404]).toContain(response.status);
    });

    it("should set CSRF cookie on GET requests", async () => {
      const response = await fetch(`${baseUrl}/nonexistent`);
      const setCookie = response.headers.get("set-cookie");

      expect(setCookie).toBeTruthy();
      expect(setCookie).toContain(CSRF_COOKIE_NAME);
    });
  });

  describe("state-changing methods", () => {
    it("should reject POST without CSRF token", async () => {
      const response = await fetch(`${baseUrl}/nonexistent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ test: "data" }),
      });

      expect(response.status).toBe(403);
      const body = await response.json();
      expect(body.error).toBe("CSRF validation failed");
    });

    it("should reject POST with mismatched CSRF token", async () => {
      // First, get a valid CSRF cookie
      const getResponse = await fetch(`${baseUrl}/nonexistent`);
      const cookies = getResponse.headers.get("set-cookie") || "";

      // Try to use a different token in the header
      const response = await fetch(`${baseUrl}/nonexistent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": "wrong-token",
          Cookie: cookies,
        },
        body: JSON.stringify({ test: "data" }),
      });

      expect(response.status).toBe(403);
      const body = await response.json();
      expect(body.error).toBe("CSRF validation failed");
    });

    it("should accept POST with valid CSRF token", async () => {
      // First, get a valid CSRF cookie
      const getResponse = await fetch(`${baseUrl}/nonexistent`);
      const cookies = getResponse.headers.get("set-cookie") || "";

      // Extract the token from the cookie
      const tokenMatch = cookies.match(new RegExp(`${CSRF_COOKIE_NAME}=([^;]+)`));
      const token = tokenMatch ? decodeURIComponent(tokenMatch[1]) : null;

      expect(token).toBeTruthy();

      // Now make a POST request with the token
      const response = await fetch(`${baseUrl}/nonexistent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": token!,
          Cookie: cookies,
        },
        body: JSON.stringify({ test: "data" }),
      });

      // 404 is expected since POST might not be implemented for this route
      // but we should not get 403 (CSRF validation should pass)
      expect(response.status).not.toBe(403);
    });

    it("should reject PUT without CSRF token", async () => {
      const response = await fetch(`${baseUrl}/nonexistent`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ test: "data" }),
      });

      expect(response.status).toBe(403);
    });

    it("should reject DELETE without CSRF token", async () => {
      const response = await fetch(`${baseUrl}/nonexistent`, {
        method: "DELETE",
      });

      expect(response.status).toBe(403);
    });

    it("should reject PATCH without CSRF token", async () => {
      const response = await fetch(`${baseUrl}/nonexistent`, {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ test: "data" }),
      });

      expect(response.status).toBe(403);
    });
  });

  describe("excluded paths", () => {
    it("should not require CSRF token for /hooks/ endpoints", async () => {
      // Hooks use their own token-based authentication
      const response = await fetch(`${baseUrl}/hooks/wake`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ text: "test" }),
      });

      // Should not get 403 for CSRF, but might get 401 for missing auth token
      expect(response.status).not.toBe(403);
    });

    it("should not require CSRF token for /v1/ endpoints (OpenAI compatible)", async () => {
      // OpenAI-compatible endpoints use API key authentication
      const response = await fetch(`${baseUrl}/v1/chat/completions`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model: "test", messages: [] }),
      });

      // Should not get 403 for CSRF, but might get 401 for missing API key
      expect(response.status).not.toBe(403);
    });
  });

  describe("Double Submit Cookie pattern", () => {
    it("should validate when cookie and header tokens match", async () => {
      // Get CSRF cookie from a GET request
      const getResponse = await fetch(`${baseUrl}/nonexistent`);
      const cookies = getResponse.headers.get("set-cookie") || "";

      // Extract token from cookie
      const tokenMatch = cookies.match(new RegExp(`${CSRF_COOKIE_NAME}=([^;]+)`));
      const token = tokenMatch ? decodeURIComponent(tokenMatch[1]) : null;

      expect(token).toBeTruthy();

      // POST with matching token
      const postResponse = await fetch(`${baseUrl}/nonexistent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": token!,
          Cookie: cookies,
        },
        body: JSON.stringify({ test: "data" }),
      });

      // Should not be 403 (CSRF validation should pass)
      expect(postResponse.status).not.toBe(403);
    });

    it("should reject when cookie and header tokens differ", async () => {
      // Get CSRF cookie from a GET request
      const getResponse = await fetch(`${baseUrl}/nonexistent`);
      const cookies = getResponse.headers.get("set-cookie") || "";

      // POST with different token
      const postResponse = await fetch(`${baseUrl}/nonexistent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": "tampered-token",
          Cookie: cookies,
        },
        body: JSON.stringify({ test: "data" }),
      });

      expect(postResponse.status).toBe(403);
    });

    it("should reject when cookie is missing but header is present", async () => {
      const response = await fetch(`${baseUrl}/nonexistent`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": "some-token",
        },
        body: JSON.stringify({ test: "data" }),
      });

      expect(response.status).toBe(403);
    });
  });
});
