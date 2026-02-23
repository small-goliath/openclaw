import { describe, it, expect, vi, beforeEach } from "vitest";
import { RequestDeduplicator, defaultRequestDeduplicator } from "./request-deduplicator";

describe("RequestDeduplicator", () => {
  beforeEach(() => {
    // Clear default instance before each test
    defaultRequestDeduplicator.clear();
  });

  describe("deduplicate", () => {
    it("should execute a new request when no pending request exists", async () => {
      const deduplicator = new RequestDeduplicator();
      const requestFn = vi.fn().mockResolvedValue("result");

      const result = await deduplicator.deduplicate("key1", requestFn);

      expect(result).toBe("result");
      expect(requestFn).toHaveBeenCalledTimes(1);
    });

    it("should return the same promise for duplicate concurrent requests", async () => {
      const deduplicator = new RequestDeduplicator();
      let resolveFn: (value: string) => void;
      const requestFn = vi.fn().mockImplementation(() => {
        return new Promise<string>((resolve) => {
          resolveFn = resolve;
        });
      });

      // Start first request
      const promise1 = deduplicator.deduplicate("key1", requestFn);

      // Wait for the promise to be stored in the map
      await new Promise((resolve) => setTimeout(resolve, 0));

      // Start second request with same key
      const promise2 = deduplicator.deduplicate("key1", requestFn);

      // Should return the same promise reference
      expect(promise1).toBe(promise2);
      // Request function should only be called once
      expect(requestFn).toHaveBeenCalledTimes(1);

      // Resolve the request
      resolveFn!("result");

      const [result1, result2] = await Promise.all([promise1, promise2]);
      expect(result1).toBe("result");
      expect(result2).toBe("result");
    });

    it("should allow new requests after the deduplication window", async () => {
      const deduplicator = new RequestDeduplicator(50); // 50ms window
      const requestFn = vi.fn().mockResolvedValue("result");

      // First request
      await deduplicator.deduplicate("key1", requestFn);
      expect(requestFn).toHaveBeenCalledTimes(1);

      // Wait for deduplication window to expire
      await new Promise((resolve) => setTimeout(resolve, 100));

      // Second request with same key should execute
      await deduplicator.deduplicate("key1", requestFn);
      expect(requestFn).toHaveBeenCalledTimes(2);
    });

    it("should handle request errors correctly", async () => {
      const deduplicator = new RequestDeduplicator();
      const error = new Error("Request failed");
      const requestFn = vi.fn().mockRejectedValue(error);

      await expect(deduplicator.deduplicate("key1", requestFn)).rejects.toThrow("Request failed");
    });

    it("should propagate errors to all duplicate requesters", async () => {
      const deduplicator = new RequestDeduplicator();
      let rejectFn: (error: Error) => void;
      const error = new Error("Request failed");
      const requestFn = vi.fn().mockImplementation(() => {
        return new Promise<string>((_, reject) => {
          rejectFn = reject;
        });
      });

      const promise1 = deduplicator.deduplicate("key1", requestFn);
      const promise2 = deduplicator.deduplicate("key1", requestFn);

      rejectFn!(error);

      await expect(promise1).rejects.toThrow("Request failed");
      await expect(promise2).rejects.toThrow("Request failed");
    });
  });

  describe("generateKey", () => {
    it("should generate consistent keys for same parameters", () => {
      const params = {
        method: "POST",
        path: "/api/users",
        body: { name: "John" },
        userId: "user123",
      };

      const key1 = RequestDeduplicator.generateKey(params);
      const key2 = RequestDeduplicator.generateKey(params);

      expect(key1).toBe(key2);
    });

    it("should generate different keys for different methods", () => {
      const key1 = RequestDeduplicator.generateKey({ method: "GET", path: "/api/users" });
      const key2 = RequestDeduplicator.generateKey({ method: "POST", path: "/api/users" });

      expect(key1).not.toBe(key2);
    });

    it("should generate different keys for different paths", () => {
      const key1 = RequestDeduplicator.generateKey({ method: "GET", path: "/api/users" });
      const key2 = RequestDeduplicator.generateKey({ method: "GET", path: "/api/posts" });

      expect(key1).not.toBe(key2);
    });

    it("should generate different keys for different bodies", () => {
      const key1 = RequestDeduplicator.generateKey({
        method: "POST",
        path: "/api/users",
        body: { name: "John" },
      });
      const key2 = RequestDeduplicator.generateKey({
        method: "POST",
        path: "/api/users",
        body: { name: "Jane" },
      });

      expect(key1).not.toBe(key2);
    });

    it("should generate different keys for different users", () => {
      const key1 = RequestDeduplicator.generateKey({
        method: "GET",
        path: "/api/profile",
        userId: "user1",
      });
      const key2 = RequestDeduplicator.generateKey({
        method: "GET",
        path: "/api/profile",
        userId: "user2",
      });

      expect(key1).not.toBe(key2);
    });

    it("should use 'anon' for missing userId", () => {
      const key = RequestDeduplicator.generateKey({ method: "GET", path: "/api/public" });

      expect(key).toContain("anon");
    });

    it("should handle empty body", () => {
      const key1 = RequestDeduplicator.generateKey({ method: "GET", path: "/api/users" });
      const key2 = RequestDeduplicator.generateKey({
        method: "GET",
        path: "/api/users",
        body: undefined,
      });

      expect(key1).toBe(key2);
    });
  });

  describe("hasPendingRequest", () => {
    it("should return true when request is pending", async () => {
      const deduplicator = new RequestDeduplicator();
      let resolveFn: () => void;
      const requestFn = vi.fn().mockImplementation(() => {
        return new Promise<void>((resolve) => {
          resolveFn = resolve;
        });
      });

      deduplicator.deduplicate("key1", requestFn);

      expect(deduplicator.hasPendingRequest("key1")).toBe(true);

      resolveFn!();
      await new Promise((resolve) => setTimeout(resolve, 0));
    });

    it("should return false when no request is pending", () => {
      const deduplicator = new RequestDeduplicator();

      expect(deduplicator.hasPendingRequest("key1")).toBe(false);
    });
  });

  describe("getPendingCount", () => {
    it("should return the number of pending requests", async () => {
      const deduplicator = new RequestDeduplicator();
      let resolveFn1: () => void;
      let resolveFn2: () => void;

      const requestFn1 = vi.fn().mockImplementation(() => {
        return new Promise<void>((resolve) => {
          resolveFn1 = resolve;
        });
      });
      const requestFn2 = vi.fn().mockImplementation(() => {
        return new Promise<void>((resolve) => {
          resolveFn2 = resolve;
        });
      });

      deduplicator.deduplicate("key1", requestFn1);
      expect(deduplicator.getPendingCount()).toBe(1);

      deduplicator.deduplicate("key2", requestFn2);
      expect(deduplicator.getPendingCount()).toBe(2);

      resolveFn1!();
      resolveFn2!();
      await new Promise((resolve) => setTimeout(resolve, 0));
    });
  });

  describe("clear", () => {
    it("should clear all pending requests", async () => {
      const deduplicator = new RequestDeduplicator();
      const requestFn = vi.fn().mockImplementation(() => {
        return new Promise<void>(() => {
          // Never resolves
        });
      });

      deduplicator.deduplicate("key1", requestFn);
      deduplicator.deduplicate("key2", requestFn);

      expect(deduplicator.getPendingCount()).toBe(2);

      deduplicator.clear();

      expect(deduplicator.getPendingCount()).toBe(0);
      expect(deduplicator.hasPendingRequest("key1")).toBe(false);
      expect(deduplicator.hasPendingRequest("key2")).toBe(false);
    });
  });

  describe("default instance", () => {
    it("should be a singleton instance", () => {
      expect(defaultRequestDeduplicator).toBeInstanceOf(RequestDeduplicator);
    });
  });
});
