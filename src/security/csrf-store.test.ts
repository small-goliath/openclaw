/**
 * Tests for CSRF token store adapters
 */

import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  MemoryCsrfStore,
  SqliteCsrfStore,
  createCsrfStore,
  type CsrfTokenEntry,
} from "./csrf-store.js";

describe("CSRF Token Store", () => {
  describe("MemoryCsrfStore", () => {
    let store: MemoryCsrfStore;

    beforeEach(() => {
      store = new MemoryCsrfStore();
    });

    afterEach(async () => {
      await store.close();
    });

    it("should store and retrieve tokens", async () => {
      const entry: CsrfTokenEntry = {
        sessionId: "session-1",
        token: "token-123",
        expiresAt: Date.now() + 3600000,
      };

      await store.set(entry);
      const retrieved = await store.get("session-1");

      expect(retrieved).toEqual(entry);
    });

    it("should return null for non-existent session", async () => {
      const retrieved = await store.get("non-existent");
      expect(retrieved).toBeNull();
    });

    it("should return null for expired tokens", async () => {
      const entry: CsrfTokenEntry = {
        sessionId: "session-1",
        token: "token-123",
        expiresAt: Date.now() - 1000, // Expired
      };

      await store.set(entry);
      const retrieved = await store.get("session-1");

      expect(retrieved).toBeNull();
    });

    it("should delete tokens", async () => {
      const entry: CsrfTokenEntry = {
        sessionId: "session-1",
        token: "token-123",
        expiresAt: Date.now() + 3600000,
      };

      await store.set(entry);
      await store.delete("session-1");

      const retrieved = await store.get("session-1");
      expect(retrieved).toBeNull();
    });

    it("should validate tokens correctly", async () => {
      const token = crypto.randomBytes(32).toString("base64url");
      const entry: CsrfTokenEntry = {
        sessionId: "session-1",
        token,
        expiresAt: Date.now() + 3600000,
      };

      await store.set(entry);

      expect(await store.validate("session-1", token)).toBe(true);
      expect(await store.validate("session-1", "wrong-token")).toBe(false);
      expect(await store.validate("non-existent", token)).toBe(false);
    });

    it("should cleanup expired tokens", async () => {
      const now = Date.now();

      await store.set({
        sessionId: "session-1",
        token: "token-1",
        expiresAt: now + 3600000, // Valid
      });

      await store.set({
        sessionId: "session-2",
        token: "token-2",
        expiresAt: now - 1000, // Expired
      });

      const removed = await store.cleanup();

      expect(removed).toBe(1);
      expect(await store.get("session-1")).not.toBeNull();
      expect(await store.get("session-2")).toBeNull();
    });
  });

  describe("SqliteCsrfStore", () => {
    let store: SqliteCsrfStore;
    let tempDir: string;
    let dbPath: string;

    beforeEach(async () => {
      tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "csrf-test-"));
      dbPath = path.join(tempDir, "csrf-test.db");
      store = new SqliteCsrfStore(dbPath);
      await store.init();
    });

    afterEach(async () => {
      await store.close();
      try {
        fs.rmSync(tempDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup errors
      }
    });

    it("should store and retrieve tokens", async () => {
      const entry: CsrfTokenEntry = {
        sessionId: "session-1",
        token: "token-123",
        expiresAt: Date.now() + 3600000,
      };

      await store.set(entry);
      const retrieved = await store.get("session-1");

      expect(retrieved).toEqual(entry);
    });

    it("should persist tokens across store instances", async () => {
      const entry: CsrfTokenEntry = {
        sessionId: "session-1",
        token: "token-123",
        expiresAt: Date.now() + 3600000,
      };

      await store.set(entry);
      await store.close();

      // Create new store instance with same database
      const newStore = new SqliteCsrfStore(dbPath);
      await newStore.init();

      const retrieved = await newStore.get("session-1");
      expect(retrieved).toEqual(entry);

      await newStore.close();
    });

    it("should update existing tokens", async () => {
      const entry1: CsrfTokenEntry = {
        sessionId: "session-1",
        token: "token-1",
        expiresAt: Date.now() + 3600000,
      };

      const entry2: CsrfTokenEntry = {
        sessionId: "session-1",
        token: "token-2",
        expiresAt: Date.now() + 7200000,
      };

      await store.set(entry1);
      await store.set(entry2);

      const retrieved = await store.get("session-1");
      expect(retrieved?.token).toBe("token-2");
    });

    it("should validate tokens correctly", async () => {
      const token = crypto.randomBytes(32).toString("base64url");
      const entry: CsrfTokenEntry = {
        sessionId: "session-1",
        token,
        expiresAt: Date.now() + 3600000,
      };

      await store.set(entry);

      expect(await store.validate("session-1", token)).toBe(true);
      expect(await store.validate("session-1", "wrong-token")).toBe(false);
    });

    it("should provide statistics", async () => {
      const now = Date.now();

      await store.set({
        sessionId: "session-1",
        token: "token-1",
        expiresAt: now + 3600000,
      });

      await store.set({
        sessionId: "session-2",
        token: "token-2",
        expiresAt: now - 1000,
      });

      const stats = store.getStats();

      expect(stats.total).toBe(2);
      expect(stats.expired).toBe(1);
    });
  });

  describe("createCsrfStore factory", () => {
    it("should create memory store", async () => {
      const store = await createCsrfStore({ type: "memory" });
      expect(store.name).toBe("memory");
      await store.close();
    });

    it("should create sqlite store", async () => {
      const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "csrf-factory-test-"));
      const dbPath = path.join(tempDir, "test.db");

      const store = await createCsrfStore({ type: "sqlite", sqlitePath: dbPath });
      expect(store.name).toBe("sqlite");

      await store.close();
      fs.rmSync(tempDir, { recursive: true, force: true });
    });

    it("should throw for sqlite without path", async () => {
      await expect(createCsrfStore({ type: "sqlite" })).rejects.toThrow("sqlitePath is required");
    });

    it("should throw for unknown store type", async () => {
      await expect(createCsrfStore({ type: "unknown" as "memory" })).rejects.toThrow(
        "Unknown CSRF store type",
      );
    });
  });
});
