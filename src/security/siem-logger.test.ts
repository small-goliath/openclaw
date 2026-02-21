/**
 * SIEM Logger Tests
 *
 * @module security/siem-logger.test
 */

import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createSecurityEvent, createAuthFailureEvent, type SiemConfig } from "./security-events.js";
import {
  SiemLogger,
  initializeSiemLogger,
  getSiemLogger,
  shutdownSiemLogger,
  logSecurityEvent,
  alertCriticalEvent,
} from "./siem-logger.js";

describe("SiemLogger", () => {
  let tempDir: string;
  let logger: SiemLogger;

  beforeEach(async () => {
    tempDir = await mkdtemp(join(tmpdir(), "siem-test-"));
  });

  afterEach(async () => {
    if (logger) {
      await logger.shutdown();
    }
    await shutdownSiemLogger();
    await rm(tempDir, { recursive: true, force: true });
  });

  describe("Initialization", () => {
    it("should initialize with enabled config", async () => {
      logger = new SiemLogger({ enabled: true, outputs: [] }, "1.0.0");
      await logger.initialize();

      expect(logger.getStatus()).toBe("running");
    });

    it("should not initialize when disabled", async () => {
      logger = new SiemLogger({ enabled: false }, "1.0.0");
      await logger.initialize();

      expect(logger.getStatus()).toBe("idle");
    });

    it("should generate correlation ID", () => {
      logger = new SiemLogger({}, "1.0.0");
      const correlationId = logger.getCorrelationId();

      expect(correlationId).toBeDefined();
      expect(typeof correlationId).toBe("string");
      expect(correlationId.length).toBeGreaterThan(0);
    });

    it("should generate new correlation ID", () => {
      logger = new SiemLogger({}, "1.0.0");
      const oldId = logger.getCorrelationId();
      const newId = logger.newCorrelationId();

      expect(newId).not.toBe(oldId);
      expect(logger.getCorrelationId()).toBe(newId);
    });
  });

  describe("File Output", () => {
    it("should write events to file", async () => {
      const logFile = join(tempDir, "security.log");
      const config: Partial<SiemConfig> = {
        enabled: true,
        outputs: [
          {
            type: "file",
            enabled: true,
            path: logFile,
          },
        ],
      };

      logger = new SiemLogger(config, "1.0.0");
      await logger.initialize();

      const event = createAuthFailureEvent(
        {
          authMethod: "token",
          failureReason: "invalid_credentials",
        },
        { component: "test" },
      );

      await logger.log(event);
      await logger.flush();

      const content = await readFile(logFile, "utf-8");
      const parsed = JSON.parse(content.trim());

      expect(parsed.eventType).toBe("AUTH_FAILURE");
      expect(parsed.severity).toBe("high");
    });

    it("should filter events by severity", async () => {
      const logFile = join(tempDir, "security.log");
      const config: Partial<SiemConfig> = {
        enabled: true,
        outputs: [
          {
            type: "file",
            enabled: true,
            path: logFile,
            minSeverity: "high",
          },
        ],
      };

      logger = new SiemLogger(config, "1.0.0");
      await logger.initialize();

      const highEvent = createSecurityEvent(
        {
          eventType: "AUTH_FAILURE",
          severity: "high",
          details: { authMethod: "token", success: false },
          component: "test",
        },
        "1.0.0",
      );

      const lowEvent = createSecurityEvent(
        {
          eventType: "AUTH_SUCCESS",
          severity: "low",
          details: { authMethod: "token", success: true },
          component: "test",
        },
        "1.0.0",
      );

      await logger.log(highEvent);
      await logger.log(lowEvent);
      await logger.flush();

      const content = await readFile(logFile, "utf-8");
      const lines = content.trim().split("\n");

      expect(lines.length).toBe(1);
      const parsed = JSON.parse(lines[0]);
      expect(parsed.severity).toBe("high");
    });

    it("should filter events by type", async () => {
      const logFile = join(tempDir, "security.log");
      const config: Partial<SiemConfig> = {
        enabled: true,
        outputs: [
          {
            type: "file",
            enabled: true,
            path: logFile,
            eventTypes: ["AUTH_FAILURE"],
          },
        ],
      };

      logger = new SiemLogger(config, "1.0.0");
      await logger.initialize();

      const authFailure = createAuthFailureEvent(
        { authMethod: "token", failureReason: "invalid_credentials" },
        { component: "test" },
      );

      const authSuccess = createSecurityEvent(
        {
          eventType: "AUTH_SUCCESS",
          severity: "info",
          details: { authMethod: "token", success: true },
          component: "test",
        },
        "1.0.0",
      );

      await logger.log(authFailure);
      await logger.log(authSuccess);
      await logger.flush();

      const content = await readFile(logFile, "utf-8");
      const lines = content.trim().split("\n");

      expect(lines.length).toBe(1);
      const parsed = JSON.parse(lines[0]);
      expect(parsed.eventType).toBe("AUTH_FAILURE");
    });
  });

  describe("Buffering", () => {
    it("should buffer events until flush", async () => {
      const logFile = join(tempDir, "security.log");
      const config: Partial<SiemConfig> = {
        enabled: true,
        bufferSize: 10,
        flushIntervalMs: 60000, // Long interval to prevent auto-flush
        outputs: [
          {
            type: "file",
            enabled: true,
            path: logFile,
          },
        ],
      };

      logger = new SiemLogger(config, "1.0.0");
      await logger.initialize();

      const event = createAuthFailureEvent(
        { authMethod: "token", failureReason: "invalid_credentials" },
        { component: "test" },
      );

      await logger.log(event);

      // Event is in buffer only, not in file yet
      expect(logger.getBufferSize()).toBe(1);

      // File should be empty (before flush) - check if file exists
      try {
        const content = await readFile(logFile, "utf-8");
        expect(content.trim()).toBe("");
      } catch {
        // File doesn't exist yet, which is expected
      }

      // Manual flush
      await logger.flush();

      expect(logger.getBufferSize()).toBe(0);

      const content = await readFile(logFile, "utf-8");
      expect(content).toContain("AUTH_FAILURE");
    });

    it("should auto-flush when buffer is full", async () => {
      const logFile = join(tempDir, "security.log");
      const config: Partial<SiemConfig> = {
        enabled: true,
        bufferSize: 3,
        flushIntervalMs: 60000,
        outputs: [
          {
            type: "file",
            enabled: true,
            path: logFile,
          },
        ],
      };

      logger = new SiemLogger(config, "1.0.0");
      await logger.initialize();

      // Add 3 events (same as buffer size)
      for (let i = 0; i < 3; i++) {
        const event = createAuthFailureEvent(
          { authMethod: "token", failureReason: `attempt_${i}` },
          { component: "test" },
        );
        await logger.log(event);
      }

      // Buffer is full, auto-flushed
      expect(logger.getBufferSize()).toBe(0);

      const content = await readFile(logFile, "utf-8");
      const lines = content.trim().split("\n");
      expect(lines.length).toBe(3);
    });
  });

  describe("Pause and Resume", () => {
    it("should pause and resume logging", async () => {
      const logFile = join(tempDir, "security.log");
      const config: Partial<SiemConfig> = {
        enabled: true,
        outputs: [
          {
            type: "file",
            enabled: true,
            path: logFile,
          },
        ],
      };

      logger = new SiemLogger(config, "1.0.0");
      await logger.initialize();

      expect(logger.getStatus()).toBe("running");

      // Log event before pause
      const event = createAuthFailureEvent(
        { authMethod: "token", failureReason: "test" },
        { component: "test" },
      );
      await logger.log(event);

      logger.pause();
      expect(logger.getStatus()).toBe("paused");

      // Events logged while paused are ignored
      const ignoredEvent = createAuthFailureEvent(
        { authMethod: "token", failureReason: "ignored" },
        { component: "test" },
      );
      await logger.log(ignoredEvent);

      logger.resume();
      expect(logger.getStatus()).toBe("running");

      await logger.flush();

      const content = await readFile(logFile, "utf-8");
      expect(content).toContain("test");
      expect(content).not.toContain("ignored");
    });
  });

  describe("Shutdown", () => {
    it("should flush remaining events on shutdown", async () => {
      const logFile = join(tempDir, "security.log");
      const config: Partial<SiemConfig> = {
        enabled: true,
        bufferSize: 100,
        flushIntervalMs: 60000,
        outputs: [
          {
            type: "file",
            enabled: true,
            path: logFile,
          },
        ],
      };

      logger = new SiemLogger(config, "1.0.0");
      await logger.initialize();

      const event = createAuthFailureEvent(
        { authMethod: "token", failureReason: "shutdown_test" },
        { component: "test" },
      );

      await logger.log(event);
      expect(logger.getBufferSize()).toBe(1);

      await logger.shutdown();

      expect(logger.getStatus()).toBe("idle");

      const content = await readFile(logFile, "utf-8");
      expect(content).toContain("shutdown_test");
    });
  });

  describe("Config Update", () => {
    it("should update config and reinitialize", async () => {
      const logFile1 = join(tempDir, "security1.log");
      const logFile2 = join(tempDir, "security2.log");

      const config: Partial<SiemConfig> = {
        enabled: true,
        outputs: [
          {
            type: "file",
            enabled: true,
            path: logFile1,
          },
        ],
      };

      logger = new SiemLogger(config, "1.0.0");
      await logger.initialize();

      const event1 = createAuthFailureEvent(
        { authMethod: "token", failureReason: "file1" },
        { component: "test" },
      );
      await logger.log(event1);
      await logger.flush();

      // Update config
      await logger.updateConfig({
        outputs: [
          {
            type: "file",
            enabled: true,
            path: logFile2,
          },
        ],
      });

      const event2 = createAuthFailureEvent(
        { authMethod: "token", failureReason: "file2" },
        { component: "test" },
      );
      await logger.log(event2);
      await logger.flush();

      // File 1 only has event1
      const content1 = await readFile(logFile1, "utf-8");
      expect(content1).toContain("file1");
      expect(content1).not.toContain("file2");

      // File 2 only has event2
      const content2 = await readFile(logFile2, "utf-8");
      expect(content2).toContain("file2");
      expect(content2).not.toContain("file1");
    });
  });

  describe("Global Instance", () => {
    it("should manage global SIEM logger instance", async () => {
      const logFile = join(tempDir, "global.log");

      const logger1 = await initializeSiemLogger(
        {
          enabled: true,
          outputs: [
            {
              type: "file",
              enabled: true,
              path: logFile,
            },
          ],
        },
        "1.0.0",
      );

      expect(getSiemLogger()).toBe(logger1);

      // Re-initialization replaces with new instance
      const logger2 = await initializeSiemLogger(
        {
          enabled: true,
          outputs: [
            {
              type: "file",
              enabled: true,
              path: logFile,
            },
          ],
        },
        "1.0.0",
      );

      expect(getSiemLogger()).toBe(logger2);
      expect(logger1).not.toBe(logger2);

      // Shutdown
      await shutdownSiemLogger();
      expect(getSiemLogger()).toBeNull();
    });

    it("should log events through global instance", async () => {
      const logFile = join(tempDir, "global.log");

      await initializeSiemLogger(
        {
          enabled: true,
          outputs: [
            {
              type: "file",
              enabled: true,
              path: logFile,
            },
          ],
        },
        "1.0.0",
      );

      const event = createAuthFailureEvent(
        { authMethod: "token", failureReason: "global_test" },
        { component: "test" },
      );

      await logSecurityEvent(event);
      await getSiemLogger()?.flush();

      const content = await readFile(logFile, "utf-8");
      expect(content).toContain("global_test");
    });

    it("should alert critical events immediately", async () => {
      const logFile = join(tempDir, "global.log");

      await initializeSiemLogger(
        {
          enabled: true,
          bufferSize: 100,
          flushIntervalMs: 60000,
          outputs: [
            {
              type: "file",
              enabled: true,
              path: logFile,
            },
          ],
        },
        "1.0.0",
      );

      const event = createSecurityEvent(
        {
          eventType: "ACCESS_VIOLATION",
          severity: "critical",
          details: {
            resource: "/admin",
            action: "delete",
            violationType: "unauthorized_access",
          },
          component: "test",
        },
        "1.0.0",
      );

      await alertCriticalEvent(event);
      // alertCriticalEvent flushes immediately, no need to call flush()

      const content = await readFile(logFile, "utf-8");
      expect(content).toContain("ACCESS_VIOLATION");
      expect(content).toContain("critical");
    });
  });

  describe("Multiple Outputs", () => {
    it("should send events to multiple outputs", async () => {
      const logFile1 = join(tempDir, "output1.log");
      const logFile2 = join(tempDir, "output2.log");

      const config: Partial<SiemConfig> = {
        enabled: true,
        outputs: [
          {
            type: "file",
            enabled: true,
            path: logFile1,
          },
          {
            type: "file",
            enabled: true,
            path: logFile2,
          },
        ],
      };

      logger = new SiemLogger(config, "1.0.0");
      await logger.initialize();

      const event = createAuthFailureEvent(
        { authMethod: "token", failureReason: "multi_output" },
        { component: "test" },
      );

      await logger.log(event);
      await logger.flush();

      const content1 = await readFile(logFile1, "utf-8");
      const content2 = await readFile(logFile2, "utf-8");

      expect(content1).toContain("multi_output");
      expect(content2).toContain("multi_output");
    });

    it("should handle partial failures gracefully", async () => {
      const validLogFile = join(tempDir, "valid.log");
      const invalidLogFile = join(tempDir, "nonexistent", "invalid.log");

      const config: Partial<SiemConfig> = {
        enabled: true,
        outputs: [
          {
            type: "file",
            enabled: true,
            path: validLogFile,
          },
          {
            type: "file",
            enabled: true,
            path: invalidLogFile, // Non-existent directory
          },
        ],
      };

      logger = new SiemLogger(config, "1.0.0");
      await logger.initialize();

      const event = createAuthFailureEvent(
        { authMethod: "token", failureReason: "partial_failure" },
        { component: "test" },
      );

      // One output fails but no exception is thrown
      await expect(logger.log(event)).resolves.not.toThrow();

      // Valid file has the log
      await logger.flush();
      const content = await readFile(validLogFile, "utf-8");
      expect(content).toContain("partial_failure");
    });
  });
});
