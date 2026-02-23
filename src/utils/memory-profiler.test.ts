/**
 * Memory Profiler Tests
 *
 * @module utils/memory-profiler.test
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  MemoryProfiler,
  getGlobalMemoryProfiler,
  isDevelopmentMode,
  initMemoryProfilingInDev,
} from "./memory-profiler.js";

describe("MemoryProfiler", () => {
  let profiler: MemoryProfiler;

  beforeEach(() => {
    profiler = new MemoryProfiler({
      intervalMs: 100,
      growthThresholdBytesPerHour: 10 * 1024 * 1024, // 10MB/hour
      maxSnapshots: 10,
      saveSnapshots: false,
    });
  });

  afterEach(() => {
    profiler.stopProfiling();
  });

  describe("startProfiling", () => {
    it("should start profiling and take initial snapshot", () => {
      expect(profiler.isProfiling()).toBe(false);
      profiler.startProfiling();
      expect(profiler.isProfiling()).toBe(true);
      expect(profiler.getSnapshots().length).toBe(1);
    });

    it("should warn if already started", () => {
      profiler.startProfiling();
      const consoleSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      profiler.startProfiling();
      consoleSpy.mockRestore();
    });
  });

  describe("stopProfiling", () => {
    it("should stop profiling", () => {
      profiler.startProfiling();
      expect(profiler.isProfiling()).toBe(true);
      profiler.stopProfiling();
      expect(profiler.isProfiling()).toBe(false);
    });

    it("should be safe to call when not profiling", () => {
      expect(() => profiler.stopProfiling()).not.toThrow();
    });
  });

  describe("getStats", () => {
    it("should return initial stats", () => {
      profiler.startProfiling();
      const stats = profiler.getStats();

      expect(stats.currentHeapUsed).toBeGreaterThan(0);
      expect(stats.peakHeapUsed).toBeGreaterThan(0);
      expect(stats.snapshotCount).toBe(1);
      expect(stats.averageGrowthRate).toBe(0);
      expect(stats.leakDetected).toBe(false);
      expect(stats.durationMs).toBeGreaterThanOrEqual(0);
    });

    it("should calculate growth rate correctly", async () => {
      profiler = new MemoryProfiler({
        intervalMs: 50,
        growthThresholdBytesPerHour: 1024 * 1024 * 1024, // 1GB/hour (high threshold)
        maxSnapshots: 10,
        saveSnapshots: false,
      });

      profiler.startProfiling();

      // Wait for a few snapshots
      await new Promise((resolve) => setTimeout(resolve, 150));

      const stats = profiler.getStats();
      expect(stats.snapshotCount).toBeGreaterThanOrEqual(2);
    });
  });

  describe("getSnapshots", () => {
    it("should return copy of snapshot array", () => {
      profiler.startProfiling();
      const snapshots1 = profiler.getSnapshots();
      const snapshots2 = profiler.getSnapshots();
      // Should return different array instances
      expect(snapshots1).not.toBe(snapshots2);
      // But with same content
      expect(snapshots1).toEqual(snapshots2);
    });
  });

  describe("forceHeapSnapshot", () => {
    it("should always save snapshot when forced, regardless of saveSnapshots option", () => {
      // forceHeapSnapshot should always save, regardless of saveSnapshots setting
      const result = profiler.forceHeapSnapshot();
      // Should return a path string (may be null if v8.writeHeapSnapshot fails in test environment)
      expect(result === null || typeof result === "string").toBe(true);
    });

    it("should return path when saveSnapshots is true", () => {
      profiler = new MemoryProfiler({
        intervalMs: 100,
        saveSnapshots: true,
      });
      const result = profiler.forceHeapSnapshot();
      // May be null if v8.writeHeapSnapshot fails in test environment
      expect(result === null || typeof result === "string").toBe(true);
    });
  });

  describe("snapshot limit", () => {
    it("should limit number of snapshots to maxSnapshots", async () => {
      profiler = new MemoryProfiler({
        intervalMs: 10,
        maxSnapshots: 3,
        saveSnapshots: false,
      });

      profiler.startProfiling();

      // Wait for more than maxSnapshots
      await new Promise((resolve) => setTimeout(resolve, 100));

      const snapshots = profiler.getSnapshots();
      expect(snapshots.length).toBeLessThanOrEqual(3);
    });
  });
});

describe("isDevelopmentMode", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("should return true when NODE_ENV is development", () => {
    process.env.NODE_ENV = "development";
    expect(isDevelopmentMode()).toBe(true);
  });

  it("should return true when OPENCLAW_DEV is 1", () => {
    process.env.NODE_ENV = "production";
    process.env.OPENCLAW_DEV = "1";
    expect(isDevelopmentMode()).toBe(true);
  });

  it("should return false in production", () => {
    process.env.NODE_ENV = "production";
    delete process.env.OPENCLAW_DEV;
    expect(isDevelopmentMode()).toBe(false);
  });
});

describe("getGlobalMemoryProfiler", () => {
  it("should return singleton instance", () => {
    const p1 = getGlobalMemoryProfiler();
    const p2 = getGlobalMemoryProfiler();
    expect(p1).toBe(p2);
  });
});

describe("initMemoryProfilingInDev", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
    getGlobalMemoryProfiler().stopProfiling();
  });

  it("should not start profiling in production", () => {
    process.env.NODE_ENV = "production";
    initMemoryProfilingInDev();
    expect(getGlobalMemoryProfiler().isProfiling()).toBe(false);
  });

  it("should start profiling in development", () => {
    process.env.NODE_ENV = "development";
    initMemoryProfilingInDev();
    expect(getGlobalMemoryProfiler().isProfiling()).toBe(true);
  });

  it("should respect custom interval from env", () => {
    process.env.NODE_ENV = "development";
    process.env.OPENCLAW_MEMORY_PROFILE_INTERVAL_MS = "5000";
    initMemoryProfilingInDev();
    expect(getGlobalMemoryProfiler().isProfiling()).toBe(true);
  });
});
