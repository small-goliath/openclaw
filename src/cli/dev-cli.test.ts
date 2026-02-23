/**
 * Development CLI Tests
 *
 * @module cli/dev-cli.test
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { runDevHeapStatus, runDevHeapSnapshot } from "./dev-cli.js";
import { getGlobalMemoryProfiler } from "../utils/memory-profiler.js";

describe("runDevHeapStatus", () => {
  beforeEach(() => {
    getGlobalMemoryProfiler().stopProfiling();
  });

  afterEach(() => {
    getGlobalMemoryProfiler().stopProfiling();
  });

  it("should output JSON when --json flag is set", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runDevHeapStatus({ json: true });
    expect(consoleSpy).toHaveBeenCalled();
    const output = consoleSpy.mock.calls[0][0];
    const parsed = JSON.parse(output as string);
    expect(parsed).toHaveProperty("currentHeapUsed");
    expect(parsed).toHaveProperty("peakHeapUsed");
    expect(parsed).toHaveProperty("snapshotCount");
    expect(parsed).toHaveProperty("isProfiling");
    expect(parsed).toHaveProperty("isDevelopmentMode");
    consoleSpy.mockRestore();
  });

  it("should output formatted text by default", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runDevHeapStatus({});
    expect(consoleSpy).toHaveBeenCalled();
    const output = consoleSpy.mock.calls[0][0];
    expect(typeof output).toBe("string");
    expect(output).toContain("Heap Memory Status");
    consoleSpy.mockRestore();
  });
});

describe("runDevHeapSnapshot", () => {
  it("should output JSON when --json flag is set", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runDevHeapSnapshot({ json: true });
    expect(consoleSpy).toHaveBeenCalled();
    const output = consoleSpy.mock.calls[0][0];
    const parsed = JSON.parse(output as string);
    expect(parsed).toHaveProperty("snapshotPath");
    expect(parsed).toHaveProperty("success");
    consoleSpy.mockRestore();
  });

  it("should output formatted text by default", async () => {
    const consoleSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    await runDevHeapSnapshot({});
    expect(consoleSpy).toHaveBeenCalled();
    const output = consoleSpy.mock.calls[0][0];
    expect(typeof output).toBe("string");
    consoleSpy.mockRestore();
  });
});
