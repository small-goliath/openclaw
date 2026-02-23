/**
 * Memory Profiler Utility
 *
 * Provides heap snapshotting and memory leak detection for development mode.
 * Monitors heap growth rate and alerts when potential leaks are detected.
 *
 * @module utils/memory-profiler
 * @see FR-017
 */

import fs from "node:fs";
import path from "node:path";
import v8 from "node:v8";
import { resolvePreferredOpenClawTmpDir } from "../infra/tmp-openclaw-dir.js";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("memory-profiler");

/**
 * Memory snapshot entry
 */
interface MemorySnapshot {
  /** Timestamp when the snapshot was taken */
  timestamp: number;
  /** Heap used in bytes */
  heapUsed: number;
  /** Heap total in bytes */
  heapTotal: number;
  /** RSS in bytes */
  rss: number;
}

/**
 * Memory statistics returned by getStats()
 */
export interface MemoryStats {
  /** Current heap used in bytes */
  currentHeapUsed: number;
  /** Peak heap used in bytes */
  peakHeapUsed: number;
  /** Average heap growth rate in bytes per hour */
  averageGrowthRate: number;
  /** Number of snapshots taken */
  snapshotCount: number;
  /** Duration of profiling in milliseconds */
  durationMs: number;
  /** Whether a potential leak has been detected */
  leakDetected: boolean;
}

/**
 * Configuration options for MemoryProfiler
 */
export interface MemoryProfilerOptions {
  /** Interval between snapshots in milliseconds (default: 60000) */
  intervalMs?: number;
  /** Growth threshold in bytes per hour to trigger leak warning (default: 10MB) */
  growthThresholdBytesPerHour?: number;
  /** Directory to save heap snapshots (default: system temp dir) */
  snapshotDir?: string;
  /** Maximum number of snapshots to keep in memory (default: 1440 - 24 hours at 1 min intervals) */
  maxSnapshots?: number;
  /** Whether to save heap snapshots to disk when leak is detected (default: true) */
  saveSnapshots?: boolean;
}

/**
 * Memory profiler for development mode heap monitoring and leak detection
 *
 * @example
 * ```typescript
 * const profiler = new MemoryProfiler();
 * profiler.startProfiling();
 *
 * // Later...
 * const stats = profiler.getStats();
 * if (stats.leakDetected) {
 *   console.warn('Memory leak detected!');
 * }
 *
 * // Cleanup
 * profiler.stopProfiling();
 * ```
 */
export class MemoryProfiler {
  private snapshots: MemorySnapshot[] = [];
  private snapshotInterval: NodeJS.Timeout | null = null;
  private readonly growthThreshold: number;
  private readonly intervalMs: number;
  private readonly snapshotDir: string;
  private readonly maxSnapshots: number;
  private readonly saveSnapshots: boolean;
  private startTime: number | null = null;
  private lastWarningTime: number = 0;
  private readonly warningCooldownMs = 5 * 60 * 1000; // 5 minutes between warnings

  constructor(options: MemoryProfilerOptions = {}) {
    this.intervalMs = options.intervalMs ?? 60000; // Default: 1 minute
    this.growthThreshold = options.growthThresholdBytesPerHour ?? 10 * 1024 * 1024; // Default: 10MB/hour
    this.snapshotDir =
      options.snapshotDir ?? path.join(resolvePreferredOpenClawTmpDir(), "heap-snapshots");
    this.maxSnapshots = options.maxSnapshots ?? 1440; // 24 hours at 1 min intervals
    this.saveSnapshots = options.saveSnapshots ?? true;
  }

  /**
   * Start memory profiling
   */
  startProfiling(): void {
    if (this.snapshotInterval) {
      log.warn("Memory profiling already started");
      return;
    }

    this.startTime = Date.now();
    this.snapshots = [];

    // Take initial snapshot
    this.takeSnapshot();

    this.snapshotInterval = setInterval(() => {
      this.takeSnapshot();
      this.checkForLeak();
    }, this.intervalMs);

    log.info(
      `Memory profiling started (interval: ${this.intervalMs}ms, threshold: ${this.formatBytes(this.growthThreshold)}/hour)`,
    );
  }

  /**
   * Stop memory profiling
   */
  stopProfiling(): void {
    if (this.snapshotInterval) {
      clearInterval(this.snapshotInterval);
      this.snapshotInterval = null;
      log.info("Memory profiling stopped");
    }
  }

  /**
   * Check if profiling is active
   */
  isProfiling(): boolean {
    return this.snapshotInterval !== null;
  }

  /**
   * Get current memory statistics
   */
  getStats(): MemoryStats {
    const current = process.memoryUsage();
    const peakHeapUsed =
      this.snapshots.length > 0
        ? Math.max(...this.snapshots.map((s) => s.heapUsed))
        : current.heapUsed;

    const durationMs = this.startTime ? Date.now() - this.startTime : 0;
    const averageGrowthRate = this.calculateGrowthRate();

    return {
      currentHeapUsed: current.heapUsed,
      peakHeapUsed,
      averageGrowthRate,
      snapshotCount: this.snapshots.length,
      durationMs,
      leakDetected: averageGrowthRate > this.growthThreshold,
    };
  }

  /**
   * Force a heap snapshot to be saved to disk
   */
  forceHeapSnapshot(): string | null {
    return this.saveHeapSnapshot("forced");
  }

  /**
   * Get all snapshots (for debugging)
   */
  getSnapshots(): ReadonlyArray<MemorySnapshot> {
    return [...this.snapshots];
  }

  private takeSnapshot(): void {
    const usage = process.memoryUsage();
    const snapshot: MemorySnapshot = {
      timestamp: Date.now(),
      heapUsed: usage.heapUsed,
      heapTotal: usage.heapTotal,
      rss: usage.rss,
    };

    this.snapshots.push(snapshot);

    // Keep only the most recent snapshots to prevent memory bloat
    if (this.snapshots.length > this.maxSnapshots) {
      this.snapshots.shift();
    }

    log.debug(
      `Snapshot taken: heapUsed=${this.formatBytes(snapshot.heapUsed)}, rss=${this.formatBytes(snapshot.rss)}`,
    );
  }

  private checkForLeak(): void {
    if (this.snapshots.length < 2) {
      return;
    }

    const growthRate = this.calculateGrowthRate();

    if (growthRate > this.growthThreshold) {
      const now = Date.now();
      const increaseSinceLast =
        this.snapshots[this.snapshots.length - 1].heapUsed - this.snapshots[0].heapUsed;

      // Only warn every 5 minutes to avoid spam
      if (now - this.lastWarningTime > this.warningCooldownMs) {
        this.lastWarningTime = now;
        log.warn(
          `Potential memory leak detected: heap growing at ${this.formatBytes(growthRate)}/hour ` +
            `(increase: ${this.formatBytes(increaseSinceLast)} over ${this.snapshots.length} snapshots)`,
        );

        if (this.saveSnapshots) {
          this.saveHeapSnapshot("leak-detected");
        }
      }
    }
  }

  private calculateGrowthRate(): number {
    if (this.snapshots.length < 2) {
      return 0;
    }

    const first = this.snapshots[0];
    const last = this.snapshots[this.snapshots.length - 1];
    const durationMs = last.timestamp - first.timestamp;

    if (durationMs === 0) {
      return 0;
    }

    const heapIncrease = last.heapUsed - first.heapUsed;
    const hoursElapsed = durationMs / (60 * 60 * 1000);

    if (hoursElapsed === 0) {
      return 0;
    }

    return heapIncrease / hoursElapsed;
  }

  private saveHeapSnapshot(reason: string): string | null {
    try {
      // Ensure directory exists
      fs.mkdirSync(this.snapshotDir, { recursive: true });

      const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
      const filename = `heap-${reason}-${timestamp}.heapsnapshot`;
      const filepath = path.join(this.snapshotDir, filename);

      const snapshot = v8.writeHeapSnapshot(filepath);
      log.info(`Heap snapshot saved: ${snapshot}`);
      return snapshot;
    } catch (error) {
      log.error(
        `Failed to save heap snapshot: ${error instanceof Error ? error.message : String(error)}`,
      );
      return null;
    }
  }

  private formatBytes(bytes: number): string {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
  }
}

/**
 * Global memory profiler instance for singleton access
 */
let globalProfiler: MemoryProfiler | null = null;

/**
 * Get or create the global memory profiler instance
 */
export function getGlobalMemoryProfiler(): MemoryProfiler {
  if (!globalProfiler) {
    globalProfiler = new MemoryProfiler();
  }
  return globalProfiler;
}

/**
 * Check if running in development mode
 */
export function isDevelopmentMode(): boolean {
  return process.env.NODE_ENV === "development" || process.env.OPENCLAW_DEV === "1";
}

/**
 * Initialize memory profiling in development mode
 */
export function initMemoryProfilingInDev(): void {
  if (!isDevelopmentMode()) {
    return;
  }

  const profiler = getGlobalMemoryProfiler();

  if (profiler.isProfiling()) {
    return;
  }

  // Parse interval from env if provided
  const intervalMs = process.env.OPENCLAW_MEMORY_PROFILE_INTERVAL_MS
    ? parseInt(process.env.OPENCLAW_MEMORY_PROFILE_INTERVAL_MS, 10)
    : undefined;

  // Parse threshold from env if provided
  const growthThreshold = process.env.OPENCLAW_MEMORY_THRESHOLD_BYTES
    ? parseInt(process.env.OPENCLAW_MEMORY_THRESHOLD_BYTES, 10)
    : undefined;

  const options: MemoryProfilerOptions = {
    intervalMs,
    growthThresholdBytesPerHour: growthThreshold,
  };

  // Create new profiler with custom options if needed
  if (intervalMs || growthThreshold) {
    globalProfiler = new MemoryProfiler(options);
    globalProfiler.startProfiling();
  } else {
    profiler.startProfiling();
  }

  // Handle graceful shutdown
  const cleanup = (): void => {
    getGlobalMemoryProfiler().stopProfiling();
  };

  process.once("SIGINT", cleanup);
  process.once("SIGTERM", cleanup);
  process.once("beforeExit", cleanup);
}
