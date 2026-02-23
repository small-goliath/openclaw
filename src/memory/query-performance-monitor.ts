import type { QueryPerformanceStats } from "./types.js";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("memory/query-perf");

/**
 * Query execution time histogram entry
 */
type QueryHistogramEntry = {
  durations: number[];
  totalCount: number;
  slowCount: number;
  errorCount: number;
};

/**
 * Configuration for query performance monitoring
 */
type QueryPerformanceConfig = {
  /** Threshold in ms for slow query detection (default: 1000ms) */
  slowQueryThreshold: number;
  /** Maximum number of durations to keep per query type (default: 1000) */
  maxHistogramSize: number;
  /** Enable SIEM integration for slow queries (default: false) */
  enableSiemIntegration: boolean;
};

/**
 * Monitors database query performance, tracks execution times,
 * detects slow queries, and exports performance statistics.
 */
export class QueryPerformanceMonitor {
  private slowQueryThreshold: number;
  private maxHistogramSize: number;
  private enableSiemIntegration: boolean;
  private queryHistogram = new Map<string, QueryHistogramEntry>();

  constructor(config?: Partial<QueryPerformanceConfig>) {
    this.slowQueryThreshold = config?.slowQueryThreshold ?? 1000; // 1 second
    this.maxHistogramSize = config?.maxHistogramSize ?? 1000;
    this.enableSiemIntegration = config?.enableSiemIntegration ?? false;
  }

  /**
   * Monitor a database query execution time
   * @param queryName - Name of the query for categorization
   * @param queryFn - Async function that executes the query
   * @returns Result of the query function
   */
  async monitorQuery<T>(queryName: string, queryFn: () => Promise<T>): Promise<T> {
    const start = performance.now();
    try {
      const result = await queryFn();
      const duration = performance.now() - start;

      this.recordQueryTime(queryName, duration, false);

      if (duration > this.slowQueryThreshold) {
        log.warn(`Slow query detected: ${queryName}`, {
          duration,
          threshold: this.slowQueryThreshold,
          queryName,
        });

        if (this.enableSiemIntegration) {
          this.sendToSiem(queryName, duration, null);
        }
      }

      return result;
    } catch (error) {
      const duration = performance.now() - start;
      this.recordQueryTime(queryName, duration, true);

      log.error(`Query failed: ${queryName}`, {
        duration,
        error: error instanceof Error ? error.message : String(error),
        queryName,
      });

      throw error;
    }
  }

  /**
   * Record query execution time in the histogram
   */
  private recordQueryTime(queryName: string, duration: number, isError: boolean): void {
    let entry = this.queryHistogram.get(queryName);
    if (!entry) {
      entry = {
        durations: [],
        totalCount: 0,
        slowCount: 0,
        errorCount: 0,
      };
      this.queryHistogram.set(queryName, entry);
    }

    entry.totalCount++;

    if (isError) {
      entry.errorCount++;
    } else {
      entry.durations.push(duration);

      // Keep histogram size bounded
      if (entry.durations.length > this.maxHistogramSize) {
        entry.durations.shift();
      }

      if (duration > this.slowQueryThreshold) {
        entry.slowCount++;
      }
    }
  }

  /**
   * Send slow query alert to SIEM system
   */
  private sendToSiem(queryName: string, duration: number, error: Error | null): void {
    // SIEM integration placeholder
    // In production, this would send to your SIEM (e.g., Splunk, ELK, Datadog)
    const siemPayload = {
      eventType: "slow_query",
      timestamp: new Date().toISOString(),
      queryName,
      duration,
      threshold: this.slowQueryThreshold,
      error: error?.message ?? null,
      severity: duration > this.slowQueryThreshold * 2 ? "high" : "medium",
    };

    // Log for now - replace with actual SIEM integration
    log.debug("SIEM alert payload", siemPayload);
  }

  /**
   * Calculate percentile from sorted array of numbers
   */
  private calculatePercentile(sortedValues: number[], percentile: number): number {
    if (sortedValues.length === 0) {
      return 0;
    }

    const index = Math.ceil((percentile / 100) * sortedValues.length) - 1;
    return sortedValues[Math.max(0, index)];
  }

  /**
   * Get performance statistics for all monitored queries
   * @returns Array of performance stats per query type
   */
  getPerformanceStats(): QueryPerformanceStats[] {
    const stats: QueryPerformanceStats[] = [];

    for (const [queryName, entry] of this.queryHistogram.entries()) {
      if (entry.durations.length === 0) {
        stats.push({
          queryName,
          count: entry.totalCount,
          avg: 0,
          p95: 0,
          p99: 0,
          max: 0,
          min: 0,
          slowQueries: entry.slowCount,
        });
        continue;
      }

      const sorted = [...entry.durations].sort((a, b) => a - b);
      const sum = sorted.reduce((acc, val) => acc + val, 0);

      stats.push({
        queryName,
        count: entry.totalCount,
        avg: sum / sorted.length,
        p95: this.calculatePercentile(sorted, 95),
        p99: this.calculatePercentile(sorted, 99),
        max: sorted[sorted.length - 1],
        min: sorted[0],
        slowQueries: entry.slowCount,
      });
    }

    return stats;
  }

  /**
   * Get performance statistics for a specific query type
   */
  getQueryStats(queryName: string): QueryPerformanceStats | null {
    const entry = this.queryHistogram.get(queryName);
    if (!entry) {
      return null;
    }

    if (entry.durations.length === 0) {
      return {
        queryName,
        count: entry.totalCount,
        avg: 0,
        p95: 0,
        p99: 0,
        max: 0,
        min: 0,
        slowQueries: entry.slowCount,
      };
    }

    const sorted = [...entry.durations].sort((a, b) => a - b);
    const sum = sorted.reduce((acc, val) => acc + val, 0);

    return {
      queryName,
      count: entry.totalCount,
      avg: sum / sorted.length,
      p95: this.calculatePercentile(sorted, 95),
      p99: this.calculatePercentile(sorted, 99),
      max: sorted[sorted.length - 1],
      min: sorted[0],
      slowQueries: entry.slowCount,
    };
  }

  /**
   * Get total number of monitored queries
   */
  getTotalQueryCount(): number {
    let total = 0;
    for (const entry of this.queryHistogram.values()) {
      total += entry.totalCount;
    }
    return total;
  }

  /**
   * Get number of slow queries detected
   */
  getSlowQueryCount(): number {
    let total = 0;
    for (const entry of this.queryHistogram.values()) {
      total += entry.slowCount;
    }
    return total;
  }

  /**
   * Get number of failed queries
   */
  getErrorCount(): number {
    let total = 0;
    for (const entry of this.queryHistogram.values()) {
      total += entry.errorCount;
    }
    return total;
  }

  /**
   * Reset all performance statistics
   */
  reset(): void {
    this.queryHistogram.clear();
    log.info("Query performance statistics reset");
  }

  /**
   * Get histogram data for a specific query type (for advanced analysis)
   */
  getHistogramData(queryName: string): number[] | null {
    const entry = this.queryHistogram.get(queryName);
    return entry ? [...entry.durations] : null;
  }
}

export type { QueryPerformanceConfig };
