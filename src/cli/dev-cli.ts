/**
 * Development CLI Commands
 *
 * Provides development utilities including memory profiling and heap snapshots.
 *
 * @module cli/dev-cli
 * @see FR-017
 */

import type { Command } from "commander";
import { getGlobalMemoryProfiler, isDevelopmentMode } from "../utils/memory-profiler.js";
import { defaultRuntime } from "../runtime.js";
import { colorize, isRich, theme } from "../terminal/theme.js";
import { formatDocsLink } from "../terminal/links.js";
import { setVerbose } from "../globals.js";

type DevHeapOptions = {
  json?: boolean;
  snapshot?: boolean;
  verbose?: boolean;
};

/**
 * Format bytes to human readable string
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

/**
 * Run heap status command
 */
export async function runDevHeapStatus(opts: DevHeapOptions): Promise<void> {
  setVerbose(Boolean(opts.verbose));

  const profiler = getGlobalMemoryProfiler();
  const stats = profiler.getStats();

  if (opts.json) {
    defaultRuntime.log(JSON.stringify({
      ...stats,
      isProfiling: profiler.isProfiling(),
      isDevelopmentMode: isDevelopmentMode(),
    }, null, 2));
    return;
  }

  const rich = isRich();
  const heading = (text: string) => colorize(rich, theme.heading, text);
  const muted = (text: string) => colorize(rich, theme.muted, text);
  const info = (text: string) => colorize(rich, theme.info, text);
  const success = (text: string) => colorize(rich, theme.success, text);
  const warn = (text: string) => colorize(rich, theme.warn, text);
  const label = (text: string) => muted(`${text}:`);

  const lines = [
    heading("Heap Memory Status"),
    `${label("Profiling")} ${profiler.isProfiling() ? success("active") : muted("inactive")}`,
    `${label("Development mode")} ${isDevelopmentMode() ? success("yes") : muted("no")}`,
    `${label("Current heap")} ${info(formatBytes(stats.currentHeapUsed))}`,
    `${label("Peak heap")} ${info(formatBytes(stats.peakHeapUsed))}`,
    `${label("Snapshots taken")} ${info(String(stats.snapshotCount))}`,
    `${label("Duration")} ${info(`${(stats.durationMs / 1000).toFixed(1)}s`)}`,
    `${label("Growth rate")} ${info(`${formatBytes(stats.averageGrowthRate)}/hour`)}`,
    `${label("Leak detected")} ${stats.leakDetected ? warn("YES") : success("no")}`,
  ];

  defaultRuntime.log(lines.join("\n"));

  if (stats.leakDetected) {
    defaultRuntime.log("");
    defaultRuntime.log(warn("Warning: Potential memory leak detected!"));
    defaultRuntime.log(muted("Heap is growing faster than the configured threshold."));
    defaultRuntime.log(muted("Check heap snapshots in the temp directory for analysis."));
  }
}

/**
 * Run heap snapshot command
 */
export async function runDevHeapSnapshot(opts: DevHeapOptions): Promise<void> {
  setVerbose(Boolean(opts.verbose));

  const profiler = getGlobalMemoryProfiler();
  const snapshotPath = profiler.forceHeapSnapshot();

  if (opts.json) {
    defaultRuntime.log(JSON.stringify({
      snapshotPath,
      success: snapshotPath !== null,
    }, null, 2));
    return;
  }

  const rich = isRich();
  const success = (text: string) => colorize(rich, theme.success, text);
  const error = (text: string) => colorize(rich, theme.danger, text);
  const muted = (text: string) => colorize(rich, theme.muted, text);

  if (snapshotPath) {
    defaultRuntime.log(success(`Heap snapshot saved: ${snapshotPath}`));
    defaultRuntime.log(muted("Load this file in Chrome DevTools Memory tab for analysis."));
  } else {
    defaultRuntime.error(error("Failed to save heap snapshot"));
    process.exitCode = 1;
  }
}

/**
 * Register dev CLI commands
 */
export function registerDevCli(program: Command): void {
  const dev = program
    .command("dev")
    .description("Development utilities")
    .addHelpText(
      "after",
      () =>
        `\n${theme.muted("Docs:")} ${formatDocsLink("/cli/dev", "docs.openclaw.ai/cli/dev")}\n`,
    );

  dev
    .command("heap")
    .description("Show heap memory status and profiling stats")
    .option("--json", "Print JSON")
    .option("--verbose", "Verbose logging", false)
    .action(async (opts: DevHeapOptions) => {
      await runDevHeapStatus(opts);
    });

  dev
    .command("heap-snapshot")
    .description("Force a heap snapshot to be saved to disk")
    .option("--json", "Print JSON")
    .option("--verbose", "Verbose logging", false)
    .action(async (opts: DevHeapOptions) => {
      await runDevHeapSnapshot(opts);
    });
}
