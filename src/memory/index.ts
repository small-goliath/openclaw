export { MemoryIndexManager } from "./manager.js";
export type {
  MemoryEmbeddingProbeResult,
  MemorySearchManager,
  MemorySearchResult,
} from "./types.js";
export { getMemorySearchManager, type MemorySearchManagerResult } from "./search-manager.js";

// Index monitoring and performance utilities
export {
  getIndexStats,
  analyzeQueryPlan,
  isQueryUsingIndex,
  updateQueryStats,
  monitorIndexEffectiveness,
  logIndexEffectivenessReport,
  type IndexStats,
  type QueryPlan,
  type QueryPerformanceResult,
} from "./memory-schema.js";

// Query performance monitoring
export {
  QueryPerformanceMonitor,
  type QueryPerformanceConfig,
} from "./query-performance-monitor.js";
export type { QueryPerformanceStats } from "./types.js";
