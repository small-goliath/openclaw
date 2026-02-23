import { createHash } from "node:crypto";

/**
 * Request deduplication parameters
 */
export interface RequestDeduplicatorKeyParams {
  /** HTTP method */
  method: string;
  /** Request path */
  path: string;
  /** Request body (optional) */
  body?: unknown;
  /** User identifier (optional) */
  userId?: string;
}

/**
 * Request deduplicator utility class
 * Caches in-flight requests by key to prevent duplicate concurrent requests
 */
export class RequestDeduplicator {
  private pendingRequests = new Map<string, Promise<unknown>>();
  private readonly dedupWindowMs: number;

  /**
   * Creates a new RequestDeduplicator instance
   * @param dedupWindowMs - Deduplication window in milliseconds (default: 5000ms)
   */
  constructor(dedupWindowMs = 5000) {
    this.dedupWindowMs = dedupWindowMs;
  }

  /**
   * Deduplicate a request by key
   * If a request with the same key is already in-flight, returns the existing promise
   * Otherwise, executes the request function and caches the promise
   *
   * @param requestKey - Unique key for the request
   * @param requestFn - Function that returns a promise for the request
   * @returns Promise that resolves to the request result
   */
  deduplicate<T>(requestKey: string, requestFn: () => Promise<T>): Promise<T> {
    const pending = this.pendingRequests.get(requestKey);
    if (pending) {
      return pending as Promise<T>;
    }

    const promise = requestFn().finally(() => {
      // Clean up after the deduplication window expires
      setTimeout(() => {
        this.pendingRequests.delete(requestKey);
      }, this.dedupWindowMs);
    });

    this.pendingRequests.set(requestKey, promise);
    return promise;
  }

  /**
   * Generate a unique request key from request parameters
   * Uses SHA-256 hash for body content to keep key length manageable
   *
   * @param params - Request parameters
   * @returns Unique request key string
   */
  static generateKey(params: RequestDeduplicatorKeyParams): string {
    const bodyHash = params.body
      ? createHash("sha256").update(JSON.stringify(params.body)).digest("hex").slice(0, 16)
      : "";
    return `${params.method}:${params.path}:${params.userId || "anon"}:${bodyHash}`;
  }

  /**
   * Check if a request is currently pending
   * @param requestKey - The request key to check
   * @returns true if the request is in-flight
   */
  hasPendingRequest(requestKey: string): boolean {
    return this.pendingRequests.has(requestKey);
  }

  /**
   * Get the number of currently pending requests
   * @returns Number of pending requests
   */
  getPendingCount(): number {
    return this.pendingRequests.size;
  }

  /**
   * Clear all pending requests (useful for testing or cleanup)
   */
  clear(): void {
    this.pendingRequests.clear();
  }
}

/**
 * Default singleton instance for common use cases
 */
export const defaultRequestDeduplicator = new RequestDeduplicator();
