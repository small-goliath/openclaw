/**
 * LRU (Least Recently Used) Cache with TTL support
 *
 * Features:
 * - Max size limit with LRU eviction
 * - TTL (Time To Live) support per entry
 * - Cache hit/miss statistics
 * - Optional mtime-based invalidation
 * - Memory leak prevention through size limits
 *
 * @module infra/cache/lru-cache
 */

export interface CacheEntry<T> {
  value: T;
  expiresAt: number;
  mtime?: number;
  lastAccessed: number;
  accessCount: number;
}

export interface CacheStats {
  hits: number;
  misses: number;
  hitRate: number;
  size: number;
  maxSize: number;
  evictions: number;
  expired: number;
}

export interface CacheOptions {
  maxSize: number;
  defaultTTL: number;
  enableStats?: boolean;
}

export interface GetOptions {
  mtime?: number;
}

export interface SetOptions {
  ttl?: number;
  mtime?: number;
}

/**
 * LRU Cache implementation with TTL support
 *
 * @example
 * ```typescript
 * const cache = new LRUCache<string>({
 *   maxSize: 100,
 *   defaultTTL: 60000, // 1 minute
 * });
 *
 * cache.set("key", "value", { mtime: fileStat.mtimeMs });
 * const value = cache.get("key", { mtime: currentMtime });
 * ```
 */
export class LRUCache<T> {
  private cache: Map<string, CacheEntry<T>>;
  private maxSize: number;
  private defaultTTL: number;
  private enableStats: boolean;

  // Statistics
  private hits = 0;
  private misses = 0;
  private evictions = 0;
  private expired = 0;

  constructor(options: CacheOptions) {
    this.maxSize = options.maxSize;
    this.defaultTTL = options.defaultTTL;
    this.enableStats = options.enableStats ?? true;
    this.cache = new Map();
  }

  /**
   * Get a value from the cache
   *
   * @param key - Cache key
   * @param options - Optional mtime for invalidation check
   * @returns Cached value or undefined if not found/expired
   */
  get(key: string, options?: GetOptions): T | undefined {
    const entry = this.cache.get(key);

    if (!entry) {
      this.recordMiss();
      return undefined;
    }

    // Check TTL expiration
    const now = Date.now();
    if (entry.expiresAt <= now) {
      this.cache.delete(key);
      this.expired++;
      this.recordMiss();
      return undefined;
    }

    // Check mtime-based invalidation
    if (options?.mtime !== undefined && entry.mtime !== undefined) {
      if (options.mtime > entry.mtime) {
        this.cache.delete(key);
        this.recordMiss();
        return undefined;
      }
    }

    // Update access metadata (LRU)
    entry.lastAccessed = now;
    entry.accessCount++;

    // Move to end (most recently used)
    this.cache.delete(key);
    this.cache.set(key, entry);

    this.recordHit();
    return entry.value;
  }

  /**
   * Set a value in the cache
   *
   * @param key - Cache key
   * @param value - Value to cache
   * @param options - Optional TTL and mtime
   */
  set(key: string, value: T, options?: SetOptions): void {
    const now = Date.now();
    const ttl = options?.ttl ?? this.defaultTTL;

    // Remove existing entry if present
    if (this.cache.has(key)) {
      this.cache.delete(key);
    }

    // Evict oldest entries if at capacity
    while (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey !== undefined) {
        this.cache.delete(firstKey);
        this.evictions++;
      } else {
        break;
      }
    }

    const entry: CacheEntry<T> = {
      value,
      expiresAt: now + ttl,
      mtime: options?.mtime,
      lastAccessed: now,
      accessCount: 1,
    };

    this.cache.set(key, entry);
  }

  /**
   * Delete a specific entry from the cache
   *
   * @param key - Cache key to delete
   * @returns true if entry was found and deleted
   */
  delete(key: string): boolean {
    return this.cache.delete(key);
  }

  /**
   * Check if a key exists in the cache (without updating LRU order)
   *
   * @param key - Cache key
   * @returns true if key exists and is not expired
   */
  has(key: string): boolean {
    const entry = this.cache.get(key);
    if (!entry) {
      return false;
    }

    const now = Date.now();
    if (entry.expiresAt <= now) {
      this.cache.delete(key);
      this.expired++;
      return false;
    }

    return true;
  }

  /**
   * Clear all entries from the cache
   */
  clear(): void {
    this.cache.clear();
    this.resetStats();
  }

  /**
   * Get cache statistics
   *
   * @returns CacheStats object with hit/miss rates
   */
  getStats(): CacheStats {
    const total = this.hits + this.misses;
    return {
      hits: this.hits,
      misses: this.misses,
      hitRate: total > 0 ? this.hits / total : 0,
      size: this.cache.size,
      maxSize: this.maxSize,
      evictions: this.evictions,
      expired: this.expired,
    };
  }

  /**
   * Reset statistics counters
   */
  resetStats(): void {
    this.hits = 0;
    this.misses = 0;
    this.evictions = 0;
    this.expired = 0;
  }

  /**
   * Get the current size of the cache
   */
  get size(): number {
    return this.cache.size;
  }

  /**
   * Clean up expired entries
   *
   * @returns Number of entries removed
   */
  cleanup(): number {
    const now = Date.now();
    let removed = 0;

    for (const [key, entry] of this.cache.entries()) {
      if (entry.expiresAt <= now) {
        this.cache.delete(key);
        removed++;
      }
    }

    this.expired += removed;
    return removed;
  }

  /**
   * Get all keys in the cache (for debugging/testing)
   */
  keys(): string[] {
    return Array.from(this.cache.keys());
  }

  private recordHit(): void {
    if (this.enableStats) {
      this.hits++;
    }
  }

  private recordMiss(): void {
    if (this.enableStats) {
      this.misses++;
    }
  }
}

/**
 * Create a cache key from file path and modification time
 *
 * @param filePath - Absolute file path
 * @param mtime - File modification time (ms)
 * @returns Cache key string
 */
export function createFileCacheKey(filePath: string, mtime: number): string {
  return `${filePath}:${mtime}`;
}

/**
 * Environment-based cache configuration
 */
export function resolveCacheConfigFromEnv(env: NodeJS.ProcessEnv): {
  maxSize: number;
  defaultTTL: number;
} {
  const maxSize = parseInt(env.OPENCLAW_CACHE_MAX_SIZE?.trim() ?? "100", 10);
  const defaultTTL = parseInt(env.OPENCLAW_CACHE_TTL_MS?.trim() ?? "60000", 10);

  return {
    maxSize: Number.isFinite(maxSize) && maxSize > 0 ? maxSize : 100,
    defaultTTL: Number.isFinite(defaultTTL) && defaultTTL > 0 ? defaultTTL : 60000,
  };
}
