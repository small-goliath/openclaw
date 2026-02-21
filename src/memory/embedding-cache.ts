/**
 * Embedding In-Memory Cache
 *
 * LRU 캐시를 사용하여 임베딩 결과를 메모리에 캐싱하여
 * 반복적인 임베딩 계산/API 호출을 줄입니다.
 *
 * @module memory/embedding-cache
 */

import type { EmbeddingProvider } from "./embeddings.js";
import { LRUCache } from "../infra/cache/lru-cache.js";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("memory:embedding-cache");

/**
 * 임베딩 캐시 설정
 */
export interface EmbeddingCacheConfig {
  /** 최대 캐시 항목 수 (기본: 1000) */
  maxSize: number;
  /** 기본 TTL (밀리초, 기본: 1시간) */
  defaultTTL: number;
  /** 캐시 활성화 여부 */
  enabled: boolean;
  /** 통계 수집 여부 */
  enableStats: boolean;
}

/**
 * 환경 변수에서 캐시 설정 로드
 */
function resolveEmbeddingCacheConfig(): EmbeddingCacheConfig {
  const maxSize = parseInt(process.env.OPENCLAW_EMBEDDING_CACHE_MAX_SIZE?.trim() ?? "1000", 10);
  const defaultTTL = parseInt(process.env.OPENCLAW_EMBEDDING_CACHE_TTL_MS?.trim() ?? "3600000", 10); // 1시간
  const enabled = process.env.OPENCLAW_EMBEDDING_CACHE_ENABLED?.trim().toLowerCase() !== "false";
  const enableStats = process.env.OPENCLAW_EMBEDDING_CACHE_STATS?.trim().toLowerCase() !== "false";

  return {
    maxSize: Number.isFinite(maxSize) && maxSize > 0 ? maxSize : 1000,
    defaultTTL: Number.isFinite(defaultTTL) && defaultTTL > 0 ? defaultTTL : 3600000,
    enabled,
    enableStats,
  };
}

/**
 * 캐시 키 생성 (텍스트 + 프로바이더 + 모델 기반)
 */
function createCacheKey(text: string, providerId: string, model: string): string {
  // 간단한 해시 함수 사용
  let hash = 0;
  const str = text.trim();
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash + char) | 0;
  }
  // 프로바이더와 모델 정보 포함
  return `${providerId}:${model}:${hash.toString(16)}:${str.length}`;
}

/**
 * 임베딩 캐시 매니저
 */
export class EmbeddingCacheManager {
  private cache: LRUCache<number[]>;
  private config: EmbeddingCacheConfig;
  private provider: EmbeddingProvider;

  constructor(provider: EmbeddingProvider, config?: Partial<EmbeddingCacheConfig>) {
    this.provider = provider;
    this.config = { ...resolveEmbeddingCacheConfig(), ...config };

    this.cache = new LRUCache<number[]>({
      maxSize: this.config.maxSize,
      defaultTTL: this.config.defaultTTL,
      enableStats: this.config.enableStats,
    });

    if (this.config.enabled) {
      log.debug(
        `Embedding cache initialized: maxSize=${this.config.maxSize}, TTL=${this.config.defaultTTL}ms`,
      );
    }
  }

  /**
   * 단일 텍스트 임베딩 (캐시 적용)
   */
  async embedQuery(text: string): Promise<number[]> {
    if (!this.config.enabled) {
      return this.provider.embedQuery(text);
    }

    const key = createCacheKey(text, this.provider.id, this.provider.model);
    const cached = this.cache.get(key);

    if (cached) {
      log.debug(`Embedding cache hit for query (${text.length} chars)`);
      return cached;
    }

    log.debug(`Embedding cache miss for query (${text.length} chars)`);
    const embedding = await this.provider.embedQuery(text);

    // 캐시 저장
    this.cache.set(key, embedding);

    return embedding;
  }

  /**
   * 배치 임베딩 (캐시 적용)
   */
  async embedBatch(texts: string[]): Promise<number[][]> {
    if (!this.config.enabled || texts.length === 0) {
      return this.provider.embedBatch(texts);
    }

    const results: (number[] | undefined)[] = Array.from({ length: texts.length });
    const missingIndices: number[] = [];
    const missingTexts: string[] = [];

    // 캐시에서 조회
    for (let i = 0; i < texts.length; i++) {
      const key = createCacheKey(texts[i], this.provider.id, this.provider.model);
      const cached = this.cache.get(key);

      if (cached) {
        results[i] = cached;
      } else {
        missingIndices.push(i);
        missingTexts.push(texts[i]);
      }
    }

    if (missingTexts.length > 0) {
      log.debug(
        `Embedding batch: ${texts.length - missingTexts.length} cached, ${missingTexts.length} to fetch`,
      );

      // 캐시 미스 항목만 API 호출
      const embeddings = await this.provider.embedBatch(missingTexts);

      // 결과 저장 및 캐시 업데이트
      for (let i = 0; i < missingIndices.length; i++) {
        const originalIndex = missingIndices[i];
        const embedding = embeddings[i];
        results[originalIndex] = embedding;

        // 캐시 저장
        const key = createCacheKey(texts[originalIndex], this.provider.id, this.provider.model);
        this.cache.set(key, embedding);
      }
    } else {
      log.debug(`Embedding batch: all ${texts.length} items cached`);
    }

    return results as number[][];
  }

  /**
   * 캐시 무효화
   */
  invalidate(): void {
    this.cache.clear();
    log.debug("Embedding cache cleared");
  }

  /**
   * 캐시 통계 조회
   */
  getStats() {
    return {
      enabled: this.config.enabled,
      ...this.cache.getStats(),
      config: {
        maxSize: this.config.maxSize,
        defaultTTL: this.config.defaultTTL,
      },
    };
  }

  /**
   * 캐시 설정 업데이트
   */
  updateConfig(config: Partial<EmbeddingCacheConfig>): void {
    this.config = { ...this.config, ...config };
    log.debug(`Embedding cache config updated: enabled=${this.config.enabled}`);
  }
}

/**
 * 기존 EmbeddingProvider를 캐싱 레이어로 감싸는 팩토리 함수
 */
export function createCachedEmbeddingProvider(
  provider: EmbeddingProvider,
  config?: Partial<EmbeddingCacheConfig>,
): EmbeddingProvider & { cacheManager: EmbeddingCacheManager } {
  const cacheManager = new EmbeddingCacheManager(provider, config);

  return {
    id: provider.id,
    model: provider.model,
    maxInputTokens: provider.maxInputTokens,
    embedQuery: (text: string) => cacheManager.embedQuery(text),
    embedBatch: (texts: string[]) => cacheManager.embedBatch(texts),
    cacheManager,
  };
}
