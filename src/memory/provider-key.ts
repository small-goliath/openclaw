import { fingerprintHeaderNames } from "./headers-fingerprint.js";
import { hashText } from "./internal.js";

// Provider Key 캐시 - 해시 재계산 방지 (Task 25)
const providerKeyCache = new Map<string, string>();
const MAX_CACHE_SIZE = 100;

/**
 * 캐시 키 생성 헬퍼
 */
function createCacheKey(params: {
  providerId: string;
  providerModel: string;
  openAi?: { baseUrl: string; model: string; headers: Record<string, string> };
  gemini?: { baseUrl: string; model: string; headers: Record<string, string> };
}): string {
  if (params.openAi) {
    const headerNames = fingerprintHeaderNames(params.openAi.headers);
    return `openai:${params.openAi.baseUrl}:${params.openAi.model}:${headerNames.join(",")}`;
  }
  if (params.gemini) {
    const headerNames = fingerprintHeaderNames(params.gemini.headers);
    return `gemini:${params.gemini.baseUrl}:${params.gemini.model}:${headerNames.join(",")}`;
  }
  return `${params.providerId}:${params.providerModel}`;
}

/**
 * LRU eviction - 가장 오래된 항목 제거
 */
function evictOldestIfNeeded(): void {
  if (providerKeyCache.size < MAX_CACHE_SIZE) {
    return;
  }
  // Map의 첫 번째 항목 제거 (가장 오래된 항목)
  const firstKey = providerKeyCache.keys().next().value;
  if (firstKey !== undefined) {
    providerKeyCache.delete(firstKey);
  }
}

export function computeEmbeddingProviderKey(params: {
  providerId: string;
  providerModel: string;
  openAi?: { baseUrl: string; model: string; headers: Record<string, string> };
  gemini?: { baseUrl: string; model: string; headers: Record<string, string> };
}): string {
  const cacheKey = createCacheKey(params);

  // 캐시에서 조회
  const cached = providerKeyCache.get(cacheKey);
  if (cached) {
    // LRU 순서 유지: 기존 항목 삭제 후 다시 추가
    providerKeyCache.delete(cacheKey);
    providerKeyCache.set(cacheKey, cached);
    return cached;
  }

  // 새로운 키 계산
  let result: string;
  if (params.openAi) {
    const headerNames = fingerprintHeaderNames(params.openAi.headers);
    result = hashText(
      JSON.stringify({
        provider: "openai",
        baseUrl: params.openAi.baseUrl,
        model: params.openAi.model,
        headerNames,
      }),
    );
  } else if (params.gemini) {
    const headerNames = fingerprintHeaderNames(params.gemini.headers);
    result = hashText(
      JSON.stringify({
        provider: "gemini",
        baseUrl: params.gemini.baseUrl,
        model: params.gemini.model,
        headerNames,
      }),
    );
  } else {
    result = hashText(JSON.stringify({ provider: params.providerId, model: params.providerModel }));
  }

  // 캐시에 저장 (LRU eviction 적용)
  evictOldestIfNeeded();
  providerKeyCache.set(cacheKey, result);

  return result;
}

/**
 * Provider Key 캐시 통계 조회 (테스트/모니터링용)
 */
export function getProviderKeyCacheStats(): {
  size: number;
  maxSize: number;
} {
  return {
    size: providerKeyCache.size,
    maxSize: MAX_CACHE_SIZE,
  };
}

/**
 * Provider Key 캐시 초기화 (테스트용)
 */
export function clearProviderKeyCache(): void {
  providerKeyCache.clear();
}
