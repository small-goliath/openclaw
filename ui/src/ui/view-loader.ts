/**
 * View Loader Module
 *
 * Route-based code splitting을 위한 dynamic import 및 prefetch 로직을 제공합니다.
 * 초기 번들 크기를 줄이고, 필요한 view만 on-demand로 로드합니다.
 */

import type { Tab } from "./navigation.ts";
import { TAB_GROUPS } from "./navigation.ts";

// View 캐시 - 이미 로드된 view 모듈 저장
const viewCache = new Map<Tab, unknown>();

// 로딩 중인 view 추적
const loadingViews = new Set<Tab>();

// Prefetch 완료된 view 추적
const prefetchedViews = new Set<Tab>();

// View가 로딩 중인지 확인
export function isViewLoading(tab: Tab): boolean {
  return loadingViews.has(tab);
}

// View가 이미 로드되었는지 확인
export function isViewLoaded(tab: Tab): boolean {
  return viewCache.has(tab);
}

// Tab별 view loader 매핑
const viewLoaders: Record<Tab, () => Promise<unknown>> = {
  overview: () => import("./views/overview.ts"),
  channels: () => import("./views/channels.ts"),
  instances: () => import("./views/instances.ts"),
  sessions: () => import("./views/sessions.ts"),
  usage: () => import("./views/usage.ts"),
  cron: () => import("./views/cron.ts"),
  agents: () => import("./views/agents.ts"),
  skills: () => import("./views/skills.ts"),
  nodes: () => import("./views/nodes.ts"),
  chat: () => import("./views/chat.ts"),
  config: () => import("./views/config.ts"),
  debug: () => import("./views/debug.ts"),
  logs: () => import("./views/logs.ts"),
};

// View 모듈 로드
export async function loadView<T>(tab: Tab): Promise<T | null> {
  // 이미 캐시에 있으면 반환
  if (viewCache.has(tab)) {
    return viewCache.get(tab) as T;
  }

  // 로딩 중이면 완료될 때까지 대기
  if (loadingViews.has(tab)) {
    // eslint-disable-next-line no-promise-executor-return
    await new Promise((resolve) => {
      const checkInterval = setInterval(() => {
        if (!loadingViews.has(tab)) {
          clearInterval(checkInterval);
          resolve(undefined);
        }
      }, 50);
    });
    return viewCache.get(tab) as T | null;
  }

  const loader = viewLoaders[tab];
  if (!loader) {
    console.error(`[ViewLoader] No loader found for tab: ${tab}`);
    return null;
  }

  loadingViews.add(tab);

  try {
    const module = await loader();
    viewCache.set(tab, module);
    return module as T;
  } catch (error) {
    console.error(`[ViewLoader] Failed to load view for tab: ${tab}`, error);
    return null;
  } finally {
    loadingViews.delete(tab);
  }
}

// Prefetch 설정
const prefetchConfig = {
  enabled: true,
  delayMs: 2000, // tab 변경 후 2초 후 prefetch 시작
  concurrentLimit: 2, // 동시에 prefetch할 최대 개수
};

let prefetchTimer: number | null = null;

// Prefetch 설정 업데이트
export function setPrefetchConfig(config: Partial<typeof prefetchConfig>) {
  Object.assign(prefetchConfig, config);
}

// 인접한 tab들 prefetch
export function prefetchAdjacentTabs(currentTab: Tab): void {
  if (!prefetchConfig.enabled) {
    return;
  }

  // 이전 타이머 취소
  if (prefetchTimer !== null) {
    clearTimeout(prefetchTimer);
    prefetchTimer = null;
  }

  // 현재 tab이 속한 group 찾기
  const currentGroup = TAB_GROUPS.find((g) => g.tabs.includes(currentTab));
  if (!currentGroup) {
    return;
  }

  // prefetch 대상 결정 (같은 group의 다른 tabs)
  const targets = currentGroup.tabs.filter(
    (tab) => tab !== currentTab && !viewCache.has(tab) && !prefetchedViews.has(tab),
  );

  if (targets.length === 0) {
    return;
  }

  // 지연 후 prefetch 시작
  prefetchTimer = window.setTimeout(() => {
    // 중요도에 따라 정렬: chat tab은 가장 높은 우선순위
    const sortedTargets = targets.toSorted((a) => (a === "chat" ? -1 : 0));

    // concurrentLimit만큼만 prefetch
    const toPrefetch = sortedTargets.slice(0, prefetchConfig.concurrentLimit);

    toPrefetch.forEach((tab) => {
      // 이미 로드 중이거나 캐시에 있으면 skip
      if (loadingViews.has(tab) || viewCache.has(tab)) {
        return;
      }

      // prefetch 마커 설정
      prefetchedViews.add(tab);

      // dynamic import with webpackPrefetch magic comment
      const loader = viewLoaders[tab];
      if (loader) {
        // 브라우저의 idle time에 prefetch
        if ("requestIdleCallback" in window) {
          requestIdleCallback(
            () => {
              loader()
                .then((module) => {
                  viewCache.set(tab, module);
                  console.log(`[ViewLoader] Prefetched: ${tab}`);
                })
                .catch((err) => {
                  console.warn(`[ViewLoader] Prefetch failed for ${tab}:`, err);
                  prefetchedViews.delete(tab);
                });
            },
            { timeout: 5000 },
          );
        } else {
          // requestIdleCallback 미지원 브라우저용 fallback
          setTimeout(() => {
            loader()
              .then((module) => {
                viewCache.set(tab, module);
                console.log(`[ViewLoader] Prefetched: ${tab}`);
              })
              .catch((err) => {
                console.warn(`[ViewLoader] Prefetch failed for ${tab}:`, err);
                prefetchedViews.delete(tab);
              });
          }, 100);
        }
      }
    });
  }, prefetchConfig.delayMs);
}

// 모든 view 캐시 초기화
export function clearViewCache(): void {
  viewCache.clear();
  prefetchedViews.clear();
  loadingViews.clear();
  if (prefetchTimer !== null) {
    clearTimeout(prefetchTimer);
    prefetchTimer = null;
  }
}

// 캐시 통계 정보
export function getCacheStats(): {
  cached: number;
  loading: number;
  prefetched: number;
  total: number;
} {
  return {
    cached: viewCache.size,
    loading: loadingViews.size,
    prefetched: prefetchedViews.size,
    total: Object.keys(viewLoaders).length,
  };
}

// Eager preload - 초기 로딩 시 필요한 view 미리 로드
export async function eagerPreload(tabs: Tab[]): Promise<void> {
  const promises = tabs.map(async (tab) => {
    if (!viewCache.has(tab) && !loadingViews.has(tab)) {
      try {
        const module = await viewLoaders[tab]();
        viewCache.set(tab, module);
        console.log(`[ViewLoader] Eager loaded: ${tab}`);
      } catch (err) {
        console.warn(`[ViewLoader] Eager load failed for ${tab}:`, err);
      }
    }
  });

  await Promise.all(promises);
}
