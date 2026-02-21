/**
 * httpOnly 쿠키 기반 인증 관리
 * XSS 공격으로부터 토큰을 보호하기 위해 localStorage 대신 쿠키 사용
 */

import type { ThemeMode } from "./theme.ts";

const SETTINGS_KEY = "openclaw.control.settings.v1";

export type UiSettings = {
  gatewayUrl: string;
  sessionKey: string;
  lastActiveSessionKey: string;
  theme: ThemeMode;
  chatFocusMode: boolean;
  chatShowThinking: boolean;
  splitRatio: number; // Sidebar split ratio (0.4 to 0.7, default 0.6)
  navCollapsed: boolean; // Collapsible sidebar state
  navGroupsCollapsed: Record<string, boolean>; // Which nav groups are collapsed
};

/**
 * 쿠키 설정 (httpOnly는 서버에서만 설정 가능)
 * 클라이언트에서 접근 가능한 토큰은 메모리에만 저장
 */
let memoryToken: string | null = null;

/**
 * 메모리에 토큰 저장 (httpOnly 쿠키는 서버에서 설정)
 */
export function setMemoryToken(token: string): void {
  memoryToken = token;
}

/**
 * 메모리에서 토큰 가져오기
 */
export function getMemoryToken(): string | null {
  return memoryToken;
}

/**
 * 메모리 토큰 삭제
 */
export function clearMemoryToken(): void {
  memoryToken = null;
}

/**
 * 설정 로드 (토큰 제외)
 */
export function loadSettings(): UiSettings {
  const defaultUrl = (() => {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    return `${proto}://${location.host}`;
  })();

  const defaults: UiSettings = {
    gatewayUrl: defaultUrl,
    sessionKey: "main",
    lastActiveSessionKey: "main",
    theme: "system",
    chatFocusMode: false,
    chatShowThinking: true,
    splitRatio: 0.6,
    navCollapsed: false,
    navGroupsCollapsed: {},
  };

  try {
    const raw = localStorage.getItem(SETTINGS_KEY);
    if (!raw) {
      return defaults;
    }
    const parsed = JSON.parse(raw) as Partial<UiSettings>;
    return {
      gatewayUrl:
        typeof parsed.gatewayUrl === "string" && parsed.gatewayUrl.trim()
          ? parsed.gatewayUrl.trim()
          : defaults.gatewayUrl,
      sessionKey:
        typeof parsed.sessionKey === "string" && parsed.sessionKey.trim()
          ? parsed.sessionKey.trim()
          : defaults.sessionKey,
      lastActiveSessionKey:
        typeof parsed.lastActiveSessionKey === "string" && parsed.lastActiveSessionKey.trim()
          ? parsed.lastActiveSessionKey.trim()
          : (typeof parsed.sessionKey === "string" && parsed.sessionKey.trim()) ||
            defaults.lastActiveSessionKey,
      theme:
        parsed.theme === "light" || parsed.theme === "dark" || parsed.theme === "system"
          ? parsed.theme
          : defaults.theme,
      chatFocusMode:
        typeof parsed.chatFocusMode === "boolean" ? parsed.chatFocusMode : defaults.chatFocusMode,
      chatShowThinking:
        typeof parsed.chatShowThinking === "boolean"
          ? parsed.chatShowThinking
          : defaults.chatShowThinking,
      splitRatio:
        typeof parsed.splitRatio === "number" &&
        parsed.splitRatio >= 0.4 &&
        parsed.splitRatio <= 0.7
          ? parsed.splitRatio
          : defaults.splitRatio,
      navCollapsed:
        typeof parsed.navCollapsed === "boolean" ? parsed.navCollapsed : defaults.navCollapsed,
      navGroupsCollapsed:
        typeof parsed.navGroupsCollapsed === "object" && parsed.navGroupsCollapsed !== null
          ? parsed.navGroupsCollapsed
          : defaults.navGroupsCollapsed,
    };
  } catch {
    return defaults;
  }
}

/**
 * 설정 저장 (토큰 제외)
 */
export function saveSettings(next: UiSettings): void {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(next));
}

/**
 * 토큰 갱신 요청 (리프레시 토큰 사용)
 */
export async function refreshToken(): Promise<boolean> {
  try {
    const response = await fetch("/api/auth/refresh", {
      method: "POST",
      credentials: "include", // httpOnly 쿠키 포함
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * 로그아웃 (쿠키 및 메모리 토큰 삭제)
 */
export async function logout(): Promise<void> {
  try {
    await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "include",
    });
  } finally {
    clearMemoryToken();
  }
}
