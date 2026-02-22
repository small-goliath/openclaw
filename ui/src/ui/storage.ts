const KEY = "openclaw.control.settings.v2";
const LEGACY_KEY = "openclaw.control.settings.v1";

import type { ThemeMode } from "./theme.ts";

// HIGH-001, SEC-002: Token removed from localStorage storage
// Token is now managed via httpOnly cookies or memory storage
export type UiSettings = {
  gatewayUrl: string;
  // token field removed - now stored in httpOnly cookie or memory
  sessionKey: string;
  lastActiveSessionKey: string;
  theme: ThemeMode;
  chatFocusMode: boolean;
  chatShowThinking: boolean;
  splitRatio: number; // Sidebar split ratio (0.4 to 0.7, default 0.6)
  navCollapsed: boolean; // Collapsible sidebar state
  navGroupsCollapsed: Record<string, boolean>; // Which nav groups are collapsed
};

// In-memory token storage (cleared on page refresh)
// For persistent tokens, httpOnly cookies should be used
let memoryToken: string | null = null;

/**
 * Get token from memory storage
 * HIGH-001: Token is no longer stored in localStorage
 */
export function getToken(): string | null {
  return memoryToken;
}

/**
 * Set token in memory storage
 * Note: For persistent sessions, server should set httpOnly cookie
 */
export function setToken(token: string | null): void {
  memoryToken = token;
}

/**
 * Migrate legacy settings to remove token from localStorage
 */
function migrateLegacySettings(): void {
  try {
    const legacyRaw = localStorage.getItem(LEGACY_KEY);
    if (legacyRaw) {
      const legacy = JSON.parse(legacyRaw) as Record<string, unknown>;
      if (legacy.token) {
        // Migrate token to memory (if still valid)
        if (typeof legacy.token === "string") {
          memoryToken = legacy.token;
        }
        // Remove legacy storage with token
        localStorage.removeItem(LEGACY_KEY);
        console.log("[Security] Migrated legacy settings, token removed from localStorage");
      }
    }
  } catch {
    // Ignore migration errors
  }
}

export function loadSettings(): UiSettings {
  // Migrate legacy settings on first load
  migrateLegacySettings();

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
    const raw = localStorage.getItem(KEY);
    if (!raw) {
      return defaults;
    }
    const parsed = JSON.parse(raw) as Partial<UiSettings>;
    return {
      gatewayUrl:
        typeof parsed.gatewayUrl === "string" && parsed.gatewayUrl.trim()
          ? parsed.gatewayUrl.trim()
          : defaults.gatewayUrl,
      // HIGH-001: Token is no longer loaded from localStorage
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

export function saveSettings(next: UiSettings) {
  localStorage.setItem(KEY, JSON.stringify(next));
}
