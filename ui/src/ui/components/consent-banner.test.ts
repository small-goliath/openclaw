/**
 * Consent Banner 컴포넌트 테스트
 * COMP-003, COMP-004, SEC-4.2, SEC-7.3 요구사항 검증
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  ConsentBanner,
  showConsentBanner,
  hideConsentBanner,
  getConsentPreferences,
  needsConsent,
} from "./consent-banner.js";

describe("ConsentBanner", () => {
  beforeEach(() => {
    // localStorage 모킹
    const storage: Record<string, string> = {};
    vi.stubGlobal("localStorage", {
      getItem: (key: string) => storage[key] || null,
      setItem: (key: string, value: string) => {
        storage[key] = value;
      },
      removeItem: (key: string) => {
        delete storage[key];
      },
    });

    // DOM 초기화
    document.body.innerHTML = "";
  });

  describe("컴포넌트 초기화", () => {
    it("ConsentBanner 컴포넌트가 정의되어야 함", () => {
      expect(customElements.get("consent-banner")).toBeDefined();
    });

    it("기본 속성이 설정되어야 함", () => {
      const banner = document.createElement("consent-banner");
      expect(banner.visible).toBe(false);
      expect(banner.privacyPolicyUrl).toBe("/privacy-policy");
      expect(banner.showDetails).toBe(false);
    });
  });

  describe("동의 설정", () => {
    it("저장된 동의 설정을 로드해야 함", () => {
      localStorage.setItem(
        "openclaw-consent-preferences",
        JSON.stringify({
          necessary: true,
          functional: true,
          analytics: false,
          marketing: false,
        }),
      );

      const banner = document.createElement("consent-banner");
      document.body.appendChild(banner);

      // 컴포넌트가 연결되면 설정을 로드함
      expect(banner.preferences.functional).toBe(true);
      expect(banner.preferences.analytics).toBe(false);
    });

    it("동의 변경 시 localStorage에 저장해야 함", () => {
      const banner = document.createElement("consent-banner");
      document.body.appendChild(banner);

      // 모든 동의 수락
      banner.acceptAll();

      const stored = JSON.parse(localStorage.getItem("openclaw-consent-preferences") || "{}");
      expect(stored.functional).toBe(true);
      expect(stored.analytics).toBe(true);
      expect(stored.marketing).toBe(true);
    });
  });

  describe("배너 표시/숨김", () => {
    it("showConsentBanner는 배너를 표시해야 함", () => {
      const banner = document.createElement("consent-banner");
      banner.visible = false;
      document.body.appendChild(banner);

      showConsentBanner();

      expect(banner.visible).toBe(true);
    });

    it("hideConsentBanner는 배너를 숨겨야 함", () => {
      const banner = document.createElement("consent-banner");
      banner.visible = true;
      document.body.appendChild(banner);

      hideConsentBanner();

      expect(banner.visible).toBe(false);
    });
  });

  describe("유틸리티 함수", () => {
    it("getConsentPreferences는 저장된 설정을 반환해야 함", () => {
      localStorage.setItem(
        "openclaw-consent-preferences",
        JSON.stringify({
          necessary: true,
          functional: true,
          analytics: true,
          marketing: true,
        }),
      );

      const prefs = getConsentPreferences();
      expect(prefs.functional).toBe(true);
      expect(prefs.analytics).toBe(true);
      expect(prefs.marketing).toBe(true);
    });

    it("getConsentPreferences는 저장된 설정이 없으면 기본값을 반환해야 함", () => {
      const prefs = getConsentPreferences();
      expect(prefs.necessary).toBe(true);
      expect(prefs.functional).toBe(false);
      expect(prefs.analytics).toBe(false);
      expect(prefs.marketing).toBe(false);
    });

    it("needsConsent는 동의 필요 여부를 반환해야 함", () => {
      // 초기 상태에서는 동의 필요
      expect(needsConsent()).toBe(true);

      // 일부 동의 설정
      localStorage.setItem(
        "openclaw-consent-preferences",
        JSON.stringify({
          necessary: true,
          functional: true,
          analytics: false,
          marketing: false,
        }),
      );
      localStorage.setItem("openclaw-consent-version", "1.0.0");

      expect(needsConsent()).toBe(false);
    });

    it("needsConsent는 버전 변경 시 true를 반환해야 함", () => {
      localStorage.setItem(
        "openclaw-consent-preferences",
        JSON.stringify({
          necessary: true,
          functional: true,
          analytics: true,
          marketing: true,
        }),
      );
      localStorage.setItem("openclaw-consent-version", "0.9.0");

      expect(needsConsent()).toBe(true);
    });
  });

  describe("접근성", () => {
    it("배너는 dialog 역할을 가져야 함", () => {
      const banner = document.createElement("consent-banner");
      banner.visible = true;
      document.body.appendChild(banner);

      const dialog = banner.shadowRoot?.querySelector('[role="dialog"]');
      expect(dialog).toBeDefined();
    });

    it("토글 스위치는 switch 역할을 가져야 함", () => {
      const banner = document.createElement("consent-banner");
      banner.showDetails = true;
      document.body.appendChild(banner);

      const switches = banner.shadowRoot?.querySelectorAll('[role="switch"]');
      expect(switches?.length).toBeGreaterThan(0);
    });
  });
});
