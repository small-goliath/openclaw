/**
 * Consent Store 테스트
 * COMP-003, COMP-004, SEC-4.2, SEC-7.3 요구사항 검증
 */

import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import {
  ConsentStore,
  initializeConsentStore,
  canExecuteScript,
  canSetCookie,
  shouldShowConsentBanner,
  exportConsentSettings,
  getConsentStatus,
  type ConsentPreferences,
} from "./consent-store.js";

// 테스트를 위한 글로벌 인스턴스 정리
declare global {
  var globalConsentStore: ConsentStore | null;
}

describe("ConsentStore", () => {
  let store: ConsentStore;
  let storage: Record<string, string> = {};

  beforeEach(() => {
    // localStorage 모킹
    storage = {};
    vi.stubGlobal("localStorage", {
      getItem: (key: string) => storage[key] || null,
      setItem: (key: string, value: string) => {
        storage[key] = value;
      },
      removeItem: (key: string) => {
        delete storage[key];
      },
    });

    // 각 테스트 전에 새로운 인스턴스 생성
    store = new ConsentStore({
      storageKeyPrefix: "test-consent",
      consentVersion: "1.0.0",
      privacyPolicyVersion: "1.0.0",
    });
  });

  afterEach(() => {
    // 각 테스트 후 저장소 정리
    store.clear();
    // 글로벌 인스턴스도 정리
    (globalThis as unknown as { globalConsentStore: ConsentStore | null }).globalConsentStore =
      null;
  });

  describe("초기화", () => {
    it("기본 설정으로 초기화되어야 함", () => {
      store.initialize();
      const prefs = store.getPreferences();

      expect(prefs.necessary).toBe(true);
      expect(prefs.functional).toBe(false);
      expect(prefs.analytics).toBe(false);
      expect(prefs.marketing).toBe(false);
    });

    it("저장된 설정을 로드해야 함", () => {
      // 현재 인스턴스로 저장 먼저 수행
      store.initialize();
      store.setMultipleConsents({
        functional: true,
        analytics: true,
        marketing: false,
      });

      // 새 인스턴스 생성 및 초기화
      const newStore = new ConsentStore({
        storageKeyPrefix: "test-consent",
        consentVersion: "1.0.0",
        privacyPolicyVersion: "1.0.0",
      });
      newStore.initialize();
      const prefs = newStore.getPreferences();

      expect(prefs.functional).toBe(true);
      expect(prefs.analytics).toBe(true);
      expect(prefs.marketing).toBe(false);

      // 정리
      newStore.clear();
    });

    it("버전이 변경되면 재동의가 필요해야 함", () => {
      storage["test-consent-preferences"] = JSON.stringify({
        necessary: true,
        functional: true,
        analytics: true,
        marketing: true,
      });
      storage["test-consent-version"] = "0.9.0"; // 다른 버전

      store.initialize();

      expect(store.needsConsent()).toBe(true);
    });
  });

  describe("동의 관리", () => {
    beforeEach(() => {
      store.initialize();
    });

    it("동의를 설정할 수 있어야 함", () => {
      store.setConsent("functional", true);
      expect(store.hasConsent("functional")).toBe(true);

      store.setConsent("analytics", true);
      expect(store.hasConsent("analytics")).toBe(true);
    });

    it("동의를 철회할 수 있어야 함", () => {
      store.setConsent("functional", true);
      expect(store.hasConsent("functional")).toBe(true);

      store.setConsent("functional", false);
      expect(store.hasConsent("functional")).toBe(false);
    });

    it("필수 동의는 변경할 수 없어야 함", () => {
      store.setConsent("necessary", false);
      expect(store.hasConsent("necessary")).toBe(true);
    });

    it("여러 동의를 한 번에 설정할 수 있어야 함", () => {
      store.setMultipleConsents({
        functional: true,
        analytics: true,
        marketing: true,
      });

      expect(store.hasConsent("functional")).toBe(true);
      expect(store.hasConsent("analytics")).toBe(true);
      expect(store.hasConsent("marketing")).toBe(true);
    });

    it("모든 동의를 수락할 수 있어야 함", () => {
      store.acceptAll();

      expect(store.hasConsent("functional")).toBe(true);
      expect(store.hasConsent("analytics")).toBe(true);
      expect(store.hasConsent("marketing")).toBe(true);
    });

    it("필수 동의만 수락할 수 있어야 함", () => {
      store.setConsent("functional", true);
      store.setConsent("analytics", true);

      store.acceptNecessaryOnly();

      expect(store.hasConsent("functional")).toBe(false);
      expect(store.hasConsent("analytics")).toBe(false);
      expect(store.hasConsent("marketing")).toBe(false);
      expect(store.hasConsent("necessary")).toBe(true);
    });

    it("모든 동의를 철회할 수 있어야 함", () => {
      store.acceptAll();
      expect(store.hasAllConsents()).toBe(true);

      store.revokeAllConsents();

      expect(store.hasConsent("functional")).toBe(false);
      expect(store.hasConsent("analytics")).toBe(false);
      expect(store.hasConsent("marketing")).toBe(false);
    });
  });

  describe("동의 상태 조회", () => {
    beforeEach(() => {
      store.initialize();
    });

    it("개별 동의 상태를 조회할 수 있어야 함", () => {
      expect(store.getConsent("necessary")).toBe("granted");
      expect(store.getConsent("functional")).toBe("denied");
    });

    it("모든 동의가 granted인지 확인할 수 있어야 함", () => {
      expect(store.hasAllConsents()).toBe(false);

      store.acceptAll();
      expect(store.hasAllConsents()).toBe(true);
    });

    it("동의가 필요한지 확인할 수 있어야 함", () => {
      // 초기 상태에서는 동의 필요
      expect(store.needsConsent()).toBe(true);

      // 일부 동의 후에도 필요
      store.setConsent("functional", true);
      expect(store.needsConsent()).toBe(false);
    });
  });

  describe("동의 로깅", () => {
    beforeEach(() => {
      store.initialize();
    });

    it("동의 변경이 로그에 기록되어야 함", () => {
      store.setConsent("functional", true);
      store.setConsent("analytics", true);

      const log = store.getConsentLog();
      expect(log.length).toBe(2);
      expect(log[0].type).toBe("functional");
      expect(log[0].state).toBe("granted");
      expect(log[1].type).toBe("analytics");
      expect(log[1].state).toBe("granted");
    });

    it("동의 로그를 낼쳐내기할 수 있어야 함", () => {
      store.setConsent("functional", true);
      store.setConsent("functional", false);

      const exported = store.exportConsentLog();
      expect(exported.entries.length).toBe(2);
      expect(exported.summary.totalEntries).toBe(2);
      expect(exported.summary.grantsByType.functional).toBe(1);
      expect(exported.summary.denialsByType.functional).toBe(1);
    });

    it("로그가 100개를 초과하면 오래된 항목이 제거되어야 함", () => {
      // 105개의 로그 항목 생성
      for (let i = 0; i < 105; i++) {
        store.setConsent("functional", i % 2 === 0);
      }

      const log = store.getConsentLog();
      expect(log.length).toBe(100);
    });
  });

  describe("처리 목적", () => {
    beforeEach(() => {
      store.initialize();
    });

    it("각 동의 유형의 처리 목적을 조회할 수 있어야 함", () => {
      const necessaryPurposes = store.getPurposes("necessary");
      expect(necessaryPurposes.length).toBeGreaterThan(0);
      expect(necessaryPurposes).toContain("서비스 제공을 위한 필수 기능");

      const analyticsPurposes = store.getPurposes("analytics");
      expect(analyticsPurposes.length).toBeGreaterThan(0);
      expect(analyticsPurposes).toContain("서비스 사용 현황 분석");
    });

    it("모든 처리 목적을 조회할 수 있어야 함", () => {
      const allPurposes = store.getAllPurposes();
      expect(Object.keys(allPurposes)).toHaveLength(4);
      expect(allPurposes.necessary.length).toBeGreaterThan(0);
      expect(allPurposes.functional.length).toBeGreaterThan(0);
      expect(allPurposes.analytics.length).toBeGreaterThan(0);
      expect(allPurposes.marketing.length).toBeGreaterThan(0);
    });
  });

  describe("버전 정보", () => {
    beforeEach(() => {
      store.initialize();
    });

    it("버전 정보를 조회할 수 있어야 함", () => {
      const version = store.getVersionInfo();
      expect(version.consentVersion).toBe("1.0.0");
      expect(version.privacyPolicyVersion).toBe("1.0.0");
      expect(version.expiryDays).toBe(365);
    });
  });

  describe("이벤트 리스너", () => {
    beforeEach(() => {
      store.initialize();
    });

    it("동의 변경 시 리스너가 호출되어야 함", () => {
      const listener = vi.fn();
      const unsubscribe = store.onChange(listener);

      store.setConsent("functional", true);

      expect(listener).toHaveBeenCalledTimes(1);
      expect(listener).toHaveBeenCalledWith(
        expect.objectContaining({
          necessary: true,
          functional: true,
        }),
      );

      unsubscribe();
    });

    it("구독 해제 후 리스너가 호출되지 않아야 함", () => {
      const listener = vi.fn();
      const unsubscribe = store.onChange(listener);

      unsubscribe();
      store.setConsent("functional", true);

      expect(listener).not.toHaveBeenCalled();
    });
  });

  describe("유틸리티 함수", () => {
    beforeEach(() => {
      // 유틸리티 함수 테스트를 위해 글로벌 인스턴스 초기화
      const freshStore = initializeConsentStore({
        storageKeyPrefix: "test-consent-util",
        consentVersion: "1.0.0",
        privacyPolicyVersion: "1.0.0",
      });
      freshStore.initialize();
      freshStore.clear();
      freshStore.initialize();
    });

    it("canExecuteScript는 동의 상태를 반영해야 함", () => {
      const testStore = initializeConsentStore({
        storageKeyPrefix: "test-consent-script",
        consentVersion: "1.0.0",
        privacyPolicyVersion: "1.0.0",
      });
      testStore.initialize();

      expect(canExecuteScript("functional")).toBe(false);

      testStore.setConsent("functional", true);
      expect(canExecuteScript("functional")).toBe(true);
    });

    it("canSetCookie는 동의 상태를 반영해야 함", () => {
      const testStore = initializeConsentStore({
        storageKeyPrefix: "test-consent-cookie",
        consentVersion: "1.0.0",
        privacyPolicyVersion: "1.0.0",
      });
      testStore.initialize();

      expect(canSetCookie("analytics")).toBe(false);

      testStore.setConsent("analytics", true);
      expect(canSetCookie("analytics")).toBe(true);
    });

    it("shouldShowConsentBanner는 동의 필요 여부를 반영해야 함", () => {
      const testStore = initializeConsentStore({
        storageKeyPrefix: "test-consent-banner",
        consentVersion: "1.0.0",
        privacyPolicyVersion: "1.0.0",
      });
      testStore.initialize();

      expect(shouldShowConsentBanner()).toBe(true);

      testStore.setConsent("functional", true);
      testStore.setConsent("analytics", true);
      testStore.setConsent("marketing", true);

      expect(shouldShowConsentBanner()).toBe(false);
    });

    it("exportConsentSettings는 설정을 JSON으로 반환해야 함", () => {
      const testStore = initializeConsentStore({
        storageKeyPrefix: "test-consent-export",
        consentVersion: "1.0.0",
        privacyPolicyVersion: "1.0.0",
      });
      testStore.initialize();

      testStore.setConsent("functional", true);
      const exported = exportConsentSettings();
      const parsed = JSON.parse(exported);

      expect(parsed.preferences.functional).toBe(true);
      expect(parsed.version.consentVersion).toBe("1.0.0");
    });

    it("getConsentStatus는 현재 상태를 반환해야 함", () => {
      const status = getConsentStatus();
      expect(status.initialized).toBe(true);
      expect(status.preferences.necessary).toBe(true);
    });
  });

  describe("싱글톤 패턴", () => {
    it("initializeConsentStore는 ConsentStore 인스턴스를 반환해야 함", () => {
      // 글로벌 인스턴스 초기화
      const store = initializeConsentStore({
        storageKeyPrefix: "test-singleton-new",
        consentVersion: "1.0.0",
        privacyPolicyVersion: "1.0.0",
      });

      // ConsentStore 인스턴스인지 확인
      expect(store).toBeInstanceOf(ConsentStore);
      expect(store.initialized).toBe(true);
    });
  });
});
