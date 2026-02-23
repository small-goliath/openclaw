/**
 * GDPR 쿠키 동의 배너 컴포넌트
 * COMP-003, COMP-004, SEC-4.2, SEC-7.3 요구사항 구현
 *
 * 기능:
 * - 세분화된 동의 관리 (analytics, functional, marketing)
 * - 슬라이드업 배너 UI
 * - 접근성 지원 (ARIA, 키보드 네비게이션)
 */

import { LitElement, html, css, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { classMap } from "lit/directives/class-map.js";

/**
 * 동의 유형
 */
type ConsentType = "necessary" | "functional" | "analytics" | "marketing";

/**
 * 동의 설정 인터페이스
 */
interface ConsentPreferences {
  necessary: boolean;
  functional: boolean;
  analytics: boolean;
  marketing: boolean;
}

/**
 * 동의 항목 메타데이터
 */
interface ConsentItemMeta {
  key: ConsentType;
  title: string;
  description: string;
  required: boolean;
  icon: string;
}

/**
 * 동의 항목 메타데이터 정의
 */
const CONSENT_ITEMS: ConsentItemMeta[] = [
  {
    key: "necessary",
    title: "필수 쿠키",
    description: "서비스 제공을 위해 필수적인 쿠키입니다. 이 쿠키는 비활성화할 수 없습니다.",
    required: true,
    icon: "shield",
  },
  {
    key: "functional",
    title: "기능성 쿠키",
    description: "사용자 설정과 선호도를 저장하여 더 나은 사용자 경험을 제공합니다.",
    required: false,
    icon: "settings",
  },
  {
    key: "analytics",
    title: "분석 쿠키",
    description: "서비스 사용 현황을 분석하여 성능을 개선하는 데 사용됩니다.",
    required: false,
    icon: "bar-chart",
  },
  {
    key: "marketing",
    title: "마케팅 쿠키",
    description: "맞춤형 광고와 마케팅 캠페인에 사용됩니다.",
    required: false,
    icon: "target",
  },
];

/**
 * 아이콘 SVG 정의
 */
const ICONS: Record<string, string> = {
  shield: `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  `,
  settings: `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <circle cx="12" cy="12" r="3"/>
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    </svg>
  `,
  "bar-chart": `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <line x1="12" y1="20" x2="12" y2="10"/>
      <line x1="18" y1="20" x2="18" y2="4"/>
      <line x1="6" y1="20" x2="6" y2="16"/>
    </svg>
  `,
  target: `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <circle cx="12" cy="12" r="10"/>
      <circle cx="12" cy="12" r="6"/>
      <circle cx="12" cy="12" r="2"/>
    </svg>
  `,
  x: `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <line x1="18" y1="6" x2="6" y2="18"/>
      <line x1="6" y1="6" x2="18" y2="18"/>
    </svg>
  `,
  "chevron-down": `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <polyline points="6 9 12 15 18 9"/>
    </svg>
  `,
  "chevron-up": `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <polyline points="18 15 12 9 6 15"/>
    </svg>
  `,
  "external-link": `
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
      <polyline points="15 3 21 3 21 9"/>
      <line x1="10" y1="14" x2="21" y2="3"/>
    </svg>
  `,
};

/**
 * 쿠키 동의 배너 컴포넌트
 */
@customElement("consent-banner")
export class ConsentBanner extends LitElement {
  @property({ type: Boolean, reflect: true }) visible = false;
  @property({ type: String }) privacyPolicyUrl = "/privacy-policy";
  @property({ type: Boolean }) showDetails = false;

  @state() private preferences: ConsentPreferences = {
    necessary: true,
    functional: false,
    analytics: false,
    marketing: false,
  };

  @state() private expandedItems: Set<ConsentType> = new Set();
  @state() private isClosing = false;

  static styles = css`
    :host {
      --banner-bg: var(--surface-elevated, #1a1a2e);
      --banner-text: var(--text-primary, #ffffff);
      --banner-text-secondary: var(--text-secondary, #a0a0a0);
      --banner-border: var(--border-color, #333344);
      --banner-accent: var(--accent-color, #4f46e5);
      --banner-accent-hover: var(--accent-hover, #4338ca);
      --banner-success: var(--success-color, #10b981);
      --banner-radius: 12px;
      --banner-shadow: 0 -4px 20px rgba(0, 0, 0, 0.3);

      display: block;
      position: fixed;
      bottom: 0;
      left: 0;
      right: 0;
      z-index: 9999;
      font-family:
        system-ui,
        -apple-system,
        sans-serif;
    }

    .banner-overlay {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.5);
      opacity: 0;
      visibility: hidden;
      transition:
        opacity 0.3s ease,
        visibility 0.3s ease;
    }

    .banner-overlay.visible {
      opacity: 1;
      visibility: visible;
    }

    .banner-container {
      background: var(--banner-bg);
      border-top: 1px solid var(--banner-border);
      box-shadow: var(--banner-shadow);
      transform: translateY(100%);
      transition: transform 0.4s cubic-bezier(0.16, 1, 0.3, 1);
      max-height: 80vh;
      overflow-y: auto;
    }

    .banner-container.visible {
      transform: translateY(0);
    }

    .banner-container.closing {
      transform: translateY(100%);
    }

    .banner-content {
      max-width: 1200px;
      margin: 0 auto;
      padding: 24px;
    }

    .banner-header {
      display: flex;
      align-items: flex-start;
      gap: 16px;
      margin-bottom: 20px;
    }

    .banner-icon {
      width: 48px;
      height: 48px;
      background: var(--banner-accent);
      border-radius: 12px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .banner-icon svg {
      width: 24px;
      height: 24px;
      color: white;
    }

    .banner-title-section {
      flex: 1;
    }

    .banner-title {
      font-size: 20px;
      font-weight: 600;
      color: var(--banner-text);
      margin: 0 0 8px 0;
    }

    .banner-description {
      font-size: 14px;
      color: var(--banner-text-secondary);
      line-height: 1.6;
      margin: 0;
    }

    .banner-close {
      background: none;
      border: none;
      color: var(--banner-text-secondary);
      cursor: pointer;
      padding: 8px;
      border-radius: 8px;
      transition: all 0.2s ease;
      flex-shrink: 0;
    }

    .banner-close:hover {
      background: var(--banner-border);
      color: var(--banner-text);
    }

    .banner-close svg {
      width: 20px;
      height: 20px;
    }

    .banner-actions {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-bottom: 20px;
    }

    .btn {
      padding: 12px 24px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s ease;
      border: none;
      display: inline-flex;
      align-items: center;
      gap: 8px;
    }

    .btn-primary {
      background: var(--banner-accent);
      color: white;
    }

    .btn-primary:hover {
      background: var(--banner-accent-hover);
    }

    .btn-secondary {
      background: var(--banner-border);
      color: var(--banner-text);
    }

    .btn-secondary:hover {
      background: #444455;
    }

    .btn-ghost {
      background: transparent;
      color: var(--banner-text-secondary);
      border: 1px solid var(--banner-border);
    }

    .btn-ghost:hover {
      background: var(--banner-border);
      color: var(--banner-text);
    }

    .details-toggle {
      display: flex;
      align-items: center;
      gap: 8px;
      color: var(--banner-text-secondary);
      font-size: 14px;
      cursor: pointer;
      padding: 8px 0;
      background: none;
      border: none;
      width: 100%;
      justify-content: flex-start;
    }

    .details-toggle:hover {
      color: var(--banner-text);
    }

    .details-toggle svg {
      width: 16px;
      height: 16px;
      transition: transform 0.2s ease;
    }

    .details-toggle.expanded svg {
      transform: rotate(180deg);
    }

    .details-section {
      display: none;
      margin-top: 20px;
      padding-top: 20px;
      border-top: 1px solid var(--banner-border);
    }

    .details-section.visible {
      display: block;
    }

    .consent-list {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .consent-item {
      background: rgba(255, 255, 255, 0.03);
      border: 1px solid var(--banner-border);
      border-radius: 10px;
      padding: 16px;
      transition: all 0.2s ease;
    }

    .consent-item:hover {
      background: rgba(255, 255, 255, 0.05);
    }

    .consent-item-header {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .consent-item-icon {
      width: 40px;
      height: 40px;
      background: var(--banner-border);
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .consent-item-icon svg {
      width: 20px;
      height: 20px;
      color: var(--banner-text);
    }

    .consent-item-info {
      flex: 1;
    }

    .consent-item-title {
      font-size: 15px;
      font-weight: 500;
      color: var(--banner-text);
      margin: 0 0 4px 0;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .consent-item-description {
      font-size: 13px;
      color: var(--banner-text-secondary);
      margin: 0;
    }

    .consent-item-required {
      font-size: 11px;
      font-weight: 600;
      color: var(--banner-success);
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .toggle-switch {
      position: relative;
      width: 48px;
      height: 26px;
      background: var(--banner-border);
      border-radius: 13px;
      cursor: pointer;
      transition: background 0.3s ease;
      flex-shrink: 0;
    }

    .toggle-switch.active {
      background: var(--banner-accent);
    }

    .toggle-switch.disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .toggle-switch::after {
      content: "";
      position: absolute;
      top: 3px;
      left: 3px;
      width: 20px;
      height: 20px;
      background: white;
      border-radius: 50%;
      transition: transform 0.3s ease;
      box-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
    }

    .toggle-switch.active::after {
      transform: translateX(22px);
    }

    .consent-item-details {
      margin-top: 12px;
      padding-top: 12px;
      border-top: 1px solid var(--banner-border);
      display: none;
    }

    .consent-item.expanded .consent-item-details {
      display: block;
    }

    .purposes-list {
      list-style: none;
      margin: 0;
      padding: 0;
      display: flex;
      flex-direction: column;
      gap: 8px;
    }

    .purposes-list li {
      font-size: 13px;
      color: var(--banner-text-secondary);
      display: flex;
      align-items: flex-start;
      gap: 8px;
    }

    .purposes-list li::before {
      content: "•";
      color: var(--banner-accent);
      font-weight: bold;
    }

    .expand-btn {
      background: none;
      border: none;
      color: var(--banner-text-secondary);
      cursor: pointer;
      padding: 4px;
      border-radius: 4px;
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.2s ease;
    }

    .expand-btn:hover {
      background: var(--banner-border);
      color: var(--banner-text);
    }

    .expand-btn svg {
      width: 16px;
      height: 16px;
      transition: transform 0.2s ease;
    }

    .consent-item.expanded .expand-btn svg {
      transform: rotate(180deg);
    }

    .privacy-link {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      color: var(--banner-accent);
      text-decoration: none;
      font-size: 14px;
      margin-top: 12px;
    }

    .privacy-link:hover {
      text-decoration: underline;
    }

    .privacy-link svg {
      width: 14px;
      height: 14px;
    }

    @media (max-width: 640px) {
      .banner-content {
        padding: 16px;
      }

      .banner-header {
        flex-direction: column;
        gap: 12px;
      }

      .banner-actions {
        flex-direction: column;
      }

      .btn {
        width: 100%;
        justify-content: center;
      }

      .consent-item-header {
        flex-wrap: wrap;
      }
    }

    /* 접근성: 포커스 스타일 */
    .btn:focus-visible,
    .toggle-switch:focus-visible,
    .banner-close:focus-visible,
    .details-toggle:focus-visible,
    .expand-btn:focus-visible {
      outline: 2px solid var(--banner-accent);
      outline-offset: 2px;
    }

    /* 접근성: reduced motion */
    @media (prefers-reduced-motion: reduce) {
      .banner-container,
      .banner-overlay,
      .toggle-switch,
      .toggle-switch::after,
      .details-toggle svg,
      .expand-btn svg {
        transition: none;
      }
    }
  `;

  connectedCallback() {
    super.connectedCallback();
    this.loadPreferences();
    this.setupKeyboardNavigation();
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    this.removeKeyboardListeners();
  }

  /**
   * 저장된 동의 설정 로드
   */
  private loadPreferences() {
    try {
      const stored = localStorage.getItem("openclaw-consent-preferences");
      if (stored) {
        const parsed = JSON.parse(stored);
        this.preferences = {
          necessary: true, // 필수는 항상 true
          functional: parsed.functional ?? false,
          analytics: parsed.analytics ?? false,
          marketing: parsed.marketing ?? false,
        };
      }
    } catch {
      // 저장된 설정이 없거나 오류 발생 시 기본값 사용
    }
  }

  /**
   * 동의 설정 저장
   */
  private savePreferences() {
    try {
      localStorage.setItem("openclaw-consent-preferences", JSON.stringify(this.preferences));
      localStorage.setItem("openclaw-consent-version", "1.0.0");
      localStorage.setItem("openclaw-consent-timestamp", new Date().toISOString());

      // 동의 변경 이벤트 발생
      this.dispatchEvent(
        new CustomEvent("consent-change", {
          detail: { ...this.preferences },
          bubbles: true,
          composed: true,
        }),
      );
    } catch {
      // 저장 실패 시 조용히 무시
    }
  }

  /**
   * 키보드 네비게이션 설정
   */
  private setupKeyboardNavigation() {
    document.addEventListener("keydown", this.handleKeyDown);
  }

  private removeKeyboardListeners() {
    document.removeEventListener("keydown", this.handleKeyDown);
  }

  private handleKeyDown = (e: KeyboardEvent) => {
    if (!this.visible) {
      return;
    }

    // ESC 키로 배너 닫기 (설정은 저장하지 않음)
    if (e.key === "Escape") {
      this.closeBanner();
    }
  };

  /**
   * 배너 닫기
   */
  private closeBanner() {
    this.isClosing = true;
    setTimeout(() => {
      this.visible = false;
      this.isClosing = false;
    }, 400);
  }

  /**
   * 모든 동의 수락
   */
  private acceptAll() {
    this.preferences = {
      necessary: true,
      functional: true,
      analytics: true,
      marketing: true,
    };
    this.savePreferences();
    this.closeBanner();
  }

  /**
   * 필수 동의만 수락
   */
  private acceptNecessaryOnly() {
    this.preferences = {
      necessary: true,
      functional: false,
      analytics: false,
      marketing: false,
    };
    this.savePreferences();
    this.closeBanner();
  }

  /**
   * 사용자 설정 저장
   */
  private savePreferencesAndClose() {
    this.savePreferences();
    this.closeBanner();
  }

  /**
   * 개별 동의 토글
   */
  private toggleConsent(type: ConsentType) {
    if (type === "necessary") {
      return;
    } // 필수는 변경 불가

    this.preferences = {
      ...this.preferences,
      [type]: !this.preferences[type],
    };
  }

  /**
   * 상세 정보 토글
   */
  private toggleDetails() {
    this.showDetails = !this.showDetails;
  }

  /**
   * 개별 항목 확장 토글
   */
  private toggleItemExpand(key: ConsentType) {
    const newExpanded = new Set(this.expandedItems);
    if (newExpanded.has(key)) {
      newExpanded.delete(key);
    } else {
      newExpanded.add(key);
    }
    this.expandedItems = newExpanded;
  }

  /**
   * 처리 목적 가져오기
   */
  private getPurposes(type: ConsentType): string[] {
    const purposes: Record<ConsentType, string[]> = {
      necessary: [
        "서비스 제공을 위한 필수 기능",
        "보안 및 인증",
        "사용자 세션 관리",
        "서비스 가용성 유지",
      ],
      functional: [
        "사용자 설정 저장",
        "언어 및 지역 설정",
        "테마 및 디스플레이 설정",
        "사용자 편의 기능",
      ],
      analytics: [
        "서비스 사용 현황 분석",
        "성능 모니터링",
        "오류 추적 및 개선",
        "사용자 경험 개선",
      ],
      marketing: [
        "맞춤형 광고 제공",
        "마케팅 캠페인 효과 측정",
        "사용자 세그먼트 분석",
        "제품 개선을 위한 피드백 수집",
      ],
    };
    return purposes[type];
  }

  render() {
    const overlayClasses = classMap({
      "banner-overlay": true,
      visible: this.visible,
    });

    const containerClasses = classMap({
      "banner-container": true,
      visible: this.visible && !this.isClosing,
      closing: this.isClosing,
    });

    const detailsClasses = classMap({
      "details-section": true,
      visible: this.showDetails,
    });

    return html`
      <div class="${overlayClasses}" @click="${this.closeBanner}"></div>
      <div class="${containerClasses}" role="dialog" aria-modal="true" aria-labelledby="consent-title">
        <div class="banner-content">
          <div class="banner-header">
            <div class="banner-icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
            </div>
            <div class="banner-title-section">
              <h2 id="consent-title" class="banner-title" lang="ko">쿠키 및 개인정보 처리 동의</h2>
              <p class="banner-description" lang="ko">
                저희 서비스는 최상의 경험을 제공하기 위해 쿠키를 사용합니다.
                아래에서 각 유형의 쿠키 사용에 대한 동의 여부를 선택하실 수 있습니다.
                필수 쿠키는 서비스 제공을 위해 필요하며 비활성화할 수 없습니다.
              </p>
            </div>
            <button 
              class="banner-close" 
              @click="${this.closeBanner}"
              aria-label="배너 닫기"
              lang="ko"
            >
              ${ICONS["x"]}
            </button>
          </div>

          <div class="banner-actions">
            <button class="btn btn-secondary" @click="${this.acceptNecessaryOnly}" lang="ko">
              필수만 수락
            </button>
            <button class="btn btn-secondary" @click="${this.acceptAll}" lang="ko">
              모두 수락
            </button>
            <button class="btn btn-ghost" @click="${this.savePreferencesAndClose}" lang="ko">
              설정 저장
            </button>
          </div>

          <button
            class="details-toggle ${this.showDetails ? "expanded" : ""}"
            @click="${this.toggleDetails}"
            aria-expanded="${this.showDetails}"
            lang="ko"
          >
            <span>상세 설정</span>
            ${ICONS["chevron-down"]}
          </button>

          <div class="${detailsClasses}">
            <div class="consent-list">
              ${CONSENT_ITEMS.map((item) => {
                const isExpanded = this.expandedItems.has(item.key);
                const isActive = this.preferences[item.key];

                return html`
                  <div class="consent-item ${isExpanded ? "expanded" : ""}">
                    <div class="consent-item-header">
                      <div class="consent-item-icon">
                        ${ICONS[item.icon]}
                      </div>
                      <div class="consent-item-info">
                        <h3 class="consent-item-title" lang="ko">
                          ${item.title}
                          ${
                            item.required
                              ? html`
                                  <span class="consent-item-required" lang="ko">필수</span>
                                `
                              : nothing
                          }
                        </h3>
                        <p class="consent-item-description" lang="ko">${item.description}</p>
                      </div>
                      <button
                        class="expand-btn"
                        @click="${() => this.toggleItemExpand(item.key)}"
                        aria-label="${isExpanded ? "접기" : "펼치기"}"
                        aria-expanded="${isExpanded}"
                        lang="ko"
                      >
                        ${ICONS["chevron-down"]}
                      </button>
                      <div
                        class="toggle-switch ${isActive ? "active" : ""} ${item.required ? "disabled" : ""}"
                        @click="${() => this.toggleConsent(item.key)}"
                        role="switch"
                        aria-checked="${isActive}"
                        aria-label="${item.title} 토글"
                        lang="ko"
                        tabindex="${item.required ? "-1" : "0"}"
                      ></div>
                    </div>
                    <div class="consent-item-details">
                      <ul class="purposes-list" lang="ko">
                        ${this.getPurposes(item.key).map((purpose) => html`<li lang="ko">${purpose}</li>`)}
                      </ul>
                    </div>
                  </div>
                `;
              })}
            </div>

            <a
              href="${this.privacyPolicyUrl}"
              class="privacy-link"
              target="_blank"
              rel="noopener noreferrer"
              lang="ko"
            >
              개인정보 처리방침 전문 보기
              ${ICONS["external-link"]}
            </a>
          </div>
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "consent-banner": ConsentBanner;
  }
}

/**
 * 배너 표시 헬퍼 함수
 */
export function showConsentBanner(): void {
  const banner = document.querySelector("consent-banner") as ConsentBanner;
  if (banner) {
    banner.visible = true;
  }
}

/**
 * 배너 숨김 헬퍼 함수
 */
export function hideConsentBanner(): void {
  const banner = document.querySelector("consent-banner") as ConsentBanner;
  if (banner) {
    banner.visible = false;
  }
}

/**
 * 동의 설정 가져오기
 */
export function getConsentPreferences(): ConsentPreferences {
  try {
    const stored = localStorage.getItem("openclaw-consent-preferences");
    if (stored) {
      return JSON.parse(stored);
    }
  } catch {
    // 오류 시 기본값 반환
  }
  return {
    necessary: true,
    functional: false,
    analytics: false,
    marketing: false,
  };
}

/**
 * 동의가 필요한지 확인
 */
export function needsConsent(): boolean {
  try {
    const stored = localStorage.getItem("openclaw-consent-preferences");
    const version = localStorage.getItem("openclaw-consent-version");

    // 저장된 설정이 없거나 버전이 다른 경우
    if (!stored || version !== "1.0.0") {
      return true;
    }

    // 모든 동의가 거부된 경우 (초기 상태)
    const preferences = JSON.parse(stored);
    return !preferences.functional && !preferences.analytics && !preferences.marketing;
  } catch {
    return true;
  }
}
