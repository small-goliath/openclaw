/**
 * 개인정보 처리방침 페이지
 * COMP-003, COMP-004, SEC-4.2, SEC-7.3 요구사항 구현
 *
 * 기능:
 * - 개인정보 처리방침 콘텐츠
 * - 데이터 처리 목적 문서화
 * - 사용자 권리 설명
 * - 동의 관리 인터페이스
 * - 동의 로그 조회
 */

import { html, css, LitElement } from "lit";
import { customElement, state } from "lit/decorators.js";

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
 * 동의 로그 항목
 */
interface ConsentLogEntry {
  timestamp: string;
  type: string;
  state: string;
  consentVersion: string;
  privacyPolicyVersion: string;
  purposes: string[];
}

/**
 * 개인정보 처리방침 페이지 컴포넌트
 */
@customElement("privacy-policy-page")
export class PrivacyPolicyPage extends LitElement {
  @state() private preferences: ConsentPreferences = {
    necessary: true,
    functional: false,
    analytics: false,
    marketing: false,
  };

  @state() private consentLog: ConsentLogEntry[] = [];
  @state() private showConsentManager = false;
  @state() private showConsentLog = false;
  @state() private lastUpdated = "2024-01-01";

  static styles = css`
    :host {
      display: block;
      max-width: 800px;
      margin: 0 auto;
      padding: 40px 20px;
      font-family:
        system-ui,
        -apple-system,
        sans-serif;
      line-height: 1.7;
      color: var(--text-primary, #ffffff);
      background: var(--surface-primary, #0f0f1a);
    }

    .page-header {
      margin-bottom: 48px;
      padding-bottom: 24px;
      border-bottom: 1px solid var(--border-color, #333344);
    }

    h1 {
      font-size: 32px;
      font-weight: 700;
      margin: 0 0 16px 0;
      color: var(--text-primary, #ffffff);
    }

    .last-updated {
      font-size: 14px;
      color: var(--text-secondary, #a0a0a0);
    }

    h2 {
      font-size: 24px;
      font-weight: 600;
      margin: 48px 0 20px 0;
      color: var(--text-primary, #ffffff);
      padding-bottom: 12px;
      border-bottom: 2px solid var(--accent-color, #4f46e5);
    }

    h3 {
      font-size: 18px;
      font-weight: 600;
      margin: 32px 0 16px 0;
      color: var(--text-primary, #ffffff);
    }

    p {
      margin: 0 0 16px 0;
      color: var(--text-secondary, #cccccc);
    }

    ul,
    ol {
      margin: 0 0 16px 0;
      padding-left: 24px;
      color: var(--text-secondary, #cccccc);
    }

    li {
      margin-bottom: 8px;
    }

    a {
      color: var(--accent-color, #4f46e5);
      text-decoration: none;
    }

    a:hover {
      text-decoration: underline;
    }

    .consent-manager {
      background: var(--surface-elevated, #1a1a2e);
      border: 1px solid var(--border-color, #333344);
      border-radius: 12px;
      padding: 24px;
      margin: 32px 0;
    }

    .consent-manager h3 {
      margin-top: 0;
    }

    .consent-status {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin: 20px 0;
    }

    .consent-status-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 12px 16px;
      background: rgba(255, 255, 255, 0.03);
      border-radius: 8px;
      border: 1px solid var(--border-color, #333344);
    }

    .consent-status-label {
      font-weight: 500;
    }

    .consent-status-value {
      font-size: 13px;
      font-weight: 600;
      padding: 4px 12px;
      border-radius: 20px;
    }

    .consent-status-value.granted {
      background: rgba(16, 185, 129, 0.2);
      color: #10b981;
    }

    .consent-status-value.denied {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
    }

    .consent-status-value.required {
      background: rgba(79, 70, 229, 0.2);
      color: #818cf8;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 12px 24px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s ease;
      border: none;
      margin-right: 12px;
      margin-bottom: 12px;
    }

    .btn-primary {
      background: var(--accent-color, #4f46e5);
      color: white;
    }

    .btn-primary:hover {
      background: var(--accent-hover, #4338ca);
    }

    .btn-secondary {
      background: var(--surface-elevated, #1a1a2e);
      color: var(--text-primary, #ffffff);
      border: 1px solid var(--border-color, #333344);
    }

    .btn-secondary:hover {
      background: var(--border-color, #333344);
    }

    .btn-danger {
      background: rgba(239, 68, 68, 0.2);
      color: #ef4444;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }

    .btn-danger:hover {
      background: rgba(239, 68, 68, 0.3);
    }

    .consent-log {
      margin-top: 24px;
      max-height: 400px;
      overflow-y: auto;
    }

    .consent-log table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    .consent-log th,
    .consent-log td {
      padding: 12px;
      text-align: left;
      border-bottom: 1px solid var(--border-color, #333344);
    }

    .consent-log th {
      font-weight: 600;
      color: var(--text-primary, #ffffff);
      background: rgba(255, 255, 255, 0.03);
      position: sticky;
      top: 0;
    }

    .consent-log td {
      color: var(--text-secondary, #cccccc);
    }

    .consent-log tr:hover td {
      background: rgba(255, 255, 255, 0.02);
    }

    .data-table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
      font-size: 14px;
    }

    .data-table th,
    .data-table td {
      padding: 12px 16px;
      text-align: left;
      border-bottom: 1px solid var(--border-color, #333344);
    }

    .data-table th {
      font-weight: 600;
      color: var(--text-primary, #ffffff);
      background: rgba(255, 255, 255, 0.03);
    }

    .data-table td {
      color: var(--text-secondary, #cccccc);
    }

    .highlight-box {
      background: rgba(79, 70, 229, 0.1);
      border-left: 4px solid var(--accent-color, #4f46e5);
      padding: 20px;
      margin: 24px 0;
      border-radius: 0 8px 8px 0;
    }

    .highlight-box p {
      margin: 0;
    }

    .rights-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 20px;
      margin: 24px 0;
    }

    .right-card {
      background: var(--surface-elevated, #1a1a2e);
      border: 1px solid var(--border-color, #333344);
      border-radius: 12px;
      padding: 20px;
    }

    .right-card h4 {
      margin: 0 0 12px 0;
      font-size: 16px;
      font-weight: 600;
      color: var(--text-primary, #ffffff);
    }

    .right-card p {
      margin: 0;
      font-size: 14px;
    }

    .contact-info {
      background: var(--surface-elevated, #1a1a2e);
      border: 1px solid var(--border-color, #333344);
      border-radius: 12px;
      padding: 24px;
      margin: 24px 0;
    }

    .contact-info h4 {
      margin: 0 0 16px 0;
      font-size: 16px;
      font-weight: 600;
    }

    .contact-item {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-bottom: 12px;
      font-size: 14px;
    }

    .contact-item svg {
      width: 18px;
      height: 18px;
      color: var(--accent-color, #4f46e5);
    }

    @media (max-width: 640px) {
      :host {
        padding: 20px 16px;
      }

      h1 {
        font-size: 24px;
      }

      h2 {
        font-size: 20px;
      }

      .consent-status {
        grid-template-columns: 1fr;
      }

      .consent-log {
        overflow-x: auto;
      }

      .consent-log table {
        min-width: 600px;
      }

      .rights-grid {
        grid-template-columns: 1fr;
      }
    }
  `;

  connectedCallback() {
    super.connectedCallback();
    this.loadPreferences();
    this.loadConsentLog();
  }

  /**
   * 동의 설정 로드
   */
  private loadPreferences() {
    try {
      const stored = localStorage.getItem("openclaw-consent-preferences");
      if (stored) {
        this.preferences = {
          ...this.preferences,
          ...JSON.parse(stored),
        };
      }
    } catch {
      // 저장된 설정이 없거나 오류 발생 시 기본값 사용
    }
  }

  /**
   * 동의 로그 로드
   */
  private loadConsentLog() {
    try {
      const stored = localStorage.getItem("openclaw-consent-log");
      if (stored) {
        this.consentLog = JSON.parse(stored);
      }
    } catch {
      // 저장된 로그가 없거나 오류 발생 시 빈 배열 사용
    }
  }

  /**
   * 동의 설정 저장
   */
  private savePreferences() {
    try {
      localStorage.setItem("openclaw-consent-preferences", JSON.stringify(this.preferences));
      localStorage.setItem("openclaw-consent-timestamp", new Date().toISOString());

      // 동의 변경 이벤트 발생
      window.dispatchEvent(
        new CustomEvent("consent-change", {
          detail: { ...this.preferences },
        }),
      );
    } catch {
      // 저장 실패 시 조용히 무시
    }
  }

  /**
   * 개별 동의 토글
   */
  private toggleConsent(type: keyof ConsentPreferences) {
    if (type === "necessary") {
      return;
    } // 필수는 변경 불가

    this.preferences = {
      ...this.preferences,
      [type]: !this.preferences[type],
    };

    this.savePreferences();
    this.logConsentChange(type, this.preferences[type] ? "granted" : "denied");
  }

  /**
   * 동의 변경 로그 기록
   */
  private logConsentChange(type: string, state: string) {
    const entry: ConsentLogEntry = {
      timestamp: new Date().toISOString(),
      type,
      state,
      consentVersion: "1.0.0",
      privacyPolicyVersion: "1.0.0",
      purposes: this.getPurposes(type),
    };

    this.consentLog = [...this.consentLog, entry];

    // 로그 크기 제한 (최근 100개만 유지)
    if (this.consentLog.length > 100) {
      this.consentLog = this.consentLog.slice(-100);
    }

    try {
      localStorage.setItem("openclaw-consent-log", JSON.stringify(this.consentLog));
    } catch {
      // 저장 실패 시 조용히 무시
    }
  }

  /**
   * 처리 목적 가져오기
   */
  private getPurposes(type: string): string[] {
    const purposes: Record<string, string[]> = {
      necessary: ["서비스 제공을 위한 필수 기능"],
      functional: ["사용자 설정 저장"],
      analytics: ["서비스 사용 현황 분석"],
      marketing: ["맞춤형 광고 제공"],
    };
    return purposes[type] || [];
  }

  /**
   * 모든 동의 철회
   */
  private revokeAllConsents() {
    if (confirm("모든 선택적 동의를 철회하시겠습니까? 이 작업은 되돌릴 수 없습니다.")) {
      this.preferences = {
        necessary: true,
        functional: false,
        analytics: false,
        marketing: false,
      };
      this.savePreferences();
      this.logConsentChange("all", "revoked");
      alert("모든 동의가 철회되었습니다.");
    }
  }

  /**
   * 동의 로그 내보내기
   */
  private exportConsentLog() {
    const exportData = {
      exportedAt: new Date().toISOString(),
      version: "1.0.0",
      entries: this.consentLog,
      summary: {
        totalEntries: this.consentLog.length,
        grants: this.consentLog.filter((e) => e.state === "granted").length,
        denials: this.consentLog.filter((e) => e.state === "denied").length,
      },
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `consent-log-${new Date().toISOString().split("T")[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  /**
   * 날짜 포맷팅
   */
  private formatDate(timestamp: string): string {
    try {
      const date = new Date(timestamp);
      return date.toLocaleString("ko-KR", {
        year: "numeric",
        month: "long",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return timestamp;
    }
  }

  render() {
    return html`
      <div class="page-header">
        <h1>개인정보 처리방침</h1>
        <p class="last-updated">최종 업데이트: ${this.lastUpdated}</p>
      </div>

      <section>
        <h2>1. 소개</h2>
        <p>
          OpenClaw(이하 "회사")는 사용자의 개인정보 보호를 매우 중요하게 생각합니다. 
          본 개인정보 처리방침은 당사가 수집하는 개인정보의 종류, 수집 목적, 보관 기간, 
          그리고 사용자의 권리에 대해 설명합니다.
        </p>
        <p>
          본 서비스를 이용함으로써 사용자는 본 개인정보 처리방침에 동의하는 것으로 간주됩니다. 
          동의하지 않는 경우 서비스 이용이 제한될 수 있습니다.
        </p>
      </section>

      <section>
        <h2>2. 수집하는 개인정보</h2>
        <p>당사는 다음과 같은 개인정보를 수집할 수 있습니다:</p>
        
        <table class="data-table">
          <thead>
            <tr>
              <th>정보 유형</th>
              <th>수집 목적</th>
              <th>보관 기간</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>계정 정보</td>
              <td>서비스 제공 및 사용자 인증</td>
              <td>계정 삭제 시까지</td>
            </tr>
            <tr>
              <td>세션 데이터</td>
              <td>대화 기록 및 서비스 개선</td>
              <td>30일</td>
            </tr>
            <tr>
              <td>사용자 설정</td>
              <td>개인화된 서비스 제공</td>
              <td>계정 삭제 시까지</td>
            </tr>
            <tr>
              <td>로그 데이터</td>
              <td>보안 및 오류 분석</td>
              <td>90일</td>
            </tr>
            <tr>
              <td>쿠키 및 유사 기술</td>
              <td>사용자 경험 개선 및 분석</td>
              <td>쿠키별 상이</td>
            </tr>
          </tbody>
        </table>
      </section>

      <section>
        <h2>3. 개인정보 이용 목적</h2>
        <p>당사는 수집한 개인정보를 다음의 목적으로 이용합니다:</p>
        <ul>
          <li><strong>서비스 제공:</strong> AI 어시스턴트 기능 및 관련 서비스 제공</li>
          <li><strong>사용자 인증:</strong> 계정 보안 및 무단 접근 방지</li>
          <li><strong>서비스 개선:</strong> 사용자 경험 분석 및 기능 개선</li>
          <li><strong>보안:</strong> 사기 방지 및 보안 위협 탐지</li>
          <li><strong>법적 의무:</strong> 관련 법규 준수 및 법적 요청 대응</li>
        </ul>
      </section>

      <section>
        <h2>4. 개인정보 제3자 제공</h2>
        <p>
          당사는 원칙적으로 사용자의 개인정보를 제3자에게 제공하지 않습니다. 
          다만, 다음의 경우에는 예외적으로 제공될 수 있습니다:
        </p>
        <ul>
          <li>사용자가 사전에 동의한 경우</li>
          <li>법령에 의해 요구되는 경우</li>
          <li>서비스 제공을 위해 필요한 범위 내에서 처리 업체에 위탁하는 경우</li>
        </ul>
      </section>

      <section>
        <h2>5. 정보주체의 권리</h2>
        <p>사용자는 다음과 같은 권리를 가집니다:</p>
        
        <div class="rights-grid">
          <div class="right-card">
            <h4>접근 권리 (Right to Access)</h4>
            <p>자신의 개인정보가 처리되고 있는지 여부와 처리 내용을 확인할 수 있습니다.</p>
          </div>
          <div class="right-card">
            <h4>정정 권리 (Right to Rectification)</h4>
            <p>부정확하거나 불완전한 개인정보의 정정을 요청할 수 있습니다.</p>
          </div>
          <div class="right-card">
            <h4>삭제 권리 (Right to Erasure)</h4>
            <p>특정 조건 하에 개인정보의 삭제를 요청할 수 있습니다.</p>
          </div>
          <div class="right-card">
            <h4>처리 제한 권리 (Right to Restrict)</h4>
            <p>특정 상황에서 개인정보 처리의 제한을 요청할 수 있습니다.</p>
          </div>
          <div class="right-card">
            <h4>데이터 이동성 권리 (Right to Portability)</h4>
            <p>자신의 데이터를 구조화된 형식으로 받아 다른 서비스로 전송할 수 있습니다.</p>
          </div>
          <div class="right-card">
            <h4>동의 철회 권리 (Right to Withdraw)</h4>
            <p>언제든지 동의를 철회할 수 있으며, 철회 후에도 지속적인 서비스 이용이 가능합니다.</p>
          </div>
        </div>

        <div class="highlight-box">
          <p>
            <strong>권리 행사 방법:</strong> 위 권리를 행사하려면 아래 연락처로 요청해 주세요. 
            요청 접수 후 30일 이내에 처리 결과를 알려드립니다.
          </p>
        </div>
      </section>

      <section>
        <h2>6. 쿠키 및 유사 기술</h2>
        <p>
          당사는 사용자 경험 개선 및 서비스 분석을 위해 쿠키와 유사한 기술을 사용합니다. 
          아래에서 각 유형의 쿠키 사용에 대한 동의를 관리할 수 있습니다.
        </p>

        <div class="consent-manager">
          <h3>동의 관리</h3>
          <p>각 유형의 쿠키 사용에 대한 동의 상태를 확인하고 변경할 수 있습니다.</p>

          <div class="consent-status">
            <div class="consent-status-item">
              <span class="consent-status-label">필수 쿠키</span>
              <span class="consent-status-value required">필수</span>
            </div>
            <div class="consent-status-item">
              <span class="consent-status-label">기능성 쿠키</span>
              <span class="consent-status-value ${this.preferences.functional ? "granted" : "denied"}">
                ${this.preferences.functional ? "동의함" : "동의하지 않음"}
              </span>
            </div>
            <div class="consent-status-item">
              <span class="consent-status-label">분석 쿠키</span>
              <span class="consent-status-value ${this.preferences.analytics ? "granted" : "denied"}">
                ${this.preferences.analytics ? "동의함" : "동의하지 않음"}
              </span>
            </div>
            <div class="consent-status-item">
              <span class="consent-status-label">마케팅 쿠키</span>
              <span class="consent-status-value ${this.preferences.marketing ? "granted" : "denied"}">
                ${this.preferences.marketing ? "동의함" : "동의하지 않음"}
              </span>
            </div>
          </div>

          <button class="btn btn-secondary" @click="${() => (this.showConsentManager = !this.showConsentManager)}">
            ${this.showConsentManager ? "설정 닫기" : "동의 설정 변경"}
          </button>
          <button class="btn btn-danger" @click="${this.revokeAllConsents}">
            모든 동의 철회
          </button>

          ${
            this.showConsentManager
              ? html`
                <div style="margin-top: 24px;">
                  <h4>상세 설정</h4>
                  <div class="consent-status" style="margin-top: 16px;">
                    <label class="consent-status-item" style="cursor: pointer;">
                      <span class="consent-status-label">기능성 쿠키</span>
                      <input
                        type="checkbox"
                        .checked="${this.preferences.functional}"
                        @change="${() => this.toggleConsent("functional")}"
                      />
                    </label>
                    <label class="consent-status-item" style="cursor: pointer;">
                      <span class="consent-status-label">분석 쿠키</span>
                      <input
                        type="checkbox"
                        .checked="${this.preferences.analytics}"
                        @change="${() => this.toggleConsent("analytics")}"
                      />
                    </label>
                    <label class="consent-status-item" style="cursor: pointer;">
                      <span class="consent-status-label">마케팅 쿠키</span>
                      <input
                        type="checkbox"
                        .checked="${this.preferences.marketing}"
                        @change="${() => this.toggleConsent("marketing")}"
                      />
                    </label>
                  </div>
                </div>
              `
              : ""
          }
        </div>
      </section>

      <section>
        <h2>7. 동의 기록 및 감사</h2>
        <p>
          당사는 투명성과 규정 준수를 위해 모든 동의 결정을 기록합니다. 
          아래에서 동의 이력을 확인하고 내보낼 수 있습니다.
        </p>

        <button class="btn btn-secondary" @click="${() => (this.showConsentLog = !this.showConsentLog)}">
          ${this.showConsentLog ? "동의 로그 숨기기" : "동의 로그 보기"}
        </button>
        <button class="btn btn-primary" @click="${this.exportConsentLog}">
          동의 로그 내보내기
        </button>

        ${
          this.showConsentLog
            ? html`
              <div class="consent-log">
                ${
                  this.consentLog.length === 0
                    ? html`
                        <p>동의 기록이 없습니다.</p>
                      `
                    : html`
                      <table>
                        <thead>
                          <tr>
                            <th>일시</th>
                            <th>유형</th>
                            <th>상태</th>
                            <th>버전</th>
                          </tr>
                        </thead>
                        <tbody>
                          ${this.consentLog
                            .slice()
                            .toReversed()
                            .map(
                              (entry) => html`
                                <tr>
                                  <td>${this.formatDate(entry.timestamp)}</td>
                                  <td>${entry.type}</td>
                                  <td>${entry.state}</td>
                                  <td>${entry.consentVersion}</td>
                                </tr>
                              `,
                            )}
                        </tbody>
                      </table>
                    `
                }
              </div>
            `
            : ""
        }
      </section>

      <section>
        <h2>8. 개인정보 보호책임자</h2>
        <div class="contact-info">
          <h4>개인정보 보호책임자 (DPO)</h4>
          <div class="contact-item">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
              <polyline points="22,6 12,13 2,6"></polyline>
            </svg>
            <span>privacy@openclaw.io</span>
          </div>
          <p style="margin-top: 16px; font-size: 14px;">
            개인정보 관련 문의, 권리 행사 요청, 또는 불만사항은 위 연락처로 접수해 주세요. 
            접수 후 30일 이내에 처리 결과를 알려드립니다.
          </p>
        </div>
      </section>

      <section>
        <h2>9. 개인정보 처리방침 변경</h2>
        <p>
          본 개인정보 처리방침은 법률 변경 또는 서비스 개선에 따라 수정될 수 있습니다. 
          중요한 변경사항이 있는 경우 서비스 내 공지사항 또는 이메일을 통해 사전에 알려드립니다.
        </p>
        <p>
          변경된 개인정보 처리방침은 공지일로부터 7일 후에 효력을 발생하며, 
          변경사항에 동의하지 않는 경우 서비스 이용을 중단하고 계정을 삭제할 수 있습니다.
        </p>
      </section>

      <section>
        <h2>10. 준거법 및 분쟁 해결</h2>
        <p>
          본 개인정보 처리방침은 대한민국 법률에 따라 규율되며, 
          개인정보 관련 분쟁이 발생할 경우 대한민국 법원의 관할권에 속합니다.
        </p>
        <p>
          사용자는 개인정보 침해에 대해 개인정보보호위원회에 불만을 제기하거나, 
          법적 구제를 통해 권리를 보호받을 수 있습니다.
        </p>
      </section>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "privacy-policy-page": PrivacyPolicyPage;
  }
}

/**
 * 개인정보 처리방침 페이지 렌더링 함수
 * (앱 통합용)
 */
export function renderPrivacyPolicy(): ReturnType<typeof html> {
  return html`
    <privacy-policy-page></privacy-policy-page>
  `;
}
