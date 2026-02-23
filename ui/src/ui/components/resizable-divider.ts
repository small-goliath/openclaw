import { LitElement, css, html } from "lit";
import { customElement, property } from "lit/decorators.js";

/**
 * A draggable divider for resizable split views.
 * Dispatches 'resize' events with { splitRatio: number } detail.
 *
 * 접근성: 슬라이더 역할을 하는 구분선 컴포넌트
 * - role="separator": 구분선 역할 명시
 * - aria-orientation="vertical": 수직 방향 표시
 * - aria-valuenow, aria-valuemin, aria-valuemax: 현재 값 범위 표시
 * - tabindex="0": 키보드 접근 가능
 * - aria-label: 스크린 리더용 레이블
 */
@customElement("resizable-divider")
export class ResizableDivider extends LitElement {
  @property({ type: Number }) splitRatio = 0.6;
  @property({ type: Number }) minRatio = 0.4;
  @property({ type: Number }) maxRatio = 0.7;
  @property({ type: String }) ariaLabel = "패널 크기 조절";
  @property({ type: String }) ariaLabelLang = "ko";

  private isDragging = false;
  private startX = 0;
  private startRatio = 0;

  static styles = css`
    :host {
      width: 4px;
      cursor: col-resize;
      background: var(--border, #333);
      transition: background 150ms ease-out;
      flex-shrink: 0;
      position: relative;
    }
    :host::before {
      content: "";
      position: absolute;
      top: 0;
      left: -4px;
      right: -4px;
      bottom: 0;
    }
    :host(:hover) {
      background: var(--accent, #007bff);
    }
    :host(.dragging) {
      background: var(--accent, #007bff);
    }
    :host(:focus-visible) {
      outline: 2px solid var(--accent, #007bff);
      outline-offset: 2px;
    }
  `;

  render() {
    // 접근성: ARIA 속성 추가
    return html`
      <div
        role="separator"
        aria-orientation="vertical"
        aria-valuenow="${Math.round(this.splitRatio * 100)}"
        aria-valuemin="${Math.round(this.minRatio * 100)}"
        aria-valuemax="${Math.round(this.maxRatio * 100)}"
        aria-label="${this.ariaLabel}"
        lang="${this.ariaLabelLang}"
        tabindex="0"
      ></div>
    `;
  }

  connectedCallback() {
    super.connectedCallback();
    this.addEventListener("mousedown", this.handleMouseDown);
    this.addEventListener("keydown", this.handleKeyDown);
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    this.removeEventListener("mousedown", this.handleMouseDown);
    this.removeEventListener("keydown", this.handleKeyDown);
    document.removeEventListener("mousemove", this.handleMouseMove);
    document.removeEventListener("mouseup", this.handleMouseUp);
  }

  private handleMouseDown = (e: MouseEvent) => {
    this.isDragging = true;
    this.startX = e.clientX;
    this.startRatio = this.splitRatio;
    this.classList.add("dragging");

    document.addEventListener("mousemove", this.handleMouseMove);
    document.addEventListener("mouseup", this.handleMouseUp);

    e.preventDefault();
  };

  private handleMouseMove = (e: MouseEvent) => {
    if (!this.isDragging) {
      return;
    }

    const container = this.parentElement;
    if (!container) {
      return;
    }

    const containerWidth = container.getBoundingClientRect().width;
    const deltaX = e.clientX - this.startX;
    const deltaRatio = deltaX / containerWidth;

    let newRatio = this.startRatio + deltaRatio;
    newRatio = Math.max(this.minRatio, Math.min(this.maxRatio, newRatio));

    this.dispatchEvent(
      new CustomEvent("resize", {
        detail: { splitRatio: newRatio },
        bubbles: true,
        composed: true,
      }),
    );
  };

  private handleMouseUp = () => {
    this.isDragging = false;
    this.classList.remove("dragging");

    document.removeEventListener("mousemove", this.handleMouseMove);
    document.removeEventListener("mouseup", this.handleMouseUp);
  };

  // 접근성: 키보드 탐색 지원
  private handleKeyDown = (e: KeyboardEvent) => {
    const step = 0.02; // 2% 단위로 조정
    let newRatio = this.splitRatio;

    switch (e.key) {
      case "ArrowLeft":
        newRatio = Math.max(this.minRatio, this.splitRatio - step);
        e.preventDefault();
        break;
      case "ArrowRight":
        newRatio = Math.min(this.maxRatio, this.splitRatio + step);
        e.preventDefault();
        break;
      case "Home":
        newRatio = this.minRatio;
        e.preventDefault();
        break;
      case "End":
        newRatio = this.maxRatio;
        e.preventDefault();
        break;
      default:
        return;
    }

    if (newRatio !== this.splitRatio) {
      this.dispatchEvent(
        new CustomEvent("resize", {
          detail: { splitRatio: newRatio },
          bubbles: true,
          composed: true,
        }),
      );
    }
  };
}

declare global {
  interface HTMLElementTagNameMap {
    "resizable-divider": ResizableDivider;
  }
}
