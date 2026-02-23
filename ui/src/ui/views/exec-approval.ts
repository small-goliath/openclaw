import { html, nothing } from "lit";
import { ref } from "lit/directives/ref.js";
import type { AppViewState } from "../app-view-state.ts";

// Focus trap configuration
const FOCUSABLE_SELECTORS = [
  'button:not([disabled])',
  'a[href]',
  'input:not([disabled])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(', ');

/**
 * Gets all focusable elements within a container.
 */
function getFocusableElements(container: HTMLElement): HTMLElement[] {
  const elements = container.querySelectorAll(FOCUSABLE_SELECTORS);
  return Array.from(elements).filter((el): el is HTMLElement => {
    const htmlEl = el as HTMLElement;
    return htmlEl.offsetParent !== null && htmlEl.tabIndex >= 0;
  });
}

/**
 * Focus trap controller for modal dialogs.
 * Manages focus within a modal element.
 */
class FocusTrapController {
  private element: HTMLElement | null = null;
  private abortController: AbortController | null = null;
  private previouslyFocusedElement: Element | null = null;
  private isActive = false;

  activate(element: HTMLElement): void {
    // Don't re-activate if already active on the same element
    if (this.isActive && this.element === element) {
      return;
    }

    // Deactivate any existing trap first
    this.deactivate();

    this.element = element;
    this.previouslyFocusedElement = document.activeElement;
    this.abortController = new AbortController();
    this.isActive = true;

    // Set up focus trap event listeners
    element.addEventListener('keydown', this.handleKeyDown, {
      signal: this.abortController.signal,
    });

    // Focus the first focusable element after a short delay to ensure DOM is ready
    requestAnimationFrame(() => {
      if (this.isActive) {
        this.focusFirstElement();
      }
    });
  }

  deactivate(): void {
    if (!this.isActive) {
      return;
    }

    this.abortController?.abort();
    this.abortController = null;
    this.isActive = false;

    // Restore focus to the previously focused element
    if (this.previouslyFocusedElement instanceof HTMLElement) {
      this.previouslyFocusedElement.focus();
    }

    this.element = null;
    this.previouslyFocusedElement = null;
  }

  private handleKeyDown = (event: KeyboardEvent): void => {
    if (event.key !== 'Tab' || !this.element) {
      return;
    }

    const focusableElements = getFocusableElements(this.element);
    if (focusableElements.length === 0) {
      return;
    }

    const firstElement = focusableElements[0];
    const lastElement = focusableElements[focusableElements.length - 1];

    // Handle Tab and Shift+Tab cycling
    if (event.shiftKey) {
      if (document.activeElement === firstElement) {
        event.preventDefault();
        lastElement.focus();
      }
    } else {
      if (document.activeElement === lastElement) {
        event.preventDefault();
        firstElement.focus();
      }
    }
  };

  private focusFirstElement(): void {
    if (!this.element) return;
    const focusableElements = getFocusableElements(this.element);
    if (focusableElements.length > 0) {
      // Focus the first focusable element (typically the primary action button)
      focusableElements[0].focus();
    } else {
      // Fallback: focus the container itself if no focusable elements
      this.element.focus();
    }
  }
}

// Global controller instance for the exec approval modal
let focusTrapInstance: FocusTrapController | null = null;

/**
 * Creates a ref callback that initializes focus trap on the modal element.
 * This is used with Lit's ref directive.
 */
function createFocusTrapRef() {
  return (el: Element | undefined) => {
    if (el instanceof HTMLElement) {
      if (!focusTrapInstance) {
        focusTrapInstance = new FocusTrapController();
      }
      focusTrapInstance.activate(el);
    } else {
      // Element is undefined (being removed), clean up focus trap
      if (focusTrapInstance) {
        focusTrapInstance.deactivate();
        focusTrapInstance = null;
      }
    }
  };
}

function formatRemaining(ms: number): string {
  const remaining = Math.max(0, ms);
  const totalSeconds = Math.floor(remaining / 1000);
  if (totalSeconds < 60) {
    return `${totalSeconds}s`;
  }
  const minutes = Math.floor(totalSeconds / 60);
  if (minutes < 60) {
    return `${minutes}m`;
  }
  const hours = Math.floor(minutes / 60);
  return `${hours}h`;
}

function renderMetaRow(label: string, value?: string | null) {
  if (!value) {
    return nothing;
  }
  return html`<div class="exec-approval-meta-row"><span>${label}</span><span>${value}</span></div>`;
}

export function renderExecApprovalPrompt(state: AppViewState) {
  const active = state.execApprovalQueue[0];
  if (!active) {
    return nothing;
  }
  const request = active.request;
  const remainingMs = active.expiresAtMs - Date.now();
  const remaining = remainingMs > 0 ? `expires in ${formatRemaining(remainingMs)}` : "expired";
  const queueCount = state.execApprovalQueue.length;
  return html`
    <div class="exec-approval-overlay" role="dialog" aria-modal="true" aria-labelledby="dialog-title" aria-live="polite" ${ref(createFocusTrapRef())}>
      <div class="exec-approval-card">
        <div class="exec-approval-header">
          <div>
            <div class="exec-approval-title" id="dialog-title">Exec approval needed</div>
            <div class="exec-approval-sub">${remaining}</div>
          </div>
          ${
            queueCount > 1
              ? html`<div class="exec-approval-queue">${queueCount} pending</div>`
              : nothing
          }
        </div>
        <div class="exec-approval-command mono">${request.command}</div>
        <div class="exec-approval-meta">
          ${renderMetaRow("Host", request.host)}
          ${renderMetaRow("Agent", request.agentId)}
          ${renderMetaRow("Session", request.sessionKey)}
          ${renderMetaRow("CWD", request.cwd)}
          ${renderMetaRow("Resolved", request.resolvedPath)}
          ${renderMetaRow("Security", request.security)}
          ${renderMetaRow("Ask", request.ask)}
        </div>
        ${
          state.execApprovalError
            ? html`<div class="exec-approval-error">${state.execApprovalError}</div>`
            : nothing
        }
        <div class="exec-approval-actions">
          <button
            class="btn primary"
            ?disabled=${state.execApprovalBusy}
            @click=${() => state.handleExecApprovalDecision("allow-once")}
          >
            Allow once
          </button>
          <button
            class="btn"
            ?disabled=${state.execApprovalBusy}
            @click=${() => state.handleExecApprovalDecision("allow-always")}
          >
            Always allow
          </button>
          <button
            class="btn danger"
            ?disabled=${state.execApprovalBusy}
            @click=${() => state.handleExecApprovalDecision("deny")}
          >
            Deny
          </button>
        </div>
      </div>
    </div>
  `;
}
