/**
 * Form Error Summary Component for Accessibility
 *
 * Provides:
 * - Error summary at the top of forms
 * - Clear error messages with remediation guidance
 * - ARIA live regions for screen reader announcements
 * - Keyboard navigation to error fields
 *
 * @module ui/src/ui/views/config-form-errors
 */

import { html, type TemplateResult } from "lit";

/** Error entry for a form field */
export interface FieldError {
  /** Field path (for linking to the field) */
  path: string;
  /** Field label or name */
  field: string;
  /** Error message */
  message: string;
  /** Suggestion for fixing the error */
  suggestion?: string;
}

/** Error summary configuration */
export interface ErrorSummaryConfig {
  /** Form ID for linking */
  formId?: string;
  /** List of errors to display */
  errors: FieldError[];
  /** Title for the error summary */
  title?: string;
}

/**
 * Generate a unique error ID for a field path
 * @param path - Field path
 * @returns Error ID string
 */
export function getErrorId(path: string): string {
  return `error-${path.replace(/[.[\]]/g, "-")}`;
}

/**
 * Generate a unique field ID for a field path
 * @param path - Field path
 * @returns Field ID string
 */
export function getFieldId(path: string): string {
  return `field-${path.replace(/[.[\]]/g, "-")}`;
}

/**
 * Render an error summary component for the top of a form
 * This helps screen reader users understand what needs to be fixed
 *
 * @param config - Error summary configuration
 * @returns Lit template result
 */
export function renderErrorSummary(config: ErrorSummaryConfig): TemplateResult {
  const { errors, title = "There is a problem", formId } = config;

  if (errors.length === 0) {
    return html``;
  }

  return html`
    <div
      class="cfg-error-summary"
      role="alert"
      aria-live="polite"
      aria-labelledby="cfg-error-summary-title"
      tabindex="-1"
    >
      <h2 id="cfg-error-summary-title" class="cfg-error-summary__title">
        ${title}
      </h2>
      <ul class="cfg-error-summary__list">
        ${errors.map(
          (error) => html`
            <li class="cfg-error-summary__item">
              <a
                href="#${getFieldId(error.path)}"
                class="cfg-error-summary__link"
                @click=${(e: Event) => {
                  e.preventDefault();
                  focusField(error.path, formId);
                }}
              >
                <span class="cfg-error-summary__field">${error.field}:</span>
                <span class="cfg-error-summary__message">${error.message}</span>
              </a>
              ${
                error.suggestion
                  ? html`
                    <span class="cfg-error-summary__suggestion">
                      ${error.suggestion}
                    </span>
                  `
                  : ""
              }
            </li>
          `,
        )}
      </ul>
    </div>
  `;
}

/**
 * Render an inline error message for a field
 * Includes ARIA attributes for accessibility
 *
 * @param params - Error message parameters
 * @returns Lit template result
 */
export function renderFieldError(params: {
  path: string;
  message: string;
  suggestion?: string;
}): TemplateResult {
  const { path, message, suggestion } = params;
  const errorId = getErrorId(path);

  return html`
    <div
      id="${errorId}"
      class="cfg-field__error"
      role="alert"
      aria-live="polite"
    >
      <strong>Error:</strong> ${message}
      ${
        suggestion
          ? html`
            <span class="cfg-field__error-help">${suggestion}</span>
          `
          : ""
      }
    </div>
  `;
}

/**
 * Focus a form field and scroll it into view
 * Used for keyboard navigation from error summary
 *
 * @param path - Field path
 * @param formId - Optional form ID for scoping
 */
function focusField(path: string, formId?: string): void {
  const fieldId = getFieldId(path);
  const selector = formId ? `#${formId} #${fieldId}` : `#${fieldId}`;
  const element = document.querySelector(selector);

  if (element) {
    // Focus the element
    if (element instanceof HTMLElement) {
      element.focus();
      element.scrollIntoView({ behavior: "smooth", block: "center" });

      // Add a temporary highlight
      element.classList.add("cfg-field--highlighted");
      setTimeout(() => {
        element.classList.remove("cfg-field--highlighted");
      }, 2000);
    }
  }
}

/**
 * Build ARIA described by attribute value
 * Combines help text and error message IDs
 *
 * @param params - Parameters for building describedby
 * @returns Space-separated list of IDs or undefined
 */
export function buildDescribedBy(params: {
  helpId?: string;
  errorId?: string;
}): string | undefined {
  const ids = [params.helpId, params.errorId].filter(Boolean);
  return ids.length > 0 ? ids.join(" ") : undefined;
}

/**
 * Validation error messages with suggestions
 * Provides clear guidance for fixing common errors
 */
export const ValidationMessages = {
  /** Required field is empty */
  required: (field: string) => ({
    message: `${field} is required`,
    suggestion: "Please enter a value for this field.",
  }),

  /** Invalid type */
  type: (field: string, expected: string, received: string) => ({
    message: `${field} must be a ${expected}`,
    suggestion: `You entered a ${received}. Please provide a valid ${expected}.`,
  }),

  /** String too short */
  minLength: (field: string, min: number) => ({
    message: `${field} must be at least ${min} characters`,
    suggestion: `Please enter at least ${min} characters.`,
  }),

  /** String too long */
  maxLength: (field: string, max: number) => ({
    message: `${field} must be no more than ${max} characters`,
    suggestion: `Please shorten your input to ${max} characters or less.`,
  }),

  /** Number below minimum */
  minimum: (field: string, min: number) => ({
    message: `${field} must be at least ${min}`,
    suggestion: `Please enter a number greater than or equal to ${min}.`,
  }),

  /** Number above maximum */
  maximum: (field: string, max: number) => ({
    message: `${field} must be no more than ${max}`,
    suggestion: `Please enter a number less than or equal to ${max}.`,
  }),

  /** Pattern mismatch */
  pattern: (field: string, description?: string) => ({
    message: `${field} format is invalid`,
    suggestion: description || "Please check the format and try again.",
  }),

  /** Enum value not in allowed list */
  enum: (field: string, values: unknown[]) => ({
    message: `${field} must be one of the allowed values`,
    suggestion: `Please select from: ${values.join(", ")}.`,
  }),

  /** Unsupported schema */
  unsupported: (field: string) => ({
    message: `${field} uses an unsupported configuration`,
    suggestion: 'Switch to "Raw JSON" mode to edit this field directly.',
  }),

  /** Generic error */
  generic: (field: string) => ({
    message: `${field} has an error`,
    suggestion: "Please check your input and try again.",
  }),
};

/**
 * CSS styles for error components
 * These should be included in the form stylesheet
 */
export const ErrorStyles = `
  .cfg-error-summary {
    background: #fef2f2;
    border: 2px solid #dc2626;
    border-radius: 4px;
    padding: 1rem;
    margin-bottom: 1.5rem;
    outline: none;
  }

  .cfg-error-summary:focus {
    box-shadow: 0 0 0 3px rgba(220, 38, 38, 0.3);
  }

  .cfg-error-summary__title {
    color: #dc2626;
    font-size: 1.125rem;
    font-weight: 600;
    margin: 0 0 0.75rem 0;
  }

  .cfg-error-summary__list {
    list-style: none;
    margin: 0;
    padding: 0;
  }

  .cfg-error-summary__item {
    margin-bottom: 0.5rem;
  }

  .cfg-error-summary__link {
    color: #dc2626;
    text-decoration: underline;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .cfg-error-summary__link:hover {
    color: #991b1b;
  }

  .cfg-error-summary__field {
    font-weight: 600;
  }

  .cfg-error-summary__message {
    font-weight: 400;
  }

  .cfg-error-summary__suggestion {
    color: #6b7280;
    font-size: 0.875rem;
  }

  .cfg-field__error {
    color: #dc2626;
    font-size: 0.875rem;
    margin-top: 0.25rem;
    padding: 0.5rem;
    background: #fef2f2;
    border-radius: 4px;
    border-left: 3px solid #dc2626;
  }

  .cfg-field__error-help {
    display: block;
    color: #6b7280;
    margin-top: 0.25rem;
  }

  .cfg-field--error .cfg-input,
  .cfg-field--error .cfg-select,
  .cfg-field--error .cfg-number__input {
    border-color: #dc2626;
  }

  .cfg-field--error .cfg-input:focus,
  .cfg-field--error .cfg-select:focus,
  .cfg-field--error .cfg-number__input:focus {
    box-shadow: 0 0 0 3px rgba(220, 38, 38, 0.3);
  }

  .cfg-field--highlighted {
    animation: cfg-field-highlight 2s ease;
  }

  @keyframes cfg-field-highlight {
    0%, 100% {
      box-shadow: none;
    }
    50% {
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.5);
    }
  }
`;
