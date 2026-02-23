import { html, nothing } from "lit";
import type { VirtualListItem } from "../components/virtual-list.ts";
import type { GatewaySessionRow, SessionsListResult } from "../types.ts";
import { formatRelativeTimestamp } from "../format.ts";
import { pathForTab } from "../navigation.ts";
import "../components/virtual-list.ts";
import { formatSessionTokens } from "../presenter.ts";

export type SessionsProps = {
  loading: boolean;
  result: SessionsListResult | null;
  error: string | null;
  activeMinutes: string;
  limit: string;
  includeGlobal: boolean;
  includeUnknown: boolean;
  basePath: string;
  onFiltersChange: (next: {
    activeMinutes: string;
    limit: string;
    includeGlobal: boolean;
    includeUnknown: boolean;
  }) => void;
  onRefresh: () => void;
  onPatch: (
    key: string,
    patch: {
      label?: string | null;
      thinkingLevel?: string | null;
      verboseLevel?: string | null;
      reasoningLevel?: string | null;
    },
  ) => void;
  onDelete: (key: string) => void;
};

/**
 * Session row with virtual list item interface
 */
type SessionRowWithId = GatewaySessionRow & VirtualListItem;

const THINK_LEVELS = ["", "off", "minimal", "low", "medium", "high", "xhigh"] as const;
const BINARY_THINK_LEVELS = ["", "off", "on"] as const;
const VERBOSE_LEVELS = [
  { value: "", label: "inherit" },
  { value: "off", label: "off (explicit)" },
  { value: "on", label: "on" },
  { value: "full", label: "full" },
] as const;
const REASONING_LEVELS = ["", "off", "on", "stream"] as const;

function normalizeProviderId(provider?: string | null): string {
  if (!provider) {
    return "";
  }
  const normalized = provider.trim().toLowerCase();
  if (normalized === "z.ai" || normalized === "z-ai") {
    return "zai";
  }
  return normalized;
}

function isBinaryThinkingProvider(provider?: string | null): boolean {
  return normalizeProviderId(provider) === "zai";
}

function resolveThinkLevelOptions(provider?: string | null): readonly string[] {
  return isBinaryThinkingProvider(provider) ? BINARY_THINK_LEVELS : THINK_LEVELS;
}

function withCurrentOption(options: readonly string[], current: string): string[] {
  if (!current) {
    return [...options];
  }
  if (options.includes(current)) {
    return [...options];
  }
  return [...options, current];
}

function withCurrentLabeledOption(
  options: readonly { value: string; label: string }[],
  current: string,
): Array<{ value: string; label: string }> {
  if (!current) {
    return [...options];
  }
  if (options.some((option) => option.value === current)) {
    return [...options];
  }
  return [...options, { value: current, label: `${current} (custom)` }];
}

function resolveThinkLevelDisplay(value: string, isBinary: boolean): string {
  if (!isBinary) {
    return value;
  }
  if (!value || value === "off") {
    return value;
  }
  return "on";
}

function resolveThinkLevelPatchValue(value: string, isBinary: boolean): string | null {
  if (!value) {
    return null;
  }
  if (!isBinary) {
    return value;
  }
  if (value === "on") {
    return "low";
  }
  return value;
}

/**
 * Threshold for enabling virtual scrolling
 * Lists smaller than this will render normally for better UX
 */
const VIRTUAL_SCROLL_THRESHOLD = 50;

/**
 * Default item height for session rows
 */
const SESSION_ITEM_HEIGHT = 56;

/**
 * Buffer size for smooth scrolling
 */
const SESSION_BUFFER_SIZE = 5;

/**
 * Convert session rows to virtual list items
 */
function adaptSessionsForVirtualList(rows: GatewaySessionRow[]): SessionRowWithId[] {
  return rows.map((row) => ({
    ...row,
    id: row.key,
  }));
}

export function renderSessions(props: SessionsProps) {
  const rows = props.result?.sessions ?? [];
  const useVirtualScroll = rows.length > VIRTUAL_SCROLL_THRESHOLD;
  const virtualItems = useVirtualScroll ? adaptSessionsForVirtualList(rows) : [];

  return html`
    <section class="card">
      <div class="row" style="justify-content: space-between;">
        <div>
          <div class="card-title">Sessions</div>
          <div class="card-sub">Active session keys and per-session overrides.</div>
        </div>
        <button class="btn" ?disabled=${props.loading} @click=${props.onRefresh}>
          ${props.loading ? "Loading…" : "Refresh"}
        </button>
      </div>

      <div class="filters" style="margin-top: 14px;">
        <label class="field">
          <span>Active within (minutes)</span>
          <input
            type="number"
            aria-label="Active within minutes"
            .value=${props.activeMinutes}
            @input=${(e: Event) =>
              props.onFiltersChange({
                activeMinutes: (e.target as HTMLInputElement).value,
                limit: props.limit,
                includeGlobal: props.includeGlobal,
                includeUnknown: props.includeUnknown,
              })}
          />
        </label>
        <label class="field">
          <span>Limit</span>
          <input
            type="number"
            aria-label="Session limit"
            .value=${props.limit}
            @input=${(e: Event) =>
              props.onFiltersChange({
                activeMinutes: props.activeMinutes,
                limit: (e.target as HTMLInputElement).value,
                includeGlobal: props.includeGlobal,
                includeUnknown: props.includeUnknown,
              })}
          />
        </label>
        <label class="field checkbox">
          <span>Include global</span>
          <input
            type="checkbox"
            aria-label="Include global sessions"
            .checked=${props.includeGlobal}
            @change=${(e: Event) =>
              props.onFiltersChange({
                activeMinutes: props.activeMinutes,
                limit: props.limit,
                includeGlobal: (e.target as HTMLInputElement).checked,
                includeUnknown: props.includeUnknown,
              })}
          />
        </label>
        <label class="field checkbox">
          <span>Include unknown</span>
          <input
            type="checkbox"
            aria-label="Include unknown sessions"
            .checked=${props.includeUnknown}
            @change=${(e: Event) =>
              props.onFiltersChange({
                activeMinutes: props.activeMinutes,
                limit: props.limit,
                includeGlobal: props.includeGlobal,
                includeUnknown: (e.target as HTMLInputElement).checked,
              })}
          />
        </label>
      </div>

      ${
        props.error
          ? html`<div class="callout danger" style="margin-top: 12px;">${props.error}</div>`
          : nothing
      }

      <div class="muted" style="margin-top: 12px;">
        ${props.result ? `Store: ${props.result.path}` : ""}
        ${
          useVirtualScroll
            ? html` · <span class="virtual-scroll-badge">Virtual scroll enabled (${rows.length} items)</span>`
            : nothing
        }
      </div>

      <div class="table" role="table" aria-label="Sessions list" style="margin-top: 16px;">
        <div class="table-head" role="rowgroup">
          <div role="row">
            <div role="columnheader" scope="col" id="col-key">Key</div>
            <div role="columnheader" scope="col" id="col-label">Label</div>
            <div role="columnheader" scope="col" id="col-kind">Kind</div>
            <div role="columnheader" scope="col" id="col-updated">Updated</div>
            <div role="columnheader" scope="col" id="col-tokens">Tokens</div>
            <div role="columnheader" scope="col" id="col-thinking">Thinking</div>
            <div role="columnheader" scope="col" id="col-verbose">Verbose</div>
            <div role="columnheader" scope="col" id="col-reasoning">Reasoning</div>
            <div role="columnheader" scope="col" id="col-actions">Actions</div>
          </div>
        </div>
        ${
          rows.length === 0
            ? html`
                <div role="status" class="muted">No sessions found.</div>
              `
            : useVirtualScroll
              ? html`
                  <virtual-list
                    .items=${virtualItems}
                    .itemHeight=${SESSION_ITEM_HEIGHT}
                    .bufferSize=${SESSION_BUFFER_SIZE}
                    .maxHeight=${600}
                    .renderItem=${(item: SessionRowWithId) =>
                      renderRow(item, props.basePath, props.onPatch, props.onDelete, props.loading)}
                    containerClass="sessions-virtual-list"
                    itemClass="table-row"
                  ></virtual-list>
                `
              : html`
                  <div role="rowgroup">
                    ${rows.map((row) =>
                      renderRow(row, props.basePath, props.onPatch, props.onDelete, props.loading),
                    )}
                  </div>
                `
        }
      </div>
    </section>
  `;
}

function renderRow(
  row: GatewaySessionRow,
  basePath: string,
  onPatch: SessionsProps["onPatch"],
  onDelete: SessionsProps["onDelete"],
  disabled: boolean,
) {
  const updated = row.updatedAt ? formatRelativeTimestamp(row.updatedAt) : "n/a";
  const rawThinking = row.thinkingLevel ?? "";
  const isBinaryThinking = isBinaryThinkingProvider(row.modelProvider);
  const thinking = resolveThinkLevelDisplay(rawThinking, isBinaryThinking);
  const thinkLevels = withCurrentOption(resolveThinkLevelOptions(row.modelProvider), thinking);
  const verbose = row.verboseLevel ?? "";
  const verboseLevels = withCurrentLabeledOption(VERBOSE_LEVELS, verbose);
  const reasoning = row.reasoningLevel ?? "";
  const reasoningLevels = withCurrentOption(REASONING_LEVELS, reasoning);
  const displayName =
    typeof row.displayName === "string" && row.displayName.trim().length > 0
      ? row.displayName.trim()
      : null;
  const label = typeof row.label === "string" ? row.label.trim() : "";
  const showDisplayName = Boolean(displayName && displayName !== row.key && displayName !== label);
  const canLink = row.kind !== "global";
  const chatUrl = canLink
    ? `${pathForTab("chat", basePath)}?session=${encodeURIComponent(row.key)}`
    : null;

  return html`
    <div class="table-row" role="row" aria-labelledby="session-${row.key}">
      <div class="mono session-key-cell" role="cell" headers="col-key" id="session-${row.key}">
        ${canLink ? html`<a href=${chatUrl} class="session-link">${row.key}</a>` : row.key}
        ${showDisplayName ? html`<span class="muted session-key-display-name">${displayName}</span>` : nothing}
      </div>
      <div role="cell" headers="col-label">
        <input
          type="text"
          aria-label="Session label for ${row.key}"
          .value=${row.label ?? ""}
          ?disabled=${disabled}
          placeholder="(optional)"
          @change=${(e: Event) => {
            const value = (e.target as HTMLInputElement).value.trim();
            onPatch(row.key, { label: value || null });
          }}
        />
      </div>
      <div role="cell" headers="col-kind">${row.kind}</div>
      <div role="cell" headers="col-updated">${updated}</div>
      <div role="cell" headers="col-tokens">${formatSessionTokens(row)}</div>
      <div role="cell" headers="col-thinking">
        <select
          aria-label="Thinking level for ${row.key}"
          ?disabled=${disabled}
          @change=${(e: Event) => {
            const value = (e.target as HTMLSelectElement).value;
            onPatch(row.key, {
              thinkingLevel: resolveThinkLevelPatchValue(value, isBinaryThinking),
            });
          }}
        >
          ${thinkLevels.map(
            (level) =>
              html`<option value=${level} ?selected=${thinking === level}>
                ${level || "inherit"}
              </option>`,
          )}
        </select>
      </div>
      <div role="cell" headers="col-verbose">
        <select
          aria-label="Verbose level for ${row.key}"
          ?disabled=${disabled}
          @change=${(e: Event) => {
            const value = (e.target as HTMLSelectElement).value;
            onPatch(row.key, { verboseLevel: value || null });
          }}
        >
          ${verboseLevels.map(
            (level) =>
              html`<option value=${level.value} ?selected=${verbose === level.value}>
                ${level.label}
              </option>`,
          )}
        </select>
      </div>
      <div role="cell" headers="col-reasoning">
        <select
          aria-label="Reasoning level for ${row.key}"
          ?disabled=${disabled}
          @change=${(e: Event) => {
            const value = (e.target as HTMLSelectElement).value;
            onPatch(row.key, { reasoningLevel: value || null });
          }}
        >
          ${reasoningLevels.map(
            (level) =>
              html`<option value=${level} ?selected=${reasoning === level}>
                ${level || "inherit"}
              </option>`,
          )}
        </select>
      </div>
      <div role="cell" headers="col-actions">
        <button
          class="btn danger"
          aria-label="Delete session ${row.key}"
          ?disabled=${disabled}
          @click=${() => onDelete(row.key)}
        >
          Delete
        </button>
      </div>
    </div>
  `;
}
