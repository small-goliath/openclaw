/**
 * Virtual List Component
 * FR-018: 가상 스크롤 구현 - 대형 세션/사용량 목록에 가상 스크롤 적용
 *
 * Features:
 * - Render only visible items for performance with large lists
 * - Support dynamic item heights
 * - Handle scroll events efficiently
 * - Buffer size for smooth scrolling
 */

import { LitElement, html, css, nothing } from "lit";
import { customElement, property, state } from "lit/decorators.js";
import { classMap } from "lit/directives/class-map.js";

/**
 * Virtual list item metadata
 */
export interface VirtualListItem {
  id: string;
  height?: number;
}

/**
 * Virtual list render function type
 */
export type VirtualListRenderFn<T> = (
  item: T,
  index: number,
  isSelected?: boolean,
) => unknown;

/**
 * Virtual list selection handler
 */
export type VirtualListSelectFn = (key: string, shiftKey: boolean) => void;

/**
 * VirtualList component for efficiently rendering large lists
 *
 * @example
 * ```html
 * <virtual-list
 *   .items="${sessions}"
 *   .itemHeight="${48}"
 *   .bufferSize="${5}"
 *   .renderItem="${renderSessionItem}"
 *   .selectedKeys="${selectedSessions}"
 *   .onSelect="${handleSelect}"
 * >
 * </virtual-list>
 * ```
 */
@customElement("virtual-list")
export class VirtualList<T extends VirtualListItem> extends LitElement {
  /**
   * Array of items to render
   */
  @property({ type: Array })
  items: T[] = [];

  /**
   * Height of each item in pixels (default: 50)
   */
  @property({ type: Number })
  itemHeight = 50;

  /**
   * Number of items to render outside the visible area for smooth scrolling (default: 5)
   */
  @property({ type: Number })
  bufferSize = 5;

  /**
   * Function to render each item
   */
  @property({ attribute: false })
  renderItem: VirtualListRenderFn<T> = () => nothing;

  /**
   * Currently selected keys
   */
  @property({ type: Array })
  selectedKeys: string[] = [];

  /**
   * Selection handler
   */
  @property({ attribute: false })
  onSelect: VirtualListSelectFn | null = null;

  /**
   * Maximum height of the container (default: 400px)
   */
  @property({ type: Number })
  maxHeight = 400;

  /**
   * Enable dynamic item heights
   */
  @property({ type: Boolean })
  dynamicHeights = false;

  /**
   * CSS class for the container
   */
  @property({ type: String })
  containerClass = "";

  /**
   * CSS class for each item
   */
  @property({ type: String })
  itemClass = "";

  @state()
  private visibleRange = { start: 0, end: 0 };

  @state()
  private _scrollTop = 0;

  @state()
  private containerHeight = 0;

  @state()
  private measuredHeights: Map<string, number> = new Map();

  private resizeObserver?: ResizeObserver;
  private containerRef: HTMLElement | null = null;
  private scrollTimeout?: number;
  private itemRefs: Map<string, HTMLElement> = new Map();

  static styles = css`
    :host {
      display: block;
      position: relative;
    }

    .virtual-container {
      overflow-y: auto;
      overflow-x: hidden;
      position: relative;
      will-change: transform;
    }

    .virtual-content {
      position: relative;
      width: 100%;
    }

    .virtual-item {
      position: absolute;
      left: 0;
      right: 0;
      box-sizing: border-box;
      will-change: transform;
    }

    .virtual-item-placeholder {
      visibility: hidden;
      position: absolute;
    }

    /* Smooth scrolling for wheel events */
    .virtual-container.smooth-scroll {
      scroll-behavior: smooth;
    }

    /* Reduced motion preference */
    @media (prefers-reduced-motion: reduce) {
      .virtual-container {
        scroll-behavior: auto;
      }
    }
  `;

  connectedCallback() {
    super.connectedCallback();
    this.calculateVisibleRange();
  }

  disconnectedCallback() {
    super.disconnectedCallback();
    this.resizeObserver?.disconnect();
    if (this.scrollTimeout) {
      window.clearTimeout(this.scrollTimeout);
    }
  }

  firstUpdated() {
    this.containerRef = this.renderRoot.querySelector(
      ".virtual-container",
    ) as HTMLElement;
    if (this.containerRef) {
      this.containerHeight = this.containerRef.clientHeight;

      // Observe container size changes
      this.resizeObserver = new ResizeObserver((entries) => {
        for (const entry of entries) {
          this.containerHeight = entry.contentRect.height;
          this.calculateVisibleRange();
        }
      });
      this.resizeObserver.observe(this.containerRef);
    }
  }

  updated(changedProperties: Map<string, unknown>) {
    if (changedProperties.has("items") || changedProperties.has("itemHeight")) {
      this.calculateVisibleRange();
    }

    // Measure dynamic heights after render
    if (this.dynamicHeights) {
      this.measureHeights();
    }
  }

  /**
   * Calculate the total height of all items
   */
  private getTotalHeight(): number {
    if (this.dynamicHeights) {
      return this.items.reduce((sum, item) => {
        return sum + (this.measuredHeights.get(item.id) ?? this.itemHeight);
      }, 0);
    }
    return this.items.length * this.itemHeight;
  }

  /**
   * Get the height of a specific item
   */
  private getItemHeight(item: T): number {
    if (this.dynamicHeights && item.height) {
      return item.height;
    }
    return this.measuredHeights.get(item.id) ?? this.itemHeight;
  }

  /**
   * Get the top position of a specific item
   */
  private getItemTop(index: number): number {
    if (this.dynamicHeights) {
      let top = 0;
      for (let i = 0; i < index && i < this.items.length; i++) {
        top += this.getItemHeight(this.items[i]);
      }
      return top;
    }
    return index * this.itemHeight;
  }

  /**
   * Measure actual heights of rendered items
   */
  private measureHeights(): void {
    for (const [id, element] of this.itemRefs) {
      if (element) {
        const height = element.getBoundingClientRect().height;
        this.measuredHeights.set(id, height);
      }
    }
  }

  /**
   * Calculate which items should be visible based on scroll position
   */
  private calculateVisibleRange(): void {
    if (this.containerHeight === 0) {
      // Use maxHeight as fallback
      this.containerHeight = this.maxHeight;
    }

    const scrollTop = this._scrollTop;
    const viewportHeight = this.containerHeight;

    let startIndex: number;
    let endIndex: number;

    if (this.dynamicHeights) {
      // Binary search for start index with dynamic heights
      startIndex = this.findIndexAtPosition(scrollTop);
      endIndex = this.findIndexAtPosition(scrollTop + viewportHeight);
    } else {
      // Simple calculation for fixed heights
      startIndex = Math.floor(scrollTop / this.itemHeight);
      endIndex = Math.ceil((scrollTop + viewportHeight) / this.itemHeight);
    }

    // Apply buffer
    startIndex = Math.max(0, startIndex - this.bufferSize);
    endIndex = Math.min(this.items.length, endIndex + this.bufferSize);

    // Only update if range changed significantly
    if (
      startIndex !== this.visibleRange.start ||
      endIndex !== this.visibleRange.end
    ) {
      this.visibleRange = { start: startIndex, end: endIndex };
    }
  }

  /**
   * Find the index of the item at a given position (for dynamic heights)
   */
  private findIndexAtPosition(position: number): number {
    let accumulatedHeight = 0;
    for (let i = 0; i < this.items.length; i++) {
      const itemHeight = this.getItemHeight(this.items[i]);
      if (accumulatedHeight + itemHeight > position) {
        return i;
      }
      accumulatedHeight += itemHeight;
    }
    return this.items.length;
  }

  /**
   * Handle scroll events efficiently with throttling
   */
  private handleScroll(e: Event): void {
    const target = e.target as HTMLElement;
    this._scrollTop = target.scrollTop;

    // Throttle calculations using requestAnimationFrame
    if (this.scrollTimeout) {
      window.clearTimeout(this.scrollTimeout);
    }

    this.scrollTimeout = window.setTimeout(() => {
      this.calculateVisibleRange();
    }, 16); // ~60fps
  }

  /**
   * Handle wheel events for smooth scrolling
   */
  private handleWheel(e: WheelEvent): void {
    // Prevent default only if we're handling the scroll
    if (this.containerRef) {
      const { scrollTop, scrollHeight, clientHeight } = this.containerRef;
      const isAtTop = scrollTop <= 0 && e.deltaY < 0;
      const isAtBottom =
        scrollTop + clientHeight >= scrollHeight && e.deltaY > 0;

      // Don't prevent default if at boundaries (allow page scroll)
      if (!isAtTop && !isAtBottom) {
        e.stopPropagation();
      }
    }
  }

  /**
   * Store reference to item element for height measurement
   */
  private setItemRef(element: HTMLElement | null, id: string): void {
    if (element) {
      this.itemRefs.set(id, element);
    } else {
      this.itemRefs.delete(id);
    }
  }

  /**
   * Scroll to a specific item by index
   */
  scrollToIndex(index: number, behavior: ScrollBehavior = "smooth"): void {
    if (index < 0 || index >= this.items.length) {
      return;
    }

    const top = this.getItemTop(index);
    this.containerRef?.scrollTo({ top, behavior });
  }

  /**
   * Scroll to a specific item by key
   */
  scrollToKey(key: string, behavior: ScrollBehavior = "smooth"): void {
    const index = this.items.findIndex((item) => item.id === key);
    if (index !== -1) {
      this.scrollToIndex(index, behavior);
    }
  }

  /**
   * Refresh visible range calculation
   */
  refresh(): void {
    this.calculateVisibleRange();
  }

  render() {
    const totalHeight = this.getTotalHeight();
    const visibleItems = this.items.slice(
      this.visibleRange.start,
      this.visibleRange.end,
    );
    const selectedSet = new Set(this.selectedKeys);

    const containerClasses = classMap({
      "virtual-container": true,
      [this.containerClass]: !!this.containerClass,
    });

    return html`
      <div
        class="${containerClasses}"
        style="max-height: ${this.maxHeight}px;"
        @scroll=${this.handleScroll}
        @wheel=${this.handleWheel}
        role="list"
        aria-label="Virtual list"
      >
        <div
          class="virtual-content"
          style="height: ${totalHeight}px;"
        >
          ${visibleItems.map((item, index) => {
            const actualIndex = this.visibleRange.start + index;
            const top = this.getItemTop(actualIndex);
            const isSelected = selectedSet.has(item.id);

            const itemClasses = classMap({
              "virtual-item": true,
              [this.itemClass]: !!this.itemClass,
              selected: isSelected,
            });

            return html`
              <div
                class="${itemClasses}"
                style="top: ${top}px;"
                role="listitem"
                data-index="${actualIndex}"
                data-key="${item.id}"
                ${(el: HTMLElement | null) => this.setItemRef(el, item.id)}
                @click=${(e: MouseEvent) =>
                  this.onSelect?.(item.id, e.shiftKey)}
              >
                ${this.renderItem(item, actualIndex, isSelected)}
              </div>
            `;
          })}
        </div>
      </div>
    `;
  }
}

declare global {
  interface HTMLElementTagNameMap {
    "virtual-list": VirtualList<VirtualListItem>;
  }
}

/**
 * Helper function to create virtual list items from any array
 */
export function createVirtualItems<T extends Record<string, unknown>>(
  items: T[],
  getId: (item: T) => string,
): Array<T & VirtualListItem> {
  return items.map((item) => ({
    ...item,
    id: getId(item),
  })) as Array<T & VirtualListItem>;
}

/**
 * Helper to adapt session items for virtual list
 */
export function adaptSessionsForVirtualList<
  T extends { key: string; id?: string },
>(sessions: T[]): Array<T & VirtualListItem> {
  return sessions.map((session) => ({
    ...session,
    id: session.id ?? session.key,
  })) as Array<T & VirtualListItem>;
}

export default VirtualList;
