/**
 * Crypto Worker Pool
 *
 * CPU 집약적인 암호화 작업을 관리하는 Worker Pool
 * - Worker Thread 생성 및 관리
 * - 작업 큐 관리 및 분배
 * - 오류 처리 및 자동 재시작
 * - 성능 메트릭 수집
 *
 * @module workers/worker-pool
 * @see security/security.md section 5.4
 */

import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import type {
  WorkerRequest,
  WorkerResponse,
  WorkerPoolConfig,
  WorkerPoolStats,
  WorkerInfo,
  WorkerStatus,
  WorkerPoolEventType,
  WorkerPoolEventListener,
  WorkerTaskType,
} from "./types.js";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("workers/pool");

// ============================================================================
// Constants
// ============================================================================

const DEFAULT_CONFIG: Required<WorkerPoolConfig> = {
  workerCount: Math.max(2, os.cpus().length - 1),
  maxQueueSize: 1000,
  taskTimeoutMs: 30000,
  restartDelayMs: 1000,
  maxRetries: 3,
  smallDataThreshold: 1024, // 1KB
};

// ============================================================================
// Worker Pool Implementation
// ============================================================================

interface PendingTask {
  id: string;
  type: WorkerTaskType;
  payload: unknown;
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
  retries: number;
  timeoutId?: NodeJS.Timeout;
  queuedAt: number;
  startedAt?: number;
}

interface WorkerWrapper {
  worker: Worker;
  info: WorkerInfo;
  currentTask?: PendingTask;
}

export class CryptoWorkerPool {
  private config: Required<WorkerPoolConfig>;
  private workers: Map<number, WorkerWrapper> = new Map();
  private taskQueue: PendingTask[] = [];
  private pendingTasks: Map<string, PendingTask> = new Map();
  private isShuttingDown = false;
  private workerIdCounter = 0;
  private stats = {
    totalTasksProcessed: 0,
    totalTasksFailed: 0,
    totalTaskDurationMs: 0,
    workerRestarts: 0,
  };
  private eventListeners: WorkerPoolEventListener[] = [];
  private workerScriptPath: string;

  constructor(config: WorkerPoolConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };

    // Resolve worker script path
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);

    // Use .ts extension for development, .js for production
    // In production (dist), the file will be crypto-worker.js
    // In development (src), we use tsx to run TypeScript directly
    const isDev = __dirname.includes("/src/") || __dirname.includes("\\src\\");
    const extension = isDev ? "ts" : "js";
    this.workerScriptPath = path.join(__dirname, `crypto-worker.${extension}`);

    log.info("Initializing CryptoWorkerPool", {
      workerCount: this.config.workerCount,
      maxQueueSize: this.config.maxQueueSize,
      workerScript: this.workerScriptPath,
      isDev,
    });

    this.initializeWorkers();
  }

  // ============================================================================
  // Worker Management
  // ============================================================================

  private initializeWorkers(): void {
    for (let i = 0; i < this.config.workerCount; i++) {
      this.createWorker();
    }
  }

  private createWorker(): WorkerWrapper {
    const id = ++this.workerIdCounter;

    try {
      // Determine if we're in development mode (running .ts files)
      const isDev = this.workerScriptPath.endsWith(".ts");

      // Create worker with appropriate execArgv for TypeScript support
      const worker = isDev
        ? new Worker(this.workerScriptPath, {
            execArgv: ["--import", "tsx/esm"],
          })
        : new Worker(this.workerScriptPath);

      const wrapper: WorkerWrapper = {
        worker,
        info: {
          id,
          status: "idle",
          createdAt: Date.now(),
          lastActivityAt: Date.now(),
          totalTasks: 0,
          errorCount: 0,
        },
      };

      worker.on("message", (response: WorkerResponse | { type: string }) => {
        // Handle ready signal
        if ("type" in response && response.type === "ready") {
          log.debug(`Worker ${id} is ready`);
          return;
        }

        // Handle task response
        this.handleWorkerResponse(wrapper, response as WorkerResponse);
      });

      worker.on("error", (error) => {
        log.error(`Worker ${id} error`, { error: error.message });
        this.handleWorkerError(wrapper, error);
      });

      worker.on("exit", (code) => {
        log.warn(`Worker ${id} exited with code ${code}`);
        this.handleWorkerExit(wrapper, code);
      });

      this.workers.set(id, wrapper);
      this.emit("worker:created", { workerId: id });

      return wrapper;
    } catch (error) {
      log.error(`Failed to create worker ${id}`, { error: String(error) });
      throw error;
    }
  }

  private handleWorkerResponse(wrapper: WorkerWrapper, response: WorkerResponse): void {
    const task = wrapper.currentTask;
    if (!task) {
      log.warn(`Received response for unknown task: ${response.id}`);
      return;
    }

    // Clear timeout
    if (task.timeoutId) {
      clearTimeout(task.timeoutId);
    }

    // Update stats
    const duration = response.metrics?.durationMs || 0;
    this.stats.totalTasksProcessed++;
    this.stats.totalTaskDurationMs += duration;

    // Update worker info
    wrapper.info.totalTasks++;
    wrapper.info.lastActivityAt = Date.now();
    wrapper.info.status = "idle";
    wrapper.currentTask = undefined;

    this.pendingTasks.delete(task.id);

    if (response.success) {
      this.emit("task:completed", {
        taskId: task.id,
        type: task.type,
        workerId: wrapper.info.id,
        durationMs: duration,
      });
      task.resolve(response.result);
    } else {
      this.stats.totalTasksFailed++;
      this.handleTaskError(wrapper, task, new Error(response.error || "Unknown error"));
    }

    // Process next task
    this.processQueue();
  }

  private handleWorkerError(wrapper: WorkerWrapper, error: Error): void {
    wrapper.info.errorCount++;
    this.emit("worker:error", {
      workerId: wrapper.info.id,
      error: error.message,
    });

    // Fail current task if any
    if (wrapper.currentTask) {
      const task = wrapper.currentTask;
      this.pendingTasks.delete(task.id);
      this.handleTaskError(wrapper, task, error);
      wrapper.currentTask = undefined;
    }

    // Restart worker
    this.restartWorker(wrapper);
  }

  private handleWorkerExit(wrapper: WorkerWrapper, code: number): void {
    // Remove from workers map
    this.workers.delete(wrapper.info.id);
    this.emit("worker:destroyed", {
      workerId: wrapper.info.id,
      exitCode: code,
    });

    // Fail current task if any
    if (wrapper.currentTask) {
      const task = wrapper.currentTask;
      this.pendingTasks.delete(task.id);
      this.handleTaskError(wrapper, task, new Error(`Worker exited with code ${code}`));
    }

    // Restart if not shutting down
    if (!this.isShuttingDown) {
      setTimeout(() => {
        this.createWorker();
        this.stats.workerRestarts++;
        this.emit("worker:restart", { workerId: wrapper.info.id });
      }, this.config.restartDelayMs);
    }
  }

  private handleTaskError(wrapper: WorkerWrapper, task: PendingTask, error: Error): void {
    if (task.retries < this.config.maxRetries) {
      task.retries++;
      log.warn(`Retrying task ${task.id} (attempt ${task.retries})`, {
        error: error.message,
      });
      this.taskQueue.unshift(task);
      this.processQueue();
    } else {
      this.emit("task:failed", {
        taskId: task.id,
        type: task.type,
        error: error.message,
        retries: task.retries,
      });
      task.reject(error);
    }
  }

  private restartWorker(wrapper: WorkerWrapper): void {
    wrapper.info.status = "restarting";
    wrapper.worker.terminate().catch(() => {});
  }

  // ============================================================================
  // Task Queue Management
  // ============================================================================

  private processQueue(): void {
    if (this.isShuttingDown || this.taskQueue.length === 0) {
      return;
    }

    // Find idle worker
    for (const wrapper of this.workers.values()) {
      if (wrapper.info.status === "idle") {
        const task = this.taskQueue.shift();
        if (!task) {
          return;
        }

        this.assignTask(wrapper, task);
        return; // Process one task at a time per call
      }
    }
  }

  private assignTask(wrapper: WorkerWrapper, task: PendingTask): void {
    wrapper.info.status = "busy";
    wrapper.info.lastActivityAt = Date.now();
    wrapper.currentTask = task;
    task.startedAt = Date.now();

    // Set timeout
    task.timeoutId = setTimeout(() => {
      this.handleTaskTimeout(wrapper, task);
    }, this.config.taskTimeoutMs);

    const request: WorkerRequest = {
      id: task.id,
      type: task.type,
      payload: task.payload,
      timestamp: Date.now(),
    };

    this.emit("task:started", {
      taskId: task.id,
      type: task.type,
      workerId: wrapper.info.id,
    });

    wrapper.worker.postMessage(request);
  }

  private handleTaskTimeout(wrapper: WorkerWrapper, task: PendingTask): void {
    log.error(`Task ${task.id} timed out`);
    this.emit("task:timeout", {
      taskId: task.id,
      type: task.type,
      workerId: wrapper.info.id,
    });

    // Terminate and restart the worker
    wrapper.worker.terminate().catch(() => {});
    this.workers.delete(wrapper.info.id);
    this.createWorker();

    // Handle task error
    wrapper.currentTask = undefined;
    this.pendingTasks.delete(task.id);
    this.handleTaskError(
      wrapper,
      task,
      new Error(`Task timeout after ${this.config.taskTimeoutMs}ms`),
    );
  }

  // ============================================================================
  // Public API
  // ============================================================================

  /**
   * Execute a task in the worker pool
   */
  execute<T>(type: WorkerTaskType, payload: unknown): Promise<T> {
    if (this.isShuttingDown) {
      return Promise.reject(new Error("Worker pool is shutting down"));
    }

    if (this.taskQueue.length >= this.config.maxQueueSize) {
      return Promise.reject(new Error("Task queue is full"));
    }

    const id = crypto.randomUUID();

    return new Promise((resolve, reject) => {
      const task: PendingTask = {
        id,
        type,
        payload,
        resolve: resolve as (value: unknown) => void,
        reject,
        retries: 0,
        queuedAt: Date.now(),
      };

      this.pendingTasks.set(id, task);
      this.taskQueue.push(task);
      this.emit("task:queued", { taskId: id, type });

      // Try to process immediately
      this.processQueue();
    });
  }

  /**
   * Check if data is small enough to process in main thread
   */
  isSmallData(data: string): boolean {
    return Buffer.byteLength(data, "utf-8") <= this.config.smallDataThreshold;
  }

  /**
   * Get current pool statistics
   */
  getStats(): WorkerPoolStats {
    const idleWorkers = Array.from(this.workers.values()).filter(
      (w) => w.info.status === "idle",
    ).length;

    const avgDuration =
      this.stats.totalTasksProcessed > 0
        ? Math.round(this.stats.totalTaskDurationMs / this.stats.totalTasksProcessed)
        : 0;

    return {
      totalWorkers: this.workers.size,
      idleWorkers,
      busyWorkers: this.workers.size - idleWorkers,
      queuedTasks: this.taskQueue.length,
      totalTasksProcessed: this.stats.totalTasksProcessed,
      totalTasksFailed: this.stats.totalTasksFailed,
      averageTaskDurationMs: avgDuration,
      workerRestarts: this.stats.workerRestarts,
    };
  }

  /**
   * Get worker information
   */
  getWorkers(): WorkerInfo[] {
    return Array.from(this.workers.values()).map((w) => ({ ...w.info }));
  }

  /**
   * Add event listener
   */
  onEvent(listener: WorkerPoolEventListener): () => void {
    this.eventListeners.push(listener);
    return () => {
      const index = this.eventListeners.indexOf(listener);
      if (index !== -1) {
        this.eventListeners.splice(index, 1);
      }
    };
  }

  private emit(type: WorkerPoolEventType, data: unknown): void {
    for (const listener of this.eventListeners) {
      try {
        listener(type, data);
      } catch (error) {
        log.error("Event listener error", { error: String(error) });
      }
    }
  }

  /**
   * Gracefully shutdown the worker pool
   */
  async shutdown(timeoutMs = 30000): Promise<void> {
    log.info("Shutting down worker pool");
    this.isShuttingDown = true;

    // Wait for pending tasks
    const startTime = Date.now();
    while (this.pendingTasks.size > 0 && Date.now() - startTime < timeoutMs) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }

    // Terminate all workers
    const terminatePromises = Array.from(this.workers.values()).map(async (wrapper) => {
      try {
        await wrapper.worker.terminate();
      } catch (error) {
        log.error(`Failed to terminate worker ${wrapper.info.id}`, {
          error: String(error),
        });
      }
    });

    await Promise.all(terminatePromises);
    this.workers.clear();

    // Reject remaining queued tasks
    for (const task of this.taskQueue) {
      task.reject(new Error("Worker pool is shutting down"));
    }
    this.taskQueue = [];

    log.info("Worker pool shutdown complete");
  }
}

// ============================================================================
// Singleton Instance
// ============================================================================

let globalWorkerPool: CryptoWorkerPool | null = null;

/**
 * Initialize the global worker pool
 */
export function initWorkerPool(config?: WorkerPoolConfig): CryptoWorkerPool {
  if (globalWorkerPool) {
    log.warn("Worker pool already initialized");
    return globalWorkerPool;
  }

  globalWorkerPool = new CryptoWorkerPool(config);
  return globalWorkerPool;
}

/**
 * Get the global worker pool
 */
export function getWorkerPool(): CryptoWorkerPool | null {
  return globalWorkerPool;
}

/**
 * Get or initialize the global worker pool
 */
export function getOrInitWorkerPool(config?: WorkerPoolConfig): CryptoWorkerPool {
  return globalWorkerPool ?? initWorkerPool(config);
}

/**
 * Shutdown the global worker pool
 */
export async function shutdownWorkerPool(timeoutMs?: number): Promise<void> {
  if (globalWorkerPool) {
    await globalWorkerPool.shutdown(timeoutMs);
    globalWorkerPool = null;
  }
}
