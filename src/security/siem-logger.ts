/**
 * SIEM Logger for Security Monitoring
 *
 * 중앙 집중식 보안 모니터링을 위한 SIEM (Security Information and Event Management) 연동
 * - 구조화된 JSON 로깅
 * - 다중 SIEM 플랫폼 연동 (Splunk, ELK, Datadog)
 * - 로그 버퍼링 및 재시도 로직
 * - 요청 추적용 correlation IDs
 *
 * @module security/siem-logger
 */

import { randomUUID } from "node:crypto";
import { createSocket, type Socket } from "node:dgram";
import { createWriteStream, type WriteStream } from "node:fs";
import { mkdir, appendFile } from "node:fs/promises";
import { connect, type Socket as TcpSocket } from "node:net";
import { dirname } from "node:path";
import { connect as tlsConnect, type TLSSocket } from "node:tls";
import type {
  SecurityEvent,
  SecuritySeverity,
  SecurityEventType,
  SiemConfig,
  HttpSiemConfig,
  SyslogSiemConfig,
  FileSiemConfig,
  SiemOutputConfig,
} from "./security-events.js";
import {
  isSeverityAtLeast,
  serializeSecurityEvent,
  toCEFFormat,
  toSyslogFormat,
  DEFAULT_SIEM_CONFIG,
} from "./security-events.js";

/**
 * 로거 상태
 */
export type SiemLoggerStatus = "idle" | "running" | "paused" | "error";

/**
 * 출력 어댑터 인터페이스
 */
interface OutputAdapter {
  /** 어댑터 초기화 */
  initialize(): Promise<void>;

  /** 이벤트 전송 */
  send(event: SecurityEvent): Promise<boolean>;

  /** 어댑터 종료 */
  close(): Promise<void>;

  /** 설정 */
  config: SiemOutputConfig;
}

/**
 * HTTP 출력 어댑터
 * Splunk HEC, Datadog HTTP, ELK 등 지원
 */
class HttpOutputAdapter implements OutputAdapter {
  private config: HttpSiemConfig;
  private url: URL;

  constructor(config: HttpSiemConfig) {
    this.config = config;
    this.url = new URL(config.url);
  }

  async initialize(): Promise<void> {
    // HTTP 어댑터는 별도 초기화 불필요
    // 연결은 각 요청 시 생성
  }

  async send(event: SecurityEvent): Promise<boolean> {
    if (!this.shouldSend(event)) {
      return true;
    }

    try {
      const payload = this.formatPayload(event);
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
        ...this.config.headers,
      };

      // 인증 헤더 추가
      if (this.config.auth) {
        switch (this.config.auth.type) {
          case "bearer":
            if (this.config.auth.token) {
              headers["Authorization"] = `Bearer ${this.config.auth.token}`;
            }
            break;
          case "basic":
            if (this.config.auth.username && this.config.auth.password) {
              const credentials = Buffer.from(
                `${this.config.auth.username}:${this.config.auth.password}`,
              ).toString("base64");
              headers["Authorization"] = `Basic ${credentials}`;
            }
            break;
          case "api_key":
            if (this.config.auth.apiKey && this.config.auth.apiKeyHeader) {
              headers[this.config.auth.apiKeyHeader] = this.config.auth.apiKey;
            }
            break;
        }
      }

      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), this.config.timeout ?? 10000);

      try {
        const response = await fetch(this.url.toString(), {
          method: "POST",
          headers,
          body: payload,
          signal: controller.signal,
        });

        clearTimeout(timeout);

        if (!response.ok) {
          console.error(`SIEM HTTP error: ${response.status} ${response.statusText}`);
          return false;
        }

        return true;
      } catch (error) {
        clearTimeout(timeout);
        throw error;
      }
    } catch (error) {
      console.error(`Failed to send event to SIEM HTTP endpoint: ${error}`);
      return false;
    }
  }

  async close(): Promise<void> {
    // HTTP 어댑터는 별도 종료 불필요
  }

  private shouldSend(event: SecurityEvent): boolean {
    // 최소 심각도 확인
    if (this.config.minSeverity && !isSeverityAtLeast(event.severity, this.config.minSeverity)) {
      return false;
    }

    // 이벤트 유형 필터 확인
    if (this.config.eventTypes && this.config.eventTypes.length > 0) {
      if (!this.config.eventTypes.includes(event.eventType)) {
        return false;
      }
    }

    return true;
  }

  private formatPayload(event: SecurityEvent): string {
    // Splunk HEC 형식 지원
    if (this.url.pathname.includes("/services/collector")) {
      return JSON.stringify({
        time: new Date(event.timestamp).getTime() / 1000,
        source: event.source.component,
        host: event.source.host,
        sourcetype: "openclaw:security",
        event,
      });
    }

    // Datadog 형식 지원
    if (this.url.hostname.includes("datadog")) {
      return JSON.stringify({
        ddsource: "openclaw",
        ddtags: `severity:${event.severity},eventType:${event.eventType}`,
        hostname: event.source.host,
        service: event.source.component,
        message: JSON.stringify(event),
      });
    }

    // 기본 JSON 형식
    return serializeSecurityEvent(event);
  }
}

/**
 * Syslog 출력 어댑터
 * UDP/TCP syslog 지원
 */
class SyslogOutputAdapter implements OutputAdapter {
  private config: SyslogSiemConfig;
  private socket: Socket | TcpSocket | TLSSocket | null = null;
  private isTcp: boolean;

  constructor(config: SyslogSiemConfig) {
    this.config = config;
    this.isTcp = config.protocol === "tcp";
  }

  async initialize(): Promise<void> {
    if (this.isTcp) {
      if (this.config.useTls) {
        this.socket = tlsConnect({
          host: this.config.host,
          port: this.config.port,
        });
      } else {
        this.socket = connect({
          host: this.config.host,
          port: this.config.port,
        });
      }

      await new Promise<void>((resolve, reject) => {
        this.socket!.once("connect", () => resolve());
        this.socket!.once("error", reject);
      });
    } else {
      this.socket = createSocket("udp4");
    }
  }

  async send(event: SecurityEvent): Promise<boolean> {
    if (!this.shouldSend(event)) {
      return true;
    }

    if (!this.socket) {
      console.error("Syslog adapter not initialized");
      return false;
    }

    try {
      const message = toSyslogFormat(event);

      if (this.isTcp) {
        // TCP: newline-terminated message
        const tcpSocket = this.socket as TcpSocket | TLSSocket;
        return new Promise((resolve) => {
          tcpSocket.write(message + "\n", (err) => {
            if (err) {
              console.error(`Failed to send syslog message: ${err}`);
              resolve(false);
            } else {
              resolve(true);
            }
          });
        });
      } else {
        // UDP
        const udpSocket = this.socket as Socket;
        return new Promise((resolve) => {
          udpSocket.send(message, this.config.port, this.config.host, (err) => {
            if (err) {
              console.error(`Failed to send syslog message: ${err}`);
              resolve(false);
            } else {
              resolve(true);
            }
          });
        });
      }
    } catch (error) {
      console.error(`Failed to send event to syslog: ${error}`);
      return false;
    }
  }

  async close(): Promise<void> {
    if (this.socket) {
      if (this.isTcp) {
        const tcpSocket = this.socket as TcpSocket | TLSSocket;
        tcpSocket.end();
        await new Promise<void>((resolve) => tcpSocket.once("close", resolve));
      } else {
        const udpSocket = this.socket as Socket;
        udpSocket.close();
      }
      this.socket = null;
    }
  }

  private shouldSend(event: SecurityEvent): boolean {
    if (this.config.minSeverity && !isSeverityAtLeast(event.severity, this.config.minSeverity)) {
      return false;
    }

    if (this.config.eventTypes && this.config.eventTypes.length > 0) {
      if (!this.config.eventTypes.includes(event.eventType)) {
        return false;
      }
    }

    return true;
  }
}

/**
 * 파일 출력 어댑터
 * 로컬 파일 로깅 (개발/테스트용)
 */
class FileOutputAdapter implements OutputAdapter {
  private config: FileSiemConfig;
  private writeStream: WriteStream | null = null;
  private currentSize = 0;

  constructor(config: FileSiemConfig) {
    this.config = config;
  }

  async initialize(): Promise<void> {
    // 디렉토리 생성
    const dir = dirname(this.config.path);
    await mkdir(dir, { recursive: true });

    // 파일 스트림 생성
    this.writeStream = createWriteStream(this.config.path, { flags: "a" });

    await new Promise<void>((resolve, reject) => {
      this.writeStream!.once("open", () => resolve());
      this.writeStream!.once("error", reject);
    });

    // 현재 파일 크기 확인 (로테이션용)
    try {
      const stats = await import("node:fs/promises").then((fs) => fs.stat(this.config.path));
      this.currentSize = stats.size;
    } catch {
      this.currentSize = 0;
    }
  }

  async send(event: SecurityEvent): Promise<boolean> {
    if (!this.shouldSend(event)) {
      return true;
    }

    if (!this.writeStream) {
      console.error("File adapter not initialized");
      return false;
    }

    try {
      const message = serializeSecurityEvent(event) + "\n";
      const messageSize = Buffer.byteLength(message, "utf8");

      // 로테이션 체크
      if (this.config.rotate && this.config.maxSize) {
        if (this.currentSize + messageSize > this.config.maxSize) {
          await this.rotateFile();
        }
      }

      return new Promise((resolve) => {
        this.writeStream!.write(message, (err) => {
          if (err) {
            console.error(`Failed to write to log file: ${err}`);
            resolve(false);
          } else {
            this.currentSize += messageSize;
            resolve(true);
          }
        });
      });
    } catch (error) {
      console.error(`Failed to write event to file: ${error}`);
      return false;
    }
  }

  async close(): Promise<void> {
    if (this.writeStream) {
      this.writeStream.end();
      await new Promise<void>((resolve) => this.writeStream!.once("close", resolve));
      this.writeStream = null;
    }
  }

  private shouldSend(event: SecurityEvent): boolean {
    if (this.config.minSeverity && !isSeverityAtLeast(event.severity, this.config.minSeverity)) {
      return false;
    }

    if (this.config.eventTypes && this.config.eventTypes.length > 0) {
      if (!this.config.eventTypes.includes(event.eventType)) {
        return false;
      }
    }

    return true;
  }

  private async rotateFile(): Promise<void> {
    if (!this.config.rotate) {
      return;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
    const rotatedPath = `${this.config.path}.${timestamp}`;

    // 현재 스트림 닫기
    this.writeStream!.end();
    await new Promise<void>((resolve) => this.writeStream!.once("close", resolve));

    // 파일 이동
    await import("node:fs/promises").then((fs) => fs.rename(this.config.path, rotatedPath));

    // 새 스트림 생성
    this.writeStream = createWriteStream(this.config.path, { flags: "a" });
    this.currentSize = 0;

    // 오래된 파일 정리
    if (this.config.maxFiles) {
      await this.cleanupOldFiles();
    }
  }

  private async cleanupOldFiles(): Promise<void> {
    const fs = await import("node:fs/promises");
    const path = await import("node:path");

    const dir = dirname(this.config.path);
    const baseName = path.basename(this.config.path);

    const files = await fs.readdir(dir);
    const logFiles = files
      .filter((f) => f.startsWith(baseName) && f !== baseName)
      .map((f) => ({
        name: f,
        path: path.join(dir, f),
      }));

    // 파일 수가 maxFiles를 초과하면 오래된 파일 삭제
    if (logFiles.length > (this.config.maxFiles ?? 0)) {
      const sortedFiles = await Promise.all(
        logFiles.map(async (f) => ({
          ...f,
          mtime: (await fs.stat(f.path)).mtime,
        })),
      );
      sortedFiles.sort((a, b) => a.mtime.getTime() - b.mtime.getTime());

      const filesToDelete = sortedFiles.slice(0, sortedFiles.length - this.config.maxFiles!);
      for (const file of filesToDelete) {
        await fs.unlink(file.path).catch(() => {
          // 삭제 실패 무시
        });
      }
    }
  }
}

/**
 * 버퍼링된 이벤트
 */
interface BufferedEvent {
  event: SecurityEvent;
  retryCount: number;
  nextRetryTime: number;
}

/**
 * SIEM 로거 클래스
 *
 * 보안 이벤트를 수집하여 설정된 SIEM 플랫폼으로 전송합니다.
 * 버퍼링, 재시도, 배치 처리를 지원합니다.
 */
export class SiemLogger {
  private config: SiemConfig;
  private adapters: OutputAdapter[] = [];
  private buffer: BufferedEvent[] = [];
  private status: SiemLoggerStatus = "idle";
  private flushTimer: NodeJS.Timeout | null = null;
  private correlationId: string;
  private appVersion: string;

  /**
   * SIEM 로거 생성자
   * @param config SIEM 설정
   * @param appVersion 애플리케이션 버전
   */
  constructor(config: Partial<SiemConfig> = {}, appVersion: string = "unknown") {
    this.config = { ...DEFAULT_SIEM_CONFIG, ...config };
    this.correlationId = randomUUID();
    this.appVersion = appVersion;
  }

  /**
   * 로거 초기화
   * 모든 출력 어댑터를 초기화합니다.
   */
  async initialize(): Promise<void> {
    if (this.status === "running") {
      return;
    }

    if (!this.config.enabled) {
      this.status = "idle";
      return;
    }

    try {
      // 출력 어댑터 생성
      this.adapters = this.config.outputs
        .filter((output) => output.enabled)
        .map((output) => this.createAdapter(output));

      // 어댑터 초기화
      await Promise.all(this.adapters.map((adapter) => adapter.initialize()));

      this.status = "running";

      // 주기적 플러시 타이머 시작
      this.startFlushTimer();
    } catch (error) {
      this.status = "error";
      console.error(`Failed to initialize SIEM logger: ${error}`);
      throw error;
    }
  }

  /**
   * 보안 이벤트 로깅
   * @param event 보안 이벤트
   */
  async log(event: SecurityEvent): Promise<void> {
    if (!this.config.enabled || this.status !== "running") {
      return;
    }

    // 버퍼에 추가
    this.buffer.push({
      event,
      retryCount: 0,
      nextRetryTime: Date.now(),
    });

    // 버퍼가 가득 차면 즉시 플러시
    if (this.buffer.length >= this.config.bufferSize) {
      await this.flush();
    }
  }

  /**
   * 버퍼 강제 플러시
   */
  async flush(): Promise<void> {
    if (this.buffer.length === 0 || this.adapters.length === 0) {
      return;
    }

    const now = Date.now();
    const eventsToSend: BufferedEvent[] = [];
    const remainingEvents: BufferedEvent[] = [];

    // 재시도 시간이 된 이벤트만 선택
    for (const buffered of this.buffer) {
      if (buffered.nextRetryTime <= now) {
        eventsToSend.push(buffered);
      } else {
        remainingEvents.push(buffered);
      }
    }

    this.buffer = remainingEvents;

    // 각 어댑터로 이벤트 전송
    const sendPromises = eventsToSend.map(async (buffered) => {
      const results = await Promise.all(
        this.adapters.map((adapter) => adapter.send(buffered.event)),
      );

      // 모든 어댑터가 실패하면 재시도 큐에 다시 추가
      const allFailed = results.every((r) => !r);
      if (allFailed && buffered.retryCount < this.config.maxRetries) {
        const retryDelay = this.config.retryDelayMs * Math.pow(2, buffered.retryCount);
        this.buffer.push({
          event: buffered.event,
          retryCount: buffered.retryCount + 1,
          nextRetryTime: now + retryDelay,
        });
      }
    });

    await Promise.all(sendPromises);
  }

  /**
   * 로거 일시 중지
   */
  pause(): void {
    if (this.status === "running") {
      this.status = "paused";
      this.stopFlushTimer();
    }
  }

  /**
   * 로거 재개
   */
  resume(): void {
    if (this.status === "paused") {
      this.status = "running";
      this.startFlushTimer();
    }
  }

  /**
   * 로거 종료
   * 남은 버퍼를 모두 플러시하고 어댑터를 종료합니다.
   */
  async shutdown(): Promise<void> {
    this.stopFlushTimer();

    // 남은 이벤트 플러시 (최대 3회 재시도)
    for (let i = 0; i < 3 && this.buffer.length > 0; i++) {
      await this.flush();
      if (this.buffer.length > 0) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }

    // 어댑터 종료
    await Promise.all(this.adapters.map((adapter) => adapter.close()));

    this.status = "idle";
    this.adapters = [];
  }

  /**
   * 현재 상태 조회
   */
  getStatus(): SiemLoggerStatus {
    return this.status;
  }

  /**
   * 버퍼 크기 조회
   */
  getBufferSize(): number {
    return this.buffer.length;
  }

  /**
   * 상관관계 ID 조회
   */
  getCorrelationId(): string {
    return this.correlationId;
  }

  /**
   * 새 상관관계 ID 생성
   */
  newCorrelationId(): string {
    this.correlationId = randomUUID();
    return this.correlationId;
  }

  /**
   * 설정 업데이트
   * @param config 새 설정
   */
  async updateConfig(config: Partial<SiemConfig>): Promise<void> {
    const wasRunning = this.status === "running";

    if (wasRunning) {
      await this.shutdown();
    }

    this.config = { ...this.config, ...config };

    if (wasRunning && this.config.enabled) {
      await this.initialize();
    }
  }

  /**
   * 출력 어댑터 생성
   */
  private createAdapter(output: SiemOutputConfig): OutputAdapter {
    switch (output.type) {
      case "http":
        return new HttpOutputAdapter(output as HttpSiemConfig);
      case "syslog":
        return new SyslogOutputAdapter(output as SyslogSiemConfig);
      case "file":
        return new FileOutputAdapter(output as FileSiemConfig);
      default:
        throw new Error(`Unknown output type: ${output.type}`);
    }
  }

  /**
   * 플러시 타이머 시작
   */
  private startFlushTimer(): void {
    if (this.flushTimer) {
      return;
    }

    this.flushTimer = setInterval(() => {
      this.flush().catch((err) => {
        console.error(`Failed to flush SIEM buffer: ${err}`);
      });
    }, this.config.flushIntervalMs);
  }

  /**
   * 플러시 타이머 중지
   */
  private stopFlushTimer(): void {
    if (this.flushTimer) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
  }
}

/**
 * 전역 SIEM 로거 인스턴스
 */
let globalSiemLogger: SiemLogger | null = null;

/**
 * 전역 SIEM 로거 초기화
 * @param config SIEM 설정
 * @param appVersion 애플리케이션 버전
 */
export async function initializeSiemLogger(
  config: Partial<SiemConfig> = {},
  appVersion: string = "unknown",
): Promise<SiemLogger> {
  if (globalSiemLogger) {
    await globalSiemLogger.shutdown();
  }

  globalSiemLogger = new SiemLogger(config, appVersion);
  await globalSiemLogger.initialize();

  return globalSiemLogger;
}

/**
 * 전역 SIEM 로거 조회
 * @returns SIEM 로거 인스턴스 (초기화되지 않았으면 null)
 */
export function getSiemLogger(): SiemLogger | null {
  return globalSiemLogger;
}

/**
 * 전역 SIEM 로거 종료
 */
export async function shutdownSiemLogger(): Promise<void> {
  if (globalSiemLogger) {
    await globalSiemLogger.shutdown();
    globalSiemLogger = null;
  }
}

/**
 * 보안 이벤트 로깅 (편의 함수)
 * @param event 보안 이벤트
 */
export async function logSecurityEvent(event: SecurityEvent): Promise<void> {
  if (globalSiemLogger) {
    await globalSiemLogger.log(event);
  }
}

/**
 * Critical 이벤트 실시간 알림
 * Critical 심각도의 이벤트는 즉시 전송합니다.
 * @param event 보안 이벤트
 */
export async function alertCriticalEvent(event: SecurityEvent): Promise<void> {
  if (!globalSiemLogger || event.severity !== "critical") {
    return;
  }

  // Critical 이벤트는 즉시 플러시
  await globalSiemLogger.log(event);
  await globalSiemLogger.flush();
}
