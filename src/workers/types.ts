/**
 * Worker Threads 타입 정의
 *
 * Crypto 작업을 Worker Thread로 오프로드하기 위한 타입 정의
 * @module workers/types
 */

/**
 * Worker에서 지원하는 작업 유형
 */
export type WorkerTaskType =
  | "hash"
  | "encrypt"
  | "decrypt"
  | "pbkdf2"
  | "argon2"
  | "compress"
  | "decompress";

/**
 * Worker 작업 요청 메시지
 */
export interface WorkerRequest {
  /** 고유 요청 ID (UUID) */
  id: string;
  /** 작업 유형 */
  type: WorkerTaskType;
  /** 작업 페이로드 */
  payload: unknown;
  /** 요청 타임스탬프 */
  timestamp: number;
}

/**
 * Worker 작업 응답 메시지
 */
export interface WorkerResponse {
  /** 요청 ID (요청과 매칭) */
  id: string;
  /** 성공 여부 */
  success: boolean;
  /** 작업 결과 (성공 시) */
  result?: unknown;
  /** 오류 메시지 (실패 시) */
  error?: string;
  /** 성능 메트릭 */
  metrics?: WorkerMetrics;
  /** 응답 타임스탬프 */
  timestamp: number;
}

/**
 * Worker 성능 메트릭
 */
export interface WorkerMetrics {
  /** 총 실행 시간 (ms) */
  durationMs: number;
  /** CPU 사용 시간 (ms, 가능한 경우) */
  cpuTimeMs?: number;
  /** 메모리 사용량 (bytes) */
  memoryBytes?: number;
}

/**
 * Worker 상태
 */
export type WorkerStatus = "idle" | "busy" | "dead" | "restarting";

/**
 * Worker 인스턴스 정보
 */
export interface WorkerInfo {
  /** Worker ID */
  id: number;
  /** 현재 상태 */
  status: WorkerStatus;
  /** 현재 처리 중인 작업 ID */
  currentTaskId?: string;
  /** 생성 시간 */
  createdAt: number;
  /** 마지막 활동 시간 */
  lastActivityAt: number;
  /** 처리한 총 작업 수 */
  totalTasks: number;
  /** 오류 발생 횟수 */
  errorCount: number;
}

/**
 * Worker Pool 설정
 */
export interface WorkerPoolConfig {
  /** Worker 수 (기본값: CPU 코어 수 - 1) */
  workerCount?: number;
  /** 최대 대기열 크기 (기본값: 1000) */
  maxQueueSize?: number;
  /** 작업 타임아웃 (ms, 기본값: 30000) */
  taskTimeoutMs?: number;
  /** Worker 재시작 간격 (ms, 기본값: 1000) */
  restartDelayMs?: number;
  /** 최대 재시도 횟수 (기본값: 3) */
  maxRetries?: number;
  /** 작은 데이터 임계값 (bytes, 이하일 때는 메인 스레드에서 처리) */
  smallDataThreshold?: number;
}

/**
 * Worker Pool 상태
 */
export interface WorkerPoolStats {
  /** 총 Worker 수 */
  totalWorkers: number;
  /** 유휴 Worker 수 */
  idleWorkers: number;
  /** 작업 중인 Worker 수 */
  busyWorkers: number;
  /** 대기 중인 작업 수 */
  queuedTasks: number;
  /** 처리된 총 작업 수 */
  totalTasksProcessed: number;
  /** 실패한 작업 수 */
  totalTasksFailed: number;
  /** 평균 작업 실행 시간 (ms) */
  averageTaskDurationMs: number;
  /** Worker 재시작 횟수 */
  workerRestarts: number;
}

/**
 * 해싱 작업 페이로드
 */
export interface HashPayload {
  /** 해싱할 데이터 */
  data: string;
  /** 알고리즘 (기본값: sha256) */
  algorithm?: "sha256" | "sha512" | "sha1" | "md5";
}

/**
 * 암호화 작업 페이로드
 */
export interface EncryptPayload {
  /** 암호화할 데이터 */
  plaintext: string;
  /** 암호화 키 (base64) */
  key: string;
  /** 초기화 벡터 (base64, 선택사항) */
  iv?: string;
  /** 알고리즘 */
  algorithm?: "aes-256-gcm";
}

/**
 * 복호화 작업 페이로드
 */
export interface DecryptPayload {
  /** 복호화할 데이터 (base64) */
  ciphertext: string;
  /** 암호화 키 (base64) */
  key: string;
  /** 초기화 벡터 (base64) */
  iv: string;
  /** 인증 태그 (base64, GCM 모드용) */
  tag: string;
  /** 알고리즘 */
  algorithm?: "aes-256-gcm";
}

/**
 * PBKDF2 작업 페이로드
 */
export interface Pbkdf2Payload {
  /** 비밀번호 */
  password: string;
  /** 솔트 */
  salt: string;
  /** 반복 횟수 */
  iterations: number;
  /** 키 길이 (bytes) */
  keyLength: number;
  /** 다이제스트 알고리즘 */
  digest?: "sha256" | "sha512";
}

/**
 * 압축 작업 페이로드
 */
export interface CompressPayload {
  /** 압축할 데이터 */
  data: string;
  /** 압축 레벨 (0-9, 기본값: 6) */
  level?: number;
}

/**
 * Worker Pool 이벤트 타입
 */
export type WorkerPoolEventType =
  | "worker:created"
  | "worker:destroyed"
  | "worker:error"
  | "worker:restart"
  | "task:queued"
  | "task:started"
  | "task:completed"
  | "task:failed"
  | "task:timeout";

/**
 * Worker Pool 이벤트 리스너
 */
export type WorkerPoolEventListener = (type: WorkerPoolEventType, data: unknown) => void;
