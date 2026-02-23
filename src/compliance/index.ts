/**
 * GDPR Compliance Module
 * COMP-003, COMP-004, SEC-4.2, SEC-7.3 요구사항 구현
 *
 * 데이터 주체 권리:
 * - 접근 권리 (Right to Access)
 * - 삭제 권리 (Right to Deletion / Right to be Forgotten)
 * - 데이터 이동성 권리 (Right to Data Portability)
 * - 수정 권리 (Right to Rectification)
 * - 이의 제기권 (Right to Object)
 *
 * 동의 관리:
 * - 세분화된 동의 관리 (necessary, functional, analytics, marketing)
 * - 동의 로깅 및 감사 추적
 * - 동의 철회 메커니즘
 * - 데이터 처리 목적 문서화
 */

// 데이터 수출 및 삭제 기능
export {
  exportUserData,
  exportPortableData,
  deleteUserData,
  rectifyUserData,
  saveExportToFile,
  calculateExportSize,
  type UserDataExport,
  type MemoryExportData,
  type CredentialExportData,
  type ConfigExportData,
  type AuditLogEntry,
  type TranscriptExportData,
  type DataExportOptions,
  type DataDeletionOptions,
  type DataDeletionResult,
  type DataRectificationOptions,
  type DataRectificationResult,
  type DataRectificationItem,
  type UserDataCategory,
} from "./data-export.js";

// GDPR API 엔드포인트
export {
  handleGdprApiRequest,
  getGdprApiStatus,
  type GdprApiOptions,
  type ObjectionPurpose,
  type ObjectionRequest,
  type ObjectionResult,
} from "./gdpr-api.js";

// 동의 관리 시스템
export {
  // 클래스 및 저장소
  ConsentStore,
  getConsentStore,
  initializeConsentStore,

  // 유틸리티 함수
  canExecuteScript,
  canSetCookie,
  shouldShowConsentBanner,
  exportConsentSettings,
  getConsentStatus,

  // 타입
  type ConsentType,
  type ConsentState,
  type ConsentPreferences,
  type ConsentLogEntry,
  type ConsentStoreConfig,
} from "./consent-store.js";
