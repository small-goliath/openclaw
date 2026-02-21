/**
 * GDPR Compliance Module
 * COMP-003, COMP-004 요구사항 구현
 *
 * 데이터 주체 권리:
 * - 접근 권리 (Right to Access)
 * - 삭제 권리 (Right to Deletion / Right to be Forgotten)
 * - 데이터 이동성 권리 (Right to Data Portability)
 */

// 데이터 수출 및 삭제 기능
export {
  exportUserData,
  exportPortableData,
  deleteUserData,
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
  type UserDataCategory,
} from "./data-export.js";

// GDPR API 엔드포인트
export { handleGdprApiRequest, getGdprApiStatus, type GdprApiOptions } from "./gdpr-api.js";
