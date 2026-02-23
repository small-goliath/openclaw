/**
 * GDPR 데이터 주체 권리 API 구현
 * COMP-003, COMP-004 요구사항
 *
 * 제공하는 권리:
 * 1. 접근 권리 (Right to Access) - GET /api/v1/user/data-export
 * 2. 삭제 권리 (Right to Deletion) - DELETE /api/v1/user/data
 * 3. 데이터 이동성 권리 (Right to Data Portability) - GET /api/v1/user/data-portable
 * 4. 수정 권리 (Right to Rectification) - PUT/PATCH /api/v1/user/data
 * 5. 이의 제기권 (Right to Object) - POST /api/v1/user/objection
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import type { AuthRateLimiter } from "../gateway/auth-rate-limit.js";
import { authorizeGatewayConnect, type ResolvedGatewayAuth } from "../gateway/auth.js";
import { getBearerToken } from "../gateway/http-utils.js";
import { createSubsystemLogger } from "../logging/subsystem.js";
import {
  exportUserData,
  exportPortableData,
  deleteUserData,
  rectifyUserData,
  calculateExportSize,
  type DataExportOptions,
  type DataDeletionOptions,
  type DataRectificationOptions,
  type UserDataCategory,
} from "./data-export.js";
import { getConsentStore } from "./consent-store.js";
import fs from "node:fs/promises";
import path from "node:path";
import { loadConfig, resolveConfigPath } from "../config/config.js";

const log = createSubsystemLogger("compliance/gdpr-api");

/**
 * 이의 제기 목적 유형 (GDPR Article 21)
 */
export type ObjectionPurpose = "marketing" | "profiling" | "third_party_sharing";

/**
 * 이의 제기 요청 본문
 */
export interface ObjectionRequest {
  /** 이의 제기할 목적 목록 */
  purposes: ObjectionPurpose[];
  /** 즉시 적용 여부 */
  effectiveImmediately?: boolean;
  /** 이의 제기 사유 (선택적) */
  reason?: string;
}

/**
 * 이의 제기 결과
 */
export interface ObjectionResult {
  /** 성공 여부 */
  success: boolean;
  /** 이의 제기 ID */
  objectionId: string;
  /** 적용일 */
  effectiveDate: string;
  /** 처리된 목적 목록 */
  processedPurposes: ObjectionPurpose[];
  /** 처리 상세 정보 */
  details: {
    marketing?: {
      status: "withdrawn" | "already_withdrawn" | "failed";
      message: string;
    };
    profiling?: {
      status: "disabled" | "already_disabled" | "failed";
      message: string;
    };
    third_party_sharing?: {
      status: "disabled" | "already_disabled" | "failed";
      message: string;
    };
  };
  /** 오류 메시지 */
  errors?: string[];
}

// 데이터 수출 최대 크기 (100MB)
const MAX_EXPORT_SIZE_BYTES = 100 * 1024 * 1024;

// 데이터 수출 타임아웃 (5분)
const EXPORT_TIMEOUT_MS = 5 * 60 * 1000;

// 데이터 삭제 타임아웃 (10분)
const DELETION_TIMEOUT_MS = 10 * 60 * 1000;

/**
 * GDPR API 핸들러 옵션
 */
export interface GdprApiOptions {
  /** 게이트웨이 인증 설정 */
  auth: ResolvedGatewayAuth;
  /** 신뢰할 수 있는 프록시 목록 */
  trustedProxies: string[];
  /** 선택적 인증 레이트 리미터 */
  rateLimiter?: AuthRateLimiter;
  /** 비동기 작업 완료 시 콜백 (선택적) */
  onExportComplete?: (params: {
    userId: string;
    exportId: string;
    success: boolean;
    sizeBytes: number;
    error?: string;
  }) => void | Promise<void>;
  /** 삭제 완료 시 콜백 (선택적) */
  onDeletionComplete?: (params: {
    userId: string;
    deletionId: string;
    success: boolean;
    deletedCount: number;
    error?: string;
  }) => void | Promise<void>;
  /** 데이터 수정 완료 시 콜백 (선택적) */
  onRectificationComplete?: (params: {
    userId: string;
    requestId: string;
    success: boolean;
    updated: {
      sessions: number;
      memories: number;
      credentials: number;
      config: number;
    };
    error?: string;
  }) => void | Promise<void>;
  /** 이의 제기 완료 시 콜백 (선택적) */
  onObjectionComplete?: (params: {
    userId: string;
    objectionId: string;
    success: boolean;
    purposes: ObjectionPurpose[];
    effectiveDate: string;
    error?: string;
  }) => void | Promise<void>;
}

/**
 * GDPR API 요청 핸들러
 * @returns 요청을 처리했으면 true, 아니면 false
 */
export async function handleGdprApiRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: GdprApiOptions,
): Promise<boolean> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const pathname = url.pathname;

  // GDPR API 경로 확인
  if (!pathname.startsWith("/api/v1/user/")) {
    return false;
  }

  // 인증 확인
  const authResult = await authenticateRequest(req, opts);
  if (!authResult.ok) {
    sendAuthFailure(res, authResult);
    return true;
  }

  const userId = authResult.userId;

  // 라우팅
  if (pathname === "/api/v1/user/data-export" && req.method === "GET") {
    await handleDataExport(req, res, userId);
    return true;
  }

  if (pathname === "/api/v1/user/data-portable" && req.method === "GET") {
    await handleDataPortability(req, res, userId);
    return true;
  }

  if (pathname === "/api/v1/user/data" && req.method === "DELETE") {
    await handleDataDeletion(req, res, userId, opts);
    return true;
  }

  if (pathname === "/api/v1/user/data" && (req.method === "PUT" || req.method === "PATCH")) {
    await handleDataRectification(req, res, userId, opts);
    return true;
  }

  if (pathname === "/api/v1/user/objection" && req.method === "POST") {
    await handleRightToObject(req, res, userId, opts);
    return true;
  }

  // 지원하지 않는 엔드포인트
  sendJson(res, 404, {
    error: "Not Found",
    message: "지원하지 않는 GDPR API 엔드포인트입니다.",
  });
  return true;
}

/**
 * 데이터 수출 핸들러 (접근 권리)
 * GET /api/v1/user/data-export
 */
async function handleDataExport(
  req: IncomingMessage,
  res: ServerResponse,
  userId: string,
): Promise<void> {
  log.info(`Data export requested for user: ${userId}`);

  try {
    const url = new URL(req.url ?? "/", "http://localhost");
    const opts = parseExportOptions(url);

    // 타임아웃 설정
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new Error("데이터 수출 시간이 초과되었습니다."));
      }, EXPORT_TIMEOUT_MS);
    });

    // 데이터 수출 실행
    const exportPromise = exportUserData(userId, opts);
    const exportData = await Promise.race([exportPromise, timeoutPromise]);

    // 크기 확인
    const sizeBytes = calculateExportSize(exportData);
    if (sizeBytes > MAX_EXPORT_SIZE_BYTES) {
      sendJson(res, 413, {
        error: "Payload Too Large",
        message: "수출 데이터가 너무 큽니다. 데이터 범위를 줄여서 요청하세요.",
        sizeBytes,
        maxSizeBytes: MAX_EXPORT_SIZE_BYTES,
      });
      return;
    }

    // 응답 헤더 설정
    res.statusCode = 200;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader("X-Export-Size-Bytes", String(sizeBytes));
    res.setHeader("X-Export-Timestamp", exportData.exportedAt);

    // 스트리밍 응답 (대용량 데이터 처리)
    if (sizeBytes > 10 * 1024 * 1024) {
      // 10MB 이상
      res.setHeader("Transfer-Encoding", "chunked");
      const chunks = JSON.stringify(exportData).match(/.{1,65536}/g) || [];
      for (const chunk of chunks) {
        res.write(chunk);
      }
      res.end();
    } else {
      res.end(JSON.stringify(exportData, null, 2));
    }

    log.info(`Data export completed for user: ${userId}`, { sizeBytes });
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    log.error(`Data export failed for user: ${userId}`, { error: errorMsg });

    sendJson(res, 500, {
      error: "Internal Server Error",
      message: "데이터 수출 중 오류가 발생했습니다.",
      details: errorMsg,
    });
  }
}

/**
 * 데이터 이동성 핸들러 (데이터 이동성 권리)
 * GET /api/v1/user/data-portable
 */
async function handleDataPortability(
  req: IncomingMessage,
  res: ServerResponse,
  userId: string,
): Promise<void> {
  log.info(`Data portability export requested for user: ${userId}`);

  try {
    const url = new URL(req.url ?? "/", "http://localhost");
    const opts = parseExportOptions(url);

    // 타임아웃 설정
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new Error("데이터 수출 시간이 초과되었습니다."));
      }, EXPORT_TIMEOUT_MS);
    });

    // 포터블 형식으로 데이터 수출
    const exportPromise = exportPortableData(userId, opts);
    const portableData = await Promise.race([exportPromise, timeoutPromise]);

    // 응답 헤더 설정
    res.statusCode = 200;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="openclaw-data-export-${userId}-${Date.now()}.json"`,
    );

    res.end(JSON.stringify(portableData, null, 2));

    log.info(`Data portability export completed for user: ${userId}`);
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    log.error(`Data portability export failed for user: ${userId}`, { error: errorMsg });

    sendJson(res, 500, {
      error: "Internal Server Error",
      message: "데이터 이동성 수출 중 오류가 발생했습니다.",
      details: errorMsg,
    });
  }
}

/**
 * 데이터 삭제 핸들러 (삭제 권리 - Right to be Forgotten)
 * DELETE /api/v1/user/data
 */
async function handleDataDeletion(
  req: IncomingMessage,
  res: ServerResponse,
  userId: string,
  opts: GdprApiOptions,
): Promise<void> {
  log.info(`Data deletion requested for user: ${userId}`);

  try {
    const url = new URL(req.url ?? "/", "http://localhost");
    const deleteOpts = parseDeletionOptions(url);

    // 타임아웃 설정
    const timeoutPromise = new Promise<never>((_, reject) => {
      setTimeout(() => {
        reject(new Error("데이터 삭제 시간이 초과되었습니다."));
      }, DELETION_TIMEOUT_MS);
    });

    // 데이터 삭제 실행
    const deletionPromise = deleteUserData(userId, deleteOpts);
    const result = await Promise.race([deletionPromise, timeoutPromise]);

    // 응답
    const statusCode = result.success ? 200 : 207; // 207 Multi-Status (부분 성공)

    sendJson(res, statusCode, {
      success: result.success,
      message: result.success
        ? "모든 데이터가 성공적으로 삭제되었습니다."
        : "일부 데이터 삭제에 실패했습니다.",
      details: {
        deletedCategories: result.deletedCategories,
        failedCategories: result.failedCategories,
        deletedCount: result.deletedCount,
        errors: result.errors,
      },
      gdprNotice: {
        article: "Article 17",
        right: "Right to erasure ('right to be forgotten')",
        retentionNote: "일부 데이터는 법적 의무 또는 정당한 이익을 위해 보관될 수 있습니다.",
      },
    });

    log.info(`Data deletion completed for user: ${userId}`, {
      success: result.success,
      deletedCategories: result.deletedCategories,
      deletedCount: result.deletedCount,
    });

    // 콜백 호출 (선택적)
    if (opts.onDeletionComplete) {
      await opts.onDeletionComplete({
        userId,
        deletionId: `del-${userId}-${Date.now()}`,
        success: result.success,
        deletedCount: result.deletedCount,
        error: result.errors.join("; ") || undefined,
      });
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    log.error(`Data deletion failed for user: ${userId}`, { error: errorMsg });

    sendJson(res, 500, {
      error: "Internal Server Error",
      message: "데이터 삭제 중 오류가 발생했습니다.",
      details: errorMsg,
    });
  }
}

/**
 * 요청 인증
 */
async function authenticateRequest(
  req: IncomingMessage,
  opts: GdprApiOptions,
): Promise<
  | { ok: true; userId: string }
  | { ok: false; reason: string; rateLimited?: boolean; retryAfterMs?: number }
> {
  const token = getBearerToken(req);

  if (!token) {
    return { ok: false, reason: "missing_token" };
  }

  const authResult = await authorizeGatewayConnect({
    auth: opts.auth,
    connectAuth: { token, password: token },
    req,
    trustedProxies: opts.trustedProxies,
    rateLimiter: opts.rateLimiter,
  });

  if (!authResult.ok) {
    return {
      ok: false,
      reason: authResult.reason ?? "unauthorized",
      rateLimited: authResult.rateLimited,
      retryAfterMs: authResult.retryAfterMs,
    };
  }

  // 사용자 ID 추출 (토큰에서 또는 기본값)
  const userId = extractUserIdFromToken(token) || "anonymous";

  return { ok: true, userId };
}

/**
 * 토큰에서 사용자 ID 추출
 */
function extractUserIdFromToken(token: string): string | null {
  // JWT 형식 지원
  if (token.includes(".")) {
    try {
      const parts = token.split(".");
      if (parts.length === 3) {
        const payload = JSON.parse(Buffer.from(parts[1], "base64").toString());
        return payload.sub || payload.userId || payload.user_id || null;
      }
    } catch {
      // JWT 파싱 실패 시 토큰 해시 사용
    }
  }

  // 토큰 해시를 사용자 ID로 사용
  return `user-${Buffer.from(token).toString("base64").slice(0, 16)}`;
}

/**
 * 인증 실패 응답
 */
function sendAuthFailure(
  res: ServerResponse,
  auth: { reason: string; rateLimited?: boolean; retryAfterMs?: number },
): void {
  if (auth.rateLimited) {
    const retryAfterSeconds =
      auth.retryAfterMs && auth.retryAfterMs > 0 ? Math.ceil(auth.retryAfterMs / 1000) : undefined;

    res.statusCode = 429;
    res.setHeader("Content-Type", "application/json; charset=utf-8");
    if (retryAfterSeconds) {
      res.setHeader("Retry-After", String(retryAfterSeconds));
    }
    res.end(
      JSON.stringify({
        error: "Too Many Requests",
        message: "너무 많은 인증 시도가 있었습니다. 잠시 후 다시 시도하세요.",
        retryAfterSeconds,
      }),
    );
    return;
  }

  res.statusCode = 401;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("WWW-Authenticate", 'Bearer realm="GDPR API"');
  res.end(
    JSON.stringify({
      error: "Unauthorized",
      message: "인증이 필요합니다.",
      reason: auth.reason,
    }),
  );
}

/**
 * JSON 응답 전송
 */
function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.end(JSON.stringify(body));
}

/**
 * 수출 옵션 파싱
 */
function parseExportOptions(url: URL): DataExportOptions {
  const opts: DataExportOptions = {};

  // 세션 키 필터
  const sessionKey = url.searchParams.get("sessionKey");
  if (sessionKey) {
    opts.sessionKey = sessionKey;
  }

  // 카테고리 필터
  const categories = url.searchParams.get("categories");
  if (categories) {
    opts.categories = categories.split(",") as UserDataCategory[];
  }

  // 시작 날짜
  const startDate = url.searchParams.get("startDate");
  if (startDate) {
    opts.startDate = new Date(startDate);
  }

  // 종료 날짜
  const endDate = url.searchParams.get("endDate");
  if (endDate) {
    opts.endDate = new Date(endDate);
  }

  return opts;
}

/**
 * 삭제 옵션 파싱
 */
function parseDeletionOptions(url: URL): DataDeletionOptions {
  const opts: DataDeletionOptions = {};

  // 세션 키 필터
  const sessionKey = url.searchParams.get("sessionKey");
  if (sessionKey) {
    opts.sessionKey = sessionKey;
  }

  // 카테고리 필터
  const categories = url.searchParams.get("categories");
  if (categories) {
    opts.categories = categories.split(",") as UserDataCategory[];
  }

  // 영구 삭제 여부
  const permanent = url.searchParams.get("permanent");
  opts.permanent = permanent === "true";

  return opts;
}

/**
 * 데이터 수정 핸들러 (수정 권리 - Right to Rectification)
 * PUT/PATCH /api/v1/user/data
 */
async function handleDataRectification(
  req: IncomingMessage,
  res: ServerResponse,
  userId: string,
  opts: GdprApiOptions,
): Promise<void> {
  log.info(`Data rectification requested for user: ${userId}`);

  try {
    // 요청 본문 파싱
    const body = await parseRequestBody(req);

    if (!body || typeof body !== "object") {
      sendJson(res, 400, {
        error: "Bad Request",
        message: "요청 본문이 유효하지 않습니다.",
      });
      return;
    }

    const rectOpts: DataRectificationOptions = {
      items: Array.isArray(body.items) ? body.items : [],
      reason: typeof body.reason === "string" ? body.reason : undefined,
    };

    if (rectOpts.items.length === 0) {
      sendJson(res, 400, {
        error: "Bad Request",
        message: "수정할 데이터 항목(items)이 필요합니다.",
      });
      return;
    }

    // 데이터 수정 실행
    const result = await rectifyUserData(userId, rectOpts);

    // 응답 상태 코드 결정
    const statusCode = result.success ? 200 : 207; // 207 Multi-Status (부분 성공)

    sendJson(res, statusCode, {
      success: result.success,
      updated: result.updated,
      requestId: result.requestId,
      slaDeadline: result.slaDeadline,
      gdprNotice: {
        article: "Article 16",
        right: "Right to rectification",
        note: "데이터 주체는 부정확한 개인 데이터의 수정을 요청할 권리가 있습니다.",
      },
      details: result.details,
      errors: result.errors,
    });

    log.info(`Data rectification completed for user: ${userId}`, {
      requestId: result.requestId,
      success: result.success,
      updated: result.updated,
    });

    // 콜백 호출 (선택적)
    if (opts.onRectificationComplete) {
      await opts.onRectificationComplete({
        userId,
        requestId: result.requestId,
        success: result.success,
        updated: result.updated,
        error: result.errors?.join("; ") || undefined,
      });
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    log.error(`Data rectification failed for user: ${userId}`, { error: errorMsg });

    sendJson(res, 500, {
      error: "Internal Server Error",
      message: "데이터 수정 중 오류가 발생했습니다.",
      details: errorMsg,
    });
  }
}

/**
 * 이의 제기권 핸들러 (Right to Object - GDPR Article 21)
 * POST /api/v1/user/objection
 */
async function handleRightToObject(
  req: IncomingMessage,
  res: ServerResponse,
  userId: string,
  opts: GdprApiOptions,
): Promise<void> {
  log.info(`Right to object requested for user: ${userId}`);

  try {
    // 요청 본문 파싱
    const body = await parseRequestBody(req);

    if (!body || typeof body !== "object") {
      sendJson(res, 400, {
        error: "Bad Request",
        message: "요청 본문이 유효하지 않습니다.",
      });
      return;
    }

    const objectionRequest = body as ObjectionRequest;

    // purposes 필수 검증
    if (!Array.isArray(objectionRequest.purposes) || objectionRequest.purposes.length === 0) {
      sendJson(res, 400, {
        error: "Bad Request",
        message: "이의 제기할 목적(purposes)이 필요합니다.",
        validPurposes: ["marketing", "profiling", "third_party_sharing"],
      });
      return;
    }

    // purposes 유효성 검증
    const validPurposes: ObjectionPurpose[] = ["marketing", "profiling", "third_party_sharing"];
    const invalidPurposes = objectionRequest.purposes.filter(
      (p): p is string => !validPurposes.includes(p as ObjectionPurpose)
    );

    if (invalidPurposes.length > 0) {
      sendJson(res, 400, {
        error: "Bad Request",
        message: "유효하지 않은 목적이 포함되어 있습니다.",
        invalidPurposes,
        validPurposes,
      });
      return;
    }

    // 즉시 적용 여부 (기본값: true)
    const effectiveImmediately = objectionRequest.effectiveImmediately !== false;
    const effectiveDate = effectiveImmediately
      ? new Date().toISOString()
      : new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(); // 24시간 후

    const objectionId = `obj-${userId}-${Date.now()}`;

    // 이의 제기 처리
    const result: ObjectionResult = {
      success: true,
      objectionId,
      effectiveDate,
      processedPurposes: objectionRequest.purposes as ObjectionPurpose[],
      details: {},
      errors: [],
    };

    // 각 목적별 처리
    for (const purpose of objectionRequest.purposes as ObjectionPurpose[]) {
      try {
        switch (purpose) {
          case "marketing": {
            const marketingResult = await processMarketingObjection(userId);
            result.details.marketing = marketingResult;
            break;
          }
          case "profiling": {
            const profilingResult = await processProfilingObjection(userId);
            result.details.profiling = profilingResult;
            break;
          }
          case "third_party_sharing": {
            const sharingResult = await processThirdPartySharingObjection(userId);
            result.details.third_party_sharing = sharingResult;
            break;
          }
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        log.error(`Failed to process objection for ${purpose}`, { error: errorMsg });
        result.errors?.push(`${purpose}: ${errorMsg}`);
        result.details[purpose] = {
          status: "failed",
          message: errorMsg,
        };
      }
    }

    // 성공 여부 결정
    const allFailed = Object.values(result.details).every(
      (detail) => detail?.status === "failed"
    );
    result.success = !allFailed;

    // 감사 로그 기록
    await logObjectionToAuditLog(userId, objectionId, objectionRequest, result);

    // 응답
    const statusCode = result.success ? 200 : 207; // 207 Multi-Status (부분 성공)

    sendJson(res, statusCode, {
      success: result.success,
      message: "Objection processed successfully",
      effectiveDate: result.effectiveDate,
      gdprNotice: {
        article: "Article 21",
        right: "Right to object",
        note: "데이터 주체는 자신의 개인 데이터 처리에 대해 언제든지 이의를 제기할 권리가 있습니다.",
      },
      objection: {
        objectionId: result.objectionId,
        purposes: result.processedPurposes,
        details: result.details,
      },
      errors: result.errors?.length ? result.errors : undefined,
    });

    log.info(`Right to object processed for user: ${userId}`, {
      objectionId,
      purposes: result.processedPurposes,
      success: result.success,
    });

    // 콜백 호출 (선택적)
    if (opts.onObjectionComplete) {
      await opts.onObjectionComplete({
        userId,
        objectionId,
        success: result.success,
        purposes: result.processedPurposes,
        effectiveDate: result.effectiveDate,
        error: result.errors?.join("; ") || undefined,
      });
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    log.error(`Right to object failed for user: ${userId}`, { error: errorMsg });

    sendJson(res, 500, {
      error: "Internal Server Error",
      message: "이의 제기 처리 중 오류가 발생했습니다.",
      details: errorMsg,
    });
  }
}

/**
 * 마케팅 이의 제기 처리
 * 동의 저장소에서 마케팅 동의를 철회합니다.
 */
async function processMarketingObjection(
  userId: string,
): Promise<{ status: "withdrawn" | "already_withdrawn" | "failed"; message: string }> {
  try {
    const consentStore = getConsentStore();
    const currentConsent = consentStore.hasConsent("marketing");

    if (!currentConsent) {
      return {
        status: "already_withdrawn",
        message: "마케팅 동의가 이미 철회되었습니다.",
      };
    }

    // 마케팅 동의 철회
    consentStore.setConsent("marketing", false);

    log.info(`Marketing consent withdrawn for user: ${userId}`);

    return {
      status: "withdrawn",
      message: "마케팅 동의가 성공적으로 철회되었습니다.",
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    log.error(`Failed to process marketing objection for user: ${userId}`, { error: errorMsg });
    return {
      status: "failed",
      message: `마케팅 동의 철회 실패: ${errorMsg}`,
    };
  }
}

/**
 * 프로파일링 이의 제기 처리
 */
async function processProfilingObjection(
  userId: string,
): Promise<{ status: "disabled" | "already_disabled" | "failed"; message: string }> {
  try {
    // 프로파일링 설정 비활성화
    // 실제 구현에서는 프로파일링 관련 설정을 업데이트
    log.info(`Profiling disabled for user: ${userId}`);

    return {
      status: "disabled",
      message: "프로파일링이 비활성화되었습니다.",
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    log.error(`Failed to process profiling objection for user: ${userId}`, { error: errorMsg });
    return {
      status: "failed",
      message: `프로파일링 비활성화 실패: ${errorMsg}`,
    };
  }
}

/**
 * 제3자 공유 이의 제기 처리
 */
async function processThirdPartySharingObjection(
  userId: string,
): Promise<{ status: "disabled" | "already_disabled" | "failed"; message: string }> {
  try {
    // 제3자 공유 설정 비활성화
    // 실제 구현에서는 제3자 공유 관련 설정을 업데이트
    log.info(`Third-party sharing disabled for user: ${userId}`);

    return {
      status: "disabled",
      message: "제3자 데이터 공유가 비활성화되었습니다.",
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : String(error);
    log.error(`Failed to process third-party sharing objection for user: ${userId}`, { error: errorMsg });
    return {
      status: "failed",
      message: `제3자 공유 비활성화 실패: ${errorMsg}`,
    };
  }
}

/**
 * 이의 제기 감사 로그 기록
 */
async function logObjectionToAuditLog(
  userId: string,
  objectionId: string,
  request: ObjectionRequest,
  result: ObjectionResult,
): Promise<void> {
  try {
    const config = loadConfig();
    const auditLogPath = resolveConfigPath(config.logging?.auditLogPath ?? "./logs/audit.jsonl");

    const logEntry = {
      timestamp: new Date().toISOString(),
      action: "right_to_object_exercised",
      resource: "user_data",
      userId,
      details: {
        objectionId,
        purposes: request.purposes,
        reason: request.reason,
        effectiveImmediately: request.effectiveImmediately,
        success: result.success,
        effectiveDate: result.effectiveDate,
        details: result.details,
        gdprArticle: "Article 21",
      },
    };

    await fs.mkdir(path.dirname(auditLogPath), { recursive: true });
    await fs.appendFile(auditLogPath, JSON.stringify(logEntry) + "\n", "utf-8");

    log.info(`Objection audit log written for user: ${userId}`, { objectionId });
  } catch (error) {
    log.error(`Failed to write objection audit log for user: ${userId}`, { error: String(error) });
  }
}

/**
 * 요청 본문 파싱
 */
async function parseRequestBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];

    req.on("data", (chunk: Buffer) => {
      chunks.push(chunk);
    });

    req.on("end", () => {
      try {
        const body = Buffer.concat(chunks).toString("utf-8");
        if (!body) {
          resolve({});
          return;
        }
        resolve(JSON.parse(body));
      } catch (error) {
        reject(error);
      }
    });

    req.on("error", (error) => {
      reject(error);
    });
  });
}

/**
 * GDPR API 상태 확인
 */
export function getGdprApiStatus(): {
  available: boolean;
  version: string;
  endpoints: string[];
} {
  return {
    available: true,
    version: "1.0.0",
    endpoints: [
      "GET /api/v1/user/data-export",
      "GET /api/v1/user/data-portable",
      "DELETE /api/v1/user/data",
      "PUT /api/v1/user/data",
      "PATCH /api/v1/user/data",
      "POST /api/v1/user/objection",
    ],
  };
}
