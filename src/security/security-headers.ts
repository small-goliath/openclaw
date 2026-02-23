/**
 * Security Headers Module
 *
 * HTTP 응답에 권장되는 보안 헤더를 적용합니다.
 * OWASP 보안 가이드라인 및 securityheaders.com 권장사항을 따릅니다.
 *
 * CSP는 nonce 기반으로 구현되어 'unsafe-inline'을 제거합니다.
 *
 * @module security/security-headers
 */

import type { Request, Response, NextFunction } from "express";
import type { ServerResponse } from "node:http";
import crypto from "node:crypto";

/**
 * HSTS (HTTP Strict Transport Security) 설정 옵션
 */
export interface HstsOptions {
  /** max-age 값 (초). 기본값: 31536000 (1년) */
  maxAge?: number;
  /** includeSubDomains 지시문 포함 여부. 기본값: true */
  includeSubDomains?: boolean;
  /** preload 지시문 포함 여부. 기본값: false */
  preload?: boolean;
}

/**
 * 보안 헤더 설정 옵션
 */
export interface SecurityHeadersOptions {
  /** HTTPS 사용 여부 (HSTS 헤더 적용 결정) */
  secure?: boolean;
  /** CSP 정책 커스터마이징 (nonce 기반 CSP 사용 시 무시됨) */
  contentSecurityPolicy?: string;
  /** Permissions-Policy 커스터마이징 */
  permissionsPolicy?: string;
  /** HSTS 설정 */
  hsts?: HstsOptions;
  /** nonce 기반 CSP 사용 여부. 기본값: true */
  useNonce?: boolean;
  /** 고정 nonce 값 (테스트용). 제공되지 않으면 랜덤 생성 */
  nonce?: string;
}

/**
 * CSP (Content Security Policy) 설정 옵션
 */
export interface CspOptions {
  /** nonce 값 */
  nonce: string;
  /** WebSocket 연결 허용 여부. 기본값: true */
  allowWebSocket?: boolean;
  /** 외부 이미지 소스 허용 여부. 기본값: true */
  allowExternalImages?: boolean;
}

/**
 * 기본 보안 헤더 값 (CSP 제외)
 */
const DEFAULT_SECURITY_HEADERS = {
  // MIME 스니핑 방지
  "X-Content-Type-Options": "nosniff",

  // 클릭재킹 방지
  "X-Frame-Options": "DENY",

  // XSS 필터 활성화
  "X-XSS-Protection": "1; mode=block",

  // Referrer 정책: 크로스 오리진 시 origin만 전송
  "Referrer-Policy": "strict-origin-when-cross-origin",

  // 기능 권한 제한
  "Permissions-Policy":
    "camera=(), " +
    "microphone=(), " +
    "geolocation=(), " +
    "payment=(), " +
    "usb=(), " +
    "magnetometer=(), " +
    "gyroscope=(), " +
    "accelerometer=(), " +
    "ambient-light-sensor=(), " +
    "autoplay=(), " +
    "battery=(), " +
    "display-capture=(), " +
    "document-domain=(), " +
    "encrypted-media=(), " +
    "fullscreen=(), " +
    "gamepad=(), " +
    "hid=(), " +
    "idle-detection=(), " +
    "local-fonts=(), " +
    "midi=(), " +
    "navigation-override=(), " +
    "picture-in-picture=(), " +
    "publickey-credentials-create=(), " +
    "publickey-credentials-get=(), " +
    "screen-wake-lock=(), " +
    "serial=(), " +
    "speaker-selection=(), " +
    "storage-access=(), " +
    "web-share=(), " +
    "xr-spatial-tracking=()",
};

/**
 * nonce 값을 생성합니다.
 *
 * @returns Base64로 인코딩된 16바이트 랜덤 nonce 문자열
 *
 * @example
 * ```typescript
 * const nonce = generateNonce(); // "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
 * ```
 */
export function generateNonce(): string {
  return crypto.randomBytes(16).toString("base64");
}

/**
 * nonce 기반 CSP (Content Security Policy) 헤더 값을 생성합니다.
 * 'unsafe-inline'을 제거하고 nonce 기반으로 대체합니다.
 *
 * @param nonce - CSP nonce 값
 * @param options - CSP 추가 옵션
 * @returns CSP 헤더 값 문자열
 *
 * @example
 * ```typescript
 * const nonce = generateNonce();
 * const csp = buildCspHeader(nonce);
 * // "default-src 'self'; script-src 'self' 'nonce-abc123...'; ..."
 * ```
 */
export function buildCspHeader(
  nonce: string,
  options: { allowWebSocket?: boolean; allowExternalImages?: boolean } = {},
): string {
  const { allowWebSocket = true, allowExternalImages = true } = options;

  const policy: Record<string, string[]> = {
    "default-src": ["'self'"],
    // 'unsafe-inline' 제거, nonce 기반으로 변경
    "script-src": ["'self'", `'nonce-${nonce}'`],
    "style-src": ["'self'", `'nonce-${nonce}'`],
    "img-src": allowExternalImages ? ["'self'", "data:", "https:"] : ["'self'", "data:"],
    "connect-src": allowWebSocket ? ["'self'", "ws:", "wss:"] : ["'self'"],
    "font-src": ["'self'"],
    "object-src": ["'none'"],
    "frame-ancestors": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
  };

  return Object.entries(policy)
    .map(([key, values]) => `${key} ${values.join(" ")}`)
    .join("; ");
}

/**
 * HSTS (HTTP Strict Transport Security) 헤더 이름
 */
const HSTS_HEADER = "Strict-Transport-Security";

/**
 * HSTS 헤더 값을 생성합니다.
 *
 * @param options - HSTS 설정 옵션
 * @returns HSTS 헤더 값 문자열
 *
 * @example
 * ```typescript
 * const hstsValue = buildHstsHeader({ maxAge: 31536000, includeSubDomains: true, preload: true });
 * // "max-age=31536000; includeSubDomains; preload"
 * ```
 */
export function buildHstsHeader(options: HstsOptions = {}): string {
  const maxAge = options.maxAge ?? 31536000; // 1 year default
  const includeSubDomains = options.includeSubDomains !== false; // true by default
  const preload = options.preload === true; // false by default

  let headerValue = `max-age=${maxAge}`;
  if (includeSubDomains) {
    headerValue += "; includeSubDomains";
  }
  if (preload) {
    headerValue += "; preload";
  }

  return headerValue;
}

/**
 * 보안 헤더를 ServerResponse에 적용합니다.
 *
 * CSP는 기본적으로 nonce 기반으로 생성됩니다.
 * 'unsafe-inline'이 제거되고 nonce를 통해서만 inline script/style이 허용됩니다.
 *
 * @param res - Node.js ServerResponse 객체
 * @param options - 보안 헤더 옵션
 * @returns 적용된 nonce 값 (CSP에 사용됨)
 *
 * @example
 * ```typescript
 * import { applySecurityHeaders } from "./security-headers.js";
 *
 * const server = createServer((req, res) => {
 *   const nonce = applySecurityHeaders(res, { secure: true });
 *   // nonce를 HTML의 inline script/style에 적용
 *   res.end(`<script nonce="${nonce}">console.log('safe');</script>`);
 * });
 * ```
 */
export function applySecurityHeaders(
  res: ServerResponse,
  options: SecurityHeadersOptions = {},
): string {
  const {
    secure = false,
    contentSecurityPolicy,
    permissionsPolicy,
    hsts,
    useNonce = true,
    nonce: providedNonce,
  } = options;

  // nonce 생성 또는 사용
  const nonce = useNonce ? providedNonce || generateNonce() : "";

  // 기본 보안 헤더 설정
  for (const [header, value] of Object.entries(DEFAULT_SECURITY_HEADERS)) {
    if (header === "Permissions-Policy" && permissionsPolicy) {
      res.setHeader(header, permissionsPolicy);
    } else {
      res.setHeader(header, value);
    }
  }

  // CSP 헤더 설정 (nonce 기반 또는 커스터마이징)
  if (contentSecurityPolicy) {
    res.setHeader("Content-Security-Policy", contentSecurityPolicy);
  } else if (useNonce) {
    res.setHeader("Content-Security-Policy", buildCspHeader(nonce));
  }

  // HTTPS 사용시 HSTS 헤더 추가
  if (secure) {
    res.setHeader(HSTS_HEADER, buildHstsHeader(hsts));
  }

  return nonce;
}

/**
 * 보안 헤더 객체를 반환합니다.
 * 테스트나 로깅에 유용합니다.
 *
 * @param options - 보안 헤더 옵션
 * @returns 보안 헤더 객체와 nonce 값
 *
 * @example
 * ```typescript
 * const { headers, nonce } = getSecurityHeaders({ secure: true });
 * console.log(headers);
 * console.log(nonce); // CSP에 사용된 nonce
 * ```
 */
export function getSecurityHeaders(options: SecurityHeadersOptions = {}): {
  headers: Record<string, string>;
  nonce: string;
} {
  const {
    secure = false,
    contentSecurityPolicy,
    permissionsPolicy,
    hsts,
    useNonce = true,
    nonce: providedNonce,
  } = options;

  const nonce = useNonce ? providedNonce || generateNonce() : "";
  const headers: Record<string, string> = {};

  for (const [header, value] of Object.entries(DEFAULT_SECURITY_HEADERS)) {
    if (header === "Permissions-Policy" && permissionsPolicy) {
      headers[header] = permissionsPolicy;
    } else {
      headers[header] = value;
    }
  }

  // CSP 헤더 설정 (nonce 기반 또는 커스터마이징)
  if (contentSecurityPolicy) {
    headers["Content-Security-Policy"] = contentSecurityPolicy;
  } else if (useNonce) {
    headers["Content-Security-Policy"] = buildCspHeader(nonce);
  }

  if (secure) {
    headers[HSTS_HEADER] = buildHstsHeader(hsts);
  }

  return { headers, nonce };
}

/**
 * Express 미들웨어로 보안 헤더를 적용합니다.
 *
 * CSP nonce는 res.locals.cspNonce에 저장되어
 * 템플릿 엔진에서 접근할 수 있습니다.
 *
 * @param options - 보안 헤더 옵션
 * @returns Express 미들웨어 함수
 *
 * @example
 * ```typescript
 * import express from "express";
 * import { securityHeadersMiddleware } from "./security-headers.js";
 *
 * const app = express();
 * app.use(securityHeadersMiddleware({ secure: true }));
 *
 * // 템플릿에서 nonce 사용
 * // <script nonce="<%= cspNonce %>">...</script>
 * ```
 */
export function securityHeadersMiddleware(
  options: SecurityHeadersOptions = {},
): (req: Request, res: Response, next: NextFunction) => void {
  return (req: Request, res: Response, next: NextFunction) => {
    const nonce = applySecurityHeaders(res as unknown as ServerResponse, options);

    // nonce를 res.locals에 저장하여 템플릿에서 사용 가능하도록 함
    if (!res.locals) {
      res.locals = {};
    }
    res.locals.cspNonce = nonce;

    next();
  };
}

/**
 * HSTS (HTTP Strict Transport Security) 미들웨어
 *
 * HTTPS 연결에만 HSTS 헤더를 설정합니다.
 * 프록시 뒤에서 실행될 때 x-forwarded-proto 헤더도 확인합니다.
 *
 * @param options - HSTS 설정 옵션
 * @returns Express 미들웨어 함수
 *
 * @example
 * ```typescript
 * import express from "express";
 * import { hstsMiddleware } from "./security-headers.js";
 *
 * const app = express();
 * app.use(hstsMiddleware({ maxAge: 31536000, includeSubDomains: true, preload: true }));
 * ```
 */
export function hstsMiddleware(
  options: HstsOptions = {},
): (req: Request, res: Response, next: NextFunction) => void {
  const headerValue = buildHstsHeader(options);

  return (req: Request, res: Response, next: NextFunction) => {
    // Check if connection is secure (direct HTTPS or behind proxy)
    const isSecure =
      req.secure || (req.headers["x-forwarded-proto"] as string)?.toLowerCase() === "https";

    if (isSecure) {
      res.setHeader(HSTS_HEADER, headerValue);
    }

    next();
  };
}

/**
 * CSP (Content Security Policy) 미들웨어
 *
 * 요청마다 고유한 nonce를 생성하여 CSP 헤더를 설정합니다.
 * 'unsafe-inline'을 제거하고 nonce 기반으로 대체하여 XSS 공격을 방지합니다.
 *
 * nonce는 res.locals.cspNonce에 저장되어 템플릿 엔진에서 접근할 수 있습니다.
 * HTML의 inline script/style에는 반드시 nonce 속성을 추가해야 합니다.
 *
 * @param options - CSP 옵션 (nonce 값을 직접 제공하거나 추가 옵션 설정)
 * @returns Express 미들웨어 함수
 *
 * @example
 * ```typescript
 * import express from "express";
 * import { cspMiddleware } from "./security-headers.js";
 *
 * const app = express();
 * app.use(cspMiddleware());
 *
 * // 템플릿에서 nonce 사용
 * // <script nonce="<%= cspNonce %>">console.log('safe');</script>
 * // <style nonce="<%= cspNonce %>">.class { color: red; }</style>
 * ```
 */
export function cspMiddleware(
  options: { nonce?: string; allowWebSocket?: boolean; allowExternalImages?: boolean } = {},
): (req: Request, res: Response, next: NextFunction) => void {
  return (req: Request, res: Response, next: NextFunction) => {
    // nonce 생성 (제공된 nonce 또는 새로 생성)
    const nonce = options.nonce || generateNonce();

    // CSP 헤더 생성 및 설정
    const cspString = buildCspHeader(nonce, {
      allowWebSocket: options.allowWebSocket,
      allowExternalImages: options.allowExternalImages,
    });

    res.setHeader("Content-Security-Policy", cspString);

    // nonce를 res.locals에 저장하여 템플릿에서 사용 가능하도록 함
    if (!res.locals) {
      res.locals = {};
    }
    res.locals.cspNonce = nonce;

    next();
  };
}
