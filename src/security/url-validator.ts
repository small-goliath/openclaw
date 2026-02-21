/**
 * URL 유효성 검사 및 SSRF 방지
 * Server-Side Request Forgery 공격 방지를 위한 URL 검증
 */

import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("security/url-validator");

/**
 * URL 검증 결과
 */
export interface UrlValidationResult {
  valid: boolean;
  error?: string;
  blockedReason?: "private_ip" | "internal_host" | "invalid_scheme" | "dns_rebinding" | "localhost";
  sanitizedUrl?: string;
}

/**
 * URL 검증 옵션
 */
export interface UrlValidationOptions {
  allowedSchemes?: string[];
  blockPrivateIPs?: boolean;
  blockLocalhost?: boolean;
  allowedHosts?: string[];
  blockedHosts?: string[];
  maxRedirects?: number;
  requireExplicitPort?: boolean;
}

const DEFAULT_OPTIONS: UrlValidationOptions = {
  allowedSchemes: ["http", "https"],
  blockPrivateIPs: true,
  blockLocalhost: true,
  maxRedirects: 5,
  requireExplicitPort: false,
};

/**
 * 낸부 IP 범위 (CIDR)
 */
const PRIVATE_IP_RANGES = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "127.0.0.0/8",
  "169.254.0.0/16", // Link-local
  "0.0.0.0/8",
  "::1/128", // IPv6 localhost
  "fc00::/7", // IPv6 private
  "fe80::/10", // IPv6 link-local
];

/**
 * IP 주소를 정수로 변환
 */
function ipToLong(ip: string): number {
  const parts = ip.split(".");
  return (
    (parseInt(parts[0], 10) << 24) +
    (parseInt(parts[1], 10) << 16) +
    (parseInt(parts[2], 10) << 8) +
    parseInt(parts[3], 10)
  );
}

/**
 * CIDR 범위 내에 IP가 있는지 확인
 */
function isIpInCidr(ip: string, cidr: string): boolean {
  const [rangeIp, prefix] = cidr.split("/");
  const prefixLength = parseInt(prefix, 10);
  const ipLong = ipToLong(ip);
  const rangeLong = ipToLong(rangeIp);
  const mask = -1 << (32 - prefixLength);
  return (ipLong & mask) === (rangeLong & mask);
}

/**
 * IP 주소가 낸부 IP인지 확인
 */
function isPrivateIP(ip: string): boolean {
  // IPv6 체크
  if (ip.includes(":")) {
    return (
      ip === "::1" ||
      ip.startsWith("fc") ||
      ip.startsWith("fd") ||
      ip.startsWith("fe80:")
    );
  }

  // IPv4 체크
  for (const range of PRIVATE_IP_RANGES) {
    if (range.includes(":")) continue; // IPv6 범위 스킵
    try {
      if (isIpInCidr(ip, range)) {
        return true;
      }
    } catch {
      continue;
    }
  }
  return false;
}

/**
 * 호스트가 localhost인지 확인
 */
function isLocalhost(host: string): boolean {
  const localhostNames = ["localhost", "127.0.0.1", "::1", "0.0.0.0"];
  return localhostNames.includes(host.toLowerCase());
}

/**
 * DNS 재바인딩 공격 방지를 위한 DNS 확인
 */
async function resolveDNS(hostname: string): Promise<string[]> {
  try {
    // Node.js dns 모듈을 동적으로 임포트
    const { lookup } = await import("node:dns/promises");
    const addresses = await lookup(hostname, { all: true });
    return addresses.map((a) => a.address);
  } catch {
    return [];
  }
}

/**
 * URL 검증 메인 함수
 */
export async function validateUrl(
  urlString: string,
  options: UrlValidationOptions = {}
): Promise<UrlValidationResult> {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  try {
    // URL 파싱
    const url = new URL(urlString);

    // 스킴 검증
    if (
      opts.allowedSchemes &&
      !opts.allowedSchemes.includes(url.protocol.replace(":", ""))
    ) {
      return {
        valid: false,
        error: `Scheme '${url.protocol}' is not allowed`,
        blockedReason: "invalid_scheme",
      };
    }

    // 호스트 추출
    const hostname = url.hostname.toLowerCase();

    // localhost 차단
    if (opts.blockLocalhost && isLocalhost(hostname)) {
      log.warn("Blocked localhost URL", { url: urlString });
      return {
        valid: false,
        error: "Localhost URLs are not allowed",
        blockedReason: "localhost",
      };
    }

    // 허용된 호스트 목록 체크
    if (opts.allowedHosts && opts.allowedHosts.length > 0) {
      const isAllowed = opts.allowedHosts.some(
        (allowed) => hostname === allowed.toLowerCase() || hostname.endsWith(`.${allowed.toLowerCase()}`)
      );
      if (!isAllowed) {
        return {
          valid: false,
          error: `Host '${hostname}' is not in the allowed list`,
        };
      }
    }

    // 차단된 호스트 목록 체크
    if (opts.blockedHosts) {
      const isBlocked = opts.blockedHosts.some(
        (blocked) => hostname === blocked.toLowerCase() || hostname.endsWith(`.${blocked.toLowerCase()}`)
      );
      if (isBlocked) {
        return {
          valid: false,
          error: `Host '${hostname}' is blocked`,
          blockedReason: "internal_host",
        };
      }
    }

    // IP 주소 직접 사용 차단
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(hostname)) {
      if (opts.blockPrivateIPs && isPrivateIP(hostname)) {
        log.warn("Blocked private IP URL", { url: urlString, ip: hostname });
        return {
          valid: false,
          error: "Private IP addresses are not allowed",
          blockedReason: "private_ip",
        };
      }
    }

    // DNS 재바인딩 방지: DNS 확인
    if (opts.blockPrivateIPs && !ipRegex.test(hostname)) {
      const resolvedIPs = await resolveDNS(hostname);
      for (const ip of resolvedIPs) {
        if (isPrivateIP(ip)) {
          log.warn("DNS rebinding attack detected", {
            url: urlString,
            hostname,
            resolvedIP: ip,
          });
          return {
            valid: false,
            error: "DNS resolution points to private IP",
            blockedReason: "dns_rebinding",
          };
        }
      }
    }

    // 정리된 URL 반환
    const sanitizedUrl = url.toString();

    return {
      valid: true,
      sanitizedUrl,
    };
  } catch (error) {
    return {
      valid: false,
      error: `Invalid URL: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * 동기 URL 검증 (DNS 확인 없이)
 */
export function validateUrlSync(
  urlString: string,
  options: UrlValidationOptions = {}
): UrlValidationResult {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  try {
    const url = new URL(urlString);

    // 스킴 검증
    if (
      opts.allowedSchemes &&
      !opts.allowedSchemes.includes(url.protocol.replace(":", ""))
    ) {
      return {
        valid: false,
        error: `Scheme '${url.protocol}' is not allowed`,
        blockedReason: "invalid_scheme",
      };
    }

    const hostname = url.hostname.toLowerCase();

    // localhost 차단
    if (opts.blockLocalhost && isLocalhost(hostname)) {
      return {
        valid: false,
        error: "Localhost URLs are not allowed",
        blockedReason: "localhost",
      };
    }

    // IP 주소 직접 사용 차단
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipRegex.test(hostname) && opts.blockPrivateIPs && isPrivateIP(hostname)) {
      return {
        valid: false,
        error: "Private IP addresses are not allowed",
        blockedReason: "private_ip",
      };
    }

    return {
      valid: true,
      sanitizedUrl: url.toString(),
    };
  } catch (error) {
    return {
      valid: false,
      error: `Invalid URL: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * URL 인코딩 검증
 */
export function validateUrlEncoding(urlString: string): UrlValidationResult {
  try {
    // 이중 인코딩 체크
    const decoded = decodeURIComponent(urlString);
    if (decoded !== urlString) {
      try {
        const doubleDecoded = decodeURIComponent(decoded);
        if (doubleDecoded !== decoded) {
          return {
            valid: false,
            error: "Double URL encoding detected",
          };
        }
      } catch {
        // 이중 디코딩 실패는 정상
      }
    }

    // 위험한 문자 체크
    const dangerousChars = ["\x00", "\x0a", "\x0d", "..", "../", "..\\"];
    for (const char of dangerousChars) {
      if (urlString.includes(char)) {
        return {
          valid: false,
          error: `Dangerous character detected: ${JSON.stringify(char)}`,
        };
      }
    }

    return { valid: true };
  } catch (error) {
    return {
      valid: false,
      error: `URL encoding validation failed: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * HTTP 요청 전 URL 검증 래퍼
 */
export async function safeFetch(
  url: string,
  init?: RequestInit,
  validationOptions?: UrlValidationOptions
): Promise<Response> {
  // URL 검증
  const validation = await validateUrl(url, validationOptions);
  if (!validation.valid) {
    throw new Error(`URL validation failed: ${validation.error}`);
  }

  // 인코딩 검증
  const encodingValidation = validateUrlEncoding(url);
  if (!encodingValidation.valid) {
    throw new Error(`URL encoding validation failed: ${encodingValidation.error}`);
  }

  // 실제 요청
  const targetUrl = validation.sanitizedUrl || url;
  return fetch(targetUrl, init);
}

/**
 * 프록시 설정을 위한 URL 검증
 */
export function validateProxyUrl(urlString: string): UrlValidationResult {
  return validateUrlSync(urlString, {
    allowedSchemes: ["http", "https", "socks4", "socks5"],
    blockPrivateIPs: false, // 프록시는 낸부 IP 허용할 수 있음
    blockLocalhost: false,
  });
}

/**
 * 웹훅 URL 검증
 */
export function validateWebhookUrl(urlString: string): UrlValidationResult {
  return validateUrlSync(urlString, {
    allowedSchemes: ["https"], // 웹훅은 HTTPS만 허용
    blockPrivateIPs: true,
    blockLocalhost: true,
  });
}
