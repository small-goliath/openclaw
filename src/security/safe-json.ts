/**
 * 안전한 JSON 파싱 구현
 * OWASP A08:2021 프로토타입 오염 방지
 * Zod 스키마 검증 및 Object.create(null) 사용
 */

import { z } from "zod";
import { createSubsystemLogger } from "../logging/subsystem.js";

const log = createSubsystemLogger("security/safe-json");

/**
 * 프로토타입 오염 감지 결과
 */
export interface PrototypePollutionCheck {
  safe: boolean;
  detectedKeys: string[];
}

/**
 * 위험한 키 목록 (프로토타입 오염에 사용될 수 있는)
 */
const DANGEROUS_KEYS = new Set([
  "__proto__",
  "constructor",
  "prototype",
  "__defineGetter__",
  "__defineSetter__",
  "__lookupGetter__",
  "__lookupSetter__",
]);

/**
 * 객체에 프로토타입 오염 시도가 있는지 확인
 */
export function detectPrototypePollution(obj: unknown): PrototypePollutionCheck {
  const detectedKeys: string[] = [];

  function check(value: unknown, path: string = ""): void {
    if (value === null || typeof value !== "object") {
      return;
    }

    if (Array.isArray(value)) {
      for (let i = 0; i < value.length; i++) {
        check(value[i], `${path}[${i}]`);
      }
      return;
    }

    for (const key of Object.keys(value)) {
      if (DANGEROUS_KEYS.has(key)) {
        detectedKeys.push(path ? `${path}.${key}` : key);
      }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      check((value as Record<string, unknown>)[key], path ? `${path}.${key}` : key);
    }
  }

  check(obj);

  return {
    safe: detectedKeys.length === 0,
    detectedKeys,
  };
}

/**
 * 프로토타입이 없는 객체 생성
 */
export function createNullObject<T extends Record<string, unknown>>(
  obj: T,
): Record<string, unknown> {
  const nullObj = Object.create(null);
  for (const key of Object.keys(obj)) {
    nullObj[key] = obj[key];
  }
  return nullObj;
}

/**
 * 안전한 JSON 파싱 결과
 */
export interface SafeJsonParseResult<T> {
  success: boolean;
  data?: T;
  error?: string;
  pollutionDetected?: boolean;
}

/**
 * 안전한 JSON 파싱 (프로토타입 오염 방지)
 */
export function safeJsonParse<T>(
  json: string,
  options: {
    schema?: z.ZodSchema<T>;
    allowPrototypePollution?: boolean;
    useNullPrototype?: boolean;
  } = {},
): SafeJsonParseResult<T> {
  const { schema, allowPrototypePollution = false, useNullPrototype = true } = options;

  try {
    // JSON 파싱
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch (parseError) {
      return {
        success: false,
        error: `Invalid JSON: ${parseError instanceof Error ? parseError.message : String(parseError)}`,
      };
    }

    // 프로토타입 오염 검사
    if (!allowPrototypePollution) {
      const pollutionCheck = detectPrototypePollution(parsed);
      if (!pollutionCheck.safe) {
        log.warn("Prototype pollution detected in JSON", {
          keys: pollutionCheck.detectedKeys,
        });
        return {
          success: false,
          error: `Prototype pollution detected: ${pollutionCheck.detectedKeys.join(", ")}`,
          pollutionDetected: true,
        };
      }
    }

    // 프로토타입 없는 객체로 변환
    if (useNullPrototype && parsed !== null && typeof parsed === "object") {
      if (Array.isArray(parsed)) {
        parsed = parsed.map((item) =>
          typeof item === "object" && item !== null
            ? createNullObject(item as Record<string, unknown>)
            : item,
        );
      } else {
        parsed = createNullObject(parsed as Record<string, unknown>);
      }
    }

    // 스키마 검증
    if (schema) {
      const result = schema.safeParse(parsed);
      if (!result.success) {
        return {
          success: false,
          error: `Schema validation failed: ${result.error.message}`,
        };
      }
      return {
        success: true,
        data: result.data,
      };
    }

    return {
      success: true,
      data: parsed as T,
    };
  } catch (error) {
    return {
      success: false,
      error: `Unexpected error: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * 안전한 JSON 파싱 (비동기, 스키마 검증 포함)
 */
export async function safeJsonParseAsync<T>(
  json: string,
  options: {
    schema?: z.ZodSchema<T>;
    allowPrototypePollution?: boolean;
    useNullPrototype?: boolean;
    transform?: (data: unknown) => Promise<T> | T;
  } = {},
): Promise<SafeJsonParseResult<T>> {
  const { transform, ...parseOptions } = options;

  const result = safeJsonParse<T>(json, parseOptions);

  if (!result.success || !transform) {
    return result;
  }

  try {
    const transformed = await transform(result.data as unknown);
    return {
      success: true,
      data: transformed,
    };
  } catch (error) {
    return {
      success: false,
      error: `Transform failed: ${error instanceof Error ? error.message : String(error)}`,
    };
  }
}

/**
 * 안전한 JSON 직렬화
 */
export function safeJsonStringify(
  obj: unknown,
  options: {
    space?: number;
    stripPrototypePollution?: boolean;
  } = {},
): string {
  const { space, stripPrototypePollution = true } = options;

  if (!stripPrototypePollution) {
    return JSON.stringify(obj, null, space);
  }

  // 위험한 키 제거
  function sanitize(value: unknown): unknown {
    if (value === null || typeof value !== "object") {
      return value;
    }

    if (Array.isArray(value)) {
      return value.map(sanitize);
    }

    const sanitized: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value)) {
      if (!DANGEROUS_KEYS.has(key)) {
        sanitized[key] = sanitize(val);
      }
    }
    return sanitized;
  }

  return JSON.stringify(sanitize(obj), null, space);
}

/**
 * 기본 스키마 정의
 */
export const SafeJsonSchemas = {
  // 문자열 객체
  stringRecord: z.record(z.string()),

  // 문자열 배열
  stringArray: z.array(z.string()),

  // 기본 객체 (모든 값 허용)
  anyObject: z.record(z.unknown()),

  // 안전한 키만 가진 객체
  safeKeyRecord: z.record(
    z.string().refine((key) => !DANGEROUS_KEYS.has(key), {
      message: "Dangerous key detected",
    }),
    z.unknown(),
  ),
};

/**
 * JSON.parse() 직접 사용 방지를 위한 ESLint 규칙 주석
 * @deprecated safeJsonParse를 사용하세요
 */
export function unsafeJsonParse<T>(json: string): T {
  log.warn("Unsafe JSON.parse() called. Use safeJsonParse() instead.");
  return JSON.parse(json) as T;
}
