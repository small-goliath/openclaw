/**
 * 안전한 JSON 파싱 유틸리티
 * 깊이 제한 및 DoS 방지 기능 제공
 */

/**
 * JSON 파싱 에러 클래스
 */
export class JsonParseError extends Error {
  constructor(
    message: string,
    public readonly cause?: string,
    public readonly depth?: number,
  ) {
    super(message);
    this.name = "JsonParseError";
  }
}

/**
 * 안전한 JSON 파싱 함수
 * @param text 파싱할 JSON 문자열
 * @param maxDepth 최대 중첩 깊이 (기본값: 100)
 * @returns 파싱된 객체
 * @throws JsonParseError 깊이 제한 초과 또는 파싱 오류 시
 */
export function safeJsonParse(text: string, maxDepth: number = 100): unknown {
  // 입력 길이 검증 (100MB 제한)
  const MAX_LENGTH = 100 * 1024 * 1024; // 100MB
  if (text.length > MAX_LENGTH) {
    throw new JsonParseError(
      `JSON payload exceeds maximum length of ${MAX_LENGTH} bytes`,
      "payload_too_large",
    );
  }

  let currentDepth = 0;
  const depthStack: number[] = [];

  try {
    return JSON.parse(text, (_key: string, value: unknown) => {
      if (typeof value === "object" && value !== null) {
        currentDepth++;
        if (currentDepth > maxDepth) {
          throw new JsonParseError(
            `JSON depth limit exceeded: ${maxDepth}`,
            "depth_limit_exceeded",
            currentDepth,
          );
        }
        depthStack.push(currentDepth);
      }

      // 값 처리 후 스택 복원
      if (typeof value === "object" && value !== null && depthStack.length > 0) {
        depthStack.pop();
        currentDepth = depthStack.length > 0 ? depthStack[depthStack.length - 1] : 0;
      }

      return value;
    });
  } catch (err) {
    if (err instanceof JsonParseError) {
      throw err;
    }
    // 기본 JSON 파싱 에러를 JsonParseError로 래핑
    throw new JsonParseError(
      err instanceof Error ? err.message : "JSON parse error",
      "parse_error",
    );
  }
}

/**
 * JSON 문자열의 깊이를 계산 (검증용)
 * @param obj 검증할 객체
 * @param maxDepth 최대 허용 깊이
 * @returns { valid: boolean; depth: number }
 */
export function validateJsonDepth(
  obj: unknown,
  maxDepth: number = 100,
): { valid: boolean; depth: number } {
  function getDepth(value: unknown, currentDepth: number): number {
    if (currentDepth > maxDepth) {
      return currentDepth;
    }

    if (typeof value !== "object" || value === null) {
      return currentDepth;
    }

    if (Array.isArray(value)) {
      let maxChildDepth = currentDepth;
      for (const item of value) {
        const childDepth = getDepth(item, currentDepth + 1);
        maxChildDepth = Math.max(maxChildDepth, childDepth);
        if (maxChildDepth > maxDepth) {
          return maxChildDepth;
        }
      }
      return maxChildDepth;
    }

    let maxChildDepth = currentDepth;
    for (const key of Object.keys(value)) {
      const childDepth = getDepth((value as Record<string, unknown>)[key], currentDepth + 1);
      maxChildDepth = Math.max(maxChildDepth, childDepth);
      if (maxChildDepth > maxDepth) {
        return maxChildDepth;
      }
    }
    return maxChildDepth;
  }

  const depth = getDepth(obj, 1);
  return { valid: depth <= maxDepth, depth };
}
