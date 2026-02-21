/**
 * Brotli Compression Utility
 *
 * 정적 에셋에 대한 Brotli 압축 지원
 * 성능 최적화를 위해 pre-compressed 파일 제공
 *
 * @module infra/compression/brotli-compression
 */

import type { ServerResponse, IncomingMessage } from "node:http";
import { createReadStream, existsSync, statSync } from "node:fs";
import { open } from "node:fs/promises";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createBrotliCompress, constants } from "node:zlib";
import { createSubsystemLogger } from "../../logging/subsystem.js";

const log = createSubsystemLogger("compression");

/**
 * Brotli 압축 옵션
 */
export interface BrotliOptions {
  /** 압축 레벨 (0-11, 기본: 4) */
  quality?: number;
  /** 모드 (0=일반, 1=텍스트, 2=Font) */
  mode?: number;
  /** 슬라이딩 윈도우 크기 (10-24, 기본: 22) */
  sizeHint?: number;
}

/**
 * Brotli 압축 설정
 */
export interface BrotliCompressionConfig {
  /** Brotli 압축 활성화 여부 */
  enabled: boolean;
  /** pre-compressed 파일 확장자 */
  extension: string;
  /** 압축할 MIME 타입 */
  mimeTypes: string[];
  /** 최소 압축 크기 (바이트) */
  minSize: number;
  /** 최대 압축 크기 (바이트) */
  maxSize: number;
  /** 압축 옵션 */
  options: BrotliOptions;
}

/**
 * 환경 변수에서 Brotli 설정 로드
 */
export function resolveBrotliConfig(): BrotliCompressionConfig {
  const enabled = process.env.OPENCLAW_BROTLI_ENABLED?.trim().toLowerCase() !== "false";
  const quality = parseInt(process.env.OPENCLAW_BROTLI_QUALITY?.trim() ?? "4", 10);
  const minSize = parseInt(process.env.OPENCLAW_BROTLI_MIN_SIZE?.trim() ?? "1024", 10);
  const maxSize = parseInt(process.env.OPENCLAW_BROTLI_MAX_SIZE?.trim() ?? "10485760", 10); // 10MB

  return {
    enabled,
    extension: ".br",
    mimeTypes: [
      "text/html",
      "text/css",
      "text/javascript",
      "application/javascript",
      "application/json",
      "application/xml",
      "text/xml",
      "text/plain",
      "image/svg+xml",
    ],
    minSize: Number.isFinite(minSize) ? minSize : 1024,
    maxSize: Number.isFinite(maxSize) ? maxSize : 10485760,
    options: {
      quality: Number.isFinite(quality) ? Math.max(0, Math.min(11, quality)) : 4,
      mode: constants.BROTLI_MODE_TEXT,
      sizeHint: 22,
    },
  };
}

/**
 * 클라이언트가 Brotli를 지원하는지 확인
 */
export function acceptsBrotli(req: IncomingMessage): boolean {
  const acceptEncoding = req.headers["accept-encoding"] || "";
  return acceptEncoding.includes("br");
}

/**
 * 파일을 Brotli로 압축
 * @param inputPath - 입력 파일 경로
 * @param outputPath - 출력 파일 경로 (기본: inputPath + ".br")
 */
export async function compressFile(
  inputPath: string,
  outputPath?: string,
  options?: BrotliOptions,
): Promise<{ success: boolean; size: number; compressedSize: number }> {
  const targetPath = outputPath || `${inputPath}.br`;
  const config = resolveBrotliConfig();

  try {
    const stats = statSync(inputPath);
    if (!stats.isFile()) {
      throw new Error("Not a file");
    }

    const inputSize = stats.size;

    // 최소/최대 크기 검사
    if (inputSize < config.minSize || inputSize > config.maxSize) {
      return {
        success: false,
        size: inputSize,
        compressedSize: 0,
      };
    }

    const brotliOptions = {
      [constants.BROTLI_PARAM_QUALITY]: options?.quality ?? config.options.quality,
      [constants.BROTLI_PARAM_MODE]: options?.mode ?? config.options.mode,
      [constants.BROTLI_PARAM_SIZE_HINT]: options?.sizeHint ?? inputSize,
    };

    const source = createReadStream(inputPath);
    const compressor = createBrotliCompress({ params: brotliOptions });

    const outputHandle = await open(targetPath, "w");
    try {
      const destination = outputHandle.createWriteStream();
      await pipeline(source, compressor, destination);
    } finally {
      await outputHandle.close();
    }

    const compressedStats = statSync(targetPath);
    const compressedSize = compressedStats.size;

    log.debug(
      `Brotli compressed: ${inputPath} (${inputSize} → ${compressedSize} bytes, ${(
        (1 - compressedSize / inputSize) *
        100
      ).toFixed(1)}% reduction)`,
    );

    return {
      success: true,
      size: inputSize,
      compressedSize,
    };
  } catch (err) {
    log.warn(`Brotli compression failed for ${inputPath}: ${String(err)}`);
    return {
      success: false,
      size: 0,
      compressedSize: 0,
    };
  }
}

/**
 * Brotli로 압축된 파일이 존재하는지 확인하고 경로 반환
 */
export function findPrecompressedFile(filePath: string): string | null {
  const brotliPath = `${filePath}.br`;
  if (existsSync(brotliPath)) {
    return brotliPath;
  }
  return null;
}

/**
 * HTTP 응답에 Brotli 압축 적용
 * @returns 압축이 적용되었으면 true, 아니면 false
 */
export async function serveBrotliCompressed(
  req: IncomingMessage,
  res: ServerResponse,
  filePath: string,
  mimeType: string,
): Promise<boolean> {
  const config = resolveBrotliConfig();

  if (!config.enabled) {
    return false;
  }

  // 클라이언트가 Brotli를 지원하는지 확인
  if (!acceptsBrotli(req)) {
    return false;
  }

  // MIME 타입이 압축 대상인지 확인
  if (!config.mimeTypes.includes(mimeType)) {
    return false;
  }

  // pre-compressed 파일 확인
  const precompressedPath = findPrecompressedFile(filePath);
  if (!precompressedPath) {
    return false;
  }

  try {
    const handle = await open(precompressedPath, "r");
    const stats = await handle.stat();

    if (!stats.isFile()) {
      await handle.close();
      return false;
    }

    // 응답 헤더 설정
    res.setHeader("Content-Encoding", "br");
    res.setHeader("Content-Type", mimeType);
    res.setHeader("Content-Length", stats.size.toString());
    res.setHeader("Vary", "Accept-Encoding");

    // 캐시 헤더 (선택적)
    res.setHeader("Cache-Control", "public, max-age=31536000, immutable");

    // 파일 스트리밍
    const stream = handle.createReadStream();
    await pipeline(stream, res);

    log.debug(`Served Brotli compressed: ${precompressedPath} (${stats.size} bytes)`);
    return true;
  } catch (err) {
    log.warn(`Failed to serve Brotli compressed file ${precompressedPath}: ${String(err)}`);
    return false;
  }
}

/**
 * 동적으로 Brotli 압축하여 응답 (on-the-fly compression)
 * CPU 사용량이 높으므로 작은 파일에만 사용 권장
 */
export async function compressAndServe(
  req: IncomingMessage,
  res: ServerResponse,
  data: Buffer | string,
  mimeType: string,
): Promise<void> {
  const config = resolveBrotliConfig();

  if (!config.enabled || !acceptsBrotli(req)) {
    res.setHeader("Content-Type", mimeType);
    res.end(data);
    return;
  }

  const buffer = Buffer.isBuffer(data) ? data : Buffer.from(data, "utf-8");

  // 크기 검사
  if (buffer.length < config.minSize || buffer.length > config.maxSize) {
    res.setHeader("Content-Type", mimeType);
    res.end(buffer);
    return;
  }

  try {
    const brotliOptions = {
      [constants.BROTLI_PARAM_QUALITY]: config.options.quality,
      [constants.BROTLI_PARAM_MODE]: config.options.mode,
      [constants.BROTLI_PARAM_SIZE_HINT]: buffer.length,
    };

    const compressor = createBrotliCompress({ params: brotliOptions });
    const source = Readable.from([buffer]);

    res.setHeader("Content-Encoding", "br");
    res.setHeader("Content-Type", mimeType);
    res.setHeader("Vary", "Accept-Encoding");

    await pipeline(source, compressor, res);
  } catch (err) {
    log.warn(`On-the-fly Brotli compression failed: ${String(err)}`);
    // 압축 실패 시 원본 데이터 전송
    res.setHeader("Content-Type", mimeType);
    res.end(buffer);
  }
}

/**
 * 여러 파일을 일괄 Brotli 압축 (빌드 타임용)
 */
export async function compressFilesBatch(
  filePaths: string[],
  options?: BrotliOptions,
): Promise<{
  totalFiles: number;
  successful: number;
  failed: number;
  totalSize: number;
  totalCompressedSize: number;
}> {
  const results = {
    totalFiles: filePaths.length,
    successful: 0,
    failed: 0,
    totalSize: 0,
    totalCompressedSize: 0,
  };

  for (const filePath of filePaths) {
    const result = await compressFile(filePath, undefined, options);
    if (result.success) {
      results.successful++;
      results.totalSize += result.size;
      results.totalCompressedSize += result.compressedSize;
    } else {
      results.failed++;
    }
  }

  log.info(
    `Brotli batch compression complete: ${results.successful}/${results.totalFiles} files, ` +
      `${results.totalSize} → ${results.totalCompressedSize} bytes ` +
      `(${
        results.totalSize > 0
          ? ((1 - results.totalCompressedSize / results.totalSize) * 100).toFixed(1)
          : 0
      }% reduction)`,
  );

  return results;
}
