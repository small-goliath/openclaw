import type { EmbeddingProvider } from "./embeddings.js";
import { estimateUtf8Bytes, splitTextToUtf8ByteLimit } from "./embedding-input-limits.js";
import { resolveEmbeddingMaxInputTokens } from "./embedding-model-limits.js";
import { hashText, type MemoryChunk } from "./internal.js";

export async function enforceEmbeddingMaxInputTokens(
  provider: EmbeddingProvider,
  chunks: MemoryChunk[],
): Promise<MemoryChunk[]> {
  const maxInputTokens = resolveEmbeddingMaxInputTokens(provider);
  const out: MemoryChunk[] = [];

  for (const chunk of chunks) {
    if (estimateUtf8Bytes(chunk.text) <= maxInputTokens) {
      out.push(chunk);
      continue;
    }

    for (const text of splitTextToUtf8ByteLimit(chunk.text, maxInputTokens)) {
      out.push({
        startLine: chunk.startLine,
        endLine: chunk.endLine,
        text,
        hash: await hashText(text),
      });
    }
  }

  return out;
}
