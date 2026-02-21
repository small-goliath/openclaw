import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const here = path.dirname(fileURLToPath(import.meta.url));

function normalizeBase(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) {
    return "/";
  }
  if (trimmed === "./") {
    return "./";
  }
  if (trimmed.endsWith("/")) {
    return trimmed;
  }
  return `${trimmed}/`;
}

export default defineConfig(() => {
  const envBase = process.env.OPENCLAW_CONTROL_UI_BASE_PATH?.trim();
  const base = envBase ? normalizeBase(envBase) : "./";
  return {
    base,
    publicDir: path.resolve(here, "public"),
    optimizeDeps: {
      include: ["lit/directives/repeat.js"],
    },
    build: {
      outDir: path.resolve(here, "../dist/control-ui"),
      emptyOutDir: true,
      sourcemap: true,
      // Chunk 크기 경고 임계값 조정 (기본 500KB에서 1000KB로)
      chunkSizeWarningLimit: 1000,
      rollupOptions: {
        output: {
          // 코드 스플리팅을 위한 manualChunks 설정
          manualChunks(id: string) {
            // Node modules chunking
            if (id.includes("node_modules")) {
              // Lit 관련 패키지를 vendor chunk로 분리
              if (id.includes("lit") || id.includes("@lit")) {
                return "vendor-lit";
              }
              // 기타 vendor chunk
              return "vendor";
            }

            // Route-based code splitting
            // 각 view를 별도의 chunk로 분리하여 초기 로딩 최적화
            if (id.includes("/src/ui/views/")) {
              // 파일명에서 view 이름 추출
              const match = id.match(/\/views\/([^/]+)\.ts$/);
              if (match) {
                const viewName = match[1];
                // 각 view를 개별 chunk로 분리
                return `route-${viewName}`;
              }
            }

            // Controllers chunking - 관련 컨트롤러들을 그룹화
            if (id.includes("/src/ui/controllers/")) {
              // config 관련 컨트롤러
              if (id.includes("/config/") || id.includes("/config.ts")) {
                return "controllers-config";
              }
              // chat 관련 컨트롤러
              if (id.includes("/chat.ts")) {
                return "controllers-chat";
              }
              // 나머지 컨트롤러들
              return "controllers";
            }

            // Core app files
            if (id.includes("/src/ui/app-")) {
              return "app-core";
            }

            // Main entry
            if (id.includes("/src/main.ts")) {
              return "main";
            }

            return undefined;
          },
          // Asset 파일명 패턴
          assetFileNames: (assetInfo) => {
            const info = assetInfo.name || "";
            if (info.endsWith(".css")) {
              return "assets/css/[name]-[hash][extname]";
            }
            return "assets/[name]-[hash][extname]";
          },
          // JS chunk 파일명 패턴
          entryFileNames: "assets/js/[name]-[hash].js",
          chunkFileNames: "assets/js/[name]-[hash].js",
        },
      },
      // CSS 코드 분할 설정
      cssCodeSplit: true,
      // 타겟 브라우저 설정
      target: "es2020",
    },
    server: {
      host: true,
      port: 5173,
      strictPort: true,
    },
  };
});
