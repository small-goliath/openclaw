import JSZip from "jszip";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import sharp from "sharp";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { isPathWithinBase } from "../../test/helpers/paths.js";

describe("media store", () => {
  let store: typeof import("./store.js");
  let home = "";
  const envSnapshot: Record<string, string | undefined> = {};

  const snapshotEnv = () => {
    for (const key of ["HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "OPENCLAW_STATE_DIR"]) {
      envSnapshot[key] = process.env[key];
    }
  };

  const restoreEnv = () => {
    for (const [key, value] of Object.entries(envSnapshot)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  };

  beforeAll(async () => {
    snapshotEnv();
    home = await fs.mkdtemp(path.join(os.tmpdir(), "openclaw-test-home-"));
    process.env.HOME = home;
    process.env.USERPROFILE = home;
    process.env.OPENCLAW_STATE_DIR = path.join(home, ".openclaw");
    if (process.platform === "win32") {
      const match = home.match(/^([A-Za-z]:)(.*)$/);
      if (match) {
        process.env.HOMEDRIVE = match[1];
        process.env.HOMEPATH = match[2] || "\\";
      }
    }
    await fs.mkdir(path.join(home, ".openclaw"), { recursive: true });
    store = await import("./store.js");
  });

  afterAll(async () => {
    restoreEnv();
    try {
      await fs.rm(home, { recursive: true, force: true });
    } catch {
      // ignore cleanup failures in tests
    }
  });

  async function withTempStore<T>(
    fn: (store: typeof import("./store.js"), home: string) => Promise<T>,
  ): Promise<T> {
    return await fn(store, home);
  }

  it("creates and returns media directory", async () => {
    await withTempStore(async (store, home) => {
      const dir = await store.ensureMediaDir();
      expect(isPathWithinBase(home, dir)).toBe(true);
      expect(path.normalize(dir)).toContain(`${path.sep}.openclaw${path.sep}media`);
      const stat = await fs.stat(dir);
      expect(stat.isDirectory()).toBe(true);
    });
  });

  it("saves buffers and enforces size limit", async () => {
    await withTempStore(async (store) => {
      const buf = Buffer.from("hello");
      const saved = await store.saveMediaBuffer(buf, "text/plain");
      const savedStat = await fs.stat(saved.path);
      expect(savedStat.size).toBe(buf.length);
      expect(saved.contentType).toBe("text/plain");
      expect(saved.path.endsWith(".txt")).toBe(true);

      const jpeg = await sharp({
        create: { width: 2, height: 2, channels: 3, background: "#123456" },
      })
        .jpeg({ quality: 80 })
        .toBuffer();
      const savedJpeg = await store.saveMediaBuffer(jpeg, "image/jpeg");
      expect(savedJpeg.contentType).toBe("image/jpeg");
      expect(savedJpeg.path.endsWith(".jpg")).toBe(true);

      const huge = Buffer.alloc(5 * 1024 * 1024 + 1);
      await expect(store.saveMediaBuffer(huge)).rejects.toThrow("Media exceeds 5MB limit");
    });
  });

  it("copies local files and cleans old media", async () => {
    await withTempStore(async (store, home) => {
      const srcFile = path.join(home, "tmp-src.txt");
      await fs.mkdir(home, { recursive: true });
      await fs.writeFile(srcFile, "local file");
      const saved = await store.saveMediaSource(srcFile);
      expect(saved.size).toBe(10);
      const savedStat = await fs.stat(saved.path);
      expect(savedStat.isFile()).toBe(true);
      expect(path.extname(saved.path)).toBe(".txt");

      // make the file look old and ensure cleanOldMedia removes it
      const past = Date.now() - 10_000;
      await fs.utimes(saved.path, past / 1000, past / 1000);
      await store.cleanOldMedia(1);
      await expect(fs.stat(saved.path)).rejects.toThrow();
    });
  });

  it("sets correct mime for xlsx by extension", async () => {
    await withTempStore(async (store, home) => {
      const xlsxPath = path.join(home, "sheet.xlsx");
      await fs.mkdir(home, { recursive: true });
      await fs.writeFile(xlsxPath, "not really an xlsx");

      const saved = await store.saveMediaSource(xlsxPath);
      expect(saved.contentType).toBe(
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      );
      expect(path.extname(saved.path)).toBe(".xlsx");
    });
  });

  it("renames media based on detected mime even when extension is wrong", async () => {
    await withTempStore(async (store, home) => {
      const pngBytes = await sharp({
        create: { width: 2, height: 2, channels: 3, background: "#00ff00" },
      })
        .png()
        .toBuffer();
      const bogusExt = path.join(home, "image-wrong.bin");
      await fs.writeFile(bogusExt, pngBytes);

      const saved = await store.saveMediaSource(bogusExt);
      expect(saved.contentType).toBe("image/png");
      expect(path.extname(saved.path)).toBe(".png");

      const buf = await fs.readFile(saved.path);
      expect(buf.equals(pngBytes)).toBe(true);
    });
  });

  it("sniffs xlsx mime for zip buffers and renames extension", async () => {
    await withTempStore(async (store, home) => {
      const zip = new JSZip();
      zip.file(
        "[Content_Types].xml",
        '<Types><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>',
      );
      zip.file("xl/workbook.xml", "<workbook/>");
      const fakeXlsx = await zip.generateAsync({ type: "nodebuffer" });
      const bogusExt = path.join(home, "sheet.bin");
      await fs.writeFile(bogusExt, fakeXlsx);

      const saved = await store.saveMediaSource(bogusExt);
      expect(saved.contentType).toBe(
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      );
      expect(path.extname(saved.path)).toBe(".xlsx");
    });
  });

  describe("extractOriginalFilename", () => {
    it("extracts original filename from embedded pattern", async () => {
      await withTempStore(async (store) => {
        // Pattern: {original}---{uuid}.{ext}
        const filename = "report---a1b2c3d4-e5f6-7890-abcd-ef1234567890.pdf";
        const result = store.extractOriginalFilename(`/path/to/${filename}`);
        expect(result).toBe("report.pdf");
      });
    });

    it("handles uppercase UUID pattern", async () => {
      await withTempStore(async (store) => {
        const filename = "Document---A1B2C3D4-E5F6-7890-ABCD-EF1234567890.docx";
        const result = store.extractOriginalFilename(`/media/inbound/${filename}`);
        expect(result).toBe("Document.docx");
      });
    });

    it("falls back to basename for non-matching patterns", async () => {
      await withTempStore(async (store) => {
        // UUID-only filename (legacy format)
        const uuidOnly = "a1b2c3d4-e5f6-7890-abcd-ef1234567890.pdf";
        expect(store.extractOriginalFilename(`/path/${uuidOnly}`)).toBe(uuidOnly);

        // Regular filename without embedded pattern
        expect(store.extractOriginalFilename("/path/to/regular.txt")).toBe("regular.txt");

        // Filename with --- but invalid UUID part
        expect(store.extractOriginalFilename("/path/to/foo---bar.txt")).toBe("foo---bar.txt");
      });
    });

    it("preserves original name with special characters", async () => {
      await withTempStore(async (store) => {
        const filename = "报告_2024---a1b2c3d4-e5f6-7890-abcd-ef1234567890.pdf";
        const result = store.extractOriginalFilename(`/media/${filename}`);
        expect(result).toBe("报告_2024.pdf");
      });
    });
  });

  describe("saveMediaBuffer with originalFilename", () => {
    it("embeds original filename in stored path when provided", async () => {
      await withTempStore(async (store) => {
        const buf = Buffer.from("test content");
        const saved = await store.saveMediaBuffer(
          buf,
          "text/plain",
          "inbound",
          5 * 1024 * 1024,
          "report.txt",
        );

        // Should contain the original name and a UUID pattern
        expect(saved.id).toMatch(/^report---[a-f0-9-]{36}\.txt$/);
        expect(saved.path).toContain("report---");

        // Should be able to extract original name
        const extracted = store.extractOriginalFilename(saved.path);
        expect(extracted).toBe("report.txt");
      });
    });

    it("sanitizes unsafe characters in original filename", async () => {
      await withTempStore(async (store) => {
        const buf = Buffer.from("test");
        // Filename with unsafe chars: < > : " / \ | ? *
        const saved = await store.saveMediaBuffer(
          buf,
          "text/plain",
          "inbound",
          5 * 1024 * 1024,
          "my<file>:test.txt",
        );

        // Unsafe chars should be replaced with underscores
        expect(saved.id).toMatch(/^my_file_test---[a-f0-9-]{36}\.txt$/);
      });
    });

    it("truncates long original filenames", async () => {
      await withTempStore(async (store) => {
        const buf = Buffer.from("test");
        const longName = "a".repeat(100) + ".txt";
        const saved = await store.saveMediaBuffer(
          buf,
          "text/plain",
          "inbound",
          5 * 1024 * 1024,
          longName,
        );

        // Original name should be truncated to 60 chars
        const baseName = path.parse(saved.id).name.split("---")[0];
        expect(baseName.length).toBeLessThanOrEqual(60);
      });
    });

    it("falls back to UUID-only when originalFilename not provided", async () => {
      await withTempStore(async (store) => {
        const buf = Buffer.from("test");
        const saved = await store.saveMediaBuffer(buf, "text/plain", "inbound");

        // Should be UUID-only pattern (legacy behavior)
        expect(saved.id).toMatch(/^[a-f0-9-]{36}\.txt$/);
        expect(saved.id).not.toContain("---");
      });
    });
  });

  describe("path traversal protection", () => {
    it("rejects originalFilename containing '..' sequence", async () => {
      await withTempStore(async (store) => {
        const buf = Buffer.from("test");

        // Path traversal 시도: ../etc/passwd
        await expect(
          store.saveMediaBuffer(buf, "text/plain", "inbound", 5 * 1024 * 1024, "../etc/passwd"),
        ).rejects.toThrow("Invalid filename: path traversal detected");

        // Path traversal 시도: file..name.txt (중간에 .. 포함)
        await expect(
          store.saveMediaBuffer(buf, "text/plain", "inbound", 5 * 1024 * 1024, "file..name.txt"),
        ).rejects.toThrow("Invalid filename: path traversal detected");

        // Path traversal 시도: ..file.txt (시작에 .. 포함)
        await expect(
          store.saveMediaBuffer(buf, "text/plain", "inbound", 5 * 1024 * 1024, "..file.txt"),
        ).rejects.toThrow("Invalid filename: path traversal detected");
      });
    });

    it("rejects originalFilename containing path separators", async () => {
      await withTempStore(async (store) => {
        const buf = Buffer.from("test");

        // Unix 경로 구분자
        await expect(
          store.saveMediaBuffer(buf, "text/plain", "inbound", 5 * 1024 * 1024, "path/to/file.txt"),
        ).rejects.toThrow("Invalid filename: path traversal detected");

        // Windows 경로 구분자
        await expect(
          store.saveMediaBuffer(
            buf,
            "text/plain",
            "inbound",
            5 * 1024 * 1024,
            "path\\to\\file.txt",
          ),
        ).rejects.toThrow("Invalid filename: path traversal detected");

        // 혼합된 경로 구분자
        await expect(
          store.saveMediaBuffer(buf, "text/plain", "inbound", 5 * 1024 * 1024, "path/to\\file.txt"),
        ).rejects.toThrow("Invalid filename: path traversal detected");
      });
    });

    it("rejects subdir containing path traversal sequences", async () => {
      await withTempStore(async (store) => {
        const buf = Buffer.from("test");

        // Path traversal in subdir
        await expect(
          store.saveMediaBuffer(buf, "text/plain", "../etc", 5 * 1024 * 1024, "file.txt"),
        ).rejects.toThrow("Invalid subdir: path traversal detected");

        // Nested path traversal
        await expect(
          store.saveMediaBuffer(
            buf,
            "text/plain",
            "inbound/../../etc",
            5 * 1024 * 1024,
            "file.txt",
          ),
        ).rejects.toThrow("Invalid subdir: path traversal detected");

        // Multiple levels of path traversal
        await expect(
          store.saveMediaBuffer(buf, "text/plain", "a/b/../../../etc", 5 * 1024 * 1024, "file.txt"),
        ).rejects.toThrow("Invalid subdir: path traversal detected");
      });
    });

    it("allows safe filenames and subdirs", async () => {
      await withTempStore(async (store) => {
        const buf = Buffer.from("test content");

        // Safe filename with dots
        const saved1 = await store.saveMediaBuffer(
          buf,
          "text/plain",
          "inbound",
          5 * 1024 * 1024,
          "my.file.name.txt",
        );
        expect(saved1.id).toMatch(/^my\.file\.name---[a-f0-9-]{36}\.txt$/);

        // Safe filename with hyphen and underscore
        const saved2 = await store.saveMediaBuffer(
          buf,
          "text/plain",
          "inbound",
          5 * 1024 * 1024,
          "my-file_name.txt",
        );
        expect(saved2.id).toMatch(/^my-file_name---[a-f0-9-]{36}\.txt$/);

        // Safe nested subdir
        const saved3 = await store.saveMediaBuffer(
          buf,
          "text/plain",
          "inbound/2024/documents",
          5 * 1024 * 1024,
          "report.txt",
        );
        expect(saved3.path).toContain("inbound");
        expect(saved3.path).toContain("2024");
        expect(saved3.path).toContain("documents");
      });
    });

    it("rejects path traversal in saveMediaSource subdir", async () => {
      await withTempStore(async (store, home) => {
        const srcFile = path.join(home, "tmp-src.txt");
        await fs.writeFile(srcFile, "local file");

        // Path traversal in subdir should be rejected
        await expect(store.saveMediaSource(srcFile, undefined, "../etc")).rejects.toThrow(
          "Invalid subdir: path traversal detected",
        );

        // Nested path traversal
        await expect(store.saveMediaSource(srcFile, undefined, "media/../../etc")).rejects.toThrow(
          "Invalid subdir: path traversal detected",
        );
      });
    });
  });
});
