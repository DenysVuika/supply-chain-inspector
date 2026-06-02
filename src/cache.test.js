import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from "vitest";
import { mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";

// ── Helpers ──────────────────────────────────────────────────────────────────

function tmpCacheDir() {
  return join(tmpdir(), `cache-test-${randomUUID()}`);
}

function writeCorruptFile(file) {
  writeFileSync(file, "not-json", "utf8");
}

// ── Tests ────────────────────────────────────────────────────────────────────

describe("safeName()", () => {
  /** @type {import("./cache.js")} */
  let cache;

  beforeAll(async () => {
    cache = await import("./cache.js");
  });

  it("preserves a plain package name", () => {
    expect(cache.safeName("lodash")).toBe("lodash");
  });

  it("strips leading @ and replaces / with __ for scoped packages", () => {
    expect(cache.safeName("@babel/core")).toBe("babel__core");
  });

  it("replaces colons with underscores", () => {
    expect(cache.safeName("foo:bar")).toBe("foo_bar");
  });

  it("handles complex scoped + versioned input", () => {
    expect(cache.safeName("@types/node")).toBe("types__node");
  });

  it("handles empty string", () => {
    expect(cache.safeName("")).toBe("");
  });
});

describe("initCache() / getCacheDir() / getScriptDir()", () => {
  /** @type {import("./cache.js")} */
  let cache;

  beforeEach(async () => {
    vi.resetModules();
    cache = await import("./cache.js");
  });

  it("creates the default cache directory and returns its path", () => {
    const dir = cache.initCache();
    expect(dir).toBeTruthy();
    expect(existsSync(dir)).toBe(true);
    expect(cache.getCacheDir()).toBe(dir);
  });

  it("accepts a custom cache directory", () => {
    const customDir = tmpCacheDir();
    const dir = cache.initCache(customDir);
    expect(dir).toBe(customDir);
    expect(existsSync(customDir)).toBe(true);
  });

  it("returns null and disables cache when noCache is true", () => {
    const dir = cache.initCache(null, true);
    expect(dir).toBeNull();
    expect(cache.getCacheDir()).toBeNull();
  });

  it("returns null when noCache is true even with a custom dir", () => {
    const dir = cache.initCache("/some/path", true);
    expect(dir).toBeNull();
  });

  it("getScriptDir() returns the directory of cache.js", () => {
    expect(cache.getScriptDir()).toBeTruthy();
    expect(typeof cache.getScriptDir()).toBe("string");
  });

  it("is idempotent — calling initCache twice doesn't break", () => {
    const dir1 = cache.initCache();
    const dir2 = cache.initCache();
    expect(dir2).toBe(dir1);
    expect(cache.getCacheDir()).toBe(dir1);
  });
});

describe("writeToCache() / readFromCache()", () => {
  /** @type {import("./cache.js")} */
  let cache;
  let cacheDir;

  beforeEach(async () => {
    vi.resetModules();
    cache = await import("./cache.js");
    cacheDir = tmpCacheDir();
    cache.initCache(cacheDir);
  });

  it("writes and reads a value", () => {
    cache.writeToCache("test-key", { hello: "world" });
    const result = cache.readFromCache("test-key", 60_000);
    expect(result).toEqual({ hello: "world" });
  });

  it("returns null for a missing key", () => {
    const result = cache.readFromCache("does-not-exist", 60_000);
    expect(result).toBeNull();
  });

  it("returns null when no cache directory is set", async () => {
    vi.resetModules();
    const cache2 = await import("./cache.js");
    const result = cache2.readFromCache("anything", 60_000);
    expect(result).toBeNull();
  });

  it("returns null when the cache file has expired by TTL", () => {
    vi.useFakeTimers();
    const key = "expired-key";
    cache.writeToCache(key, "fresh");

    // Advance past a 10-second TTL
    vi.advanceTimersByTime(11_000);
    const result = cache.readFromCache(key, 10_000);
    expect(result).toBeNull();
    vi.useRealTimers();
  });

  it("returns data when within TTL", () => {
    vi.useFakeTimers();
    const key = "ttl-key";
    cache.writeToCache(key, "still-good");
    vi.advanceTimersByTime(5_000);
    const result = cache.readFromCache(key, 10_000);
    expect(result).toBe("still-good");
    vi.useRealTimers();
  });

  it("returns null for a corrupt cache file", () => {
    const key = "corrupt-key";
    cache.writeToCache(key, "data");
    writeCorruptFile(join(cacheDir, `${key}.json`));
    const result = cache.readFromCache(key, 60_000);
    expect(result).toBeNull();
  });

  it("does not crash when writing to an unwritable directory", () => {
    expect(() => {
      cache.writeToCache("test", "data");
    }).not.toThrow();
  });

  it("invokes logWarn callback on write failure", () => {
    const warn = vi.fn();
    cache.writeToCache("./bad/path/../key", "data", warn);
    expect(warn).toHaveBeenCalled();
  });

  it("increments fileCacheStats on read hit", () => {
    cache.writeToCache("stats-key", { val: 1 });
    const hitsBefore = cache.fileCacheStats.hits;
    cache.readFromCache("stats-key", 60_000);
    expect(cache.fileCacheStats.hits).toBe(hitsBefore + 1);
  });

  it("increments fileCacheStats.writes on write", () => {
    const writesBefore = cache.fileCacheStats.writes;
    cache.writeToCache("write-test", "val");
    expect(cache.fileCacheStats.writes).toBe(writesBefore + 1);
  });
});

describe("module-level in-memory caches", () => {
  /** @type {import("./cache.js")} */
  let cache;

  beforeAll(async () => {
    cache = await import("./cache.js");
  });

  it("npmCache is a Map", () => {
    expect(cache.npmCache).toBeInstanceOf(Map);
  });

  it("scorecardCache is a Map", () => {
    expect(cache.scorecardCache).toBeInstanceOf(Map);
  });

  it("cacheStats has npmHits and scorecardHits", () => {
    expect(cache.cacheStats).toHaveProperty("npmHits", 0);
    expect(cache.cacheStats).toHaveProperty("scorecardHits", 0);
  });
});

describe("TTL constants", () => {
  /** @type {import("./cache.js")} */
  let cache;

  beforeAll(async () => {
    cache = await import("./cache.js");
  });

  it("TTL_NPM is 6 hours", () => {
    expect(cache.TTL_NPM).toBe(6 * 60 * 60 * 1000);
  });

  it("TTL_OSV is 6 hours", () => {
    expect(cache.TTL_OSV).toBe(6 * 60 * 60 * 1000);
  });

  it("TTL_SCORECARD is 24 hours", () => {
    expect(cache.TTL_SCORECARD).toBe(24 * 60 * 60 * 1000);
  });

  it("TTL_KEV is 24 hours", () => {
    expect(cache.TTL_KEV).toBe(24 * 60 * 60 * 1000);
  });
});
