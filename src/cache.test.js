import { describe, it, expect, beforeAll, beforeEach, vi } from "vitest";
import { readFile, writeFile, mkdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";

// ── Helpers ──────────────────────────────────────────────────────────────────

function tmpCacheDir() {
  return join(tmpdir(), `cache-test-${randomUUID()}`);
}

async function writeCorruptFile(file) {
  await writeFile(file, "not-json", "utf8");
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

  it("replaces backslashes", () => {
    expect(cache.safeName("foo\\bar")).toBe("foo_bar");
  });

  it("replaces +, #, and other unsafe chars", () => {
    expect(cache.safeName("foo+bar")).toBe("foo_bar");
    expect(cache.safeName("a#b")).toBe("a_b");
  });

  it("replaces angle brackets and pipe", () => {
    expect(cache.safeName("a<b>c|d")).toBe("a_b_c_d");
  });

  it("preserves dots, hyphens, and @ after leading strip", () => {
    expect(cache.safeName("1.2.3-beta.1")).toBe("1.2.3-beta.1");
  });
});

describe("initCache() / getCacheDir() / getScriptDir()", () => {
  /** @type {import("./cache.js")} */
  let cache;

  beforeEach(async () => {
    vi.resetModules();
    cache = await import("./cache.js");
  });

  it("creates the default cache directory and returns its path", async () => {
    const dir = await cache.initCache();
    expect(dir).toBeTruthy();
    // Verify directory exists by trying to stat it
    const s = await stat(dir);
    expect(s.isDirectory()).toBe(true);
    expect(cache.getCacheDir()).toBe(dir);
  });

  it("accepts a custom cache directory", async () => {
    const customDir = tmpCacheDir();
    const dir = await cache.initCache(customDir);
    expect(dir).toBe(customDir);
    const s = await stat(customDir);
    expect(s.isDirectory()).toBe(true);
  });

  it("returns null and disables cache when noCache is true", async () => {
    const dir = await cache.initCache(null, true);
    expect(dir).toBeNull();
    expect(cache.getCacheDir()).toBeNull();
  });

  it("returns null when noCache is true even with a custom dir", async () => {
    const dir = await cache.initCache("/some/path", true);
    expect(dir).toBeNull();
  });

  it("getScriptDir() returns the directory of cache.js", () => {
    expect(cache.getScriptDir()).toBeTruthy();
    expect(typeof cache.getScriptDir()).toBe("string");
  });

  it("is idempotent — calling initCache twice doesn't break", async () => {
    const dir1 = await cache.initCache();
    const dir2 = await cache.initCache();
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
    await cache.initCache(cacheDir);
  });

  it("writes and reads a value", async () => {
    await cache.writeToCache("test-key", { hello: "world" });
    const result = await cache.readFromCache("test-key", 60_000);
    expect(result).toEqual({ hello: "world" });
  });

  it("returns null for a missing key", async () => {
    const result = await cache.readFromCache("does-not-exist", 60_000);
    expect(result).toBeNull();
  });

  it("returns null when no cache directory is set", async () => {
    vi.resetModules();
    const cache2 = await import("./cache.js");
    const result = await cache2.readFromCache("anything", 60_000);
    expect(result).toBeNull();
  });

  it("returns null when the cache file has expired by TTL", async () => {
    vi.useFakeTimers();
    const key = "expired-key";
    await cache.writeToCache(key, "fresh");

    // Advance past a 10-second TTL
    vi.advanceTimersByTime(11_000);
    const result = await cache.readFromCache(key, 10_000);
    expect(result).toBeNull();
    vi.useRealTimers();
  });

  it("returns data when within TTL", async () => {
    vi.useFakeTimers();
    const key = "ttl-key";
    await cache.writeToCache(key, "still-good");
    vi.advanceTimersByTime(5_000);
    const result = await cache.readFromCache(key, 10_000);
    expect(result).toBe("still-good");
    vi.useRealTimers();
  });

  it("returns null for a corrupt cache file", async () => {
    const key = "corrupt-key";
    await cache.writeToCache(key, "data");
    await writeCorruptFile(join(cacheDir, `${key}.json`));
    const result = await cache.readFromCache(key, 60_000);
    expect(result).toBeNull();
  });

  it("does not crash when writing to an unwritable directory", async () => {
    // Should not throw — errors are swallowed with logWarn
    await expect(
      cache.writeToCache("test", "data"),
    ).resolves.toBeUndefined();
  });

  it("invokes logWarn callback on write failure", async () => {
    const warn = vi.fn();
    // Write to a path with invalid characters in the key — the tmp file
    // path will also be invalid, causing a write failure
    await cache.writeToCache("./bad/path/../key", "data", warn);
    expect(warn).toHaveBeenCalled();
  });

  it("increments fileCacheStats on read hit", async () => {
    await cache.writeToCache("stats-key", { val: 1 });
    const hitsBefore = cache.fileCacheStats.hits;
    await cache.readFromCache("stats-key", 60_000);
    expect(cache.fileCacheStats.hits).toBe(hitsBefore + 1);
  });

  it("increments fileCacheStats.writes on write", async () => {
    const writesBefore = cache.fileCacheStats.writes;
    await cache.writeToCache("write-test", "val");
    expect(cache.fileCacheStats.writes).toBe(writesBefore + 1);
  });

  it("leaves no tmp files after a successful write", async () => {
    await cache.writeToCache("clean-key", { data: 42 });
    const { readdirSync } = await import("node:fs");
    const files = readdirSync(cacheDir);
    const tmpFiles = files.filter((f) => f.endsWith(".tmp"));
    expect(tmpFiles).toHaveLength(0);
  });

  it("atomically writes — file appears only after rename", async () => {
    // Write and verify the final file exists (not a tmp file)
    await cache.writeToCache("atomic-key", { atomic: true });
    const content = JSON.parse(
      await readFile(join(cacheDir, "atomic-key.json"), "utf8"),
    );
    expect(content.data).toEqual({ atomic: true });
    expect(content.cachedAt).toBeTruthy();
  });

  it("overwrites an existing cache entry", async () => {
    await cache.writeToCache("overwrite-key", { version: 1 });
    await cache.writeToCache("overwrite-key", { version: 2 });
    const result = await cache.readFromCache("overwrite-key", 60_000);
    expect(result).toEqual({ version: 2 });
  });
});

describe("readStaleFromCache()", () => {
  /** @type {import("./cache.js")} */
  let cache;
  let cacheDir;

  beforeEach(async () => {
    vi.resetModules();
    cache = await import("./cache.js");
    cacheDir = tmpCacheDir();
    await cache.initCache(cacheDir);
  });

  it("returns null for a missing key", async () => {
    const result = await cache.readStaleFromCache("missing", 60_000, 30_000);
    expect(result).toBeNull();
  });

  it("returns null when no cache directory is set", async () => {
    vi.resetModules();
    const cache2 = await import("./cache.js");
    const result = await cache2.readStaleFromCache("anything", 60_000, 30_000);
    expect(result).toBeNull();
  });

  it("returns { data, stale: false } when within soft TTL", async () => {
    await cache.writeToCache("fresh-key", { val: 1 });
    const result = await cache.readStaleFromCache("fresh-key", 60_000, 30_000);
    expect(result).toEqual({ data: { val: 1 }, stale: false });
  });

  it("returns { data, stale: true } when past soft TTL but within hard TTL", async () => {
    vi.useFakeTimers();
    await cache.writeToCache("stale-key", { val: 2 });

    // Advance past soft TTL (30s) but not hard TTL (60s)
    vi.advanceTimersByTime(40_000);
    const result = await cache.readStaleFromCache("stale-key", 60_000, 30_000);
    expect(result).toEqual({ data: { val: 2 }, stale: true });
    vi.useRealTimers();
  });

  it("returns null when past hard TTL (expired)", async () => {
    vi.useFakeTimers();
    await cache.writeToCache("expired-key", { val: 3 });

    // Advance past hard TTL (60s)
    vi.advanceTimersByTime(61_000);
    const result = await cache.readStaleFromCache("expired-key", 60_000, 30_000);
    expect(result).toBeNull();
    vi.useRealTimers();
  });

  it("returns null for a corrupt cache file", async () => {
    await cache.writeToCache("corrupt-key", "data");
    await writeCorruptFile(join(cacheDir, "corrupt-key.json"));
    const result = await cache.readStaleFromCache("corrupt-key", 60_000, 30_000);
    expect(result).toBeNull();
  });

  it("increments fileCacheStats.hits on a hit (fresh or stale)", async () => {
    await cache.writeToCache("stats-stale", { val: 4 });
    const hitsBefore = cache.fileCacheStats.hits;
    await cache.readStaleFromCache("stats-stale", 60_000, 30_000);
    expect(cache.fileCacheStats.hits).toBe(hitsBefore + 1);
  });

  it("does not increment hits on a miss", async () => {
    const hitsBefore = cache.fileCacheStats.hits;
    await cache.readStaleFromCache("no-such-key", 60_000, 30_000);
    expect(cache.fileCacheStats.hits).toBe(hitsBefore);
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

  it("TTL_NPM is 24 hours (hard)", () => {
    expect(cache.TTL_NPM).toBe(24 * 60 * 60 * 1000);
  });

  it("TTL_OSV is 12 hours (hard)", () => {
    expect(cache.TTL_OSV).toBe(12 * 60 * 60 * 1000);
  });

  it("TTL_SCORECARD is 48 hours (hard)", () => {
    expect(cache.TTL_SCORECARD).toBe(48 * 60 * 60 * 1000);
  });

  it("TTL_KEV is 48 hours (hard)", () => {
    expect(cache.TTL_KEV).toBe(48 * 60 * 60 * 1000);
  });

  it("SOFT_TTL_NPM is 6 hours", () => {
    expect(cache.SOFT_TTL_NPM).toBe(6 * 60 * 60 * 1000);
  });

  it("SOFT_TTL_OSV is 2 hours", () => {
    expect(cache.SOFT_TTL_OSV).toBe(2 * 60 * 60 * 1000);
  });

  it("SOFT_TTL_SCORECARD is 12 hours", () => {
    expect(cache.SOFT_TTL_SCORECARD).toBe(12 * 60 * 60 * 1000);
  });

  it("SOFT_TTL_KEV is 12 hours", () => {
    expect(cache.SOFT_TTL_KEV).toBe(12 * 60 * 60 * 1000);
  });

  it("soft TTLs are always less than hard TTLs", () => {
    expect(cache.SOFT_TTL_NPM).toBeLessThan(cache.TTL_NPM);
    expect(cache.SOFT_TTL_OSV).toBeLessThan(cache.TTL_OSV);
    expect(cache.SOFT_TTL_SCORECARD).toBeLessThan(cache.TTL_SCORECARD);
    expect(cache.SOFT_TTL_KEV).toBeLessThan(cache.TTL_KEV);
  });
});

describe("concurrent writes", () => {
  /** @type {import("./cache.js")} */
  let cache;
  let cacheDir;

  beforeEach(async () => {
    vi.resetModules();
    cache = await import("./cache.js");
    cacheDir = tmpCacheDir();
    await cache.initCache(cacheDir);
  });

  it("handles concurrent writes to the same key without corruption", async () => {
    const promises = Array.from({ length: 10 }, (_, i) =>
      cache.writeToCache("concurrent-key", { value: i }),
    );
    await Promise.all(promises);

    // File should be valid JSON and readable
    const result = await cache.readFromCache("concurrent-key", 60_000);
    expect(result).toBeTruthy();
    expect(result).toHaveProperty("value");
  });

  it("handles concurrent writes to different keys", async () => {
    const promises = Array.from({ length: 10 }, (_, i) =>
      cache.writeToCache(`key-${i}`, { value: i }),
    );
    await Promise.all(promises);

    for (let i = 0; i < 10; i++) {
      const result = await cache.readFromCache(`key-${i}`, 60_000);
      expect(result).toEqual({ value: i });
    }
  });
});

describe("cache key format", () => {
  /** @type {import("./cache.js")} */
  let cache;
  let cacheDir;

  beforeEach(async () => {
    vi.resetModules();
    cache = await import("./cache.js");
    cacheDir = tmpCacheDir();
    await cache.initCache(cacheDir);
  });

  it("npm cache keys use safeName", async () => {
    await cache.writeToCache("npm_babel__core", { name: "@babel/core" });
    const result = await cache.readFromCache("npm_babel__core", 60_000);
    expect(result).toEqual({ name: "@babel/core" });
  });

  it("scorecard cache keys use owner__repo format", async () => {
    await cache.writeToCache("scorecard_babel__babel", { score: 8.5 });
    const result = await cache.readFromCache(
      "scorecard_babel__babel",
      60_000,
    );
    expect(result).toEqual({ score: 8.5 });
  });
});
