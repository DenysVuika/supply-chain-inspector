/**
 * cache.js
 *
 * File-based caching module for supply-chain-inspector.
 * Persists API responses between runs so repeated invocations on the same
 * project don't re-fetch unchanged data.
 *
 * Also provides in-flight request deduplication via in-memory Maps.
 *
 * File I/O is fully async to avoid blocking the event loop during concurrent
 * fetches.  Writes are atomic (write-to-tmp + rename) to prevent corrupt
 * cache files on crash.
 */

import { readFile, writeFile, unlink, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Resolved path of the project root (one level up from src/) — used to anchor
// the default cache directory so the cache always lives at the project root
// regardless of cwd.
const _scriptDir = dirname(dirname(fileURLToPath(import.meta.url)));

// ── File-cache TTLs ───────────────────────────────────────────────────────────
// Default hard TTLs — after this long, the entry is expired and must be re-fetched.
// npm registry docs change when new versions are published → 24 h default.
// OSV advisories are updated continuously but rarely change within an hour → 12 h.
// OpenSSF Scorecard is recomputed weekly by the OpenSSF infrastructure → 48 h.
// CISA KEV is updated ~weekly → 48 h.
export const TTL_NPM = 24 * 60 * 60 * 1000; // 24 hours (hard)
export const TTL_OSV = 12 * 60 * 60 * 1000; // 12 hours (hard)
export const TTL_SCORECARD = 48 * 60 * 60 * 1000; // 48 hours (hard)
export const TTL_KEV = 48 * 60 * 60 * 1000; // 48 hours (hard)

// Default soft TTLs — after this long, serve stale data and refresh in background.
// Soft TTL must be strictly less than the corresponding hard TTL.
export const SOFT_TTL_NPM = 6 * 60 * 60 * 1000; // 6 hours
export const SOFT_TTL_OSV = 2 * 60 * 60 * 1000; // 2 hours
export const SOFT_TTL_SCORECARD = 12 * 60 * 60 * 1000; // 12 hours
export const SOFT_TTL_KEV = 12 * 60 * 60 * 1000; // 12 hours

// ─── Per-run in-flight deduplication caches ───────────────────────────────────
//
// Each cache stores the Promise itself, not the resolved value.
// This means concurrent workers that request the same key share one in-flight
// HTTP request instead of each firing their own — critical for monorepos where
// dozens of packages (e.g. all @babel/*, @jest/*, @angular/*) share one repo
// and would otherwise trigger redundant Scorecard API calls in parallel.
//
// The npm cache handles the case where the same package appears in multiple
// dependency groups (dependencies + devDependencies) when --include-dev is used.

export const npmCache = new Map(); // package name  → Promise<pkgData | null>
export const scorecardCache = new Map(); // "owner/repo"  → Promise<result>

// Simple hit counters surfaced in the run summary
export const cacheStats = { npmHits: 0, scorecardHits: 0 };

// ─── File-based cache ─────────────────────────────────────────────────────────
//
// Persists API responses between runs so repeated invocations on the same
// project don't re-fetch unchanged data.  Each entry is a tiny JSON file:
//
//   { "cachedAt": "<ISO-8601>", "data": <original API response> }
//
// The cache directory is created on first use and can be safely deleted at any
// time — the script will recreate it and fall back to live API calls.
//
// Layout (all files sit flat inside _cacheDir):
//   npm_<name>.json              — full npm registry package document
//   osv_<name>_<version>.json   — OSV.dev vulnerability result
//   scorecard_<owner>__<repo>.json — OpenSSF Scorecard result

let _cacheDir = null; // set via initCache()
export const fileCacheStats = { hits: 0, writes: 0 };

/**
 * Sanitise an arbitrary string for use as a filename component.
 * Handles all characters that are invalid on common filesystems:
 *   @babel/core  →  babel__core
 *   1.2.3-beta.1 →  1.2.3-beta.1   (dots/hyphens are fine)
 *   foo+bar      →  foo_bar
 */
export function safeName(str) {
  return String(str)
    .replace(/^@/, "") // strip leading @ from scoped packages
    .replace(/\//g, "__") // @scope/name → scope__name
    .replace(/[/\\:*?"<>|+#]/g, "_"); // replace remaining filesystem-unsafe chars
}

/**
 * Read a cached value. Returns the stored data or null if the entry is
 * absent, unreadable, or older than `ttlMs` milliseconds.
 */
export async function readFromCache(key, ttlMs) {
  if (!_cacheDir) return null;
  try {
    const { cachedAt, data } = JSON.parse(
      await readFile(join(_cacheDir, `${key}.json`), "utf8"),
    );
    if (Date.now() - new Date(cachedAt).getTime() > ttlMs) return null;
    fileCacheStats.hits++;
    return data;
  } catch {
    return null; // missing, corrupt, or unreadable — treat as cache miss
  }
}

/**
 * Read a cached value with stale-while-revalidate semantics.
 *
 * Returns an object with `{ data, stale }` or `null`:
 *   - `null` — entry is missing, corrupt, or past the hard TTL (expired)
 *   - `{ data, stale: false }` — entry is fresh (within soft TTL)
 *   - `{ data, stale: true }` — entry is stale (past soft TTL, within hard TTL)
 *     The caller should return `data` immediately and trigger a background
 *     refresh so the next invocation gets fresh data.
 *
 * @param {string} key - Cache key
 * @param {number} hardTtlMs - Hard TTL: after this, entry is expired
 * @param {number} softTtlMs - Soft TTL: after this, entry is stale but usable
 */
export async function readStaleFromCache(key, hardTtlMs, softTtlMs) {
  if (!_cacheDir) return null;
  try {
    const { cachedAt, data } = JSON.parse(
      await readFile(join(_cacheDir, `${key}.json`), "utf8"),
    );
    const age = Date.now() - new Date(cachedAt).getTime();
    if (age > hardTtlMs) return null; // expired
    fileCacheStats.hits++;
    return { data, stale: age > softTtlMs };
  } catch {
    return null; // missing, corrupt, or unreadable
  }
}

/**
 * Atomically rename a file.  Falls back to copy+delete for cross-device
 * moves (unlikely for a local cache but handles edge cases).
 */
async function atomicRename(oldPath, newPath) {
  try {
    const { rename: renameFn } = await import("node:fs/promises");
    await renameFn(oldPath, newPath);
  } catch (err) {
    if (err.code === "EXDEV") {
      await writeFile(newPath, await readFile(oldPath));
      await unlink(oldPath);
    } else {
      throw err;
    }
  }
}

/**
 * Write a value to the cache atomically.
 * Uses write-to-temp + rename to prevent corrupt files on crash.
 * Errors are logged as warnings but never thrown so a non-writable cache
 * directory never breaks the main analysis.
 * @param {string} key - Cache key
 * @param {any} data - Data to cache
 * @param {function} [logWarn] - Optional warning logger function
 * @returns {Promise<void>}
 */
export async function writeToCache(key, data, logWarn) {
  if (!_cacheDir) return;
  const dest = join(_cacheDir, `${key}.json`);
  const tmp = join(_cacheDir, `._${key}.${Date.now()}.tmp`);
  try {
    await writeFile(
      tmp,
      JSON.stringify({ cachedAt: new Date().toISOString(), data }),
      "utf8",
    );
    await atomicRename(tmp, dest);
    fileCacheStats.writes++;
  } catch (err) {
    // Clean up temp file if it exists
    try {
      await unlink(tmp);
    } catch {
      // ignore — file may not have been created
    }
    if (logWarn) {
      logWarn(`Cache write failed for ${key}: ${err.message}`);
    }
  }
}

/**
 * Initialize the cache directory.
 * @param {string|null} cacheDir - Custom cache directory path, or null for default
 * @param {boolean} noCache - If true, disable caching entirely
 * @returns {Promise<string|null>} The resolved cache directory path, or null if caching is disabled
 */
export async function initCache(cacheDir = null, noCache = false) {
  if (noCache) {
    _cacheDir = null;
    return null;
  }

  if (cacheDir) {
    _cacheDir = cacheDir;
  } else {
    _cacheDir = join(_scriptDir, ".cache");
  }

  try {
    await mkdir(_cacheDir, { recursive: true });
    return _cacheDir;
  } catch {
    _cacheDir = null;
    return null;
  }
}

/**
 * Get the current cache directory path.
 * @returns {string|null} The cache directory path, or null if caching is disabled
 */
export function getCacheDir() {
  return _cacheDir;
}

/**
 * Get the script directory path (project root).
 * @returns {string} The script directory path
 */
export function getScriptDir() {
  return _scriptDir;
}
