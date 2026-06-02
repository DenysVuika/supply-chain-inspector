/**
 * cache.js
 *
 * File-based caching module for supply-chain-inspector.
 * Persists API responses between runs so repeated invocations on the same
 * project don't re-fetch unchanged data.
 *
 * Also provides in-flight request deduplication via in-memory Maps.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Resolved path of the project root (one level up from src/) — used to anchor
// the default cache directory so the cache always lives at the project root
// regardless of cwd.
const _scriptDir = dirname(dirname(fileURLToPath(import.meta.url)));

// ── File-cache TTLs ───────────────────────────────────────────────────────────
// npm registry docs change when new versions are published → refresh every 6 h.
// OSV advisories are updated continuously but rarely change within an hour → 6 h.
// OpenSSF Scorecard is recomputed weekly by the OpenSSF infrastructure → 24 h.
export const TTL_NPM = 6 * 60 * 60 * 1000; //  6 hours
export const TTL_OSV = 6 * 60 * 60 * 1000; //  6 hours
export const TTL_SCORECARD = 24 * 60 * 60 * 1000; // 24 hours
export const TTL_KEV = 24 * 60 * 60 * 1000; // 24 hours — CISA updates ~weekly

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
 *   @babel/core  →  babel__core
 *   1.2.3-beta.1 →  1.2.3-beta.1   (dots/hyphens are fine)
 */
export function safeName(str) {
  return String(str)
    .replace(/^@/, "") // strip leading @ from scoped packages
    .replace(/\//g, "__") // @scope/name → scope__name
    .replace(/:/g, "_"); // guard against any colons
}

/**
 * Read a cached value. Returns the stored data or null if the entry is
 * absent, unreadable, or older than `ttlMs` milliseconds.
 */
export function readFromCache(key, ttlMs) {
  if (!_cacheDir) return null;
  const file = join(_cacheDir, `${key}.json`);
  if (!existsSync(file)) return null;
  try {
    const { cachedAt, data } = JSON.parse(readFileSync(file, "utf8"));
    if (Date.now() - new Date(cachedAt).getTime() > ttlMs) return null;
    fileCacheStats.hits++;
    return data;
  } catch {
    return null; // corrupt or unreadable — treat as cache miss
  }
}

/**
 * Write a value to the cache. Errors are logged as warnings but never thrown
 * so a non-writable cache directory never breaks the main analysis.
 * @param {string} key - Cache key
 * @param {any} data - Data to cache
 * @param {function} [logWarn] - Optional warning logger function
 */
export function writeToCache(key, data, logWarn) {
  if (!_cacheDir) return;
  try {
    writeFileSync(
      join(_cacheDir, `${key}.json`),
      JSON.stringify({ cachedAt: new Date().toISOString(), data }, null, 2),
      "utf8",
    );
    fileCacheStats.writes++;
  } catch (err) {
    if (logWarn) {
      logWarn(`Cache write failed for ${key}: ${err.message}`);
    }
  }
}

/**
 * Initialize the cache directory.
 * @param {string|null} cacheDir - Custom cache directory path, or null for default
 * @param {boolean} noCache - If true, disable caching entirely
 * @returns {string|null} The resolved cache directory path, or null if caching is disabled
 */
export function initCache(cacheDir = null, noCache = false) {
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
    mkdirSync(_cacheDir, { recursive: true });
    return _cacheDir;
  } catch (err) {
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
