#!/usr/bin/env node

/**
 * inspect-dependencies.js
 *
 * Standalone supply chain data collector for npm packages.
 * Reads a package.json, fetches security-relevant data from public APIs
 * for every dependency, and prints a formatted security report to the terminal.
 * JSON output is opt-in, keeping the console readable for large projects.
 *
 * No external npm packages required. Requires Node.js 18+ (native fetch).
 * No GitHub API token required — all data sources are public and unauthenticated.
 *
 * ─── Usage ────────────────────────────────────────────────────────────────────
 *
 node scripts/inspect-dependencies.js <path/to/package.json|url> [options]

 Examples:
   # Local file
   node scripts/inspect-dependencies.js package.json

   # Remote URL (GitHub, raw content, etc.)
   node scripts/inspect-dependencies.js https://raw.githubusercontent.com/angular/angular/refs/heads/main/package.json
 *
 * ─── Options ──────────────────────────────────────────────────────────────────
 *
 *   Dependency scope (default: production dependencies only)
 *     --include-dev          Also inspect devDependencies
 *     --include-peer         Also inspect peerDependencies
 *     --include-optional     Also inspect optionalDependencies
 *     --include-transitive   Also inspect every transitive dependency resolved
 *                            in package-lock.json, deduplicated by name@version.
 *                            Packages already present as direct deps are skipped
 *                            to avoid double-counting.  Requires a lockfile.
 *
 *   Version history
 *     --version-history=<N>  Versions to keep per package (default: 10, min: 2)
 *                              2  = downgrade / major-jump detection only
 *                              5  = + rapid publish bursts + dormancy detection
 *                              10 = + cadence baseline (recommended)
 *                              20+= broader history, larger output
 *
 *   Data collection
 *     --concurrency=<N>      Max parallel package fetches (default: 5)
 *     --lockfile=<path|url>  Path or URL to package-lock.json for exact version resolution
 *                            (auto-detected next to package.json if not given;
 *                            for URLs, auto-detects package-lock.json in same directory)
 *     --no-scorecard         Skip OpenSSF Scorecard lookups (faster, offline-friendly)
 *     --no-vulns             Skip OSV.dev vulnerability lookups
 *
 *   Cache
 *     --cache-dir=<path>     Where to store cached API responses
 *                            (default: .cache/ next to this script)
 *     --no-cache             Disable file cache; always fetch live data
 *
 *   Cache TTLs (not configurable; delete cache files to force refresh):
 *     npm registry  6 h   — refreshed when new package versions are published
 *     OSV.dev       6 h   — vulnerability data is fairly stable within hours
 *     Scorecard    24 h   — OpenSSF recomputes scores weekly; daily is enough
 *
 *   Report
 *     --findings             Show per-package findings detail below the table.
 *                            By default only the summary table is shown;
 *                            a one-line hint indicates when issues were found.
 *
 *   Output
 *     --json                 Print the full JSON result array to stdout
 *     --output=<path>        Write JSON to a file (implies --json)
 *     --html=<path>          Write a standalone HTML security report to a file
 *
 *   Color
 *     NO_COLOR=1             Disable ANSI colors (also auto-disabled when not a TTY)
 *
 * ─── Output modes ─────────────────────────────────────────────────────────────
 *
 *   By default only the formatted report is shown (on stderr).
 *   JSON is never written unless explicitly requested:
 *
 *   # Report only — clean terminal view, no JSON noise
 *   node scripts/inspect-dependencies.js package.json
 *
 *   # Report on stderr + JSON on stdout — pipe JSON to another tool
 *   node scripts/inspect-dependencies.js package.json --json
 *
 *   # Report on stderr + JSON saved to file — review both independently
 *   node scripts/inspect-dependencies.js package.json --output=results.json
 *
 *   # Write a standalone HTML report — open in any browser, no server needed
 *   node scripts/inspect-dependencies.js package.json --html=report.html
 *
 *   # HTML report + JSON side by side (useful for both humans and tooling)
 *   node scripts/inspect-dependencies.js package.json --output=scan.json --html=report.html
 *
 *   # Suppress the report, get only JSON (e.g. for scripting)
 *   node scripts/inspect-dependencies.js package.json --json 2>/dev/null
 *
 *   # Pipe JSON straight to an AI tool
 *   node scripts/inspect-dependencies.js package.json --json | llm "analyze these deps"
 *
 * ─── Common recipes ───────────────────────────────────────────────────────────
 *
 *   # Scan all dependency groups, save JSON for later AI analysis
 *   node scripts/inspect-dependencies.js package.json \
 *     --include-dev --include-peer \
 *     --output=scan.json
 *
 *   # Full scan with both HTML report and JSON output
 *   node scripts/inspect-dependencies.js package.json \
 *     --include-dev --include-peer \
 *     --output=scan.json --html=report.html
 *
 *   # Inspect a remote package.json from a GitHub repository
 *   node scripts/inspect-dependencies.js https://raw.githubusercontent.com/angular/angular/refs/heads/main/package.json
 *
 *   # Inspect remote package.json with full scan (auto-detects remote lockfile)
 *   node scripts/inspect-dependencies.js https://raw.githubusercontent.com/user/repo/main/package.json \
 *     --include-dev --html=report.html
 *
 *   # Inspect remote package.json with explicit remote lockfile URL
 *   node scripts/inspect-dependencies.js https://raw.githubusercontent.com/user/repo/main/package.json \
 *     --lockfile=https://raw.githubusercontent.com/user/repo/main/package-lock.json
 *
 *   # Quick scan — skip Scorecard (no outbound calls to api.scorecard.dev)
 *   node scripts/inspect-dependencies.js package.json --no-scorecard
 *
 *   # High concurrency for large lockfiles (mind rate limits)
 *   node scripts/inspect-dependencies.js package.json --concurrency=10
 *
 *   # CI-friendly: plain text report, exit code reflects nothing (advisory only)
 *   NO_COLOR=1 node scripts/inspect-dependencies.js package.json 2>&1
 *
 *   # Force fresh data, ignoring any cached responses
 *   node scripts/inspect-dependencies.js package.json --no-cache
 *
 *   # Use a shared cache directory for multiple projects
 *   node scripts/inspect-dependencies.js package.json --cache-dir=~/.supply-chain-cache
 *
 * ─── Data sources ─────────────────────────────────────────────────────────────
 *
 *   npm Registry      https://registry.npmjs.org      metadata, scripts, maintainers
 *   OSV.dev           https://api.osv.dev/v1/query    known CVEs and advisories
 *   OpenSSF Scorecard https://api.scorecard.dev       project health (17 checks)
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from "node:fs";
import { resolve, dirname, basename, join } from "node:path";
import { fileURLToPath } from "node:url";

// Resolved path of this script file — used to anchor the default cache directory
// so the cache always lives next to inspect-dependencies.js regardless of cwd.
const _scriptDir = dirname(fileURLToPath(import.meta.url));

// ─── Constants ────────────────────────────────────────────────────────────────

const NPM_REGISTRY = "https://registry.npmjs.org";
const OSV_API = "https://api.osv.dev/v1";
const SCORECARD_API = "https://api.scorecard.dev";

// ── File-cache TTLs ───────────────────────────────────────────────────────────
// npm registry docs change when new versions are published → refresh every 6 h.
// OSV advisories are updated continuously but rarely change within an hour → 6 h.
// OpenSSF Scorecard is recomputed weekly by the OpenSSF infrastructure → 24 h.
const TTL_NPM = 6 * 60 * 60 * 1000; //  6 hours
const TTL_OSV = 6 * 60 * 60 * 1000; //  6 hours
const TTL_SCORECARD = 24 * 60 * 60 * 1000; // 24 hours

const LIFECYCLE_KEYS = [
  "preinstall",
  "install",
  "postinstall",
  "preuninstall",
  "postuninstall",
  "prepare",
  "prepack",
  "postpack",
];

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

const _npmCache = new Map(); // package name  → Promise<pkgData | null>
const _scorecardCache = new Map(); // "owner/repo"  → Promise<result>

// Simple hit counters surfaced in the run summary
const _cacheStats = { npmHits: 0, scorecardHits: 0 };

// ─── CLI argument parsing ─────────────────────────────────────────────────────

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = {
    packageJsonPath: null,
    includeDev: false,
    includePeer: false,
    includeOptional: false,
    concurrency: 5,
    versionHistory: 10, // 10 covers all threat patterns; see extractVersionHistory
    lockfilePath: null,
    output: null,
    html: null,
    json: false,
    skipScorecard: false,
    skipVulns: false,
    cacheDir: null, // null → resolved to default in main()
    noCache: false,
    includeTransitive: false,
    showFindings: false,
  };

  for (const arg of args) {
    if (arg === "--include-dev") {
      opts.includeDev = true;
      continue;
    }
    if (arg === "--include-peer") {
      opts.includePeer = true;
      continue;
    }
    if (arg === "--include-optional") {
      opts.includeOptional = true;
      continue;
    }
    if (arg === "--findings") {
      opts.showFindings = true;
      continue;
    }
    if (arg === "--include-transitive") {
      opts.includeTransitive = true;
      continue;
    }
    if (arg === "--json") {
      opts.json = true;
      continue;
    }
    if (arg === "--no-scorecard") {
      opts.skipScorecard = true;
      continue;
    }
    if (arg === "--no-vulns") {
      opts.skipVulns = true;
      continue;
    }

    if (arg.startsWith("--concurrency=")) {
      const n = parseInt(arg.split("=")[1], 10);
      if (!isNaN(n) && n > 0) opts.concurrency = n;
      continue;
    }
    if (arg.startsWith("--version-history=")) {
      const n = parseInt(arg.split("=")[1], 10);
      if (!isNaN(n) && n >= 2) opts.versionHistory = n;
      continue;
    }
    if (arg.startsWith("--lockfile=")) {
      opts.lockfilePath = arg.split("=").slice(1).join("=");
      continue;
    }
    if (arg.startsWith("--cache-dir=")) {
      opts.cacheDir = arg.split("=").slice(1).join("=");
      continue;
    }
    if (arg === "--no-cache") {
      opts.noCache = true;
      continue;
    }
    if (arg.startsWith("--output=")) {
      opts.output = arg.split("=").slice(1).join("=");
      // --output implies --json (no point writing a file with no content)
      opts.json = true;
      continue;
    }
    if (arg.startsWith("--html=")) {
      opts.html = arg.split("=").slice(1).join("=");
      continue;
    }
    if (!arg.startsWith("--")) {
      opts.packageJsonPath = arg;
    }
  }

  return opts;
}

// ─── Logging (always to stderr; stdout is reserved for --json output) ─────────

function log(msg) {
  process.stderr.write(msg + "\n");
}
function logOk(msg) {
  process.stderr.write(`  ✓ ${msg}\n`);
}
function logErr(msg) {
  process.stderr.write(`  ✗ ${msg}\n`);
}
function logWarn(msg) {
  process.stderr.write(`  ⚠ ${msg}\n`);
}

// ─── ANSI color helpers ───────────────────────────────────────────────────────
//
// Respects NO_COLOR env var (https://no-color.org) and non-TTY pipes so that
// piped JSON output and CI logs are never polluted with escape codes.

const USE_COLOR = process.stderr.isTTY === true && !process.env.NO_COLOR;

function esc(code) {
  return USE_COLOR ? `\x1b[${code}m` : "";
}

const C = {
  reset: esc(0),
  bold: esc(1),
  dim: esc(2),
  red: esc(31),
  yellow: esc(33),
  green: esc(32),
  cyan: esc(36),
  // bold/bright variants for high-severity signals
  bred: esc("1;31"),
  bgreen: esc("1;32"),
  byellow: esc("1;33"),
};

/** Visible string length — strips ANSI codes before measuring. */
function visLen(str) {
  return str.replace(/\x1b\[[0-9;]*m/g, "").length;
}

/** Right-pad `str` to `width` visible characters. */
function rpad(str, width) {
  const pad = width - visLen(str);
  return pad > 0 ? str + " ".repeat(pad) : str;
}

/** Truncate to `max` chars, adding ellipsis if cut. */
function truncate(str, max) {
  return str.length > max ? str.slice(0, max - 1) + "…" : str;
}

/** Render a 6-block scorecard bar with a numeric label.  e.g. "████░░ 6.8" */
function scorecardBar(score) {
  if (score === null || score === undefined) return `${C.dim}─ n/a  ${C.reset}`;
  const filled = Math.round((score / 10) * 6);
  const bar = "█".repeat(filled) + "░".repeat(6 - filled);
  const color = score < 3 ? C.red : score < 5 ? C.yellow : C.green;
  return `${color}${bar}${C.reset} ${score.toFixed(1)}`;
}

/** Short vulnerability summary for the table column. */
function vulnCell(vulns) {
  const s = vulns?.summary;
  if (!s || s.total === 0) return `${C.dim}─${C.reset}`;
  if (s.critical > 0) return `${C.bred}${s.total} CRITICAL${C.reset}`;
  if (s.high > 0) return `${C.red}${s.total} HIGH${C.reset}`;
  if (s.medium > 0) return `${C.yellow}${s.total} MEDIUM${C.reset}`;
  return `${C.dim}${s.total} LOW${C.reset}`;
}

/** Fixed-width severity badge for the findings list. */
function sevBadge(sev) {
  switch ((sev ?? "").toUpperCase()) {
    case "CRITICAL":
      return `${C.bred}[CRITICAL]${C.reset}`;
    case "HIGH":
      return `${C.red}[HIGH    ]${C.reset}`;
    case "MEDIUM":
      return `${C.yellow}[MEDIUM  ]${C.reset}`;
    case "LOW":
      return `${C.dim}[LOW     ]${C.reset}`;
    default:
      return `${C.dim}[UNKNOWN ]${C.reset}`;
  }
}

/**
 * Parse a package-lock.json and return every installed package (direct + transitive)
 * as an array of { name, version }, deduplicated by name@version.
 *
 * Handles:
 *   v2/v3 (packages field) — flat map; nested installs appear as
 *     "node_modules/foo/node_modules/bar" so we extract the innermost name.
 *   v1 (dependencies field) — recursive tree; we traverse it depth-first.
 *
 * The same package at the same version installed in multiple locations is
 * returned only once (deduplicated by "name@version").  The same package at
 * different versions (e.g. two consumers requiring incompatible ranges) produces
 * one entry per distinct version.
 */
function loadAllLockfilePackages(lockfilePath) {
  if (!lockfilePath || !existsSync(lockfilePath)) return [];

  try {
    const raw = readFileSync(lockfilePath, "utf8");
    const lock = JSON.parse(raw);
    // Key: "name@version" — ensures one entry per distinct package+version pair.
    const seen = new Map();

    if (lock.packages && typeof lock.packages === "object") {
      // v2 / v3: flat map of every node_modules path in the install tree.
      for (const [pkgPath, pkgMeta] of Object.entries(lock.packages)) {
        if (!pkgPath || !pkgPath.startsWith("node_modules/")) continue;
        if (!pkgMeta.version) continue;

        // Extract the innermost package name regardless of nesting depth by
        // slicing from the last occurrence of "node_modules/":
        //   "node_modules/foo"                     → "foo"
        //   "node_modules/@scope/foo"              → "@scope/foo"
        //   "node_modules/foo/node_modules/bar"    → "bar"
        //   "node_modules/foo/node_modules/@s/bar" → "@s/bar"
        //
        // Splitting on "/node_modules/" (with leading slash) fails for the
        // top-level case because the string starts with "node_modules/" (no
        // leading slash), leaving the whole path as the only segment.
        // lastIndexOf handles all depths uniformly.
        const lastNm = pkgPath.lastIndexOf("node_modules/");
        const name = pkgPath.slice(lastNm + "node_modules/".length);
        const key = `${name}@${pkgMeta.version}`;
        if (!seen.has(key)) seen.set(key, { name, version: pkgMeta.version });
      }
    } else if (lock.dependencies && typeof lock.dependencies === "object") {
      // v1: recursive tree — each node may have its own nested `dependencies`.
      function traverse(deps) {
        for (const [name, meta] of Object.entries(deps)) {
          if (meta.version) {
            const key = `${name}@${meta.version}`;
            if (!seen.has(key)) seen.set(key, { name, version: meta.version });
          }
          if (meta.dependencies && typeof meta.dependencies === "object") {
            traverse(meta.dependencies);
          }
        }
      }
      traverse(lock.dependencies);
    }

    return Array.from(seen.values());
  } catch (err) {
    logWarn(`Could not load transitive packages from lockfile: ${err.message}`);
    return [];
  }
}

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

let _cacheDir = null; // set in main() after CLI args are parsed
const _fileCacheStats = { hits: 0, writes: 0 };

/**
 * Sanitise an arbitrary string for use as a filename component.
 *   @babel/core  →  babel__core
 *   1.2.3-beta.1 →  1.2.3-beta.1   (dots/hyphens are fine)
 */
function safeName(str) {
  return String(str)
    .replace(/^@/, "") // strip leading @ from scoped packages
    .replace(/\//g, "__") // @scope/name → scope__name
    .replace(/:/g, "_"); // guard against any colons
}

/**
 * Read a cached value.  Returns the stored data or null if the entry is
 * absent, unreadable, or older than `ttlMs` milliseconds.
 */
function readFromCache(key, ttlMs) {
  if (!_cacheDir) return null;
  const file = join(_cacheDir, `${key}.json`);
  if (!existsSync(file)) return null;
  try {
    const { cachedAt, data } = JSON.parse(readFileSync(file, "utf8"));
    if (Date.now() - new Date(cachedAt).getTime() > ttlMs) return null;
    _fileCacheStats.hits++;
    return data;
  } catch {
    return null; // corrupt or unreadable — treat as cache miss
  }
}

/**
 * Write a value to the cache.  Errors are logged as warnings but never thrown
 * so a non-writable cache directory never breaks the main analysis.
 */
function writeToCache(key, data) {
  if (!_cacheDir) return;
  try {
    writeFileSync(
      join(_cacheDir, `${key}.json`),
      JSON.stringify({ cachedAt: new Date().toISOString(), data }, null, 2),
      "utf8",
    );
    _fileCacheStats.writes++;
  } catch (err) {
    logWarn(`Cache write failed for ${key}: ${err.message}`);
  }
}

// ─── Lockfile parsing (package-lock.json v1/v2/v3) ───────────────────────────

/**
 * Parse lockfile data object and return a Map of { packageName -> resolvedVersion }.
 * Only stores the top-level (non-nested) entry for each name, which is the version
 * that the project itself directly depends on.
 * Supports lockfile formats v1 (dependencies), v2/v3 (packages).
 */
function parseLockfileVersions(lock) {
  const versions = new Map();

  // v2 / v3 format: lock.packages is a flat map of node_modules paths
  if (lock.packages && typeof lock.packages === "object") {
    for (const [pkgPath, pkgMeta] of Object.entries(lock.packages)) {
      if (!pkgPath.startsWith("node_modules/")) continue;
      if (!pkgMeta.version) continue;
      // Strip the leading "node_modules/" (handles nested: node_modules/a/node_modules/b)
      const name = pkgPath.replace(/^node_modules\//, "");
      // Only store the top-level entry (no nesting slash after scope slash)
      const parts = name.split("/");
      const topName = parts[0].startsWith("@")
        ? `${parts[0]}/${parts[1]}`
        : parts[0];
      if (!versions.has(topName)) {
        versions.set(topName, pkgMeta.version);
      }
    }
    return versions;
  }

  // v1 format: lock.dependencies is a nested tree
  if (lock.dependencies && typeof lock.dependencies === "object") {
    for (const [name, pkgMeta] of Object.entries(lock.dependencies)) {
      if (pkgMeta.version) {
        versions.set(name, pkgMeta.version);
      }
    }
    return versions;
  }

  return versions;
}

/**
 * Load and parse a package-lock.json from a file path.
 * Returns a Map of { packageName -> resolvedVersion }.
 */
function loadLockfileVersions(lockfilePath) {
  if (!lockfilePath || !existsSync(lockfilePath)) return new Map();

  try {
    const raw = readFileSync(lockfilePath, "utf8");
    const lock = JSON.parse(raw);
    return parseLockfileVersions(lock);
  } catch (err) {
    logWarn(`Failed to parse lockfile at ${lockfilePath}: ${err.message}`);
    return new Map();
  }
}

/**
 * Load all packages from a lockfile (for --include-transitive).
 * Reads from file path only (not used for remote lockfiles yet).
 */
function loadAllLockfilePackagesFromData(lock) {
  const versions = new Map();

  // v2 / v3 format: lock.packages is a flat map of node_modules paths
  if (lock.packages && typeof lock.packages === "object") {
    for (const [pkgPath, pkgMeta] of Object.entries(lock.packages)) {
      if (!pkgPath.startsWith("node_modules/")) continue;
      if (!pkgMeta.version) continue;
      const name = pkgPath.replace(/^node_modules\//, "");
      const parts = name.split("/");
      const topName = parts[0].startsWith("@")
        ? `${parts[0]}/${parts[1]}`
        : parts[0];
      if (!versions.has(topName)) {
        versions.set(topName, pkgMeta.version);
      }
    }
    return Array.from(versions.entries()).map(([name, version]) => ({
      name,
      version,
    }));
  }

  // v1 format: need to traverse the tree
  const seen = new Set();
  function traverse(deps) {
    if (!deps || typeof deps !== "object") return;
    for (const [name, pkgMeta] of Object.entries(deps)) {
      const key = `${name}@${pkgMeta.version}`;
      if (!seen.has(key) && pkgMeta.version) {
        seen.add(key);
        versions.set(name, pkgMeta.version);
      }
      if (pkgMeta.dependencies) {
        traverse(pkgMeta.dependencies);
      }
    }
  }
  traverse(lock.dependencies);

  return Array.from(versions.entries()).map(([name, version]) => ({
    name,
    version,
  }));
}

/**
 * Load all packages from a lockfile file path (for --include-transitive).
 */
function loadAllLockfilePackages(lockfilePath) {
  if (!lockfilePath || !existsSync(lockfilePath)) return [];

  try {
    const raw = readFileSync(lockfilePath, "utf8");
    const lock = JSON.parse(raw);
    return loadAllLockfilePackagesFromData(lock);
  } catch (err) {
    logWarn(`Could not parse lockfile: ${err.message}`);
    return [];
  }
}

// ─── Version spec helpers ─────────────────────────────────────────────────────

/**
 * Strip semver range operators (^, ~, >=, etc.) to get a bare version string.
 * Returns null if the spec is not a usable pinned-style version (e.g. "latest", "*", file:, git:).
 */
function stripRangeOperators(spec) {
  if (!spec || typeof spec !== "string") return null;

  const trimmed = spec.trim();

  // Non-registry specs — skip
  if (
    trimmed === "*" ||
    trimmed === "" ||
    trimmed === "latest" ||
    trimmed === "x" ||
    trimmed.startsWith("http") ||
    trimmed.startsWith("git") ||
    trimmed.startsWith("file:") ||
    trimmed.startsWith("link:") ||
    trimmed.startsWith("workspace:") ||
    trimmed.includes(" ") // ranges like ">=1.0.0 <2.0.0"
  )
    return null;

  const stripped = trimmed.replace(/^[~^>=<]+/, "").trim();

  // Must start with a digit to be a version
  if (!/^\d/.test(stripped)) return null;

  return stripped;
}

// ─── npm Registry client ──────────────────────────────────────────────────────

/**
 * Fetch full package document from npm registry.
 * Handles scoped packages correctly (@scope/name).
 * Results are deduplicated: concurrent callers for the same package name share
 * one in-flight request.
 */
function fetchNpmPackage(name) {
  if (_npmCache.has(name)) {
    _cacheStats.npmHits++;
    return _npmCache.get(name);
  }
  const promise = _doFetchNpmPackage(name);
  _npmCache.set(name, promise);
  return promise;
}

async function _doFetchNpmPackage(name) {
  const cacheKey = `npm_${safeName(name)}`;
  const cached = readFromCache(cacheKey, TTL_NPM);
  if (cached) return cached;

  // npm registry requires scoped package names to be URL-encoded as %40scope%2Fname
  const encoded = name.startsWith("@")
    ? `@${encodeURIComponent(name.slice(1))}` // preserve leading @, encode the rest
    : encodeURIComponent(name);

  const url = `${NPM_REGISTRY}/${encoded}`;

  try {
    const res = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(15_000),
    });
    if (res.status === 404) return null;
    if (!res.ok) {
      logErr(`npm registry ${res.status} for ${name}`);
      return null;
    }
    const data = await res.json();
    writeToCache(cacheKey, data);
    return data;
  } catch (err) {
    logErr(`npm fetch failed for ${name}: ${err.message}`);
    return null;
  }
}

/**
 * Given full package data from the registry, resolve the best concrete version to analyze.
 * Priority: lockfile > exact spec match > dist-tag "latest" > newest version.
 */
function resolveVersion(pkgData, versionSpec, lockfileVersion) {
  if (!pkgData) return stripRangeOperators(versionSpec) || null;

  // Lockfile is the most accurate — use it first
  if (lockfileVersion && pkgData.versions?.[lockfileVersion])
    return lockfileVersion;

  // Exact version in the registry
  const stripped = stripRangeOperators(versionSpec);
  if (stripped && pkgData.versions?.[stripped]) return stripped;

  // dist-tags (e.g. "latest")
  const distTag =
    pkgData["dist-tags"]?.[versionSpec] || pkgData["dist-tags"]?.latest;
  if (distTag && pkgData.versions?.[distTag]) return distTag;

  // Fallback: newest version key in the registry doc
  const allVersions = Object.keys(pkgData.versions || {});
  if (allVersions.length > 0) return allVersions[allVersions.length - 1];

  return null;
}

/**
 * Extract security-relevant metadata for a specific version from the registry doc.
 */
function extractVersionMetadata(pkgData, version) {
  if (!pkgData || !version) return null;
  const vd = pkgData.versions?.[version];
  if (!vd) return null;

  const publishDate = pkgData.time?.[version] || null;
  const publishedMs = publishDate
    ? Date.now() - new Date(publishDate).getTime()
    : null;

  // Lifecycle scripts
  const lifecycleScripts = {};
  for (const key of LIFECYCLE_KEYS) {
    if (vd.scripts?.[key]) lifecycleScripts[key] = vd.scripts[key];
  }

  // Maintainers (prefer version-level, fall back to package-level)
  const rawMaintainers = vd.maintainers || pkgData.maintainers || [];
  const maintainers = rawMaintainers.map((m) =>
    typeof m === "string" ? m : m.name,
  );

  return {
    name: pkgData.name,
    version,
    publishDate,
    publishedHoursAgo:
      publishedMs !== null ? Math.floor(publishedMs / 3_600_000) : null,
    publisher: vd._npmUser?.name ?? null,
    maintainers,
    lifecycleScripts,
    hasInstallScripts: Object.keys(lifecycleScripts).length > 0,
    repository: normalizeRepoUrl(vd.repository ?? pkgData.repository),
    homepage: vd.homepage ?? pkgData.homepage ?? null,
    license: vd.license ?? pkgData.license ?? null,
    directDependencies: Object.keys(vd.dependencies ?? {}),
    dependencyCount: Object.keys(vd.dependencies ?? {}).length,
    devDependencyCount: Object.keys(vd.devDependencies ?? {}).length,
    peerDependencyCount: Object.keys(vd.peerDependencies ?? {}).length,
    unpackedSize: vd.dist?.unpackedSize ?? null,
    integrity: vd.dist?.integrity ?? null,
    tarball: vd.dist?.tarball ?? null,
  };
}

/**
 * Extract chronological version history from the registry doc.
 *
 * How many versions are needed per threat type:
 *   ≥ 2  — downgrade / major-version jump (just need current vs. previous)
 *   ≥ 5  — rapid successive publishes (need to see the burst window)
 *   ≥ 5  — dormancy then sudden publish: slice(-N) takes the *newest* N entries,
 *           so the old pre-gap version and the suspicious new one are both visible
 *           even with only 5 entries, as long as the package wasn't prolific.
 *   ≥ 10 — cadence baseline (enough history to spot anomalies against a normal
 *           rhythm); also matches the "VERSION HISTORY (last 10)" contract in
 *           the AI analysis prompt (scripts/prompts/analysis-prompt.md).
 *
 * Default: 10.  Values below 2 are rejected by the CLI parser.
 *
 * @param {object} pkgData - Full npm registry package document
 * @param {number} [limit=10] - How many of the most-recent versions to keep
 */
function extractVersionHistory(pkgData, limit = 10) {
  if (!pkgData?.time) return [];

  return Object.entries(pkgData.time)
    .filter(([key]) => key !== "created" && key !== "modified")
    .map(([version, date]) => ({ version, date }))
    .sort((a, b) => new Date(a.date) - new Date(b.date))
    .slice(-limit);
}

/**
 * Extract the first 3 versions of the current publisher (for new publisher detection).
 */
function extractPublisherHistory(pkgData, currentPublisher) {
  if (!pkgData?.versions || !currentPublisher) return [];

  const history = [];
  for (const [ver, vd] of Object.entries(pkgData.versions)) {
    const pub = vd._npmUser?.name;
    if (pub) history.push({ version: ver, publisher: pub });
  }

  // Return last 5 publish events sorted by when they appear in the registry
  return history.slice(-5);
}

function normalizeRepoUrl(repo) {
  if (!repo) return null;
  const raw = typeof repo === "string" ? repo : (repo.url ?? null);
  if (!raw) return null;
  return raw
    .replace(/^git\+/, "")
    .replace(/^git:\/\/github\.com/, "https://github.com")
    .replace(/^ssh:\/\/git@github\.com/, "https://github.com")
    .replace(/\.git$/, "");
}

// ─── OSV.dev vulnerability client ────────────────────────────────────────────

/**
 * Query OSV.dev for known vulnerabilities for a specific package version.
 * @returns {{ summary: object, list: Array }}
 */
async function fetchVulnerabilities(name, version, ecosystem = "npm") {
  const cacheKey = `osv_${safeName(name)}_${safeName(version)}`;
  const cached = readFromCache(cacheKey, TTL_OSV);
  if (cached) return cached;

  const empty = {
    summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
    list: [],
    error: null,
  };

  try {
    const res = await fetch(`${OSV_API}/query`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ version, package: { name, ecosystem } }),
      signal: AbortSignal.timeout(15_000),
    });

    if (!res.ok) {
      logErr(`OSV ${res.status} for ${name}@${version}`);
      return { ...empty, error: `osv_${res.status}` };
    }

    const data = await res.json();
    const vulns = data.vulns || [];

    const summary = {
      total: vulns.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0,
    };
    const list = vulns.map((v) => {
      const severity = classifyCvssSeverity(v);
      summary[severity.toLowerCase()]++;
      return {
        id: v.id,
        summary: v.summary ?? "No summary available",
        severity,
        aliases: v.aliases ?? [],
        published: v.published ?? null,
        modified: v.modified ?? null,
        references: (v.references ?? []).slice(0, 3).map((r) => r.url),
        affectedRanges: extractAffectedRanges(v),
      };
    });

    // Sort by severity descending
    const severityOrder = {
      CRITICAL: 0,
      HIGH: 1,
      MEDIUM: 2,
      LOW: 3,
      UNKNOWN: 4,
    };
    list.sort(
      (a, b) =>
        (severityOrder[a.severity] ?? 99) - (severityOrder[b.severity] ?? 99),
    );

    const result = { summary, list, error: null };
    writeToCache(cacheKey, result);
    return result;
  } catch (err) {
    logErr(`OSV query failed for ${name}@${version}: ${err.message}`);
    return { ...empty, error: err.message };
  }
}

function classifyCvssSeverity(vuln) {
  // Try CVSS v4 or v3 score
  for (const s of vuln.severity ?? []) {
    if (s.type === "CVSS_V4" || s.type === "CVSS_V3") {
      const score = parseCvssVector(s.score);
      if (score >= 9.0) return "CRITICAL";
      if (score >= 7.0) return "HIGH";
      if (score >= 4.0) return "MEDIUM";
      return "LOW";
    }
  }
  // Fall back to database_specific.severity (e.g. GitHub Advisory)
  const db = vuln.database_specific?.severity;
  if (db) return db.toUpperCase();
  return "UNKNOWN";
}

function parseCvssVector(cvssVector) {
  if (typeof cvssVector === "number") return cvssVector;
  if (typeof cvssVector !== "string") return 5.0;
  // Heuristic extraction from CVSS vector — no full parser needed
  // Network-accessible, no privileges, full impact → near-max
  if (cvssVector.includes("/AV:N/") && cvssVector.includes("/PR:N/")) {
    if (cvssVector.includes("/C:H/I:H/A:H")) return 9.8;
    if (
      cvssVector.includes("/C:H/") ||
      cvssVector.includes("/I:H/") ||
      cvssVector.includes("/A:H/")
    )
      return 8.0;
    return 7.0;
  }
  if (cvssVector.includes("/AV:N/")) return 6.5;
  return 5.0;
}

function extractAffectedRanges(vuln) {
  const ranges = [];
  for (const affected of vuln.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      const introduced = range.events?.find((e) => e.introduced)?.introduced;
      const fixed = range.events?.find((e) => e.fixed)?.fixed;
      if (introduced || fixed) {
        ranges.push({ introduced: introduced ?? null, fixed: fixed ?? null });
      }
    }
  }
  return ranges.slice(0, 5);
}

// ─── OpenSSF Scorecard client ─────────────────────────────────────────────────

/**
 * Parse a GitHub repository URL (in any common format) into { owner, repo }.
 */
function parseGitHubUrl(url) {
  if (!url || typeof url !== "string") return null;

  const cleaned = url
    .replace(/^git\+/, "")
    .replace(/^git:\/\//, "https://")
    .replace(/^ssh:\/\/git@github\.com/, "https://github.com")
    .replace(/\.git$/, "")
    .trim();

  const match = cleaned.match(/github\.com[/:]([^/\s]+)\/([^/?\s#]+)/);
  if (!match) return null;

  return { owner: match[1], repo: match[2] };
}

/**
 * Fetch the OpenSSF Scorecard for a repository identified by its URL.
 * Results are deduplicated by normalized "owner/repo" key: all packages that
 * share a monorepo (e.g. every @babel/* package → babel/babel) make exactly
 * one HTTP request regardless of how many are processed concurrently.
 * @param {string} repoUrl - Repository URL from npm registry metadata
 * @returns {Promise<object>}
 */
function fetchScorecard(repoUrl) {
  const notAvailable = {
    score: null,
    checks: [],
    signals: {},
    error: "not_github_repo",
  };

  const parsed = parseGitHubUrl(repoUrl);
  if (!parsed) return Promise.resolve(notAvailable);

  // Normalise to lowercase so "Babel/Babel" and "babel/babel" share one entry
  const cacheKey = `${parsed.owner}/${parsed.repo}`.toLowerCase();

  if (_scorecardCache.has(cacheKey)) {
    _cacheStats.scorecardHits++;
    return _scorecardCache.get(cacheKey);
  }

  const promise = _doFetchScorecard(parsed);
  _scorecardCache.set(cacheKey, promise);
  return promise;
}

async function _doFetchScorecard(parsed) {
  const cacheKey =
    `scorecard_${safeName(parsed.owner)}__${safeName(parsed.repo)}`.toLowerCase();
  const cached = readFromCache(cacheKey, TTL_SCORECARD);
  if (cached) return cached;

  const notAvailable = {
    score: null,
    checks: [],
    signals: {},
    error: "not_github_repo",
  };
  const url = `${SCORECARD_API}/projects/github.com/${parsed.owner}/${parsed.repo}`;

  try {
    const res = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(15_000),
    });

    if (res.status === 404)
      return { ...notAvailable, error: "scorecard_not_found" };
    if (!res.ok) {
      logWarn(`Scorecard API ${res.status} for ${parsed.owner}/${parsed.repo}`);
      return { ...notAvailable, error: `scorecard_api_${res.status}` };
    }

    const data = await res.json();

    const checks = (data.checks ?? []).map((c) => ({
      name: c.name,
      score: c.score, // 0-10 or -1 if not applicable
      reason: c.reason ?? null,
    }));

    // Build a flat signals object for easy AI consumption
    const checkMap = new Map(checks.map((c) => [c.name, c.score]));
    const signals = {
      maintained: checkMap.get("Maintained") ?? null,
      codeReview: checkMap.get("Code-Review") ?? null,
      vulnerabilities: checkMap.get("Vulnerabilities") ?? null,
      signedReleases: checkMap.get("Signed-Releases") ?? null,
      branchProtection: checkMap.get("Branch-Protection") ?? null,
      securityPolicy: checkMap.get("Security-Policy") ?? null,
      dangerousWorkflow: checkMap.get("Dangerous-Workflow") ?? null,
      binaryArtifacts: checkMap.get("Binary-Artifacts") ?? null,
      pinned: checkMap.get("Pinned-Dependencies") ?? null,
      ciTests: checkMap.get("CI-Tests") ?? null,
    };

    const result = {
      score: data.score ?? null,
      checks,
      signals,
      repoChecked: `github.com/${parsed.owner}/${parsed.repo}`,
      error: null,
    };
    writeToCache(cacheKey, result);
    return result;
  } catch (err) {
    logWarn(
      `Scorecard fetch failed for ${parsed.owner}/${parsed.repo}: ${err.message}`,
    );
    return { ...notAvailable, error: err.message };
  }
}

// ─── Concurrency limiter ──────────────────────────────────────────────────────

/**
 * Run an array of async task functions with a max concurrency.
 * Returns results in the same order as the input tasks.
 */
async function runWithConcurrency(tasks, concurrency) {
  const results = new Array(tasks.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < tasks.length) {
      const i = nextIndex++;
      results[i] = await tasks[i]();
    }
  }

  const workers = Array.from(
    { length: Math.min(concurrency, tasks.length) },
    () => worker(),
  );
  await Promise.all(workers);
  return results;
}

// ─── Per-package analysis ─────────────────────────────────────────────────────

/**
 * Collect all security-relevant data for a single npm package.
 */
async function inspectPackage(
  { name, versionSpec, scope },
  lockfileVersion,
  opts,
) {
  log(`  → ${name}  (${versionSpec})`);

  // ── Step 1: npm registry ────────────────────────────────────────────────────
  const pkgData = await fetchNpmPackage(name);

  if (!pkgData) {
    logWarn(`  Package not found on npm registry: ${name}`);
    return buildNotFoundResult(name, versionSpec, scope, lockfileVersion);
  }

  // ── Step 2: Version resolution ──────────────────────────────────────────────
  const resolvedVersion = resolveVersion(pkgData, versionSpec, lockfileVersion);

  if (!resolvedVersion) {
    logWarn(`  Could not resolve version for ${name} (spec: ${versionSpec})`);
  }

  // ── Step 3: Extract metadata ────────────────────────────────────────────────
  const registryMeta = extractVersionMetadata(pkgData, resolvedVersion);
  const versionHistory = extractVersionHistory(pkgData, opts.versionHistory);
  const publisherHistory = extractPublisherHistory(
    pkgData,
    registryMeta?.publisher,
  );

  const sourceRepo = registryMeta?.repository ?? null;

  // ── Step 4: Parallel — OSV vulnerabilities + Scorecard ─────────────────────
  const [vulnerabilities, scorecard] = await Promise.all([
    resolvedVersion && !opts.skipVulns
      ? fetchVulnerabilities(name, resolvedVersion, "npm")
      : Promise.resolve({
          summary: {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            unknown: 0,
          },
          list: [],
          error: "skipped",
        }),
    sourceRepo && !opts.skipScorecard
      ? fetchScorecard(sourceRepo)
      : Promise.resolve({
          score: null,
          checks: [],
          signals: {},
          error: sourceRepo ? "skipped" : "no_source_repo",
        }),
  ]);

  const vulnCount = vulnerabilities.summary.total;
  const scScore = scorecard.score;
  const vulnPart =
    vulnCount > 0
      ? `vulns: ${vulnerabilities.summary.critical > 0 ? C.bred : vulnerabilities.summary.high > 0 ? C.red : C.yellow}${vulnCount}${C.reset}`
      : `vulns: ${C.dim}0${C.reset}`;
  const scPart =
    scScore === null
      ? `scorecard: ${C.dim}n/a${C.reset}`
      : `scorecard: ${scScore < 3 ? C.red : scScore < 5 ? C.yellow : C.green}${scScore}${C.reset}`;
  logOk(`${name}@${resolvedVersion ?? "?"}  —  ${vulnPart}  ${scPart}`);

  return {
    name,
    versionSpec,
    resolvedVersion: resolvedVersion ?? null,
    lockfileVersion: lockfileVersion ?? null,
    scope,
    ecosystem: "npm",
    sourceRepository: sourceRepo,
    notFound: false,
    registry: registryMeta,
    versionHistory,
    publisherHistory,
    vulnerabilities,
    scorecard,
    collectedAt: new Date().toISOString(),
  };
}

/**
 * Build a minimal result entry for packages that could not be found on npm.
 * Still useful for the AI — a missing package can itself be a signal.
 */
function buildNotFoundResult(name, versionSpec, scope, lockfileVersion) {
  return {
    name,
    versionSpec,
    resolvedVersion:
      stripRangeOperators(versionSpec) ?? lockfileVersion ?? null,
    lockfileVersion: lockfileVersion ?? null,
    scope,
    ecosystem: "npm",
    sourceRepository: null,
    notFound: true,
    registry: null,
    versionHistory: [],
    publisherHistory: [],
    vulnerabilities: {
      summary: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0,
      },
      list: [],
      error: "package_not_found",
    },
    scorecard: {
      score: null,
      checks: [],
      signals: {},
      error: "package_not_found",
    },
    collectedAt: new Date().toISOString(),
  };
}

// ─── HTML report ──────────────────────────────────────────────────────────────

/**
 * Generate a fully self-contained HTML security report (no external dependencies).
 * Includes a summary table and collapsible per-package detail sections.
 *
 * @param {Array}  results  Output of inspectPackage for every dependency
 * @param {object} pkg      Parsed package.json of the scanned project
 * @returns {string}        Complete HTML document as a string
 */
function generateHtmlReport(results, pkg) {
  const pkgLabel =
    `${pkg.name ?? "(unnamed)"}` + (pkg.version ? `@${pkg.version}` : "");

  // Classify each result into its security signals — mirrors printReport logic
  const annotated = results.map((r) => {
    const signals = [];
    if (r.notFound) signals.push("not_found");
    if ((r.vulnerabilities?.summary?.total ?? 0) > 0) signals.push("vulns");
    if (r.registry?.hasInstallScripts) signals.push("scripts");
    if (
      r.scorecard?.score !== null &&
      r.scorecard?.score !== undefined &&
      r.scorecard.score < 5
    )
      signals.push("low_scorecard");
    if ((r.registry?.publishedHoursAgo ?? Infinity) < 48)
      signals.push("very_recent");
    if (!r.sourceRepository && !r.notFound) signals.push("no_repo");
    return { r, signals };
  });

  const findings = annotated.filter((a) => a.signals.length > 0);

  const totals = results.reduce(
    (acc, r) => {
      const s = r.vulnerabilities?.summary ?? {};
      acc.critical += s.critical ?? 0;
      acc.high += s.high ?? 0;
      acc.medium += s.medium ?? 0;
      acc.low += s.low ?? 0;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0 },
  );

  const cleanCount = results.length - findings.length;
  const generatedAt = new Date().toUTCString();

  /** Format a date string safely, returning a fallback if the value is invalid. */
  function safeDate(value, fallback = "—") {
    if (!value) return fallback;
    const dt = new Date(value);
    return isNaN(dt.getTime()) ? fallback : dt.toISOString().slice(0, 10);
  }

  /** Escape a value for safe embedding in HTML. */
  function he(s) {
    return String(s ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function vulnBadgeHtml(summary) {
    if (!summary || summary.total === 0)
      return '<span class="badge clean">─</span>';
    if (summary.critical > 0)
      return `<span class="badge critical">${summary.total} CRITICAL</span>`;
    if (summary.high > 0)
      return `<span class="badge high">${summary.total} HIGH</span>`;
    if (summary.medium > 0)
      return `<span class="badge medium">${summary.total} MEDIUM</span>`;
    return `<span class="badge low">${summary.total} LOW</span>`;
  }

  function scorecardHtml(score) {
    if (score === null || score === undefined)
      return '<span class="sc-na">─ n/a</span>';
    const pct = Math.round((score / 10) * 100);
    const cls = score < 3 ? "sc-low" : score < 5 ? "sc-med" : "sc-high";
    return (
      `<span class="sc-bar ${cls}"><span class="sc-fill" style="width:${pct}%"></span></span>` +
      ` <span class="sc-score ${cls}">${score.toFixed(1)}</span>`
    );
  }

  function sevBadgeHtml(sev) {
    const cls = (sev ?? "unknown").toLowerCase();
    return `<span class="sev-badge ${cls}">${he(sev ?? "UNKNOWN")}</span>`;
  }

  // ── Per-package table rows ─────────────────────────────────────────────────
  const tableRows = annotated
    .map(({ r, signals }) => {
      const ver = r.resolvedVersion ?? r.versionSpec ?? "?";
      const hasFindings = signals.length > 0;
      const rowClass = r.notFound
        ? "row-not-found"
        : hasFindings
          ? "row-findings"
          : "row-clean";

      const nameHtml = hasFindings
        ? `<a href="#pkg-${he(r.name)}" class="pkg-link">${he(r.name)}</a>`
        : he(r.name);

      const scriptHtml = r.registry?.hasInstallScripts
        ? '<span class="badge scripts">&#x26A0; yes</span>'
        : '<span class="badge clean">─</span>';

      const repoHtml = r.sourceRepository
        ? `<a href="${he(r.sourceRepository)}" target="_blank" rel="noopener" class="repo-link" title="${he(r.sourceRepository)}">&#x2197;</a>`
        : '<span class="dim">─</span>';

      return (
        `        <tr class="${rowClass}">\n` +
        `          <td class="td-name">${nameHtml}</td>\n` +
        `          <td class="td-ver"><code>${he(ver)}</code></td>\n` +
        `          <td class="td-scope"><span class="scope">${he(r.scope ?? "")}</span></td>\n` +
        `          <td class="td-vuln">${vulnBadgeHtml(r.vulnerabilities?.summary)}</td>\n` +
        `          <td class="td-sc">${scorecardHtml(r.scorecard?.score ?? null)}</td>\n` +
        `          <td class="td-scripts">${scriptHtml}</td>\n` +
        `          <td class="td-repo">${repoHtml}</td>\n` +
        `        </tr>`
      );
    })
    .join("\n");

  // ── Collapsible per-package finding cards ─────────────────────────────────
  const findingCards = findings
    .map(({ r, signals }) => {
      const ver = r.resolvedVersion ?? r.versionSpec ?? "?";

      const chips = [];
      if (signals.includes("vulns")) {
        const s = r.vulnerabilities.summary;
        const cls =
          s.critical > 0
            ? "critical"
            : s.high > 0
              ? "high"
              : s.medium > 0
                ? "medium"
                : "low";
        chips.push(
          `<span class="chip ${cls}">${s.total} vuln${s.total !== 1 ? "s" : ""}</span>`,
        );
      }
      if (signals.includes("scripts"))
        chips.push('<span class="chip scripts">install scripts</span>');
      if (signals.includes("low_scorecard"))
        chips.push(
          `<span class="chip scorecard">Scorecard ${r.scorecard.score.toFixed(1)}/10</span>`,
        );
      if (signals.includes("very_recent"))
        chips.push(
          `<span class="chip recent">published ${r.registry.publishedHoursAgo}h ago</span>`,
        );
      if (signals.includes("not_found"))
        chips.push('<span class="chip not-found">not found on registry</span>');
      if (signals.includes("no_repo"))
        chips.push('<span class="chip no-repo">no source repo</span>');

      let body = "";

      // ── Vulnerabilities ──────────────────────────────────────────────────
      if (signals.includes("vulns")) {
        const list = r.vulnerabilities.list ?? [];
        const items = list
          .map((v) => {
            const fix = v.affectedRanges?.find((rng) => rng.fixed);
            const aliases = v.aliases?.length
              ? ` <span class="aliases">${v.aliases.map(he).join(", ")}</span>`
              : "";
            const refs = (v.references ?? [])
              .map(
                (url) =>
                  `<a href="${he(url)}" target="_blank" rel="noopener">${he(url)}</a>`,
              )
              .join(" ");
            return (
              `              <li class="vuln-item ${(v.severity ?? "unknown").toLowerCase()}">\n` +
              `                <div class="vuln-header">${sevBadgeHtml(v.severity)} <strong>${he(v.id)}</strong>${aliases}</div>\n` +
              `                <div class="vuln-summary">${he(v.summary)}</div>\n` +
              (fix
                ? `                <div class="vuln-fix">Fix available: <code>${he(fix.fixed)}</code></div>\n`
                : "") +
              (refs
                ? `                <div class="vuln-refs">${refs}</div>\n`
                : "") +
              `              </li>`
            );
          })
          .join("\n");
        body +=
          `\n          <div class="detail-section">\n` +
          `            <h4>Vulnerabilities (${list.length})</h4>\n` +
          `            <ul class="vuln-list">\n${items}\n            </ul>\n` +
          `          </div>`;
      }

      // ── Install scripts ───────────────────────────────────────────────────
      if (signals.includes("scripts")) {
        const scripts = Object.entries(r.registry?.lifecycleScripts ?? {});
        const items = scripts
          .map(
            ([key, cmd]) =>
              `              <li><code class="script-key">${he(key)}</code>` +
              `<span class="script-cmd">${he(cmd)}</span></li>`,
          )
          .join("\n");
        body +=
          `\n          <div class="detail-section">\n` +
          `            <h4>Install Scripts (${scripts.length})</h4>\n` +
          `            <ul class="script-list">\n${items}\n            </ul>\n` +
          `          </div>`;
      }

      // ── Low Scorecard checks ──────────────────────────────────────────────
      if (signals.includes("low_scorecard")) {
        const bad = (r.scorecard.checks ?? [])
          .filter((chk) => typeof chk.score === "number" && chk.score < 5)
          .sort((a, b) => a.score - b.score)
          .slice(0, 8);
        const items = bad
          .map((chk) => {
            const score = chk.score === -1 ? "N/A" : `${chk.score}/10`;
            const reason = chk.reason
              ? ` <span class="sc-check-reason">&#x2014; ${he(chk.reason)}</span>`
              : "";
            return (
              `              <li>` +
              `<span class="sc-check-name">${he(chk.name)}</span>` +
              `<span class="sc-check-score">${score}</span>${reason}</li>`
            );
          })
          .join("\n");
        body +=
          `\n          <div class="detail-section">\n` +
          `            <h4>Low Scorecard Checks</h4>\n` +
          `            <ul class="scorecard-list">\n${items}\n            </ul>\n` +
          `          </div>`;
      }

      // ── Version history ───────────────────────────────────────────────────
      if ((r.versionHistory?.length ?? 0) > 0) {
        const items = [...r.versionHistory]
          .reverse()
          .slice(0, 10)
          .map((vh) => {
            const d = safeDate(vh.date);
            return (
              `              <li><code>${he(vh.version)}</code>` +
              `<span class="vdate">${d}</span></li>`
            );
          })
          .join("\n");
        body +=
          `\n          <div class="detail-section">\n` +
          `            <h4>Recent Version History</h4>\n` +
          `            <ul class="version-list">\n${items}\n            </ul>\n` +
          `          </div>`;
      }

      // ── Package metadata ──────────────────────────────────────────────────
      const meta = r.registry;
      if (meta) {
        const rows = [];
        if (meta.license)
          rows.push(`<tr><th>License</th><td>${he(meta.license)}</td></tr>`);
        if (meta.publisher)
          rows.push(
            `<tr><th>Publisher</th><td>${he(meta.publisher)}</td></tr>`,
          );
        if (meta.publishDate)
          rows.push(
            `<tr><th>Published</th><td>${safeDate(meta.publishDate)}</td></tr>`,
          );
        if (meta.dependencyCount !== undefined)
          rows.push(
            `<tr><th>Dependencies</th><td>${meta.dependencyCount}</td></tr>`,
          );
        if (meta.unpackedSize)
          rows.push(
            `<tr><th>Unpacked size</th><td>${(meta.unpackedSize / 1024).toFixed(1)} kB</td></tr>`,
          );
        if (rows.length > 0) {
          body +=
            `\n          <div class="detail-section">\n` +
            `            <h4>Package Info</h4>\n` +
            `            <table class="meta-table"><tbody>${rows.join("")}</tbody></table>\n` +
            `          </div>`;
        }
      }

      return (
        `      <details class="pkg-finding" id="pkg-${he(r.name)}">\n` +
        `        <summary>\n` +
        `          <span class="pkg-name">${he(r.name)}</span>\n` +
        `          <span class="pkg-ver">${he(ver)}</span>\n` +
        `          <span class="chips">${chips.join("")}</span>\n` +
        `        </summary>\n` +
        `        <div class="finding-body">${body}\n        </div>\n` +
        `      </details>`
      );
    })
    .join("\n");

  // ── Totals banner chips ───────────────────────────────────────────────────
  const totalChips = [];
  if (totals.critical)
    totalChips.push(
      `<span class="total-chip critical">&#x25CF; ${totals.critical} critical</span>`,
    );
  if (totals.high)
    totalChips.push(
      `<span class="total-chip high">&#x25CF; ${totals.high} high</span>`,
    );
  if (totals.medium)
    totalChips.push(
      `<span class="total-chip medium">&#x25CF; ${totals.medium} medium</span>`,
    );
  if (totals.low)
    totalChips.push(
      `<span class="total-chip low">&#x25CF; ${totals.low} low</span>`,
    );
  if (findings.length > 0)
    totalChips.push(
      `<span class="total-chip findings">&#x26A0; ${findings.length} with findings</span>`,
    );
  if (cleanCount > 0)
    totalChips.push(
      `<span class="total-chip clean">&#x2713; ${cleanCount} clean</span>`,
    );
  if (findings.length === 0)
    totalChips.push(
      `<span class="total-chip clean">&#x2713; all ${results.length} package(s) clean</span>`,
    );

  const findingsSection =
    findings.length > 0
      ? `  <section>\n    <h2>Findings (${findings.length})</h2>\n${findingCards}\n  </section>`
      : `  <section>\n    <p class="all-clean">&#x2713; No security issues detected across all ${results.length} package(s).</p>\n  </section>`;

  // ── Assemble the full HTML document ──────────────────────────────────────
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Supply Chain Report &#x2014; ${he(pkgLabel)}</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

    :root {
      --bg:     #0d1117;
      --bg2:    #161b22;
      --bg3:    #21262d;
      --border: #30363d;
      --text:   #c9d1d9;
      --dim:    #8b949e;
      --bright: #f0f6fc;
      --red:    #f85149;
      --orange: #e3a84a;
      --yellow: #d4a017;
      --green:  #3fb950;
      --blue:   #58a6ff;
      --radius: 6px;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                   Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding-bottom: 64px;
    }

    a { color: var(--blue); text-decoration: none; }
    a:hover { text-decoration: underline; }
    code {
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
      font-size: 0.85em;
      background: var(--bg3);
      padding: 1px 4px;
      border-radius: 3px;
    }

    /* ── Header ── */
    .site-header {
      background: var(--bg2);
      border-bottom: 1px solid var(--border);
      padding: 20px 32px;
    }
    .site-header h1 {
      font-size: 1.4rem;
      font-weight: 700;
      color: var(--bright);
      letter-spacing: -0.02em;
    }
    .site-header .meta {
      margin-top: 6px;
      font-size: 0.82rem;
      color: var(--dim);
      display: flex;
      gap: 18px;
      flex-wrap: wrap;
    }
    .site-header .meta strong { color: var(--text); }

    /* ── Totals banner ── */
    .totals-bar {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      padding: 12px 32px;
      background: var(--bg2);
      border-bottom: 1px solid var(--border);
    }
    .total-chip {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 10px;
      border-radius: 20px;
      font-size: 0.77rem;
      font-weight: 600;
      border: 1px solid currentColor;
    }
    .total-chip.critical { color: #ff4444; background: #200a0a; }
    .total-chip.high     { color: #f85149; background: #200a0a; }
    .total-chip.medium   { color: #e3a84a; background: #1e1206; }
    .total-chip.low      { color: #8b949e; background: #1c2128; }
    .total-chip.clean    { color: #3fb950; background: #0a1f10; }
    .total-chip.findings { color: #e3a84a; background: #1e1206; }

    /* ── Layout ── */
    .main { max-width: 1100px; margin: 0 auto; padding: 0 32px; }
    section { margin-top: 28px; }
    section > h2 {
      font-size: 0.78rem;
      font-weight: 700;
      color: var(--dim);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 10px;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--border);
    }
    .all-clean { color: var(--green); padding: 14px 0; font-size: 0.9rem; }

    /* ── Package table ── */
    .pkg-table-wrap {
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: var(--radius);
    }
    .pkg-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    .pkg-table th {
      text-align: left;
      padding: 8px 14px;
      font-size: 0.71rem;
      font-weight: 600;
      color: var(--dim);
      text-transform: uppercase;
      letter-spacing: 0.07em;
      background: var(--bg3);
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }
    .pkg-table td {
      padding: 7px 14px;
      border-bottom: 1px solid var(--border);
      vertical-align: middle;
    }
    .pkg-table tr:last-child td { border-bottom: none; }
    .pkg-table tbody tr { background: var(--bg2); }
    .pkg-table tbody tr:hover td { background: var(--bg3); transition: background 0.1s; }
    .pkg-link { color: var(--bright); font-weight: 500; }
    .pkg-link:hover { color: var(--blue); }
    .td-repo { text-align: center; }
    .repo-link { font-size: 1rem; opacity: 0.6; }
    .repo-link:hover { opacity: 1; }
    .dim { color: var(--dim); }
    .scope {
      display: inline-block;
      padding: 1px 7px;
      border-radius: 10px;
      font-size: 0.7rem;
      background: var(--bg3);
      color: var(--dim);
      border: 1px solid var(--border);
    }

    /* ── Vuln / script badges ── */
    .badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 10px;
      font-size: 0.71rem;
      font-weight: 700;
      border: 1px solid transparent;
    }
    .badge.critical { background: #200a0a; color: #ff4444; border-color: #ff4444; }
    .badge.high     { background: #200a0a; color: #f85149; border-color: #f85149; }
    .badge.medium   { background: #1e1206; color: #e3a84a; border-color: #e3a84a; }
    .badge.low      { background: #1c2128; color: #8b949e; border-color: #8b949e; }
    .badge.clean    { color: var(--dim); font-weight: 400; }
    .badge.scripts  { background: #1e1206; color: #e3a84a; border-color: #e3a84a; }

    /* ── Scorecard bar ── */
    .sc-bar {
      display: inline-block;
      width: 56px;
      height: 7px;
      background: var(--bg3);
      border-radius: 4px;
      vertical-align: middle;
      position: relative;
      overflow: hidden;
      border: 1px solid var(--border);
    }
    .sc-fill {
      position: absolute;
      top: 0; left: 0; bottom: 0;
      border-radius: 4px;
      transition: width 0.4s ease;
    }
    .sc-bar.sc-high .sc-fill { background: var(--green); }
    .sc-bar.sc-med  .sc-fill { background: var(--orange); }
    .sc-bar.sc-low  .sc-fill { background: var(--red); }
    .sc-score { font-size: 0.8rem; vertical-align: middle; margin-left: 5px; }
    .sc-score.sc-high { color: var(--green); }
    .sc-score.sc-med  { color: var(--orange); }
    .sc-score.sc-low  { color: var(--red); }
    .sc-na { color: var(--dim); font-size: 0.8rem; }

    /* ── Finding cards (collapsible <details>) ── */
    .pkg-finding {
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      margin-bottom: 6px;
      overflow: hidden;
    }
    .pkg-finding > summary {
      list-style: none;
      display: flex;
      align-items: center;
      gap: 10px;
      padding: 11px 16px;
      cursor: pointer;
      user-select: none;
      flex-wrap: wrap;
    }
    .pkg-finding > summary::-webkit-details-marker { display: none; }
    .pkg-finding > summary::before {
      content: "\\25B6";
      font-size: 0.6rem;
      color: var(--dim);
      flex-shrink: 0;
      transition: transform 0.15s ease;
    }
    .pkg-finding[open] > summary::before { transform: rotate(90deg); }
    .pkg-finding > summary:hover { background: var(--bg3); }
    .pkg-finding > summary .pkg-name {
      font-weight: 600;
      color: var(--bright);
      font-size: 0.92rem;
    }
    .pkg-finding > summary .pkg-ver {
      font-size: 0.77rem;
      color: var(--dim);
      font-family: "SFMono-Regular", Consolas, monospace;
      background: var(--bg3);
      padding: 1px 6px;
      border-radius: 4px;
    }
    .chips { display: inline-flex; gap: 5px; flex-wrap: wrap; margin-left: auto; }
    .chip {
      display: inline-flex;
      align-items: center;
      padding: 2px 8px;
      border-radius: 12px;
      font-size: 0.69rem;
      font-weight: 600;
      border: 1px solid currentColor;
    }
    .chip.critical  { color: #ff4444; background: #200a0a; }
    .chip.high      { color: #f85149; background: #200a0a; }
    .chip.medium    { color: #e3a84a; background: #1e1206; }
    .chip.low       { color: #8b949e; background: #1c2128; }
    .chip.scripts   { color: #e3a84a; background: #1e1206; }
    .chip.scorecard { color: #e3a84a; background: #1e1206; }
    .chip.recent    { color: #d4a017; background: #1e1a06; }
    .chip.not-found { color: #f85149; background: #200a0a; }
    .chip.no-repo   { color: var(--dim); background: var(--bg3); }

    .finding-body {
      padding: 4px 16px 16px;
      border-top: 1px solid var(--border);
    }
    .detail-section { margin-top: 14px; }
    .detail-section h4 {
      font-size: 0.69rem;
      font-weight: 700;
      color: var(--dim);
      text-transform: uppercase;
      letter-spacing: 0.08em;
      margin-bottom: 8px;
    }

    /* Vulnerability list */
    .vuln-list { list-style: none; display: flex; flex-direction: column; gap: 6px; }
    .vuln-item {
      background: var(--bg3);
      border: 1px solid var(--border);
      border-left: 3px solid var(--border);
      border-radius: var(--radius);
      padding: 9px 13px;
      font-size: 0.82rem;
    }
    .vuln-item.critical { border-left-color: #ff4444; }
    .vuln-item.high     { border-left-color: #f85149; }
    .vuln-item.medium   { border-left-color: #e3a84a; }
    .vuln-item.low      { border-left-color: #8b949e; }
    .vuln-item.unknown  { border-left-color: var(--dim); }
    .vuln-header {
      display: flex;
      align-items: center;
      gap: 7px;
      margin-bottom: 4px;
      flex-wrap: wrap;
    }
    .vuln-header strong { color: var(--bright); }
    .aliases { font-size: 0.72rem; color: var(--dim); }
    .vuln-summary { color: var(--text); margin-bottom: 3px; }
    .vuln-fix { font-size: 0.78rem; color: var(--green); }
    .vuln-fix code { background: transparent; padding: 0; color: var(--green); }
    .vuln-refs { font-size: 0.72rem; color: var(--dim); margin-top: 4px; word-break: break-all; }

    .sev-badge {
      display: inline-block;
      padding: 1px 6px;
      border-radius: 4px;
      font-size: 0.67rem;
      font-weight: 700;
      text-transform: uppercase;
    }
    .sev-badge.critical { background: #ff4444; color: #fff; }
    .sev-badge.high     { background: #f85149; color: #fff; }
    .sev-badge.medium   { background: #e3a84a; color: #000; }
    .sev-badge.low      { background: var(--bg3); color: var(--dim); border: 1px solid var(--border); }
    .sev-badge.unknown  { background: var(--bg3); color: var(--dim); border: 1px solid var(--border); }

    /* Install scripts */
    .script-list { list-style: none; display: flex; flex-direction: column; gap: 5px; }
    .script-list li {
      display: flex;
      gap: 12px;
      align-items: flex-start;
      background: var(--bg3);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 6px 10px;
      font-size: 0.82rem;
    }
    .script-key {
      color: #e3a84a;
      min-width: 110px;
      flex-shrink: 0;
      background: transparent;
      padding: 0;
    }
    .script-cmd { color: var(--dim); word-break: break-all; }

    /* Scorecard checks */
    .scorecard-list { list-style: none; }
    .scorecard-list li {
      display: flex;
      align-items: baseline;
      gap: 10px;
      padding: 5px 0;
      border-bottom: 1px solid var(--border);
      font-size: 0.82rem;
    }
    .scorecard-list li:last-child { border-bottom: none; }
    .sc-check-name { color: var(--bright); font-weight: 500; min-width: 180px; flex-shrink: 0; }
    .sc-check-score { color: var(--red); font-weight: 600; min-width: 44px; }
    .sc-check-reason { color: var(--dim); }

    /* Version history grid */
    .version-list {
      list-style: none;
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(175px, 1fr));
      gap: 4px;
    }
    .version-list li {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 0.78rem;
      padding: 4px 8px;
      background: var(--bg3);
      border-radius: 4px;
    }
    .version-list code { background: transparent; padding: 0; color: var(--blue); }
    .vdate { color: var(--dim); }

    /* Package metadata table */
    .meta-table { border-collapse: collapse; font-size: 0.82rem; }
    .meta-table th,
    .meta-table td { padding: 4px 12px 4px 0; text-align: left; border-bottom: 1px solid var(--border); }
    .meta-table tr:last-child th,
    .meta-table tr:last-child td { border-bottom: none; }
    .meta-table th { color: var(--dim); font-weight: 500; width: 130px; vertical-align: top; }
    .meta-table td { color: var(--text); }

    /* ── Footer ── */
    .site-footer {
      margin-top: 48px;
      padding: 14px 32px;
      border-top: 1px solid var(--border);
      font-size: 0.72rem;
      color: var(--dim);
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
    }
  </style>
</head>
<body>

<header class="site-header">
  <h1>&#x1F6E1;&#xFE0F; Supply Chain Report</h1>
  <div class="meta">
    <span><strong>${he(pkgLabel)}</strong></span>
    <span>${results.length} package(s) inspected</span>
    <span>Generated ${generatedAt}</span>
  </div>
</header>

<div class="totals-bar">
  ${totalChips.join("\n  ")}
</div>

<div class="main">

  <section>
    <h2>Packages</h2>
    <div class="pkg-table-wrap">
      <table class="pkg-table">
        <thead>
          <tr>
            <th>Package</th>
            <th>Version</th>
            <th>Scope</th>
            <th>Vulnerabilities</th>
            <th>Scorecard</th>
            <th>Scripts</th>
            <th>Repo</th>
          </tr>
        </thead>
        <tbody>
${tableRows}
        </tbody>
      </table>
    </div>
  </section>

${findingsSection}

</div>

<footer class="site-footer">
  <span>Generated by <strong>inspect-dependencies.js</strong></span>
  <span>Data sources: npm Registry &#x00B7; OSV.dev &#x00B7; OpenSSF Scorecard</span>
</footer>

</body>
</html>`;
}

// ─── Terminal report ──────────────────────────────────────────────────────────

/**
 * Print a human-readable security report to stderr after all packages have been
 * inspected. stdout is untouched so the JSON output can still be piped/redirected.
 *
 * Layout:
 *   ━━━ header ━━━
 *   per-package table  (name | version | vulns | scorecard | scripts)
 *   ─── findings ───  (only packages with at least one signal)
 *     ● pkg@ver  signal chips
 *       ├ [SEVERITY] CVE-ID — summary / fix
 *       ├ postinstall  "script content"
 *       └ Scorecard · Check: 0/10
 *   ━━━ footer totals ━━━
 */
function printReport(results, pkg, showFindings = false) {
  const W = Math.min(process.stderr.columns ?? 80, 90);
  const hr = (ch = "─") => ch.repeat(W);
  const HR = (ch = "━") => ch.repeat(W);

  // ── Classify each result into its security signals ────────────────────────
  const annotated = results.map((r) => {
    const signals = [];
    if (r.notFound) signals.push("not_found");
    if ((r.vulnerabilities?.summary?.total ?? 0) > 0) signals.push("vulns");
    if (r.registry?.hasInstallScripts) signals.push("scripts");
    if (
      r.scorecard?.score !== null &&
      r.scorecard?.score !== undefined &&
      r.scorecard.score < 5
    )
      signals.push("low_scorecard");
    if ((r.registry?.publishedHoursAgo ?? Infinity) < 48)
      signals.push("very_recent");
    if (!r.sourceRepository && !r.notFound) signals.push("no_repo");
    return { r, signals };
  });
  const findings = annotated.filter((a) => a.signals.length > 0);

  // ── Header ────────────────────────────────────────────────────────────────
  const pkgLabel =
    `${pkg.name ?? "(unnamed)"}` + (pkg.version ? `@${pkg.version}` : "");
  log("");
  log(HR());
  log(
    `${C.bold}  SUPPLY CHAIN REPORT${C.reset}` +
      `  ·  ${pkgLabel}` +
      `  ·  ${results.length} package(s)`,
  );
  log(HR());

  // ── Per-package summary table ─────────────────────────────────────────────
  const COL_NAME = Math.max(14, ...results.map((r) => r.name.length)) + 2;
  const COL_VER =
    Math.max(
      9,
      ...results.map((r) => (r.resolvedVersion ?? r.versionSpec ?? "?").length),
    ) + 2;
  const COL_VULN = 14;
  const COL_SC = 16;

  log("");
  log(
    `${C.dim}  ` +
      rpad("PACKAGE", COL_NAME) +
      rpad("VERSION", COL_VER) +
      rpad("VULNS", COL_VULN) +
      rpad("SCORECARD", COL_SC) +
      `SCRIPTS${C.reset}`,
  );
  log(`  ${"─".repeat(COL_NAME + COL_VER + COL_VULN + COL_SC + 10)}`);

  for (const { r } of annotated) {
    const name = r.notFound ? `${C.red}${r.name}${C.reset}` : r.name;
    const ver = r.resolvedVersion ?? r.versionSpec ?? "?";
    const vuln = vulnCell(r.vulnerabilities);
    const sc = scorecardBar(r.scorecard?.score ?? null);
    const scr = r.registry?.hasInstallScripts
      ? `${C.yellow}⚠ yes${C.reset}`
      : `${C.dim}─${C.reset}`;

    log(
      `  ${rpad(name, COL_NAME)}` +
        `${rpad(ver, COL_VER)}` +
        `${rpad(vuln, COL_VULN)}` +
        `${rpad(sc, COL_SC)}` +
        scr,
    );
  }

  // ── Findings detail section ───────────────────────────────────────────────
  if (findings.length === 0) {
    log("");
    log(
      `${C.bgreen}  ✓ All ${results.length} package(s) passed — ` +
        `no security issues detected.${C.reset}`,
    );
  } else if (!showFindings) {
    log("");
    log(
      `${C.dim}  ${findings.length} package(s) have signals — ` +
        `run with --findings for details.${C.reset}`,
    );
  } else {
    log("");
    log(hr());
    log(
      `${C.bold}  FINDINGS${C.reset}` +
        `  ·  ${findings.length} package(s) need attention`,
    );
    log(hr());

    for (const { r, signals } of findings) {
      const ver = r.resolvedVersion ?? r.versionSpec ?? "?";

      // Headline chips (brief coloured labels)
      const chips = [];
      if (signals.includes("vulns")) {
        const s = r.vulnerabilities.summary;
        chips.push(
          s.critical > 0
            ? `${C.bred}${s.total} critical vuln${s.total !== 1 ? "s" : ""}${C.reset}`
            : s.high > 0
              ? `${C.red}${s.total} high vuln${s.total !== 1 ? "s" : ""}${C.reset}`
              : s.medium > 0
                ? `${C.yellow}${s.total} medium vuln${s.total !== 1 ? "s" : ""}${C.reset}`
                : `${C.dim}${s.total} low vuln${s.total !== 1 ? "s" : ""}${C.reset}`,
        );
      }
      if (signals.includes("scripts"))
        chips.push(`${C.yellow}install scripts${C.reset}`);
      if (signals.includes("low_scorecard"))
        chips.push(
          `${C.yellow}Scorecard ${r.scorecard.score.toFixed(1)}/10${C.reset}`,
        );
      if (signals.includes("very_recent"))
        chips.push(
          `${C.byellow}published ${r.registry.publishedHoursAgo}h ago${C.reset}`,
        );
      if (signals.includes("not_found"))
        chips.push(`${C.red}not found on registry${C.reset}`);
      if (signals.includes("no_repo"))
        chips.push(`${C.dim}no source repository${C.reset}`);

      log("");
      log(`  ${C.bold}● ${r.name}@${ver}${C.reset}  ${chips.join("  ·  ")}`);

      // Vulnerability list
      if (signals.includes("vulns")) {
        const list = r.vulnerabilities.list ?? [];
        list.forEach((v, i) => {
          const last = i === list.length - 1;
          const tree = last ? "└" : "├";
          const cont = last ? " " : "│";
          const fix = v.affectedRanges?.find((rng) => rng.fixed);
          log(
            `    ${tree} ${sevBadge(v.severity)}  ${C.bold}${v.id}${C.reset}`,
          );
          log(`    ${cont}   ${C.dim}${truncate(v.summary, W - 10)}${C.reset}`);
          if (fix)
            log(`    ${cont}   ${C.cyan}Fix available: ${fix.fixed}${C.reset}`);
        });
      }

      // Install script list
      if (signals.includes("scripts")) {
        const scripts = Object.entries(r.registry?.lifecycleScripts ?? {});
        scripts.forEach(([key, cmd], i) => {
          const last = i === scripts.length - 1;
          log(
            `    ${last ? "└" : "├"} ` +
              `${C.yellow}${rpad(key, 14)}${C.reset}` +
              `"${truncate(cmd, 55)}"`,
          );
        });
      }

      // Low-scoring Scorecard checks
      if (signals.includes("low_scorecard")) {
        const bad = (r.scorecard.checks ?? [])
          .filter((chk) => typeof chk.score === "number" && chk.score < 5)
          .sort((a, b) => a.score - b.score)
          .slice(0, 5);
        bad.forEach((chk, i) => {
          const last = i === bad.length - 1;
          const score = chk.score === -1 ? "N/A" : `${chk.score}/10`;
          log(
            `    ${last ? "└" : "├"} ` +
              `${C.dim}Scorecard · ${chk.name}: ${score}${C.reset}`,
          );
        });
      }

      // Very-recent-publish warning
      if (signals.includes("very_recent") && !signals.includes("vulns")) {
        log(
          `    └ ${C.yellow}Only ${r.registry.publishedHoursAgo}h old — ` +
            `consider waiting before adopting${C.reset}`,
        );
      }
    }
  }

  // ── Footer totals ─────────────────────────────────────────────────────────
  const totals = results.reduce(
    (acc, r) => {
      const s = r.vulnerabilities?.summary ?? {};
      acc.critical += s.critical ?? 0;
      acc.high += s.high ?? 0;
      acc.medium += s.medium ?? 0;
      acc.low += s.low ?? 0;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0 },
  );
  const cleanCount = results.length - findings.length;

  const footerChips = [];
  if (totals.critical)
    footerChips.push(`${C.bred}${totals.critical} critical${C.reset}`);
  if (totals.high) footerChips.push(`${C.red}${totals.high} high${C.reset}`);
  if (totals.medium)
    footerChips.push(`${C.yellow}${totals.medium} medium${C.reset}`);
  if (totals.low) footerChips.push(`${C.dim}${totals.low} low${C.reset}`);

  // Always show a "findings vs clean" split so the footer is never empty
  if (findings.length > 0)
    footerChips.push(`${C.yellow}${findings.length} with findings${C.reset}`);
  if (cleanCount > 0)
    footerChips.push(`${C.green}${cleanCount} clean${C.reset}`);
  if (footerChips.length === 0)
    footerChips.push(
      `${C.bgreen}✓ all ${results.length} package(s) clean${C.reset}`,
    );

  log("");
  log(HR());
  log(`  ${footerChips.join("  ·  ")}`);
  log(HR());
}

// ─── Main ─────────────────────────────────────────────────────────────────────

/**
 * Check if a string is a URL (http:// or https://)
 */
function isUrl(str) {
  return /^https?:\/\//i.test(str);
}

/**
 * Convert a package.json URL to its corresponding package-lock.json URL
 * E.g., https://raw.githubusercontent.com/.../package.json -> .../package-lock.json
 */
function getLockfileUrl(packageJsonUrl) {
  return packageJsonUrl.replace(/package\.json$/, "package-lock.json");
}

/**
 * Fetch and parse a lockfile from a URL
 */
async function fetchLockfileFromUrl(url) {
  try {
    logOk(`Fetching lockfile from ${url}...\n`);
    const res = await fetch(url, {
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(30000),
    });
    if (!res.ok) {
      if (res.status === 404) {
        return null; // Lockfile not found, which is acceptable
      }
      logWarn(`Failed to fetch lockfile (${res.status} ${res.statusText})`);
      return null;
    }
    const text = await res.text();
    return JSON.parse(text);
  } catch (err) {
    logWarn(`Failed to fetch or parse lockfile from URL: ${err.message}`);
    return null;
  }
}

async function main() {
  const opts = parseArgs(process.argv);

  // ── Validate input ──────────────────────────────────────────────────────────
  if (!opts.packageJsonPath) {
    process.stderr.write(
      [
        "Usage: node inspect-dependencies.js <path/to/package.json|url> [options]",
        "",
        "Options:",
        "  --include-dev          Include devDependencies",
        "  --include-peer         Include peerDependencies",
        "  --include-optional     Include optionalDependencies",
        "  --include-transitive   Include all transitive deps from package-lock.json",
        "                         (requires a lockfile; deduped by name@version)",
        "  --findings             Show per-package findings detail after the table",
        "                         (default: table only; hint shown when issues exist)",
        "  --concurrency=<N>      Max parallel fetches (default: 5)",
        "  --version-history=<N>  Versions to keep per package (default: 10, min: 2)",
        "                           2  = downgrade / major-jump detection only",
        "                           5  = + rapid publish bursts + dormancy detection",
        "                           10 = + cadence baseline (recommended)",
        "                           20+= broader history, larger output",
        "  --lockfile=<path|url>  Path or URL to package-lock.json",
        "  --json                 Print the full JSON result to stdout",
        "  --output=<path>        Write JSON to a file (implies --json)",
        "  --html=<path>          Write a standalone HTML report to a file",
        "  --no-scorecard         Skip OpenSSF Scorecard lookups",
        "  --no-vulns             Skip OSV.dev vulnerability lookups",
        "  --cache-dir=<path>     File-cache directory (default: .cache/ next to this script)",
        "  --no-cache             Disable the file cache entirely (always fetch live data)",
        "",
      ].join("\n"),
    );
    process.exit(1);
  }

  const isUrlInput = isUrl(opts.packageJsonPath);
  let pkgPath;
  let pkg;

  if (isUrlInput) {
    // Fetch package.json from URL
    try {
      logOk(`Fetching package.json from ${opts.packageJsonPath}...\n`);
      const res = await fetch(opts.packageJsonPath, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(30000),
      });
      if (!res.ok) {
        process.stderr.write(
          `Error: Failed to fetch URL (${res.status} ${res.statusText}): ${opts.packageJsonPath}\n`,
        );
        process.exit(1);
      }
      const text = await res.text();
      pkg = JSON.parse(text);
      pkgPath = opts.packageJsonPath; // Use URL as the path for display purposes
    } catch (err) {
      process.stderr.write(
        `Error: Failed to fetch or parse package.json from URL: ${err.message}\n`,
      );
      process.exit(1);
    }
  } else {
    // Read package.json from local file
    pkgPath = resolve(opts.packageJsonPath);
    if (!existsSync(pkgPath)) {
      process.stderr.write(`Error: File not found: ${pkgPath}\n`);
      process.exit(1);
    }

    try {
      pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    } catch (err) {
      process.stderr.write(
        `Error: Failed to parse ${basename(pkgPath)}: ${err.message}\n`,
      );
      process.exit(1);
    }
  }

  // ── File cache initialisation ─────────────────────────────────────────────
  if (!opts.noCache) {
    _cacheDir = opts.cacheDir
      ? resolve(opts.cacheDir)
      : join(_scriptDir, ".cache");
    try {
      mkdirSync(_cacheDir, { recursive: true });
    } catch (err) {
      logWarn(
        `Could not create cache directory, caching disabled: ${err.message}`,
      );
      _cacheDir = null;
    }
  }

  log(`\nSupply Chain Inspector`);
  log(`Package: ${pkg.name ?? "(unnamed)"} ${pkg.version ?? ""}`);
  log(`Source:  ${pkgPath}`);

  // ── Load lockfile for exact version resolution ──────────────────────────────
  let lockfilePath;
  let lockfileData = null;

  if (isUrlInput) {
    // Handle remote lockfile
    if (opts.lockfilePath) {
      // User specified a lockfile path/URL
      if (isUrl(opts.lockfilePath)) {
        lockfilePath = opts.lockfilePath;
        lockfileData = await fetchLockfileFromUrl(lockfilePath);
      } else {
        // User specified a local lockfile with a remote package.json
        lockfilePath = resolve(opts.lockfilePath);
        if (!existsSync(lockfilePath)) {
          logWarn(`Lockfile not found at ${lockfilePath}`);
        }
      }
    } else {
      // Auto-detect lockfile from the same URL directory
      lockfilePath = getLockfileUrl(pkgPath);
      lockfileData = await fetchLockfileFromUrl(lockfilePath);
    }
  } else {
    // Local file handling (existing behavior)
    lockfilePath = opts.lockfilePath
      ? resolve(opts.lockfilePath)
      : resolve(dirname(pkgPath), "package-lock.json");
  }

  const lockfileVersions = lockfileData
    ? parseLockfileVersions(lockfileData)
    : loadLockfileVersions(lockfilePath);
  if (lockfileVersions.size > 0) {
    log(
      `Lockfile: ${lockfilePath} (${lockfileVersions.size} resolved versions)`,
    );
  } else {
    logWarn(`No lockfile found — versions will be resolved from npm registry`);
  }
  if (_cacheDir) {
    log(`${C.dim}Cache:    ${_cacheDir}${C.reset}`);
  } else if (opts.noCache) {
    log(`${C.dim}Cache:    disabled (--no-cache)${C.reset}`);
  }

  // ── Collect all dependency entries to inspect ───────────────────────────────
  const entries = [];

  const addDeps = (depsObj, scope) => {
    if (!depsObj || typeof depsObj !== "object") return;
    for (const [name, versionSpec] of Object.entries(depsObj)) {
      entries.push({ name, versionSpec, scope });
    }
  };

  addDeps(pkg.dependencies, "dependencies");
  addDeps(pkg.devDependencies, opts.includeDev ? "devDependencies" : null);
  addDeps(pkg.peerDependencies, opts.includePeer ? "peerDependencies" : null);
  addDeps(
    pkg.optionalDependencies,
    opts.includeOptional ? "optionalDependencies" : null,
  );

  // ── Transitive dependencies from lockfile ─────────────────────────────────
  if (opts.includeTransitive) {
    let allPkgs = [];

    if (lockfileData) {
      // Use remote lockfile data
      allPkgs = loadAllLockfilePackagesFromData(lockfileData);
    } else if (lockfilePath && existsSync(lockfilePath)) {
      // Use local lockfile
      allPkgs = loadAllLockfilePackages(lockfilePath);
    }

    if (allPkgs.length === 0) {
      logWarn(
        "--include-transitive requires a lockfile" +
          (lockfileData === null && isUrlInput
            ? " (lockfile not found at remote location)"
            : !lockfilePath
              ? ""
              : `; none found at ${lockfilePath}`),
      );
    } else {
      const directNames = new Set(entries.map((e) => e.name));
      let added = 0;
      for (const { name, version } of allPkgs) {
        // Skip packages already covered by a direct-dep entry so we don't
        // double-analyze them (the direct entry already carries the right scope).
        if (directNames.has(name)) continue;
        // versionSpec is the exact resolved version — no range operators needed.
        entries.push({ name, versionSpec: version, scope: "transitive" });
        added++;
      }
      if (added > 0) {
        log(`  + ${added} transitive package(s) from lockfile`);
      } else {
        log(`  No additional transitive packages found in lockfile.`);
      }
    }
  }

  // Remove entries that had scope=null (not included)
  const toInspect = entries.filter((e) => e.scope !== null);

  if (toInspect.length === 0) {
    log("\nNo dependencies found to inspect.");
    if (opts.json) {
      const json = JSON.stringify([], null, 2);
      if (opts.output) {
        writeFileSync(opts.output, json, "utf8");
        log(`Output written to: ${opts.output}`);
      } else {
        process.stdout.write(json + "\n");
      }
    }
    process.exit(0);
  }

  log(
    `\nInspecting ${toInspect.length} package(s) — concurrency: ${opts.concurrency}`,
  );
  if (opts.skipVulns) log("  [OSV.dev lookups skipped]");
  if (opts.skipScorecard) log("  [Scorecard lookups skipped]");
  log("");

  // ── Run all inspections with concurrency limit ──────────────────────────────
  const tasks = toInspect.map(
    (entry) => () =>
      inspectPackage(entry, lockfileVersions.get(entry.name) ?? null, opts),
  );

  const results = await runWithConcurrency(tasks, opts.concurrency);

  // ── Summary ─────────────────────────────────────────────────────────────────
  // ── Security report ───────────────────────────────────────────────────────
  printReport(results, pkg, opts.showFindings);

  // ── HTML report (opt-in via --html=<path>) ────────────────────────────────
  if (opts.html) {
    const htmlPath = resolve(opts.html);
    try {
      writeFileSync(htmlPath, generateHtmlReport(results, pkg), "utf8");
      log(`${C.dim}  HTML report written to: ${opts.html}${C.reset}`);
    } catch (err) {
      logErr(`Failed to write HTML report: ${err.message}`);
    }
  }

  // ── Cache stats ───────────────────────────────────────────────────────────
  const uniqueNpm = _npmCache.size;
  const uniqueScorecard = _scorecardCache.size;
  const anyStats =
    _cacheStats.npmHits > 0 ||
    _cacheStats.scorecardHits > 0 ||
    _fileCacheStats.hits > 0 ||
    _fileCacheStats.writes > 0;
  if (anyStats) {
    const parts = [];
    if (_fileCacheStats.hits > 0)
      parts.push(
        `${_fileCacheStats.hits} file-cache hit${_fileCacheStats.hits !== 1 ? "s" : ""}`,
      );
    if (_fileCacheStats.writes > 0)
      parts.push(`${_fileCacheStats.writes} written`);
    if (_cacheStats.npmHits > 0 || _cacheStats.scorecardHits > 0)
      parts.push(
        `${_cacheStats.npmHits + _cacheStats.scorecardHits} in-flight deduped`,
      );
    log(`${C.dim}  cache: ${parts.join("  ·  ")}${C.reset}`);
    log("");
  }

  // ── JSON output (opt-in via --json or --output) ───────────────────────────
  if (opts.json) {
    const json = JSON.stringify(results, null, 2);
    if (opts.output) {
      writeFileSync(resolve(opts.output), json, "utf8");
      log(`${C.dim}  JSON written to: ${opts.output}${C.reset}`);
    } else {
      process.stdout.write(json + "\n");
    }
  } else {
    log(
      `${C.dim}  Tip: run with --json to print full data, or --output=<file> to save it.${C.reset}`,
    );
    log("");
  }
}

main().catch((err) => {
  process.stderr.write(`\nFatal error: ${err.message}\n${err.stack}\n`);
  process.exit(1);
});
