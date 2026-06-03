#!/usr/bin/env node

/**
 * inspect.js
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
 npx supply-chain-inspector <path/to/package.json|url|npm-package-name> [options]

 Examples:
   # Local file
   npx supply-chain-inspector package.json

   # Remote URL (GitHub, raw content, etc.)
   npx supply-chain-inspector https://raw.githubusercontent.com/angular/angular/refs/heads/main/package.json

   # Direct npm package inspection (no package.json needed)
   npx supply-chain-inspector lodash-es
   npx supply-chain-inspector @nx/jest
   npx supply-chain-inspector react@18.2.0
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
 *     --verbose              Show per-package request/progress logs
 *     --lockfile=<path|url>  Path or URL to package-lock.json for exact version resolution
 *                            (auto-detected next to package.json if not given;
 *                            for URLs, auto-detects package-lock.json in same directory)
 *     --no-scorecard         Skip OpenSSF Scorecard lookups (faster, offline-friendly)
 *     --no-vulns             Skip OSV.dev vulnerability lookups
 *     --fail-on=<severity>    Exit with code 1 if vulns at or above threshold
 *                            (low | medium | high | critical; default: critical)
 *     --fail-licenses=<lic>     Exit with code 1 if any dep uses a restricted license
 *                            (comma-separated list: GPL,AGPL,LGPL,etc)
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
 *     --html[=<path>]        Write a standalone HTML security report to a file
 *                            (defaults to report.html when no path given)
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
 *   npx supply-chain-inspector package.json
 *
 *   # Report on stderr + JSON on stdout — pipe JSON to another tool
 *   npx supply-chain-inspector package.json --json
 *
 *   # Report on stderr + JSON saved to file — review both independently
 *   npx supply-chain-inspector package.json --output=results.json
 *
 *   # Write a standalone HTML report — open in any browser, no server needed
 *   npx supply-chain-inspector package.json --html=report.html
 *
 *   # HTML report + JSON side by side (useful for both humans and tooling)
 *   npx supply-chain-inspector package.json --output=scan.json --html=report.html
 *
 *   # Suppress the report, get only JSON (e.g. for scripting)
 *   npx supply-chain-inspector package.json --json 2>/dev/null
 *
 *   # Pipe JSON straight to an AI tool
 *   npx supply-chain-inspector package.json --json | llm "analyze these deps"
 *
 * ─── Common recipes ───────────────────────────────────────────────────────────
 *
 *   # Scan all dependency groups, save JSON for later AI analysis
 *   npx supply-chain-inspector package.json \
 *     --include-dev --include-peer \
 *     --output=scan.json
 *
 *   # Full scan with both HTML report and JSON output
 *   npx supply-chain-inspector package.json \
 *     --include-dev --include-peer \
 *     --output=scan.json --html=report.html
 *
 *   # Inspect a remote package.json from a GitHub repository
 *   npx supply-chain-inspector https://raw.githubusercontent.com/angular/angular/refs/heads/main/package.json
 *
 *   # Inspect remote package.json with full scan (auto-detects remote lockfile)
 *   npx supply-chain-inspector https://raw.githubusercontent.com/user/repo/main/package.json \
 *     --include-dev --html=report.html
 *
 *   # Inspect remote package.json with explicit remote lockfile URL
 *   npx supply-chain-inspector https://raw.githubusercontent.com/user/repo/main/package.json \
 *     --lockfile=https://raw.githubusercontent.com/user/repo/main/package-lock.json
 *
 *   # Quick scan — skip Scorecard (no outbound calls to api.scorecard.dev)
 *   npx supply-chain-inspector package.json --no-scorecard
 *
 *   # High concurrency for large lockfiles (mind rate limits)
 *   npx supply-chain-inspector package.json --concurrency=10
 *
 *   # Fail on GPL/AGPL licenses (for copyleft policies in CI)
 *   npx supply-chain-inspector package.json --fail-licenses="GPL,AGPL"
 *
 *   # CI-friendly: plain text report, exit code reflects nothing (advisory only)
 *   NO_COLOR=1 npx supply-chain-inspector package.json 2>&1
 *
 *   # Force fresh data, ignoring any cached responses
 *   npx supply-chain-inspector package.json --no-cache
 *
 *   # Use a shared cache directory for multiple projects
 *   npx supply-chain-inspector package.json --cache-dir=~/.supply-chain-cache
 *
 * ─── Data sources ─────────────────────────────────────────────────────────────
 *
 *   npm Registry      https://registry.npmjs.org      metadata, scripts, maintainers
 *   OSV.dev           https://api.osv.dev/v1/query    known CVEs and advisories
 *   OpenSSF Scorecard https://api.scorecard.dev       project health (17 checks)
 */

import { readFileSync, writeFileSync, existsSync, realpathSync } from 'node:fs';
import { resolve, dirname, basename, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { log, logOk, logErr, logWarn } from './logger.js';
import { isNpmPackageName, parsePackageSpec } from './pkg.js';
import {
  getScriptDir,
  TTL_NPM,
  TTL_OSV,
  TTL_SCORECARD,
  TTL_KEV,
  npmCache,
  scorecardCache,
  cacheStats,
  initCache,
  getCacheDir,
  safeName,
  readFromCache,
  writeToCache,
  fileCacheStats,
} from './cache.js';
import {
  loadCssTemplate,
  loadHtmlTemplate,
  renderTemplate,
} from './templates.js';
import { generateGraphReport } from './graph.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const NPM_REGISTRY = 'https://registry.npmjs.org';
const OSV_API = 'https://api.osv.dev/v1';
const SCORECARD_API = 'https://api.scorecard.dev';
const KEV_URL =
  'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

const LIFECYCLE_KEYS = [
  'preinstall',
  'install',
  'postinstall',
  'preuninstall',
  'postuninstall',
  'prepare',
  'prepack',
  'postpack',
];

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
    graph: null,
    graphNoDev: false,
    json: false,
    skipScorecard: false,
    skipVulns: false,
    skipKev: false,
    cacheDir: null, // null → resolved to default in main()
    noCache: false,
    verbose: false,
    includeTransitive: false,
    showFindings: false,
    failOn: 'critical', // 'low' | 'medium' | 'high' | 'critical'
    failLicenses: null,
  };

  for (const arg of args) {
    if (arg === '--include-dev') {
      opts.includeDev = true;
      continue;
    }
    if (arg === '--include-peer') {
      opts.includePeer = true;
      continue;
    }
    if (arg === '--include-optional') {
      opts.includeOptional = true;
      continue;
    }
    if (arg === '--findings') {
      opts.showFindings = true;
      continue;
    }
    if (arg === '--include-transitive') {
      opts.includeTransitive = true;
      continue;
    }
    if (arg === '--json') {
      opts.json = true;
      continue;
    }
    if (arg === '--no-scorecard') {
      opts.skipScorecard = true;
      continue;
    }
    if (arg === '--no-vulns') {
      opts.skipVulns = true;
      continue;
    }
    if (arg === '--no-kev') {
      opts.skipKev = true;
      continue;
    }

    if (arg.startsWith('--concurrency=')) {
      const n = parseInt(arg.split('=')[1], 10);
      if (!isNaN(n) && n > 0) opts.concurrency = n;
      continue;
    }
    if (arg === '--verbose' || arg === '--versbose') {
      opts.verbose = true;
      continue;
    }
    if (arg.startsWith('--version-history=')) {
      const n = parseInt(arg.split('=')[1], 10);
      if (!isNaN(n) && n >= 2) opts.versionHistory = n;
      continue;
    }
    if (arg.startsWith('--fail-on=')) {
      const level = arg.split('=')[1].toLowerCase();
      if (['low', 'medium', 'high', 'critical'].includes(level)) {
        opts.failOn = level;
      }
      continue;
    }
    if (arg.startsWith('--fail-licenses=')) {
      const raw = arg.split('=').slice(1).join('=');
      opts.failLicenses = raw
        .split(',')
        .map((s) => s.trim().toUpperCase())
        .filter(Boolean);
      continue;
    }
    if (arg.startsWith('--lockfile=')) {
      opts.lockfilePath = arg.split('=').slice(1).join('=');
      continue;
    }
    if (arg.startsWith('--cache-dir=')) {
      opts.cacheDir = arg.split('=').slice(1).join('=');
      continue;
    }
    if (arg === '--no-cache') {
      opts.noCache = true;
      continue;
    }
    if (arg.startsWith('--output=')) {
      opts.output = arg.split('=').slice(1).join('=');
      // --output implies --json (no point writing a file with no content)
      opts.json = true;
      continue;
    }
    if (arg === '--html') {
      opts.html = 'report.html';
      continue;
    }
    if (arg.startsWith('--html=')) {
      opts.html = arg.split('=').slice(1).join('=');
      continue;
    }
    if (arg === '--graph') {
      opts.graph = 'graph-report.html';
      continue;
    }
    if (arg.startsWith('--graph=')) {
      opts.graph = arg.split('=').slice(1).join('=');
      continue;
    }
    if (arg === '--graph-no-dev') {
      opts.graphNoDev = true;
      continue;
    }
    if (!arg.startsWith('--')) {
      opts.packageJsonPath = arg;
    }
  }

  return opts;
}

// ─── ANSI color helpers ───────────────────────────────────────────────────────
//
// Respects NO_COLOR env var (https://no-color.org) and non-TTY pipes so that
// piped JSON output and CI logs are never polluted with escape codes.

const USE_COLOR = process.stderr.isTTY === true && !process.env.NO_COLOR;

function esc(code) {
  return USE_COLOR ? `\x1b[${code}m` : '';
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
  bred: esc('1;31'),
  bgreen: esc('1;32'),
  byellow: esc('1;33'),
};

/** Visible string length — strips ANSI codes before measuring. */
function visLen(str) {
  return str.replace(/\x1b\[[0-9;]*m/g, '').length;
}

/** Right-pad `str` to `width` visible characters. */
function rpad(str, width) {
  const pad = width - visLen(str);
  return pad > 0 ? str + ' '.repeat(pad) : str;
}

/** Truncate to `max` chars, adding ellipsis if cut. */
function truncate(str, max) {
  return str.length > max ? str.slice(0, max - 1) + '…' : str;
}

/** Render a 6-block scorecard bar with a numeric label.  e.g. "████░░ 6.8" */
function scorecardBar(score) {
  if (score === null || score === undefined || score < 0)
    return `${C.dim}─ n/a  ${C.reset}`;
  const filled = Math.round((score / 10) * 6);
  const bar = '█'.repeat(filled) + '░'.repeat(6 - filled);
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
  switch ((sev ?? '').toUpperCase()) {
    case 'CRITICAL':
      return `${C.bred}[CRITICAL]${C.reset}`;
    case 'HIGH':
      return `${C.red}[HIGH    ]${C.reset}`;
    case 'MEDIUM':
      return `${C.yellow}[MEDIUM  ]${C.reset}`;
    case 'LOW':
      return `${C.dim}[LOW     ]${C.reset}`;
    default:
      return `${C.dim}[UNKNOWN ]${C.reset}`;
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
  if (lock.packages && typeof lock.packages === 'object') {
    for (const [pkgPath, pkgMeta] of Object.entries(lock.packages)) {
      if (!pkgPath.startsWith('node_modules/')) continue;
      if (!pkgMeta.version) continue;
      // Strip the leading "node_modules/" (handles nested: node_modules/a/node_modules/b)
      const name = pkgPath.replace(/^node_modules\//, '');
      // Only store the top-level entry (no nesting slash after scope slash)
      const parts = name.split('/');
      const topName = parts[0].startsWith('@')
        ? `${parts[0]}/${parts[1]}`
        : parts[0];
      if (!versions.has(topName)) {
        versions.set(topName, pkgMeta.version);
      }
    }
    return versions;
  }

  // v1 format: lock.dependencies is a nested tree
  if (lock.dependencies && typeof lock.dependencies === 'object') {
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
    const raw = readFileSync(lockfilePath, 'utf8');
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
  const entries = new Map();

  // v2 / v3 format: lock.packages is a flat map of node_modules paths
  if (lock.packages && typeof lock.packages === 'object') {
    for (const [pkgPath, pkgMeta] of Object.entries(lock.packages)) {
      if (!pkgPath.startsWith('node_modules/')) continue;
      if (!pkgMeta.version) continue;

      // Use the actual package at the end of the node_modules chain, e.g.
      // node_modules/a/node_modules/@scope/b -> @scope/b
      const segments = pkgPath.split('node_modules/').filter(Boolean);
      const name = segments[segments.length - 1];
      if (!name) continue;

      const key = `${name}@${pkgMeta.version}`;
      if (!entries.has(key)) {
        entries.set(key, { name, version: pkgMeta.version });
      }
    }
    return Array.from(entries.values());
  }

  // v1 format: need to traverse the tree
  const seen = new Set();
  function traverse(deps) {
    if (!deps || typeof deps !== 'object') return;
    for (const [name, pkgMeta] of Object.entries(deps)) {
      const key = `${name}@${pkgMeta.version}`;
      if (!seen.has(key) && pkgMeta.version) {
        seen.add(key);
        entries.set(key, { name, version: pkgMeta.version });
      }
      if (pkgMeta.dependencies) {
        traverse(pkgMeta.dependencies);
      }
    }
  }
  traverse(lock.dependencies);

  return Array.from(entries.values());
}

/**
 * Load all packages from a lockfile file path (for --include-transitive).
 */
function loadAllLockfilePackages(lockfilePath) {
  if (!lockfilePath || !existsSync(lockfilePath)) return [];

  try {
    const raw = readFileSync(lockfilePath, 'utf8');
    const lock = JSON.parse(raw);
    return loadAllLockfilePackagesFromData(lock);
  } catch (err) {
    logWarn(`Could not parse lockfile: ${err.message}`);
    return [];
  }
}

/**
 * Choose lockfile version override for an inspection entry.
 * Transitive entries already carry an exact lockfile version in versionSpec,
 * so they must not be remapped by top-level name-based lockfile resolution.
 */
export function selectLockfileVersionForEntry(entry, lockfileVersions) {
  if (entry?.scope === 'transitive') return null;
  return lockfileVersions.get(entry.name) ?? null;
}

/**
 * Load and parse lockfile JSON from file path.
 * Returns null when missing or invalid.
 */
function loadLockfileData(lockfilePath) {
  if (!lockfilePath || !existsSync(lockfilePath)) return null;

  try {
    const raw = readFileSync(lockfilePath, 'utf8');
    return JSON.parse(raw);
  } catch (err) {
    logWarn(`Could not parse lockfile data: ${err.message}`);
    return null;
  }
}

/**
 * Extract package-to-package dependency edges from package-lock.json data.
 * Supports lockfile v1 nested dependencies and v2/v3 packages map.
 * Returns objects: { fromName, fromVersion, toName, toVersion }.
 */
function extractLockfileDependencyEdges(lock) {
  if (!lock || typeof lock !== 'object') return [];

  const edgeKeys = new Set();
  const edges = [];

  const addEdge = (fromName, fromVersion, toName, toVersion) => {
    if (!fromName || !toName) return;
    const key = `${fromName}@${fromVersion ?? '?'}->${toName}@${toVersion ?? '?'}`;
    if (edgeKeys.has(key)) return;
    edgeKeys.add(key);
    edges.push({ fromName, fromVersion, toName, toVersion });
  };

  // lockfile v2/v3: flat packages map keyed by node_modules path
  if (lock.packages && typeof lock.packages === 'object') {
    const pathMeta = new Map();

    for (const [pkgPath, pkgMeta] of Object.entries(lock.packages)) {
      if (!pkgPath.startsWith('node_modules/')) continue;
      if (!pkgMeta?.version) continue;

      const fullPath = pkgPath.replace(/^node_modules\//, '');
      const leafPath = fullPath.split('/node_modules/').pop() ?? fullPath;
      const leafParts = leafPath.split('/');
      const name = leafParts[0].startsWith('@')
        ? `${leafParts[0]}/${leafParts[1]}`
        : leafParts[0];

      pathMeta.set(pkgPath, {
        name,
        version: pkgMeta.version,
        deps: {
          ...(pkgMeta.dependencies ?? {}),
          ...(pkgMeta.optionalDependencies ?? {}),
          ...(pkgMeta.peerDependencies ?? {}),
        },
      });
    }

    const resolveDepPath = (parentPath, depName) => {
      let current = parentPath;

      while (true) {
        const candidate = current
          ? `${current}/node_modules/${depName}`
          : `node_modules/${depName}`;
        if (pathMeta.has(candidate)) return candidate;

        if (!current) break;
        const upIdx = current.lastIndexOf('/node_modules/');
        if (upIdx === -1) {
          current = '';
        } else {
          current = current.slice(0, upIdx);
        }
      }

      return null;
    };

    for (const [pkgPath, meta] of pathMeta.entries()) {
      for (const depName of Object.keys(meta.deps ?? {})) {
        const depPath = resolveDepPath(pkgPath, depName);
        if (!depPath) continue;
        const depMeta = pathMeta.get(depPath);
        if (!depMeta) continue;
        addEdge(meta.name, meta.version, depMeta.name, depMeta.version);
      }
    }

    return edges;
  }

  // lockfile v1: nested dependencies tree
  const walk = (parent, depsObj) => {
    if (!depsObj || typeof depsObj !== 'object') return;
    for (const [name, meta] of Object.entries(depsObj)) {
      if (!meta || !meta.version) continue;
      addEdge(parent.name, parent.version, name, meta.version);
      walk({ name, version: meta.version }, meta.dependencies);
    }
  };

  if (lock.dependencies && typeof lock.dependencies === 'object') {
    for (const [name, meta] of Object.entries(lock.dependencies)) {
      if (!meta || !meta.version) continue;
      walk({ name, version: meta.version }, meta.dependencies);
    }
  }

  return edges;
}

// ─── Version spec helpers ─────────────────────────────────────────────────────

/**
 * Strip semver range operators (^, ~, >=, etc.) to get a bare version string.
 * Returns null if the spec is not a usable pinned-style version (e.g. "latest", "*", file:, git:).
 */
function stripRangeOperators(spec) {
  if (!spec || typeof spec !== 'string') return null;

  const trimmed = spec.trim();

  // Non-registry specs — skip
  if (
    trimmed === '*' ||
    trimmed === '' ||
    trimmed === 'latest' ||
    trimmed === 'x' ||
    trimmed.startsWith('http') ||
    trimmed.startsWith('git') ||
    trimmed.startsWith('file:') ||
    trimmed.startsWith('link:') ||
    trimmed.startsWith('workspace:') ||
    trimmed.includes(' ') // ranges like ">=1.0.0 <2.0.0"
  )
    return null;

  const stripped = trimmed.replace(/^[~^>=<]+/, '').trim();

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
  if (npmCache.has(name)) {
    cacheStats.npmHits++;
    return npmCache.get(name);
  }
  const promise = _doFetchNpmPackage(name);
  npmCache.set(name, promise);
  return promise;
}

async function _doFetchNpmPackage(name) {
  const cacheKey = `npm_${safeName(name)}`;
  const cached = readFromCache(cacheKey, TTL_NPM);
  if (cached) return cached;

  // npm registry requires scoped package names to be URL-encoded as %40scope%2Fname
  const encoded = name.startsWith('@')
    ? `@${encodeURIComponent(name.slice(1))}` // preserve leading @, encode the rest
    : encodeURIComponent(name);

  const url = `${NPM_REGISTRY}/${encoded}`;

  try {
    const res = await fetch(url, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(15_000),
    });
    if (res.status === 404) return null;
    if (!res.ok) {
      logErr(`npm registry ${res.status} for ${name}`);
      return null;
    }
    const data = await res.json();
    writeToCache(cacheKey, data, logWarn);
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
    pkgData['dist-tags']?.[versionSpec] || pkgData['dist-tags']?.latest;
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
    typeof m === 'string' ? m : m.name,
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
    dependencies: vd.dependencies ?? {},
    devDependencies: vd.devDependencies ?? {},
    peerDependencies: vd.peerDependencies ?? {},
    optionalDependencies: vd.optionalDependencies ?? {},
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
    .filter(([key]) => key !== 'created' && key !== 'modified')
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
  const raw = typeof repo === 'string' ? repo : (repo.url ?? null);
  if (!raw) return null;
  return raw
    .replace(/^git\+/, '')
    .replace(/^git:\/\/github\.com/, 'https://github.com')
    .replace(/^ssh:\/\/git@github\.com/, 'https://github.com')
    .replace(/\.git$/, '');
}

// ─── OSV.dev vulnerability client ────────────────────────────────────────────

/**
 * Query OSV.dev for known vulnerabilities for a specific package version.
 * @returns {{ summary: object, list: Array }}
 */
async function fetchVulnerabilities(name, version, ecosystem = 'npm') {
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
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
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
        summary: v.summary ?? 'No summary available',
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
    writeToCache(cacheKey, result, logWarn);
    return result;
  } catch (err) {
    logErr(`OSV query failed for ${name}@${version}: ${err.message}`);
    return { ...empty, error: err.message };
  }
}

// ─── CISA KEV (Known Exploited Vulnerabilities) ───────────────────────────────

/**
 * Fetch the full CISA KEV catalog and cache it for 24 h.
 * Returns an array of KEV entry objects, or [] on error.
 *
 * Each entry has:
 *   cveID, vendorProject, product, vulnerabilityName,
 *   dateAdded, shortDescription, requiredAction, dueDate,
 *   knownRansomwareCampaignUse, notes
 */
async function fetchKEVList() {
  const cacheKey = 'kev_catalog';
  const cached = readFromCache(cacheKey, TTL_KEV);
  if (cached) return cached;

  try {
    const res = await fetch(KEV_URL, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) {
      logErr(`KEV catalog fetch failed: ${res.status} ${res.statusText}`);
      return [];
    }
    const data = await res.json();
    const list = data.vulnerabilities ?? [];
    writeToCache(cacheKey, list, logWarn);
    return list;
  } catch (err) {
    logErr(`KEV catalog fetch error: ${err.message}`);
    return [];
  }
}

/**
 * Cross-reference all vulnerability IDs found in the scan results against the
 * CISA KEV catalog.  Checks both the primary OSV id (e.g. GHSA-xxxx) and all
 * aliases (usually includes the canonical CVE-xxxx identifier).
 *
 * Returns an array of match objects:
 *   { packageName, version, vuln, kev }
 */
function matchKEVs(results, kevList) {
  if (!kevList || kevList.length === 0) return [];

  // Build a fast lookup: CVE-ID → KEV entry
  const kevMap = new Map(kevList.map((k) => [k.cveID, k]));
  const matches = [];

  for (const r of results) {
    const vulns = r.vulnerabilities?.list ?? [];
    for (const v of vulns) {
      const ids = [v.id, ...(v.aliases ?? [])];
      for (const id of ids) {
        const kev = kevMap.get(id);
        if (kev) {
          matches.push({
            packageName: r.name,
            version: r.resolvedVersion ?? r.versionSpec ?? '?',
            vuln: v,
            kev,
          });
          break; // don't report the same vuln twice for the same package
        }
      }
    }
  }

  return matches;
}

function classifyCvssSeverity(vuln) {
  // Try CVSS v4 or v3 score
  for (const s of vuln.severity ?? []) {
    if (s.type === 'CVSS_V4' || s.type === 'CVSS_V3') {
      const score = parseCvssVector(s.score);
      if (score >= 9.0) return 'CRITICAL';
      if (score >= 7.0) return 'HIGH';
      if (score >= 4.0) return 'MEDIUM';
      return 'LOW';
    }
  }
  // Fall back to database_specific.severity (e.g. GitHub Advisory)
  const db = vuln.database_specific?.severity;
  if (db) return db.toUpperCase();
  return 'UNKNOWN';
}

function parseCvssVector(cvssVector) {
  if (typeof cvssVector === 'number') return cvssVector;
  if (typeof cvssVector !== 'string') return 5.0;
  // Heuristic extraction from CVSS vector — no full parser needed
  // Network-accessible, no privileges, full impact → near-max
  if (cvssVector.includes('/AV:N/') && cvssVector.includes('/PR:N/')) {
    if (cvssVector.includes('/C:H/I:H/A:H')) return 9.8;
    if (
      cvssVector.includes('/C:H/') ||
      cvssVector.includes('/I:H/') ||
      cvssVector.includes('/A:H/')
    )
      return 8.0;
    return 7.0;
  }
  if (cvssVector.includes('/AV:N/')) return 6.5;
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

function normalizeLicense(license) {
  if (!license || typeof license !== 'string') return null;

  const raw = license.trim().toUpperCase();

  if (raw === 'NOASSERTION' || raw === 'NONE') return null;

  if (raw === 'MIT') return 'MIT';
  if (raw === 'ISC') return 'ISC';
  if (raw === 'BSD-2-CLAUSE' || raw === 'BSD-2-CLAUSE-SHORT')
    return 'BSD-2-CLAUSE';
  if (raw === 'BSD-3-CLAUSE' || raw === 'BSD-3-CLAUSE-SHORT' || raw === 'BSD')
    return 'BSD-3-CLAUSE';
  if (raw === 'Apache-2.0' || raw === 'Apache-2.0-only') return 'Apache-2.0';
  if (raw === '0BSD') return '0BSD';
  if (raw === 'CC0-1.0') return 'CC0-1.0';
  if (raw === 'CC-BY-4.0') return 'CC-BY-4.0';
  if (raw === 'UNLICENSED') return 'UNLICENSED';

  if (raw.startsWith('GPL-')) {
    let base = raw.replace(/^GPL-/, '');
    base = base.replace(/-OR-LATER$/, '').replace(/-ONLY$/, '');
    if (/^\d+$/.test(base)) return `GPL-${base}`;
    if (/^\d+\.\d+$/.test(base)) return `GPL-${base}`;
    return 'GPL';
  }
  if (raw.startsWith('LGPL-')) {
    let base = raw.replace(/^LGPL-/, '');
    base = base.replace(/-OR-LATER$/, '').replace(/-ONLY$/, '');
    if (/^\d+$/.test(base)) return `LGPL-${base}`;
    if (/^\d+\.\d+$/.test(base)) return `LGPL-${base}`;
    return 'LGPL';
  }
  if (
    raw === 'AGPL-3.0' ||
    raw === 'AGPL-3.0-ONLY' ||
    raw === 'AGPL-3.0-OR-LATER'
  )
    return 'AGPL-3.0';
  if (raw.startsWith('AGPL-')) {
    let base = raw.replace(/^AGPL-/, '');
    base = base.replace(/-OR-LATER$/, '').replace(/-ONLY$/, '');
    if (/^\d+\.\d+$/.test(base)) return `AGPL-${base}`;
    return 'AGPL';
  }

  return raw;
}

function checkRestrictedLicenseFailures(results, opts) {
  if (!opts.failLicenses || opts.failLicenses.length === 0) return [];

  const failed = [];
  for (const r of results) {
    const lic = normalizeLicense(r.registry?.license);
    if (!lic) continue;

    for (const failLic of opts.failLicenses) {
      if (lic === failLic || lic.startsWith(failLic + '-')) {
        failed.push({
          name: r.name,
          version: r.resolvedVersion ?? r.versionSpec ?? '?',
          license: r.registry?.license ?? '(unknown)',
        });
        break;
      }
    }
  }
  return failed;
}

// ─── OpenSSF Scorecard client ─────────────────────────────────────────────────

/**
 * Parse a GitHub repository URL (in any common format) into { owner, repo }.
 */
function parseGitHubUrl(url) {
  if (!url || typeof url !== 'string') return null;

  const cleaned = url
    .replace(/^git\+/, '')
    .replace(/^git:\/\//, 'https://')
    .replace(/^ssh:\/\/git@github\.com/, 'https://github.com')
    .replace(/\.git$/, '')
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
    error: 'not_github_repo',
  };

  const parsed = parseGitHubUrl(repoUrl);
  if (!parsed) return Promise.resolve(notAvailable);

  // Normalise to lowercase so "Babel/Babel" and "babel/babel" share one entry
  const cacheKey = `${parsed.owner}/${parsed.repo}`.toLowerCase();

  if (scorecardCache.has(cacheKey)) {
    cacheStats.scorecardHits++;
    return scorecardCache.get(cacheKey);
  }

  const promise = _doFetchScorecard(parsed);
  scorecardCache.set(cacheKey, promise);
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
    error: 'not_github_repo',
  };
  const url = `${SCORECARD_API}/projects/github.com/${parsed.owner}/${parsed.repo}`;

  try {
    const res = await fetch(url, {
      headers: { Accept: 'application/json' },
      signal: AbortSignal.timeout(15_000),
    });

    if (res.status === 404)
      return { ...notAvailable, error: 'scorecard_not_found' };
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
      maintained: checkMap.get('Maintained') ?? null,
      codeReview: checkMap.get('Code-Review') ?? null,
      vulnerabilities: checkMap.get('Vulnerabilities') ?? null,
      signedReleases: checkMap.get('Signed-Releases') ?? null,
      branchProtection: checkMap.get('Branch-Protection') ?? null,
      securityPolicy: checkMap.get('Security-Policy') ?? null,
      dangerousWorkflow: checkMap.get('Dangerous-Workflow') ?? null,
      binaryArtifacts: checkMap.get('Binary-Artifacts') ?? null,
      pinned: checkMap.get('Pinned-Dependencies') ?? null,
      ciTests: checkMap.get('CI-Tests') ?? null,
    };

    const result = {
      score: data.score ?? null,
      checks,
      signals,
      repoChecked: `github.com/${parsed.owner}/${parsed.repo}`,
      error: null,
    };
    writeToCache(cacheKey, result, logWarn);
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
  if (opts.verbose) {
    log(`  → ${name}  (${versionSpec})`);
  }

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
      ? fetchVulnerabilities(name, resolvedVersion, 'npm')
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
          error: 'skipped',
        }),
    sourceRepo && !opts.skipScorecard
      ? fetchScorecard(sourceRepo)
      : Promise.resolve({
          score: null,
          checks: [],
          signals: {},
          error: sourceRepo ? 'skipped' : 'no_source_repo',
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
  if (opts.verbose) {
    logOk(`${name}@${resolvedVersion ?? '?'}  —  ${vulnPart}  ${scPart}`);
  }

  return {
    name,
    versionSpec,
    resolvedVersion: resolvedVersion ?? null,
    lockfileVersion: lockfileVersion ?? null,
    scope,
    ecosystem: 'npm',
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
    ecosystem: 'npm',
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
      error: 'package_not_found',
    },
    scorecard: {
      score: null,
      checks: [],
      signals: {},
      error: 'package_not_found',
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
 * @param {object} opts     CLI options (for license failure checks)
 * @param {Array}  kevMatches Optional CISA KEV matches
 * @returns {string}        Complete HTML document as a string
 */
function generateHtmlReport(results, pkg, opts, kevMatches = []) {
  // Load templates
  const cssTemplate = loadCssTemplate();
  const htmlTemplate = loadHtmlTemplate();

  const pkgLabel =
    `${pkg.name ?? '(unnamed)'}` + (pkg.version ? `@${pkg.version}` : '');

  const restrictedFailures = checkRestrictedLicenseFailures(results, opts);

  // Classify each result into its security signals — mirrors printReport logic
  const annotated = results.map((r) => {
    const signals = [];
    if (r.notFound) signals.push('not_found');
    if ((r.vulnerabilities?.summary?.total ?? 0) > 0) signals.push('vulns');
    if (r.registry?.hasInstallScripts) signals.push('scripts');
    if (
      r.scorecard?.score !== null &&
      r.scorecard?.score !== undefined &&
      r.scorecard.score < 5
    )
      signals.push('low_scorecard');
    if ((r.registry?.publishedHoursAgo ?? Infinity) < 48)
      signals.push('very_recent');
    if (!r.sourceRepository && !r.notFound) signals.push('no_repo');
    if (opts.failLicenses?.length > 0) {
      const lic = normalizeLicense(r.registry?.license);
      if (lic) {
        for (const failLic of opts.failLicenses) {
          if (lic === failLic || lic.startsWith(failLic + '-')) {
            signals.push('restricted_license');
            break;
          }
        }
      }
    }
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
  function safeDate(value, fallback = '—') {
    if (!value) return fallback;
    const dt = new Date(value);
    return isNaN(dt.getTime()) ? fallback : dt.toISOString().slice(0, 10);
  }

  /** Escape a value for safe embedding in HTML. */
  function he(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
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
    const cls = score < 3 ? 'sc-low' : score < 5 ? 'sc-med' : 'sc-high';
    return (
      `<span class="sc-bar ${cls}"><span class="sc-fill" style="width:${pct}%"></span></span>` +
      ` <span class="sc-score ${cls}">${score.toFixed(1)}</span>`
    );
  }

  function sevBadgeHtml(sev) {
    const cls = (sev ?? 'unknown').toLowerCase();
    return `<span class="sev-badge ${cls}">${he(sev ?? 'UNKNOWN')}</span>`;
  }

  // ── Per-package table rows ─────────────────────────────────────────────────
  const tableRows = annotated
    .map(({ r, signals }) => {
      const ver = r.resolvedVersion ?? r.versionSpec ?? '?';
      const hasFindings = signals.length > 0;
      const rowClass = r.notFound
        ? 'row-not-found'
        : hasFindings
          ? 'row-findings'
          : 'row-clean';

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
        `          <td class="td-scope"><span class="scope">${he(r.scope ?? '')}</span></td>\n` +
        `          <td class="td-vuln">${vulnBadgeHtml(r.vulnerabilities?.summary)}</td>\n` +
        `          <td class="td-sc">${scorecardHtml(r.scorecard?.score ?? null)}</td>\n` +
        `          <td class="td-scripts">${scriptHtml}</td>\n` +
        `          <td class="td-repo">${repoHtml}</td>\n` +
        `        </tr>`
      );
    })
    .join('\n');

  // ── Collapsible per-package finding cards ─────────────────────────────────
  const findingCards = findings
    .map(({ r, signals }) => {
      const ver = r.resolvedVersion ?? r.versionSpec ?? '?';

      const chips = [];
      if (signals.includes('vulns')) {
        const s = r.vulnerabilities.summary;
        const cls =
          s.critical > 0
            ? 'critical'
            : s.high > 0
              ? 'high'
              : s.medium > 0
                ? 'medium'
                : 'low';
        chips.push(
          `<span class="chip ${cls}">${s.total} vuln${s.total !== 1 ? 's' : ''}</span>`,
        );
      }
      if (signals.includes('scripts'))
        chips.push('<span class="chip scripts">install scripts</span>');
      if (signals.includes('low_scorecard'))
        chips.push(
          `<span class="chip scorecard">Scorecard ${r.scorecard.score.toFixed(1)}/10</span>`,
        );
      if (signals.includes('very_recent'))
        chips.push(
          `<span class="chip recent">published ${r.registry.publishedHoursAgo}h ago</span>`,
        );
      if (signals.includes('not_found'))
        chips.push('<span class="chip not-found">not found on registry</span>');
      if (signals.includes('no_repo'))
        chips.push('<span class="chip no-repo">no source repo</span>');
      if (signals.includes('restricted_license'))
        chips.push(
          `<span class="chip license">${he(r.registry?.license ?? 'restricted')}</span>`,
        );

      let body = '';

      // ── Vulnerabilities ──────────────────────────────────────────────────
      if (signals.includes('vulns')) {
        const list = r.vulnerabilities.list ?? [];
        const items = list
          .map((v) => {
            const fix = v.affectedRanges?.find((rng) => rng.fixed);
            const aliases = v.aliases?.length
              ? ` <span class="aliases">${v.aliases.map(he).join(', ')}</span>`
              : '';
            const refs = (v.references ?? [])
              .map(
                (url) =>
                  `<a href="${he(url)}" target="_blank" rel="noopener">${he(url)}</a>`,
              )
              .join(' ');
            return (
              `              <li class="vuln-item ${(v.severity ?? 'unknown').toLowerCase()}">\n` +
              `                <div class="vuln-header">${sevBadgeHtml(v.severity)} <strong>${he(v.id)}</strong>${aliases}</div>\n` +
              `                <div class="vuln-summary">${he(v.summary)}</div>\n` +
              (fix
                ? `                <div class="vuln-fix">Fix available: <code>${he(fix.fixed)}</code></div>\n`
                : '') +
              (refs
                ? `                <div class="vuln-refs">${refs}</div>\n`
                : '') +
              `              </li>`
            );
          })
          .join('\n');
        body +=
          `\n          <div class="detail-section">\n` +
          `            <h4>Vulnerabilities (${list.length})</h4>\n` +
          `            <ul class="vuln-list">\n${items}\n            </ul>\n` +
          `          </div>`;
      }

      // ── Install scripts ───────────────────────────────────────────────────
      if (signals.includes('scripts')) {
        const scripts = Object.entries(r.registry?.lifecycleScripts ?? {});
        const items = scripts
          .map(
            ([key, cmd]) =>
              `              <li><code class="script-key">${he(key)}</code>` +
              `<span class="script-cmd">${he(cmd)}</span></li>`,
          )
          .join('\n');
        body +=
          `\n          <div class="detail-section">\n` +
          `            <h4>Install Scripts (${scripts.length})</h4>\n` +
          `            <ul class="script-list">\n${items}\n            </ul>\n` +
          `          </div>`;
      }

      // ── Low Scorecard checks ──────────────────────────────────────────────
      if (signals.includes('low_scorecard')) {
        const bad = (r.scorecard.checks ?? [])
          .filter((chk) => typeof chk.score === 'number' && chk.score < 5)
          .sort((a, b) => a.score - b.score)
          .slice(0, 8);
        const items = bad
          .map((chk) => {
            const score = chk.score === -1 ? 'N/A' : `${chk.score}/10`;
            const reason = chk.reason
              ? ` <span class="sc-check-reason">&#x2014; ${he(chk.reason)}</span>`
              : '';
            return (
              `              <li>` +
              `<span class="sc-check-name">${he(chk.name)}</span>` +
              `<span class="sc-check-score">${score}</span>${reason}</li>`
            );
          })
          .join('\n');
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
            const versionUrl = `https://www.npmjs.com/package/${encodeURIComponent(r.name)}/v/${encodeURIComponent(vh.version)}`;
            return (
              `              <li><code><a href="${versionUrl}" target="_blank" rel="noopener noreferrer">${he(vh.version)}</a></code>` +
              `<span class="vdate">${d}</span></li>`
            );
          })
          .join('\n');
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
            `            <table class="meta-table"><tbody>${rows.join('')}</tbody></table>\n` +
            `          </div>`;
        }
      }

      return (
        `      <details class="pkg-finding" id="pkg-${he(r.name)}">\n` +
        `        <summary>\n` +
        `          <span class="pkg-name">${he(r.name)}</span>\n` +
        `          <span class="pkg-ver">${he(ver)}</span>\n` +
        `          <span class="chips">${chips.join('')}</span>\n` +
        `        </summary>\n` +
        `        <div class="finding-body">${body}\n        </div>\n` +
        `      </details>`
      );
    })
    .join('\n');

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
  if (restrictedFailures.length > 0)
    totalChips.push(
      `<span class="total-chip license">&#x2696; ${restrictedFailures.length} restricted license${restrictedFailures.length !== 1 ? 's' : ''}</span>`,
    );
  if (kevMatches.length > 0)
    totalChips.push(
      `<span class="total-chip kev">&#x25B2; ${kevMatches.length} KEV match${kevMatches.length !== 1 ? 'es' : ''}</span>`,
    );

  const findingsSection =
    findings.length > 0
      ? `  <section>\n    <h2>Findings (${findings.length})</h2>\n${findingCards}\n  </section>`
      : `  <section>\n    <p class="all-clean">&#x2713; No security issues detected across all ${results.length} package(s).</p>\n  </section>`;

  // ── License failure section ─────────────────────────────────────────────
  const licenseSection =
    restrictedFailures.length === 0
      ? ''
      : (() => {
          const items = restrictedFailures
            .map(({ name, version, license }) => {
              return (
                `    <li class="license-item">\n` +
                `      <div class="license-header">\n` +
                `        <span class="license-pkg-name">${he(name)}</span>\n` +
                `        <span class="license-pkg-ver">${he(version)}</span>\n` +
                `        <span class="license-badge">${he(license)}</span>\n` +
                `      </div>\n` +
                `    </li>`
              );
            })
            .join('\n');
          return (
            `  <section class="license-section">\n` +
            `    <div class="license-alert-banner">\n` +
            `      <span class="license-icon">&#x2696;&#xFE0F;</span>\n` +
            `      <span>RESTRICTED LICENSES &mdash; Copyleft licenses detected in dependencies</span>\n` +
            `      <span class="license-count">${restrictedFailures.length} match${restrictedFailures.length !== 1 ? 'es' : ''}</span>\n` +
            `    </div>\n` +
            `    <ul class="license-list">\n${items}\n    </ul>\n` +
            `  </section>`
          );
        })();

  // ── KEV alert section ────────────────────────────────────────────────────
  const kevSection =
    kevMatches.length === 0
      ? ''
      : (() => {
          const items = kevMatches
            .map(({ packageName, version, vuln, kev }) => {
              const ransomware =
                (kev.knownRansomwareCampaignUse ?? '').toLowerCase() === 'known'
                  ? `<div class="kev-ransomware">&#x26A0; Known ransomware campaign use</div>`
                  : '';
              const dueStr = kev.dueDate
                ? ` &middot; Due: <strong>${he(kev.dueDate)}</strong>`
                : '';
              return (
                `    <li class="kev-item">\n` +
                `      <div class="kev-item-header">\n` +
                `        <span class="kev-pkg-name">${he(packageName)}</span>\n` +
                `        <span class="kev-pkg-ver">${he(version)}</span>\n` +
                `        ${sevBadgeHtml(vuln.severity)}\n` +
                `        <span class="kev-cve">${he(vuln.id)}</span>\n` +
                `      </div>\n` +
                `      <div class="kev-meta">\n` +
                `        <span class="kev-meta-label">Summary</span>\n` +
                `        <span class="kev-meta-value">${he(vuln.summary)}</span>\n` +
                `        <span class="kev-meta-label">Vendor / Product</span>\n` +
                `        <span class="kev-meta-value">${he(kev.vendorProject)} &#x2014; ${he(kev.product)}</span>\n` +
                `        <span class="kev-meta-label">Added to KEV</span>\n` +
                `        <span class="kev-meta-value">${he(kev.dateAdded)}${dueStr}</span>\n` +
                `        <span class="kev-meta-label">Required action</span>\n` +
                `        <span class="kev-meta-value">${he(kev.requiredAction ?? '—')}</span>\n` +
                `      </div>\n` +
                `      ${ransomware}\n` +
                `      <a class="kev-catalog-link" href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener">&#x2197; CISA KEV Catalog</a>\n` +
                `    </li>`
              );
            })
            .join('\n');
          return (
            `  <section class="kev-section">\n` +
            `    <div class="kev-alert-banner">\n` +
            `      <span class="kev-icon">&#x26A0;&#xFE0F;</span>\n` +
            `      <span>KNOWN EXPLOITED VULNERABILITIES &mdash; Active exploitation confirmed by CISA</span>\n` +
            `      <span class="kev-count">${kevMatches.length} match${kevMatches.length !== 1 ? 'es' : ''}</span>\n` +
            `    </div>\n` +
            `    <ul class="kev-list">\n${items}\n    </ul>\n` +
            `  </section>`
          );
        })();

  // ── Assemble using template ──────────────────────────────────────────────
  const replacements = {
    TITLE: he(pkgLabel),
    CSS: cssTemplate,
    PKG_LABEL: he(pkgLabel),
    PKG_COUNT: results.length,
    GENERATED_AT: generatedAt,
    TOTAL_CHIPS: totalChips.join('\n  '),
    TABLE_ROWS: tableRows,
    KEV_SECTION: kevSection,
    LICENSE_SECTION: licenseSection,
    FINDINGS_SECTION: findingsSection,
  };

  return renderTemplate(htmlTemplate, replacements);
}

// Graph report generation moved to src/graph.js.

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
function printReport(
  results,
  pkg,
  opts,
  showFindings = false,
  kevMatches = [],
) {
  const W = Math.min(process.stderr.columns ?? 80, 90);
  const hr = (ch = '─') => ch.repeat(W);
  const HR = (ch = '━') => ch.repeat(W);

  // ── Classify each result into its security signals ────────────────────────
  const annotated = results.map((r) => {
    const signals = [];
    if (r.notFound) signals.push('not_found');
    if ((r.vulnerabilities?.summary?.total ?? 0) > 0) signals.push('vulns');
    if (r.registry?.hasInstallScripts) signals.push('scripts');
    if (
      r.scorecard?.score !== null &&
      r.scorecard?.score !== undefined &&
      r.scorecard.score < 5
    )
      signals.push('low_scorecard');
    if ((r.registry?.publishedHoursAgo ?? Infinity) < 48)
      signals.push('very_recent');
    if (!r.sourceRepository && !r.notFound) signals.push('no_repo');
    return { r, signals };
  });
  const findings = annotated.filter((a) => a.signals.length > 0);

  // ── Header ────────────────────────────────────────────────────────────────
  const pkgLabel =
    `${pkg.name ?? '(unnamed)'}` + (pkg.version ? `@${pkg.version}` : '');
  log('');
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
      ...results.map((r) => (r.resolvedVersion ?? r.versionSpec ?? '?').length),
    ) + 2;
  const COL_VULN = 14;
  const COL_SC = 16;

  log('');
  log(
    `${C.dim}  ` +
      rpad('PACKAGE', COL_NAME) +
      rpad('VERSION', COL_VER) +
      rpad('VULNS', COL_VULN) +
      rpad('SCORECARD', COL_SC) +
      `SCRIPTS${C.reset}`,
  );
  log(`  ${'─'.repeat(COL_NAME + COL_VER + COL_VULN + COL_SC + 10)}`);

  for (const { r } of annotated) {
    const name = r.notFound ? `${C.red}${r.name}${C.reset}` : r.name;
    const ver = r.resolvedVersion ?? r.versionSpec ?? '?';
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
    log('');
    log(
      `${C.bgreen}  ✓ All ${results.length} package(s) passed — ` +
        `no security issues detected.${C.reset}`,
    );
  } else if (!showFindings) {
    log('');
    log(
      `${C.dim}  ${findings.length} package(s) have signals — ` +
        `run with --findings for details.${C.reset}`,
    );
  } else {
    log('');
    log(hr());
    log(
      `${C.bold}  FINDINGS${C.reset}` +
        `  ·  ${findings.length} package(s) need attention`,
    );
    log(hr());

    for (const { r, signals } of findings) {
      const ver = r.resolvedVersion ?? r.versionSpec ?? '?';

      // Headline chips (brief coloured labels)
      const chips = [];
      if (signals.includes('vulns')) {
        const s = r.vulnerabilities.summary;
        chips.push(
          s.critical > 0
            ? `${C.bred}${s.total} critical vuln${s.total !== 1 ? 's' : ''}${C.reset}`
            : s.high > 0
              ? `${C.red}${s.total} high vuln${s.total !== 1 ? 's' : ''}${C.reset}`
              : s.medium > 0
                ? `${C.yellow}${s.total} medium vuln${s.total !== 1 ? 's' : ''}${C.reset}`
                : `${C.dim}${s.total} low vuln${s.total !== 1 ? 's' : ''}${C.reset}`,
        );
      }
      if (signals.includes('scripts'))
        chips.push(`${C.yellow}install scripts${C.reset}`);
      if (signals.includes('low_scorecard'))
        chips.push(
          `${C.yellow}Scorecard ${r.scorecard.score.toFixed(1)}/10${C.reset}`,
        );
      if (signals.includes('very_recent'))
        chips.push(
          `${C.byellow}published ${r.registry.publishedHoursAgo}h ago${C.reset}`,
        );
      if (signals.includes('not_found'))
        chips.push(`${C.red}not found on registry${C.reset}`);
      if (signals.includes('no_repo'))
        chips.push(`${C.dim}no source repository${C.reset}`);

      log('');
      log(`  ${C.bold}● ${r.name}@${ver}${C.reset}  ${chips.join('  ·  ')}`);

      // Vulnerability list
      if (signals.includes('vulns')) {
        const list = r.vulnerabilities.list ?? [];
        list.forEach((v, i) => {
          const last = i === list.length - 1;
          const tree = last ? '└' : '├';
          const cont = last ? ' ' : '│';
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
      if (signals.includes('scripts')) {
        const scripts = Object.entries(r.registry?.lifecycleScripts ?? {});
        scripts.forEach(([key, cmd], i) => {
          const last = i === scripts.length - 1;
          log(
            `    ${last ? '└' : '├'} ` +
              `${C.yellow}${rpad(key, 14)}${C.reset}` +
              `"${truncate(cmd, 55)}"`,
          );
        });
      }

      // Low-scoring Scorecard checks
      if (signals.includes('low_scorecard')) {
        const bad = (r.scorecard.checks ?? [])
          .filter((chk) => typeof chk.score === 'number' && chk.score < 5)
          .sort((a, b) => a.score - b.score)
          .slice(0, 5);
        bad.forEach((chk, i) => {
          const last = i === bad.length - 1;
          const score = chk.score === -1 ? 'N/A' : `${chk.score}/10`;
          log(
            `    ${last ? '└' : '├'} ` +
              `${C.dim}Scorecard · ${chk.name}: ${score}${C.reset}`,
          );
        });
      }

      // Very-recent-publish warning
      if (signals.includes('very_recent') && !signals.includes('vulns')) {
        log(
          `    └ ${C.yellow}Only ${r.registry.publishedHoursAgo}h old — ` +
            `consider waiting before adopting${C.reset}`,
        );
      }
    }
  }

  // ── CISA KEV alert section ─────────────────────────────────────────────────
  if (kevMatches.length > 0) {
    log('');
    const kevHr = `${C.bred}${hr()}${C.reset}`;
    log(kevHr);
    log(
      `${C.bred}  ▲ KNOWN EXPLOITED VULNERABILITIES (CISA KEV)${C.reset}` +
        `  ·  ${C.bred}${kevMatches.length} match${kevMatches.length !== 1 ? 'es' : ''}${C.reset} with actively exploited CVEs`,
    );
    log(kevHr);

    // Fixed label column width — longest label is "Vendor / Product:" (17 chars)
    // We pad each label to 17 chars then add 2 spaces of gutter.
    const KEV_LAB = 17 + 2; // 19 visible chars total
    const label = (txt) =>
      `    ${C.yellow}${txt}${C.reset}${' '.repeat(KEV_LAB - txt.length)}`;

    for (const { packageName, version, vuln, kev } of kevMatches) {
      log('');
      log(
        `  ${C.bred}● ${packageName}@${version}${C.reset}` +
          `  ${sevBadge(vuln.severity)}  ${C.bold}${vuln.id}${C.reset}`,
      );
      log(`    ${C.dim}${truncate(vuln.summary, W - 6)}${C.reset}`);
      log(`${label('Vendor / Product:')}${kev.vendorProject} — ${kev.product}`);
      log(
        `${label('Added to KEV:')}${kev.dateAdded}` +
          (kev.dueDate ? `  ·  Due: ${kev.dueDate}` : ''),
      );
      log(
        `${label('Required action:')}${truncate(kev.requiredAction ?? '—', W - KEV_LAB - 4)}`,
      );
      if ((kev.knownRansomwareCampaignUse ?? '').toLowerCase() === 'known') {
        log(`    ${C.bred}⚠  Known ransomware campaign use${C.reset}`);
      }
      log(
        `    ${C.cyan}https://www.cisa.gov/known-exploited-vulnerabilities-catalog${C.reset}`,
      );
    }

    log('');
    log(kevHr);
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
  if (kevMatches.length > 0)
    footerChips.push(
      `${C.bred}▲ ${kevMatches.length} KEV match${kevMatches.length !== 1 ? 'es' : ''}${C.reset}`,
    );

  log('');
  log(HR());
  log(`  ${footerChips.join('  ·  ')}`);
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
  return packageJsonUrl.replace(/package\.json$/, 'package-lock.json');
}

/**
 * Convert a package.json URL to a sibling file URL in the same directory.
 */
function getSiblingUrl(packageJsonUrl, siblingName) {
  return packageJsonUrl.replace(/package\.json$/, siblingName);
}

/**
 * Best-effort existence check for a remote file URL.
 */
async function remoteFileExists(url) {
  try {
    const res = await fetch(url, {
      method: 'HEAD',
      signal: AbortSignal.timeout(15000),
    });

    // Some hosts may not allow HEAD; fall back to a lightweight GET.
    if (res.status === 405) {
      const getRes = await fetch(url, {
        method: 'GET',
        headers: { Range: 'bytes=0-0' },
        signal: AbortSignal.timeout(15000),
      });
      return getRes.ok;
    }

    return res.ok;
  } catch {
    return false;
  }
}

/**
 * Fetch and parse a lockfile from a URL
 */
async function fetchLockfileFromUrl(url) {
  try {
    logOk(`Fetching lockfile from ${url}...\n`);
    const res = await fetch(url, {
      headers: { Accept: 'application/json' },
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
        'Usage: npx supply-chain-inspector <path/to/package.json|url|npm-package> [options]',
        '',
        'Input modes:',
        '  package.json path   Scan all dependencies in a local package.json',
        '  URL                 Scan a remote package.json (GitHub, raw content, etc.)',
        '  npm package name    Inspect a single package directly (e.g. lodash-es, @nx/jest)',
        '',
        'Options:',
        '  --include-dev          Include devDependencies',
        '  --include-peer         Include peerDependencies',
        '  --include-optional     Include optionalDependencies',
        '  --include-transitive   Include all transitive deps from package-lock.json',
        '                         (requires a lockfile; deduped by name@version)',
        '  --findings             Show per-package findings detail after the table',
        '                         (default: table only; hint shown when issues exist)',
        '  --concurrency=<N>      Max parallel fetches (default: 5)',
        '  --verbose              Show per-package fetch/progress logs',
        '  --version-history=<N>  Versions to keep per package (default: 10, min: 2)',
        '                           2  = downgrade / major-jump detection only',
        '                           5  = + rapid publish bursts + dormancy detection',
        '                           10 = + cadence baseline (recommended)',
        '                           20+= broader history, larger output',
        '  --lockfile=<path|url>  Path or URL to package-lock.json',
        '  --json                 Print the full JSON result to stdout',
        '  --output=<path>        Write JSON to a file (implies --json)',
        '  --html[=<path>]        Write a standalone HTML report to a file',
        '                         (defaults to report.html when no path given)',
        '  --graph[=<path>]       Write a vis-network dependency graph report',
        '                         (defaults to graph-report.html when no path given)',
        '  --graph-no-dev         In npm-package graph mode, hide devDependencies',
        '                         (default graph view includes all dependency scopes)',
        '  --no-scorecard         Skip OpenSSF Scorecard lookups',
        '  --no-vulns             Skip OSV.dev vulnerability lookups',
        '  --no-kev               Skip CISA KEV cross-reference (implies no KEV section)',
        '  --cache-dir=<path>     File-cache directory (default: .cache/ next to this script)',
        '  --no-cache             Disable the file cache entirely (always fetch live data)',
        '',
      ].join('\n'),
    );
    process.exit(1);
  }

  const isUrlInput = isUrl(opts.packageJsonPath);
  const isNpmInput =
    !isUrlInput &&
    isNpmPackageName(opts.packageJsonPath) &&
    !existsSync(resolve(opts.packageJsonPath));

  // ── NPM package name mode ──────────────────────────────────────────────────
  if (isNpmInput) {
    const parsed = parsePackageSpec(opts.packageJsonPath);
    if (!parsed) {
      process.stderr.write(
        `Error: Could not parse package spec: ${opts.packageJsonPath}\n`,
      );
      process.exit(1);
    }

    // File cache initialisation
    const scriptDir = getScriptDir();
    const resolvedCacheDir = opts.cacheDir
      ? resolve(opts.cacheDir)
      : join(scriptDir, '.cache');
    initCache(resolvedCacheDir, opts.noCache);

    const cacheDir = getCacheDir();
    if (cacheDir) {
      log(`${C.dim}Cache:    ${cacheDir}${C.reset}`);
    } else if (opts.noCache) {
      log(`${C.dim}Cache:    disabled (--no-cache)${C.reset}`);
    }

    log(`\nSupply Chain Inspector`);
    log(`Package: ${parsed.name}@${parsed.versionSpec}`);
    log(`Mode:    npm package (direct inspection)`);
    log('');

    const entry = {
      name: parsed.name,
      versionSpec: parsed.versionSpec,
      scope: 'direct',
    };

    log(`Inspecting 1 package — concurrency: ${opts.concurrency}`);
    if (opts.skipVulns) log('  [OSV.dev lookups skipped]');
    if (opts.skipScorecard) log('  [Scorecard lookups skipped]');
    log('');

    const results = await runWithConcurrency(
      [() => inspectPackage(entry, null, opts)],
      opts.concurrency,
    );

    // CISA KEV cross-reference
    let kevMatches = [];
    if (!opts.skipVulns && !opts.skipKev) {
      log(`\n${C.dim}Fetching CISA KEV catalog...${C.reset}`);
      const kevList = await fetchKEVList();
      if (kevList.length > 0) {
        kevMatches = matchKEVs(results, kevList);
        if (kevMatches.length > 0) {
          logWarn(
            `${kevMatches.length} KEV match${kevMatches.length !== 1 ? 'es' : ''} found — ` +
              `actively exploited CVE${kevMatches.length !== 1 ? 's' : ''} in this package!`,
          );
        } else {
          logOk(`KEV check complete — no actively exploited CVEs found.`);
        }
      }
    }

    // Summary
    const pkg = {
      name: parsed.name,
      version: results[0]?.resolvedVersion ?? null,
    };
    printReport(results, pkg, opts, opts.showFindings, kevMatches);

    // HTML report
    if (opts.html) {
      const htmlPath = resolve(opts.html);
      try {
        writeFileSync(
          htmlPath,
          generateHtmlReport(results, pkg, opts, kevMatches),
          'utf8',
        );
        log(`${C.dim}  HTML report written to: ${opts.html}${C.reset}`);
      } catch (err) {
        logErr(`Failed to write HTML report: ${err.message}`);
      }
    }

    // Graph report
    if (opts.graph) {
      const graphPath = resolve(opts.graph);
      try {
        const mainResult = results[0] ?? null;
        const reg = mainResult?.registry ?? {};
        const rootPkgLabel = `${parsed.name}@${mainResult?.resolvedVersion ?? parsed.versionSpec}`;
        const toDepEntries = (obj) =>
          Object.entries(obj ?? {}).map(([name, versionSpec]) => ({
            name,
            versionSpec,
          }));

        const graphContext = {
          rootLabel: parsed.name,
          rootTitle: `${rootPkgLabel}\nRoot npm package`,
          scopeDependencies: {
            dependencies: toDepEntries(reg.dependencies),
            devDependencies: opts.graphNoDev
              ? []
              : toDepEntries(reg.devDependencies),
            peerDependencies: toDepEntries(reg.peerDependencies),
            optionalDependencies: toDepEntries(reg.optionalDependencies),
          },
        };

        if (opts.graphNoDev) {
          log(
            `${C.dim}  graph: hiding devDependencies for npm-package mode ` +
              `(remove --graph-no-dev to include them)${C.reset}`,
          );
        }

        writeFileSync(
          graphPath,
          generateGraphReport(
            results,
            pkg,
            opts,
            kevMatches,
            null,
            null,
            graphContext,
          ),
          'utf8',
        );
        log(`${C.dim}  Graph report written to: ${opts.graph}${C.reset}`);
      } catch (err) {
        logErr(`Failed to write graph report: ${err.message}`);
      }
    }

    // Cache stats
    const uniqueNpm = npmCache.size;
    const uniqueScorecard = scorecardCache.size;
    const anyStats =
      cacheStats.npmHits > 0 ||
      cacheStats.scorecardHits > 0 ||
      fileCacheStats.hits > 0 ||
      fileCacheStats.writes > 0;
    if (anyStats) {
      const parts = [];
      if (fileCacheStats.hits > 0)
        parts.push(
          `${fileCacheStats.hits} file-cache hit${fileCacheStats.hits !== 1 ? 's' : ''}`,
        );
      if (fileCacheStats.writes > 0)
        parts.push(`${fileCacheStats.writes} written`);
      if (cacheStats.npmHits > 0 || cacheStats.scorecardHits > 0)
        parts.push(
          `${cacheStats.npmHits + cacheStats.scorecardHits} in-flight deduped`,
        );
      log(`${C.dim}  cache: ${parts.join('  ·  ')}${C.reset}`);
      log('');
    }

    // JSON output
    if (opts.json) {
      const json = JSON.stringify(results, null, 2);
      if (opts.output) {
        writeFileSync(resolve(opts.output), json, 'utf8');
        log(`${C.dim}  JSON written to: ${opts.output}${C.reset}`);
      } else {
        process.stdout.write(json + '\n');
      }
    } else {
      log(
        `${C.dim}  Tip: run with --json to print full data, or --output=<file> to save it.${C.reset}`,
      );
      log('');
    }

    // Exit code
    const severityLevels = ['low', 'medium', 'high', 'critical'];
    const failThreshold = severityLevels.indexOf(opts.failOn);
    let shouldFail = false;

    const restrictedFailures = checkRestrictedLicenseFailures(results, opts);
    if (restrictedFailures.length > 0) {
      shouldFail = true;
      log('');
      const boxWidth = 79;
      const topLine = '╔' + '═'.repeat(boxWidth - 2) + '╗';
      const bottomLine = '╚' + '═'.repeat(boxWidth - 2) + '╝';
      const message = `LICENSE FAILURE: Restricted licenses found`;
      const padding = ' '.repeat(boxWidth - 2 - message.length - 2);
      const contentLine = `║  ${message}${padding}║`;
      log(`${C.bred}${topLine}${C.reset}`);
      log(`${C.bred}${contentLine}${C.reset}`);
      log(`${C.bred}${bottomLine}${C.reset}`);
      log('');
      for (const pkg of restrictedFailures) {
        logErr(
          `  ${C.red}▪${C.reset} ${C.bold}${pkg.name}${C.reset}${C.dim}@${pkg.version}${C.reset}: ${C.yellow}${pkg.license}${C.reset}`,
        );
      }
      log('');
    }

    for (const result of results) {
      if (result.vulnerabilities?.summary) {
        const summary = result.vulnerabilities.summary;
        for (let i = failThreshold; i < severityLevels.length; i++) {
          const level = severityLevels[i];
          if (summary[level] > 0) {
            shouldFail = true;
            log('');
            const boxWidth = 79;
            const topLine = '╔' + '═'.repeat(boxWidth - 2) + '╗';
            const bottomLine = '╚' + '═'.repeat(boxWidth - 2) + '╝';
            const message = `SECURITY FAILURE: Vulnerabilities at or above '${opts.failOn}' threshold`;
            const padding = ' '.repeat(boxWidth - 2 - message.length - 2);
            const contentLine = `║  ${message}${padding}║`;
            log(`${C.bred}${topLine}${C.reset}`);
            log(`${C.bred}${contentLine}${C.reset}`);
            log(`${C.bred}${bottomLine}${C.reset}`);
            log('');
            const colorMap = {
              critical: C.bred,
              high: C.red,
              medium: C.yellow,
              low: C.dim,
            };
            logErr(
              `  ${C.red}▪${C.reset} ${C.bold}${result.name}${C.reset}${C.dim}:${C.reset} ${colorMap[level]}${summary[level]} ${level.toUpperCase()}${C.reset}`,
            );
            log('');
            break;
          }
        }
      }
    }

    if (kevMatches.length > 0) {
      shouldFail = true;
    }

    if (shouldFail) process.exit(1);
    return; // Exit early — skip the package.json flow below
  }

  let pkgPath;
  let pkg;

  if (isUrlInput) {
    // Fetch package.json from URL
    try {
      logOk(`Fetching package.json from ${opts.packageJsonPath}...\n`);
      const res = await fetch(opts.packageJsonPath, {
        headers: { Accept: 'application/json' },
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
      pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
    } catch (err) {
      process.stderr.write(
        `Error: Failed to parse ${basename(pkgPath)}: ${err.message}\n`,
      );
      process.exit(1);
    }
  }

  // ── File cache initialisation ─────────────────────────────────────────────
  const scriptDir = getScriptDir();
  const resolvedCacheDir = opts.cacheDir
    ? resolve(opts.cacheDir)
    : join(scriptDir, '.cache');
  initCache(resolvedCacheDir, opts.noCache);

  // Log cache directory info
  const cacheDir = getCacheDir();
  if (cacheDir) {
    log(`${C.dim}Cache:    ${cacheDir}${C.reset}`);
  } else if (opts.noCache) {
    log(`${C.dim}Cache:    disabled (--no-cache)${C.reset}`);
  }

  log(`\nSupply Chain Inspector`);
  log(`Package: ${pkg.name ?? '(unnamed)'} ${pkg.version ?? ''}`);
  log(`Source:  ${pkgPath}`);

  // ── Load lockfile for exact version resolution ──────────────────────────────
  let lockfilePath;
  let lockfileData = null;
  let hasRemotePnpmLockfile = false;
  let remotePnpmLockfileUrl = null;

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

      if (opts.includeTransitive && !lockfileData) {
        remotePnpmLockfileUrl = getSiblingUrl(pkgPath, 'pnpm-lock.yaml');
        hasRemotePnpmLockfile = await remoteFileExists(remotePnpmLockfileUrl);
      }
    }
  } else {
    // Local file handling (existing behavior)
    lockfilePath = opts.lockfilePath
      ? resolve(opts.lockfilePath)
      : resolve(dirname(pkgPath), 'package-lock.json');
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

  // ── Collect all dependency entries to inspect ───────────────────────────────
  const entries = [];

  const addDeps = (depsObj, scope) => {
    if (!depsObj || typeof depsObj !== 'object') return;
    for (const [name, versionSpec] of Object.entries(depsObj)) {
      entries.push({ name, versionSpec, scope });
    }
  };

  addDeps(pkg.dependencies, 'dependencies');
  addDeps(pkg.devDependencies, opts.includeDev ? 'devDependencies' : null);
  addDeps(pkg.peerDependencies, opts.includePeer ? 'peerDependencies' : null);
  addDeps(
    pkg.optionalDependencies,
    opts.includeOptional ? 'optionalDependencies' : null,
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
        '--include-transitive requires a lockfile' +
          (lockfileData === null && isUrlInput
            ? hasRemotePnpmLockfile
              ? ` (package-lock.json not found at remote location; detected pnpm-lock.yaml at ${remotePnpmLockfileUrl}, but only package-lock.json is currently supported)`
              : ' (lockfile not found at remote location)'
            : !lockfilePath
              ? ''
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
        entries.push({ name, versionSpec: version, scope: 'transitive' });
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
    log('\nNo dependencies found to inspect.');
    if (opts.json) {
      const json = JSON.stringify([], null, 2);
      if (opts.output) {
        writeFileSync(opts.output, json, 'utf8');
        log(`Output written to: ${opts.output}`);
      } else {
        process.stdout.write(json + '\n');
      }
    }
    process.exit(0);
  }

  log(
    `\nInspecting ${toInspect.length} package(s) — concurrency: ${opts.concurrency}`,
  );
  if (opts.skipVulns) log('  [OSV.dev lookups skipped]');
  if (opts.skipScorecard) log('  [Scorecard lookups skipped]');
  log('');

  // ── Run all inspections with concurrency limit ──────────────────────────────
  const tasks = toInspect.map(
    (entry) => () =>
      inspectPackage(
        entry,
        selectLockfileVersionForEntry(entry, lockfileVersions),
        opts,
      ),
  );

  const results = await runWithConcurrency(tasks, opts.concurrency);

  // ── CISA KEV cross-reference ─────────────────────────────────────────────
  let kevMatches = [];
  if (!opts.skipVulns && !opts.skipKev) {
    log(`\n${C.dim}Fetching CISA KEV catalog...${C.reset}`);
    const kevList = await fetchKEVList();
    if (kevList.length > 0) {
      kevMatches = matchKEVs(results, kevList);
      if (kevMatches.length > 0) {
        logWarn(
          `${kevMatches.length} KEV match${kevMatches.length !== 1 ? 'es' : ''} found — ` +
            `actively exploited CVE${kevMatches.length !== 1 ? 's' : ''} in your dependencies!`,
        );
      } else {
        logOk(`KEV check complete — no actively exploited CVEs found.`);
      }
    }
  }

  // ── Summary ─────────────────────────────────────────────────────────────────
  // ── Security report ───────────────────────────────────────────────────────
  printReport(results, pkg, opts, opts.showFindings, kevMatches);

  // ── HTML report (opt-in via --html=<path>) ────────────────────────────────
  if (opts.html) {
    const htmlPath = resolve(opts.html);
    try {
      writeFileSync(
        htmlPath,
        generateHtmlReport(results, pkg, opts, kevMatches),
        'utf8',
      );
      log(`${C.dim}  HTML report written to: ${opts.html}${C.reset}`);
    } catch (err) {
      logErr(`Failed to write HTML report: ${err.message}`);
    }
  }

  // ── Graph report (opt-in via --graph=<path>) ─────────────────────────────
  if (opts.graph) {
    const graphPath = resolve(opts.graph);
    try {
      writeFileSync(
        graphPath,
        generateGraphReport(
          results,
          pkg,
          opts,
          kevMatches,
          lockfileData,
          lockfilePath,
        ),
        'utf8',
      );
      log(`${C.dim}  Graph report written to: ${opts.graph}${C.reset}`);
    } catch (err) {
      logErr(`Failed to write graph report: ${err.message}`);
    }
  }

  // ── Cache stats ───────────────────────────────────────────────────────────
  const uniqueNpm = npmCache.size;
  const uniqueScorecard = scorecardCache.size;
  const anyStats =
    cacheStats.npmHits > 0 ||
    cacheStats.scorecardHits > 0 ||
    fileCacheStats.hits > 0 ||
    fileCacheStats.writes > 0;
  if (anyStats) {
    const parts = [];
    if (fileCacheStats.hits > 0)
      parts.push(
        `${fileCacheStats.hits} file-cache hit${fileCacheStats.hits !== 1 ? 's' : ''}`,
      );
    if (fileCacheStats.writes > 0)
      parts.push(`${fileCacheStats.writes} written`);
    if (cacheStats.npmHits > 0 || cacheStats.scorecardHits > 0)
      parts.push(
        `${cacheStats.npmHits + cacheStats.scorecardHits} in-flight deduped`,
      );
    log(`${C.dim}  cache: ${parts.join('  ·  ')}${C.reset}`);
    log('');
  }

  // ── Lockfile status (summary) ───────────────────────────────────────────
  const lockfileResolvedCount = lockfileVersions.size;
  const lockfileSource = lockfileData
    ? 'remote'
    : lockfilePath && existsSync(lockfilePath)
      ? 'local'
      : null;

  if (lockfileResolvedCount > 0 && lockfileSource) {
    const autoDetected =
      isUrlInput && !opts.lockfilePath && lockfileSource === 'remote';
    const sourceText = autoDetected
      ? `${lockfileSource}, auto-detected`
      : lockfileSource;
    log(
      `${C.dim}  lockfile: ${sourceText} (${lockfileResolvedCount} resolved version${lockfileResolvedCount !== 1 ? 's' : ''})${C.reset}`,
    );
  } else {
    const reason = isUrlInput
      ? hasRemotePnpmLockfile
        ? 'package-lock missing/unreadable; pnpm-lock.yaml detected but unsupported'
        : 'missing or unreadable remote lockfile'
      : 'missing or unreadable lockfile';
    log(
      `${C.dim}  lockfile: none (${reason}; npm registry fallback)${C.reset}`,
    );
  }
  log('');

  // ── JSON output (opt-in via --json or --output) ───────────────────────────
  if (opts.json) {
    const json = JSON.stringify(results, null, 2);
    if (opts.output) {
      writeFileSync(resolve(opts.output), json, 'utf8');
      log(`${C.dim}  JSON written to: ${opts.output}${C.reset}`);
    } else {
      process.stdout.write(json + '\n');
    }
  } else {
    log(
      `${C.dim}  Tip: run with --json to print full data, or --output=<file> to save it.${C.reset}`,
    );
    log('');
  }

  // ── Exit code based on --fail-on threshold and --fail-licenses ────────
  const severityLevels = ['low', 'medium', 'high', 'critical'];
  const failThreshold = severityLevels.indexOf(opts.failOn);

  let shouldFail = false;
  const failedPackages = [];

  // Check license failures
  const restrictedFailures = checkRestrictedLicenseFailures(results, opts);
  if (restrictedFailures.length > 0) {
    shouldFail = true;
    log('');
    const boxWidth = 79;
    const topLine = '╔' + '═'.repeat(boxWidth - 2) + '╗';
    const bottomLine = '╚' + '═'.repeat(boxWidth - 2) + '╝';
    const message = `LICENSE FAILURE: Restricted licenses found in dependencies`;
    const padding = ' '.repeat(boxWidth - 2 - message.length - 2);
    const contentLine = `║  ${message}${padding}║`;

    log(`${C.bred}${topLine}${C.reset}`);
    log(`${C.bred}${contentLine}${C.reset}`);
    log(`${C.bred}${bottomLine}${C.reset}`);
    log('');
    for (const pkg of restrictedFailures.slice(0, 5)) {
      logErr(
        `  ${C.red}▪${C.reset} ${C.bold}${pkg.name}${C.reset}${C.dim}@${pkg.version}${C.reset}: ${C.yellow}${pkg.license}${C.reset}`,
      );
    }
    if (restrictedFailures.length > 5) {
      log(`  ${C.dim}... and ${restrictedFailures.length - 5} more${C.reset}`);
    }
    log('');
  }

  // Check vulnerability failures
  for (const result of results) {
    if (result.vulnerabilities && result.vulnerabilities.summary) {
      const summary = result.vulnerabilities.summary;
      for (let i = failThreshold; i < severityLevels.length; i++) {
        const level = severityLevels[i];
        if (summary[level] > 0) {
          shouldFail = true;
          failedPackages.push({
            name: result.name,
            level: level,
            count: summary[level],
          });
          break;
        }
      }
    }
  }

  if (failedPackages.length > 0) {
    log('');
    const boxWidth = 79;
    const topLine = '╔' + '═'.repeat(boxWidth - 2) + '╗';
    const bottomLine = '╚' + '═'.repeat(boxWidth - 2) + '╝';
    const message = `SECURITY FAILURE: Vulnerabilities found at or above '${opts.failOn}' threshold`;
    const padding = ' '.repeat(boxWidth - 2 - message.length - 2);
    const contentLine = `║  ${message}${padding}║`;

    log(`${C.bred}${topLine}${C.reset}`);
    log(`${C.bred}${contentLine}${C.reset}`);
    log(`${C.bred}${bottomLine}${C.reset}`);
    log('');
    for (const pkg of failedPackages.slice(0, 5)) {
      const colorMap = {
        critical: C.bred,
        high: C.red,
        medium: C.yellow,
        low: C.dim,
      };
      const color = colorMap[pkg.level] || C.red;
      logErr(
        `  ${C.red}▪${C.reset} ${C.bold}${pkg.name}${C.reset}${C.dim}:${C.reset} ${color}${pkg.count} ${pkg.level.toUpperCase()}${C.reset}`,
      );
    }
    if (failedPackages.length > 5) {
      log(`  ${C.dim}... and ${failedPackages.length - 5} more${C.reset}`);
    }
    log('');
  }

  // ── KEV hard-fail (always triggers when matches exist, unless --no-kev) ───
  // A KEV entry means active real-world exploitation confirmed by CISA.
  // This is independent of --fail-on: even a MEDIUM KEV is more dangerous
  // than a theoretical CRITICAL that nobody is currently exploiting.
  if (kevMatches.length > 0) {
    log('');
    const boxWidth = 79;
    const topLine = '╔' + '═'.repeat(boxWidth - 2) + '╗';
    const bottomLine = '╚' + '═'.repeat(boxWidth - 2) + '╝';
    const n = kevMatches.length;
    const message = `SECURITY FAILURE: ${n} actively exploited CVE${n !== 1 ? 's' : ''} (CISA KEV) in your dependencies`;
    const padding = ' '.repeat(Math.max(0, boxWidth - 2 - message.length - 2));
    const contentLine = `║  ${message}${padding}║`;

    log(`${C.bred}${topLine}${C.reset}`);
    log(`${C.bred}${contentLine}${C.reset}`);
    log(`${C.bred}${bottomLine}${C.reset}`);
    log('');
    for (const { packageName, version, vuln, kev } of kevMatches) {
      logErr(
        `  ${C.red}▪${C.reset} ${C.bold}${packageName}@${version}${C.reset}` +
          `${C.dim}:${C.reset} ${C.bred}${vuln.id}${C.reset}` +
          `  ${C.dim}(added to KEV: ${kev.dateAdded})${C.reset}`,
      );
    }
    log('');
    shouldFail = true;
  }

  if (shouldFail) {
    process.exit(1);
  }
}

// ─── CLI entry point ─────────────────────────────────────────────────────────

const isMainModule = (() => {
  if (!process.argv[1]) return false;

  try {
    const argvPath = realpathSync(resolve(process.argv[1]));
    const modulePath = realpathSync(fileURLToPath(import.meta.url));
    return argvPath === modulePath;
  } catch {
    return import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
  }
})();

if (isMainModule) {
  main().catch((err) => {
    process.stderr.write(`\nFatal error: ${err.message}\n${err.stack}\n`);
    process.exit(1);
  });
}
