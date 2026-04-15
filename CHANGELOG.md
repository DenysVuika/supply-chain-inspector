# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.1] — 2026-04-15

### Changed

- Updated `license` field in `package.json` to use the SPDX identifier `Apache-2.0`
  instead of the non-standard `SEE LICENSE IN LICENSE` string

### Added

- `CHANGELOG.md` — project changelog following the [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format

---

## [0.1.0] — 2026-04-15

### Added

- **Vulnerability scanning** via [OSV.dev](https://osv.dev) — known CVEs and
  security advisories, severity-ranked (Critical / High / Medium / Low) with
  full advisory details, aliases, and affected version ranges
- **OpenSSF Scorecard integration** via [scorecard.dev](https://scorecard.dev) —
  aggregate score out of 10 plus individual check scores covering code review,
  branch protection, signed releases, dangerous workflows, binary artifacts,
  pinned dependencies, CI tests, security policy, and more
- **Install-script detection** — flags packages that declare `preinstall`,
  `postinstall`, `prepare`, or other lifecycle hooks (a common malware vector)
- **Publisher history tracking** — shows who published each of the last N versions
  to help detect account takeovers or unexpected publisher changes
- **Version history** — configurable look-back window (`--version-history=<N>`,
  default 10) to surface dormancy, publish bursts, or suspicious major version jumps
- **Transitive dependency support** (`--include-transitive`) — scans every
  package resolved in `package-lock.json`, not just direct dependencies,
  deduplicated by `name@version`
- **Lockfile-aware resolution** — auto-detects `package-lock.json` next to
  `package.json` for exact pinned versions instead of resolving semver ranges
- **Dependency scope flags** — `--include-dev`, `--include-peer`,
  `--include-optional` to extend scanning beyond production dependencies
- **Formatted terminal report** — colour-coded summary table with vulnerability
  badges, scorecard progress bars, and script indicators; expandable per-package
  findings detail via `--findings`
- **Standalone HTML report** (`--html=<path>`) — fully self-contained, shareable
  report viewable in any browser with no server or internet connection required
- **JSON output** (`--json`, `--output=<path>`) — machine-readable result array
  for piping into other tools, CI artifacts, or AI assistants
- **File cache** — API responses cached to disk to speed up repeated runs and
  reduce network usage (npm Registry: 6 h, OSV.dev: 6 h, OpenSSF Scorecard: 24 h)
- **In-flight deduplication** — concurrent workers that request the same package
  or repository share a single HTTP request instead of firing duplicates
- **Configurable concurrency** (`--concurrency=<N>`, default 5) for tuning
  parallel package fetches against API rate limits
- **Cache control flags** — `--cache-dir=<path>` to share a cache across
  projects; `--no-cache` to force fresh data on every run
- **`--no-scorecard` / `--no-vulns`** flags to skip individual data sources for
  faster or offline runs
- **`NO_COLOR` support** — disables ANSI colours when set; colours are also
  automatically disabled when stderr is not a TTY
- **Zero dependencies** — uses Node.js 18+ built-in `fetch`; nothing to install
- **Dual bin aliases** — available as both `supply-chain-inspector` and the
  shorter `nsci` after a global install
- **`npx` support** — run directly from the npm registry with no prior install step

[0.1.1]: https://github.com/denysvuika/supply-chain-inspector/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/denysvuika/supply-chain-inspector/releases/tag/v0.1.0