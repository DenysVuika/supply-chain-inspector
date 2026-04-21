# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [1.2.0] — 2026-05-01

### Added

- **CISA KEV cross-reference** — after vulnerability scanning, all discovered CVEs are
  automatically matched against the [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
  - Fetches the full KEV catalog over HTTPS with a 24-hour file cache (no API key required)
  - Matches on both primary OSV IDs (e.g. `GHSA-xxxx`) **and** all CVE aliases, so
    `GHSA-2m8v-572m-ff2v → CVE-2021-21315` is correctly identified as a KEV hit
  - KEV section only appears when at least one match is found, keeping clean scans noise-free

- **CLI KEV alert section** — a bold red `▲▲▲` banner is printed below the findings
  block whenever KEV matches are detected, listing for each match:
  - Package name and version, severity badge, and CVE/advisory ID
  - CISA vendor, product, date added to KEV, and remediation due date
  - Required action text from the CISA catalog
  - Ransomware campaign flag (`⚠ Known ransomware campaign use`) when applicable
  - Direct link to the CISA KEV catalog

- **HTML report KEV section** — a styled alert card block is injected above the
  Findings section when KEV matches exist, with full metadata per match (vendor,
  product, dates, required action, ransomware badge, CISA catalog link); a
  `▲ N KEV matches` chip is also added to the totals banner

- **`--no-kev` flag** — skips the CISA KEV fetch and cross-reference step
  (KEV is also skipped automatically when `--no-vulns` is used); also the only
  way to opt out of the KEV hard-fail in CI

- **KEV hard-fail** — any KEV match causes the script to exit with code `1`
  unconditionally, independent of `--fail-on`; a dedicated failure box is
  printed listing each matching package, CVE ID, and the date it was added to
  the catalog; both the `--fail-on` box and the KEV box are shown when both
  conditions trigger in the same run

- **KEV footer chip** — `▲ N KEV matches` appended to the terminal report footer
  totals line alongside the existing severity counts

- **CISA KEV** added to the data sources list in the HTML report footer

### Changed

- Cache TTL table extended with KEV entry: 24 h (CISA updates the catalog ~weekly)
- Exit-code logic restructured: `--fail-on` severity check no longer calls
  `process.exit(1)` immediately; both the severity check and the KEV check now
  set a shared `shouldFail` flag, allowing both failure boxes to be displayed
  before a single `process.exit(1)` at the end of the run
- CI Integration documentation updated to reflect that KEV matches are a second,
  always-on hard-fail path alongside `--fail-on`

---

## [1.1.0] — 2026-04-20

### Added

- **`--fail-on` option** — exit with code 1 when vulnerabilities at or above the specified severity threshold are found
  - Accepts `low`, `medium`, `high`, or `critical` (default: `critical`)
  - Enables CI pipeline failures based on security policy
  - When set to `low`, any vulnerability will cause failure; when set to `critical`, only critical vulnerabilities trigger failure
  - Displays a clear, boxed failure message listing affected packages with severity badges

### Changed

- Version numbers in HTML report "Recent Version History" are now clickable links to corresponding NPM package version pages
- CI Integration documentation updated to demonstrate `--fail-on` usage for pipeline security gates

---

## [1.0.0] — 2026-04-16

### Added

- **Remote URL support** — inspect dependencies from remote `package.json` URLs without cloning repositories
  - Accepts any HTTP(S) URL as input (e.g., `https://raw.githubusercontent.com/user/repo/refs/heads/main/package.json`)
  - Automatically fetches and parses remote `package.json` files with proper error handling and 30-second timeout
  - Useful for CI/CD pipelines, quick audits, and inspecting public repositories
- **Remote lockfile support** — automatic fetching of `package-lock.json` from remote URLs
  - Auto-detects and fetches `package-lock.json` from the same directory as remote `package.json`
  - Supports explicit remote lockfile URLs via `--lockfile=<url>`
  - Enables `--include-transitive` functionality with remote URLs
  - Mixed mode: use remote `package.json` with local lockfile or vice versa
  - Graceful fallback when remote lockfile is not found (404 responses handled cleanly)
- **Enhanced `--lockfile` option** — now accepts both local paths and remote URLs
  - Format: `--lockfile=<path|url>`
  - Works seamlessly with both local and remote `package.json` inputs

### Changed

- Refactored lockfile parsing logic for better code reuse:
  - Extracted `parseLockfileVersions()` to parse lockfile data objects
  - Extracted `loadAllLockfilePackagesFromData()` for transitive dependency extraction
  - Both local and remote lockfiles now use the same parsing logic
- Improved error messages for `--include-transitive` to provide context-specific guidance
- Updated all documentation (script comments, usage messages, README) to reflect URL support

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

[1.2.0]: https://github.com/denysvuika/supply-chain-inspector/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/denysvuika/supply-chain-inspector/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/denysvuika/supply-chain-inspector/compare/v0.1.1...v1.0.0
[0.1.1]: https://github.com/denysvuika/supply-chain-inspector/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/denysvuika/supply-chain-inspector/releases/tag/v0.1.0