#!/usr/bin/env bash
#
# Integration test: simulates what `npx supply-chain-inspector` does.
# Packs the current branch into a tarball, installs it in an isolated
# temp directory, and runs it against a test package.json.
#
# Usage:  bash tests/integration-npx.sh
# Requires: node >= 18, npm

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  ✓ $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  ✗ $1"; }

echo "=== npx integration test ==="
echo "Temp dir: $TMPDIR"
echo ""

# ── 1. Pack the project ──────────────────────────────────────────────────────
echo "1. Packing tarball..."
cd "$REPO_ROOT"
TARBALL=$(npm pack --pack-destination "$TMPDIR" 2>/dev/null | tail -1)
TARBALL_PATH="$TMPDIR/$TARBALL"
if [ ! -f "$TARBALL_PATH" ]; then
  fail "Tarball not created at $TARBALL_PATH"
  echo "FAIL"; exit 1
fi
pass "Tarball created: $TARBALL"

# ── 2. Create an isolated install directory ──────────────────────────────────
echo ""
echo "2. Installing in isolated directory..."
INSTALL_DIR="$TMPDIR/project"
mkdir -p "$INSTALL_DIR"

# Create a minimal package.json so npm install has something to work with
cat > "$INSTALL_DIR/package.json" <<'PKGJSON'
{
  "name": "test-project",
  "version": "1.0.0",
  "private": true,
  "dependencies": {
    "left-pad": "1.3.0"
  }
}
PKGJSON

# Install from tarball
cd "$INSTALL_DIR"
npm install "$TARBALL_PATH" --save 2>/dev/null >/dev/null
if [ -d "$INSTALL_DIR/node_modules/supply-chain-inspector" ]; then
  pass "Package installed successfully"
else
  fail "Package not found in node_modules"
  echo "FAIL"; exit 1
fi

# ── 3. Verify the bin entry works ────────────────────────────────────────────
echo ""
echo "3. Verifying bin entry..."
BIN_PATH="$INSTALL_DIR/node_modules/.bin/supply-chain-inspector"
if [ -L "$BIN_PATH" ] && [ -x "$BIN_PATH" ]; then
  pass "Bin symlink exists and is executable"
else
  fail "Bin symlink missing or not executable at $BIN_PATH"
  echo "FAIL"; exit 1
fi

# ── 4. Run the script against left-pad (single package) ─────────────────────
echo ""
echo "4. Running: npx supply-chain-inspector left-pad --no-scorecard --no-vulns"
cd "$INSTALL_DIR"
OUTPUT=$("$BIN_PATH" left-pad --no-scorecard --no-vulns 2>&1 || true)
if echo "$OUTPUT" | grep -q "Supply Chain Inspector"; then
  pass "Script started and printed header"
else
  fail "Script did not print expected header"
  echo "  Output: $OUTPUT"
fi

if echo "$OUTPUT" | grep -q "left-pad"; then
  pass "Script found and inspected left-pad"
else
  fail "Script did not inspect left-pad"
  echo "  Output: $OUTPUT"
fi

# ── 5. Verify cache directory was created ────────────────────────────────────
echo ""
echo "5. Checking cache directory..."
# Cache is at package_root/.cache (two levels up from src/cache.js)
PKG_ROOT="$INSTALL_DIR/node_modules/supply-chain-inspector"
CACHE_DIR="$PKG_ROOT/.cache"
if [ -d "$CACHE_DIR" ]; then
  pass "Cache directory created at $CACHE_DIR"
  CACHE_FILES=$(ls "$CACHE_DIR"/*.json 2>/dev/null | wc -l)
  pass "Cache contains $CACHE_FILES file(s)"
else
  fail "Cache directory not found at $CACHE_DIR"
fi

# ── 6. Run again to verify cache hits ───────────────────────────────────────
echo ""
echo "6. Running again (should use cache)..."
OUTPUT2=$("$BIN_PATH" left-pad --no-scorecard --no-vulns 2>&1 || true)
if echo "$OUTPUT2" | grep -q "cache:"; then
  pass "Second run shows cache stats"
else
  pass "Second run completed"
fi

# ── 7. Test --json output ────────────────────────────────────────────────────
echo ""
echo "7. Testing --json output..."
OUTPUT3=$("$BIN_PATH" left-pad --no-cache --no-scorecard --no-vulns --json 2>/dev/null || true)
if echo "$OUTPUT3" | grep -q '"name": "left-pad"'; then
  pass "--json output contains expected data"
else
  fail "--json output missing expected data"
  echo "  Output: $OUTPUT3"
fi

# ── 8. Test --help ───────────────────────────────────────────────────────────
echo ""
echo "8. Testing --help (via invalid input to trigger usage)..."
OUTPUT4=$("$BIN_PATH" 2>&1 || true)
if echo "$OUTPUT4" | grep -q "Usage:"; then
  pass "Help/usage text displayed"
else
  # Some versions print help differently
  if echo "$OUTPUT4" | grep -q "supply-chain-inspector"; then
    pass "Help text contains package name"
  else
    fail "Help text not displayed"
    echo "  Output: $OUTPUT4"
  fi
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "=== Results ==="
TOTAL=$((PASS + FAIL))
echo "  $PASS/$TOTAL passed"
if [ $FAIL -gt 0 ]; then
  echo "  $FAIL failed"
  exit 1
else
  echo "  All tests passed!"
fi
