/**
 * logger.js
 *
 * Logging helpers for supply-chain-inspector.
 * All output goes to stderr so that stdout stays clean for --json output.
 */

export function log(msg) {
  process.stderr.write(msg + "\n");
}

export function logOk(msg) {
  process.stderr.write(`  ✓ ${msg}\n`);
}

export function logErr(msg) {
  process.stderr.write(`  ✗ ${msg}\n`);
}

export function logWarn(msg) {
  process.stderr.write(`  ⚠ ${msg}\n`);
}
