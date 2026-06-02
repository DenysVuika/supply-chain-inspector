/**
 * pkg.js
 *
 * Pure utility functions for parsing and detecting npm package name specs.
 * Extracted so they can be tested without triggering the CLI entry point.
 */

/**
 * Check if a string looks like an npm package name.
 * Handles both scoped (@scope/name) and unscoped (lodash-es) names.
 * Returns false for file paths (contains / not starting with @, has extension, etc.)
 */
export function isNpmPackageName(str) {
  if (!str || typeof str !== "string") return false;

  // Strip version specifier to get the base package name
  // lodash-es@4.17.21 → lodash-es, @nx/angular@20.8.3 → @nx/angular
  let baseName = str;
  if (str.startsWith("@")) {
    // Scoped: @scope/name@version → last @ splits name from version
    const lastAt = str.lastIndexOf("@");
    if (lastAt > 0) baseName = str.slice(0, lastAt); // @scope/name
  } else {
    // Unscoped: name@version → first @ splits name from version
    const firstAt = str.indexOf("@");
    if (firstAt > 0) baseName = str.slice(0, firstAt); // name
  }

  // File paths: has a directory separator that's not part of a scope
  if (baseName.includes("/") && !baseName.startsWith("@")) return false;

  // File paths: has a file extension like .json, .js, .ts, etc.
  if (/\.(json|js|ts|mjs|cjs|jsx|tsx|yaml|yml|toml|lock)$/i.test(baseName))
    return false;

  // File paths: starts with ./ or ../ or absolute path
  if (baseName.startsWith(".") || baseName.startsWith("/")) return false;

  // npm package names: must match [@[scope/]name][@version]
  // Scoped: @scope/name — name part allows a-z, 0-9, ., -, _
  // Unscoped: name — allows a-z, 0-9, ., -, _
  const npmNameRegex = /^(?:@[^@\s]+\/)?[^@\s]+$/;
  if (!npmNameRegex.test(baseName)) return false;

  // Additional: npm package names must not be empty
  const nameOnly = baseName.replace(/^@[^/]+\//, "");
  if (!nameOnly || nameOnly.length === 0) return false;

  return true;
}

/**
 * Parse an npm package spec string into { name, versionSpec }.
 * Supports:
 *   lodash-es          → { name: "lodash-es", versionSpec: "*" }
 *   lodash-es@4.17.21  → { name: "lodash-es", versionSpec: "4.17.21" }
 *   @nx/jest           → { name: "@nx/jest", versionSpec: "*" }
 *   @nx/jest@1.0.0     → { name: "@nx/jest", versionSpec: "1.0.0" }
 */
export function parsePackageSpec(spec) {
  if (!spec) return null;

  if (spec.startsWith("@")) {
    // Scoped: @scope/name or @scope/name@version
    const withoutAt = spec.slice(1);
    const slashIdx = withoutAt.indexOf("/");
    if (slashIdx === -1) return null; // Malformed scoped name

    const scope = withoutAt.slice(0, slashIdx);
    const rest = withoutAt.slice(slashIdx + 1);

    const lastAt = rest.lastIndexOf("@");
    if (lastAt > 0) {
      return {
        name: `@${scope}/${rest.slice(0, lastAt)}`,
        versionSpec: rest.slice(lastAt + 1),
      };
    }
    return { name: `@${scope}/${rest}`, versionSpec: "*" };
  }

  // Unscoped: name or name@version
  const lastAt = spec.lastIndexOf("@");
  if (lastAt > 0) {
    return {
      name: spec.slice(0, lastAt),
      versionSpec: spec.slice(lastAt + 1),
    };
  }
  return { name: spec, versionSpec: "*" };
}
