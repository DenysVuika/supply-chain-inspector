import { describe, it, expect } from "vitest";
import { isNpmPackageName, parsePackageSpec } from "./inspect.js";

// ── isNpmPackageName ─────────────────────────────────────────────────────────

describe("isNpmPackageName()", () => {
  // ── Should recognise as npm packages ───────────────────────────────────────

  it("accepts a plain unscoped name", () => {
    expect(isNpmPackageName("lodash")).toBe(true);
  });

  it("accepts a hyphenated unscoped name", () => {
    expect(isNpmPackageName("lodash-es")).toBe(true);
  });

  it("accepts a scoped package", () => {
    expect(isNpmPackageName("@nx/jest")).toBe(true);
  });

  it("accepts a scoped package with dots", () => {
    expect(isNpmPackageName("@angular/core")).toBe(true);
  });

  it("accepts a scoped package with hyphens", () => {
    expect(isNpmPackageName("@my-org/my-package")).toBe(true);
  });

  it("accepts a scoped package with underscores", () => {
    expect(isNpmPackageName("@scope/my_pkg")).toBe(true);
  });

  it("accepts a name with digits", () => {
    expect(isNpmPackageName("node16")).toBe(true);
  });

  it("accepts a single-word name", () => {
    expect(isNpmPackageName("react")).toBe(true);
  });

  // ── Version specifiers ─────────────────────────────────────────────────────

  it("accepts unscoped name with version", () => {
    expect(isNpmPackageName("lodash-es@4.17.21")).toBe(true);
  });

  it("accepts scoped name with version", () => {
    expect(isNpmPackageName("@nx/jest@20.8.3")).toBe(true);
  });

  it("accepts scoped name with complex version", () => {
    expect(isNpmPackageName("@angular/core@^17.0.0")).toBe(true);
  });

  it("accepts name with tilde range", () => {
    expect(isNpmPackageName("express@~4.18.0")).toBe(true);
  });

  // ── Should reject as NOT npm package names ─────────────────────────────────

  it("rejects a JSON file path", () => {
    expect(isNpmPackageName("package.json")).toBe(false);
  });

  it("rejects a .js file", () => {
    expect(isNpmPackageName("index.js")).toBe(false);
  });

  it("rejects a .ts file", () => {
    expect(isNpmPackageName("main.ts")).toBe(false);
  });

  it("rejects a .mjs file", () => {
    expect(isNpmPackageName("util.mjs")).toBe(false);
  });

  it("rejects a .lock file", () => {
    expect(isNpmPackageName("package-lock.json")).toBe(false);
  });

  it("rejects relative path with ./", () => {
    expect(isNpmPackageName("./package.json")).toBe(false);
  });

  it("rejects relative path with ../", () => {
    expect(isNpmPackageName("../package.json")).toBe(false);
  });

  it("rejects absolute path", () => {
    expect(isNpmPackageName("/home/user/package.json")).toBe(false);
  });

  it("rejects a relative directory path", () => {
    expect(isNpmPackageName("src/index")).toBe(false);
  });

  it("rejects empty string", () => {
    expect(isNpmPackageName("")).toBe(false);
  });

  it("rejects null", () => {
    expect(isNpmPackageName(null)).toBe(false);
  });

  it("rejects undefined", () => {
    expect(isNpmPackageName(undefined)).toBe(false);
  });

  it("rejects a URL", () => {
    expect(isNpmPackageName("https://example.com/package.json")).toBe(false);
  });

  it("rejects a .yaml file", () => {
    expect(isNpmPackageName("config.yaml")).toBe(false);
  });

  it("rejects a .toml file", () => {
    expect(isNpmPackageName("Cargo.toml")).toBe(false);
  });
});

// ── parsePackageSpec ──────────────────────────────────────────────────────────

describe("parsePackageSpec()", () => {
  // ── Unscoped packages ──────────────────────────────────────────────────────

  it("parses a plain unscoped name", () => {
    expect(parsePackageSpec("lodash")).toEqual({
      name: "lodash",
      versionSpec: "*",
    });
  });

  it("parses a hyphenated unscoped name", () => {
    expect(parsePackageSpec("lodash-es")).toEqual({
      name: "lodash-es",
      versionSpec: "*",
    });
  });

  it("parses unscoped name with exact version", () => {
    expect(parsePackageSpec("lodash-es@4.17.21")).toEqual({
      name: "lodash-es",
      versionSpec: "4.17.21",
    });
  });

  it("parses unscoped name with semver range", () => {
    expect(parsePackageSpec("express@^4.18.2")).toEqual({
      name: "express",
      versionSpec: "^4.18.2",
    });
  });

  it("parses unscoped name with tilde range", () => {
    expect(parsePackageSpec("react@~18.2.0")).toEqual({
      name: "react",
      versionSpec: "~18.2.0",
    });
  });

  // ── Scoped packages ────────────────────────────────────────────────────────

  it("parses a scoped name without version", () => {
    expect(parsePackageSpec("@nx/jest")).toEqual({
      name: "@nx/jest",
      versionSpec: "*",
    });
  });

  it("parses a scoped name with version", () => {
    expect(parsePackageSpec("@nx/jest@20.8.3")).toEqual({
      name: "@nx/jest",
      versionSpec: "20.8.3",
    });
  });

  it("parses a scoped name with semver range", () => {
    expect(parsePackageSpec("@angular/core@^17.0.0")).toEqual({
      name: "@angular/core",
      versionSpec: "^17.0.0",
    });
  });

  it("parses a scoped name with tilde range", () => {
    expect(parsePackageSpec("@types/node@~20.11.0")).toEqual({
      name: "@types/node",
      versionSpec: "~20.11.0",
    });
  });

  it("parses a scoped name with complex org name", () => {
    expect(parsePackageSpec("@my-org/my-package@1.0.0-beta.1")).toEqual({
      name: "@my-org/my-package",
      versionSpec: "1.0.0-beta.1",
    });
  });

  // ── Edge cases ─────────────────────────────────────────────────────────────

  it("returns null for null input", () => {
    expect(parsePackageSpec(null)).toBeNull();
  });

  it("returns null for empty string", () => {
    expect(parsePackageSpec("")).toBeNull();
  });

  it("returns null for bare scope with no name", () => {
    expect(parsePackageSpec("@nx")).toBeNull();
  });
});
