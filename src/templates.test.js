import { describe, it, expect, beforeEach } from "vitest";
import {
  loadCssTemplate,
  loadHtmlTemplate,
  clearTemplateCache,
  renderTemplate,
  getTemplatesDir,
} from "./templates.js";

describe("renderTemplate()", () => {
  it("replaces a single placeholder", () => {
    const result = renderTemplate("Hello {{NAME}}!", { NAME: "World" });
    expect(result).toBe("Hello World!");
  });

  it("replaces multiple different placeholders", () => {
    const result = renderTemplate("{{A}} and {{B}}", { A: "foo", B: "bar" });
    expect(result).toBe("foo and bar");
  });

  it("replaces the same placeholder multiple times", () => {
    const result = renderTemplate("{{X}}/{{X}}/{{X}}", { X: "a" });
    expect(result).toBe("a/a/a");
  });

  it("handles missing keys gracefully (leaves placeholder intact)", () => {
    const result = renderTemplate("Hello {{NAME}}!", {});
    expect(result).toBe("Hello {{NAME}}!");
  });

  it("handles extra keys in replacements (ignores them)", () => {
    const result = renderTemplate("Hello {{NAME}}!", { NAME: "A", EXTRA: "B" });
    expect(result).toBe("Hello A!");
  });

  it("replaces with empty string", () => {
    const result = renderTemplate("Hello {{NAME}}!", { NAME: "" });
    expect(result).toBe("Hello !");
  });

  it("replaces with values containing special characters", () => {
    const result = renderTemplate("{{VAL}}", { VAL: '<script>alert("xss")</script>' });
    expect(result).toBe('<script>alert("xss")</script>');
  });

  it("handles template with no placeholders", () => {
    const result = renderTemplate("plain text", { KEY: "val" });
    expect(result).toBe("plain text");
  });

  it("handles empty template string", () => {
    const result = renderTemplate("", { KEY: "val" });
    expect(result).toBe("");
  });

  it("handles multiline template content", () => {
    const template = "line1\n{{A}}\nline2\n{{B}}";
    const result = renderTemplate(template, { A: "one", B: "two" });
    expect(result).toBe("line1\none\nline2\ntwo");
  });
});

describe("getTemplatesDir()", () => {
  it("returns a non-empty string path", () => {
    const dir = getTemplatesDir();
    expect(typeof dir).toBe("string");
    expect(dir.length).toBeGreaterThan(0);
  });

  it("ends with assets/templates", () => {
    const dir = getTemplatesDir();
    expect(dir).toMatch(/assets[/\\]templates$/);
  });
});

describe("loadCssTemplate()", () => {
  beforeEach(() => {
    clearTemplateCache();
  });

  it("returns a non-empty string", () => {
    const css = loadCssTemplate();
    expect(typeof css).toBe("string");
    expect(css.length).toBeGreaterThan(0);
  });

  it("contains expected CSS variables", () => {
    const css = loadCssTemplate();
    expect(css).toContain("--bg:");
    expect(css).toContain("--text:");
  });

  it("returns the same value on subsequent calls (caching)", () => {
    const first = loadCssTemplate();
    const second = loadCssTemplate();
    expect(second).toBe(first);
  });
});

describe("loadHtmlTemplate()", () => {
  beforeEach(() => {
    clearTemplateCache();
  });

  it("returns a non-empty string", () => {
    const html = loadHtmlTemplate();
    expect(typeof html).toBe("string");
    expect(html.length).toBeGreaterThan(0);
  });

  it("contains expected placeholders", () => {
    const html = loadHtmlTemplate();
    expect(html).toContain("{{TITLE}}");
    expect(html).toContain("{{CSS}}");
    expect(html).toContain("{{PKG_LABEL}}");
    expect(html).toContain("{{TABLE_ROWS}}");
    expect(html).toContain("{{FINDINGS_SECTION}}");
  });

  it("returns the same value on subsequent calls (caching)", () => {
    const first = loadHtmlTemplate();
    const second = loadHtmlTemplate();
    expect(second).toBe(first);
  });
});

describe("clearTemplateCache()", () => {
  it("clears cached values so next load reads from disk", () => {
    clearTemplateCache();
    const first = loadHtmlTemplate();
    clearTemplateCache();
    const second = loadHtmlTemplate();
    // Same content since it's the same file, but cache was reset
    expect(second).toBe(first);
  });
});
