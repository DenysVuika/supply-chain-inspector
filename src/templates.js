/**
 * templates.js
 * Template loading and rendering utilities for HTML report generation.
 * Loads CSS and HTML templates from the assets/templates directory.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const TEMPLATES_DIR = resolve(__dirname, "..", "assets", "templates");
const HTML_DIR = resolve(TEMPLATES_DIR, "html");
const GRAPH_DIR = resolve(TEMPLATES_DIR, "graph");
const CSS_PATH = resolve(HTML_DIR, "report.css");
const HTML_PATH = resolve(HTML_DIR, "report.html");
const GRAPH_CSS_PATH = resolve(GRAPH_DIR, "report.css");
const GRAPH_HTML_PATH = resolve(GRAPH_DIR, "report.html");
const GRAPH_JS_PATH = resolve(GRAPH_DIR, "report.js");

let cssCache = null;
let htmlCache = null;
let graphCssCache = null;
let graphHtmlCache = null;
let graphJsCache = null;

/**
 * Load and cache the CSS template.
 * @returns {string} The CSS content
 */
export function loadCssTemplate() {
  if (cssCache) return cssCache;
  try {
    cssCache = readFileSync(CSS_PATH, "utf8");
    return cssCache;
  } catch (err) {
    throw new Error(`Failed to load CSS template from ${CSS_PATH}: ${err.message}`);
  }
}

/**
 * Load and cache the HTML template.
 * @returns {string} The HTML template content
 */
export function loadHtmlTemplate() {
  if (htmlCache) return htmlCache;
  try {
    htmlCache = readFileSync(HTML_PATH, "utf8");
    return htmlCache;
  } catch (err) {
    throw new Error(`Failed to load HTML template from ${HTML_PATH}: ${err.message}`);
  }
}

/**
 * Load and cache the graph CSS template.
 * @returns {string} The graph CSS content
 */
export function loadGraphCssTemplate() {
  if (graphCssCache) return graphCssCache;
  try {
    graphCssCache = readFileSync(GRAPH_CSS_PATH, "utf8");
    return graphCssCache;
  } catch (err) {
    throw new Error(
      `Failed to load graph CSS template from ${GRAPH_CSS_PATH}: ${err.message}`,
    );
  }
}

/**
 * Load and cache the graph HTML template.
 * @returns {string} The graph HTML template content
 */
export function loadGraphHtmlTemplate() {
  if (graphHtmlCache) return graphHtmlCache;
  try {
    graphHtmlCache = readFileSync(GRAPH_HTML_PATH, "utf8");
    return graphHtmlCache;
  } catch (err) {
    throw new Error(
      `Failed to load graph HTML template from ${GRAPH_HTML_PATH}: ${err.message}`,
    );
  }
}

/**
 * Load and cache the graph JavaScript template.
 * @returns {string} The graph JavaScript template content
 */
export function loadGraphJsTemplate() {
  if (graphJsCache) return graphJsCache;
  try {
    graphJsCache = readFileSync(GRAPH_JS_PATH, "utf8");
    return graphJsCache;
  } catch (err) {
    throw new Error(
      `Failed to load graph JS template from ${GRAPH_JS_PATH}: ${err.message}`,
    );
  }
}

/**
 * Clear template caches (useful for testing or reload).
 */
export function clearTemplateCache() {
  cssCache = null;
  htmlCache = null;
  graphCssCache = null;
  graphHtmlCache = null;
  graphJsCache = null;
}

/**
 * Simple template replacement - replaces placeholders in the form {{PLACEHOLDER}} with values.
 * @param {string} template - The template string with {{PLACEHOLDER}} markers
 * @param {Object} replacements - Object with key-value pairs for replacement
 * @returns {string} The template with all placeholders replaced
 */
export function renderTemplate(template, replacements) {
  let result = template;
  for (const [key, value] of Object.entries(replacements)) {
    const placeholder = `{{${key}}}`;
    result = result.split(placeholder).join(value);
  }
  return result;
}

/**
 * Get the templates directory path.
 * @returns {string} The absolute path to the templates directory
 */
export function getTemplatesDir() {
  return TEMPLATES_DIR;
}
