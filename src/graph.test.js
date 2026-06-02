import { describe, expect, it } from 'vitest';
import {
  extractLockfileDependencyEdges,
  generateGraphReport,
} from './graph.js';

describe('extractLockfileDependencyEdges()', () => {
  it('extracts edges from lockfile v2 packages map', () => {
    const lock = {
      packages: {
        '': { name: 'root' },
        'node_modules/a': {
          version: '1.0.0',
          dependencies: { b: '^1.0.0' },
        },
        'node_modules/b': {
          version: '1.1.0',
        },
      },
    };

    const edges = extractLockfileDependencyEdges(lock);
    expect(edges).toEqual(
      expect.arrayContaining([
        {
          fromName: 'a',
          fromVersion: '1.0.0',
          toName: 'b',
          toVersion: '1.1.0',
        },
      ]),
    );
  });

  it('considers optional and peer dependencies', () => {
    const lock = {
      packages: {
        'node_modules/a': {
          version: '1.0.0',
          optionalDependencies: { b: '^1.0.0' },
          peerDependencies: { c: '^1.0.0' },
        },
        'node_modules/b': { version: '1.2.0' },
        'node_modules/c': { version: '1.3.0' },
      },
    };

    const edges = extractLockfileDependencyEdges(lock);
    expect(edges).toEqual(
      expect.arrayContaining([
        {
          fromName: 'a',
          fromVersion: '1.0.0',
          toName: 'b',
          toVersion: '1.2.0',
        },
        {
          fromName: 'a',
          fromVersion: '1.0.0',
          toName: 'c',
          toVersion: '1.3.0',
        },
      ]),
    );
  });
});

describe('generateGraphReport()', () => {
  function parsePayloadFromHtml(html) {
    const payloadMatch = html.match(/const graphPayload = (\{[\s\S]*?\});\n/);
    expect(payloadMatch).toBeTruthy();
    return JSON.parse(payloadMatch[1]);
  }

  function rootConnectedNodeIds(payload) {
    const adjacency = new Map(payload.nodes.map((n) => [n.id, new Set()]));
    for (const edge of payload.edges) {
      if (!adjacency.has(edge.from) || !adjacency.has(edge.to)) continue;
      adjacency.get(edge.from).add(edge.to);
      adjacency.get(edge.to).add(edge.from);
    }

    const root = payload.nodes.find((n) => n.group === 'root');
    expect(root).toBeTruthy();

    const seen = new Set([root.id]);
    const queue = [root.id];
    while (queue.length > 0) {
      const current = queue.shift();
      for (const next of adjacency.get(current) || []) {
        if (seen.has(next)) continue;
        seen.add(next);
        queue.push(next);
      }
    }

    return seen;
  }

  it('injects rendered graph script into HTML template', () => {
    const results = [
      {
        name: 'left-pad',
        versionSpec: '^1.3.0',
        resolvedVersion: '1.3.0',
        scope: 'dependencies',
        notFound: false,
        registry: { hasInstallScripts: false },
        vulnerabilities: {
          summary: {
            total: 1,
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            unknown: 0,
          },
        },
        scorecard: { score: 7.2 },
      },
    ];

    const html = generateGraphReport(
      results,
      { name: 'demo', version: '1.0.0' },
      { includeTransitive: false },
      [],
      null,
      null,
      null,
    );

    expect(html).toContain('const graphPayload = {');
    expect(html).toContain('new vis.Network(container, data, options)');
    expect(html).not.toContain('__GRAPH_SCRIPT__');
    expect(html).not.toContain('{{GRAPH_PAYLOAD}}');
    expect(html).toContain("Reflow Once");
    expect(html).toContain('id="btn-refit"');
    expect(html).not.toContain('id="btn-reset"');
    expect(html).not.toContain('id="btn-collapse"');
  });

  it('adds lockfile parent path for red transitive nodes without scanned parent results', () => {
    const results = [
      {
        name: 'tmp',
        versionSpec: '0.2.4',
        resolvedVersion: '0.2.4',
        scope: 'transitive',
        notFound: false,
        registry: { hasInstallScripts: false },
        vulnerabilities: {
          summary: {
            total: 1,
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            unknown: 0,
          },
        },
        scorecard: { score: 7.2 },
      },
    ];

    const lockfileData = {
      packages: {
        'node_modules/nx': {
          version: '22.7.4',
          dependencies: { tmp: '0.2.4' },
        },
        'node_modules/nx/node_modules/tmp': {
          version: '0.2.4',
        },
      },
    };

    const html = generateGraphReport(
      results,
      {
        name: 'demo',
        version: '1.0.0',
        dependencies: { nx: '^22.0.0' },
      },
      { includeTransitive: true },
      [],
      lockfileData,
      null,
      null,
    );

    const payload = parsePayloadFromHtml(html);
    const nxNode = payload.nodes.find((n) => n.label === 'nx@22.7.4');
    const tmpNode = payload.nodes.find((n) => n.label === 'tmp@0.2.4');
    const depsScopeNode = payload.nodes.find((n) => n.label === 'dependencies');

    expect(nxNode).toBeTruthy();
    expect(tmpNode).toBeTruthy();
    expect(depsScopeNode).toBeTruthy();
    expect(
      payload.edges.some(
        (e) =>
          e.kind === 'contains' &&
          e.from === depsScopeNode.id &&
          e.to === nxNode.id,
      ),
    ).toBe(true);
    expect(
      payload.edges.some(
        (e) =>
          e.kind === 'depends' && e.from === nxNode.id && e.to === tmpNode.id,
      ),
    ).toBe(true);
  });

  it('keeps all red findings connected to root component', () => {
    const results = [
      {
        name: 'a-parent',
        versionSpec: '1.0.0',
        resolvedVersion: '1.0.0',
        scope: 'transitive',
        notFound: false,
        registry: { hasInstallScripts: false },
        vulnerabilities: {
          summary: {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            unknown: 0,
          },
        },
        scorecard: { score: 7.2 },
      },
      {
        name: 'b-red',
        versionSpec: '2.0.0',
        resolvedVersion: '2.0.0',
        scope: 'transitive',
        notFound: false,
        registry: { hasInstallScripts: false },
        vulnerabilities: {
          summary: {
            total: 1,
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            unknown: 0,
          },
        },
        scorecard: { score: 7.2 },
      },
    ];

    const lockfileData = {
      packages: {
        'node_modules/a-parent': {
          version: '1.0.0',
          dependencies: { 'b-red': '2.0.0' },
        },
        'node_modules/a-parent/node_modules/b-red': {
          version: '2.0.0',
        },
      },
    };

    const html = generateGraphReport(
      results,
      {
        name: 'demo',
        version: '1.0.0',
      },
      { includeTransitive: true },
      [],
      lockfileData,
      null,
      null,
    );

    const payload = parsePayloadFromHtml(html);
    const connected = rootConnectedNodeIds(payload);
    const redNodes = payload.nodes.filter((n) => n.riskTone === 'red');

    expect(redNodes.length).toBeGreaterThan(0);
    for (const redNode of redNodes) {
      expect(connected.has(redNode.id)).toBe(true);
    }
  });

  it('prunes disconnected components from payload graph', () => {
    const results = [
      {
        name: 'main-red',
        versionSpec: '1.0.0',
        resolvedVersion: '1.0.0',
        scope: 'dependencies',
        notFound: false,
        registry: { hasInstallScripts: false },
        vulnerabilities: {
          summary: {
            total: 1,
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            unknown: 0,
          },
        },
        scorecard: { score: 7.2 },
      },
      {
        name: 'island-parent',
        versionSpec: '1.0.0',
        resolvedVersion: '1.0.0',
        scope: 'transitive',
        notFound: false,
        registry: { hasInstallScripts: false },
        vulnerabilities: {
          summary: {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            unknown: 0,
          },
        },
        scorecard: { score: 7.2 },
      },
      {
        name: 'island-child',
        versionSpec: '2.0.0',
        resolvedVersion: '2.0.0',
        scope: 'transitive',
        notFound: false,
        registry: { hasInstallScripts: false },
        vulnerabilities: {
          summary: {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            unknown: 0,
          },
        },
        scorecard: { score: 7.2 },
      },
    ];

    const lockfileData = {
      packages: {
        'node_modules/island-parent': {
          version: '1.0.0',
          dependencies: { 'island-child': '2.0.0' },
        },
        'node_modules/island-parent/node_modules/island-child': {
          version: '2.0.0',
        },
      },
    };

    const html = generateGraphReport(
      results,
      {
        name: 'demo',
        version: '1.0.0',
        dependencies: { 'main-red': '^1.0.0' },
      },
      { includeTransitive: true },
      [],
      lockfileData,
      null,
      null,
    );

    const payload = parsePayloadFromHtml(html);
    const connected = rootConnectedNodeIds(payload);

    expect(connected.size).toBe(payload.nodes.length);
    expect(payload.nodes.find((n) => n.label === 'island-parent@1.0.0')).toBeFalsy();
    expect(payload.nodes.find((n) => n.label === 'island-child@2.0.0')).toBeFalsy();
  });
});
