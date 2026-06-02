/**
 * graph.js
 * Graph report generation for dependency visualization.
 */

import {
  loadGraphCssTemplate,
  loadGraphHtmlTemplate,
  loadGraphJsTemplate,
  renderTemplate,
} from './templates.js';

/**
 * Extract package-to-package dependency edges from package-lock.json data.
 * Supports lockfile v1 nested dependencies and v2/v3 packages map.
 * Returns objects: { fromName, fromVersion, toName, toVersion }.
 */
export function extractLockfileDependencyEdges(lock) {
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

  // Resolve dependency package path using Node-style upward lookup through
  // ancestor node_modules directories.
  const resolveDepPath = (parentPath, depName, versionByPath) => {
    const safeParent = parentPath || '';

    // Root-level resolution candidate.
    const rootCandidate = `node_modules/${depName}`;

    // Parent-local candidate first.
    if (safeParent) {
      const localCandidate = `${safeParent}/node_modules/${depName}`;
      if (versionByPath.has(localCandidate)) return localCandidate;
    }

    let cursor = safeParent;
    while (cursor) {
      // Remove one package segment from .../node_modules/<name> (supports scoped names).
      const up = cursor.replace(/\/node_modules\/(?:@[^/]+\/)?[^/]+$/, '');
      if (up === cursor) break;
      cursor = up;
      const candidate = cursor
        ? `${cursor}/node_modules/${depName}`
        : rootCandidate;
      if (versionByPath.has(candidate)) return candidate;
    }

    if (versionByPath.has(rootCandidate)) return rootCandidate;
    return null;
  };

  // lockfile v2/v3: flat packages map keyed by node_modules path
  if (lock.packages && typeof lock.packages === 'object') {
    const versionByPath = new Map();
    for (const [pkgPath, pkgMeta] of Object.entries(lock.packages)) {
      if (!pkgPath || pkgPath === '') continue; // root
      if (!pkgPath.includes('node_modules/')) continue;
      const parts = pkgPath.split('node_modules/');
      const name = parts[parts.length - 1];
      if (!name) continue;
      versionByPath.set(pkgPath, { name, version: pkgMeta?.version ?? null });
    }

    for (const [pkgPath, pkgMeta] of Object.entries(lock.packages)) {
      if (!pkgPath || pkgPath === '') continue;
      if (!pkgPath.includes('node_modules/')) continue;
      const fromInfo = versionByPath.get(pkgPath);
      if (!fromInfo) continue;

      const depNames = new Set([
        ...Object.keys(pkgMeta?.dependencies ?? {}),
        ...Object.keys(pkgMeta?.optionalDependencies ?? {}),
        ...Object.keys(pkgMeta?.peerDependencies ?? {}),
      ]);
      for (const depName of depNames) {
        const resolvedPath = resolveDepPath(pkgPath, depName, versionByPath);
        const toInfo = resolvedPath ? versionByPath.get(resolvedPath) : null;
        addEdge(
          fromInfo.name,
          fromInfo.version,
          depName,
          toInfo?.version ?? null,
        );
      }
    }
  }

  // lockfile v1: nested dependencies tree
  const walk = (parent, depsObj) => {
    if (!depsObj || typeof depsObj !== 'object') return;
    for (const [name, meta] of Object.entries(depsObj)) {
      if (parent)
        addEdge(
          parent.name,
          parent.version ?? null,
          name,
          meta?.version ?? null,
        );
      walk({ name, version: meta?.version ?? null }, meta?.dependencies);
    }
  };

  if (lock.dependencies && typeof lock.dependencies === 'object') {
    walk(null, lock.dependencies);
  }

  return edges;
}

/**
 * Generate a dependency graph report using vis-network.
 */
export function generateGraphReport(
  results,
  pkg,
  opts,
  kevMatches = [],
  lockfileData = null,
  _lockfilePath = null,
  graphContext = null,
) {
  const cssTemplate = loadGraphCssTemplate();
  const htmlTemplate = loadGraphHtmlTemplate();
  const jsTemplate = loadGraphJsTemplate();

  const pkgLabel =
    `${pkg.name ?? '(unnamed)'}` + (pkg.version ? `@${pkg.version}` : '');

  function he(s) {
    return String(s ?? '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // Direct scopes only. Transitive dependencies are represented through
  // package-to-package edges, not by a dedicated scope node.
  const scopes = [
    { key: 'dependencies', label: 'dependencies' },
    { key: 'devDependencies', label: 'devDependencies' },
    { key: 'peerDependencies', label: 'peerDependencies' },
    { key: 'optionalDependencies', label: 'optionalDependencies' },
  ];

  let nextId = 1;
  let nodes = [];
  let edges = [];
  const nodeIds = new Map();
  const edgeKeys = new Set();
  const scopePackageCounts = new Map(scopes.map((scope) => [scope.key, 0]));
  const resultNodeByName = new Map();
  const resultNodeByNameVersion = new Map();

  const kevSet = new Set(
    kevMatches.map((m) => `${m.packageName}@${m.version ?? '?'}`),
  );

  const isProblematic = (r) => {
    const version = r.resolvedVersion ?? r.versionSpec ?? '?';
    if (r.notFound) return true;
    if ((r.vulnerabilities?.summary?.total ?? 0) > 0) return true;
    if (r.registry?.hasInstallScripts) return true;
    if (
      r.scorecard?.score !== null &&
      r.scorecard?.score !== undefined &&
      r.scorecard.score < 5
    ) {
      return true;
    }
    if (kevSet.has(`${r.name}@${version}`)) return true;
    return false;
  };

  // Red is strictly high/critical/KEV. Orange stays as secondary signal.
  const graphRiskTone = (r) => {
    const version = r.resolvedVersion ?? r.versionSpec ?? '?';
    const summary = r.vulnerabilities?.summary ?? {};
    const hasHighOrCritical =
      (summary.high ?? 0) > 0 || (summary.critical ?? 0) > 0;
    const hasKev = kevSet.has(`${r.name}@${version}`);
    if (hasHighOrCritical || hasKev) return 'red';
    if (isProblematic(r)) return 'orange';
    return 'none';
  };

  const addNode = (key, node) => {
    if (nodeIds.has(key)) return nodeIds.get(key);
    const id = nextId++;
    nodes.push({ id, ...node });
    nodeIds.set(key, id);
    return id;
  };

  const addEdge = (from, to, extra = {}) => {
    const label = extra.label ?? '';
    const kind = extra.kind ?? 'contains';
    const key = `${from}->${to}|${label}|${extra.className ?? ''}|${kind}`;
    if (edgeKeys.has(key)) return;
    edgeKeys.add(key);
    const edge = { from, to };
    if (label) edge.label = label;
    edge.kind = kind;
    if (extra.dashes !== undefined) edge.dashes = extra.dashes;
    if (extra.color) edge.color = extra.color;
    if (extra.width !== undefined) edge.width = extra.width;
    if (extra.smooth) edge.smooth = extra.smooth;
    edges.push(edge);
  };

  const rootLabel = graphContext?.rootLabel ?? 'package.json';
  const rootTitle =
    graphContext?.rootTitle ?? `${pkgLabel}\nRoot package manifest`;

  const rootId = addNode('root', {
    label: rootLabel,
    group: 'root',
    title: rootTitle,
  });

  const scopeNodeIds = new Map();
  const scopeDefs = new Map(scopes.map((scope) => [scope.key, scope]));
  const syntheticLockNodeByNameVersion = new Map();
  const ensureScopeNode = (scopeKey) => {
    if (scopeNodeIds.has(scopeKey)) return scopeNodeIds.get(scopeKey);
    const scope = scopeDefs.get(scopeKey) ?? scopeDefs.get('dependencies');
    if (!scope) return null;
    const id = addNode(`scope:${scope.key}`, {
      label: scope.label,
      group: 'section',
      title: `Dependency scope: ${scope.label}`,
    });
    scopeNodeIds.set(scope.key, id);
    addEdge(rootId, id, { kind: 'contains' });
    return id;
  };

  const normalizeScope = (scope) => {
    if (!scope || scope === 'direct') return 'dependencies';
    if (scope === 'transitive') return 'transitive';
    if (scopeDefs.has(scope)) return scope;
    return 'dependencies';
  };

  const vulnerabilitiesCount = (r) => r.vulnerabilities?.summary?.total ?? 0;
  const findingsCount = results.filter(
    (r) => graphRiskTone(r) === 'red',
  ).length;
  const depEdges =
    opts.includeTransitive && lockfileData
      ? extractLockfileDependencyEdges(lockfileData)
      : [];

  const ensureLockfileParentNode = (dep) => {
    const fromVersion = dep.fromVersion ?? '?';
    const nameVersionKey = `${dep.fromName}@${fromVersion}`;

    const existingResult = resultNodeByNameVersion.get(nameVersionKey);
    if (existingResult) return existingResult;

    const existingSynthetic =
      syntheticLockNodeByNameVersion.get(nameVersionKey);
    if (existingSynthetic) return existingSynthetic;

    const syntheticKey = `lock-parent:${nameVersionKey}`;
    const existingId = nodeIds.get(syntheticKey);
    if (existingId) return existingId;

    const scopeKey = 'dependencies';
    const parentScopeId =
      ensureScopeNode(scopeKey) ?? ensureScopeNode('dependencies');
    const nodeId = addNode(syntheticKey, {
      label: `${dep.fromName}@${fromVersion}`,
      group: scopeKey,
      riskTone: 'none',
      title: `${dep.fromName}@${fromVersion}\nScope: ${scopeKey}\nSource: package-lock dependency path`,
    });

    if (parentScopeId) {
      addEdge(parentScopeId, nodeId, { kind: 'contains' });
      scopePackageCounts.set(
        scopeKey,
        (scopePackageCounts.get(scopeKey) ?? 0) + 1,
      );
    }

    syntheticLockNodeByNameVersion.set(nameVersionKey, nodeId);

    return nodeId;
  };

  for (const r of results) {
    const scope = normalizeScope(r.scope);
    const version = r.resolvedVersion ?? r.versionSpec ?? '?';
    const pkgKey = `pkg:${r.name}@${version}`;
    const vulnTotal = vulnerabilitiesCount(r);
    const score = r.scorecard?.score;
    const label = `${r.name}@${version}`;

    const titleParts = [
      `${r.name}@${version}`,
      `Scope: ${r.scope ?? 'dependencies'}`,
      `Vulnerabilities: ${vulnTotal}`,
      `Scorecard: ${
        score === null || score === undefined ? 'n/a' : score.toFixed(1)
      }`,
      `Install scripts: ${r.registry?.hasInstallScripts ? 'yes' : 'no'}`,
    ];
    if (r.notFound)
      titleParts.push('Package metadata not found in npm registry');

    const problematic = isProblematic(r);
    const tone = graphRiskTone(r);
    const nodeId = addNode(pkgKey, {
      label,
      group: scope,
      problematic,
      riskTone: tone,
      ...(tone === 'red'
        ? {
            color: {
              background: '#4a1616',
              border: '#ff6b6b',
              highlight: { background: '#662020', border: '#ff9a9a' },
              hover: { background: '#5a1b1b', border: '#ff7f7f' },
            },
            borderWidth: 2.4,
            font: { color: '#fff2f2' },
          }
        : tone === 'orange'
          ? {
              color: {
                background: '#4a3110',
                border: '#ffb347',
                highlight: { background: '#5b3c13', border: '#ffd08a' },
                hover: { background: '#6a4718', border: '#ffbf66' },
              },
              borderWidth: 2,
              font: { color: '#fff4de' },
            }
          : {}),
      title: titleParts.join('\n'),
    });

    resultNodeByName.set(r.name, nodeId);
    resultNodeByNameVersion.set(`${r.name}@${version}`, nodeId);

    // Do not create a dedicated transitive scope bucket in the graph.
    if (scope !== 'transitive') {
      const parentScopeId =
        ensureScopeNode(scope) ?? ensureScopeNode('dependencies');
      addEdge(parentScopeId, nodeId, { kind: 'contains' });
      scopePackageCounts.set(scope, (scopePackageCounts.get(scope) ?? 0) + 1);
    }
  }

  // Additional dependency nodes for npm-package mode where we only inspect one
  // package result, but still want its declared dependency graph visible.
  const additionalDeps = graphContext?.scopeDependencies;
  if (additionalDeps && typeof additionalDeps === 'object') {
    for (const scope of scopes) {
      const deps = additionalDeps[scope.key] ?? [];
      if (deps.length === 0) continue;
      const parentScopeId = ensureScopeNode(scope.key);
      if (!parentScopeId) continue;
      for (const dep of deps) {
        const depName = dep?.name;
        if (!depName) continue;
        if (resultNodeByName.has(depName)) continue;

        const depVersionSpec = dep.versionSpec ?? '*';
        const depKey = `ext:${scope.key}:${depName}@${depVersionSpec}`;
        const depId = addNode(depKey, {
          label: `${depName}@${depVersionSpec}`,
          group: scope.key,
          riskTone: 'none',
          title: `${depName}@${depVersionSpec}\nScope: ${scope.key}\nSource: npm package metadata`,
        });
        addEdge(parentScopeId, depId, { kind: 'contains' });
        scopePackageCounts.set(
          scope.key,
          (scopePackageCounts.get(scope.key) ?? 0) + 1,
        );
      }
    }
  }

  const dependsEdgeStyle = {
    kind: 'depends',
    dashes: true,
    color: { color: '#7e8794', highlight: '#b9c2cf' },
    width: 1,
    smooth: { type: 'cubicBezier', roundness: 0.2 },
  };

  // Add lockfile package-to-package edges for deeper transitive visibility.
  if (depEdges.length > 0) {
    const reverseByTo = new Map();
    const redNameVersionKeys = new Set(
      nodes
        .filter((n) => n.riskTone === 'red')
        .map((n) => String(n.label))
        .filter((label) => label.includes('@')),
    );

    const addReverse = (toKey, dep) => {
      if (!reverseByTo.has(toKey)) reverseByTo.set(toKey, []);
      reverseByTo.get(toKey).push(dep);
    };

    for (const dep of depEdges) {
      const toKey = `${dep.toName}@${dep.toVersion ?? '?'}`;
      addReverse(toKey, dep);
    }

    const closureEdgeSet = new Set();
    const seenKeys = new Set([...redNameVersionKeys]);
    const queue = [...redNameVersionKeys];

    while (queue.length > 0) {
      const current = queue.shift();
      const parents = reverseByTo.get(current) || [];
      for (const dep of parents) {
        const edgeKey = `${dep.fromName}@${dep.fromVersion ?? '?'}->${dep.toName}@${dep.toVersion ?? '?'}`;
        if (!closureEdgeSet.has(edgeKey)) closureEdgeSet.add(edgeKey);

        const fromKey = `${dep.fromName}@${dep.fromVersion ?? '?'}`;
        if (seenKeys.has(fromKey)) continue;
        seenKeys.add(fromKey);
        queue.push(fromKey);
      }
    }

    for (const dep of depEdges) {
      const edgeKey = `${dep.fromName}@${dep.fromVersion ?? '?'}->${dep.toName}@${dep.toVersion ?? '?'}`;
      // Keep only edges in the ancestry closure of red findings.
      if (!closureEdgeSet.has(edgeKey)) continue;

      const fromKey = `${dep.fromName}@${dep.fromVersion ?? '?'}`;
      const toKey = `${dep.toName}@${dep.toVersion ?? '?'}`;
      const fromId =
        resultNodeByNameVersion.get(fromKey) ??
        syntheticLockNodeByNameVersion.get(fromKey) ??
        resultNodeByName.get(dep.fromName) ??
        ensureLockfileParentNode(dep);
      const toId =
        resultNodeByNameVersion.get(toKey) ??
        syntheticLockNodeByNameVersion.get(toKey) ??
        resultNodeByName.get(dep.toName) ??
        ensureLockfileParentNode({
          fromName: dep.toName,
          fromVersion: dep.toVersion,
        });
      if (!fromId || !toId || fromId === toId) continue;
      addEdge(fromId, toId, dependsEdgeStyle);
    }
  }

  if (opts.includeTransitive) {
    const dependsLinkedNodeIds = new Set();
    for (const e of edges) {
      if (e.kind !== 'depends') continue;
      dependsLinkedNodeIds.add(e.from);
      dependsLinkedNodeIds.add(e.to);
    }

    // Fallback: keep red transitive nodes navigable even when lockfile
    // dependency linkage is ambiguous by first trying lockfile parent nodes,
    // then attaching directly to dependencies scope as last resort.
    const depsScopeId =
      scopeNodeIds.get('dependencies') ?? ensureScopeNode('dependencies');

    // Prefer explicit parent path from lockfile for red transitive nodes.
    if (depEdges.length > 0) {
      for (const n of nodes) {
        if (n.group !== 'transitive' || n.riskTone !== 'red') continue;
        if (dependsLinkedNodeIds.has(n.id)) continue;

        const [toName, toVersion = '?'] = String(n.label).split('@');
        const parentEdges = depEdges.filter(
          (dep) =>
            dep.toName === toName && String(dep.toVersion ?? '?') === toVersion,
        );

        for (const dep of parentEdges) {
          const parentId =
            resultNodeByNameVersion.get(
              `${dep.fromName}@${dep.fromVersion ?? '?'}`,
            ) ??
            resultNodeByName.get(dep.fromName) ??
            ensureLockfileParentNode(dep);

          if (!parentId || parentId === n.id) continue;
          addEdge(parentId, n.id, dependsEdgeStyle);
          dependsLinkedNodeIds.add(parentId);
          dependsLinkedNodeIds.add(n.id);
        }
      }
    }

    if (depsScopeId) {
      for (const n of nodes) {
        if (n.group !== 'transitive' || n.riskTone !== 'red') continue;
        if (dependsLinkedNodeIds.has(n.id)) continue;

        addEdge(depsScopeId, n.id, {
          kind: 'depends',
          dashes: true,
          color: { color: '#d85f69', highlight: '#ef8088' },
          width: 1.6,
        });
      }

      // Ensure every red finding is connected into the visible root component.
      // Some lockfile-resolved red nodes can be linked by dependency edges but
      // still disconnected from the root/section contains tree.
      const adjacency = new Map(nodes.map((n) => [n.id, new Set()]));
      for (const e of edges) {
        if (!adjacency.has(e.from) || !adjacency.has(e.to)) continue;
        adjacency.get(e.from).add(e.to);
        adjacency.get(e.to).add(e.from);
      }

      const rootConnected = new Set();
      const queueFromRoot = [rootId];
      rootConnected.add(rootId);
      while (queueFromRoot.length > 0) {
        const current = queueFromRoot.shift();
        const neighbours = adjacency.get(current) || [];
        for (const next of neighbours) {
          if (rootConnected.has(next)) continue;
          rootConnected.add(next);
          queueFromRoot.push(next);
        }
      }

      for (const n of nodes) {
        if (n.riskTone !== 'red') continue;
        if (rootConnected.has(n.id)) continue;

        addEdge(depsScopeId, n.id, {
          kind: 'depends',
          dashes: true,
          color: { color: '#d85f69', highlight: '#ef8088' },
          width: 1.6,
        });
      }
    }

    const orphanTransitiveIds = new Set(
      nodes
        .filter(
          (n) =>
            n.group === 'transitive' &&
            !dependsLinkedNodeIds.has(n.id) &&
            n.riskTone !== 'red',
        )
        .map((n) => n.id),
    );

    if (orphanTransitiveIds.size > 0) {
      nodes = nodes.filter((n) => !orphanTransitiveIds.has(n.id));
      edges = edges.filter(
        (e) =>
          !orphanTransitiveIds.has(e.from) && !orphanTransitiveIds.has(e.to),
      );
    }
  }

  // Keep the payload graph coherent: remove any components detached from root.
  // Disconnected islands create confusing visuals and broken navigation context.
  const adjacency = new Map(nodes.map((n) => [n.id, new Set()]));
  for (const e of edges) {
    if (!adjacency.has(e.from) || !adjacency.has(e.to)) continue;
    adjacency.get(e.from).add(e.to);
    adjacency.get(e.to).add(e.from);
  }

  const rootConnected = new Set([rootId]);
  const queueFromRoot = [rootId];
  while (queueFromRoot.length > 0) {
    const current = queueFromRoot.shift();
    const neighbours = adjacency.get(current) || [];
    for (const next of neighbours) {
      if (rootConnected.has(next)) continue;
      rootConnected.add(next);
      queueFromRoot.push(next);
    }
  }

  nodes = nodes.filter((n) => rootConnected.has(n.id));
  edges = edges.filter(
    (e) => rootConnected.has(e.from) && rootConnected.has(e.to),
  );

  const scopeCounts = scopes
    .map((s) => {
      const count = scopePackageCounts.get(s.key) ?? 0;
      return `<span class="summary-chip">${he(s.label)}: ${count}</span>`;
    })
    .join('\n');

  const summaryChips =
    scopeCounts +
    '\n' +
    `<span class="summary-chip ${findingsCount > 0 ? 'warn' : 'ok'}">high/critical findings: ${findingsCount}</span>` +
    '\n' +
    `<span class="summary-chip">nodes: ${nodes.length}</span>` +
    '\n' +
    `<span class="summary-chip">edges: ${edges.length}</span>`;

  const payload = JSON.stringify({
    nodes,
    edges,
    graphMeta: {
      rootId,
      defaultView: 'findings',
      focusMode: 'red-only-paths',
    },
  }).replace(/<\//g, '<\\/');

  const renderedScript = renderTemplate(jsTemplate, {
    GRAPH_PAYLOAD: payload,
  });

  const renderedHtml = renderTemplate(htmlTemplate, {
    TITLE: he(pkgLabel),
    CSS: cssTemplate,
    PKG_LABEL: he(pkgLabel),
    GENERATED_AT: new Date().toUTCString(),
    SUMMARY_CHIPS: summaryChips,
  });

  return renderedHtml.replace('__GRAPH_SCRIPT__', renderedScript);
}
