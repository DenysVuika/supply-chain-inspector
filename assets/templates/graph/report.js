const graphPayload = {{GRAPH_PAYLOAD}};

const container = document.getElementById("dependency-graph");
const btnRefit = document.getElementById("btn-refit");
const btnReflow = document.getElementById("btn-reflow");

const allNodes = graphPayload.nodes || [];
const allEdges = graphPayload.edges || [];
const graphMeta = graphPayload.graphMeta || {};
const AUTO_REFLOW_NODE_THRESHOLD = 80;

const containsEdges = allEdges.filter((e) => (e.kind || "contains") === "contains");
const dependsEdges = allEdges.filter((e) => e.kind === "depends");

const nodeById = new Map(allNodes.map((n) => [n.id, n]));
const childrenById = new Map();
const parentsById = new Map();
const dependsChildrenById = new Map();
const dependsParentsById = new Map();

function mapPush(map, key, value) {
  if (!map.has(key)) map.set(key, []);
  map.get(key).push(value);
}

for (const edge of containsEdges) {
  mapPush(childrenById, edge.from, edge.to);
  mapPush(parentsById, edge.to, edge.from);
}

for (const edge of dependsEdges) {
  mapPush(dependsChildrenById, edge.from, edge.to);
  mapPush(dependsParentsById, edge.to, edge.from);
}

const ownRiskToneById = new Map(
  allNodes.map((n) => [n.id, n.riskTone === "red" ? "red" : "none"]),
);
const isRedNodeById = (nodeId) => ownRiskToneById.get(nodeId) === "red";
const isRiskNode = (node) => isRedNodeById(node.id);
const isIssueLeadingNodeId = (nodeId) =>
  isRedNodeById(nodeId) || redPathByDepends.has(nodeId);

const sectionNodeIds = new Set(
  allNodes.filter((n) => n.group === "section").map((n) => n.id),
);
const directDependencyNodeIds = new Set(
  containsEdges
    .filter((e) => sectionNodeIds.has(e.from))
    .map((e) => e.to),
);

// Keep only dependency subgraph that is reachable from direct dependencies.
const reachableFromDirect = new Set([...directDependencyNodeIds]);
const reachQueue = [...directDependencyNodeIds];
while (reachQueue.length > 0) {
  const current = reachQueue.shift();
  const depChildren = dependsChildrenById.get(current) || [];
  for (const childId of depChildren) {
    if (reachableFromDirect.has(childId)) continue;
    reachableFromDirect.add(childId);
    reachQueue.push(childId);
  }
}

// Mark all package nodes that can reach a red node over dependency edges.
const redPathByDepends = new Set();
const queue = [];
for (const node of allNodes) {
  if (isRedNodeById(node.id)) {
    redPathByDepends.add(node.id);
    queue.push(node.id);
  }
}
while (queue.length > 0) {
  const current = queue.shift();
  const depParents = dependsParentsById.get(current) || [];
  for (const parentId of depParents) {
    if (redPathByDepends.has(parentId)) continue;
    redPathByDepends.add(parentId);
    queue.push(parentId);
  }
}

// Bubble red lineage into contains tree so root/scope/direct deps can be highlighted.
const descendantRiskById = new Map();
function markContainsAncestorsRed(nodeId) {
  const cParents = parentsById.get(nodeId) || [];
  for (const parentId of cParents) {
    if (descendantRiskById.get(parentId) === "red") continue;
    descendantRiskById.set(parentId, "red");
    markContainsAncestorsRed(parentId);
  }
}
for (const nodeId of redPathByDepends) {
  markContainsAncestorsRed(nodeId);
}

const findingsVisibleBase = new Set();
for (const node of allNodes) {
  if (node.group === "root") {
    findingsVisibleBase.add(node.id);
    continue;
  }

  if (node.group === "section") {
    // Hide scope buckets that have no risky descendants.
    if (descendantRiskById.get(node.id) === "red") {
      findingsVisibleBase.add(node.id);
    }
    continue;
  }

  if (directDependencyNodeIds.has(node.id)) {
    // Keep direct/synthetic package nodes only when they lead to a red finding.
    if (isIssueLeadingNodeId(node.id)) {
      findingsVisibleBase.add(node.id);
    }
    continue;
  }
  if (isIssueLeadingNodeId(node.id)) {
    findingsVisibleBase.add(node.id);
  }
}

const levelsById = new Map();
function computeLevels(rootId) {
  if (!rootId || !nodeById.has(rootId)) return;
  levelsById.clear();
  const queue = [rootId];
  levelsById.set(rootId, 0);
  while (queue.length > 0) {
    const current = queue.shift();
    const currentLevel = levelsById.get(current) || 0;
    const children = childrenById.get(current) || [];
    for (const childId of children) {
      if (levelsById.has(childId)) continue;
      levelsById.set(childId, currentLevel + 1);
      queue.push(childId);
    }
  }
}
computeLevels(graphMeta.rootId);

const visible = new Set();
const edgeBaseById = new Map();

function containsEdgeId(edge) {
  return `contains:${edge.from}->${edge.to}`;
}

function dependsEdgeId(edge) {
  return `depends:${edge.from}->${edge.to}`;
}

function ringRadius(level) {
  const base = 150;
  const step = 190;
  return base + Math.max(0, level - 1) * step;
}

function radialSeedNodes(visibleNodeList) {
  const byLevel = new Map();
  for (const n of visibleNodeList) {
    const level = levelsById.get(n.id) ?? 1;
    if (!byLevel.has(level)) byLevel.set(level, []);
    byLevel.get(level).push(n);
  }

  const seeded = [];
  for (const [level, levelNodes] of byLevel.entries()) {
    if (level === 0) {
      for (const n of levelNodes) {
        seeded.push({ ...n, x: 0, y: 0, fixed: { x: true, y: true } });
      }
      continue;
    }

    const radius = ringRadius(level);
    const count = levelNodes.length;
    for (let i = 0; i < count; i += 1) {
      const angle = (2 * Math.PI * i) / Math.max(1, count) - Math.PI / 2;
      const x = Math.cos(angle) * radius;
      const y = Math.sin(angle) * radius;
      seeded.push({ ...levelNodes[i], x, y });
    }
  }
  return seeded;
}

function cloneColor(color) {
  if (!color || typeof color !== "object") return null;
  return JSON.parse(JSON.stringify(color));
}

function riskStyledNode(node) {
  const copy = { ...node };
  const isRisk = isRiskNode(node);
  const inheritedTone = descendantRiskById.get(node.id) || "none";
  const isRedPathNode = redPathByDepends.has(node.id);
  if (!isRisk && (inheritedTone === "red" || isRedPathNode)) {
    // Ancestor/path nodes should remain clearly secondary to true red findings.
    const toneStyle = {
      border: "#b88f95",
      highlightBorder: "#cca8ad",
      hoverBorder: "#dcc1c5",
    };
    const base = cloneColor(node.color) || {
      background: "#2f2430",
      border: toneStyle.border,
      highlight: { background: "#413043", border: toneStyle.highlightBorder },
      hover: { background: "#4c3850", border: toneStyle.hoverBorder },
    };
    copy.color = {
      ...base,
      border: toneStyle.border,
      highlight: {
        ...(base.highlight || {}),
        border: toneStyle.highlightBorder,
      },
      hover: {
        ...(base.hover || {}),
        border: toneStyle.hoverBorder,
      },
    };
    copy.borderWidth = Math.max(Number(node.borderWidth || 1), 1.5);
  }

  const children = childrenById.get(node.id) || [];
  const hiddenChildren = children.filter(
    (childId) => isIssueLeadingNodeId(childId) && !visible.has(childId),
  ).length;
  copy.label = hiddenChildren > 0 ? `${node.label}\n(+${hiddenChildren})` : node.label;

  return copy;
}

function applyViewState() {
  visible.clear();

  for (const id of findingsVisibleBase) visible.add(id);

  if (graphMeta.rootId && nodeById.has(graphMeta.rootId)) {
    visible.add(graphMeta.rootId);
  }

  // Keep only the root-connected subgraph to avoid detached visual islands.
  if (graphMeta.rootId && visible.has(graphMeta.rootId)) {
    const connected = new Set([graphMeta.rootId]);
    const queue = [graphMeta.rootId];
    while (queue.length > 0) {
      const current = queue.shift();
      for (const edge of allEdges) {
        if (!visible.has(edge.from) || !visible.has(edge.to)) continue;
        const next =
          edge.from === current
            ? edge.to
            : edge.to === current
              ? edge.from
              : null;
        if (next === null || connected.has(next)) continue;
        connected.add(next);
        queue.push(next);
      }
    }

    for (const id of Array.from(visible)) {
      if (!connected.has(id)) visible.delete(id);
    }
  }

  const visibleNodes = allNodes
    .filter((n) => visible.has(n.id))
    .map((n) => riskStyledNode(n));

  data.nodes.clear();
  data.nodes.add(radialSeedNodes(visibleNodes));

  const visibleContainsEdges = containsEdges
    .filter((e) => visible.has(e.from) && visible.has(e.to))
    .map((e) => {
      const id = containsEdgeId(e);
      const withId = { ...e, id };
        const fromOwn = ownRiskToneById.get(e.from) || "none";
        const toOwn = ownRiskToneById.get(e.to) || "none";
        const fromDesc = descendantRiskById.get(e.from) || "none";
        const toDesc = descendantRiskById.get(e.to) || "none";
        const ownRed = fromOwn === "red" || toOwn === "red";
        const inheritedRed = fromDesc === "red" || toDesc === "red";
        if (ownRed) {
          return {
            ...withId,
            color: { color: "#d85f69", highlight: "#ef8088", hover: "#ff9ca3" },
            width: 1.8,
          };
        }
        if (inheritedRed) {
          return {
            ...withId,
            color: { color: "#b88f95", highlight: "#cca8ad", hover: "#dcc1c5" },
            width: 1.2,
          };
        }
        return withId;
      });

  const visibleDependsEdges = dependsEdges
    .filter((e) => visible.has(e.from) && visible.has(e.to))
    .map((e) => ({ ...e, id: dependsEdgeId(e) }));

  const visibleEdges = [...visibleContainsEdges, ...visibleDependsEdges];

  edgeBaseById.clear();
  for (const edge of visibleEdges) {
    edgeBaseById.set(edge.id, {
      ...edge,
      color: cloneColor(edge.color),
    });
  }

  data.edges.clear();
  data.edges.add(visibleEdges);
}

function resetPathHighlight() {
  if (edgeBaseById.size === 0) return;
  data.edges.clear();
  data.edges.add(
    Array.from(edgeBaseById.values()).map((edge) => ({
      ...edge,
      color: cloneColor(edge.color),
    })),
  );
}

function collectAncestorPathEdgeIds(startNodeId) {
  const edgeIds = new Set();
  const seen = new Set([startNodeId]);
  const queue = [startNodeId];

  while (queue.length > 0) {
    const current = queue.shift();

    const depParents = dependsParentsById.get(current) || [];
    for (const parentId of depParents) {
      if (visible.has(parentId) && visible.has(current)) {
        edgeIds.add(dependsEdgeId({ from: parentId, to: current }));
      }
      if (!seen.has(parentId)) {
        seen.add(parentId);
        queue.push(parentId);
      }
    }

    const containsParents = parentsById.get(current) || [];
    for (const parentId of containsParents) {
      if (visible.has(parentId) && visible.has(current)) {
        edgeIds.add(containsEdgeId({ from: parentId, to: current }));
      }
      if (!seen.has(parentId)) {
        seen.add(parentId);
        queue.push(parentId);
      }
    }
  }

  return edgeIds;
}

function highlightPathToRoot(nodeId) {
  if (!isRedNodeById(nodeId)) return;

  const pathEdgeIds = collectAncestorPathEdgeIds(nodeId);
  if (pathEdgeIds.size === 0) return;

  const updates = [];
  for (const edgeId of pathEdgeIds) {
    const base = edgeBaseById.get(edgeId);
    if (!base) continue;

    updates.push({
      id: edgeId,
      dashes: false,
      width: Math.max(Number(base.width || 1.4) + 1.2, 2.6),
      color: {
        color: "#ffd166",
        highlight: "#ffe29a",
        hover: "#fff0bf",
      },
    });
  }

  if (updates.length > 0) {
    data.edges.update(updates);
  }
}

const data = {
  nodes: new vis.DataSet([]),
  edges: new vis.DataSet([]),
};

const options = {
  autoResize: true,
  interaction: {
    hover: true,
    navigationButtons: false,
    keyboard: true,
  },
  layout: {
    improvedLayout: true,
    randomSeed: 42,
    hierarchical: false,
  },
  physics: {
    enabled: false,
    solver: "forceAtlas2Based",
    forceAtlas2Based: {
      gravitationalConstant: -42,
      centralGravity: 0.003,
      springLength: 155,
      springConstant: 0.045,
      damping: 0.72,
      avoidOverlap: 0.9,
    },
    stabilization: {
      enabled: true,
      iterations: 420,
      updateInterval: 25,
      fit: true,
    },
  },
  edges: {
    arrows: {
      to: {
        enabled: true,
        scaleFactor: 0.6,
      },
    },
    smooth: {
      type: "dynamic",
      roundness: 0.35,
    },
    width: 1.4,
  },
  nodes: {
    shape: "box",
    margin: 8,
    borderWidth: 1.2,
    mass: 1.1,
    font: {
      face: "Verdana, Geneva, sans-serif",
      size: 13,
    },
  },
  groups: {
    root: {
      shape: "ellipse",
      borderWidth: 3.2,
      mass: 2.2,
      color: {
        background: "#12375a",
        border: "#5ac8fa",
        highlight: { background: "#184a77", border: "#8ce0ff" },
      },
      font: { color: "#f2fbff", size: 22, bold: true },
    },
    section: {
      color: {
        background: "#1b2a22",
        border: "#75c17e",
        highlight: { background: "#243a2f", border: "#9de9a6" },
      },
      font: { color: "#e9f8eb", size: 13, bold: true },
    },
    dependencies: {
      color: {
        background: "#17233a",
        border: "#6ea8fe",
        highlight: { background: "#20304f", border: "#97c4ff" },
      },
      font: { color: "#eef5ff" },
    },
    devDependencies: {
      color: {
        background: "#342516",
        border: "#f6b26b",
        highlight: { background: "#47331f", border: "#ffd19d" },
      },
      font: { color: "#fff4e8" },
    },
    peerDependencies: {
      color: {
        background: "#2b1f35",
        border: "#c99cff",
        highlight: { background: "#3a2948", border: "#debfff" },
      },
      font: { color: "#f7ebff" },
    },
    optionalDependencies: {
      color: {
        background: "#2c3020",
        border: "#bfd97d",
        highlight: { background: "#3a3f2a", border: "#d8f4a0" },
      },
      font: { color: "#f4fbe6" },
    },
    transitive: {
      color: {
        background: "#33363d",
        border: "#9aa0ab",
        highlight: { background: "#444954", border: "#c6cbd6" },
      },
      font: { color: "#f0f2f6" },
    },
  },
};

const network = new vis.Network(container, data, options);

network.on("selectNode", (params) => {
  resetPathHighlight();
  const nodeId = params.nodes?.[0];
  if (!nodeId) return;
  highlightPathToRoot(nodeId);
});

network.on("deselectNode", () => {
  resetPathHighlight();
});

function reflowOnce() {
  network.setOptions({
    physics: {
      enabled: true,
    },
  });

  let finished = false;
  const freeze = () => {
    if (finished) return;
    finished = true;
    network.setOptions({
      physics: {
        enabled: false,
      },
    });
    network.fit({ animation: { duration: 280, easingFunction: "easeInOutQuad" } });
  };

  network.once("stabilized", freeze);
  network.stabilize(220);
  setTimeout(freeze, 800);
}

btnRefit.addEventListener("click", () => {
  network.fit({ animation: { duration: 280, easingFunction: "easeInOutQuad" } });
});

btnReflow.addEventListener("click", () => {
  reflowOnce();
});

applyViewState();
setTimeout(() => {
  if (allNodes.length > AUTO_REFLOW_NODE_THRESHOLD) {
    reflowOnce();
  } else {
    network.fit({ animation: { duration: 280, easingFunction: "easeInOutQuad" } });
  }
}, 50);
