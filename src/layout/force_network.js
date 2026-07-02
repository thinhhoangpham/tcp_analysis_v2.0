// src/layout/force_network.js
// Force-directed 2D network layout — canonical D3 live simulation pattern.

import { highlightHoveredLink, unhighlightLinks, getLinkHighlightInfo, highlightEndpointLabels, unhighlightEndpointLabels, showLineArrowhead, removeArrowheads } from '../rendering/highlightUtils.js';

const DEFAULT_MIN_GROUP_SIZE = 2;

// RFC1918 private ranges: 10/8, 172.16/12, 192.168/16
function _isRFC1918(ip) {
  const p = ip.split('.');
  if (p.length < 4) return false;
  const a = +p[0], b = +p[1];
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

// Level catalog — add new subnet sizes by extending this map.
// keyFn returns null to indicate "this IP doesn't participate at this level"
// (e.g., a public IP at the 'internal' level). Null-keyed steps are skipped
// during tree construction.
const LEVEL_DEFS = {
  subnet24: {
    name: 'subnet24',
    suffix: '.0/24',
    keyFn: (ip) => {
      const p = ip.split('.');
      return p.length >= 3 ? `${p[0]}.${p[1]}.${p[2]}` : ip;
    },
  },
  subnet16: {
    name: 'subnet16',
    suffix: '.0.0/16',
    keyFn: (ip) => {
      const p = ip.split('.');
      return p.length >= 2 ? `${p[0]}.${p[1]}` : ip;
    },
  },
  internal: {
    name: 'internal',
    suffix: '',
    keyFn: (ip) => _isRFC1918(ip) ? 'Internal' : null,
  },
};

// Build the country/org level defs bound to an ipMetaMap closure. Returns
// null entries when the map is absent so the layout silently degrades to
// subnet-only grouping in that case.
function _buildMetaLevelDefs(ipMetaMap) {
  if (!ipMetaMap) return {};
  return {
    country: {
      name: 'country',
      suffix: '',
      keyFn: (ip) => {
        const m = ipMetaMap[ip];
        return m && m.country ? m.country : null;
      },
    },
    org: {
      name: 'org',
      suffix: '',
      keyFn: (ip) => {
        const m = ipMetaMap[ip];
        return m && m.org ? m.org : null;
      },
    },
  };
}

export class ForceNetworkLayout {
  constructor(opts) {
    this.d3 = opts.d3;
    this.svg = opts.svg;
    this.width = opts.width;
    this.height = opts.height;
    this.margin = opts.margin;
    this.colorForAttack = opts.colorForAttack;
    this.tooltip = opts.tooltip;
    this.showTooltip = opts.showTooltip;
    this.hideTooltip = opts.hideTooltip;

    // Data
    this._links = null;
    this._allIps = null;
    this._ipToComponent = null;
    this._components = null;
    this._activeLabelKey = 'attack_group';

    // Label-visibility threshold: solo nodes with degree below this stay
    // hidden until hovered. Pass Infinity to hide all solo labels by default
    // (e.g. in dense magnifier panels). Groups/anchors are always on.
    this._labelDegreeThreshold = opts.labelDegreeThreshold ?? 5;

    // Grouping state.
    // _groupBy: 'none' | level-name string | array of level names innermost-first
    //   e.g. ['subnet24', 'subnet16'] means /24 combos nested inside /16 combos.
    // _levels: ordered array of resolved LEVEL_DEFS (innermost-first).
    // _expandedGroups: Set of group ids ("subnet16:172.28") explicitly opened.
    // _minGroupSize: per-level threshold; level names absent fall back to default.
    // _nestingExclusions: per-level Set<ip> of IPs that bypass that level.
    // Per-instance level catalog: static subnet/internal defs + (optional)
    // country/org defs bound to the supplied IP meta map.
    this._ipMetaMap = opts.ipMetaMap || null;
    this._levelDefs = { ...LEVEL_DEFS, ..._buildMetaLevelDefs(this._ipMetaMap), ...(opts.extraLevelDefs || {}) };

    this._groupBy = opts.groupBy || 'none';
    this._levels = this._parseGroupBy(this._groupBy);
    this._minGroupSize = opts.minGroupSize || {};
    this._nestingExclusions = opts.nestingExclusions || {};
    this._expandedGroups = new Set();
    this._memberToGroup = new Map();
    this._groupTree = null; // built each topology pass; root has children = top-level groups + solo IPs

    // Per-tick cache of expanded-group bounding circles ({subnet, cx, cy, r}[]).
    // Populated by _makeClusterForce, consumed by _makeBoundaryRepelForce and
    // _drawHulls so all three agree on the same circles.
    this._groupCircles = [];

    // Simulation + rendering state
    this._simulation = null;
    this._container = null;
    this._centerG = null;
    this._linkSel = null;
    this._gradSel = null;
    this._nodeSel = null;
    this._aggregated = null;
    this._nodeData = null;
    this._linkData = null;
    this._simLinks = null;
    this._radiusScale = null;
    this._linkWidthScale = null;
    this._cx = 0;
    this._cy = 0;
    this._drawWidth = 0;
    this._drawHeight = 0;
    this._fitScale = 1;
    this._fitContentCx = 0;
    this._fitContentCy = 0;
  }

  // ───────────────────────── Data ─────────────────────────

  setData(linksWithNodes, allIps, ipToComponent, components, activeLabelKey) {
    this._links = linksWithNodes;
    this._allIps = allIps;
    this._ipToComponent = ipToComponent;
    this._components = components;
    this._activeLabelKey = activeLabelKey || 'attack_group';
  }

  // ───────────────────── Aggregation ──────────────────────

  aggregateForTimeRange(timeRange) {
    const labelKey = this._activeLabelKey;
    const agg = new Map();

    for (const l of this._links) {
      if (timeRange) {
        if (l.minute < timeRange.min || l.minute > timeRange.max) continue;
      }

      const attackType = l[labelKey] || 'normal';
      const [ipA, ipB] = l.sourceIp < l.targetIp
        ? [l.sourceIp, l.targetIp]
        : [l.targetIp, l.sourceIp];
      const key = `${ipA}::${ipB}::${attackType}`;

      if (agg.has(key)) {
        agg.get(key).count += (l.count || 1);
      } else {
        // Canonical pair for grouping, but preserve original direction for gradient
        agg.set(key, {
          sourceIp: ipA, targetIp: ipB,
          origSourceIp: l.sourceIp, origTargetIp: l.targetIp,
          attackType, count: l.count || 1
        });
      }
    }

    this._aggregated = agg;
    return agg;
  }

  // ──────────────────── Build Data ──────────────────────

  // ─────────────── Level / hierarchy helpers ────────────────

  /**
   * Normalize a groupBy option into an ordered list of level defs
   * (innermost first → outermost last). Accepts:
   *   'none'  → []
   *   'subnet24' or 'subnet16' → single-level
   *   ['subnet24','subnet16'] → nested (innermost-first)
   */
  _parseGroupBy(g) {
    if (!g || g === 'none') return [];
    const arr = Array.isArray(g) ? g : [g];
    return arr.map(name => this._levelDefs[name]).filter(Boolean);
  }

  _levelDef(name) { return this._levelDefs ? this._levelDefs[name] : null; }

  _minSizeFor(levelName) {
    return this._minGroupSize[levelName] ?? DEFAULT_MIN_GROUP_SIZE;
  }

  _excludesIp(levelName, ip) {
    const ex = this._nestingExclusions[levelName];
    return !!(ex && ex.has(ip));
  }

  /**
   * Group keys for an IP, outermost-first (e.g. ['172.28', '172.28.4']).
   * Respects `nestingExclusions` per level.
   */
  _ipGroupKeys(ip) {
    const keys = [];
    // _levels is innermost-first; walk in reverse to produce outermost-first.
    for (let i = this._levels.length - 1; i >= 0; i--) {
      const lvl = this._levels[i];
      if (this._excludesIp(lvl.name, ip)) continue;
      const key = lvl.keyFn(ip);
      if (key == null) continue; // IP doesn't participate at this level
      keys.push({ level: lvl, key });
    }
    return keys;
  }

  _groupId(levelName, key) { return `group:${levelName}:${key}`; }
  _anchorId(levelName, key) { return `anchor:${levelName}:${key}`; }

  // Label suffix for a specific node data (uses its level if known)
  _suffixForNode(nd) {
    const def = nd && nd.level ? this._levelDef(nd.level) : null;
    return def ? def.suffix : '';
  }

  /**
   * Effective-open: a group is open iff it's in `_expandedGroups` AND every
   * ancestor is also effectively open. Walks the tree node's ancestor chain.
   */
  _isEffectivelyOpen(treeNode) {
    if (!treeNode || treeNode.type !== 'group') return false;
    let n = treeNode;
    while (n && n.type === 'group') {
      if (!this._expandedGroups.has(n.id)) return false;
      n = n.parent;
    }
    return true;
  }

  /**
   * Returns the tree node that represents this IP at the simulation level —
   * the OUTERMOST group containing it (anchor if effectively open, super-node
   * if closed). If the IP has no group ancestors, returns the IP's own leaf.
   */
  _simNodeForIp(ip) {
    const node = this._ipNodeIndex.get(ip);
    if (!node) return null;
    // Walk up to top-level (parent.type === 'root')
    let n = node;
    while (n.parent && n.parent.type !== 'root') n = n.parent;
    return n;
  }

  /**
   * Returns the deepest visible tree node containing this IP — used for
   * rendering link endpoints (and summary-link aggregation).
   * - If the IP has no group ancestors → returns the IP leaf.
   * - If all ancestors effectively open → returns the IP leaf (packed member).
   * - Else returns the outermost-most closed group inside any open chain.
   */
  _renderNodeForIp(ip) {
    const node = this._ipNodeIndex.get(ip);
    if (!node) return null;
    let n = node;
    const chain = []; // [innermost, ..., outermost]
    while (n.parent && n.parent.type !== 'root') {
      n = n.parent;
      chain.push(n);
    }
    // chain is innermost-group → outermost-group. Find the OUTERMOST group
    // that is not effectively open. That's the deepest visible super-node.
    for (let i = chain.length - 1; i >= 0; i--) {
      if (!this._isEffectivelyOpen(chain[i])) return chain[i];
    }
    return node; // all groups effectively open → IP itself is visible
  }

  _buildDataFromAggregation() {
    if (this._levels.length > 0) {
      this._buildCollapsedTopology();
    } else {
      this._buildFlatTopology();
    }
  }

  /**
   * Set of underlying real IPs represented by a node-data record.
   * Groups/anchors expose `memberIPs` (populated during tree build); leaf IP
   * nodes resolve to their own id.
   */
  _memberIpsOf(nd) {
    if (!nd) return new Set();
    if (nd.memberIPs) return new Set(nd.memberIPs);
    return new Set([nd.id]);
  }

  // ─────────────── Group-tree construction ───────────────

  /**
   * Build `_groupTree` from the current aggregation. The tree is rooted at a
   * virtual node whose children are top-level groups + solo IPs (IPs with no
   * group at any level).
   *
   * Levels are applied OUTERMOST first. A group at level L is created only
   * if it has ≥ `minGroupSize[L]` distinct IPs underneath. Groups that don't
   * meet the threshold are skipped (their IPs/sub-groups attach to the
   * next-outer ancestor — or to the root if none).
   *
   * Also populates:
   *   `_ipNodeIndex`  — Map<ip, leafNode>
   *   `_groupNodeIndex` — Map<groupId, groupNode>
   *   `_memberToGroup` — Map<ip, innermost-group-key> (only for collapsed innermost; for compat with shift-click code)
   */
  _buildGroupTree(ipSet) {
    const root = { type: 'root', parent: null, children: [] };
    this._ipNodeIndex = new Map();
    this._groupNodeIndex = new Map();

    // Step 1: compute per-IP outer-to-inner key path (respecting exclusions)
    const ipPaths = new Map(); // ip → [{level, key}, ...] outermost-first
    for (const ip of ipSet) ipPaths.set(ip, this._ipGroupKeys(ip));

    // Step 2: for each level outermost-first, decide which keys qualify as groups.
    // qualifyingKeys[levelName] = Set<key> of keys with ≥ minSize members
    const levelsOuterFirst = [...this._levels].reverse();
    const qualifyingKeys = new Map();
    for (const lvl of levelsOuterFirst) {
      const counts = new Map();
      for (const [ip, path] of ipPaths) {
        for (const step of path) {
          if (step.level.name === lvl.name) {
            counts.set(step.key, (counts.get(step.key) || 0) + 1);
          }
        }
      }
      const min = this._minSizeFor(lvl.name);
      const qual = new Set();
      for (const [k, c] of counts) if (c >= min) qual.add(k);
      qualifyingKeys.set(lvl.name, qual);
    }

    // Step 3: for each IP, filter its path to only qualifying keys
    const filteredPaths = new Map();
    for (const [ip, path] of ipPaths) {
      const fp = path.filter(s => qualifyingKeys.get(s.level.name).has(s.key));
      filteredPaths.set(ip, fp);
    }

    // Step 4: build tree by walking each IP's filtered path
    this._memberToGroup.clear();
    for (const ip of ipSet) {
      const path = filteredPaths.get(ip);
      let parent = root;
      for (const step of path) {
        const id = this._groupId(step.level.name, step.key);
        let groupNode = this._groupNodeIndex.get(id);
        if (!groupNode) {
          groupNode = {
            type: 'group',
            level: step.level,
            key: step.key,
            id,
            parent,
            children: [],
            ipMembers: [], // all leaf IPs in this subtree
          };
          this._groupNodeIndex.set(id, groupNode);
          parent.children.push(groupNode);
        }
        groupNode.ipMembers.push(ip);
        parent = groupNode;
      }
      const leaf = { type: 'ip', id: ip, ip, parent, children: [] };
      this._ipNodeIndex.set(ip, leaf);
      parent.children.push(leaf);

      // Compat: innermost group key → still tracked for legacy code paths
      if (path.length > 0) {
        const innermost = path[path.length - 1];
        this._memberToGroup.set(ip, innermost.key);
      }
    }

    this._groupTree = root;
  }

  _buildFlatTopology() {
    const d3 = this.d3;
    const agg = this._aggregated;

    // Unique IPs
    const ipSet = new Set();
    for (const entry of agg.values()) {
      ipSet.add(entry.sourceIp);
      ipSet.add(entry.targetIp);
    }

    // IP degrees
    const ipDegree = new Map();
    for (const entry of agg.values()) {
      ipDegree.set(entry.sourceIp, (ipDegree.get(entry.sourceIp) || 0) + 1);
      ipDegree.set(entry.targetIp, (ipDegree.get(entry.targetIp) || 0) + 1);
    }

    const maxDeg = Math.max(1, ...ipDegree.values());
    this._radiusScale = d3.scaleSqrt().domain([0, maxDeg]).range([5, 20]);

    // Nodes
    const nodeById = new Map();
    this._nodeData = [];
    for (const ip of ipSet) {
      const nd = { id: ip, degree: ipDegree.get(ip) || 0 };
      nodeById.set(ip, nd);
      this._nodeData.push(nd);
    }

    // Unique pair links for simulation force
    const pairCounts = new Map();
    for (const entry of agg.values()) {
      const pk = entry.sourceIp < entry.targetIp
        ? `${entry.sourceIp}::${entry.targetIp}`
        : `${entry.targetIp}::${entry.sourceIp}`;
      pairCounts.set(pk, (pairCounts.get(pk) || 0) + entry.count);
    }
    this._simLinks = [];
    for (const [pk, cnt] of pairCounts) {
      const [s, t] = pk.split('::');
      this._simLinks.push({ source: s, target: t, value: cnt });
    }

    // Parallel links for rendering — grouped by canonical pair
    const pairBuckets = new Map();
    for (const entry of agg.values()) {
      const pk = entry.sourceIp < entry.targetIp
        ? `${entry.sourceIp}::${entry.targetIp}`
        : `${entry.targetIp}::${entry.sourceIp}`;
      if (!pairBuckets.has(pk)) pairBuckets.set(pk, []);
      pairBuckets.get(pk).push(entry);
    }

    let maxCount = 1;
    for (const entry of agg.values()) {
      if (entry.count > maxCount) maxCount = entry.count;
    }
    this._linkWidthScale = d3.scaleSqrt().domain([1, maxCount]).range([1.5, 8]);

    this._memberToGroup.clear();
    this._simNodeData = this._nodeData;
    this._linkData = [];
    for (const [, entries] of pairBuckets) {
      const total = entries.length;
      entries.forEach((entry, idx) => {
        const offset = (idx - (total - 1) / 2) * 4;
        this._linkData.push({
          sourceNode: nodeById.get(entry.sourceIp),
          targetNode: nodeById.get(entry.targetIp),
          attackType: entry.attackType,
          attackTypes: new Set([entry.attackType]),
          count: entry.count,
          sourceIp: entry.sourceIp,
          targetIp: entry.targetIp,
          // Original traffic direction (for gradient): is canonical source the real source?
          directionReversed: (entry.origSourceIp || entry.sourceIp) !== entry.sourceIp,
          parallelOffset: offset,
          isAggregated: false,
        });
      });
    }
  }

  _buildCollapsedTopology() {
    const d3 = this.d3;
    const agg = this._aggregated;

    // 1) Collect unique IPs and per-IP degree
    const ipSet = new Set();
    const ipDegree = new Map();
    for (const entry of agg.values()) {
      ipSet.add(entry.sourceIp);
      ipSet.add(entry.targetIp);
      ipDegree.set(entry.sourceIp, (ipDegree.get(entry.sourceIp) || 0) + 1);
      ipDegree.set(entry.targetIp, (ipDegree.get(entry.targetIp) || 0) + 1);
    }

    // 2) Build the group hierarchy tree (handles N levels + exclusions + per-level minSize)
    this._buildGroupTree(ipSet);

    // 3) Compute summed degree for every group node (for super-node radius)
    const sumDegreeRec = (n) => {
      if (n.type === 'ip') return ipDegree.get(n.ip) || 0;
      n.degree = n.children.reduce((s, c) => s + sumDegreeRec(c), 0);
      return n.degree;
    };
    for (const c of this._groupTree.children) sumDegreeRec(c);

    // 4) Radius scale from per-group-or-ip degree (visible elements only)
    const visibleDegrees = [];
    for (const n of this._groupNodeIndex.values()) visibleDegrees.push(n.degree || 0);
    for (const ip of ipSet) visibleDegrees.push(ipDegree.get(ip) || 0);
    const maxDeg = Math.max(1, ...visibleDegrees);
    this._radiusScale = d3.scaleSqrt().domain([0, maxDeg]).range([5, 20]);

    // 5) Emit flat node list from the tree.
    //   - Closed group → super-node ({ isGroup, group, level, parentGroupNode? })
    //   - Open group   → anchor ({ isAnchor, packedRadius, parentGroupNode? })
    //   - IP whose innermost effective ancestor is open → packed member ({ isPacked, parentGroupNode })
    //   - IP with no group → solo (in sim)
    // `parentGroupNode` refers to the *open* group that visually contains this node,
    // or null if the node sits at top level (in the simulation).
    const nodeById = new Map();
    this._nodeData = [];

    const containingOpenGroup = (treeNode) => {
      // Walk up; return the innermost effectively-open group ancestor, or null
      let n = treeNode.parent;
      while (n && n.type !== 'root') {
        if (this._isEffectivelyOpen(n)) return n;
        n = n.parent;
      }
      return null;
    };

    // Emit groups (closed → super-node, open → anchor). Two passes so anchor
    // packedRadius can read sibling group radii too.
    const groupNodesEmitted = [];
    const walkGroups = (n) => {
      if (n.type === 'group') {
        const isOpen = this._isEffectivelyOpen(n);
        const parentOpen = containingOpenGroup(n);
        if (isOpen) {
          const nd = {
            id: this._anchorId(n.level.name, n.key),
            isAnchor: true,
            level: n.level.name,
            group: n.key, // for label compat
            subnet: n.key, // legacy
            degree: 1,
            treeNode: n,
            parentGroupNode: parentOpen,
            memberIPs: n.ipMembers,
            packedRadius: 0, // filled below
          };
          nodeById.set(nd.id, nd);
          this._nodeData.push(nd);
          groupNodesEmitted.push({ node: n, emitted: nd, isOpen: true });
        } else {
          // Only emit super-node if it would be visible (parent is open OR top-level)
          const parentEff = n.parent.type === 'root' || this._isEffectivelyOpen(n.parent);
          if (parentEff) {
            const nd = {
              id: this._groupId(n.level.name, n.key),
              isGroup: true,
              level: n.level.name,
              group: n.key,
              subnet: n.key, // legacy
              degree: n.degree || 0,
              count: n.ipMembers.length,
              memberIPs: n.ipMembers,
              treeNode: n,
              parentGroupNode: parentOpen,
            };
            nodeById.set(nd.id, nd);
            this._nodeData.push(nd);
            groupNodesEmitted.push({ node: n, emitted: nd, isOpen: false });
          }
        }
      }
      for (const c of n.children) walkGroups(c);
    };
    walkGroups(this._groupTree);

    // Emit IP nodes
    for (const ip of ipSet) {
      const leaf = this._ipNodeIndex.get(ip);
      const parentOpen = containingOpenGroup(leaf);
      // If innermost group ancestor exists and is closed, IP is hidden inside super-node
      const innermost = leaf.parent.type === 'root' ? null : leaf.parent;
      if (innermost && !this._isEffectivelyOpen(innermost)) continue; // hidden
      const nd = {
        id: ip,
        degree: ipDegree.get(ip) || 0,
        subnet: innermost ? innermost.key : null,
        isPacked: !!parentOpen,
        parentGroupNode: parentOpen,
      };
      nodeById.set(ip, nd);
      this._nodeData.push(nd);
    }

    // 6) Compute packed radius for each open-group anchor.
    //    A group's "children" for packing = the visible nodes whose parentGroupNode === this group.
    //    Process innermost-first so inner anchors' packedRadius is finalized
    //    before being used as a child size in outer packings.
    const orderByDepth = [];
    const depthOf = (n) => {
      let d = 0;
      let p = n.parent;
      while (p && p.type !== 'root') { d++; p = p.parent; }
      return d;
    };
    for (const g of groupNodesEmitted) {
      if (g.isOpen) orderByDepth.push({ entry: g, depth: depthOf(g.node) });
    }
    orderByDepth.sort((a, b) => b.depth - a.depth); // deepest first

    const effectiveRadius = (nd) => {
      if (nd.isAnchor) return nd.packedRadius || this._radiusScale(1);
      if (nd.isGroup) return this._radiusScale(nd.degree || 1);
      return this._radiusScale(nd.degree || 0);
    };
    for (const { entry } of orderByDepth) {
      const children = this._nodeData.filter(n => n.parentGroupNode === entry.node);
      entry.emitted.packedRadius = this._computePackedRadiusFromChildren(children, effectiveRadius);
      entry.emitted.packingChildren = children;
    }
    // Convenience for legacy code: expose effective radius getter on instance
    this._effectiveRadiusOf = effectiveRadius;

    // 7) Sim-node list: any node not packed inside an open group
    this._simNodeData = this._nodeData.filter(n => !n.parentGroupNode);

    // 8) Simulation + render link resolvers
    const simEndpointId = (ip) => {
      const node = this._simNodeForIp(ip);
      if (!node) return ip;
      if (node.type === 'ip') return ip;
      // node is a group; pick anchor (open) or super-node id (closed)
      return this._isEffectivelyOpen(node)
        ? this._anchorId(node.level.name, node.key)
        : this._groupId(node.level.name, node.key);
    };
    // LCA of two IPs in the group tree (returns null if their only common
    // ancestor is the virtual root).
    const lcaOf = (ipA, ipB) => {
      const leafA = this._ipNodeIndex.get(ipA);
      const leafB = this._ipNodeIndex.get(ipB);
      if (!leafA || !leafB) return null;
      const ancestorsA = new Set();
      let n = leafA.parent;
      while (n && n.type !== 'root') { ancestorsA.add(n); n = n.parent; }
      n = leafB.parent;
      while (n && n.type !== 'root') {
        if (ancestorsA.has(n)) return n;
        n = n.parent;
      }
      return null;
    };

    // Render endpoint for one side of a link: the OUTERMOST group on this IP's
    // chain that is a strict descendant of `lcaNode` (or of root, if lcaNode is
    // null). That endpoint terminates the line at the outer boundary visible
    // at this link's nesting level. Falls back to the IP itself when there is
    // no such group (e.g. solo IPs, or IPs whose only group ancestor IS the
    // LCA — meaning the link is intra-group at the deepest open level).
    const renderEndpointId = (ip, lcaNode) => {
      const leaf = this._ipNodeIndex.get(ip);
      if (!leaf) return ip;
      let n = leaf.parent;
      let outermostBelowLca = null;
      while (n && n.type !== 'root' && n !== lcaNode) {
        outermostBelowLca = n;
        n = n.parent;
      }
      if (!outermostBelowLca) return ip;
      return this._isEffectivelyOpen(outermostBelowLca)
        ? this._anchorId(outermostBelowLca.level.name, outermostBelowLca.key)
        : this._groupId(outermostBelowLca.level.name, outermostBelowLca.key);
    };

    // 9) Build simulation links
    const simPairCounts = new Map();
    for (const entry of agg.values()) {
      const la = simEndpointId(entry.sourceIp);
      const lb = simEndpointId(entry.targetIp);
      if (la === lb) continue;
      const pk = la < lb ? `${la}::${lb}` : `${lb}::${la}`;
      simPairCounts.set(pk, (simPairCounts.get(pk) || 0) + entry.count);
    }
    this._simLinks = [];
    for (const [pk, cnt] of simPairCounts) {
      const sep = pk.indexOf('::');
      const s = pk.slice(0, sep), t = pk.slice(sep + 2);
      // Endpoints must reference sim nodes only — drop any that resolved to
      // a non-sim id (shouldn't happen, but defensive)
      if (!nodeById.has(s) || !nodeById.has(t)) continue;
      this._simLinks.push({ source: s, target: t, value: cnt });
    }

    // Rendering links use renderEndpointId — deepest visible endpoint.
    // For nested combos this naturally aggregates at the right level.
    const renderBuckets = new Map(); // `${la}::${lb}::${attackType}` → bucket
    for (const entry of agg.values()) {
      const lca = lcaOf(entry.sourceIp, entry.targetIp);
      const la = renderEndpointId(entry.sourceIp, lca);
      const lb = renderEndpointId(entry.targetIp, lca);
      if (la === lb) continue;
      const [canonA, canonB] = la < lb ? [la, lb] : [lb, la];
      const key = `${canonA}::${canonB}::${entry.attackType}`;
      if (!renderBuckets.has(key)) {
        renderBuckets.set(key, { canonA, canonB, attackType: entry.attackType, count: 0, entries: [] });
      }
      const b = renderBuckets.get(key);
      b.count += entry.count;
      b.entries.push(entry);
    }

    // Group by canonical pair for parallel-offset computation
    const pairBuckets = new Map();
    for (const [, b] of renderBuckets) {
      const pk = `${b.canonA}::${b.canonB}`;
      if (!pairBuckets.has(pk)) pairBuckets.set(pk, []);
      pairBuckets.get(pk).push(b);
    }

    let maxCount = 1;
    for (const [, b] of renderBuckets) {
      if (b.count > maxCount) maxCount = b.count;
    }
    this._linkWidthScale = d3.scaleSqrt().domain([1, maxCount]).range([1.5, 8]);

    this._linkData = [];
    for (const [, buckets] of pairBuckets) {
      const total = buckets.length;
      buckets.forEach((b, idx) => {
        const offset = (idx - (total - 1) / 2) * 4;
        const srcNode = nodeById.get(b.canonA);
        const tgtNode = nodeById.get(b.canonB);
        if (!srcNode || !tgtNode) return;
        const isAggregated = !!(srcNode.isGroup || tgtNode.isGroup || srcNode.isAnchor || tgtNode.isAnchor);

        // For aggregated links, gradient direction is ambiguous — default false.
        // For non-aggregated, preserve original-direction from the dominant entry.
        let directionReversed = false;
        if (!isAggregated && b.entries.length > 0) {
          const e = b.entries[0];
          directionReversed = (e.origSourceIp || e.sourceIp) !== b.canonA;
        }

        this._linkData.push({
          sourceNode: srcNode,
          targetNode: tgtNode,
          attackType: b.attackType,
          attackTypes: new Set([b.attackType]),
          count: b.count,
          sourceIp: b.canonA,
          targetIp: b.canonB,
          directionReversed,
          parallelOffset: offset,
          isAggregated,
          entries: b.entries,
        });
      });
    }

    // Build summary links: aggregate member↔external entries into
    // anchor↔external lines (at the IP's innermost open ancestor).
    // Member entries (one per real IP↔external) are kept (marked
    // isMember:true) but hidden by default — hover reveals them.
    if (this._expandedGroups.size > 0) {
      const innermostOpenAncestor = (node) => {
        // For an IP node-data, returns the innermost open ancestor's tree node
        if (!node.isPacked) return null;
        const leaf = this._ipNodeIndex.get(node.id);
        if (!leaf) return null;
        let n = leaf.parent;
        while (n && n.type !== 'root') {
          if (this._isEffectivelyOpen(n)) return n;
          n = n.parent;
        }
        return null;
      };
      const summaryByKey = new Map();
      for (const link of this._linkData) {
        const srcPacked = link.sourceNode.isPacked;
        const tgtPacked = link.targetNode.isPacked;
        if (!srcPacked && !tgtPacked) continue;
        link.isMember = true;

        const srcAnc = srcPacked ? innermostOpenAncestor(link.sourceNode) : null;
        const tgtAnc = tgtPacked ? innermostOpenAncestor(link.targetNode) : null;
        const srcEndpointId = srcAnc
          ? this._anchorId(srcAnc.level.name, srcAnc.key) : link.sourceNode.id;
        const tgtEndpointId = tgtAnc
          ? this._anchorId(tgtAnc.level.name, tgtAnc.key) : link.targetNode.id;
        if (srcEndpointId === tgtEndpointId) { link.isIntraGroup = true; continue; } // intra-group
        const [aId, bId] = srcEndpointId < tgtEndpointId
          ? [srcEndpointId, tgtEndpointId]
          : [tgtEndpointId, srcEndpointId];
        const key = `${aId}::${bId}::${link.attackType}`;
        link.summaryKey = key;
        if (!summaryByKey.has(key)) {
          const aNode = nodeById.get(aId);
          const bNode = nodeById.get(bId);
          if (!aNode || !bNode) continue;
          summaryByKey.set(key, {
            sourceNode: aNode,
            targetNode: bNode,
            attackType: link.attackType,
            attackTypes: new Set([link.attackType]),
            count: 0,
            sourceIp: aId,
            targetIp: bId,
            directionReversed: false,
            parallelOffset: 0,
            isAggregated: true,
            isSummary: true,
            memberCount: 0,
          });
        }
        const s = summaryByKey.get(key);
        s.count += link.count;
        s.memberCount += 1;
      }

      // Assign parallel offsets within each canonical anchor-pair
      const summaryPairs = new Map();
      for (const s of summaryByKey.values()) {
        const pk = `${s.sourceIp}::${s.targetIp}`;
        if (!summaryPairs.has(pk)) summaryPairs.set(pk, []);
        summaryPairs.get(pk).push(s);
      }
      for (const arr of summaryPairs.values()) {
        const total = arr.length;
        arr.forEach((s, idx) => {
          s.parallelOffset = (idx - (total - 1) / 2) * 4;
        });
      }

      for (const s of summaryByKey.values()) this._linkData.push(s);

      // Update width scale to include summary counts
      let maxCount = this._linkWidthScale.domain()[1];
      for (const s of summaryByKey.values()) {
        if (s.count > maxCount) maxCount = s.count;
      }
      this._linkWidthScale = d3.scaleSqrt().domain([1, maxCount]).range([1.5, 8]);
    }
  }

  // ──────────────────── Rendering ──────────────────────

  /**
   * Render with live simulation. Optionally accepts starting positions
   * (absolute SVG coords) so nodes animate from those positions.
   * @param {d3.Selection} container – the <g> to render into
   * @param {Map<string,{x,y}>|null} startPositions – absolute SVG coords
   */
  render(container, startPositions, { staticStart = false } = {}) {
    const d3 = this.d3;

    // Stop any existing simulation
    if (this._simulation) {
      this._simulation.stop();
      this._simulation = null;
    }

    this._container = container;
    container.selectAll('*').remove();

    if (!this._aggregated || this._aggregated.size === 0) return;

    this._buildDataFromAggregation();

    // Drawing area
    const viewportH = window.innerHeight || this.height;
    const usableHeight = Math.max(400, viewportH - 160);
    const drawWidth = this._drawWidth = this.width - this.margin.left - this.margin.right;
    const drawHeight = this._drawHeight = usableHeight;

    this.svg.attr('height', this.margin.top + drawHeight + this.margin.bottom);

    // Center of drawing area
    const cx = this._cx = this.margin.left + drawWidth / 2;
    const cy = this._cy = this.margin.top + drawHeight / 2;

    // Set initial positions (convert from absolute to centered coords)
    if (startPositions) {
      for (const nd of this._nodeData) {
        const sp = startPositions.get(nd.id);
        if (sp) {
          nd.x = sp.x - cx;
          nd.y = sp.y - cy;
        }
      }
    }
    // Anchors initialize at their members' centroid if no start position given
    for (const nd of this._nodeData) {
      if (!nd.isAnchor || nd.x != null) continue;
      let sx = 0, sy = 0, n = 0;
      for (const mid of (nd.memberIPs || [])) {
        const m = this._nodeData.find(x => x.id === mid);
        if (m && m.x != null) { sx += m.x; sy += m.y; n++; }
      }
      nd.x = n > 0 ? sx / n : 0;
      nd.y = n > 0 ? sy / n : 0;
    }
    // Place packed members at initial anchor-relative positions
    this._placePackedMembers();

    // Centered group
    const g = this._centerG = container.append('g')
      .attr('transform', `translate(${cx},${cy})`);

    // --- Hulls (behind everything) — visible boundary for expanded /24 groups ---
    this._hullG = g.append('g').attr('class', 'expanded-group-hulls');

    // --- Directional gradients for links ---
    const NEUTRAL_GREY = '#999';
    const gradDefs = g.append('defs');
    const gradSel = gradDefs.selectAll('linearGradient')
      .data(this._linkData)
      .join('linearGradient')
      .attr('id', (d, i) => `force-grad-${i}`)
      .attr('gradientUnits', 'userSpaceOnUse');
    gradSel.append('stop')
      .attr('offset', '0%')
      .attr('stop-color', d => d.directionReversed ? NEUTRAL_GREY : this.colorForAttack(d.attackType));
    gradSel.append('stop')
      .attr('offset', '100%')
      .attr('stop-color', d => d.directionReversed ? this.colorForAttack(d.attackType) : NEUTRAL_GREY);

    // --- Links (behind nodes) ---
    // By default: summary links + non-group links visible; member links hidden.
    // Hover reveals member-level fan, hiding the corresponding summary.
    const linkSel = g.append('g')
      .attr('stroke-opacity', 0.6)
      .selectAll('line')
      .data(this._linkData)
      .join('line')
      .attr('class', 'force-link')
      .attr('stroke', (d, i) => `url(#force-grad-${i})`)
      .attr('stroke-width', d => {
        const w = this._linkWidthScale(d.count);
        return d.isAggregated ? Math.max(w * 1.25, 2.5) : w;
      })
      .attr('stroke-dasharray', d => d.isAggregated ? '4 3' : null)
      .style('display', d => (d.isMember && !d.isIntraGroup) ? 'none' : null);

    // --- Nodes (anchors are invisible — they only drive link force) ---
    const visibleNodes = this._nodeData.filter(d => !d.isAnchor);
    const nodeSel = g.append('g')
      .attr('stroke', '#fff')
      .attr('stroke-width', 1.5)
      .selectAll('g')
      .data(visibleNodes, d => d.id)
      .join('g')
      .attr('class', 'force-node');

    nodeSel.append('circle')
      .attr('r', d => this._radiusScale(d.degree))
      .attr('fill', d => this._nodeColor(d))
      .attr('stroke-width', d => d.isGroup ? 3 : 1.5);

    // Outer ring for super-nodes
    nodeSel.filter(d => d.isGroup)
      .append('circle')
      .attr('r', d => this._radiusScale(d.degree) + 4)
      .attr('fill', 'none')
      .attr('stroke', d => this._nodeColor(d))
      .attr('stroke-width', 1.5);

    // Hubs (high-degree solos, all super-nodes, and packed members) keep
    // their label visible. Low-degree solos hide their label until hovered —
    // mirrors ReGraph's selection-driven label reveal in dense charts.
    const LABEL_DEGREE_THRESHOLD = this._labelDegreeThreshold;
    const labelAlwaysOn = (d) =>
      !d.isPacked && (d.degree || 0) >= LABEL_DEGREE_THRESHOLD;

    nodeSel.append('text')
      .attr('class', 'node-label')
      .attr('x', d => this._radiusScale(d.degree) + (d.isGroup ? 8 : 6))
      .attr('dy', '0.35em')
      .style('fill', '#333')
      .style('stroke', 'none')
      .style('font-size', '11px')
      .style('pointer-events', 'none')
      .style('display', d => labelAlwaysOn(d) ? null : 'none')
      .text(d => d.isGroup ? `${d.group}${this._suffixForNode(d)} · ${d.count}` : d.id);

    this._labelAlwaysOn = labelAlwaysOn;

    this._linkSel = linkSel;
    this._gradSel = gradSel;
    this._nodeSel = nodeSel;

    // --- Force simulation (two-layer: outer layout sees solos + super-nodes
    // + anchors only; packed members are placed deterministically in _ticked) ---
    const simulation = d3.forceSimulation(this._simNodeData)
      .force('link', d3.forceLink(this._simLinks).id(d => d.id)
        .distance(d => {
          // Pull external nodes far enough away to not visually overlap
          // anchor circles. Base distance + each side's combo radius.
          const sr = d.source.packedRadius || 0;
          const tr = d.target.packedRadius || 0;
          return 80 + sr + tr;
        })
        .strength(0.5))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('x', d3.forceX())
      .force('y', d3.forceY())
      .force('collide', d3.forceCollide(d =>
        d.isAnchor ? (d.packedRadius || 0) + 8 : this._radiusScale(d.degree) + 5))
      .on('tick', () => this._ticked());

    this._simulation = simulation;

    if (staticStart) {
      // Stop the timer so simulation doesn't animate; position DOM once
      simulation.stop();
      this._ticked();
    }

    // --- Drag (packed members can't be dragged — their positions are derived) ---
    nodeSel.filter(d => !d.isPacked).call(d3.drag()
      .on('start', function (event, d) {
        if (!event.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
        d3.select(this).classed('dragging', true);
      })
      .on('drag', (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on('end', function (event, d) {
        if (!event.active) simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
        d3.select(this).classed('dragging', false);
      })
    );

    // --- Click on super-node: expand it (one level deeper) ---
    // Collapse happens via clicking the open group's boundary circle (_drawHulls).
    nodeSel.on('click', (event, d) => {
      if (event.defaultPrevented) return;
      if (this._levels.length === 0) return;
      if (d.isGroup) {
        event.stopPropagation();
        const gid = this._groupId(d.level, d.group);
        this._rebuildWithGroupChange(
          () => this._expandedGroups.add(gid),
          'expand', { level: d.level, key: d.group, id: gid });
      }
    });

    // --- Hover interactions ---
    this._attachHoverInteractions();
  }

  /**
   * Computes trimmed line endpoints for a link (trims at anchor circle edges
   * + applies parallel offset for multi-attack-type fanning). Single source
   * of truth — used by tick, hover handlers, and visibility toggles.
   */
  /**
   * Radius at which a line should visually terminate on this node-data. Open
   * groups (anchors) trim at their bounding-circle (packedRadius); closed
   * super-nodes and IP leaves trim at their _radiusScale circle.
   */
  _visibleRadiusOf(nd) {
    if (!nd) return 0;
    if (nd.isAnchor) return nd.packedRadius || 0;
    return this._radiusScale ? (this._radiusScale(nd.degree) || 0) : 0;
  }

  _linkEndpoints(d) {
    let sx = d.sourceNode.x, sy = d.sourceNode.y;
    let tx = d.targetNode.x, ty = d.targetNode.y;
    const dx = tx - sx, dy = ty - sy;
    const len = Math.sqrt(dx * dx + dy * dy) || 1;
    const ux = dx / len, uy = dy / len;
    let trimS = this._visibleRadiusOf(d.sourceNode);
    let trimT = this._visibleRadiusOf(d.targetNode);
    if (trimS + trimT >= len) {
      const scale = (len * 0.95) / (trimS + trimT);
      trimS *= scale; trimT *= scale;
    }
    sx += ux * trimS; sy += uy * trimS;
    tx -= ux * trimT; ty -= uy * trimT;
    const nx = (-uy) * (d.parallelOffset || 0);
    const ny = (ux) * (d.parallelOffset || 0);
    return { sx: sx + nx, sy: sy + ny, tx: tx + nx, ty: ty + ny };
  }

  /**
   * Force-refresh all currently visible line endpoints. Call after toggling
   * link visibility so newly-shown lines don't carry stale x1/y1/x2/y2 from
   * a previous state.
   */
  _refreshLinkEndpoints() {
    if (!this._linkSel) return;
    // Any visibility change can orphan an arrowhead overlay (the link it was
    // attached to may have just become display:none, swallowing its mouseout).
    if (this._centerG) removeArrowheads(this._centerG);
    const self = this;
    this._linkSel.each(function (d) {
      if (this.style.display === 'none') return;
      const p = self._linkEndpoints(d);
      this.setAttribute('x1', p.sx);
      this.setAttribute('y1', p.sy);
      this.setAttribute('x2', p.tx);
      this.setAttribute('y2', p.ty);
    });
  }

  // ──────────────────── Tick ──────────────────────

  _ticked() {
    const linkSel = this._linkSel;
    const gradSel = this._gradSel;
    const nodeSel = this._nodeSel;
    if (!linkSel || !nodeSel) return;

    const endpoints = (d) => this._linkEndpoints(d);

    // Update links and gradient endpoints with parallel offsets
    linkSel.each(function (d) {
      const p = endpoints(d);
      this.setAttribute('x1', p.sx);
      this.setAttribute('y1', p.sy);
      this.setAttribute('x2', p.tx);
      this.setAttribute('y2', p.ty);
    });

    if (gradSel) {
      gradSel.each(function (d) {
        const p = endpoints(d);
        this.setAttribute('x1', p.sx);
        this.setAttribute('y1', p.sy);
        this.setAttribute('x2', p.tx);
        this.setAttribute('y2', p.ty);
      });
    }

    // Place packed members deterministically around their anchors
    this._placePackedMembers();

    // Update nodes
    nodeSel.attr('transform', d => `translate(${d.x},${d.y})`);

    // Recompute boundary circles from anchor positions (used by _drawHulls
    // for rendering, and by boundaryRepel for top-level repulsion only —
    // nested circles are inside their parent so don't need separate repel).
    this._groupCircles = [];
    for (const n of this._nodeData) {
      if (!n.isAnchor) continue;
      this._groupCircles.push({
        id: this._groupId(n.level, n.subnet),
        level: n.level,
        key: n.subnet,
        subnet: n.subnet, // legacy
        cx: n.x, cy: n.y,
        r: n.packedRadius || 28,
        isTopLevel: !n.parentGroupNode,
      });
    }

    // Redraw expanded-group hulls
    this._drawHulls();

    // Auto-fit: scale the centered group so all nodes stay within the drawing area
    this._autoFit();
  }

  // ─────────────── Cluster force + hulls (expanded /24 groups) ───────────────

  /**
   * Custom force that pulls each node sharing a `subnet` toward the centroid
   * of that subnet — but only for subnets currently in `_expandedGroups`.
   * Keeps members of an expanded /24 visually clustered so users can tell
   * which group a node was ungrouped from.
   */
  /**
   * Sunflower (Vogel) spiral packing radius for N members. Each member
   * occupies a disk of `step` diameter; the bounding radius is the max
   * polar radius plus the member radius.
   */
  _computePackedRadius(members) {
    if (!members || members.length === 0) return 0;
    const memberR = Math.max(...members.map(m => this._radiusScale(m.degree)));
    const step = 2 * memberR + 4;
    const N = members.length;
    if (N === 1) return memberR + 14;
    const maxR = step * Math.sqrt(N - 0.5);
    return maxR + memberR + 14;
  }

  /**
   * Tight variable-size circle packing via d3.packSiblings + d3.packEnclose.
   * Mutates each child with `.packDx/.packDy` offsets (relative to anchor),
   * returns the bounding circle radius.
   *
   * Replaces the previous uniform sunflower step (which made the bounding
   * circle blow up whenever one child was much larger than the rest).
   */
  _computePackedRadiusFromChildren(children, effRadiusFn) {
    if (!children || children.length === 0) return 0;
    const CHILD_PAD = 16; // gap between siblings
    const RIM_PAD = 14;   // gap between outermost child and bounding circle
    const d3 = this.d3;
    if (children.length === 1) {
      const r = effRadiusFn(children[0]);
      children[0].packDx = 0;
      children[0].packDy = 0;
      return r + RIM_PAD;
    }
    // Inflate each child's packing radius by half the desired sibling gap.
    const circles = children.map(c => ({ r: effRadiusFn(c) + CHILD_PAD / 2 }));
    d3.packSiblings(circles);
    const enclose = d3.packEnclose(circles);
    children.forEach((c, i) => {
      c.packDx = circles[i].x - enclose.x;
      c.packDy = circles[i].y - enclose.y;
    });
    return enclose.r + RIM_PAD;
  }

  /**
   * Recursively place all packed nodes (IPs, closed sub-group super-nodes,
   * and nested open anchors) inside their parent open-group anchor using
   * the precomputed offsets from d3.packSiblings (set in
   * `_computePackedRadiusFromChildren`).
   *
   * Anchors must be walked outermost-first so each level's anchor positions
   * are settled before its children inherit them.
   */
  _placePackedMembers() {
    if (!this._nodeData) return;
    const anchors = this._nodeData.filter(n => n.isAnchor);
    const depthOf = (anchorNd) => {
      let d = 0;
      let p = anchorNd.parentGroupNode;
      while (p) { d++; p = p.parent && p.parent.type !== 'root' ? p.parent : null; }
      return d;
    };
    anchors.sort((a, b) => depthOf(a) - depthOf(b));

    for (const a of anchors) {
      const kids = a.packingChildren || [];
      for (const k of kids) {
        k.x = a.x + (k.packDx || 0);
        k.y = a.y + (k.packDy || 0);
      }
    }
  }

  _makeClusterForce_UNUSED(strength = 0.2) {
    const self = this;
    let nodes = [];
    const PAD = 14;
    function force(alpha) {
      const expanded = self._expandedGroups;
      self._groupCircles = [];
      if (!expanded || expanded.size === 0) return;

      // Anchor positions per subnet (anchor nodes participate in link force)
      const anchors = new Map();
      for (const n of nodes) {
        if (n.isAnchor && n.subnet) anchors.set(n.subnet, n);
      }

      // Hard relaxation: move each member a fraction of the way toward its
      // anchor every tick (not alpha-scaled, so it never weakens). Keeps the
      // cluster glued to the anchor regardless of link tension on externals.
      const LERP = 0.35;
      for (const n of nodes) {
        if (n.isGroup || n.isAnchor) continue;
        if (!n.subnet || !expanded.has(n.subnet)) continue;
        const a = anchors.get(n.subnet);
        if (!a) continue;
        n.x += (a.x - n.x) * LERP;
        n.y += (a.y - n.y) * LERP;
      }

      // Bounding-circle radius per subnet (max member offset from anchor),
      // capped via median so a single stray member can't blow up the radius.
      const distsBySubnet = new Map();
      for (const n of nodes) {
        if (n.isGroup || n.isAnchor) continue;
        if (!n.subnet || !expanded.has(n.subnet)) continue;
        const a = anchors.get(n.subnet);
        if (!a) continue;
        const r = self._radiusScale(n.degree);
        const d = Math.hypot(n.x - a.x, n.y - a.y) + r;
        if (!distsBySubnet.has(n.subnet)) distsBySubnet.set(n.subnet, []);
        distsBySubnet.get(n.subnet).push(d);
      }

      for (const [subnet, a] of anchors) {
        const ds = distsBySubnet.get(subnet) || [];
        ds.sort((x, y) => x - y);
        // Use 90th percentile distance to ignore one stray outlier
        const idx = Math.max(0, Math.floor(ds.length * 0.9) - 0);
        const dMax = ds.length > 0 ? ds[Math.min(idx, ds.length - 1)] : 0;
        const r = Math.max(dMax + PAD, 28);
        self._groupCircles.push({ subnet, cx: a.x, cy: a.y, r });
      }
    }
    force.initialize = (n) => { nodes = n; };
    return force;
  }

  /**
   * Pushes any node that is NOT a member of an expanded /24 group out of
   * that group's bounding circle. Makes the circle behave like a solid
   * super-node so external IPs and other groups stop overlapping it.
   */
  _makeBoundaryRepelForce() {
    const self = this;
    let nodes = [];
    function force() {
      const allCircles = self._groupCircles;
      if (!allCircles || allCircles.length === 0) return;
      // Only top-level circles repel sim nodes — nested circles are inside
      // their parent's circle and don't need a separate exclusion zone.
      const circles = allCircles.filter(c => c.isTopLevel);
      if (circles.length === 0) return;
      const circleBySubnet = new Map();
      for (const c of circles) circleBySubnet.set(c.subnet, c);
      for (const n of nodes) {
        if (n.fx != null || n.fy != null) continue; // user is dragging
        // For anchor nodes use their group's circle radius (so circle-to-circle
        // separation is honored). For everything else use the node's draw radius.
        const ownCircle = n.isAnchor ? circleBySubnet.get(n.subnet) : null;
        const nr = ownCircle ? ownCircle.r : self._radiusScale(n.degree || 0);
        for (const c of circles) {
          if (n.subnet === c.subnet && !n.isGroup) continue; // member or own anchor — skip
          let dx = n.x - c.cx;
          let dy = n.y - c.cy;
          let dist = Math.hypot(dx, dy);
          const minDist = c.r + nr + 40;
          if (dist < minDist) {
            if (dist < 0.001) {
              // Coincident — pick an arbitrary direction so we can push out
              dx = 1; dy = 0; dist = 1;
            }
            // Hard clamp: move node to the boundary and kill inward velocity
            const ux = dx / dist, uy = dy / dist;
            n.x = c.cx + ux * minDist;
            n.y = c.cy + uy * minDist;
            const vDotU = (n.vx || 0) * ux + (n.vy || 0) * uy;
            if (vDotU < 0) {
              n.vx -= vDotU * ux;
              n.vy -= vDotU * uy;
            }
          }
        }
      }
    }
    force.initialize = (n) => { nodes = n; };
    return force;
  }

  /**
   * Draws a clean bounding circle behind each expanded /24 group. Circle
   * is centered on the members' centroid with radius = max-member-distance
   * + padding. Circle click collapses the group.
   */
  _drawHulls() {
    if (!this._hullG) return;
    const expanded = this._expandedGroups;

    if (!expanded || expanded.size === 0 || !this._groupCircles || this._groupCircles.length === 0) {
      this._hullG.selectAll('circle').remove();
      this._hullG.selectAll('text').remove();
      return;
    }

    // Reuse circles computed by the cluster force so all three (cluster pull,
    // boundary repel, render) stay in sync.
    const circleData = this._groupCircles;

    const cSel = this._hullG.selectAll('circle').data(circleData, d => d.id);
    cSel.exit().remove();
    const cEnt = cSel.enter().append('circle')
      .attr('class', 'expanded-group-boundary')
      .attr('fill', d => this._hullColor(d.key))
      .attr('fill-opacity', 0.08)
      .attr('stroke', d => this._hullColor(d.key))
      .attr('stroke-opacity', 0.7)
      .attr('stroke-width', 1.5)
      .attr('stroke-dasharray', '5 3')
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation();
        this._rebuildWithGroupChange(
          () => this._expandedGroups.delete(d.id),
          'collapse', { level: d.level, key: d.key, id: d.id });
      })
      .on('mouseover', (event, d) => {
        removeArrowheads(this._centerG);
        const suffix = this._levelDef(d.level)?.suffix || '';
        this.showTooltip(this.tooltip, event,
          `<strong>${d.key}${suffix}</strong><br>Click to collapse`);
      })
      .on('mousemove', (event) => {
        if (this.tooltip && this.tooltip.style.display !== 'none') {
          this.tooltip.style.left = (event.clientX + 10) + 'px';
          this.tooltip.style.top = (event.clientY + 10) + 'px';
        }
      })
      .on('mouseout', () => this.hideTooltip(this.tooltip));
    cEnt.merge(cSel)
      .attr('cx', d => d.cx).attr('cy', d => d.cy).attr('r', d => d.r);

    const tSel = this._hullG.selectAll('text').data(circleData, d => d.id);
    tSel.exit().remove();
    const tEnt = tSel.enter().append('text')
      .attr('class', 'expanded-group-label')
      .attr('text-anchor', 'middle')
      .style('font-size', '11px')
      .style('font-weight', '600')
      .style('pointer-events', 'none')
      .style('fill', d => this._hullColor(d.key))
      .text(d => `${d.key}${this._levelDef(d.level)?.suffix || ''}`);
    tEnt.merge(tSel)
      .attr('x', d => d.cx)
      .attr('y', d => d.cy - d.r - 4);
  }

  _hullColor(subnet) {
    let h = 0;
    for (const c of subnet) h = (h * 31 + c.charCodeAt(0)) | 0;
    const hue = (h & 0xff) / 255;
    return this.d3.interpolateRainbow(hue);
  }

  _autoFit() {
    if (!this._centerG || !this._nodeData || this._nodeData.length === 0) return;

    const labelPad = 80; // extra space for IP label text
    let xMin = Infinity, xMax = -Infinity, yMin = Infinity, yMax = -Infinity;
    for (const d of this._nodeData) {
      if (d.isAnchor) continue;
      const r = this._radiusScale(d.degree);
      xMin = Math.min(xMin, d.x - r);
      xMax = Math.max(xMax, d.x + r + labelPad);
      yMin = Math.min(yMin, d.y - r);
      yMax = Math.max(yMax, d.y + r);
    }

    const contentW = (xMax - xMin) || 1;
    const contentH = (yMax - yMin) || 1;
    const contentCx = (xMin + xMax) / 2;
    const contentCy = (yMin + yMax) / 2;

    const scaleX = this._drawWidth / contentW;
    const scaleY = this._drawHeight / contentH;
    const scale = Math.min(scaleX, scaleY, 1.5); // cap so small graphs don't over-zoom

    this._fitScale = scale;
    this._fitContentCx = contentCx;
    this._fitContentCy = contentCy;

    this._centerG.attr('transform',
      `translate(${this._cx},${this._cy}) scale(${scale}) translate(${-contentCx},${-contentCy})`);
  }

  // ──────────────────── Hover ──────────────────────

  _attachHoverInteractions() {
    const self = this;

    // Node hover
    this._nodeSel
      .on('mouseover', function (event, d) {
        // Clear any orphan arrowhead from a prior link hover
        removeArrowheads(self._centerG);
        // ReGraph-style "contents links" reveal: hide aggregated lines that
        // cross d's boundary and draw a fan of real connections from d.
        const { fanPartners, matchedLinks } = self._revealExplodedFan(d);
        // Neighbor set: d itself + direct link partners + fan partners
        const neighbors = new Set([d.id, ...fanPartners]);
        for (const l of self._linkData) {
          if (matchedLinks.has(l)) continue; // hidden by fan
          if (l.sourceIp === d.id) neighbors.add(l.targetIp);
          else if (l.targetIp === d.id) neighbors.add(l.sourceIp);
        }
        self._linkSel
          .attr('stroke-opacity', l =>
            (l.sourceIp === d.id || l.targetIp === d.id) ? 1 : 0.15)
          .attr('stroke-width', l => {
            const base = self._linkWidthScale(l.count);
            return (l.sourceIp === d.id || l.targetIp === d.id)
              ? Math.max(base * 1.5, 3) : base;
          });
        self._nodeSel.select('circle')
          .attr('opacity', n => neighbors.has(n.id) ? 1 : 0.3);
        // Reveal labels of hovered node + neighbors (ReGraph-style)
        self._nodeSel.select('text.node-label')
          .style('display', n =>
            (neighbors.has(n.id) || self._labelAlwaysOn(n)) ? null : 'none');
        const tipHtml = d.isGroup
          ? `<strong>${d.group}${self._suffixForNode(d)}</strong><br>${d.count} IPs`
          : `<strong>${d.id}</strong><br>Connections: ${d.degree}`;
        self.showTooltip(self.tooltip, event, tipHtml);
      })
      .on('mousemove', function (event) {
        if (self.tooltip && self.tooltip.style.display !== 'none') {
          self.tooltip.style.left = (event.clientX + 10) + 'px';
          self.tooltip.style.top = (event.clientY + 10) + 'px';
        }
      })
      .on('mouseout', function () {
        removeArrowheads(self._centerG);
        self._clearExplodedFan();
        unhighlightLinks(self._linkSel, self._linkWidthScale);
        self._nodeSel.select('circle').attr('opacity', 1);
        // Restore default label visibility
        self._nodeSel.select('text.node-label')
          .style('display', n => self._labelAlwaysOn(n) ? null : 'none');
        // Restore summary/member default visibility
        self._restoreSummaryMemberDefault();
        self.hideTooltip(self.tooltip);
      });

    // Link hover — shared highlight logic with timearcs
    this._linkSel
      .on('mouseover', function (event, d) {
        // If hovering a summary link, reveal only the members connecting
        // its external endpoint to the anchor (not the whole group's fan).
        if (d.isSummary) {
          const externalNode = d.sourceNode.isAnchor ? d.targetNode : d.sourceNode;
          self._revealMemberFans(externalNode);
        }
        // Dim all links, highlight hovered (shared with timearcs)
        highlightHoveredLink(self._linkSel, d, this, self._linkWidthScale, self.d3);

        // Compute attack color (shared with timearcs)
        const { activeIPs, attackColor } = getLinkHighlightInfo(d, self.colorForAttack);

        // Show directional arrowhead at target end — but not for summary lines,
        // which get hidden immediately when their member fan is revealed.
        let arrowBase = null;
        if (!d.isSummary) {
          const targetNode = d.directionReversed ? d.sourceNode : d.targetNode;
          const targetR = self._visibleRadiusOf(targetNode);
          const hoveredStrokeW = parseFloat(this.getAttribute('stroke-width')) || 1;
          arrowBase = showLineArrowhead(self._centerG, d, attackColor, targetR, hoveredStrokeW);

          // Trim the line so it ends at the arrowhead base (not past it)
          if (arrowBase) {
            const isTargetAtX2 = !d.directionReversed;
            if (isTargetAtX2) {
              this.setAttribute('x2', arrowBase.baseX);
              this.setAttribute('y2', arrowBase.baseY);
            } else {
              this.setAttribute('x1', arrowBase.baseX);
              this.setAttribute('y1', arrowBase.baseY);
            }
          }
        }

        // Highlight source node with attack color; other nodes keep their
        // normal fill (via _nodeColor) so custom styling survives hover.
        const origSource = d.directionReversed ? d.targetIp : d.sourceIp;
        self._nodeSel.select('circle')
          .attr('fill', n => (n.id === origSource) ? attackColor : self._nodeColor(n))
          .attr('opacity', n => activeIPs.has(n.id) ? 1 : 0.3);
        // Reveal endpoint labels
        self._nodeSel.select('text.node-label')
          .style('display', n =>
            (activeIPs.has(n.id) || self._labelAlwaysOn(n)) ? null : 'none');
        highlightEndpointLabels(self._nodeSel.select('text'), activeIPs, attackColor);

        // Anchor id format: "anchor:LEVEL:KEY" → display as "KEY<suffix>"
        const displayId = (id) => {
          if (!id.startsWith('anchor:')) return id;
          const rest = id.slice('anchor:'.length);
          const colon = rest.indexOf(':');
          if (colon < 0) return rest;
          const lvl = rest.slice(0, colon), key = rest.slice(colon + 1);
          return `${key}${self._levelDef(lvl)?.suffix || ''}`;
        };
        const extraInfo = d.isSummary
          ? `<br>${d.memberCount} member connection${d.memberCount === 1 ? '' : 's'}` : '';
        self.showTooltip(self.tooltip, event,
          `<strong>${displayId(d.sourceIp)} \u2194 ${displayId(d.targetIp)}</strong><br>` +
          `Attack: ${d.attackType}<br>Count: ${d.count}${extraInfo}`);
      })
      .on('mousemove', function (event) {
        if (self.tooltip && self.tooltip.style.display !== 'none') {
          self.tooltip.style.left = (event.clientX + 10) + 'px';
          self.tooltip.style.top = (event.clientY + 10) + 'px';
        }
      })
      .on('mouseout', function (event, d) {
        // Remove arrowhead overlay
        removeArrowheads(self._centerG);

        // Restore line endpoints (trimmed to anchor circle edges)
        if (d) {
          const p = self._linkEndpoints(d);
          this.setAttribute('x1', p.sx);
          this.setAttribute('y1', p.sy);
          this.setAttribute('x2', p.tx);
          this.setAttribute('y2', p.ty);
        }

        // Restore links (shared with timearcs)
        unhighlightLinks(self._linkSel, self._linkWidthScale);

        // Restore nodes
        self._nodeSel.select('circle')
          .attr('fill', n => self._nodeColor(n))
          .attr('opacity', 1);
        unhighlightEndpointLabels(self._nodeSel.select('text'));
        // Restore default label visibility
        self._nodeSel.select('text.node-label')
          .style('display', n => self._labelAlwaysOn(n) ? null : 'none');
        // Restore summary/member default visibility
        self._restoreSummaryMemberDefault();

        self.hideTooltip(self.tooltip);
      });
  }

  // ────────── Summary/Member link reveal helpers ──────────

  /**
   * Reveal member-level fan(s) for groups related to the hovered node.
   *
   * - Hovered packed member or anchor → reveal all members of that subnet,
   *   hide all summaries touching that anchor.
   * - Hovered external node → reveal members of every summary it touches,
   *   hide those specific summaries.
   * - Hovered solo (no group connection) → no-op.
   */
  _revealMemberFans(node) {
    if (!this._linkSel || !this._linkData) return;

    // Build a predicate `(link) → 'reveal' | 'leave'` based on what was hovered.
    // - Packed member: only that member's own links.
    // - Anchor: every member of that subnet.
    // - External connected to a group: only members of those groups that this
    //   external talks to.
    let scope = null;
    if (node.isPacked) {
      scope = { kind: 'memberId', id: node.id };
    } else if (node.isAnchor) {
      scope = { kind: 'subnet', subnet: node.subnet };
    } else {
      // External — find summaries touching it; reveal their fans.
      const externalAnchors = new Set();
      for (const l of this._linkData) {
        if (!l.isSummary) continue;
        if (l.sourceIp === node.id && l.targetIp.startsWith('anchor:'))
          externalAnchors.add(l.targetIp);
        else if (l.targetIp === node.id && l.sourceIp.startsWith('anchor:'))
          externalAnchors.add(l.sourceIp);
      }
      if (externalAnchors.size === 0) return;
      scope = { kind: 'externalToAnchors', externalId: node.id, anchors: externalAnchors };
    }

    const memberMatch = (l) => {
      // Returns true if this member link should be revealed under current scope
      if (!l.isMember) return false;
      const src = l.sourceNode, tgt = l.targetNode;
      if (scope.kind === 'memberId') {
        return src.id === scope.id || tgt.id === scope.id;
      }
      if (scope.kind === 'subnet') {
        return (src.isPacked && src.subnet === scope.subnet) ||
               (tgt.isPacked && tgt.subnet === scope.subnet);
      }
      // externalToAnchors
      const touchesExternal = src.id === scope.externalId || tgt.id === scope.externalId;
      if (!touchesExternal) return false;
      // Member's innermost-group anchor id depends on its tree level
      const packedSide = src.isPacked ? src : (tgt.isPacked ? tgt : null);
      if (!packedSide) return false;
      const leaf = this._ipNodeIndex.get(packedSide.id);
      if (!leaf || leaf.parent.type === 'root') return false;
      const innermost = leaf.parent;
      return scope.anchors.has(this._anchorId(innermost.level.name, innermost.key));
    };

    const summaryMatch = (l) => {
      if (!l.isSummary) return false;
      // Hide summary if any of its member links would be revealed
      const srcIsAnchor = l.sourceNode.isAnchor;
      const tgtIsAnchor = l.targetNode.isAnchor;
      if (scope.kind === 'memberId') {
        // Only hide the specific summary that this member rolls up into
        const leaf = this._ipNodeIndex.get(scope.id);
        if (!leaf || leaf.parent.type === 'root') return false;
        const innermost = leaf.parent;
        const memberAnchor = this._anchorId(innermost.level.name, innermost.key);
        const involves =
          (srcIsAnchor && l.sourceIp === memberAnchor) ||
          (tgtIsAnchor && l.targetIp === memberAnchor);
        if (!involves) return false;
        // And only if its external endpoint is a neighbor of the member
        const externalId = srcIsAnchor ? l.targetIp : l.sourceIp;
        // Check the member actually connects to this external
        for (const ml of this._linkData) {
          if (!ml.isMember) continue;
          if ((ml.sourceNode.id === scope.id && ml.targetNode.id === externalId) ||
              (ml.targetNode.id === scope.id && ml.sourceNode.id === externalId)) {
            return true;
          }
        }
        return false;
      }
      if (scope.kind === 'subnet') {
        return (srcIsAnchor && l.sourceNode.subnet === scope.subnet) ||
               (tgtIsAnchor && l.targetNode.subnet === scope.subnet);
      }
      // externalToAnchors
      return (l.sourceIp === scope.externalId && scope.anchors.has(l.targetIp)) ||
             (l.targetIp === scope.externalId && scope.anchors.has(l.sourceIp));
    };

    this._linkSel.style('display', (l) => {
      if (l.isSummary) return summaryMatch(l) ? 'none' : null;
      if (l.isIntraGroup) return null; // always visible
      if (l.isMember) return memberMatch(l) ? null : 'none';
      return null;
    });
    this._refreshLinkEndpoints();
  }

  _restoreSummaryMemberDefault() {
    if (!this._linkSel) return;
    this._linkSel.style('display', d => (d.isMember && !d.isIntraGroup) ? 'none' : null);
    this._refreshLinkEndpoints();
  }

  /**
   * ReGraph-style "contents links" reveal: when hovering a node that is part of
   * (or contains) an aggregated group, hide the aggregated render lines that
   * cross its boundary and draw temporary fan lines from the hovered node to
   * the deepest-visible partner on each underlying real connection.
   *
   * Intra-group traffic (entries with both endpoints inside d's member set)
   * is preserved — only links that cross d's boundary are replaced.
   *
   * Returns { fanPartners: Set<nodeId>, matchedLinks: Set<link> }.
   */
  _revealExplodedFan(d) {
    const empty = { fanPartners: new Set(), matchedLinks: new Set() };
    if (!this._linkSel || !this._linkData || !this._centerG) return empty;
    this._clearExplodedFan();

    const memberIps = this._memberIpsOf(d);
    if (memberIps.size === 0) return empty;

    const matchedLinks = new Set();
    const fanAgg = new Map(); // `${partnerId}::${attackType}` → { partnerNode, attackType, count, outbound, inbound }

    for (const l of this._linkData) {
      if (!l.entries) continue;
      let crossesD = false;
      const partnerEntries = [];
      for (const e of l.entries) {
        const sIn = memberIps.has(e.sourceIp);
        const tIn = memberIps.has(e.targetIp);
        if (sIn === tIn) continue; // both in or both out → not a crossing entry
        crossesD = true;
        const orig = e.origSourceIp || e.sourceIp;
        partnerEntries.push({
          partnerIp: sIn ? e.targetIp : e.sourceIp,
          count: e.count,
          hoveredIsSource: memberIps.has(orig),
        });
      }
      if (!crossesD) continue;
      matchedLinks.add(l);
      for (const pe of partnerEntries) {
        const partnerTree = this._renderNodeForIp(pe.partnerIp);
        let partnerId;
        if (!partnerTree || partnerTree.type === 'ip') partnerId = pe.partnerIp;
        else partnerId = this._isEffectivelyOpen(partnerTree)
          ? this._anchorId(partnerTree.level.name, partnerTree.key)
          : this._groupId(partnerTree.level.name, partnerTree.key);
        if (partnerId === d.id) continue;
        const key = `${partnerId}::${l.attackType}`;
        if (!fanAgg.has(key)) {
          const partnerNd = this._nodeData.find(n => n.id === partnerId);
          if (!partnerNd) continue;
          fanAgg.set(key, {
            partnerNode: partnerNd, attackType: l.attackType,
            count: 0, outbound: 0, inbound: 0,
          });
        }
        const f = fanAgg.get(key);
        f.count += pe.count;
        if (pe.hoveredIsSource) f.outbound += pe.count;
        else f.inbound += pe.count;
      }
    }

    // Hide matched render lines
    this._linkSel.style('display', l => matchedLinks.has(l) ? 'none' : ((l.isMember && !l.isIntraGroup) ? 'none' : null));

    // Draw fan group
    const colorForAttack = (atk) => this.colorForAttack ? this.colorForAttack(atk) : '#888';
    const g = this._centerG.append('g').attr('class', 'exploded-fan-group')
      .style('pointer-events', 'none');
    const fanPartners = new Set();
    for (const f of fanAgg.values()) {
      fanPartners.add(f.partnerNode.id);
      const w = this._linkWidthScale(Math.max(1, f.count));
      const strokeWidth = Math.max(2, w);
      // Dominant direction: if more traffic flows hovered→partner, arrow at partner end.
      const directionReversed = f.inbound > f.outbound;
      const fakeLink = {
        sourceNode: d,
        targetNode: f.partnerNode,
        parallelOffset: 0,
        directionReversed,
      };
      const ep = this._linkEndpoints(fakeLink);
      const color = colorForAttack(f.attackType);
      // One sub-group per fan line so each gets its own arrowhead (showLineArrowhead
      // removes prior arrowheads from its container).
      const lineG = g.append('g');
      const line = lineG.append('line')
        .attr('x1', ep.sx).attr('y1', ep.sy)
        .attr('x2', ep.tx).attr('y2', ep.ty)
        .attr('stroke', color)
        .attr('stroke-width', strokeWidth)
        .attr('stroke-opacity', 0.9);
      // Arrowhead at the traffic target end
      const targetNode = directionReversed ? d : f.partnerNode;
      const targetR = this._visibleRadiusOf(targetNode);
      const arrowBase = showLineArrowhead(lineG, fakeLink, color, targetR, strokeWidth);
      if (arrowBase) {
        if (directionReversed) {
          line.attr('x1', arrowBase.baseX).attr('y1', arrowBase.baseY);
        } else {
          line.attr('x2', arrowBase.baseX).attr('y2', arrowBase.baseY);
        }
      }
    }

    return { fanPartners, matchedLinks };
  }

  _clearExplodedFan() {
    if (this._centerG) this._centerG.selectAll('.exploded-fan-group').remove();
    if (this._linkSel) this._linkSel.style('display', l => (l.isMember && !l.isIntraGroup) ? 'none' : null);
  }

  // ──────────────────── Node Color ──────────────────────

  _nodeColor(nodeData) {
    if (!this._aggregated) return '#999';

    if (nodeData.isGroup) {
      // Deterministic hue from subnet string — visually distinct per /24
      let h = 0;
      for (const c of nodeData.group) h = (h * 31 + c.charCodeAt(0)) | 0;
      const hue = (h & 0xff) / 255;
      return this.d3.interpolateRainbow(hue);
    }

    // Only color nodes that are the original traffic source (matches link gradient)
    let bestAttack = null, bestCount = 0;
    for (const entry of this._aggregated.values()) {
      const origSrc = entry.origSourceIp || entry.sourceIp;
      if (origSrc === nodeData.id) {
        if (entry.count > bestCount) {
          bestCount = entry.count;
          bestAttack = entry.attackType;
        }
      }
    }
    return bestAttack ? this.colorForAttack(bestAttack) : '#999';
  }

  // ─────────────────── Grouping Helpers ───────────────────

  /**
   * Snapshot current node positions, apply a mutation to grouping state,
   * then re-render with centroid/spread starting positions.
   *
   * @param {Function} mutate – thunk that modifies _expandedGroups
   * @param {'expand'|'collapse'} direction
   * @param {{level:string, key:string, id:string}} group – the group being changed
   */
  _rebuildWithGroupChange(mutate, direction, group) {
    const before = new Map();
    if (this._nodeData) {
      for (const nd of this._nodeData) {
        before.set(nd.id, { x: nd.x + this._cx, y: nd.y + this._cy });
      }
    }

    mutate();
    this._buildDataFromAggregation();

    const startPositions = new Map();
    const groupNodeId = this._groupId(group.level, group.key);
    const anchorNodeId = this._anchorId(group.level, group.key);

    if (direction === 'expand') {
      // Super-node previously at superPos — anchor takes over that position.
      const superPos = before.get(groupNodeId);
      if (superPos) startPositions.set(anchorNodeId, { ...superPos });
    } else {
      // Collapse: super-node starts at the anchor's last position.
      const anchorPos = before.get(anchorNodeId);
      if (anchorPos) startPositions.set(groupNodeId, { ...anchorPos });
    }
    // Preserve any node position that survived the rebuild
    for (const nd of this._nodeData) {
      if (startPositions.has(nd.id)) continue;
      const prev = before.get(nd.id);
      if (prev) startPositions.set(nd.id, prev);
    }

    this.render(this._container, startPositions);
  }

  /**
   * Switch groupBy mode. Clears expanded groups and re-renders from current positions.
   */
  setGroupBy(groupBy) {
    if (groupBy === this._groupBy) return;
    if (!this._aggregated || this._aggregated.size === 0) {
      this._groupBy = groupBy;
      return;
    }

    // Snapshot current positions
    const currentPositions = new Map();
    if (this._nodeData) {
      for (const nd of this._nodeData) {
        currentPositions.set(nd.id, { x: nd.x + this._cx, y: nd.y + this._cy });
      }
    }

    this._groupBy = groupBy;
    this._levels = this._parseGroupBy(groupBy);
    this._expandedGroups.clear();

    // Build new topology to compute starting positions
    this._buildDataFromAggregation();

    if (this._levels.length > 0) {
      // New super-nodes: start at centroid of their members' last positions
      const startPositions = new Map();
      for (const nd of this._nodeData) {
        if (nd.isGroup) {
          let sx = 0, sy = 0, n = 0;
          for (const ip of nd.memberIPs) {
            const p = currentPositions.get(ip);
            if (p) { sx += p.x; sy += p.y; n++; }
          }
          if (n > 0) startPositions.set(nd.id, { x: sx / n, y: sy / n });
        } else {
          const prev = currentPositions.get(nd.id);
          if (prev) startPositions.set(nd.id, prev);
        }
      }
      this.render(this._container, startPositions);
    } else {
      // Ungrouping: individual IPs start at their super-node's last position
      const startPositions = new Map();
      for (const nd of this._nodeData) {
        const prev = currentPositions.get(nd.id);
        if (prev) {
          startPositions.set(nd.id, prev);
        }
      }
      this.render(this._container, startPositions);
    }
  }

  // ─────────────────── Update Methods ─────────────────────

  /**
   * Re-aggregate for a new time range and re-render with live simulation.
   * Preserves current node positions so transitions are smooth.
   */
  updateTimeFilter(timeRange) {
    if (!this._container) return;

    // Save current positions (convert from centered to absolute)
    const currentPositions = new Map();
    if (this._nodeData) {
      for (const nd of this._nodeData) {
        currentPositions.set(nd.id, {
          x: nd.x + this._cx,
          y: nd.y + this._cy
        });
      }
    }

    this.aggregateForTimeRange(timeRange);
    this.render(this._container, currentPositions);
  }

  /**
   * Show/hide links by attack type.
   * For aggregated links, a link is visible iff visibleSet intersects its attackTypes.
   */
  updateVisibleAttacks(visibleSet) {
    if (!this._linkSel || !this._nodeSel) return;

    this._linkSel
      .style('display', d => {
        // d.attackTypes is always a Set (set in both _buildFlatTopology and _buildCollapsedTopology)
        for (const t of d.attackTypes) {
          if (visibleSet.has(t)) return null;
        }
        return 'none';
      });

    const visibleIds = new Set();
    for (const d of this._linkData) {
      let visible = false;
      for (const t of d.attackTypes) {
        if (visibleSet.has(t)) { visible = true; break; }
      }
      if (visible) {
        visibleIds.add(d.sourceIp);
        visibleIds.add(d.targetIp);
      }
    }
    this._nodeSel
      .style('display', d => {
        if (visibleIds.has(d.id)) return null;
        // super-nodes: visible if any member appears in visible links
        if (d.isGroup && d.memberIPs) {
          return d.memberIPs.some(ip => visibleIds.has(ip)) ? null : 'none';
        }
        return 'none';
      });
  }

  /**
   * Pre-run the force simulation to completion and return final positions.
   * Call after setData() + aggregateForTimeRange().
   * @param {Map<string,{x,y}>|null} startPositions – absolute SVG coords
   * @returns {{ rawPositions: Map, visualPositions: Map }}
   *   rawPositions: centered coords + cx/cy (pass to render as startPositions)
   *   visualPositions: screen positions after autoFit (use for arc animation targets)
   */
  precalculate(startPositions) {
    const d3 = this.d3;

    const viewportH = window.innerHeight || this.height;
    const usableHeight = Math.max(400, viewportH - 160);
    this._drawWidth = this.width - this.margin.left - this.margin.right;
    this._drawHeight = usableHeight;
    this._cx = this.margin.left + this._drawWidth / 2;
    this._cy = this.margin.top + this._drawHeight / 2;

    this._buildDataFromAggregation();

    if (startPositions) {
      for (const nd of this._nodeData) {
        const sp = startPositions.get(nd.id);
        if (sp) {
          nd.x = sp.x - this._cx;
          nd.y = sp.y - this._cy;
        }
      }
    }

    // Create temporary simulation with identical forces, run to completion
    const sim = d3.forceSimulation(this._simNodeData)
      .force('link', d3.forceLink(this._simLinks).id(d => d.id)
        .distance(d => 80 + (d.source.packedRadius || 0) + (d.target.packedRadius || 0))
        .strength(0.5))
      .force('charge', d3.forceManyBody().strength(-200))
      .force('x', d3.forceX())
      .force('y', d3.forceY())
      .force('collide', d3.forceCollide(d =>
        d.isAnchor ? (d.packedRadius || 0) + 8 : this._radiusScale(d.degree) + 5))
      .stop();

    const n = Math.ceil(Math.log(sim.alphaMin()) / Math.log(1 - sim.alphaDecay()));
    for (let i = 0; i < n; ++i) sim.tick();

    // Position packed members around their final anchor positions
    this._placePackedMembers();

    // Raw positions (for render's startPositions)
    const rawPositions = new Map();
    for (const nd of this._nodeData) {
      rawPositions.set(nd.id, { x: nd.x + this._cx, y: nd.y + this._cy });
    }

    // Compute autoFit transform to get visual (on-screen) positions
    const labelPad = 80;
    let xMin = Infinity, xMax = -Infinity, yMin = Infinity, yMax = -Infinity;
    for (const d of this._nodeData) {
      if (d.isAnchor) continue;
      const r = this._radiusScale(d.degree);
      xMin = Math.min(xMin, d.x - r);
      xMax = Math.max(xMax, d.x + r + labelPad);
      yMin = Math.min(yMin, d.y - r);
      yMax = Math.max(yMax, d.y + r);
    }
    const contentW = (xMax - xMin) || 1;
    const contentH = (yMax - yMin) || 1;
    const contentCx = (xMin + xMax) / 2;
    const contentCy = (yMin + yMax) / 2;
    const scaleX = this._drawWidth / contentW;
    const scaleY = this._drawHeight / contentH;
    const scale = Math.min(scaleX, scaleY, 1.5);

    const visualPositions = new Map();
    for (const nd of this._nodeData) {
      const pos = {
        x: this._cx + scale * (nd.x - contentCx),
        y: this._cy + scale * (nd.y - contentCy)
      };
      visualPositions.set(nd.id, pos);
      // Alias member IPs to their super-node so arc transitions merge correctly
      if (nd.isGroup && nd.memberIPs) {
        for (const ip of nd.memberIPs) visualPositions.set(ip, pos);
      }
    }

    return { rawPositions, visualPositions };
  }

  /**
   * Returns node positions accounting for the autoFit scale transform,
   * i.e. where nodes actually appear on screen.
   */
  getVisualNodePositions() {
    if (!this._nodeData) return new Map();
    const s = this._fitScale || 1;
    const ccx = this._fitContentCx || 0;
    const ccy = this._fitContentCy || 0;
    const m = new Map();
    for (const nd of this._nodeData) {
      const pos = {
        x: this._cx + s * (nd.x - ccx),
        y: this._cy + s * (nd.y - ccy)
      };
      m.set(nd.id, pos);
      // Alias member IPs to their super-node so arc split animation starts correctly
      if (nd.isGroup && nd.memberIPs) {
        for (const ip of nd.memberIPs) m.set(ip, pos);
      }
    }
    return m;
  }

  getNodePositions() {
    if (!this._nodeData) return new Map();
    const m = new Map();
    for (const nd of this._nodeData) {
      m.set(nd.id, { x: nd.x + this._cx, y: nd.y + this._cy });
    }
    return m;
  }

  // ───────────────────── Cleanup ──────────────────────────

  destroy() {
    if (this._simulation) {
      this._simulation.stop();
      this._simulation = null;
    }
    if (this._container) {
      this._container.selectAll('*').remove();
    }
    this._linkSel = null;
    this._gradSel = null;
    this._nodeSel = null;
    this._centerG = null;
    this._hullG = null;
    this._nodeData = null;
    this._linkData = null;
    this._simLinks = null;
    this._aggregated = null;
  }
}
