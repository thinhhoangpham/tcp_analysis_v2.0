# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Workflow Rules
- When asked to write a plan, ONLY write the plan file. Do not attempt to implement, ask to implement, or exit plan mode. Stop after writing the file.

## Project Overview

This is a **dual-visualization network traffic analysis system** built with D3.js v7 for analyzing TCP packet data and attack patterns. It provides two complementary views:

1. **Network TimeArcs** (`attack-network.html` → `attack-network.js`) - Arc-based visualization of attack events over time with force-directed IP positioning. **Default mode: Force layout network view** (2D force-directed network graph); Timearcs Time Line View (arc-based timeline) available via radio toggle
2. **TCP Connection Analysis** (`tcp-analysis.html` → `tcp-analysis.js`) - Detailed packet-level visualization with three named UI components:
   - **Packet View** — main visualization area: stacked circles, arcs, time axis (`#chart-column`)
   - **Overview Bar chart** — stacked flow bars at bottom, brush-navigable time range (`#overview-container`)
   - **Control Panel** — floating draggable panel: IP selection, legends, view controls (`#control-panel`)

## Running the Application

This is a static HTML/JavaScript application. Serve the directory with any HTTP server:

```bash
# Python 3
python -m http.server 8000

# Node.js (npx)
npx serve .

# Then open:
# http://localhost:8000/attack-network.html  (TimeArcs view)
# http://localhost:8000/tcp-analysis.html   (TCP Analysis view)
```

The `index.html` redirects to `attack-network.html` by default.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Main Visualizations                                     │
│  attack-network.js (~2000 LOC)   - Arc network view      │
│  tcp-analysis.js (~4600 LOC)     - Packet analysis view  │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────┐
│  Supporting Modules                                      │
│  control-panel.js - Control Panel UI (drag/collapse)     │
│  sidebar.js      - IP/flow selection UI                  │
│  legends.js      - Legend rendering                      │
│  overview_chart.js - Overview Bar chart + brush nav      │
│  folder_integration.js (~1300 LOC) - Folder data coord   │
│  folder_loader.js - Chunked folder data loading          │
│  viewer_loader.js - Viewer initialization utilities      │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────┴──────────────────────────────┐
│  /src Modular System (ES6 modules)                       │
│                                                          │
│  rendering/   bars.js, circles.js, arcPath.js, rows.js   │
│               arcInteractions.js, highlightUtils.js      │
│               tooltip.js, svgSetup.js, initialRender.js  │
│  scales/      scaleFactory.js, distortion.js (fisheye)   │
│               bifocal.js (focus+context layout math)     │
│  layout/      forceSimulation.js, force_network.js       │
│               timearcs_layout.js (~1600 LOC, class)      │
│  interaction/ zoom.js, dragReorder.js, resize.js         │
│  data/        binning.js (visible packets, bar width calc) │
│               csvParser.js, flowReconstruction.js        │
│               resolution-manager.js, data-source.js      │
│               component-loader.js, csv-resolution-manager.js│
│               aggregation.js, flow-loader.js             │
│               flow-list-loader.js (lazy CSV loading)     │
│               adaptive-overview-loader.js                │
│               packet-filter.js, flow-data-handler.js     │
│  tcp/         flags.js (TCP flag classification)         │
│  groundTruth/ groundTruth.js (attack event loading)      │
│  mappings/    decoders.js, loaders.js                    │
│  workers/     packetWorkerManager.js                     │
│  plugins/     d3-fisheye.js                              │
│  search/      pattern-language.js (DSL tokenizer/parser/  │
│               compiler/matcher), pattern-presets.js,     │
│               pattern-search-engine.js,                  │
│               flow-abstractor.js, search-results.js,     │
│               pattern-ast-to-blocks.js, blocks-to-dsl.js │
│  ui/          legend.js, bifocal-handles.js              │
│               loading-indicator.js                       │
│               pattern-search-panel.js,                   │
│               pattern-builder-popup.js/.css               │
│  utils/       formatters.js, helpers.js                  │
│  config/      constants.js                               │
└──────────────────────────────────────────────────────────┘
```

### Key Data Flow

1. **CSV Input** → `csvParser.js` stream parsing OR folder-based chunked loading
2. **Packet Objects** → flow reconstruction, force layout positioning
3. **Ground Truth** → `groundTruth.js` loads attack event annotations from CSV
4. **Pre-binned Data** → Multi-resolution CSV files loaded by `csv-resolution-manager.js` (hours/minutes/seconds/100ms/10ms/1ms/raw)
5. **Resolution Management** → `resolution-manager.js` handles zoom-level data with LRU caching
6. **Rendering** → stacked bars by flag type, arcs between IPs (`initialRender.js` prepares data, `bars.js`/`circles.js` render)

**Flow Data for Overview Bar chart** (tcp-analysis.js:1703-1757):
- When IPs are selected, `updateIPFilter()` is called (async function)
- Uses adaptive multi-resolution loader (`flow_bins_index.json`) for efficient Overview Bar chart rendering
- Falls back to `flow_bins.json` or chunk loading if multi-resolution not available
- Passes filtered/aggregated data to `overview_chart.js` for categorization and binning

### Worker Pattern

`packet_worker.js` handles packet filtering off the main thread:
- Receives packets via `init` message; filters by connection keys or IPs; returns `Uint8Array` visibility mask
- Managed by `src/workers/packetWorkerManager.js`

## Configuration

- `config.js` - Centralized settings (`GLOBAL_BIN_COUNT`, batch sizes)
- `src/config/constants.js` - Colors, sizes, TCP states

### JSON Mapping Files

- `full_ip_map.json` - IP address → descriptive name
- `attack_group_mapping.json` / `attack_group_color_mapping.json` - Attack type → category → color
- `event_type_mapping.json`, `flag_colors.json`, `flow_colors.json` - Visual styling

## Data Formats

**TimeArcs CSV**: `timestamp, length, src_ip, dst_ip, protocol, count`

**TCP Analysis CSV**: `timestamp, src_ip, dst_ip, src_port, dst_port, flags, length, ...`

**Folder-based data** (v3 format - `chunked_flows_by_ip_pair`):
```
packets_data/attack_flows_day1to5/
├── manifest.json              # Dataset metadata (version 3.0, format, totals, time range)
├── flows/
│   ├── pairs_meta.json        # IP pair index with per-pair chunk metadata
│   └── by_pair/               # Flows organized by IP pair (574 pairs, 1318 chunks)
├── indices/
│   ├── bins.json              # Time bins with total packet counts
│   ├── flow_bins.json         # Pre-aggregated flows by IP pair (single resolution)
│   ├── flow_bins_index.json   # Multi-resolution index for adaptive loading
│   ├── flow_bins_1s.json / flow_bins_1min.json / flow_bins_10min.json / flow_bins_hour.json
│   └── flow_list/             # Flow summaries for flow list popup (lazy-loaded CSVs)
│       ├── index.json         # IP pair index with file references (~87KB)
│       └── *.csv              # Per-IP-pair CSV files (574 files, ~525MB total)
└── ips/
    ├── ip_stats.json / flag_stats.json / unique_ips.json
```

Legacy v2 format (`chunked_flows`) also supported; code auto-detects from `manifest.json`.

## Key Implementation Details

### Two Main Visualization Files

- `attack-network.js` (~2000 LOC) - Arc network view orchestrator (data loading, mode switching, UI wiring)
- `tcp-analysis.js` (~4600 LOC) - Detailed packet analysis with stacked bars

Both compose modules from `/src` and maintain extensive internal state (IP positions, selections, zoom state).

### TimearcsLayout Class

`src/layout/timearcs_layout.js` (~1600 LOC) encapsulates the timearcs arc visualization. Mirrors the `ForceNetworkLayout` pattern: constructor options, separate `setData()` and `render()` calls, pull-based context retrieval via callbacks.

Key responsibilities: force simulation, arc rendering (gradient by attack type), IP label layout, bifocal distortion, drag-to-brush selection, animated layout transitions.

**Loading Bar** (`tcp-analysis.html`, `tcp-analysis.css`): shown while data loads; disappears after initial render.

### Overview Bar chart

`overview_chart.js` (~1100 LOC):
- Stacked bar overview of flows by close type/invalid reason
- Brush-based time range selection synced with Packet View zoom
- Legend clicks hide/show categories and recompute bar heights (two-pass: new sharedMax, then restack)

**Legend filter behavior**: Module-level `overviewHiddenReasons` / `overviewHiddenCloseTypes` Sets persist across IP filter changes. `recomputeOverviewBars()` dispatches to `_recomputeFlows()` or `_recomputeAdaptive()`. `_applyPositions()` applies 200ms animated transitions. Both overview-local sets AND main-app sets (`hiddenInvalidReasonsRef`/`hiddenCloseTypesRef`) are considered.

**Adaptive loading**: `AdaptiveOverviewLoader` initialized from `flow_bins_index.json`. Picks resolution by visible range: 1s (≤10min), 1min (≤120min), 10min (≤7200min), hour (>7200min). Fallback: adaptive → `flow_bins.json` → chunk loading.

### Flow List CSV Files (Lazy Loading)

Per-IP-pair CSVs in `indices/flow_list/`. Only `index.json` loaded at startup. CSVs fetched on Overview Bar chart click, cached thereafter.

**Packet column format** (`fp`): `delta_ts:flags:dir,...` — delta microseconds from flow start, TCP flags bitmask, direction (1=ip1→ip2).

**When `fp` column present**: "View Packets" works without chunk files. Without `fp`: "View Packets" and "Export CSV" disabled.

Generate with: `python packets_data/generate_flow_data.py --input-dir packets_data/attack_flows_day1to5`

### Packet Data Multi-Resolution (v3.3)

| Resolution | Bin Size | Auto Threshold |
|------------|----------|----------------|
| hours | 1 hour | > 2 days |
| minutes | 1 minute | > 1 hour |
| seconds | 1 second | > 1 minute |
| 100ms | 100ms | > 10 seconds |
| 10ms | 10ms | > 1 second |
| 1ms | 1ms | > 100ms |
| raw | individual packets | ≤ 100ms |

**Resolution Selection** (`getResolutionForVisibleRange()` in `tcp-analysis.js`):
- **Auto mode**: Picks coarsest level whose threshold the visible range exceeds
- **Manual override**: Dropdown selects explicit level; zooming in auto-refines one step at a time, never goes coarser than selected
- Dropdown labels use "+" suffix (e.g., "Minutes+"). Resolution badge: blue = auto, orange = manual

### Ground Truth Integration

`src/groundTruth/groundTruth.js` loads attack annotations from `GroundTruth_UTC_naive.csv`, converts timestamps to microseconds, filters by selected IPs.

### IP Pair Layout System

**Per-IP Dynamic Row Heights** (`src/layout/ipPositioning.js`):
- Base row height: `pairCount * 32px`
- When Separate Flags on: expanded post-binning by `computeFlagSeparationHeights()` / `computeSubRowLayout()`
- `ipRowHeights` Map in state; cumulative Y positioning

**IP Pair Vertical Offsets**: Pairs within a row ordered by first-packet time. Each pair offset: `pairIndex * (subRowHeight + SUB_ROW_GAP)`.

**Sub-Row Target IP Labels** (`circles.js`): small italic `.sub-row-ip-label` text, shown only for multi-pair expanded rows. 9px monospace, `#888`, pointer-events: none.

**Row Hover Highlighting**: grey shades; highlights all bins belonging to hovered IP pair.

**IP Label Hover Styling**: Hovered=bold+black; connected=weight 500+black; non-connected=opacity 0.25.

**Row Collapse Behavior**:
- Multi-pair rows start **collapsed by default** (`defaultCollapseApplied` flag)
- `state.layout.collapsedIPs` Set tracks collapsed IPs
- Per-IP SVG toggle circles at `toggleX = -168`; **"Expand All"/"Collapse All"** sticky pill button (`#expand-all-btn`) at top of `#chart-container`
- Collapsed rows merge bins at same (time, yPos, flagType) into single circles

**Key Data Structures**:
```javascript
// ipPairOrderByRow: Map<yPos, { order: Map<ipPairKey, index>, count: number }>
// ipRowHeights: Map<ip, heightInPixels>
// collapsedIPs: Set<ip>
// subRowHeights: Map<"ip|pairKey", number>  (null when separateFlags off)
// subRowOffsets: Map<"ip|pairKey", number>  (null when separateFlags off)
// state.search.newlyAddedIPs: Set<ip>
```

**IMPORTANT — `ipPairOrderByRow` must be updated in-place**:
`renderIPRowLabels()` in `svgSetup.js` captures `ipPairOrderByRow` in mouseover closures. Replacing the Map breaks those closures. Always update in-place:
```javascript
const newOrder = computeIPPairOrderByRow(packets, ipPositions);
state.layout.ipPairOrderByRow.clear();
for (const [k, v] of newOrder) state.layout.ipPairOrderByRow.set(k, v);
```
Used at 4 sites: resolution change, drag-reorder, collapse/expand, flag separation adjustment.

### Circle View Modes (TCP Analysis)

**Separate Flags** (`#separateFlags` checkbox, `state.ui.separateFlags`):
- Groups co-located circles by `(binCenter, yPosWithOffset)`, sorts by `FLAG_PHASE_ORDER` (SYN→SYN+ACK→ACK→PSH→FIN→RST→OTHER), packs sequentially
- Post-binning pipeline: `computeFlagSeparationHeights()` → `computeSubRowLayout()` → stores in `state.layout.subRowHeights/subRowOffsets`; reset to `null` when off
- Implemented in `circles.js:174-224`, `tcp-analysis.js:409-507`
- Named "Separate Flags" in UI. Default: off.

### Link Rendering (TCP Analysis Packet View)

1. **Hover S-curves** (temporary, `circles.js`) — S-curve on mouseover showing flow direction + midpoint arrowhead; removed on mouseout. Collapsed circles (`ipPairKey === '__collapsed__'`) skip S-curve.
2. **Sub-row arcs** (`#showSubRowArcs`, `state.ui.showSubRowArcs`) — persistent low-opacity arcs per IP pair sub-row
3. **TCP Flow arcs** (`#showTcpFlows`, `state.ui.showTcpFlows`) — persistent arcs for selected flows, drawn by `drawSelectedFlowArcs()` in `tcp-analysis.js:1654-1758`

Event handlers (`handleMouseover/move/out`) are defined as named closures inside `renderCircles`, bound in **both** enter and update join paths so zoomed/panned circles always use current scales.

**Circle Hover Callbacks**: `onCircleHighlight(srcIp, dstIps)` / `onCircleClearHighlight()` wire `.highlighted`, `.connected`, `.faded` CSS classes.

**Arc Path Connections** (`arcPath.js`): `arcPathGenerator()` accepts optional `srcY`/`dstY`; hover handlers use `calculateYPosWithOffset()` for accurate sub-row positions.

### Force-Directed Layout

- **TimeArcs** (`timearcs_layout.js`): Multi-force simulation with component separation, hub attraction, y-constraints
- **Force Network** (`force_network.js`): Default view in TimeArcs. Supports `precalculate()` for pre-computing positions. On load: timearcs renders first, then auto-transitions via `transitionToForceLayout()`

**Network Mode Toggle**: Radio buttons (Timearcs / Force layout). Default: force layout. Force uses `attack_group` for color; Timearcs uses `attack`.

### Brush Selection System (attack-network.js)

Drag-to-brush selection for arc/node export to tcp-analysis:
- **`persistentSelections[]`**: Data objects `{id, timeBounds, ips, arcs, timeRange}`, survive resize
- **`multiSelectionsGroup`**: Must be reset to `null` in `render()` cleanup (after `svg.selectAll('*').remove()`) — forgetting causes selections to append to a detached DOM element
- **`computeSelectionBounds()`**: Recomputes pixel bounds from IP names using current scales (not stale pixels)
- **`redrawAllPersistentSelections()`**: Called after positions finalize and from force layout resize handler

### Box Selection System (tcp-analysis.js)

Horizontal click-drag on IP rows to select packets for CSV export:
- **Enable**: `#enableBoxSelection` (`state.ui.enableBoxSelection`). Disables pan; wheel zoom still works.
- **Collapsed mode**: full IP row; **Expanded mode**: specific sub-row + partner sub-row
- `boxSelections[]` stored as data coordinates, recomputed on zoom/resize via `redrawAllBoxSelections()`
- Export: `exportBoxSelectionCSV()` fetches raw packets via `fetchChunksForRange(start, end, 'raw')`

**SVG layering**: Overlay rect (`.box-select-overlay`, `pointer-events: all`) + selections group (`.box-selections-group`, `pointer-events: none`; `foreignObject` buttons override).

**Key functions**: `setupBoxSelectionDrag()`, `detectIPRowFromY()`, `computeSubRowBounds()`, `finalizeBoxSelection()`, `createBoxSelectionVisual()`, `redrawAllBoxSelections()`, `exportBoxSelectionCSV()`

### Pattern Search System

**Architecture** (`src/search/`):
- `pattern-language.js` — Tokenizer, parser, compiler, matcher for the DSL
- `pattern-presets.js` — Built-in presets (see `memory/MEMORY.md` for current preset table and coverage analysis)
- `pattern-search-engine.js` — Orchestrates search across `FlowListLoader` data
- `flow-abstractor.js` — Converts packet arrays to abstract event sequences (3 levels)
- `search-results.js` — Stores per-IP-pair match counts
- `pattern-search-panel.js` — Search panel UI in Control Panel
- `pattern-builder-popup.js` — Visual block-based pattern builder popup

**DSL Grammar**:
```
pattern   := sequence ('|' sequence)*
sequence  := element ('->' element)*
element   := '!'? atom quantifier?
atom      := event_name constraint? | '(' pattern ')' | '.' | '*' | '$' | '^'
quantifier := '+' | '?' | '{' min (',' max?)? '}'
constraint := '[' key op value (',' key op value)* ']'
```

Key semantics: `->` = strict adjacency; `.`/`*` = wildcard; `!SYN_ACK` = negative lookahead (zero-width); `$` = end anchor (zero-width); `^` = start anchor (zero-width). Both anchors bypass the quantifier loop in `compileElement()`.

**Abstraction Levels**: Level 1 (per-packet: flagType/dir/deltaTime), Level 2 (TCP phase groups), Level 3 (single outcome per flow).

**Flag → DSL**: `classifyFlags()` in `flags.js` → display name → `FLAG_TO_DSL` map. Key: `RST` (0x04) and `RST_ACK` (0x14) are **distinct** tokens — patterns must use `(RST | RST_ACK)` to match both.

**Match behavior**: scans all start positions, reports first match per flow only.

**"Select IPs" behavior**: additive only; newly added IPs in `state.search.newlyAddedIPs`, shown gold (`#f1c40f`). Persist until `clearPatternSearch()`, new search, or manual checkbox change.

**Important**: `.node-label` elements live in `svg` (not `mainGroup`). Use `d3.select(svg.node()).selectAll('.node-label')`.

**Pattern Builder Popup**: block-based drag-and-drop; flag palette + symbols row (`^`, `$`, `·` wildcard, `( | )` group creator). Group creator builds `(A | B)` alternation groups with 2–4 alternatives. `blocks-to-dsl.js` serializes; `pattern-ast-to-blocks.js` converts AST → blocks for preset loading.

**Count mismatch**: Level 1 pattern counts ≠ overview chart counts by design (different classification systems — packet-level adjacency vs Python state machine). See `memory/MEMORY.md` for details.

### Shared Highlight Logic

`src/rendering/highlightUtils.js`:
- `highlightHoveredLink()` / `unhighlightLinks()` — dim/highlight links
- `getLinkHighlightInfo()` — active IPs + attack color from datum (handles both arc and force-link shapes)
- `highlightEndpointLabels()` / `unhighlightEndpointLabels()` — bold/dim IP labels
- `showArcArrowhead()` / `showLineArrowhead()` / `removeArrowheads()` — mouseover-only directional arrowheads

### Control Panel

`control-panel.js`: `position: fixed` aside, drag-to-move, click title bar to collapse.
- **Zoom controls bar**: `position: absolute; bottom: 100%` — stays visible when collapsed, moves with panel
- Uses `overflow: visible` so zoom bar isn't clipped

### Fisheye Distortion

`src/plugins/d3-fisheye.js` wrapped by `src/scales/distortion.js`. Controlled by "Lensing" toggle and zoom slider.

### Performance Optimizations

- Binning (millions of packets → thousands of bins)
- Web Worker for off-main-thread packet filtering
- LRU cache for detail chunk loading (`resolution-manager.js`)
- Multi-resolution loading (coarse overview → fine detail)
- IP-pair organization (v3): load only selected pair chunks
- Lazy flow list loading: CSVs fetched only on Overview Bar chart click

## Module Dependencies

Main files import from `/src`:
- **Rendering**: `bars.js`, `circles.js`, `arcPath.js`, `rows.js`, `tooltip.js`, `arcInteractions.js`, `highlightUtils.js`, `svgSetup.js`
- **Data**: `binning.js`, `flowReconstruction.js`, `csvParser.js`, `aggregation.js`, `resolution-manager.js`, `csv-resolution-manager.js`, `data-source.js`, `component-loader.js`, `initialRender.js`
- **Layout**: `forceSimulation.js`, `force_network.js`, `timearcs_layout.js`
- **Interaction**: `zoom.js`, `arcInteractions.js`, `dragReorder.js`, `resize.js`
- **Scales**: `scaleFactory.js`, `distortion.js`, `bifocal.js`
- **Ground Truth**: `groundTruth.js`
- **Utils**: `formatters.js`, `helpers.js`
- **UI**: `legend.js`, `bifocal-handles.js`, `loading-indicator.js`, `pattern-search-panel.js`, `pattern-builder-popup.js`
- **Search**: `pattern-language.js`, `pattern-search-engine.js`, `pattern-presets.js`, `flow-abstractor.js`, `search-results.js`
- **Config**: `constants.js`

## Original TimeArcs Source

The `timearcs_source/` directory contains the original TimeArcs implementation for political blog analysis (unrelated to this project).
