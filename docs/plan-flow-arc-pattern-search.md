# Plan: Flow Arc Pattern Search for attack-network.js

## Overview

Temporal pattern matching over flow close-type arc data in attack-network.js. Matches behavioral sequences (e.g., `GRACEFUL+ -> RST_HANDSHAKE+`) across IP pair timelines to reveal attack natures. Built on the existing DSL engine with a new Level 4 abstraction.

## Architecture Decision

**Level 4 "Close Type Sequence" abstraction** operating on pre-aggregated `_linksWithNodes` already in memory. Zero CSV loading, zero Web Worker involvement, runs synchronously in <50ms for typical datasets (~500 pairs x ~90 bins).

Reuses `parsePattern()`, `compilePattern()`, and `matchPattern()` from existing DSL engine verbatim. Only `matchesEventName()` and `getEventAttribute()` need a Level 4 branch.

## New Files

### `src/search/flow-arc-abstractor.js`

Transforms `_linksWithNodes` into Level 4 phase sequences per IP pair.

**Pipeline:**
1. Group links by canonical pair key `min(src,tgt)<->max(src,tgt)`
2. Sort each pair's bins by minute
3. Collapse consecutive same-closeType bins into phases
4. Apply noise tolerance: absorb minority bins where `count < noiseRatio * neighborAvg`
5. Assign `volumeLabel` (high/medium/low) using pre-computed percentiles

**Exports:**
```javascript
export function buildPairPhaseMap(linksWithNodes, options = {})
// returns Map<pairKey, { src, tgt, phases: [Level4Event], rawBins }>

export function abstractPairToLevel4(phases, percentiles)
// returns [{closeType, minuteStart, minuteEnd, totalCount, binCount, ratio, volumeLabel}]

export function computeVolumePercentiles(linksWithNodes)
// returns { p25, p50, p75, p90 }
```

**Level 4 Event shape:**
```javascript
{
    closeType: 'RST_HANDSHAKE',  // discriminator for matchesEventName()
    minuteStart: 14,
    minuteEnd: 16,
    totalCount: 297,
    binCount: 2,
    ratio: 0.94,                 // fraction of bins dominated by this type
    volumeLabel: 'high'          // percentile-based: 'high'|'medium'|'low'
}
```

**Noise tolerance algorithm (`_collapsePhases`):**
1. First pass: group consecutive bins with same `attack` (close_type) into raw phases
2. Second pass: for each run of 1-2 bins surrounded by larger runs of a different type, check if minority bin's `count < noiseRatio * avg(neighborCounts)`. If so, absorb into preceding phase
3. Merge adjacent same-type phases after absorption
4. Cap at 3 passes to prevent infinite loop. Default `noiseRatio = 0.1`

### `src/search/flow-arc-search-engine.js`

Orchestrates matching of compiled DSL patterns against all pair phase sequences.

```javascript
export class FlowArcSearchEngine {
    constructor({ getLinksWithNodes }) { ... }

    search(patternString, options = {})
    // options: { scope: 'all'|'selected', selectedIPs: Set, withinMinutes: number|null }
    // returns FlowArcSearchResults

    evaluateFanPattern(type, closeType, threshold, withinMinutes)
    // type: 'fan_in'|'fan_out'
    // returns FlowArcSearchResults
}

export class FlowArcSearchResults {
    matchedPairKeys     // Set<string>
    matchedLinks        // link objects in matched regions
    matchedTimeRanges   // Map<pairKey, [{minuteStart, minuteEnd}]>
    totalSearched       // number
    totalMatched        // number
    searchTimeMs        // number
    error               // string|null
    patternString       // string
}
```

**`within(Nm)` post-filter:** For each matched region, compute `phases[end-1].minuteEnd - phases[start].minuteStart`. Discard if > `withinMinutes`.

**Fan pattern evaluation (bypasses DSL):**
- `fan_in`: Group by target IP → count distinct source IPs with matching close_type → targets exceeding threshold match
- `fan_out`: Group by source IP → count distinct target IPs with matching close_type → sources exceeding threshold match

### `src/search/flow-arc-presets.js`

Kill-chain organized preset library.

```javascript
export const CLOSE_TYPE_TOKENS = {
    'graceful':              'GRACEFUL',
    'abortive':              'ABORTIVE',
    'rst_during_handshake':  'RST_HANDSHAKE',
    'incomplete_no_synack':  'INCOMPLETE',
    'incomplete_no_ack':     'INCOMPLETE_ACK',
    'invalid_ack':           'INVALID_ACK',
    'invalid_synack':        'INVALID_SYNACK',
    'unknown_invalid':       'UNKNOWN',
};
```

**Presets by kill chain phase:**

| Phase | ID | Pattern | Description |
|-------|------|---------|-------------|
| Recon | recon_scan | `INCOMPLETE{3,}` | Port scan / host discovery |
| Recon | recon_rst_flood | `RST_HANDSHAKE{3,}` | Active probing |
| Delivery | delivery_probe_then_connect | `INCOMPLETE+ -> GRACEFUL` (within 10m) | Scan found open port |
| Delivery | delivery_invalid_then_connect | `(RST_HANDSHAKE \| INCOMPLETE \| INCOMPLETE_ACK)+ -> GRACEFUL+` | Failed attempts → success |
| Exploitation | exploit_graceful_to_rst | `GRACEFUL+ -> RST_HANDSHAKE+` (within 5m) | Session disruption |
| Exploitation | exploit_abortive_burst | `ABORTIVE{3,}` | Connection failures |
| Impact | ddos_incomplete_flood | `INCOMPLETE[volume=high]+` | SYN flood |
| Impact | ddos_unknown_flood | `UNKNOWN{2,}` | Anomalous traffic |
| Recovery | recovery_rst_to_graceful | `(RST_HANDSHAKE \| INCOMPLETE)+ -> GRACEFUL+` | Attack subsiding |
| Recovery | recovery_abortive_to_graceful | `ABORTIVE+ -> GRACEFUL{2,}` | Failures → success |
| Fan | fan_in_ddos | fan_in, incomplete_no_synack, sources>5 | DDoS target detection |
| Fan | fan_out_scan | fan_out, incomplete_no_synack, targets>5 | Port scan source detection |

### `src/ui/flow-arc-search-panel.js`

Floating panel UI for flow mode, follows same pattern as `#legendPanel`.

```javascript
export function initFlowArcSearchPanel(options)
// options: { onSearch, onClear, onFanSearch }

export function showFlowArcSearchResults(results, colorForAttack)
export function clearFlowArcSearchResults()
export function showFlowArcSearchProgress(label)
export function hideFlowArcSearchProgress()
```

**Panel sections:**
1. Pattern input textarea + Run button
2. Preset grid organized by kill-chain phase (color-coded headers)
3. Fan pattern sub-panel (type dropdown, close_type dropdown, threshold input)
4. `within(Nm)` time window control
5. Results summary (matched/total pairs, pair list)
6. Clear button

**Position:** `fixed; top: 80px; left: 16px; width: 280px; max-height: 70vh; z-index: 1000`. No overlap with `#legendPanel` (bottom-right).

**Token coloring:** Preset DSL patterns displayed in monospace with tokens colored via `flowColorMap` (GRACEFUL=green, RST_HANDSHAKE=purple, INCOMPLETE=orange, etc.).

## Existing Files to Modify

### `src/search/pattern-language.js`

**`matchesEventName()` (~line 490):** Add Level 4 branch:
```javascript
if (event.closeType !== undefined) return event.closeType === name;
```

**`getEventAttribute()` (~line 516):** Add Level 4 block:
```javascript
if (event.closeType !== undefined) {
    switch (key) {
        case 'ratio':    return event.ratio;
        case 'volume':   return event.volumeLabel;
        case 'count':    return event.totalCount;
        case 'bins':     return event.binCount;
        case 'dur':
        case 'duration': return event.minuteEnd - event.minuteStart;
    }
}
```

**`compilePattern()` (~line 596):** Add `level === 4` case delegating to `compileNode()` (same as Level 1/2).

### `src/layout/timearcs_layout.js`

**Constructor:** Add `getFlowArcSearchState` option (optional callback, defaults to `() => null`).

**New public method `applyFlowArcSearchHighlight(results)`:**
- Dim unmatched arcs to 8% opacity, raise matched to 85%
- Bold IP labels for matched pairs, fade others to 30%
- Draw colored bands on time axis for matched time ranges (4px rects at y=31, opacity 0.3)
- Store `_flowArcSearchActive` and `_flowArcSearchMatchedKeys` for hover-leave restoration

**New public method `clearFlowArcSearchHighlight()`:**
- Restore all arcs to default 60% opacity
- Remove `.flow-arc-match-band` rects
- Reset IP label styling
- Clear `_flowArcSearchActive`

**Pass `getFlowArcSearchState` to `createArcLeaveHandler`** at the call site (~line 626).

### `src/rendering/arcInteractions.js`

**`createArcLeaveHandler`:** Add `getSearchHighlightState` to config. On leave, if search active, restore matched/unmatched opacity instead of default 60%:
```javascript
const searchState = config.getSearchHighlightState?.();
if (searchState?.active) {
    arcPaths.style('stroke-opacity', d => {
        const pk = _pairKey(d.sourceIp || d.sourceNode?.name, d.targetIp || d.targetNode?.name);
        return searchState.matchedPairKeys.has(pk) ? 0.85 : 0.08;
    });
} else {
    unhighlightLinks(arcPaths, widthScale);
}
```

### `src/config/constants.js`

Add three constants:
```javascript
export const FLOW_ARC_SEARCH_MATCH_OPACITY = 0.85;
export const FLOW_ARC_SEARCH_DIM_OPACITY = 0.08;
export const FLOW_ARC_SEARCH_BAND_OPACITY = 0.3;
```

### `attack-network.html`

Add after `#legendPanel`:
```html
<div id="flowArcSearchPanel" style="display:none;" class="legend-panel flow-arc-search-panel"></div>
```

### `attack-network.js`

**Imports:** `flow-arc-search-panel.js`, `flow-arc-search-engine.js`

**State:**
```javascript
let flowArcSearchEngine = null;
let flowArcSearchResults = null;
let flowArcSearchPanelInit = false;
```

**`getFlowArcSearchState()`:** Returns `{ active, matchedPairKeys }` or null.

**Pass `getFlowArcSearchState`** into `TimearcsLayout` constructor.

**`_initFlowArcSearchPanel()`:** Creates engine, wires `onSearch`/`onFanSearch`/`onClear` callbacks. Called on first flow-mode render completion.

**`switchDataMode()`:** Reset search state, hide panel when leaving flow mode.

**`render()` completion:** Re-apply highlight if `flowArcSearchResults` exists (handles legend toggle re-renders).

## Data Flow

```
[_linksWithNodes] (in-memory, set during render)
        |
        v
[flow-arc-abstractor: buildPairPhaseMap()]
  Group by pair → sort by minute → collapse phases → noise tolerance → volume labels
        |
        v  Map<pairKey, { phases: [Level4Event] }>
[flow-arc-search-engine: search()]
  parsePattern() → compilePattern(level=4) → matchPattern() per pair → within() filter
        |
        v  FlowArcSearchResults
        |
   +----+----+
   |         |
   v         v
[TimearcsLayout:           [flow-arc-search-panel:
 applyFlowArcSearch-        showFlowArcSearchResults()]
 Highlight()]               Match count, pair list
 Dim/highlight arcs
 Bold IP labels
 Time axis bands
```

## Build Sequence

- [ ] **Phase 1.1** — Patch `pattern-language.js`: Level 4 in `matchesEventName`, `getEventAttribute`, `compilePattern`
- [ ] **Phase 1.2** — Create `flow-arc-abstractor.js`: `buildPairPhaseMap`, `abstractPairToLevel4`, `computeVolumePercentiles`
- [ ] **Phase 1.3** — Create `flow-arc-presets.js`: vocabulary maps + all presets
- [ ] **Phase 2.1** — Create `flow-arc-search-engine.js`: `FlowArcSearchEngine` + `FlowArcSearchResults`
- [ ] **Phase 3.1** — Patch `arcInteractions.js`: search-aware leave handler
- [ ] **Phase 3.2** — Patch `timearcs_layout.js`: constructor option + two public methods
- [ ] **Phase 3.3** — Patch `constants.js`: three opacity constants
- [ ] **Phase 4.1** — Create `flow-arc-search-panel.js`: full panel UI
- [ ] **Phase 4.2** — Patch `attack-network.html`: panel anchor div
- [ ] **Phase 4.3** — Patch `attack-network.js`: imports, state, panel lifecycle, highlight re-apply

## Performance

For default 90-minute dataset (~9,000 flow-mode links, ~500 pairs):
- `buildPairPhaseMap()`: <10ms
- `search()` with compilation + matching all pairs: <50ms
- No async decomposition needed — fully synchronous

## Future Layers (not in this plan)

**Layer 2 — Cross-Pair Aggregate:** `fan_in`/`fan_out` patterns evaluating across multiple pairs. Foundation implemented here via `evaluateFanPattern()` in the engine; full DSL syntax extension deferred.

**Layer 3 — Regime Change Detection:** Automatic change-point detection via chi-squared/KL-divergence on sliding window close-type distributions. No user pattern needed. Annotates timeline with transition markers. Separate feature.
