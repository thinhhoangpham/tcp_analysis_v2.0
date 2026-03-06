# TCP Flow Pattern Search — Implementation Plan

## Context

The TCP Analysis visualization currently shows packet-level and flow-level data but has no way to **search for structural patterns** across flows. Inspired by the EventPad paper (Cappers & van Wijk, IEEE TVCG 2018), this feature adds a **rule-based pattern search** system that abstracts raw TCP packets into higher-level phases, then matches user-defined sequential patterns against flows.

**Problem**: An analyst investigating a 5-day network capture with 5.4M flows and 574 IP pairs currently has no way to ask "show me all flows that completed a handshake but had no data transfer" or "find IP pairs where RST floods occur during handshakes." They must manually inspect flows.

**Solution**: A multi-level abstraction + pattern matching engine with a text DSL, preset patterns, and visual highlighting of matches in the Packet View.

---

## Design Decisions

| Decision | Choice |
|----------|--------|
| Input method | Text DSL with autocomplete + preset dropdown |
| Search scope | Toggle: "Selected IPs" (fast) or "All IPs" (discovery via flow_bins) |
| Output display | Highlight matched circles in Packet View + results summary in Control Panel |
| MVP scope | All 3 abstraction levels (Outcome, Phase, Packet) |

---

## Architecture

### Multi-Level Abstraction Hierarchy

| Level | Name | Events | Data Source | Speed |
|-------|------|--------|-------------|-------|
| 3 | Outcome | `COMPLETE_GRACEFUL`, `COMPLETE_ABORTED`, `ONGOING`, `RST_HANDSHAKE`, `INVALID_ACK`, `INVALID_SYNACK`, `NO_SYNACK`, `NO_ACK`, `UNKNOWN_INVALID` | Flow metadata / flow_bins | Instant |
| 2 | Phase | `HANDSHAKE`, `DATA`, `FIN_CLOSE`, `RST_CLOSE` | Embedded packets from CSV | Progressive |
| 1 | Packet | `SYN`, `SYN_ACK`, `ACK`, `PSH_ACK`, `FIN`, `FIN_ACK`, `RST`, `RST_ACK`, `OTHER` | Embedded packets from CSV | Progressive |

Level 3 maps directly to existing `closeType`/`invalidReason` fields. Levels 2 and 1 require `_embeddedPackets` from `FlowListLoader` CSV files.

### Abstraction Logic

**Level 2 (Phase)**: Group consecutive packets by `flagPhase()` result. Collapse each contiguous run into one phase event:
```
Packets: SYN, SYN+ACK, ACK, PSH+ACK, PSH+ACK, PSH+ACK, FIN, FIN+ACK, ACK
Phases:  HANDSHAKE(3pkts), DATA(3pkts), FIN_CLOSE(3pkts)
```
Split `closing` phase into `FIN_CLOSE` vs `RST_CLOSE` based on whether the phase contains RST flags.

**Level 1 (Packet)**: Map each packet through `classifyFlags()`. Use underscore notation (`SYN_ACK` instead of `SYN+ACK`) in the DSL for parser safety. Add `dir` (out/in relative to initiator) and `dt` (delta time from previous packet) as queryable attributes.

### Search Scope Strategy

- **"Selected IPs" mode**: Search `state.flows.current` (Level 3) or load CSVs for selected IP pairs only (Level 2/1)
- **"All IPs" mode**:
  - Level 3: Scan `flow_bins` data from `AdaptiveOverviewLoader` — already loaded, contains close type counts per IP pair for ALL 574 pairs. No CSV loading needed.
  - Level 2/1: Load CSVs pair-by-pair via `FlowListLoader._loadPairFlows()`, progressively. Show progress bar. Support cancellation.
- Results include a **"Select matched IPs"** button so users can drill from all-IP discovery into selected-IP deep analysis.

---

## Pattern Language

### Grammar
```
pattern      := disjunction
disjunction  := sequence ('|' sequence)*
sequence     := element (('->' | '→') element)*
element      := negation quantifier?
negation     := '!' atom | atom
atom         := event_name constraint? | '(' pattern ')' | wildcard
wildcard     := '*' | '.'
quantifier   := '+' | '?' | '{' NUMBER (',' NUMBER?)? '}'
constraint   := '[' condition (',' condition)* ']'
condition    := IDENT operator value
operator     := '=' | '!=' | '<' | '>' | '<=' | '>='
value        := NUMBER unit? | STRING
unit         := 'us' | 'ms' | 's' | 'min'
event_name   := IDENT ('_' IDENT)*
```

### Examples
```
# Level 3
COMPLETE_GRACEFUL                     # All graceful closes
RST_HANDSHAKE | NO_SYNACK            # Failed handshakes (any kind)
COMPLETE_GRACEFUL[packets<5]          # Very short graceful flows

# Level 2
HANDSHAKE -> DATA+ -> FIN_CLOSE       # Normal TCP lifecycle
HANDSHAKE -> RST_CLOSE                # Port scan pattern (no data)
HANDSHAKE -> DATA[dur>60s] -> *       # Long data sessions

# Level 1
SYN[dir=out] -> SYN_ACK[dir=in,dt<50ms] -> ACK[dir=out]   # Fast handshake
SYN[dir=out] -> !SYN_ACK                                    # SYN without response
RST{3,}                                                      # RST flood (3+ consecutive)
```

### Constraint Attributes
- **Level 1**: `dir` (out|in), `dt` (time delta: `<100ms`), `flags` (raw bitmask)
- **Level 2**: `count` (packet count), `dur` (duration), `bytes` (byte count)
- **Level 3**: `packets` (total), `dur` (flow duration), `bytes` (total)

---

## New Files

### `src/search/flow-abstractor.js` (~250 LOC)
Transforms flows into abstract event sequences at each level.

Key exports:
- `abstractToLevel3(flow)` → `{ outcome: string }` — maps `closeType`/`invalidReason` to outcome enum
- `abstractToLevel2(packets)` → `[{ phase, packetCount, duration, hasRst }]` — groups consecutive packets by `flagPhase()`, splits closing into FIN_CLOSE/RST_CLOSE
- `abstractToLevel1(packets)` → `[{ flagType, dir, deltaTime }]` — maps each packet via `classifyFlags()`, adds direction + timing

Reuses: `classifyFlags()` and `flagPhase()` from `src/tcp/flags.js`

### `src/search/pattern-language.js` (~500 LOC)
Parser, compiler, and matcher for the pattern DSL.

Key exports:
- `parsePattern(patternString, level)` → AST
- `compilePattern(ast)` → `MatcherFunction`
- `matchPattern(matcher, abstractedSequence)` → `{ matched: boolean, matchedRegions: [{start, end}] }`
- `validatePattern(patternString, level)` → `{ valid: boolean, error?: string, position?: number }`

Compilation strategy:
- Level 3 patterns compile to predicate functions (each flow = one event, `|` = OR)
- Level 2/1 patterns compile to sequence matchers that walk through event arrays consuming elements based on quantifiers. `!` creates a negative lookahead. `*`/`.` matches any single event.

### `src/search/pattern-presets.js` (~120 LOC)
Built-in pattern library organized by level.

```javascript
export const PATTERN_PRESETS = {
  outcome: [
    { id: 'failed_handshake', label: 'Failed Handshakes', level: 3,
      pattern: 'RST_HANDSHAKE | NO_SYNACK | NO_ACK' },
    { id: 'graceful', label: 'Graceful Closes', level: 3, pattern: 'COMPLETE_GRACEFUL' },
    { id: 'aborted', label: 'Aborted Connections', level: 3, pattern: 'COMPLETE_ABORTED' },
    ...
  ],
  phase: [
    { id: 'normal_flow', label: 'Normal TCP Flow', level: 2,
      pattern: 'HANDSHAKE -> DATA+ -> FIN_CLOSE' },
    { id: 'scan_pattern', label: 'Port Scan (no data)', level: 2,
      pattern: 'HANDSHAKE -> RST_CLOSE' },
    ...
  ],
  packet: [
    { id: 'syn_no_response', label: 'SYN without SYN+ACK', level: 1,
      pattern: 'SYN[dir=out] -> !SYN_ACK' },
    { id: 'rst_flood', label: 'RST Flood (3+)', level: 1, pattern: 'RST{3,}' },
    ...
  ]
};
```

### `src/search/pattern-search-engine.js` (~400 LOC)
Search orchestrator tying together data access, abstraction, and matching.

```javascript
export class PatternSearchEngine {
  constructor({ getState, getFlowListLoader, getAdaptiveLoader, onProgress, onResults })

  async search(patternString, level, scope)  // scope: 'selected' | 'all'
  cancel()

  // Internal paths:
  _searchLevel3Selected(matcher)      // Scans state.flows.current
  _searchLevel3All(matcher)           // Scans flow_bins from AdaptiveOverviewLoader
  async _searchWithPackets(matcher, level, ipPairs)  // Pair-by-pair CSV loading
}
```

Level 3 "All IPs" path: iterate `flow_bins` entries, check each IP pair's close type counts against the pattern. This scans pre-loaded data — no network requests.

Level 2/1 path: for each relevant IP pair, call `FlowListLoader._loadPairFlows()` (respects cache), abstract each flow's packets, run matcher. Report progress after each pair.

### `src/search/search-results.js` (~200 LOC)
Results data model.

```javascript
export class SearchResults {
  matchedFlowIds: Set<number>
  matchedFlows: Array                    // Flow objects (or summaries for Level 3 all-IP)
  matchedIpPairs: Map<pairKey, count>    // IP pair → match count
  byTimeBin: Map<binIndex, count>        // For time distribution
  byOutcome: Map<closeType, count>       // For breakdown
  totalSearched: number
  totalMatches: number
  searchTimeMs: number

  addMatch(flow, matchRegions)
  getSummary() → string
  getMatchedIPs() → string[]            // For "Select matched IPs" button
}
```

### `src/ui/pattern-search-panel.js` (~300 LOC)
UI creation and wiring for the search section in the Control Panel.

Key exports:
- `initPatternSearchUI(containerEl, options)` — creates DOM, wires events, populates presets
- `updatePresets(level)` — swaps preset dropdown options when level changes
- `showSearchProgress(pct, label)` / `hideSearchProgress()`
- `showSearchResults(results)` — renders summary + "View Details" + "Select matched IPs"
- `clearSearchResults()`

Autocomplete: as user types in the pattern input, show a dropdown of valid event names for the current level. Use a simple `<datalist>` or custom dropdown positioned below input.

---

## Modified Files

### `tcp-analysis.html`
Add new collapsible control-group section in the Control Panel (after "Ground Truth Events", before the closing `</div>` of `#controls-body`):

```html
<div class="control-group collapsible collapsed" id="patternSearchGroup">
  <label class="collapsible-header">
    <span>Flow Pattern Search</span>
    <span class="collapse-icon">&#x25BC;</span>
  </label>
  <div class="collapsible-body">
    <div id="patternSearchContainer"></div>
  </div>
</div>
```

The `#patternSearchContainer` is populated by `initPatternSearchUI()` from `pattern-search-panel.js`. This keeps HTML minimal and logic in JS.

### `tcp-analysis.css` (~40 lines)
- `.search-match-highlight` — gold ring/glow on matched flow circles (`stroke: #f1c40f; stroke-width: 2px; filter: drop-shadow(0 0 3px rgba(241, 196, 15, 0.6))`)
- `.search-match-dimmed` — reduced opacity for non-matching circles when filter active (`.circle-group:not(.search-match-highlight) { opacity: 0.15; }`)
- `#patternSearchContainer` — internal layout styles
- `.pattern-input` — monospace font, validation border colors
- `.search-progress` — progress bar styling
- `.search-results-summary` — results box styling

### `tcp-analysis.js` — 5 integration points

**1. State addition** (near line 270, after `flows`):
```javascript
search: {
  active: false,
  engine: null,
  results: null,
  level: 3,
  scope: 'selected',
  filterActive: false   // when true, dim non-matching circles
}
```

**2. Imports** (top of file):
```javascript
import { PatternSearchEngine } from './src/search/pattern-search-engine.js';
import { initPatternSearchUI } from './src/ui/pattern-search-panel.js';
```

**3. Engine initialization** (after control panel wiring, ~line 1040):
```javascript
state.search.engine = new PatternSearchEngine({
  getState: () => state,
  getFlowListLoader: () => flowListLoader,
  getAdaptiveLoader: () => adaptiveOverviewLoader,
  onProgress: (pct, label) => showSearchProgress(pct, label),
  onResults: (results) => applySearchResults(results)
});

initPatternSearchUI(document.getElementById('patternSearchContainer'), {
  onSearch: async (pattern, level, scope) => { ... },
  onClear: () => { clearSearchResults(); },
  onFilterToggle: (active) => { state.search.filterActive = active; reRenderCircles(); },
  onSelectMatchedIPs: (ips) => { /* programmatically select these IPs */ }
});
```

**4. Circle rendering integration** — modify `renderCircles()` call site to apply highlight classes:
After circles are rendered, if `state.search.active && state.search.results`:
- Add `.search-match-highlight` class to circles whose flow matches
- If `state.search.filterActive`, add `.search-match-dimmed` to non-matching circles
- Matching is checked via `state.search.results.matchedFlowIds.has(d.flowId)` or by checking if the circle's `(src_ip, dst_ip, ipPairKey)` belongs to a matched IP pair (for Level 3 all-IP results that don't have individual flow IDs)

**5. IP selection sync** — when "Select matched IPs" is clicked:
- Extract unique IPs from `results.getMatchedIPs()`
- Programmatically check those IPs in the sidebar checkbox list
- Trigger `updateIPFilter()` to refresh the visualization

### `control-panel.js`
Add collapsible toggle wiring for `#patternSearchGroup` in `initControlPanel()` (follows existing pattern at line 72-76).

### `src/tcp/flags.js` — Add abstraction constants (after line 132)
```javascript
export const TCP_PHASES = { HANDSHAKE: 'HANDSHAKE', DATA: 'DATA', FIN_CLOSE: 'FIN_CLOSE', RST_CLOSE: 'RST_CLOSE' };

export const FLOW_OUTCOMES = {
  COMPLETE_GRACEFUL: 'COMPLETE_GRACEFUL', COMPLETE_ABORTED: 'COMPLETE_ABORTED',
  ONGOING: 'ONGOING', RST_HANDSHAKE: 'RST_HANDSHAKE', INVALID_ACK: 'INVALID_ACK',
  INVALID_SYNACK: 'INVALID_SYNACK', NO_SYNACK: 'NO_SYNACK', NO_ACK: 'NO_ACK',
  UNKNOWN_INVALID: 'UNKNOWN_INVALID'
};

export function flowToOutcome(flow) {
  if (flow.closeType === 'graceful') return FLOW_OUTCOMES.COMPLETE_GRACEFUL;
  if (flow.closeType === 'abortive') return FLOW_OUTCOMES.COMPLETE_ABORTED;
  if (flow.closeType === 'ongoing')  return FLOW_OUTCOMES.ONGOING;
  const map = { rst_during_handshake: 'RST_HANDSHAKE', invalid_ack: 'INVALID_ACK',
    invalid_synack: 'INVALID_SYNACK', incomplete_no_synack: 'NO_SYNACK',
    incomplete_no_ack: 'NO_ACK', unknown_invalid: 'UNKNOWN_INVALID' };
  return FLOW_OUTCOMES[map[flow.invalidReason]] || FLOW_OUTCOMES.UNKNOWN_INVALID;
}
```

---

## Data Flow

```
User Input (preset/text + level + scope)
         │
         ▼
┌─ pattern-language.js ──────────┐
│  tokenize → parse → compile    │
│  → MatcherFunction             │
└────────────┬───────────────────┘
             │
             ▼
┌─ pattern-search-engine.js ─────────────────────────────┐
│                                                         │
│  Level 3 + "Selected"  →  scan state.flows.current      │
│  Level 3 + "All IPs"   →  scan flow_bins (pre-loaded)   │
│  Level 2/1 + "Selected" → load CSVs for selected pairs  │
│  Level 2/1 + "All IPs"  → load CSVs pair-by-pair (prog) │
│                                                         │
│  For each flow:                                         │
│    flow-abstractor.js → abstract to level                │
│    matchPattern(matcher, abstracted) → match result      │
│    if matched → results.addMatch(flow)                   │
│                                                         │
│  onProgress(pct) → update progress bar                   │
│  onResults(results) → apply to visualization             │
└────────────────────────────────┬────────────────────────┘
                                 │
                                 ▼
┌─ tcp-analysis.js ──────────────────────────────────────┐
│  applySearchResults(results):                           │
│    state.search.results = results                       │
│    state.search.active = true                           │
│    Re-render circles with highlight classes              │
│    Show results summary in Control Panel                 │
│    If filter active: dim non-matching circles            │
└─────────────────────────────────────────────────────────┘
```

---

## UI Layout (in Control Panel)

```
┌─ Flow Pattern Search ──────────────── ▼ ─┐
│                                           │
│  Level: (o) Outcome  ( ) Phase  ( ) Pkt   │
│  Scope: (o) Selected IPs  ( ) All IPs     │
│                                           │
│  Preset: [-- Select preset --        ▼]   │
│  Pattern: [HANDSHAKE -> DATA+ -> ...   ]  │
│  hint: Use -> for sequence, + for 1+      │
│                                           │
│  [  Search  ]  [ Clear ]                  │
│                                           │
│  ┌─ Results ────────────────────────┐     │
│  │  1,523 / 5,482 flows matched     │     │
│  │  12 IP pairs · 42ms              │     │
│  │  [View Flows]  [Select IPs]      │     │
│  └──────────────────────────────────┘     │
│                                           │
│  [x] Highlight matches only               │
│                                           │
└───────────────────────────────────────────┘
```

"View Flows" opens the existing flow list modal (`createFlowListCapped`) with matched flows.
"Select IPs" programmatically selects matched IP addresses in the sidebar.

---

## Implementation Phases

Each phase delivers a **complete, end-to-end testable feature**. After each phase, the user can open `tcp-analysis.html`, interact with the search UI, and see results.

---

### Phase 1: Level 1 Packet Pattern Search (foundation + end-to-end)

**Goal**: Build the full pattern matching engine at the most granular level — individual packet flag sequences with direction/timing constraints, negation, sequence operators. This phase creates ALL new files, the full UI, and the complete search pipeline. Levels 2 and 3 build on this foundation.

**New files created**:
| File | LOC | Purpose |
|------|-----|---------|
| `src/tcp/flags.js` (extend) | +30 | `FLOW_OUTCOMES`, `TCP_PHASES`, `flowToOutcome()` constants |
| `src/search/flow-abstractor.js` | ~100 | `abstractToLevel1(packets)` — maps each packet via `classifyFlags()`, adds `dir`, `dt` |
| `src/search/pattern-language.js` | ~500 | **Full** pattern language: tokenizer, parser, compiler, matcher. All operators: `\|`, `->`, `+`, `?`, `{n,m}`, `!`, `.`/`*`, `()`, `[constraints]` |
| `src/search/pattern-presets.js` | ~50 | Level 1 presets (SYN no response, RST flood, fast handshake, triple ACK, etc.) |
| `src/search/pattern-search-engine.js` | ~300 | Search engine with `_searchWithPackets()` — pair-by-pair CSV loading via `FlowListLoader._loadPairFlows()`, progress reporting, cancellation |
| `src/search/search-results.js` | ~150 | `SearchResults` class with matched IDs, IP pair counts, summary |
| `src/ui/pattern-search-panel.js` | ~300 | Full UI: level radios (only Packet enabled), scope radios, preset dropdown, text input with autocomplete, search/clear/cancel buttons, progress bar, results summary, "View Flows", "Select matched IPs", highlight toggle |

**Modified files**:
| File | Changes |
|------|---------|
| `tcp-analysis.html` | Add `#patternSearchGroup` collapsible section + `#patternSearchContainer` |
| `tcp-analysis.css` | Add `.search-match-highlight`, `.search-match-dimmed`, `.pattern-input`, `.search-results-summary`, `.search-progress` styles |
| `tcp-analysis.js` | Add `state.search`, imports, engine init, wire `initPatternSearchUI()`, `applySearchResults()`, circle highlight integration, cancel wiring |
| `control-panel.js` | Add collapsible wiring for `#patternSearchGroup` |

**What works after Phase 1**:
- Open app → expand "Flow Pattern Search" in Control Panel
- Level radio on "Packet" (Phase/Outcome radios visible but disabled)
- Pick preset "SYN without SYN+ACK" → fills pattern input with `SYN[dir=out] -> !SYN_ACK`
- Or type custom: `SYN[dir=out] -> SYN_ACK[dir=in,dt<50ms] -> ACK[dir=out]`
- Full DSL works: `->` sequences, `+`/`?`/`{n,m}` quantifiers, `!` negation, `[dir=out,dt<100ms]` constraints, `|` disjunction, `.` wildcard
- "Selected IPs" scope: loads CSVs for selected pairs, searches embedded packets
- "All IPs" scope: progressive pair-by-pair CSV loading with progress bar + cancel
- Results summary: "1,523 / 5,482 flows matched · 12 IP pairs · 420ms"
- "View Flows" opens existing flow list modal with matched flows
- "Select matched IPs" selects discovered IPs in sidebar
- "Highlight matches only" → matching circles glow gold, non-matching dim
- "Clear" resets everything
- Warning shown if no embedded packet data available

**How to test**:
1. Serve the app (`python -m http.server 8000`), open `tcp-analysis.html`, select a few IPs
2. Expand "Flow Pattern Search", pick "SYN without SYN+ACK" preset, click Search
3. Verify matched flows are ones where SYN was sent but no SYN+ACK received
4. Type `RST{3,}` — verify matches contain 3+ consecutive RST packets
5. Type `SYN -> SYN_ACK[dt>1s]` — verify matches have slow handshake (>1s)
6. Test `RST[dir=in]` — verify RST came from responder
7. Test "All IPs" scope → progress bar appears, cancel works mid-search
8. Toggle "Highlight matches only" → verify circle highlighting in Packet View
9. Click "Select matched IPs" → verify sidebar checkboxes update

---

### Phase 2: Level 2 Phase Pattern Search

**Goal**: Add TCP phase abstraction layer. Groups consecutive packets into phases (HANDSHAKE, DATA, FIN_CLOSE, RST_CLOSE). Reuses the full pattern language from Phase 1.

**Files extended**:
| File | Changes |
|------|---------|
| `src/search/flow-abstractor.js` | +80 LOC: add `abstractToLevel2(packets)` — groups consecutive packets by `flagPhase()`, collapses into phase events, splits closing into FIN_CLOSE/RST_CLOSE. Each phase carries `{packetCount, duration, bytes}` |
| `src/search/pattern-presets.js` | +40 LOC: Level 2 presets (normal flow, port scan, no data, RST after data, long session) |
| `src/search/pattern-search-engine.js` | +20 LOC: add Level 2 dispatch in `_searchWithPackets()` (abstract to level 2 before matching) |
| `src/ui/pattern-search-panel.js` | +30 LOC: enable Phase radio, update autocomplete for Level 2 event names (`HANDSHAKE`, `DATA`, `FIN_CLOSE`, `RST_CLOSE`), update hint text |

**What works after Phase 2** (in addition to Phase 1):
- Switch Level radio to "Phase" → presets update to Level 2 patterns
- Type `HANDSHAKE -> DATA+ -> FIN_CLOSE` or pick "Normal TCP Flow" preset
- Phase constraint support: `HANDSHAKE -> DATA[dur>60s] -> *` (long data sessions)
- `HANDSHAKE -> RST_CLOSE` finds port scan patterns (connect then immediately RST, no data)
- All Phase 1 features (progress, cancel, highlighting) work identically

**How to test**:
1. Select 2-3 IPs with visible flows in the Packet View
2. Search with "Normal TCP Flow" preset (`HANDSHAKE -> DATA+ -> FIN_CLOSE`)
3. Verify matched flows have SYN→SYN+ACK→ACK, then PSH+ACK packets, then FIN packets
4. Search with "Port Scan" preset (`HANDSHAKE -> RST_CLOSE`) — verify matches are flows with handshake immediately followed by RST
5. Test phase constraints: `DATA[count>100]` — flows with >100 data packets
6. Verify Level 1 (Packet) still works correctly after adding Level 2

---

### Phase 3: Level 3 Outcome Search + All-IPs Discovery

**Goal**: Add flow outcome abstraction (works from metadata alone — no packets needed). Enable instant "All IPs" discovery via pre-loaded `flow_bins` data.

**Files extended**:
| File | Changes |
|------|---------|
| `src/search/flow-abstractor.js` | +30 LOC: add `abstractToLevel3(flow)` — maps `closeType`/`invalidReason` to outcome enum using `flowToOutcome()` |
| `src/search/pattern-presets.js` | +40 LOC: Level 3 presets (failed handshakes, graceful, aborted, all invalid, ongoing) |
| `src/search/pattern-search-engine.js` | +100 LOC: add `_searchLevel3Selected(matcher)` (scans `state.flows.current`, instant), `_searchLevel3All(matcher)` (scans `flow_bins` from `AdaptiveOverviewLoader` — ALL 574 IP pairs, no CSV loading) |
| `src/ui/pattern-search-panel.js` | +30 LOC: enable Outcome radio, update autocomplete for Level 3 event names, note "All IPs" is instant at this level |

**Key addition — All-IPs via flow_bins**: Level 3 "All IPs" search scans the pre-loaded `flow_bins` data which contains close type counts per IP pair for ALL 574 pairs. This enables **instant whole-dataset discovery** (e.g., "which IP pairs have the most RST during handshake?") without loading any CSV files.

**What works after Phase 3** (in addition to Phases 1-2):
- Switch Level radio to "Outcome" → presets update to Level 3 patterns
- Pick "Failed Handshakes" → `RST_HANDSHAKE | NO_SYNACK | NO_ACK`
- Custom: `COMPLETE_GRACEFUL[packets<5]` (very short graceful flows)
- "Selected IPs" scope → instant results from `state.flows.current` metadata
- "All IPs" scope → **instant** results scanning `flow_bins` (no loading, <50ms)
- "Select matched IPs" enables discovery workflow: search all → select → drill down with Level 1/2

**How to test**:
1. With no IPs selected, switch to Level 3, scope "All IPs"
2. Pick "Failed Handshakes" preset, click Search
3. Verify results show matches across ALL IP pairs (not just selected)
4. Verify search completes instantly (<50ms) — no progress bar needed
5. Click "Select matched IPs" → sidebar selects IPs with failed handshakes
6. Switch to Level 1 (Packet), scope "Selected IPs", search `SYN[dir=out] -> !SYN_ACK` for deeper analysis
7. Test `COMPLETE_GRACEFUL[dur<1s]` — verify matches are short-lived graceful flows
8. Verify Levels 1 and 2 still work correctly

---

## Performance Notes

| Operation | Cost | Notes |
|-----------|------|-------|
| Level 3 "Selected" | <10ms | Scans in-memory flow array |
| Level 3 "All IPs" | <50ms | Scans pre-loaded flow_bins (~574 pairs) |
| Level 2/1 "Selected" (10 IPs) | ~200ms | Load ~45 CSV pairs (if not cached), abstract + match |
| Level 2/1 "All IPs" | ~30-120s | Load all 574 CSV files (~525MB). Progressive with cancel. |

FlowListLoader caches loaded CSVs, so subsequent searches on the same IP pairs are instant.

---

## Verification

Each phase has its own test procedure listed in the phase description above. Cross-cutting verification:

1. **No regressions**: After each phase, verify existing features (IP selection, overview chart, zoom, box selection, flow list modal) still work correctly
2. **State cleanup**: Verify "Clear" button fully resets search state and removes highlights
3. **IP selection sync**: After changing selected IPs, verify search results auto-clear (stale results would reference old IPs)
4. **Zoom/pan**: Verify circle highlights persist through zoom and pan operations (highlights re-applied during `renderCircles()`)
5. **Console errors**: No JS errors during any search operation, including edge cases (no IPs selected, empty pattern, no embedded packets)
