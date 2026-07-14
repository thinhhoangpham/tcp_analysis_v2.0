# First-Degree Neighbor Expansion — Design

**Date:** 2026-07-14
**Page:** TCP Connection Analysis (`tcp-analysis.html` / `tcp-analysis.js`)

## Goal

Add a control that, for each currently-selected "origin" IP (the IPs brushed in
attack-network.js and handed off to tcp-analysis, plus any the user manually
selected), finds that IP's first-degree neighbors (IPs it directly communicated
with) and adds them to the visualization, capped and ranked to keep the row-based
view usable.

## Motivation

Opening tcp-analysis from an attack-network brush shows only the brushed IPs and
their connections *to each other*. Users want to see the brushed IPs' direct
neighbors (e.g. a scanner's targets, a victim's peers) without hunting for and
manually checking each one in the 19,666-IP list.

## Data Characteristics (measured)

- Flow dataset (`flows_set1_90min`): **19,604 distinct IPs**, median first-degree
  degree **128**, p90 **219**, **max 435**. 62% of IPs have >100 neighbors.
- Because typical degree is high, adding ALL first-degree neighbors would flood the
  one-row-per-IP view. Hence the top-N cap below.

## Requirements

### Neighbor discovery
- **Data source depends on View Mode:** Packets view → packet bins; Flows view →
  flow data.
- **Time scope depends on how the page was opened:**
  - Brush open → within the brushed window (`state.timearcs.overviewTimeExtent`).
  - Standalone open → full loaded dataset span.
- Discovery runs against the **unfiltered loaded bins** (`state.data.full`), NOT the
  both-endpoints-selected filtered set (`packet-filter.js` keeps only packets where
  both ends are selected, which would hide not-yet-selected neighbors).
- For each origin IP, scan bins where it appears as `src_ip` or `dst_ip`; the other
  endpoint is a candidate neighbor. Sum **packet count** per candidate.

### Ranking & cap
- Per origin IP: take the **top 50 neighbors by total packet count** (in scope).
- Union the per-origin top-50 sets across all origin IPs.
- Remove any IPs already in the current selection (origin IPs + already-added).
- The remainder are the neighbors to add.

### Ranking data source
- Counts come **from the loaded resolution bins in the current view** (no extra
  fetch). Accepted limitation: at coarse resolutions, bin counts may under-count vs
  raw packets; ranking is best-effort on loaded data.

### UI & interaction
- A **checkbox** in the Control Panel, placed **near the existing view toggles**
  (Sub-row Arcs / Separate Bins / Flow Threading), labeled e.g.
  "Add first-degree neighbors". Works on brush-open AND standalone.
- **ON:** compute neighbors (per above), check their IP boxes, add them to the
  selection, re-render. Neighbors joining the selection makes existing
  pair-rendering draw their connections to the origin IPs.
- **OFF:** remove exactly the IPs this feature added (tracked set), restoring the
  prior selection. Manually-added and origin IPs are untouched.

### Visual distinction
- **Origin/brushed IPs get a filled-dot (●) prefix** on their row label so the
  origin selection stands out. Added-neighbor rows render with plain labels.
- The marker is driven by `state.neighbors.originIPs` so it survives re-renders.

## State & Data Flow

New state (on the existing `state` object):
- `state.neighbors.enabled` — checkbox on/off.
- `state.neighbors.originIPs` — Set of origin IPs (brushed prefilter IPs + any the
  user manually selected before toggling on). Drives the ● marker.
- `state.neighbors.addedIPs` — Set of IPs added by this feature, for clean removal
  on toggle-off.

Flow:
- On brush open: `originIPs` seeded from the brush prefilter IPs.
- Toggle ON: compute neighbors → add to selection + `addedIPs` → check boxes →
  `updateIPFilter()` re-render.
- Toggle OFF: uncheck/remove `addedIPs` from selection → clear `addedIPs` →
  re-render.
- Row-label renderer reads `originIPs` to draw the ● prefix.

## Components / Files

Scope: shared files MAY be edited for this feature (explicit override of the usual
tcp-analysis-only rule).

- `tcp-analysis.html` — add the checkbox near the view toggles.
- `control-panel.js` — checkbox wiring; if IP-row label rendering lives here, add
  the ● prefix logic here.
- `tcp-analysis.js` — new neighbor-computation function (scan `state.data.full` in
  scope, rank by packet count, top-50, union, dedup vs selected); toggle handler;
  seed `originIPs` from brush prefilter; integrate add/remove into the selection
  update path (`updateIPFilter`).
- Label rendering in `/src` (e.g. `renderIPRowLabels`) — ● prefix for origin IPs,
  if that is where labels are drawn.

## Non-Goals (YAGNI)

- No second-degree (neighbors-of-neighbors) expansion.
- No "load more neighbors" beyond the top-50 cap.
- No per-neighbor styling beyond the origin-IP ● marker.
- No new fetch/scan of the raw dataset for exact counts (uses loaded bins).

## Verification

Manual verification by the user (no Playwright automation):
- Brush-open → toggle ON adds ≤50 neighbors per origin IP; they render as rows
  connected to the origin IPs.
- Origin/brushed IP rows show the ● prefix; neighbor rows do not.
- Toggle OFF restores exactly the pre-toggle selection.
- Works in both Packets and Flows view modes, and standalone (full-span scope).

## Open Risks

- `renderIPRowLabels` closures capture `ipPairOrderByRow` by reference (per
  CLAUDE.md gotcha); adding/removing neighbor rows must update it in-place
  (`.clear()` + repopulate), not replace it.
- Coarse-resolution bin counts under-ranking low-volume neighbors (accepted).
