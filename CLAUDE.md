# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Workflow Rules
- When asked to write a plan, ONLY write the plan file. Do not attempt to implement, ask to implement, or exit plan mode. Stop after writing the file.

## Project Overview

Dual-visualization network traffic analysis system built with D3.js v7 for TCP packet data and attack patterns.

1. **Network TimeArcs** (`attack-network.html` → `attack-network.js`) - Arc-based visualization with force-directed IP positioning. Default: Force layout; Timearcs via toggle. Data source: "Attack Events" or "TCP Flows".
2. **TCP Connection Analysis** (`tcp-analysis.html` → `tcp-analysis.js`) - Packet-level visualization with Packet View (circles) / Flow View (lozenges), Overview Bar chart, and Control Panel.

## Running the Application

Static HTML/JS app. Serve with any HTTP server:
```bash
python -m http.server 8000
# http://localhost:8000/attack-network.html  (TimeArcs)
# http://localhost:8000/tcp-analysis.html   (TCP Analysis)
```

## Architecture

```
Main:    attack-network.js (~2200 LOC), tcp-analysis.js (~4600 LOC)
Support: control-panel.js, sidebar.js, legends.js, overview_chart.js,
         folder_integration.js, folder_loader.js, viewer_loader.js

/src:
  rendering/  circles.js, lozenges.js, bars.js, rows.js, arcPath.js,
              svgSetup.js, initialRender.js, tooltip.js,
              arcInteractions.js, highlightUtils.js
  scales/     scaleFactory.js, distortion.js, bifocal.js
  layout/     forceSimulation.js, force_network.js, timearcs_layout.js
  interaction/ zoom.js, dragReorder.js, resize.js
  data/       binning.js, csvParser.js, flowReconstruction.js,
              resolution-manager.js, csv-resolution-manager.js,
              adaptive-overview-loader.js, flow-loader.js,
              flow-list-loader.js, packet-filter.js, flow-data-handler.js
  search/     pattern-language.js, pattern-presets.js,
              pattern-search-engine.js, flow-abstractor.js,
              search-results.js, pattern-ast-to-blocks.js, blocks-to-dsl.js
  ui/         legend.js, bifocal-handles.js, loading-indicator.js,
              pattern-search-panel.js, pattern-builder-popup.js
  config/     constants.js
  tcp/        flags.js
  workers/    packetWorkerManager.js
  plugins/    d3-fisheye.js
  groundTruth/ groundTruth.js
  mappings/   decoders.js, loaders.js
  utils/      formatters.js, helpers.js
```

> **Detailed subsystem docs**: see `ARCHITECTURE.md` (data formats, layout system, selection systems, pattern search DSL, etc.)

## Critical Gotchas

- **`ipPairOrderByRow` must be updated in-place** (not replaced) — `renderIPRowLabels()` closures capture the Map reference. Always `.clear()` then re-populate. Affects 4 sites: resolution change, drag-reorder, collapse/expand, flag separation.
- **`.node-label` elements live in `svg`**, not `mainGroup` — use `d3.select(svg.node()).selectAll('.node-label')`
- **`multiSelectionsGroup` must be reset to `null`** in `render()` cleanup after `svg.selectAll('*').remove()`
- **`RST` (0x04) and `RST_ACK` (0x14) are distinct DSL tokens** — patterns must use `(RST | RST_ACK)` to match both
- **Pattern counts ≠ overview chart counts** by design (packet-level adjacency vs Python state machine)
- **`layoutTransitionInProgress`** guard prevents concurrent mode switches in attack-network.js
