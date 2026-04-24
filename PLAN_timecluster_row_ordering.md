# PLAN: TimeCluster-inspired row ordering (bag-of-motifs)

Translation-invariant row ordering for the flow-only view in
`tcp-flow-analysis.js`. Adapts the TimeCluster 2019 approach (sliding-window
+ unsupervised feature extraction + dimensionality reduction) to the
multi-IP setting: each IP is represented by a **normalized histogram over a
shared motif dictionary**, and IPs are ordered by 1-D projection of those
histograms.

## 1. Goal

- Replace the `first_ts` sort in `initFlowOnlyMode` with a behavior-based
  sort that groups IPs with similar flow shapes together **regardless of
  when the activity happens**.
- Produce a representation that is (a) translation-invariant, (b) robust to
  amplitude differences, (c) interpretable (motifs can be labeled by a
  human), (d) scales to the full 18K-IP dataset.
- Keep it optional: existing `first_ts` and Tier 1 (PCA) orderings remain
  available via the sidebar dropdown.

## 2. Why bag-of-motifs

- A burst occurring at minute 7 and the same burst at minute 30 generate
  **the same window**, so they land in the same motif cluster, so the two
  IPs' motif histograms look similar.
- Shape is decoupled from timing and amplitude by the pre-clustering
  normalization. After that, IP-to-IP similarity is just histogram
  similarity (cosine / Bhattacharyya / JS).
- Motif clusters are inspectable — each one can be visualized as a small
  heatmap and given a human label ("scan burst", "steady beacon", "ramp-up
  session"). This unlocks a secondary UI surface later.

## 3. Architecture (end-to-end)

```
┌────────────────────────────────────────────────────────────────────────┐
│ OFFLINE (Python, one run per dataset)                                  │
│                                                                        │
│  flow_bins_1min.json ┐                                                 │
│  flow_list/*.csv     ├──► build_ip_profiles.py ──► ip_profiles.npy     │
│  ip_stats.json       ┘    (multichannel per-IP time series, normalized)│
│                                                                        │
│  ip_profiles.npy ──► extract_windows.py ──► windows.npy + window_ip_idx│
│                                                                        │
│  windows.npy     ──► cluster_motifs.py ──► motifs.npy + window_labels  │
│                      (k-means on flattened windows; or DCAE → k-means) │
│                                                                        │
│  window_labels   ──► build_histograms.py ──► ip_motif_hist.json        │
│                      (one K-dim histogram per IP)                      │
│                                                                        │
│  motifs.npy      ──► render_motifs.py ──► motifs_preview.png           │
│                      (diagnostic image of each motif centroid)         │
└────────────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────────────┐
│ IN-BROWSER (tcp-flow-analysis.js, on filter change)                    │
│                                                                        │
│  ip_motif_hist.json ──► sortByMotifPCA(ips, hist) ──► ipOrder          │
│                         (standardize → 1-D PCA → argsort)              │
│                                                                        │
│  state.layout.ipOrder = ipOrder                                        │
│  ... existing layout/render path (WebGL renderer consumes ipOrder) ... │
└────────────────────────────────────────────────────────────────────────┘
```

Every offline step writes an artifact; later steps read it. This lets each
stage be re-run and tuned independently.

## 4. Data shapes and decisions

### 4.1 IP profile (per-IP multichannel time series)

Shape: `(n_ips, n_bins, n_channels)` where

- `n_bins = 55` for the 1-minute resolution on the current dataset (read
  from `flow_bins_index.json`)
- `n_channels = 7`:
  1. total flow count initiated
  2. graceful close count
  3. abortive close count
  4. invalid close count
  5. ongoing close count
  6. mean flow duration in bin (µs, log-transformed)
  7. active-flow fraction (fraction of flows in bin with `close_type=ongoing`
     at bin start)

Transformations applied offline per-IP (not per-window):

- Counts → `log1p`
- Each channel standardized globally (mean 0, var 1 across all IPs and bins)
  using stats computed from non-empty bins only

Output: `ip_profiles.npy` — float32, shape `(18348, 55, 7)`, ≈ 28 MB on disk.

### 4.2 Windows

Slide a window of width `w = 5` bins with stride `s = 1` across each IP's
profile. Per IP yields `n_bins - w + 1 = 51` candidate windows. Flatten to
shape `(w × n_channels,) = (35,)`.

**Filter empty windows**: any window whose flow-count channel sums to below
a threshold (e.g., 3 across all bins) is dropped. These are "quiet spans"
and would all cluster into one dominant "silent" motif, swamping the
dictionary.

Per-window normalization (critical): **subtract the window's mean and
divide by its std-dev across all 35 values** before clustering. This removes
amplitude. Two windows with the same shape but 10× difference in flow
count become the same vector. This is the normalization that makes
"similar shape at different amplitude" work.

Output:

- `windows.npy` — float32, shape `(N_windows, 35)` where `N_windows ≈ 200K`
  after filtering (est. ~20% of raw windows are non-empty)
- `window_ip_idx.npy` — int32, shape `(N_windows,)`, maps each window back
  to its source IP index

### 4.3 Motif dictionary (k-means pass)

- `K = 64` motif clusters (power-of-2 for later GPU work; also a reasonable
  dictionary size for 200K windows — ~3K windows per cluster on average).
- **Mini-batch k-means** with batch size 4096, 50 iterations. Scikit-learn
  `MiniBatchKMeans`. Deterministic with `random_state=0`.
- Distance metric: Euclidean on standardized windows. Since each window
  is already per-window-standardized (mean 0, std 1), Euclidean is
  equivalent to shape-distance — it ignores amplitude and mean level.

Outputs:

- `motifs.npy` — float32, shape `(K=64, 35)`, the cluster centroids
- `window_labels.npy` — int32, shape `(N_windows,)`, cluster assignment
  per window

### 4.4 Per-IP motif histograms

For each IP:

1. Collect all window labels where `window_ip_idx == ip`
2. Build K-dim count vector `h[i] = bincount(labels, minlength=K)`
3. L1-normalize: `h[i] /= h[i].sum() + ε`

Edge case: IPs with **zero** surviving windows (after the
flow-count-threshold filter) have no motif representation. Assign them a
sentinel histogram (all zeros) and sort them separately at the bottom of
the view under a "quiet IPs" section.

Output: `ip_motif_hist.json` — `{ ip_address: [K floats] }`. At K=64,
n=18348, ≈ 5 MB uncompressed, <1 MB gzipped.

### 4.5 Ordering computation (in-browser)

Inputs: histograms for the currently-selected IPs, as an `n × K` matrix `H`.

1. Standardize columns: `H ← (H − col_mean) / col_std`
2. 1-D PCA via power iteration (20 iters) → vector `v ∈ ℝ^K`
3. Scores: `s = H · v`
4. `ipOrder = argsort(s)`, with sign fixed by convention (lowest-volume IPs
   at the top if ambiguous)

Same in-browser code path as Tier 1; only the feature source differs.

## 5. Phased delivery

### Phase 1 — Proof of life (skip DCAE, direct k-means)

Goal: ship a working motif-based ordering, validate that it produces better
bands than Tier 1 on known cases (scanners active at different times).

Scope:

- Python script `scripts/build_motif_histograms.py` producing
  `ip_motif_hist.json`. Single-file script, steps 4.1–4.4 inline.
- Diagnostic output: `motifs_preview.png` — 8×8 grid of motif centroids
  rendered as small heatmaps, for human labeling. Write once, inspect
  visually.
- Browser: new function `sortByMotifScore(ips)` in `tcp-flow-analysis.js`;
  new dropdown option "Similarity (motifs)" in the sidebar; swap at the
  `first_ts` site (`tcp-flow-analysis.js:6682`).
- Fallback: if `ip_motif_hist.json` is missing, fall back to Tier 1 PCA,
  then to `first_ts`.

Exit criterion: on a known pair of scanners active at different times,
both IPs sit within 5 rows of each other in the rendered view.

Estimated effort: ~2 days.

### Phase 2 — Motif inspection UI

Goal: make motifs human-labelable and help analysts understand *why* two
IPs were grouped.

Scope:

- Sidebar panel showing the K motif centroids as a scrollable list. Each
  entry: small sparkline of the centroid's flow-count channel + colored
  bars for close-type channels, plus a click-to-label input.
- Hovering an IP row highlights its top-3 motifs in the panel.
- Clicking a motif highlights all IPs whose histogram has significant mass
  in that motif.
- Labels persist to `localStorage` (keyed by dataset + motif index +
  centroid fingerprint to survive re-runs).

Exit criterion: an analyst can label 10 motifs in under 5 minutes and the
labels survive page reload.

Estimated effort: ~3 days.

### Phase 3 — DCAE upgrade (optional)

Goal: replace the flattened-window representation with a DCAE-learned
latent code; cluster in latent space. Expected gain: motifs capture
nonlinear structure that flat k-means misses (e.g., "burst that ramps and
then decays gracefully" becomes a single motif instead of splitting across
several linear cluster boundaries).

Scope:

- `scripts/train_window_autoencoder.py` — a small 1-D CNN autoencoder.
  Input shape `(35,)` as `(5, 7)`; conv-pool-conv-pool-flatten-dense
  bottleneck (16 dims) — symmetric decoder. MSE loss, Adam, ~30 epochs,
  early stopping on held-out windows.
- `cluster_motifs.py` run on latent codes instead of raw windows.
- Version the artifacts (`ip_motif_hist_v2.json`) so Phase 1 output can
  still be loaded for comparison.

Exit criterion: measurable improvement on a held-out labeling task (e.g.,
a human pre-labels 100 IPs into behavior classes; check whether same-class
IPs have smaller histogram distance under DCAE motifs than under flat
motifs).

Estimated effort: ~4 days including training-infrastructure setup.

Skip this phase unless Phase 1 produces visibly unconvincing motifs.

### Phase 4 — Weight slider integration (optional)

Goal: let the user interpolate between "when" (Tier 1 PCA) and "how"
(motif histogram) orderings.

Scope:

- A single `alpha` slider in the sidebar, 0 = pure Tier 1, 1 = pure motif.
- Combine by concatenating the two feature vectors with weights
  `[√(1-α)·F_tier1, √α·F_motif]` and running PCA on the concatenation.
- Re-run on slider change (cached for stable settings).

Exit criterion: sliding from 0 to 1 produces a smooth visible transition
between the two orderings.

Estimated effort: ~1 day on top of Phase 1.

## 6. Key parameters and defaults

| Parameter | Default | Notes |
|---|---|---|
| Bin resolution | 1 minute | Matches existing flow binning; swap to 10s if sub-minute structure matters |
| Channels | 7 | See §4.1; add more if needed |
| Window width `w` | 5 bins | Short enough to catch bursts, long enough to have shape |
| Window stride `s` | 1 bin | Dense overlap — cheap and gives robustness |
| Min window activity | 3 flows | Drops silent windows |
| Motif count `K` | 64 | Bump to 128 if motifs look over-merged |
| k-means batch | 4096 | Mini-batch for scalability |
| k-means iterations | 50 | Deterministic with fixed seed |
| PCA iterations | 20 | Same as Tier 1 |
| Histogram norm | L1 | Distribution over motifs |

All parameters live at the top of the Python scripts; re-running a single
stage with new values is cheap.

## 7. Artifacts and file layout

```
packets_data/<dataset>/ips/
    ip_motif_hist.json           # Phase 1 primary artifact (shipped to browser)
    motifs_preview.png           # Phase 1 diagnostic (not shipped)

packets_data/<dataset>/_precompute/  # Intermediate, not committed, not served
    ip_profiles.npy
    windows.npy
    window_ip_idx.npy
    motifs.npy
    window_labels.npy

scripts/
    build_ip_profiles.py
    extract_windows.py
    cluster_motifs.py
    build_histograms.py
    render_motifs.py
    build_motif_histograms.py    # wrapper that runs all five in order

src/data/
    motif-histogram-loader.js    # fetches ip_motif_hist.json with caching

tcp-flow-analysis.js             # adds sortByMotifScore, dropdown wiring
control-panel.js                 # adds ordering-mode dropdown
```

## 8. Validation plan

- **Translation-invariance test**: synthetic case — duplicate a real IP's
  flow record but shift all start times by 20 minutes. Run the pipeline.
  The duplicate IP should land within 5 rows of the original.
- **Amplitude-invariance test**: synthetic case — duplicate a real IP but
  10× all flow counts in the same bins. Duplicate should land adjacent.
- **Known-scanner test**: manually tag 5 IPs as "same scan campaign"
  across different active windows. Check they land within 10 rows of each
  other.
- **Regression test**: Tier 1 ordering should differ from motif ordering
  by at least N rows on some IPs (otherwise motifs aren't adding value).
  If Tier 1 and motif orderings are nearly identical, Block A in Tier 1 is
  dominating motif histograms aren't sharp enough — bump K or lower window
  threshold.

## 9. Risks and mitigations

- **Sparse-IP representation is noisy.** An IP with 5 windows gives a
  histogram that's essentially a one-hot; small changes to clustering
  move it significantly. **Mitigation**: threshold IPs at ≥ 20 surviving
  windows for ordering; park sparse IPs at the bottom.
- **Motif dictionary drift across datasets.** Re-running on a new capture
  produces different centroids; any user-applied motif labels don't
  transfer. **Mitigation**: save motif centroids and allow the new run to
  bootstrap from the old centroids (initialize k-means with them). Also
  fingerprint centroids for label matching (see Phase 2).
- **"Quiet" dominant motif.** Even after filtering, many surviving
  windows look like mild low-amplitude noise and get clustered into one
  big bucket; most IPs then have most of their mass in it, and the
  histogram becomes nearly-constant across IPs. **Mitigation**: after
  clustering, identify the largest cluster and either drop it from the
  histogram (treat as background) or down-weight it heavily.
- **Stale precompute.** Dataset changes but `ip_motif_hist.json` not
  regenerated. **Mitigation**: include dataset fingerprint (from
  `manifest.json`) in the histogram file; browser compares and falls back
  to Tier 1 if mismatched.
- **Offline pipeline is Python, browser is JS.** Adds a build-time step
  that a pure-JS analyst might forget to run. **Mitigation**: document in
  `CLAUDE.md` under a new "Precompute" section; add a `make motifs`
  target; make the browser loudly warn when the histogram file is missing
  or stale.

## 10. Out of scope (for future plans)

- Pair-aware extensions (see `NOTES_pair_aware_row_clustering.md`)
- Responder-side ordering / bipartite co-clustering
- Online / streaming motif update as new data arrives
- Cross-dataset motif transfer (same motif dictionary across captures)
- Automatic motif labeling via a language model or attack-taxonomy lookup
- Multi-resolution motifs (windows at 10s and 1min and 10min,
  concatenated histograms)

All of the above are reasonable v2 directions; none are needed to validate
whether the motif approach is worth adopting.

## 11. Decision point after Phase 1

After Phase 1 ships and the validation tests run, three outcomes drive the
next step:

1. **Motif ordering clearly beats Tier 1** on the known-scanner test →
   proceed to Phase 2 (inspection UI) to make it usable by analysts.
2. **Motif ordering is comparable to Tier 1** → ship Phase 4 (weight
   slider) so users choose; skip Phase 2 for now.
3. **Motif ordering underperforms Tier 1** → diagnose via
   `motifs_preview.png`. Likely causes: window size too short, K too low,
   too many near-silent windows leaking through. If tuning doesn't fix,
   escalate to Phase 3 (DCAE).
