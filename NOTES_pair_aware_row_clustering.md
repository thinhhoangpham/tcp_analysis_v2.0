# Pair-Aware Extensions for IP Row Clustering (for later review)

**Context:** The first-pass row-clustering design treats each initiator IP as an
independent time series (temporal activity + close-type + duration features).
These notes capture ideas that would fold **pair / peer information** into the
ordering, to revisit after the initiator-only version ships.

## 1. Peer-set signatures as a similarity axis

Represent each initiator IP by the **set of responder IPs it contacted**
(filename convention `<src>__<dst>.csv` in `indices/flow_list/` makes this
trivial to extract). Two initiators that hit the same servers likely play the
same role (e.g., scanners hitting a shared victim list).

- Encode each peer-set as a MinHash signature (~128 permutations).
- Cosine / Jaccard on signatures, mixed into the main feature vector with a
  weight `ω_peer`.
- LSH bucketing (band-hash) gives an O(n) approximate clustering for free.
- Caveat: responder IPs need to be canonicalized — MinHash is sensitive to
  aliasing (e.g., same IP appearing with different casing / whitespace).

## 2. Per-pair close-type fingerprints

Extend the per-IP close-type histogram to a **per-(peer, close-type) tensor**:
for each initiator, concatenate histograms for its top-k peers (k ≈ 5).
Catches patterns like "this IP has graceful closes with its normal peers but
abortive resets with one specific peer."

- Cost: adds 4k extra dims per IP.
- Alternative: per-initiator entropy of close-type across peers (high entropy =
  mixed behaviour, low = monoculture) as one scalar feature. Cheap, often
  enough.

## 3. Bipartite co-clustering (joint row & column ordering)

Treat the flow matrix as bipartite: rows = initiators, columns = responders,
edge weights = flow counts or some close-type-weighted score. Reorder **both
axes** jointly.

- Spectral bipartite co-clustering (Dhillon 2001): compute SVD of a normalized
  adjacency matrix, order rows by left singular vectors, columns by right.
- Useful when the eventual viz wants two-sided grouping (e.g., responder-rows
  view as a secondary panel). Not directly needed for the current
  initiator-only row layout.

## 4. Pair-weighted row distance

Instead of summing features across pairs, define row distance as:

```
d(i, j) = α·d_temporal(i, j) + β·d_closetype(i, j) + γ·d_peer_overlap(i, j)
```

where `d_peer_overlap` is `1 − Jaccard(peers(i), peers(j))`. Feeds into any of
the seriation algorithms from the main menu (PCA / Fiedler / OLO / 2-opt)
without changing the pipeline — just a richer distance.

## 5. Graph-Laplacian ordering via the pair graph

Build a graph where nodes = initiator IPs and edges connect IPs that share a
significant responder, weighted by count of shared peers (or a χ²-corrected
overlap score). Fiedler vector of that graph directly orders rows by
"community" in the pair topology.

- Equivalent to spectral clustering on the **one-mode projection** of the
  bipartite flow graph onto the initiator side.
- Scales fine with a sparse graph even at n ≈ 18K.

## 6. Role-aware dual rows (longer-term)

Right now an IP appears on one row (as initiator). If the UI later supports
two lanes per IP (initiator lane + responder lane), the ordering problem
becomes two coupled seriations on the same set of IPs — naturally solved with
bipartite co-clustering (#3) or with a "mirror" constraint where the same IP
sits at symmetric positions on both axes.

## 7. Pair-stability over time

For flow animation / time-brushing, consider a seriation that minimizes
**row re-ordering cost** as the time window slides. This needs a
time-windowed version of the feature vector and a penalty term on positional
change between adjacent windows — out of scope for v1 but worth keeping in
mind before we commit to a static ordering baked into a precomputed file.

## Pointers into the data

- Pair keys: `flow_bins_*.json` → `flows_by_ip_pair["A<->B"]` with
  `initiated_by` telling us directionality per bin.
- Per-pair flow streams: `indices/flow_list/<src>__<dst>.csv`.
- Global per-IP rollups: `ips/ip_stats.json` (packets/bytes/first_ts/last_ts).

## Things NOT to put in the pair-aware version

- Per-pair duration histograms (cardinality explosion; duration is fine
  rolled up per-initiator).
- Full n×n peer-overlap matrix computed eagerly — use LSH.
- Anything that requires loading every per-pair CSV client-side for the
  18K-IP case; precompute server-side.
