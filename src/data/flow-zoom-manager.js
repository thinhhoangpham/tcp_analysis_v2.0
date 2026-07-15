// src/data/flow-zoom-manager.js
//
// Manages Kronograph-style semantic zoom for the flow lozenge view.
//
// Responsibilities:
//   1. Tier selection   — decides per IP pair whether to use pre-binned data
//                         or individual flows based on visible time range.
//   2. On-demand loading — triggers loading of individual flow CSVs when
//                          zoomed in enough.
//   3. 1D pixel-proximity clustering — merges nearby items into visual
//                                      clusters to avoid overdraw.

import { LOZENGE_MIN_WIDTH } from '../config/constants.js';

// ─── Module-level helper (outside class for performance) ──────────────────────

/**
 * Finalises a cluster object produced by clusterFlows, computing its center
 * timestamp and cleaning up internal tracking fields.
 *
 * @param {object} cluster - Mutable cluster object being built by the sweep.
 */
function _finalizeCluster(cluster) {
    cluster.binCenter = Math.round((cluster.binStart + cluster.binEnd) / 2);

    // If only a single individual flow was merged, propagate its un-binned identity.
    if (cluster._childCount === 1 && cluster.count === 1) {
        cluster.binned = false;
        cluster.clustered = false;
    }

    // Remove internal tracking fields — callers should not see these.
    delete cluster._pxEnd;
    delete cluster._childCount;
}

// ─── FlowZoomManager ─────────────────────────────────────────────────────────

export class FlowZoomManager {
    /**
     * @param {object} adaptiveOverviewLoader - Provides pre-binned flow data
     *   via `getFlowBinsByPair(selectedIPs, visibleStart, visibleEnd)`.
     * @param {object} flowListLoader - Provides individual flow data via
     *   `getFlowsInRange(pairKey, start, end)`, `getFlowCount(pairKey)`, and
     *   `_loadPairFlows(pairKey)`.
     */
    constructor(adaptiveOverviewLoader, flowListLoader) {
        this.adaptiveOverviewLoader = adaptiveOverviewLoader;
        this.flowListLoader = flowListLoader;

        // Last cluster output — returned when nothing meaningful changed.
        this._lastClusterResult = null;

        // Set of pair keys whose individual CSV is currently being fetched.
        this._pendingLoads = new Set();

        // Pairs that don't exist in flow_list — skip loading them again.
        this._missingPairs = new Set();

        // Callback invoked after an individual flow CSV finishes loading,
        // so the caller can trigger a re-render without waiting for a zoom event.
        this.onDataLoaded = null;

        // Stash last call args so we can re-run after async load completes.
        this._lastXScale = null;
        this._lastSelectedIPs = null;
    }

    // ─── Main API ─────────────────────────────────────────────────────────────

    /**
     * Returns clustered flow data for the current zoom viewport.
     *
     * Called from the debounced zoom handler whenever the view is in flow mode.
     * All timestamps are in microseconds.
     *
     * @param {d3.ScaleTime} xScale   - Current D3 time scale (domain in µs).
     * @param {string[]}     selectedIPs - Array of IP strings currently visible.
     * @param {object}       [options={}] - Reserved for future use.
     * @returns {Promise<{items: object[], globalMaxCount: number,
     *                    resolution: string, tier: string}>}
     */
    async getClusteredFlowData(xScale, selectedIPs, options = {}) {
        this._lastXScale = xScale;
        this._lastSelectedIPs = selectedIPs;
        const [visibleStart, visibleEnd] = xScale.domain().map(d => +d);

        // Get bins at appropriate resolution (actual time ranges)
        const binnedResult = await this.adaptiveOverviewLoader.getFlowBinsByPair(
            selectedIPs, visibleStart, visibleEnd
        );

        const allItems = [];
        const individualPairs = new Set();

        // Individual flows only at finest bin resolution (1s) — same as
        // packet view going from coarse bins → fine bins → raw packets
        if (binnedResult.resolution === '1s') {
            const pairsInView = new Set(binnedResult.items.map(d => d.pairKey));
            const pairsToLoad = [];
            for (const pairKey of pairsInView) {
                const flows = this.flowListLoader.getFlowsInRange(
                    pairKey, visibleStart, visibleEnd
                );
                if (flows !== null && flows.length > 0) {
                    individualPairs.add(pairKey);
                    for (const f of flows) {
                        allItems.push({
                            pairKey,
                            initiator: f.initiator,
                            responder: f.responder,
                            binStart: f.startTime,
                            binEnd: f.endTime,
                            binCenter: Math.round((f.startTime + f.endTime) / 2),
                            closeType: (f.closeType === 'invalid' && f.invalidReason) ? f.invalidReason : f.closeType,
                            invalidReason: f.invalidReason || '',
                            count: 1,
                            binned: false,
                            clustered: false
                        });
                    }
                } else if (flows === null) {
                    pairsToLoad.push(pairKey);
                }
            }
            if (pairsToLoad.length > 0) {
                this._triggerFlowLoads(pairsToLoad);
            }
        }

        // Bins for pairs not yet loaded as individual flows
        for (const item of binnedResult.items) {
            if (!individualPairs.has(item.pairKey)) {
                allItems.push(item);
            }
        }

        // Debug: check abortive items
        const abortiveItems = allItems.filter(d => d.closeType === 'abortive');
        if (abortiveItems.length > 0) {
            console.log(`[FlowZoomManager] abortive items:`, abortiveItems.map(d => ({
                pair: d.pairKey, binStart: d.binStart, binEnd: d.binEnd,
                width: d.binEnd - d.binStart, binned: d.binned, initiator: d.initiator
            })));
        }

        let globalMaxCount = 0;
        for (const item of allItems) {
            if (item.count > globalMaxCount) globalMaxCount = item.count;
        }

        const result = {
            items: allItems,
            globalMaxCount: Math.max(1, globalMaxCount),
            resolution: individualPairs.size > 0 ? 'mixed' : binnedResult.resolution,
            tier: individualPairs.size > 0 ? 'mixed' : 'binned'
        };

        this._lastClusterResult = result;
        return result;
    }

    // ─── Clustering ───────────────────────────────────────────────────────────

    /**
     * Merges nearby flow items into visual clusters using a 1D pixel-space
     * sweep per (pairKey, closeType, initiator) group.
     *
     * This is the performance-critical hot path — O(N log N) due to the sort,
     * O(N) for the sweep. Timing is logged when it exceeds 5 ms.
     *
     * All timestamps in items are in microseconds.
     *
     * @param {object[]} items  - Flat array of flow/bin items.
     * @param {d3.Scale} xScale - Current D3 scale mapping µs → pixels.
     * @returns {object[]} Clustered items.
     */
    clusterFlows(items, xScale) {
        if (!items || items.length === 0) return [];

        const t0 = performance.now();

        // Group by (pairKey + closeType + initiator) — O(N) with Map.
        const groups = new Map();
        for (const item of items) {
            const key = `${item.pairKey}|${item.closeType}|${item.initiator}`;
            if (!groups.has(key)) groups.set(key, []);
            groups.get(key).push(item);
        }

        const clusters = [];

        for (const [/* groupKey */, groupItems] of groups) {
            // Sort ascending by start time within the group.
            groupItems.sort(
                (a, b) => (a.binStart ?? a.startTime) - (b.binStart ?? b.startTime)
            );

            // 1D sweep: merge items whose pixel extents are within gapPx.
            let cluster = null;

            for (const item of groupItems) {
                const itemStart = item.binStart ?? item.startTime;
                const itemEnd   = item.binEnd   ?? item.endTime ?? itemStart;
                const itemCount = item.count || 1;

                const pxStart = xScale(itemStart);
                const pxEnd   = xScale(itemEnd);

                if (cluster === null) {
                    // Start a fresh cluster.
                    cluster = {
                        pairKey:       item.pairKey,
                        initiator:     item.initiator,
                        responder:     item.responder,
                        closeType:     item.closeType,
                        invalidReason: item.invalidReason || '',
                        binStart:      itemStart,
                        binEnd:        itemEnd,
                        count:         itemCount,
                        binned:        true,     // _finalizeCluster may flip this
                        clustered:     true,
                        _pxEnd:        Math.max(pxEnd, pxStart + LOZENGE_MIN_WIDTH),
                        _childCount:   1
                    };
                } else if (pxStart <= cluster._pxEnd) {
                    // Close enough — absorb into current cluster.
                    cluster.binEnd    = Math.max(cluster.binEnd, itemEnd);
                    cluster.count    += itemCount;
                    cluster._pxEnd   = Math.max(cluster._pxEnd, pxEnd, pxStart + LOZENGE_MIN_WIDTH);
                    cluster._childCount++;
                } else {
                    // Gap too large — emit current cluster and start a new one.
                    _finalizeCluster(cluster);
                    clusters.push(cluster);

                    cluster = {
                        pairKey:       item.pairKey,
                        initiator:     item.initiator,
                        responder:     item.responder,
                        closeType:     item.closeType,
                        invalidReason: item.invalidReason || '',
                        binStart:      itemStart,
                        binEnd:        itemEnd,
                        count:         itemCount,
                        binned:        true,
                        clustered:     true,
                        _pxEnd:        Math.max(pxEnd, pxStart + LOZENGE_MIN_WIDTH),
                        _childCount:   1
                    };
                }
            }

            // Emit the last cluster in this group.
            if (cluster !== null) {
                _finalizeCluster(cluster);
                clusters.push(cluster);
            }
        }

        const elapsed = performance.now() - t0;
        if (elapsed > 5) {
            console.log(
                `[FlowZoomManager] clusterFlows: ${items.length} items → ` +
                `${clusters.length} clusters in ${elapsed.toFixed(1)}ms`
            );
        }

        return clusters;
    }

    // ─── Async Flow Loading ───────────────────────────────────────────────────

    /**
     * Fires an async load of the individual flow CSV for a pair, guarded so
     * that only one in-flight request exists per pair at a time.
     *
     * The caller does NOT await this — the result is available on the next
     * zoom event once the CSV has been parsed.
     *
     * @param {string} pairKey - Canonical "ip1<->ip2" key.
     */
    _triggerFlowLoads(pairKeys) {
        // Filter to pairs not already loading or known missing
        const toLoad = pairKeys.filter(pk =>
            !this._pendingLoads.has(pk) && !this._missingPairs.has(pk)
        );
        if (toLoad.length === 0) return;

        for (const pk of toLoad) this._pendingLoads.add(pk);

        // Load all in parallel, then re-render once when ALL are done
        Promise.all(toLoad.map(async (pk) => {
            try {
                const flows = await this.flowListLoader._loadPairFlows(pk);
                if (!flows || flows.length === 0) {
                    this._missingPairs.add(pk);
                }
            } catch (err) {
                console.warn(`[FlowZoomManager] Failed to load ${pk}:`, err);
                this._missingPairs.add(pk);
            } finally {
                this._pendingLoads.delete(pk);
            }
        })).then(() => {
            // All loads done — one single re-render
            if (this.onDataLoaded && this._lastXScale && this._lastSelectedIPs) {
                this.getClusteredFlowData(this._lastXScale, this._lastSelectedIPs)
                    .then(result => this.onDataLoaded(result));
            }
        });
    }

    // ─── Cache Helpers ────────────────────────────────────────────────────────

    /**
     * Invalidates cached cluster output and selected-pairs state.
     * Call this whenever the underlying data changes (e.g. resolution switch,
     * new data load, IP selection reset).
     */
    invalidateCache() {
        this._lastClusterResult = null;
    }
}
