// src/search/pattern-search-engine.js
// Orchestrates data access, abstraction, and pattern matching across all levels and scopes.

import { parsePattern, compilePattern, matchPattern } from './pattern-language.js';
import { abstractToLevel1, abstractToLevel2, abstractToLevel3 } from './flow-abstractor.js';
import { SearchResults } from './search-results.js';

export class PatternSearchEngine {
    /**
     * @param {Object} options
     * @param {Function} options.getState            - () => state (from tcp-analysis.js)
     * @param {Function} options.getFlowListLoader   - () => FlowListLoader instance
     * @param {Function} options.getAdaptiveLoader   - () => AdaptiveOverviewLoader instance
     * @param {Function} options.onProgress          - (pct: 0-1, label: string) => void
     * @param {Function} options.onResults           - (results: SearchResults) => void
     */
    constructor({ getState, getFlowListLoader, getAdaptiveLoader, onProgress, onResults }) {
        this._getState = getState;
        this._getFlowListLoader = getFlowListLoader;
        this._getAdaptiveLoader = getAdaptiveLoader;
        this._onProgress = onProgress || (() => {});
        this._onResults = onResults || (() => {});
        this._cancelled = false;
        this._running = false;
    }

    /**
     * Run a search. Resolves when complete (or cancelled).
     * @param {string} patternString - DSL pattern
     * @param {number} level         - 1, 2, or 3
     * @param {string} scope         - 'selected' | 'all'
     * @param {number[]|null} timeRange - [startUs, endUs] or null for all time
     * @returns {Promise<SearchResults|null>} Results or null if cancelled
     */
    async search(patternString, level, scope, timeRange = null) {
        if (this._running) this.cancel();

        this._cancelled = false;
        this._running = true;
        this._timeRange = timeRange;

        const startMs = performance.now();

        let results;
        try {
            // Parse and compile once
            const ast = parsePattern(patternString);
            const matcher = compilePattern(ast, level);

            if (level === 3) {
                results = scope === 'all'
                    ? await this._searchLevel3All(matcher)
                    : await this._searchLevel3Selected(matcher, timeRange);
            } else {
                // Level 1 or 2 — need embedded packets from CSVs
                const pairs = this._getPairsForScope(scope);
                results = await this._searchWithPackets(matcher, level, pairs, timeRange);
            }

            if (this._cancelled) return null;

            results.searchTimeMs = Math.round(performance.now() - startMs);
            this._onResults(results);
            return results;

        } catch (err) {
            console.error('[PatternSearchEngine] Search error:', err);
            // Return an empty results with error rather than throwing
            const errResults = new SearchResults();
            errResults.error = err.message;
            errResults.searchTimeMs = Math.round(performance.now() - startMs);
            this._onResults(errResults);
            return errResults;

        } finally {
            this._running = false;
        }
    }

    /**
     * Cancel any in-progress search.
     */
    cancel() {
        this._cancelled = true;
    }

    // ─── Level 3 ─────────────────────────────────────────────────────────────

    /**
     * Level 3 + "Selected IPs": scans state.flows.current (in-memory, instant).
     */
    async _searchLevel3Selected(matcher, timeRange = null) {
        const state = this._getState();
        const flows = state.flows.current || [];
        const results = new SearchResults();

        for (const flow of flows) {
            // Skip flows outside the time range (overlap check)
            if (timeRange) {
                const [tStart, tEnd] = timeRange;
                if (flow.startTime > tEnd || flow.endTime < tStart) {
                    results.totalSearched++;
                    continue;
                }
            }

            results.totalSearched++;
            const outcomeEvent = abstractToLevel3(flow);
            const { matched } = matchPattern(matcher, [outcomeEvent], 3);
            if (matched) {
                results.addMatch(flow, [{ start: 0, end: 1 }]);
            }
        }

        return results;
    }

    /**
     * Level 3 + "All IPs": scans flow_bins from AdaptiveOverviewLoader.
     * The flow_bins contain aggregated counts per IP pair — no CSV loading needed.
     * Synthesizes minimal flow objects for each IP pair / close type combination.
     */
    async _searchLevel3All(matcher) {
        const results = new SearchResults();
        const loader = this._getAdaptiveLoader ? this._getAdaptiveLoader() : null;

        if (!loader) {
            console.warn('[PatternSearchEngine] No AdaptiveOverviewLoader available for Level 3 All-IPs search');
            return results;
        }

        // Try to get the coarsest resolution bins (already loaded / tiny)
        let binData = null;
        try {
            await loader.loadIndex();
            // Prefer hour resolution for fastest scan — it has all pairs
            const resolution = 'hour';
            binData = await loader.loadResolution(resolution);
        } catch (err) {
            console.warn('[PatternSearchEngine] Could not load flow_bins for Level 3 search:', err);
            return results;
        }

        if (!binData || !Array.isArray(binData)) return results;

        // Aggregate counts per IP pair across all bins
        const pairTotals = new Map();  // pairKey -> { closeType counts }

        for (const bin of binData) {
            if (!bin.flows_by_ip_pair) continue;
            for (const [pairKey, counts] of Object.entries(bin.flows_by_ip_pair)) {
                if (!pairTotals.has(pairKey)) {
                    pairTotals.set(pairKey, { graceful: 0, abortive: 0, ongoing: 0 });
                }
                const totals = pairTotals.get(pairKey);

                // Merge counts
                const closeTypes = ['graceful', 'abortive', 'ongoing'];
                for (const ct of closeTypes) {
                    if (counts[ct]) totals[ct] = (totals[ct] || 0) + counts[ct];
                }
                if (counts.invalid && typeof counts.invalid === 'object') {
                    for (const [reason, cnt] of Object.entries(counts.invalid)) {
                        totals[reason] = (totals[reason] || 0) + cnt;
                    }
                }
            }
        }

        // For each IP pair, synthesize flow-like objects for each closeType bucket
        const invalidReasons = [
            'rst_during_handshake', 'invalid_ack', 'invalid_synack',
            'incomplete_no_synack', 'incomplete_no_ack', 'unknown_invalid'
        ];

        for (const [pairKey, totals] of pairTotals) {
            const [ip1, ip2] = pairKey.split('<->');

            const checkOutcome = (closeType, invalidReason, count) => {
                if (!count || count <= 0) return;
                const syntheticFlow = { closeType, invalidReason: invalidReason || '' };
                const outcomeEvent = abstractToLevel3(syntheticFlow);
                const { matched } = matchPattern(matcher, [outcomeEvent], 3);

                if (matched) {
                    for (let i = 0; i < count; i++) {
                        results.totalSearched++;
                        // Synthetic flow for summary purposes
                        const flow = {
                            id: `${pairKey}::${closeType}::${invalidReason || 'none'}::${i}`,
                            initiator: ip1,
                            responder: ip2,
                            closeType,
                            invalidReason: invalidReason || '',
                            totalPackets: 0,
                            _synthetic: true,
                            _ipPairKey: pairKey
                        };
                        results.addMatch(flow, [{ start: 0, end: 1 }]);
                    }
                } else {
                    results.totalSearched += count;
                }
            };

            checkOutcome('graceful', null, totals.graceful);
            checkOutcome('abortive', null, totals.abortive);
            checkOutcome('ongoing',  null, totals.ongoing);

            for (const reason of invalidReasons) {
                checkOutcome('invalid', reason, totals[reason]);
            }
        }

        return results;
    }

    // ─── Level 1 / 2 ─────────────────────────────────────────────────────────

    /**
     * Level 1 or 2, any scope: loads CSV files pair-by-pair via FlowListLoader.
     * Reports progress after each pair. Supports cancellation.
     *
     * @param {Function} matcher       - Compiled matcher from compilePattern()
     * @param {number}   level         - 1 or 2
     * @param {string[]} pairs         - IP pair keys to search
     * @param {number[]|null} timeRange - [startUs, endUs] or null for all time
     */
    async _searchWithPackets(matcher, level, pairs, timeRange = null) {
        const results = new SearchResults();
        const loader = this._getFlowListLoader ? this._getFlowListLoader() : null;

        if (!loader || !loader.isLoaded()) {
            results.error = 'Flow list data not available. Load flow_list CSV files to enable Level 1/2 search.';
            return results;
        }

        if (!loader.hasEmbeddedPackets()) {
            results.error = 'No embedded packet data in flow_list CSV. Re-generate with generate_flow_data.py to enable packet-level search.';
            return results;
        }

        const total = pairs.length;
        for (let i = 0; i < pairs.length; i++) {
            if (this._cancelled) break;

            const pairKey = pairs[i];
            this._onProgress(i / total, `Searching ${pairKey} (${i + 1}/${total})`);

            let flows;
            try {
                flows = await loader._loadPairFlows(pairKey);
            } catch (err) {
                console.warn(`[PatternSearchEngine] Failed to load ${pairKey}:`, err);
                continue;
            }

            for (const flow of flows) {
                // Skip flows outside the time range (overlap check)
                if (timeRange) {
                    const [tStart, tEnd] = timeRange;
                    if (flow.startTime > tEnd || flow.endTime < tStart) {
                        results.totalSearched++;
                        continue;
                    }
                }

                if (!flow._hasEmbeddedPackets) {
                    results.totalSearched++;
                    continue;
                }

                const packets = flow._embeddedPackets;
                const abstracted = level === 1
                    ? abstractToLevel1(packets)
                    : abstractToLevel2(packets);

                const { matched, matchedRegions } = matchPattern(matcher, abstracted, level);
                results.totalSearched++;
                if (matched) {
                    results.addMatch(flow, matchedRegions);
                }
            }
        }

        return results;
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    /**
     * Get the list of IP pair keys to search based on scope.
     * 'selected' → pairs involving currently selected IPs
     * 'all'      → all known pairs from FlowListLoader index
     */
    _getPairsForScope(scope) {
        const loader = this._getFlowListLoader ? this._getFlowListLoader() : null;

        if (scope === 'all') {
            if (loader && loader.isLoaded() && loader.pairsByKey) {
                return Array.from(loader.pairsByKey.keys());
            }
            return [];
        }

        // 'selected' scope
        const selectedIPs = this._getSelectedIPs();

        if (!loader || !loader.isLoaded()) return [];
        return loader._getRelevantPairs(selectedIPs);
    }

    /**
     * Extract currently selected IP addresses from the sidebar checkboxes.
     */
    _getSelectedIPs() {
        const checkboxes = document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked');
        return Array.from(checkboxes).map(cb => cb.value);
    }
}
