// ─── Flow Arc Search Engine ──────────────────────────────────────────────────
//
// Orchestrates pattern matching against flow arc data (Level 4).
// Operates synchronously on in-memory _linksWithNodes — no async I/O needed.

import { parsePattern, compilePattern, matchPattern } from './pattern-language.js';
import { buildPairPhaseMap, computeVolumePercentiles, canonicalPairKey } from './flow-arc-abstractor.js';

// ─── Results class ───────────────────────────────────────────────────────────

export class FlowArcSearchResults {
    constructor() {
        this.matchedPairKeys = new Set();
        this.matchedLinks = [];
        this.matchedTimeRanges = new Map(); // Map<pairKey, [{minuteStart, minuteEnd}]>
        this.totalSearched = 0;
        this.totalMatched = 0;
        this.searchTimeMs = 0;
        this.error = null;
        this.patternString = '';
    }
}

// ─── Engine class ────────────────────────────────────────────────────────────

export class FlowArcSearchEngine {
    /**
     * @param {Object} options
     * @param {Function} options.getLinksWithNodes - () => Array of link objects
     */
    constructor({ getLinksWithNodes }) {
        this._getLinksWithNodes = getLinksWithNodes;
    }

    /**
     * Search for a DSL pattern across all IP pair phase sequences.
     *
     * @param {string} patternString - DSL pattern (e.g., "GRACEFUL+ -> RST_HANDSHAKE+")
     * @param {Object} options
     * @param {string} options.scope - 'all' or 'selected'
     * @param {Set<string>} options.selectedIPs - IPs to restrict search to (when scope='selected')
     * @param {number|null} options.withinMinutes - Max duration for matched region
     * @returns {FlowArcSearchResults}
     */
    search(patternString, options = {}) {
        const t0 = performance.now();
        const results = new FlowArcSearchResults();
        results.patternString = patternString;

        const links = this._getLinksWithNodes();
        if (!links || links.length === 0) {
            results.error = 'No flow data available';
            results.searchTimeMs = performance.now() - t0;
            return results;
        }

        // Parse and compile pattern
        let matcher;
        try {
            const ast = parsePattern(patternString);
            matcher = compilePattern(ast, 4);
        } catch (e) {
            results.error = e.message || 'Invalid pattern syntax';
            results.searchTimeMs = performance.now() - t0;
            return results;
        }

        // Build phase map
        const percentiles = computeVolumePercentiles(links);
        const pairPhaseMap = buildPairPhaseMap(links, { percentiles });

        const { scope, selectedIPs, withinMinutes } = options;

        // Match against each pair
        for (const [pairKey, { src, tgt, phases, rawBins }] of pairPhaseMap) {
            // Scope filtering
            if (scope === 'selected' && selectedIPs) {
                if (!selectedIPs.has(src) && !selectedIPs.has(tgt)) continue;
            }

            results.totalSearched++;

            if (phases.length === 0) continue;

            const matchResult = matchPattern(matcher, phases, 4);
            if (!matchResult.matched) continue;

            // Apply within(Nm) filter
            let regions = matchResult.matchedRegions;
            if (withinMinutes != null && withinMinutes > 0) {
                regions = this._applyWithinFilter(regions, phases, withinMinutes);
            }
            if (regions.length === 0) continue;

            // Record match
            results.matchedPairKeys.add(pairKey);
            results.totalMatched++;

            // Collect matched time ranges
            const timeRanges = regions.map(r => ({
                minuteStart: phases[r.start].minuteStart,
                minuteEnd: phases[Math.min(r.end, phases.length) - 1].minuteEnd
            }));
            results.matchedTimeRanges.set(pairKey, timeRanges);

            // Collect matched links
            const matchedLinks = this._linksForMatch(pairKey, timeRanges, links);
            results.matchedLinks.push(...matchedLinks);
        }

        results.searchTimeMs = performance.now() - t0;
        return results;
    }

    /**
     * Evaluate a fan-in or fan-out pattern (bypasses DSL).
     *
     * @param {'fan_in'|'fan_out'} type
     * @param {string} closeType - Raw close_type string (e.g., 'incomplete_no_synack')
     * @param {number} threshold - Minimum distinct partners to qualify
     * @param {number|null} withinMinutes - Optional time window
     * @returns {FlowArcSearchResults}
     */
    evaluateFanPattern(type, closeType, threshold, withinMinutes) {
        const t0 = performance.now();
        const results = new FlowArcSearchResults();
        results.patternString = `${type}(${closeType}, >${threshold})`;

        const links = this._getLinksWithNodes();
        if (!links || links.length === 0) {
            results.error = 'No flow data available';
            results.searchTimeMs = performance.now() - t0;
            return results;
        }

        // Group by the "hub" IP (target for fan_in, source for fan_out)
        const hubGroups = new Map();
        for (const link of links) {
            if (link.attack !== closeType) continue;

            const src = link.sourceIp || link.sourceNode?.name;
            const tgt = link.targetIp || link.targetNode?.name;
            const hub = type === 'fan_in' ? tgt : src;
            const partner = type === 'fan_in' ? src : tgt;

            if (!hub || !partner) continue;

            if (!hubGroups.has(hub)) {
                hubGroups.set(hub, { partners: new Set(), links: [] });
            }
            hubGroups.get(hub).partners.add(partner);
            hubGroups.get(hub).links.push(link);
        }

        results.totalSearched = hubGroups.size;

        for (const [hub, { partners, links: hubLinks }] of hubGroups) {
            if (partners.size < threshold) continue;

            // Optional: within time window filter
            if (withinMinutes != null && withinMinutes > 0) {
                const minutes = hubLinks.map(l => l.minute);
                const span = Math.max(...minutes) - Math.min(...minutes);
                if (span > withinMinutes) continue;
            }

            results.totalMatched++;

            // Add all pair keys involving this hub
            for (const partner of partners) {
                const pk = canonicalPairKey(hub, partner);
                results.matchedPairKeys.add(pk);
            }

            // Collect time ranges
            const minMinute = Math.min(...hubLinks.map(l => l.minute));
            const maxMinute = Math.max(...hubLinks.map(l => l.minute));
            for (const partner of partners) {
                const pk = canonicalPairKey(hub, partner);
                if (!results.matchedTimeRanges.has(pk)) {
                    results.matchedTimeRanges.set(pk, []);
                }
                results.matchedTimeRanges.get(pk).push({
                    minuteStart: minMinute,
                    minuteEnd: maxMinute
                });
            }

            results.matchedLinks.push(...hubLinks);
        }

        results.searchTimeMs = performance.now() - t0;
        return results;
    }

    // ─── Private helpers ─────────────────────────────────────────────────────

    _applyWithinFilter(regions, phases, withinMinutes) {
        return regions.filter(r => {
            const endIdx = Math.min(r.end, phases.length) - 1;
            if (endIdx < r.start) return true; // degenerate region
            const duration = phases[endIdx].minuteEnd - phases[r.start].minuteStart;
            return duration <= withinMinutes;
        });
    }

    _linksForMatch(pairKey, timeRanges, allLinks) {
        const [a, b] = pairKey.split('<->');
        return allLinks.filter(link => {
            const src = link.sourceIp || link.sourceNode?.name;
            const tgt = link.targetIp || link.targetNode?.name;
            const pk = canonicalPairKey(src, tgt);
            if (pk !== pairKey) return false;
            return timeRanges.some(r => link.minute >= r.minuteStart && link.minute <= r.minuteEnd);
        });
    }
}
