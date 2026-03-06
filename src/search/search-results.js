// src/search/search-results.js
// Data model for pattern search results.

export class SearchResults {
    constructor() {
        this.matchedFlowIds = new Set();          // Set of flow id values (number or string for synthetic)
        this.matchedFlows = [];                   // Full flow objects or summaries
        this.matchedIpPairs = new Map();          // pairKey -> count
        this.byOutcome = new Map();               // closeType/invalidReason -> count
        this.totalSearched = 0;
        this.totalMatches = 0;
        this.searchTimeMs = 0;
        this.error = null;
    }

    /**
     * Record a matched flow.
     * @param {Object} flow          - Flow object (real or synthetic)
     * @param {Array}  matchRegions  - [{start, end}] from matchPattern()
     */
    addMatch(flow, matchRegions) {
        this.matchedFlowIds.add(flow.id);
        this.matchedFlows.push(flow);
        this.totalMatches++;

        // Tally by IP pair
        const pairKey = flow._ipPairKey ||
            (flow.initiator && flow.responder
                ? (flow.initiator < flow.responder
                    ? `${flow.initiator}<->${flow.responder}`
                    : `${flow.responder}<->${flow.initiator}`)
                : 'unknown');

        this.matchedIpPairs.set(pairKey, (this.matchedIpPairs.get(pairKey) || 0) + 1);

        // Tally by outcome/closeType
        const outcomeKey = flow.invalidReason || flow.closeType || 'unknown';
        this.byOutcome.set(outcomeKey, (this.byOutcome.get(outcomeKey) || 0) + 1);
    }

    /**
     * One-line summary string for display in the UI.
     * @returns {string}
     */
    getSummary() {
        if (this.error) return `Error: ${this.error}`;
        const pairCount = this.matchedIpPairs.size;
        return `${this.totalMatches.toLocaleString()} / ${this.totalSearched.toLocaleString()} flows matched \u00b7 ${pairCount} IP pair${pairCount !== 1 ? 's' : ''} \u00b7 ${this.searchTimeMs}ms`;
    }

    /**
     * Unique IP addresses that appear in matched flows (as initiator or responder).
     * Used by "Select matched IPs" button.
     * @returns {string[]}
     */
    getMatchedIPs() {
        const ipSet = new Set();
        for (const flow of this.matchedFlows) {
            if (flow.initiator) ipSet.add(flow.initiator);
            if (flow.responder) ipSet.add(flow.responder);
            // Synthetic Level 3 flows store IPs in _ipPairKey
            if (flow._ipPairKey) {
                const [a, b] = flow._ipPairKey.split('<->');
                if (a) ipSet.add(a);
                if (b) ipSet.add(b);
            }
        }
        return Array.from(ipSet);
    }

    /**
     * Returns flows de-duplicated by flow id (real flows only, not synthetic).
     * Useful for "View Flows" to avoid showing duplicate synthetic entries.
     * @returns {Object[]}
     */
    getRealFlows() {
        return this.matchedFlows.filter(f => !f._synthetic);
    }

    /**
     * True if the results contain no error and at least one match.
     */
    get hasMatches() {
        return !this.error && this.totalMatches > 0;
    }
}
