// src/data/flow-loader.js
// Flow loading decision tree.

import { LOG } from '../utils/formatters.js';
import { getFlowListLoader } from './flow-list-loader.js';

/**
 * Filter regular flows by selected IPs.
 * @param {Array} flows - Array of flow objects
 * @param {Set<string>} selectedIPSet - Set of selected IPs
 * @returns {Array} Filtered flows
 */
export function filterFlowsByIPs(flows, selectedIPSet) {
    if (!Array.isArray(flows)) return [];
    return flows.filter(f =>
        selectedIPSet.has(f.initiator) && selectedIPSet.has(f.responder)
    );
}

/**
 * Main flow loading decision tree.
 * Determines the best loading strategy and returns loaded flows.
 */
export async function loadFlowData(context) {
    const {
        getState,
        flowDataState,
        adaptiveOverviewLoader,
        selectedIPs,
        refreshAdaptiveOverview,
        calculateGroundTruthStats,
        sbUpdateGroundTruthStatsUI,
        eventColors
    } = context;

    const state = getState();
    const selectedIPSet = new Set(selectedIPs);

    // Case 1: No IPs selected - show no flows
    if (selectedIPs.length === 0) {
        return { flows: [], skipSyncUpdates: false };
    }

    // Case 2: Flow list CSV files available - defer loading until popup opens
    const flowListLoader = getFlowListLoader();
    if (flowListLoader.isLoaded()) {
        LOG(`[FlowListLoader] Flow list CSV available - will load on-demand when popup opens`);
        console.log(`[FlowListLoader] Deferring CSV load for ${selectedIPs.length} IPs until popup opens`);

        if (adaptiveOverviewLoader && flowDataState && flowDataState.hasAdaptiveOverview) {
            (async () => {
                await refreshAdaptiveOverview(selectedIPs);
            })();
        }

        return { flows: [], skipSyncUpdates: false, hasFlowListAvailable: true };
    }

    // Case 2.5: Adaptive overview available but NO flow list - skip bulk loading
    if (adaptiveOverviewLoader && flowDataState && flowDataState.hasAdaptiveOverview) {
        LOG(`[AdaptiveOverview] Using pre-aggregated overview data`);
        console.log(`[AdaptiveOverview] Skipping bulk loading for ${selectedIPs.length} IPs - no flow list available`);

        (async () => {
            await refreshAdaptiveOverview(selectedIPs);

            const tcpFlowStats = document.getElementById('tcpFlowStats');
            if (tcpFlowStats) {
                const totalFlows = adaptiveOverviewLoader.index?.total_flows || 0;
                tcpFlowStats.innerHTML = `<span style="color: #28a745;">Adaptive Overview Mode</span><br>
                    <span style="color: #666;">${totalFlows.toLocaleString()} total flows</span><br>
                    <span style="color: #888; font-size: 11px;">Flow list not available (no flow_list files)</span>`;
            }

            const stats = calculateGroundTruthStats(state.flows.groundTruth, selectedIPs, eventColors);
            sbUpdateGroundTruthStatsUI(stats.html, stats.hasMatches);
        })();

        return { flows: [], skipSyncUpdates: true };
    }

    // Case 3: Regular flows - filter in-memory
    LOG(`Filtering ${state.flows.tcp.length} flows with selected IPs:`, selectedIPs);
    const filtered = filterFlowsByIPs(state.flows.tcp, selectedIPSet);
    LOG(`Filtered to ${filtered.length} flows matching selected IPs`);

    return { flows: filtered, skipSyncUpdates: false };
}
