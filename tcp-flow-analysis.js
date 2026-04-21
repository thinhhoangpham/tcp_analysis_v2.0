// Extracted from ip_arc_diagram_3.html inline script
// This file contains all logic for the IP Connection Analysis visualization
import { initControlPanel, createIPCheckboxes as sbCreateIPCheckboxes, filterIPList as sbFilterIPList, filterFlowList as sbFilterFlowList, updateFlagStats as sbUpdateFlagStats, updateIPStats as sbUpdateIPStats, createFlowListCapped as sbCreateFlowListCapped, updateTcpFlowStats as sbUpdateTcpFlowStats, updateGroundTruthStatsUI as sbUpdateGroundTruthStatsUI, wireControlPanelControls as sbWireControlPanelControls, showFlowProgress as sbShowFlowProgress, updateFlowProgress as sbUpdateFlowProgress, hideFlowProgress as sbHideFlowProgress, wireFlowListModalControls as sbWireFlowListModalControls, showCsvProgress as sbShowCsvProgress, updateCsvProgress as sbUpdateCsvProgress, hideCsvProgress as sbHideCsvProgress, refreshIPCollapseState as sbRefreshIPCollapseState, updateSizeLegend as sbUpdateSizeLegend } from './control-panel.js';
import { renderInvalidLegend as sbRenderInvalidLegend, renderClosingLegend as sbRenderClosingLegend, drawFlagLegend as drawFlagLegendFromModule } from './legends.js';
import { initOverview, createOverviewChart, createOverviewFromAdaptive, createFlowOverviewChart, updateBrushFromZoom, updateOverviewInvalidVisibility, setBrushUpdating, refreshFlowOverview } from './overview_chart.js';
import { FLOW_RECONSTRUCT_BATCH } from './config.js';
import {
    DEBUG, RADIUS_MIN, RADIUS_MAX, ROW_GAP, TOP_PAD,
    SUB_ROW_HEIGHT, SUB_ROW_GAP,
    TCP_STATES, HANDSHAKE_TIMEOUT_MS, REORDER_WINDOW_PKTS, REORDER_WINDOW_MS,
    DEFAULT_FLAG_COLORS, FLAG_CURVATURE, PROTOCOL_MAP,
    DEFAULT_FLOW_COLORS, DEFAULT_EVENT_COLORS,
    LOZENGE_MIN_HEIGHT, LOZENGE_MAX_HEIGHT, LOZENGE_MIN_WIDTH, CLOSE_TYPE_STACK_ORDER
} from './src/config/constants.js';
import {
    LOG, formatBytes, formatTimestamp, formatDuration,
    utcToEpochMicroseconds, epochMicrosecondsToUTC,
    makeConnectionKey, clamp, normalizeProtocolValue,
    createSmartTickFormatter, createZoomAdaptiveTickFormatter
} from './src/utils/formatters.js';
import { createDualBandAxis } from './src/scales/dualBandAxis.js';
import {
    classifyFlags, getFlagType, flagPhase, isFlagVisibleByPhase,
    has, isSYN, isSYNACK, isACKonly,
    getColoredFlagBadges, getTopFlags
} from './src/tcp/flags.js';
import { getVisiblePackets, computeBarWidthPx } from './src/data/binning.js';
import { AdaptiveOverviewLoader } from './src/data/adaptive-overview-loader.js';
import { FlowZoomManager } from './src/data/flow-zoom-manager.js';
import {
    computeTimeArcsRange,
    initializeAdaptiveLoader,
    updateFlowDataUI,
    calculateChartDimensions
} from './src/data/flow-data-handler.js';
import {
    reconstructFlowsFromCSVAsync,
    reconstructFlowsFromCSV,
    buildSelectedFlowKeySet as buildSelectedFlowKeySetFromModule,
    verifyFlowPacketConnection,
    exportFlowToCSV as exportFlowToCSVFromModule
} from './src/data/flowReconstruction.js';
import { renderCircles } from './src/rendering/circles.js';
import { renderLozenges } from './src/rendering/lozenges.js';
import { createTooltipHTML } from './src/rendering/tooltip.js';
import { arcPathGenerator } from './src/rendering/arcPath.js';
import { createZoomBehavior, applyZoomDomain as applyZoomDomainFromModule } from './src/interaction/zoom.js';
import { setupZoomButtons, updateZoomButtonStates } from './src/interaction/zoomButtons.js';
import { createDragReorderBehavior } from './src/interaction/dragReorder.js';
import { setupWindowResizeHandler as setupWindowResizeHandlerFromModule } from './src/interaction/resize.js';
import {
    loadGroundTruthData,
    filterGroundTruthByIPs,
    prepareGroundTruthBoxData,
    calculateGroundTruthStats
} from './src/groundTruth/groundTruth.js';
import {
    createPacketWorkerManager,
    applyVisibilityToDots
} from './src/workers/packetWorkerManager.js';
import {
    computeIPCounts,
    computeIPPositioning,
    applyIPPositioningToState,
    computeIPPairOrderByRow,
    computeIPPairCounts
} from './src/layout/ipPositioning.js';
import {
    computeActiveIPs as computeActiveIPsFilter,
    computeCompactPositions,
    applyFilteredPositions,
    restoreBasePositionsToState,
    animateIPRows as animateIPRowsFilter
} from './src/layout/ipRowFilter.js';
import {
    createSVGStructure,
    createBottomOverlay,
    renderIPRowLabels,
    resizeBottomOverlay
} from './src/rendering/svgSetup.js';
import {
    prepareInitialRenderData,
    prepareFlowRenderData,
    performInitialRender,
    createRadiusScale
} from './src/rendering/initialRender.js';
import {
    createTimeArcsZoomHandler,
    createDurationLabelUpdater,
    clearZoomTimeouts,
    resetResolutionTransitionState
} from './src/interaction/timearcsZoomHandler.js';
import { createIPFilterController } from './src/interaction/ip-filter-controller.js';
import { CanvasFlowRenderer } from './src/rendering/canvas-flow-renderer.js';
import { WebGLFlowRenderer } from './src/rendering/webgl-flow-renderer.js';
import { tryLoadFlowList, getFlowListLoader } from './src/data/flow-list-loader.js';
import { PatternSearchEngine } from './src/search/pattern-search-engine.js';
import { initPatternSearchUI, showSearchProgress, hideSearchProgress, showSearchResults, clearSearchResults as clearSearchResultsUI } from './src/ui/pattern-search-panel.js';

// Multi-resolution support (optional - may not be available)
let getMultiResData = null;
let isMultiResAvailable = null;
let getCurrentResolution = null;
let setMultiResSelectedIPs = null;
let loadFlowDetailWithPackets = null;
let extractPacketsFromFlow = null;
let getChunkedFlowState = null;

// Try to dynamically import multi-resolution functions
try {
    const folderIntegration = await import('./folder_integration.js');
    getMultiResData = folderIntegration.getMultiResData;
    isMultiResAvailable = folderIntegration.isMultiResAvailable;
    getCurrentResolution = folderIntegration.getCurrentResolution;
    setMultiResSelectedIPs = folderIntegration.setMultiResSelectedIPs;
    loadFlowDetailWithPackets = folderIntegration.loadFlowDetailWithPackets;
    extractPacketsFromFlow = folderIntegration.extractPacketsFromFlow;
    getChunkedFlowState = folderIntegration.getChunkedFlowState;
    console.log('Multi-resolution support loaded');
} catch (err) {
    console.log('Multi-resolution support not available:', err.message);
}

// Multi-resolution state
let useMultiRes = false;  // Whether to use multi-resolution data
let currentResolutionLevel = null;  // Current resolution: 'seconds', 'milliseconds', 'raw', or null
let isInitialResolutionLoad = true;  // Only sync with overview on initial load, then allow free zoom
let manualResolutionOverride = null;  // User-selected resolution override (null = auto)

let defaultCollapseApplied = false;  // Auto-collapse all multi-pair IP rows on first render

// --- Web Worker for packet filtering ---
let workerManager = null;

function initializeWorkerManager() {
    workerManager = createPacketWorkerManager({
        onVisibilityApplied: (mask) => {
            if (!mainGroup) {
                console.warn('Worker visibility applied but mainGroup not available');
                return;
            }
            const dots = mainGroup.selectAll('.direction-dot').nodes();
            if (DEBUG && dots.length !== mask.length) {
                console.warn(`Worker mask/dots mismatch: mask=${mask.length}, dots=${dots.length}. This may indicate DOM was updated after worker init.`);
            }
            applyVisibilityToDots(mask, dots, {
                onComplete: () => {
                    try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); }
                }
            });
        },
        onError: (error) => {
            console.error('Worker error, falling back to legacy filtering:', error);
            legacyFilterPacketsBySelectedFlows();
        }
    });
}

// --- Error logging helper for catch blocks ---
// Provides consistent error logging with context for debugging
// Usage: catch(e) { logCatchError('functionName', e); }
function logCatchError(context, error) {
    if (DEBUG) {
        console.warn(`[${context}] Error caught:`, error?.message || error);
    }
}

function reinitializeWorkerIfNeeded(packets) {
    if (workerManager && packets) {
        try {
            workerManager.initPackets(packets);
        } catch (err) {
            console.error('Failed to reinitialize worker:', err);
            legacyFilterPacketsBySelectedFlows();
        }
    }
}

function syncWorkerWithRenderedData() {
    if (!workerManager || !mainGroup) return;
    
    // Get currently rendered dots data
    const dots = mainGroup.selectAll('.direction-dot');
    const renderedData = [];
    
    dots.each(function(d) {
        if (d) {
            // Extract the data bound to each DOM element
            renderedData.push({
                src_ip: d.src_ip,
                dst_ip: d.dst_ip,
                src_port: d.src_port,
                dst_port: d.dst_port,
                _packetIndex: renderedData.length // Use array index as packet index
            });
        }
    });
    
    if (renderedData.length > 0) {
        try {
            workerManager.initPackets(renderedData);
        } catch (err) {
            console.error('Failed to sync worker with rendered data:', err);
        }
    }
}
// state.data.full, state.data.filtered, state.data.isPreBinned moved to state.data (Phase 6)
let svg, mainGroup, width, height, xScale, yScale, zoom;
// Bottom overlay (fixed area above overview) for main x-axis and legends
let bottomOverlaySvg = null;
let bottomOverlayRoot = null;
let bottomOverlayAxisGroup = null;
let dualAxis = null;
let bottomOverlayDurationLabel = null;
let bottomOverlayWidth = 0;
let bottomOverlayHeight = 140; // generous to fit axis + legends without changing sizes
let chartMarginLeft = 180;
let chartMarginRight = 120;
// Layers for performance tuning: persistent full-domain layer and dynamic zoom layer
let fullDomainLayer = null;
let dynamicLayer = null;
// The element that has the zoom behavior attached (svg container)
let zoomTarget = null;
let dotsSelection; // Cache the dots selection for performance
        
// Overview timeline variables moved to overview_chart.js
let isHardResetInProgress = false; // Programmatic Reset View fast-path
// state.data.timeExtent moved to state.data (Phase 6)
// Global bin count is sourced from shared config.js
// pairs, state.layout.ipPositions, ipOrder moved to state.layout (Phase 4)

// TimeArcs integration variables moved to state.timearcs (Phase 3)

// Force layout variables moved to state.layout (Phase 4)
// Flow variables moved to state.flows (Phase 5)
// Global toggle state for invalid flow categories in legend
const hiddenInvalidReasons = new Set();
// Cache for IP filtered packet subsets (key: sorted IP list)
const filterCache = new Map();

// Cache for full-domain binned result to make Reset View fast (state.data.version moved to state.data)
let fullDomainBinsCache = { version: -1, data: [], binSize: null, sorted: false };
// Global radius scaling: anchor sizes across zooms
// - RADIUS_MIN: circle size for an individual packet (count = 1)
// - globalMaxBinCount: computed from the initial full-domain binning; reused at all zoom levels
let globalMaxBinCount = 1;

// useBinning and renderMode moved to state.ui (Phase 2)

// Consolidated state object for better organization
const state = {
    // Phase 1: Flow Detail Mode (isolated, ~20 refs)
    flowDetail: {
        mode: false,           // Whether we're in single-flow detail view
        flow: null,            // The flow object being viewed in detail
        packets: [],           // Extracted packets from the flow
        previousState: null    // State to restore when exiting flow detail mode
    },

    // Phase 2: UI Toggles (isolated, ~30 refs)
    ui: {
        showTcpFlows: true,      // Toggle for TCP flow visualization
        showEstablishment: true, // Toggle for establishment phase
        showDataTransfer: true,  // Toggle for data transfer phase
        showClosing: true,       // Toggle for closing phase
        showGroundTruth: false,  // Toggle for ground truth visualization
        useBinning: true,        // User toggle: binning on/off
        renderMode: 'flows',     // Default view mode: 'flows' (lozenges) or 'packets' (circles)
        separateFlags: false,    // Spread overlapping flag circles vertically
        showSubRowArcs: false,   // Show permanent ghost arcs for IP pair sub-rows
        showFlowThreading: true  // Auto-draw flow threading arcs at raw resolution
    },

    // Phase 3: TimeArcs Integration (isolated, ~50 refs)
    timearcs: {
        ipOrder: null,            // Array of IPs in vertical order from TimeArcs, or null
        timeRange: null,          // {minUs, maxUs} or null (microseconds)
        overviewTimeExtent: null, // [start, end] in data units, or null (falls back to state.data.timeExtent)
        intendedZoomDomain: null  // [start, end] in data units, persists zoom state
    },

    // Phase 4: Layout (medium coupling, ~70 refs)
    layout: {
        ipPositions: new Map(),   // Global IP positions map
        ipOrder: [],              // Current vertical order of IPs
        pairs: new Map(),         // Global pairs map for IP pairing system
        ipPairCounts: new Map(),  // Count of unique destination IPs per source IP
        ipRowHeights: new Map(),  // Per-IP row heights based on pair count
        ipConnectivity: new Map(), // Map<ip, Set<connectedIps>> for row highlighting
        collapsedIPs: new Set(),  // Set of IPs whose sub-rows are collapsed into one
        // IP row filter snapshots (saved after each full layout computation)
        basePositions: new Map(),      // Snapshot of ipPositions (unfiltered)
        baseRowHeights: new Map(),     // Snapshot of ipRowHeights (unfiltered)
        basePairOrderByRow: new Map(), // Snapshot of ipPairOrderByRow (unfiltered)
        activeIPs: null                // Set<ip> with connections in visible window, or null (= all)
    },

    // Phase 5: Flows (medium coupling, ~60 refs)
    flows: {
        tcp: [],                  // Store detected TCP flows (from CSV)
        current: [],              // Flows matching current IP selection (subset of tcp)
        selectedIds: new Set(),   // Store IDs of selected flows as strings
        groundTruth: []           // Store ground truth events
    },

    // Phase 6: Data (high coupling, ~130 refs)
    data: {
        full: [],                 // Full dataset
        filtered: [],             // Filtered dataset (by IP selection)
        isPreBinned: false,       // Track if data is already pre-binned (from multi-resolution)
        version: 0,               // Increment when filtered data changes
        timeExtent: [0, 0]        // Global time extent for the dataset
    },

    // Pattern search
    search: {
        active: false,            // True when results are applied to visualization
        engine: null,             // PatternSearchEngine instance
        results: null,            // SearchResults instance
        level: 1,                 // Active search level (1=Packet, 2=Phase, 3=Outcome)
        scope: 'selected',        // 'selected' | 'all'
        filterActive: false,      // When true, dim non-matching circles
        newlyAddedIPs: new Set()  // IPs added by "Select IPs" (gold-highlighted until cleared)
    },

    // Flow View mode data
    flowView: {
        binnedData: [],           // processed binned flow lozenges ready for rendering
        individualData: [],       // individual flow objects (Tier 2)
        resolution: null,         // current resolution level
        globalMaxCount: 1,        // max count across all bins (for hScale)
        tier: 'binned'            // 'binned' | 'individual'
    }
};

// Create canonical IP pair key (alphabetically ordered)
function makeIpPairKey(srcIp, dstIp) {
    if (!srcIp || !dstIp) return 'unknown';
    return srcIp < dstIp ? `${srcIp}<->${dstIp}` : `${dstIp}<->${srcIp}`;
}

/**
 * Save a snapshot of the current IP positioning into the layout state's
 * base* fields.  Call this after every full layout computation so the
 * zoom-based row filter always has a valid reference to restore from.
 *
 * @param {object} state - Global app state.
 */
function saveBasePositions(state) {
    state.layout.basePositions = new Map(state.layout.ipPositions);
    state.layout.baseRowHeights = new Map(state.layout.ipRowHeights);
    // Deep-copy ipPairOrderByRow (values contain their own Map).
    const copy = new Map();
    for (const [yPos, { order, count }] of state.layout.ipPairOrderByRow) {
        copy.set(yPos, { order: new Map(order), count });
    }
    state.layout.basePairOrderByRow = copy;
}

/**
 * Merge bins for collapsed IPs: bins at the same (time, yPos, flagType) from
 * different IP pairs are combined into a single bin with summed counts.
 * Only bins whose src_ip is in the collapsedIPs set are merged.
 */
function collapseSubRowsBins(binned, collapsedIPs) {
    if (!collapsedIPs || collapsedIPs.size === 0) return binned;
    const pass = [];     // bins for non-collapsed IPs (unchanged)
    const merge = [];    // bins for collapsed IPs (need merging)
    for (const d of binned) {
        if (d.src_ip && collapsedIPs.has(d.src_ip)) {
            merge.push(d);
        } else {
            pass.push(d);
        }
    }
    if (merge.length === 0) return binned;

    // Group by (src_ip | time | yPos | flagType)
    // src_ip is included to prevent merging items from different collapsed IPs
    // (flow bin items lack yPos until renderLozenges computes it, causing
    //  items from unrelated IPs to collide on the same merge key)
    const groups = new Map();
    for (const d of merge) {
        const t = Number.isFinite(d.binCenter) ? Math.floor(d.binCenter)
            : (Number.isFinite(d.binTimestamp) ? Math.floor(d.binTimestamp) : Math.floor(d.timestamp));
        const ft = d.flagType || 'OTHER';
        const key = `${d.src_ip}|${t}|${d.yPos}|${ft}`;
        let g = groups.get(key);
        if (!g) {
            g = {
                ...d,
                count: 0,
                totalBytes: 0,
                originalPackets: [],
                ipPairs: [],
                allIPs: new Set(),
                _seenPairs: new Set()
            };
            groups.set(key, g);
        }
        g.count += (d.count || 1);
        g.totalBytes = (g.totalBytes || 0) + (d.totalBytes || 0);
        if (Array.isArray(d.originalPackets)) {
            g.originalPackets.push(...d.originalPackets);
        }
        if (d.src_ip) g.allIPs.add(d.src_ip);
        if (d.dst_ip) g.allIPs.add(d.dst_ip);
        const pk = makeIpPairKey(d.src_ip, d.dst_ip);
        if (!g._seenPairs.has(pk)) {
            g._seenPairs.add(pk);
            g.ipPairs.push({ src_ip: d.src_ip, dst_ip: d.dst_ip, count: d.count || 1 });
        }
    }
    for (const g of groups.values()) {
        g.ipPairKey = '__collapsed__';
        delete g._seenPairs;
        pass.push(g);
    }
    return pass;
}

/**
 * Compute the maximum merged bin count per collapsed IP.
 * Mirrors the grouping logic of collapseSubRowsBins but only tracks max counts.
 * Used to update globalMaxBinCount and row heights for collapsed IPs.
 * @param {Array} binnedPackets - Binned packet data (pre-collapse)
 * @param {Set} collapsedIPs - Set of collapsed IP addresses
 * @returns {Object|null} { globalMax, maxPerIP: Map<string, number> } or null if no collapsed IPs
 */
function computeCollapsedMaxCounts(binnedPackets, collapsedIPs) {
    if (!collapsedIPs || collapsedIPs.size === 0) return null;
    const maxPerIP = new Map();
    const groups = new Map(); // key: "ip|time|flag" → count
    for (const d of binnedPackets) {
        if (!d.src_ip || !collapsedIPs.has(d.src_ip)) continue;
        const t = Number.isFinite(d.binCenter) ? Math.floor(d.binCenter)
            : (Number.isFinite(d.binTimestamp) ? Math.floor(d.binTimestamp) : Math.floor(d.timestamp));
        const ft = d.flagType || 'OTHER';
        const key = `${d.src_ip}|${t}|${ft}`;
        groups.set(key, (groups.get(key) || 0) + (d.count || 1));
    }
    let globalMax = 0;
    for (const [key, count] of groups) {
        const ip = key.split('|')[0];
        if (count > (maxPerIP.get(ip) || 0)) maxPerIP.set(ip, count);
        if (count > globalMax) globalMax = count;
    }
    return { globalMax, maxPerIP };
}

/**
 * Compute needed sub-row heights based on actual flag circle stacking.
 * For each (IP, pairKey) sub-row, finds the maximum sum-of-diameters
 * across all co-located flag groups at any time position.
 *
 * @param {Array} binnedPackets - Binned packet data (post-collapse)
 * @param {Function} rScale - Radius scale function
 * @returns {Map<string, number>} "ip|pairKey" → max needed sub-row height
 */
function computeFlagSeparationHeights(binnedPackets, rScale) {
    // Group by (src_ip, ipPairKey, timeKey) to find co-located flags
    const groups = new Map();
    for (const d of binnedPackets) {
        if (!d.src_ip || !d.dst_ip) continue;
        const ipPairKey = d.ipPairKey === '__collapsed__' ? '__collapsed__'
            : makeIpPairKey(d.src_ip, d.dst_ip);
        const tKey = Math.floor(
            d.binned && Number.isFinite(d.binCenter) ? d.binCenter
            : (Number.isFinite(d.binTimestamp) ? d.binTimestamp : d.timestamp)
        );
        const groupKey = `${d.src_ip}|${ipPairKey}|${tKey}`;
        if (!groups.has(groupKey)) groups.set(groupKey, []);
        groups.get(groupKey).push(d);
    }

    // For each (IP, pairKey) sub-row, find the max sum-of-diameters
    const perSubRowHeight = new Map(); // "ip|pairKey" → max height needed
    for (const group of groups.values()) {
        if (group.length <= 1) continue;
        const ip = group[0].src_ip;
        const ipPairKey = group[0].ipPairKey === '__collapsed__' ? '__collapsed__'
            : makeIpPairKey(group[0].src_ip, group[0].dst_ip);
        const subRowKey = `${ip}|${ipPairKey}`;
        let totalDiameters = 0;
        for (const d of group) {
            const r = d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN;
            totalDiameters += 2 * r;
        }
        const current = perSubRowHeight.get(subRowKey) || SUB_ROW_HEIGHT;
        if (totalDiameters > current) {
            perSubRowHeight.set(subRowKey, totalDiameters);
        }
    }
    return perSubRowHeight;
}

/**
 * Compute per-sub-row Y offsets and IP row heights from per-sub-row stacking heights.
 * Each sub-row gets exactly the height it needs, and the offset is cumulative so
 * sub-rows with different heights pack tightly.
 *
 * @param {Map<string, number>} perSubRowHeight - "ip|pairKey" → needed height
 * @param {Map<number, {order: Map, count: number}>} ipPairOrderByRow
 * @param {Map<string, number>} ipPositions - IP → baseY
 * @param {Array<string>} ipOrder
 * @param {Set<string>} collapsedIPs
 * @returns {{ subRowOffsets: Map<string, number>, subRowHeights: Map<string, number>, ipRowHeightUpdates: Map<string, number> }}
 */
function computeSubRowLayout(perSubRowHeight, ipPairOrderByRow, ipPositions, ipOrder, collapsedIPs) {
    const subRowOffsets = new Map();   // "ip|pairKey" → Y offset from baseY
    const subRowHeights = new Map();   // "ip|pairKey" → effective height
    const ipRowHeightUpdates = new Map();

    for (const ip of ipOrder) {
        if (collapsedIPs && collapsedIPs.has(ip)) continue;

        const baseY = ipPositions.get(ip);
        if (baseY === undefined) continue;

        const pairInfo = ipPairOrderByRow.get(baseY);
        if (!pairInfo) continue;

        // Sort sub-rows by their pair index (stable ordering)
        const sortedPairs = [...pairInfo.order.entries()].sort((a, b) => a[1] - b[1]);

        let prevCenter = 0;
        let prevHalfH = 0;
        let firstH = 0;

        for (let i = 0; i < sortedPairs.length; i++) {
            const [pairKey] = sortedPairs[i];
            const key = `${ip}|${pairKey}`;
            const h = Math.max(SUB_ROW_HEIGHT, perSubRowHeight.get(key) || SUB_ROW_HEIGHT);
            subRowHeights.set(key, h);

            if (i === 0) {
                subRowOffsets.set(key, 0);
                prevCenter = 0;
                prevHalfH = h / 2;
                firstH = h;
            } else {
                // Place this sub-row so the gap between it and the previous is SUB_ROW_GAP
                const center = prevCenter + prevHalfH + SUB_ROW_GAP + h / 2;
                subRowOffsets.set(key, center);
                prevCenter = center;
                prevHalfH = h / 2;
            }
        }

        // Total row height: from top of first sub-row to bottom of last + padding
        if (sortedPairs.length > 0) {
            const totalHeight = firstH / 2 + prevCenter + prevHalfH + SUB_ROW_GAP;
            const neededRowHeight = Math.max(ROW_GAP, totalHeight);
            ipRowHeightUpdates.set(ip, neededRowHeight);
        }
    }

    return { subRowOffsets, subRowHeights, ipRowHeightUpdates };
}

/**
 * Apply collapse overrides to ipPairOrderByRow for collapsed IPs.
 * All pairs for a collapsed IP get index 0, count 1.
 */
function applyCollapseOverrides(ipPairOrderByRow) {
    if (!state.layout.collapsedIPs.size) return;
    for (const ip of state.layout.collapsedIPs) {
        const yPos = state.layout.ipPositions.get(ip);
        if (yPos === undefined) continue;
        const pairInfo = ipPairOrderByRow.get(yPos);
        if (pairInfo) {
            const collapsedOrder = new Map();
            for (const key of pairInfo.order.keys()) collapsedOrder.set(key, 0);
            ipPairOrderByRow.set(yPos, { order: collapsedOrder, count: 1 });
        }
    }
}

/**
 * Create or update the sticky "Expand/Collapse All" sub-row button.
 * Uses CSS `position: sticky` to stay visible at the top while scrolling.
 * Called after renderIPRowLabels on each render.
 * @param {number} marginTop - The chart's top margin (px)
 */
function createOrUpdateExpandAllBtn(marginTop) {
    const container = document.getElementById('chart-container');
    if (!container) return;

    // Only show when multi-pair IPs exist
    let hasMultiPairIPs = false;
    if (state.layout.ipPairCounts) {
        for (const [, count] of state.layout.ipPairCounts) {
            if (count > 1) { hasMultiPairIPs = true; break; }
        }
    }

    let btn = document.getElementById('expand-all-btn');
    if (!btn) {
        btn = document.createElement('div');
        btn.id = 'expand-all-btn';
        // Insert as first child so sticky positioning works from the top
        container.insertBefore(btn, container.firstChild);

        btn.addEventListener('click', () => {
            if (state.layout.collapsedIPs.size > 0) {
                // Expand all
                state.layout.collapsedIPs.clear();
            } else {
                // Collapse all
                for (const ip of state.layout.ipOrder) {
                    if ((state.layout.ipPairCounts.get(ip) || 1) > 1) {
                        state.layout.collapsedIPs.add(ip);
                    }
                }
            }
            const savedDomain = xScale ? xScale.domain().slice() : null;
            isHardResetInProgress = true;
            visualizeTimeArcs(state.data.filtered);
            updateTcpFlowPacketsGlobal();
            drawSelectedFlowArcs();
            applyInvalidReasonFilter();
            if (savedDomain && xScale && (savedDomain[0] !== state.data.timeExtent[0] || savedDomain[1] !== state.data.timeExtent[1])) {
                applyZoomDomain(savedDomain, 'program');
            }
        });
    }

    btn.style.display = hasMultiPairIPs ? '' : 'none';
    if (!hasMultiPairIPs) return;

    // Visual state: collapsed → gray + right chevron; expanded → green + down chevron
    const isCollapsedState = state.layout.collapsedIPs.size > 0;
    const fill = isCollapsedState ? '#6c757d' : '#28a745';
    const hoverFill = isCollapsedState ? '#5a6268' : '#218838';
    const chevron = isCollapsedState
        ? 'M -2 -3 L 2 0 L -2 3'   // right chevron (collapsed state)
        : 'M -3 -2 L 0 2 L 3 -2';  // down chevron (expanded state)
    const label = isCollapsedState ? 'Expand All' : 'Collapse All';
    const title = isCollapsedState ? 'Expand all sub-rows' : 'Collapse all sub-rows';

    btn.title = title;
    const pillW = isCollapsedState ? 96 : 106;
    btn.innerHTML = `
        <svg width="${pillW}" height="24" viewBox="0 0 ${pillW} 24" style="display:block;">
            <rect rx="12" ry="12" width="${pillW}" height="24" fill="${fill}"
                  stroke="#fff" stroke-width="1.5" style="transition: fill 0.2s ease;"/>
            <g transform="translate(14, 12)">
                <path d="${chevron}" fill="none" stroke="#fff" stroke-width="2"
                      stroke-linecap="round" stroke-linejoin="round"/>
            </g>
            <text x="26" y="16.5" fill="#fff" font-size="12" font-weight="600"
                  font-family="system-ui, -apple-system, sans-serif">${label}</text>
        </svg>`;

    // Hover effect on the pill background
    btn.onmouseenter = () => {
        const rect = btn.querySelector('rect');
        if (rect) rect.setAttribute('fill', hoverFill);
    };
    btn.onmouseleave = () => {
        const rect = btn.querySelector('rect');
        if (rect) rect.setAttribute('fill', fill);
    };
}

/**
 * Compute y position for an IP accounting for sub-row offset within an expanded row.
 * Falls back to base ipPositions when sub-row data is unavailable.
 */
function getIPYWithSubRowOffset(ip, srcIp, dstIp) {
    const baseY = findIPPosition(ip, srcIp, dstIp, state.layout.pairs, state.layout.ipPositions);
    if (!baseY || !state.layout.ipPairOrderByRow) return baseY;
    const pairKey = makeIpPairKey(srcIp, dstIp);
    const pairInfo = state.layout.ipPairOrderByRow.get(baseY);
    if (!pairInfo || pairInfo.count <= 1) return baseY;
    const pairIndex = pairInfo.order.get(pairKey) || 0;
    // Use precomputed offset when available (per-sub-row variable heights)
    const offsetKey = `${ip}|${pairKey}`;
    const offset = state.layout.subRowOffsets && state.layout.subRowOffsets.get(offsetKey);
    return baseY + (offset ?? pairIndex * (SUB_ROW_HEIGHT + SUB_ROW_GAP));
}

/**
 * Build a position lookup from rendered DOM circles.
 * This accounts for both sub-row offsets AND flag separation — the single
 * source of truth for where circles actually appear on screen.
 * Returns { exact: Map, byRow: Map } where:
 *   exact: `${time}|${src_ip}|${dst_ip}|${flagType}` → yPosWithOffset
 *   byRow:  `${time}|${src_ip}|${flagType}` → yPosWithOffset (fallback for collapsed rows)
 */
function buildCirclePositionMap() {
    const exact = new Map();
    const byRow = new Map();
    const activeLayer = (dynamicLayer && dynamicLayer.style('display') !== 'none' && !dynamicLayer.selectAll('.direction-dot').empty())
        ? dynamicLayer
        : fullDomainLayer;
    if (!activeLayer) return { exact, byRow };

    activeLayer.selectAll('.direction-dot').each(function () {
        const d = d3.select(this).datum();
        if (!d || !d.src_ip) return;
        const time = Math.floor(d.binCenter ?? d.timestamp ?? 0);
        const flagType = d.flagType || d.flag_type || getFlagType(d);
        const yPos = d.yPosWithOffset;
        if (yPos == null) return;

        // For collapsed circles, register every merged IP pair
        const pairs = (d.ipPairKey === '__collapsed__' && Array.isArray(d.ipPairs))
            ? d.ipPairs
            : [{ src_ip: d.src_ip, dst_ip: d.dst_ip }];

        for (const p of pairs) {
            if (p.dst_ip) {
                exact.set(`${time}|${d.src_ip}|${p.dst_ip}|${flagType}`, yPos);
            }
        }

        // Row-level fallback (first circle wins — all collapsed circles share yPos)
        const rowKey = `${time}|${d.src_ip}|${flagType}`;
        if (!byRow.has(rowKey)) byRow.set(rowKey, yPos);
    });

    return { exact, byRow };
}

/**
 * Look up the actual rendered y-position for a packet using the circle position map.
 * Falls back to getIPYWithSubRowOffset() when no matching circle is in the DOM.
 */
function lookupCircleY(circlePosMap, time, srcIp, dstIp, flagType) {
    const t = Math.floor(time);
    return circlePosMap.exact.get(`${t}|${srcIp}|${dstIp}|${flagType}`)
        ?? circlePosMap.byRow.get(`${t}|${srcIp}|${flagType}`)
        ?? getIPYWithSubRowOffset(srcIp, srcIp, dstIp);
}

/**
 * Sync sub-row-highlight rect positions with current state.layout.
 * Called after any position recalculation (collapse adjustment, drag reorder).
 */
function syncSubRowHighlights(svgEl, st) {
    svgEl.selectAll('.sub-row-highlight, .sub-row-hover-target').each(function() {
        const rect = d3.select(this);
        const d = rect.datum();
        if (!d || !d.ip) return;
        const baseY = st.layout.ipPositions.get(d.ip);
        if (baseY === undefined) return;
        // Use precomputed per-sub-row offset and height
        const offsetKey = `${d.ip}|${d.pairKey}`;
        const offset = st.layout.subRowOffsets && st.layout.subRowOffsets.get(offsetKey);
        const centerY = baseY + (offset ?? d.pairIndex * (SUB_ROW_HEIGHT + SUB_ROW_GAP));
        const heightKey = `${d.ip}|${d.pairKey}`;
        const effectiveSRH = (st.layout.subRowHeights && st.layout.subRowHeights.get(heightKey)) || SUB_ROW_HEIGHT;
        rect.attr('y', centerY - effectiveSRH / 2)
            .attr('height', effectiveSRH);
    });
}

// Circle hover: highlight source/destination IP rows and labels
function onCircleHighlight(srcIp, dstIps) {
    // Bold source label, mark destination labels, fade others
    svg.selectAll('.node-label')
        .classed('highlighted', d => d === srcIp)
        .classed('connected', d => dstIps.has(d))
        .classed('faded', d => d !== srcIp && !dstIps.has(d));
}

function onCircleClearHighlight() {
    svg.selectAll('.node-label')
        .classed('highlighted', false)
        .classed('connected', false)
        .classed('faded', false);
}

// Wrapper to call imported renderCircles with required options and event handlers
function renderCirclesWithOptions(layer, binned, rScale, transitionOpts) {
    const data = collapseSubRowsBins(binned, state.layout.collapsedIPs);
    const processed = renderCircles(layer, data, {
        xScale,
        rScale,
        flagColors,
        RADIUS_MIN,
        ROW_GAP,
        ipRowHeights: state.layout.ipRowHeights,
        ipPairCounts: state.layout.ipPairCounts,
        stableIpPairOrderByRow: state.layout.ipPairOrderByRow,
        subRowHeights: state.layout.subRowHeights,
        subRowOffsets: state.layout.subRowOffsets,
        mainGroup,
        arcPathGenerator,
        findIPPosition,
        pairs: state.layout.pairs,
        ipPositions: state.layout.ipPositions,
        createTooltipHTML,
        FLAG_CURVATURE,
        d3,
        separateFlags: state.ui.separateFlags,
        onCircleHighlight,
        onCircleClearHighlight,
        transitionOpts
    });

    // Apply search highlight classes after circles are rendered
    if (state.search && (state.search.active || state.search.newlyAddedIPs.size > 0)) {
        applySearchHighlightClasses();
    }
}

// Wrapper to call imported renderLozenges with required options.
function renderLozengesWithOptions(layer, flowData, transitionOpts) {
    if (!flowData || flowData.length === 0) {
        if (layer) layer.selectAll('.flow-lozenge').remove();
        return;
    }

    const chartContainer = document.getElementById('chart-container');
    const scrollTop = chartContainer ? chartContainer.scrollTop : 0;
    const viewportH = chartContainer ? chartContainer.clientHeight : 800;

    // Alias flow fields so collapseSubRowsBins can operate on them:
    // it checks d.src_ip for collapse and groups by d.flagType
    const aliased = flowData.map(d => ({
        ...d,
        src_ip: d.initiator,
        dst_ip: d.responder,
        flagType: d.closeType
    }));
    const data = collapseSubRowsBins(aliased, state.layout.collapsedIPs);

    const maxCount = state.flowView.globalMaxCount || 1;
    const hScale = d3.scaleSqrt()
        .domain([1, Math.max(1, maxCount)])
        .range([LOZENGE_MIN_HEIGHT, LOZENGE_MAX_HEIGHT]);

    // Build flowColorMap from the loaded flowColors object
    const colorMap = new Map();
    if (flowColors.closing) {
        for (const [k, v] of Object.entries(flowColors.closing)) colorMap.set(k, v);
    }
    if (flowColors.ongoing) {
        for (const [k, v] of Object.entries(flowColors.ongoing)) colorMap.set(k, v);
    }
    if (flowColors.invalid) {
        for (const [k, v] of Object.entries(flowColors.invalid)) colorMap.set(k, v);
    }

    // When the main WebGL renderer is active, skipSvgRects:true suppresses SVG rect
    // creation; renderLozenges still computes yPosWithOffset for every item so we
    // can hand the result to the WebGL renderer.
    const useMainWebGL = !!mainWebGLRenderer;
    const processed = renderLozenges(layer, data, {
        xScale,
        hScale,
        flowColorMap: colorMap,
        LOZENGE_MIN_HEIGHT,
        LOZENGE_MAX_HEIGHT,
        LOZENGE_MIN_WIDTH,
        ROW_GAP,
        ipRowHeights: state.layout.ipRowHeights,
        ipPairCounts: state.layout.ipPairCounts,
        stableIpPairOrderByRow: state.layout.ipPairOrderByRow,
        subRowHeights: state.layout.subRowHeights,
        subRowOffsets: state.layout.subRowOffsets,
        mainGroup,
        findIPPosition,
        ipPositions: state.layout.ipPositions,
        createTooltipHTML: createFlowLozengeTooltipHTML,
        d3,
        CLOSE_TYPE_STACK_ORDER,
        separateFlags: state.ui.separateFlags,
        onLozengeHighlight: onCircleHighlight,
        onLozengeClearHighlight: onCircleClearHighlight,
        transitionOpts,
        skipSvgRects: useMainWebGL
    });

    // Feed processed items (with yPosWithOffset) to the main WebGL renderer.
    if (useMainWebGL && processed && processed.length > 0) {
        try {
            mainWebGLRenderer.setData(processed, colorMap, hScale, {
                minHeight: LOZENGE_MIN_HEIGHT,
                maxHeight: LOZENGE_MAX_HEIGHT
            });
            mainWebGLRenderer.render(xScale, scrollTop, viewportH);
        } catch (e) { console.warn('[MainWebGL] render failed', e); }
    }

}

// Create tooltip HTML for flow lozenge
function createFlowLozengeTooltipHTML(d) {
    const closeType = d.closeType || 'unknown';
    const count = d.count || 1;
    const lines = [`<strong>${closeType}</strong>`];
    if (d.clustered && count > 1) {
        lines.push(`${count} flows clustered`);
    } else if (d.binned && count > 1) {
        lines.push(`Count: ${count} flows`);
    }
    if (d.initiator) lines.push(`From: ${d.initiator}`);
    if (d.responder) lines.push(`To: ${d.responder}`);
    if (d.binStart && d.binEnd) {
        lines.push(`Time: ${formatTimestamp(d.binStart).utcTime} — ${formatTimestamp(d.binEnd).utcTime}`);
    } else if (d.startTime) {
        lines.push(`Start: ${formatTimestamp(d.startTime).utcTime}`);
        if (d.endTime && d.endTime !== d.startTime) {
            lines.push(`End: ${formatTimestamp(d.endTime).utcTime}`);
            lines.push(`Duration: ${formatDuration(d.endTime - d.startTime)}`);
        }
    }
    if (d.totalPackets) lines.push(`Packets: ${d.totalPackets}`);
    return lines.join('<br>');
}

// Load flow bin data from AdaptiveOverviewLoader for the flow lozenge view
async function loadFlowViewData() {
    if (!adaptiveOverviewLoader || !adaptiveOverviewLoader.index) {
        console.warn('[FlowView] No adaptive overview loader available');
        state.flowView.binnedData = [];
        return;
    }

    let selectedIPs = Array.from(
        document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')
    ).map(cb => cb.value);

    const timeExtent = state.data.timeExtent;

    // Load all IP pairs when time range is <= 90 minutes
    if (timeExtent && timeExtent[1] > timeExtent[0]) {
        const timeRangeUs = timeExtent[1] - timeExtent[0];
        if (timeRangeUs > 0 && timeRangeUs <= ALL_IP_PAIRS_TIME_THRESHOLD_US) {
            const allIPs = getAllFlowDataIPs();
            if (allIPs && allIPs.length >= 2) {
                console.log(`[FlowView] Time range ${(timeRangeUs / 60_000_000).toFixed(1)} min <= 90 min — using all ${allIPs.length} IPs`);
                selectedIPs = allIPs;
            }
        }
    }

    if (selectedIPs.length < 2) {
        state.flowView.binnedData = [];
        state.flowView.globalMaxCount = 1;
        return;
    }

    if (!timeExtent || timeExtent[0] >= timeExtent[1]) {
        state.flowView.binnedData = [];
        return;
    }

    try {
        const result = await adaptiveOverviewLoader.getFlowBinsByPair(
            selectedIPs, timeExtent[0], timeExtent[1]
        );
        state.flowView.binnedData = result.items;
        state.flowView.globalMaxCount = result.globalMaxCount;
        state.flowView.resolution = result.resolution;
        state.flowView.tier = 'binned';
        if (flowZoomManager) flowZoomManager.invalidateCache();
        console.log(`[FlowView] Loaded ${result.items.length} flow bin items at ${result.resolution} resolution`);
    } catch (err) {
        console.error('[FlowView] Failed to load flow bin data:', err);
        state.flowView.binnedData = [];
    }
}

// Callback for FlowZoomManager: re-render after individual flow CSVs finish loading.
// Triggers a programmatic zoom to the current domain, which re-enters the zoom handler
// and runs through the full pipeline (render + row filter + indicator update).
function _onFlowZoomDataLoaded(result) {
    if (state.ui.renderMode !== 'flows') return;
    state.flowView.binnedData = result.items;
    state.flowView.globalMaxCount = result.globalMaxCount;
    state.flowView.resolution = result.resolution;
    state.flowView.tier = result.tier;
    // Nudge the zoom handler by re-applying the current domain
    if (typeof applyZoomDomain === 'function') {
        try {
            const xDomain = window.__arc_x_domain__;
            if (xDomain) applyZoomDomain(xDomain, 'program');
        } catch (e) { console.warn('[FlowView] Re-zoom after load failed:', e); }
    }
}

// Handle switching between Packets and Flows view modes
async function switchViewMode(mode, { force = false } = {}) {
    if (!force && mode === state.ui.renderMode) return;
    state.ui.renderMode = mode;
    console.log(`[ViewMode] Switching to ${mode}${force ? ' (forced)' : ''}`);

    if (mode === 'flows') {
        // Clear circle and bar elements from packet view
        if (fullDomainLayer) {
            fullDomainLayer.selectAll('.direction-dot').remove();
            fullDomainLayer.selectAll('.bin-bar-segment').remove();
            fullDomainLayer.selectAll('.bin-stack').remove();
        }
        if (dynamicLayer) {
            dynamicLayer.selectAll('.direction-dot').remove();
            dynamicLayer.selectAll('.bin-bar-segment').remove();
            dynamicLayer.selectAll('.bin-stack').remove();
        }
        // Trigger zoom handler — FlowZoomManager handles all data loading
        const xDomain = window.__arc_x_domain__;
        if (flowZoomManager && xDomain) {
            applyZoomDomain(xDomain, 'program');
        } else {
            // Fallback: load binned data for initial render
            await loadFlowViewData();
            renderMarksForLayerLocal(fullDomainLayer, null, null);
        }
    } else {
        // Clear lozenge sub-row label remnants (rects are WebGL — no SVG to remove)
        if (fullDomainLayer) fullDomainLayer.selectAll('.sub-row-ip-label').remove();
        if (dynamicLayer) dynamicLayer.selectAll('.sub-row-ip-label').remove();

        // Lazy-load packet data the first time the user switches to packet view
        if (!state.data.full || state.data.full.length === 0) {
            console.log('[ViewMode] Packet data not loaded yet — loading now...');
            await loadFromPath(DEFAULT_DATA_PATH);
        }

        // Re-render circles from cached data
        if (fullDomainBinsCache && fullDomainBinsCache.data) {
            const rScale = d3.scaleSqrt()
                .domain([1, Math.max(1, globalMaxBinCount)])
                .range([RADIUS_MIN, RADIUS_MAX]);
            renderMarksForLayerLocal(fullDomainLayer, fullDomainBinsCache.data, rScale);
        }
    }

    // Toggle visibility of packet-specific controls
    const packetOnlyControls = document.querySelectorAll('#showSubRowArcs, #showFlowThreading');
    packetOnlyControls.forEach(el => {
        const label = el.closest('label');
        if (label) label.style.display = mode === 'flows' ? 'none' : '';
    });


    // Swap flag legend for flow close-type legend (or vice versa)
    const flagStatsEl = document.getElementById('flagStats');
    const sizeLegendEl = document.getElementById('sizeLegend');
    if (mode === 'flows') {
        // Replace flag legend with flow close-type legend
        if (flagStatsEl) {
            flagStatsEl.setAttribute('data-original-label', flagStatsEl.previousElementSibling?.textContent || '');
            const label = flagStatsEl.previousElementSibling;
            if (label && label.tagName === 'LABEL') label.textContent = 'Flow Types';
            flagStatsEl.innerHTML = buildFlowTypeLegendHTML();
        }
        if (sizeLegendEl) {
            sizeLegendEl.previousElementSibling.textContent = 'Flow Count';
            sizeLegendEl.innerHTML = '<div style="color: #666; font-size: 11px;">Lozenge height = flow count</div>';
        }
    } else {
        // Restore original flag legend
        if (flagStatsEl) {
            const label = flagStatsEl.previousElementSibling;
            if (label && label.tagName === 'LABEL') label.textContent = flagStatsEl.getAttribute('data-original-label') || 'TCP Flags';
            // Trigger re-render of flag stats
            if (typeof updateFlagStats === 'function' && state.data.filtered.length > 0) {
                updateFlagStats(state.data.filtered);
            }
        }
        if (sizeLegendEl) {
            sizeLegendEl.previousElementSibling.textContent = 'Packet Count';
            drawSizeLegend();
        }
    }
}

// Unified render function
function renderMarksForLayerLocal(layer, data, rScale, transitionOpts) {
    if (state.ui.renderMode === 'flows') {
        return renderLozengesWithOptions(layer, state.flowView.binnedData, transitionOpts);
    }
    return renderCirclesWithOptions(layer, data, rScale, transitionOpts);
}

// Size legend moved to control panel; update it there
function drawSizeLegend() {
    sbUpdateSizeLegend(globalMaxBinCount, RADIUS_MIN, RADIUS_MAX);
}

// Flag color legend moved to control panel; no-op here to keep call sites intact
function drawFlagLegend() {}

// Build HTML for flow close-type legend (used when in Flows view mode)
function buildFlowTypeLegendHTML() {
    // Build color map from flowColors
    const entries = [];
    if (flowColors.closing) {
        for (const [name, color] of Object.entries(flowColors.closing)) {
            entries.push({ name, color, category: 'Closing' });
        }
    }
    if (flowColors.ongoing) {
        for (const [name, color] of Object.entries(flowColors.ongoing)) {
            entries.push({ name, color, category: 'Ongoing' });
        }
    }
    if (flowColors.invalid) {
        for (const [name, color] of Object.entries(flowColors.invalid)) {
            entries.push({ name, color, category: 'Invalid' });
        }
    }

    if (entries.length === 0) {
        return '<div style="color: #666;">No flow colors loaded</div>';
    }

    let html = '';
    let lastCategory = '';
    for (const { name, color, category } of entries) {
        if (category !== lastCategory) {
            if (lastCategory) html += '<div style="margin-top: 4px;"></div>';
            html += `<div style="font-size: 10px; color: #999; margin-bottom: 2px;">${category}</div>`;
            lastCategory = category;
        }
        const displayName = name.replace(/_/g, ' ');
        html += `<div style="display: flex; align-items: center; margin-bottom: 2px;">
            <span style="display: inline-block; width: 14px; height: 8px; border-radius: 4px; background: ${color}; margin-right: 6px; flex-shrink: 0;"></span>
            <span style="font-size: 11px;">${displayName}</span>
        </div>`;
    }
    return html;
}

// TCP flag colors, now loaded from flag_colors.json with defaults
let flagColors = { ...DEFAULT_FLAG_COLORS };
// Flow-related colors (closing types and invalid reasons) loaded from flow_colors.json
let flowColors = {
    closing: {
        graceful: '#8e44ad',
        abortive: '#c0392b'
    },
    ongoing: {
        open: '#6c757d',
        incomplete: '#adb5bd'
    },
    invalid: {
        // Optional overrides; default invalid reason colors derive from flagColors
    }
};

// Load color mapping for ground truth events
let eventColors = {};
fetch('color_mapping.json')
    .then(response => response.json())
    .then(colors => {
        eventColors = colors;
        LOG('Loaded event colors:', eventColors);
    })
    .catch(error => {
        console.warn('Could not load color_mapping.json:', error);
        // Use default colors if file not found
        eventColors = {
            'normal': '#4B4B4B',
            'client compromise': '#D41159',
            'malware ddos': '#2A9D4F',
            'scan /usr/bin/nmap': '#C9A200',
            'ddos': '#264D99'
        };
    });

// Load colors for flags from external JSON, merging into the existing object
fetch('flag_colors.json')
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
    .then(colors => {
        Object.assign(flagColors, colors);
        LOG('Loaded flag colors:', flagColors);
        try { drawFlagLegend(); } catch(e) { logCatchError('drawFlagLegend', e); }
    })
    .catch(err => {
        console.warn('Could not load flag_colors.json:', err);
        // keep defaults in flagColors
    });

// Load colors for flows (closing + invalid) from external JSON, deep-merge
fetch('flow_colors.json')
    .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
    .then(colors => {
        try {
            if (colors && typeof colors === 'object') {
                if (colors.closing && typeof colors.closing === 'object') {
                    flowColors.closing = { ...flowColors.closing, ...colors.closing };
                }
                if (colors.invalid && typeof colors.invalid === 'object') {
                    flowColors.invalid = { ...flowColors.invalid, ...colors.invalid };
                }
                if (colors.ongoing && typeof colors.ongoing === 'object') {
                    flowColors.ongoing = { ...flowColors.ongoing, ...colors.ongoing };
                }
            }
            LOG('Loaded flow colors:', flowColors);
        } catch (e) { console.warn('Merging flow_colors.json failed:', e); }
    })
    .catch(err => {
        console.warn('Could not load flow_colors.json:', err);
        // keep defaults in flowColors
    });

// Initialization function for the bar diagram module
function initializeBarVisualization() {
    // Seed `width` from the chart container so any early-running render (overview
    // refresh triggered before visualizeData runs) gets a real number. visualizeData
    // later overwrites this with the exact margin-adjusted value.
    try {
        const chartEl = document.getElementById('chart-container');
        if (chartEl && chartEl.clientWidth > 0) {
            const leftMargin = 180, rightMargin = 120;
            width = Math.max(100, chartEl.clientWidth - leftMargin - rightMargin);
        } else {
            width = 800; // conservative fallback
        }
    } catch (e) {
        width = 800;
    }

    // Initialize overview module with references
    initOverview({
        d3,
        applyZoomDomain: (domain, source) => applyZoomDomain(domain, source),
        getWidth: () => width,
        getTimeExtent: () => {
            const result = state.timearcs.overviewTimeExtent || flowDataState?.timeExtent || state.data.timeExtent;
            console.log('[getTimeExtent] Returning:', result, '| state.timearcs.overviewTimeExtent:', state.timearcs.overviewTimeExtent, '| flowDataState?.timeExtent:', flowDataState?.timeExtent, '| timeExtent:', state.data.timeExtent);
            return result;
        },
        getCurrentDomain: () => {
            // Return current xScale domain, with state.timearcs.intendedZoomDomain as fallback
            // This handles race conditions where zoom hasn't been applied yet
            const current = xScale ? xScale.domain() : null;
            if (current && current[0] !== undefined && current[1] !== undefined) {
                // Check if at full extent - if so, prefer state.timearcs.intendedZoomDomain
                const atFullExtent = state.data.timeExtent &&
                    Math.abs(current[0] - state.data.timeExtent[0]) < 1 &&
                    Math.abs(current[1] - state.data.timeExtent[1]) < 1;
                if (atFullExtent && state.timearcs.intendedZoomDomain) {
                    return state.timearcs.intendedZoomDomain;
                }
                return current;
            }
            return state.timearcs.intendedZoomDomain || current;
        },
        getOverviewTimeExtent: () => state.timearcs.overviewTimeExtent, // TimeArcs range or null
        getCurrentFlows: () => state.flows.current,
        getSelectedFlowIds: () => state.flows.selectedIds,
        updateTcpFlowPacketsGlobal: () => updateTcpFlowPacketsGlobal(),
        createFlowList: (flows) => createFlowList(flows),
        // Load flows for a given time range (async, prefers FlowListLoader CSV files when available)
        loadChunksForTimeRange: async (startTime, endTime) => {
            const state = getFlowDataState();

            // Get currently selected IPs to filter flows
            let selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked'))
                .map(cb => cb.value);

            // Bypass IP filtering when time range is <= 90 minutes (load all IP pairs)
            const timeRangeUs = endTime - startTime;
            const loadAll = timeRangeUs > 0 && timeRangeUs <= ALL_IP_PAIRS_TIME_THRESHOLD_US;
            if (loadAll) {
                const allIPs = getAllFlowDataIPs();
                if (allIPs) {
                    console.log(`[loadChunksForTimeRange] Time range ${(timeRangeUs / 60_000_000).toFixed(1)} min <= 90 min — using all ${allIPs.length} IPs`);
                    selectedIPs = allIPs;
                }
            }

            // Try FlowListLoader first (loads from CSV files - works without chunk files)
            const flowListLoader = getFlowListLoader();
            if (flowListLoader.isLoaded()) {
                console.log(`[loadChunksForTimeRange] Using FlowListLoader CSV for ${selectedIPs.length} IPs, time: ${startTime}-${endTime}`);
                const flows = await flowListLoader.filterByIPs(selectedIPs, [startTime, endTime]);
                console.log(`[loadChunksForTimeRange] FlowListLoader returned ${flows.length} flows`);
                return flows;
            }

            // Fall back to chunked flows loader (null IPs = load all for short ranges)
            if (state && typeof state.loadChunksForTimeRange === 'function') {
                return await state.loadChunksForTimeRange(startTime, endTime, loadAll ? null : selectedIPs);
            }
            if (state && typeof state.loadFlowsForTimeRange === 'function') {
                const result = await state.loadFlowsForTimeRange(startTime, endTime);
                // For multires, filter by selected IPs here since the function doesn't support it
                if (result && !loadAll && selectedIPs.length > 0) {
                    const selectedIPSet = new Set(selectedIPs);
                    return result.filter(f =>
                        selectedIPSet.has(f.initiator) && selectedIPSet.has(f.responder)
                    );
                }
                return result;
            }
            return [];
        },
        sbRenderInvalidLegend: (panel, html, title) => sbRenderInvalidLegend(panel, html, title),
        sbRenderClosingLegend: (panel, html, title) => sbRenderClosingLegend(panel, html, title),
        makeConnectionKey: (a,b,c,d) => makeConnectionKey(a,b,c,d),
        // Allow overview legend toggles to affect the arc graph immediately
        applyInvalidReasonFilter: () => applyInvalidReasonFilter(),
        hiddenInvalidReasons,
        hiddenCloseTypes,
        flagColors,
        flowColors
    });
    initControlPanel({
        onResetView: () => {
            if (state.data.full.length > 0 && zoomTarget && zoom && state.data.timeExtent && state.data.timeExtent[1] > state.data.timeExtent[0]) {
                isHardResetInProgress = true;
                applyZoomDomain([state.data.timeExtent[0], state.data.timeExtent[1]], 'reset');
                if (state.ui.showTcpFlows && state.flows.selectedIds && state.flows.selectedIds.size > 0) {
                    try { setTimeout(() => redrawSelectedFlowsView(), 0); } catch(e) { logCatchError('redrawSelectedFlowsView', e); }
                }
            }
        }
    });
    // Delegate control panel event wiring
    sbWireControlPanelControls({
        onIpSearch: (term) => sbFilterIPList(term),
        onSelectAllIPs: () => { document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = true); updateIPFilter(); },
        onClearAllIPs: () => { document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = false); updateIPFilter(); },
        onToggleShowTcpFlows: (checked) => { state.ui.showTcpFlows = checked; updateTcpFlowPacketsGlobal(); drawSelectedFlowArcs(); try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); } },
        onToggleEstablishment: (checked) => { state.ui.showEstablishment = checked; drawSelectedFlowArcs(); try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); } },
        onToggleDataTransfer: (checked) => { state.ui.showDataTransfer = checked; drawSelectedFlowArcs(); try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); } },
        onToggleClosing: (checked) => { state.ui.showClosing = checked; drawSelectedFlowArcs(); try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); } },
        onToggleGroundTruth: (checked) => {
            state.ui.showGroundTruth = checked;
            const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value);
            drawGroundTruthBoxes(selectedIPs);
        },
        onToggleSubRowArcs: (checked) => {
            state.ui.showSubRowArcs = checked;
            drawSubRowArcs();
        },
        onToggleSeparateFlags: (checked) => {
            state.ui.separateFlags = checked;
            const savedDomain = xScale ? xScale.domain().slice() : null;
            isHardResetInProgress = true;
            try {
                visualizeTimeArcs(state.data.filtered);
                updateTcpFlowPacketsGlobal();
                drawSelectedFlowArcs();
                applyInvalidReasonFilter();
                if (savedDomain && xScale && (savedDomain[0] !== state.data.timeExtent[0] || savedDomain[1] !== state.data.timeExtent[1])) {
                    applyZoomDomain(savedDomain, 'program');
                }
            } catch(e) { logCatchError('toggleSeparateFlags', e); }
        },
        onToggleFlowThreading: (checked) => {
            state.ui.showFlowThreading = checked;
            if (!checked) {
                clearAutoFlowThreading();
            } else if (currentResolutionLevel === 'raw' && xScale) {
                // Turning on while already at raw resolution — draw immediately
                const visible = getVisiblePackets(state.data.filtered, xScale);
                drawAutoFlowThreading(visible);
            }
        },
        onToggleBinning: (checked) => {
            state.ui.useBinning = checked;
            const savedDomain = xScale ? xScale.domain().slice() : null;
            isHardResetInProgress = true;

            // Force immediate re-render of the visualization
            try {
                // Re-render the main visualization with current filtered data
                visualizeTimeArcs(state.data.filtered);

                // Update TCP flow packets and arcs
                updateTcpFlowPacketsGlobal();

                // Redraw selected flow arcs with new binning
                drawSelectedFlowArcs();

                // Apply any active filters
                applyInvalidReasonFilter();

                // Restore zoom position after rebuild
                if (savedDomain && xScale && (savedDomain[0] !== state.data.timeExtent[0] || savedDomain[1] !== state.data.timeExtent[1])) {
                    applyZoomDomain(savedDomain, 'program');
                }

                // Update legends to reflect new scaling
                setTimeout(() => {
                    try {
                        try {
                            const axisBaseY = Math.max(20, bottomOverlayHeight - 34);
                            drawSizeLegend(bottomOverlayRoot, width, bottomOverlayHeight, axisBaseY);
                        } catch(e) { logCatchError('drawSizeLegend', e); }
                        drawFlagLegend();
                        const selIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value);
                        drawGroundTruthBoxes(selIPs);
                    } catch(e) { logCatchError('binningToggle.refresh', e); }
                }, 50);
            } catch (e) {
                console.warn('Error updating visualization after binning toggle:', e);
            }
        },
        onViewModeChange: (mode) => switchViewMode(mode)
    });

    // Window resize handler for responsive visualization
    setupWindowResizeHandler();

    // ── Pattern Search Engine + UI ──────────────────────────────────────────
    state.search.engine = new PatternSearchEngine({
        getState: () => state,
        getFlowListLoader: () => getFlowListLoader(),
        getAdaptiveLoader: () => adaptiveOverviewLoader,
        onProgress: (pct, label) => showSearchProgress(pct, label),
        onResults: (results) => applySearchResults(results)
    });

    initPatternSearchUI(document.getElementById('patternSearchContainer'), {
        onSearch: async (pattern, level, scope, timeRangeMode) => {
            state.search.level = level;
            state.search.scope = scope;
            const timeRange = timeRangeMode === 'view' ? xScale.domain() : null;
            if (state.search.engine) {
                await state.search.engine.search(pattern, level, scope, timeRange);
            }
        },
        onCancel: () => {
            if (state.search.engine) state.search.engine.cancel();
            hideSearchProgress();
        },
        onClear: () => {
            clearPatternSearch();
        },
        onFilterToggle: (active) => {
            state.search.filterActive = active;
            reRenderCirclesWithSearchHighlight();
        },
        onSelectMatchedIPs: (ips) => {
            selectMatchedIPsInSidebar(ips);
        }
    });
    // ───────────────────────────────────────────────────────────────────────

    // Zoom In/Out button handlers (configurable zoom step per click)
    setupZoomButtons({
        getXScale: () => xScale,
        getTimeExtent: () => state.data.timeExtent,
        applyZoomDomain,
        setIsHardResetInProgress: (val) => { isHardResetInProgress = val; }
    });

    // Populate resolution dropdown
    populateResolutionDropdown();

    // Wire Flow List modal controls
    try {
        sbWireFlowListModalControls({
            onSelectAll: () => {
                document.querySelectorAll('#flowListModalList .flow-checkbox').forEach(cb => { if (!cb.checked) cb.click(); });
            },
            onClearAll: () => {
                document.querySelectorAll('#flowListModalList .flow-checkbox').forEach(cb => { if (cb.checked) cb.click(); });
            },
            onSearch: (term) => {
                const items = document.querySelectorAll('#flowListModalList .flow-item');
                const t = (term || '').toLowerCase();
                items.forEach(it => {
                    const text = (it.innerText || it.textContent || '').toLowerCase();
                    it.style.display = text.includes(t) ? '' : 'none';
                });
            }
        });
    } catch(e) { logCatchError('sbWireFlowListModalControls', e); }
}

// Window resize handler for responsive visualization
// Uses module for event handling, with custom onResize callback for app-specific logic
function setupWindowResizeHandler() {
    const handleResizeLogic = () => {
        try {
            // Only proceed if we have data and existing visualization
            if (!state.data.full || state.data.full.length === 0 || !svg || !xScale || !yScale) {
                return;
            }

            console.log('[Resize] Handling window resize, updating visualization dimensions');

            // Store old dimensions for comparison
            const oldWidth = width;
            const oldHeight = height;

            // IMPORTANT: Save the current TIME DOMAIN before resize
            // This is what we want to preserve, not the pixel-based transform
            const currentDomain = xScale.domain();
            console.log('[Resize] Preserving time domain across resize:', currentDomain);
            console.log('[Resize] Current timeExtent:', state.data.timeExtent);

            const container = d3.select("#chart-container").node();
            if (!container) return;

            // Calculate new dimensions
            const containerRect = container.getBoundingClientRect();
            const newWidth = Math.max(400, containerRect.width - chartMarginLeft - chartMarginRight);
            const newHeight = Math.max(300, containerRect.height - 100); // Leave space for controls

            // Update global dimensions
            width = newWidth;
            height = newHeight;

            console.log(`[Resize] Dimensions: ${oldWidth}x${oldHeight} -> ${width}x${height}`);

            // Resize main SVG
            svg.attr('width', width + chartMarginLeft + chartMarginRight)
               .attr('height', height + 100); // Extra space for bottom margin

            // Keep zoom-capture rect in sync with new dimensions
            svg.select('.zoom-capture')
                .attr('width', width)
                .attr('height', height);

            // Update scales with new width
            if (xScale && state.data.timeExtent) {
                xScale.range([0, width]);
            }
            
            // Update bottom overlay dimensions
            bottomOverlayWidth = Math.max(0, newWidth + chartMarginLeft + chartMarginRight);
            d3.select('#chart-bottom-overlay-svg')
                .attr('width', bottomOverlayWidth)
                .attr('height', bottomOverlayHeight);
            
            if (bottomOverlayRoot) {
                bottomOverlayRoot.attr('transform', `translate(${chartMarginLeft},0)`);
            }
            
            // Update main chart axis and legends with zoom-adaptive formatting
            if (bottomOverlayAxisGroup && xScale && state.data.timeExtent) {
                bottomOverlayAxisGroup.call(dualAxis);
                
                // Redraw legends with new dimensions
                const axisBaseY = Math.max(20, bottomOverlayHeight - 34);
                if (bottomOverlayDurationLabel) {
                    bottomOverlayDurationLabel.attr('y', axisBaseY - 12);
                }
                
                try { 
                    drawSizeLegend(bottomOverlayRoot, newWidth, bottomOverlayHeight, axisBaseY); 
                } catch (e) { 
                    LOG('Error redrawing size legend:', e); 
                }
                
                try { 
                    drawFlagLegend(); 
                } catch (e) { 
                    LOG('Error redrawing flag legend:', e); 
                }
            }
            
            // Update zoom behavior with new dimensions
            if (zoom && zoomTarget) {
                zoom.extent([[0, 0], [width, height]])
                    .scaleExtent([1, Math.max(20, width / 50)]);

                // Clear ALL caches and circles to force complete fresh rendering
                fullDomainBinsCache = { version: -1, data: [], binSize: null, sorted: false };
                state.data.version++;
                dotsSelection = null;

                // Clear circles from both layers - they'll be re-rendered with new scale
                if (fullDomainLayer) {
                    fullDomainLayer.selectAll('.direction-dot').remove();
                    fullDomainLayer.selectAll('.bin-bar-segment').remove();
                    fullDomainLayer.selectAll('.bin-stack').remove();
                }
                if (dynamicLayer) {
                    dynamicLayer.selectAll('.direction-dot').remove();
                    dynamicLayer.selectAll('.bin-bar-segment').remove();
                    dynamicLayer.selectAll('.bin-stack').remove();
                }

                // Restore the SAME TIME DOMAIN after resize using the proper zoom function
                if (currentDomain && currentDomain[0] !== undefined && currentDomain[1] !== undefined) {
                    console.log(`[Resize] Restoring zoom domain: [${currentDomain[0]}, ${currentDomain[1]}]`);
                    console.log(`[Resize] Domain width: ${currentDomain[1] - currentDomain[0]}`);

                    // Use applyZoomDomain which properly calculates transform and triggers re-render
                    isHardResetInProgress = true;
                    applyZoomDomain(currentDomain, 'resize');

                    // Verify the domain was restored
                    setTimeout(() => {
                        console.log(`[Resize] After applyZoomDomain, xScale.domain():`, xScale.domain());
                    }, 100);
                } else {
                    console.log('[Resize] No domain to restore, resetting to full domain');
                    isHardResetInProgress = true;
                    applyZoomDomain(state.data.timeExtent, 'resize');
                }
            }
            
            // Recreate overview chart with new dimensions using proper refresh mechanism
            if (state.data.timeExtent && state.data.timeExtent.length === 2) {
                try {
                    // Get selected IPs to pass to the adaptive overview refresh
                    const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked'))
                        .map(cb => cb.value);

                    const effectiveOverviewExtent = state.timearcs.overviewTimeExtent || state.data.timeExtent;

                    // Use refreshAdaptiveOverview which handles adaptive loading properly
                    // This ensures the overview chart uses the same data source as after IP filtering
                    refreshAdaptiveOverview(selectedIPs, effectiveOverviewExtent)
                        .then(() => {
                            // Restore brush selection to current zoom domain if available
                            if (xScale && updateBrushFromZoom) {
                                updateBrushFromZoom();
                            }
                        })
                        .catch(e => {
                            LOG('Error recreating overview chart on resize:', e);
                        });
                } catch (e) {
                    LOG('Error recreating overview chart on resize:', e);
                }
            }
            
            // The zoom handler will take care of redrawing dots and arcs
            // Just need to update any additional elements that aren't handled by zoom
            
            // Update clip path with new dimensions
            if (svg) {
                svg.select('#clip rect')
                    .attr('width', width + 40) // DOT_RADIUS equivalent
                    .attr('height', height + 80); // 2 * DOT_RADIUS equivalent
            }
            
            // Update global domain for overview sync
            try {
                window.__arc_x_domain__ = xScale.domain();
            } catch(e) { logCatchError('setArcXDomain', e); }
            
            LOG('Window resize handling complete');
            
        } catch (e) {
            console.warn('Error during window resize:', e);
        }
    };
    
    // Use module's resize handler with our custom logic
    return setupWindowResizeHandlerFromModule({
        debounceMs: 150,
        onResize: handleResizeLogic
    });
}

// ── Pattern Search helpers ────────────────────────────────────────────────────

/**
 * Called by PatternSearchEngine.onResults — stores results and re-renders.
 * @param {import('./src/search/search-results.js').SearchResults} results
 */
function applySearchResults(results) {
    state.search.results = results;
    state.search.active = !results.error && results.totalMatches > 0;

    // Show results summary in the UI panel
    showSearchResults(
        results,
        (flows) => {
            // "View Flows" — open existing flow list modal with matched flows
            try {
                const overlay = document.getElementById('flowListModalOverlay');
                if (overlay) {
                    overlay.style.display = 'flex';
                    sbCreateFlowListCapped(
                        flows, state.flows.selectedIds,
                        formatBytes, formatTimestamp,
                        null, null, null,
                        {}, null, flows.some(f => f._hasEmbeddedPackets)
                    );
                }
            } catch (e) { logCatchError('applySearchResults.viewFlows', e); }
        },
        (ips) => selectMatchedIPsInSidebar(ips)
    );

    // Re-render circles to apply highlights
    reRenderCirclesWithSearchHighlight();
}

/**
 * Reset all search state and remove highlights.
 */
function clearPatternSearch() {
    state.search.active = false;
    state.search.results = null;
    state.search.filterActive = false;
    state.search.newlyAddedIPs.clear();
    clearSearchResultsUI();
    reRenderCirclesWithSearchHighlight();
}

/**
 * Trigger a circle re-render so search highlight classes are applied.
 * Uses the same pattern as other lightweight re-renders: re-call renderCircles
 * on the existing dots layer if available.
 */
function reRenderCirclesWithSearchHighlight() {
    // Applying classes after renderCircles is driven by the zoom/render pipeline.
    // We request an immediate re-render by triggering the standard redraw.
    try {
        if (state.data.filtered && state.data.filtered.length > 0 && typeof visualizeTimeArcs === 'function') {
            // Lightweight: only re-apply highlight classes to existing circles
            applySearchHighlightClasses();
        }
    } catch (e) {
        logCatchError('reRenderCirclesWithSearchHighlight', e);
    }
}

/**
 * Apply/remove search highlight styling based on current search state.
 * Draws a golden box at the source IP row for each matched IP pair,
 * with an arrow from the box's leading edge to the destination IP row.
 */
function applySearchHighlightClasses() {
    if (!mainGroup) return;

    const chartCol = document.getElementById('chart-column');

    // Remove previous highlight visuals
    mainGroup.selectAll('.search-highlight-box').remove();

    // Apply/remove golden "newly added" label styling (independent of search active state).
    // Labels live in the parent svg (not mainGroup), so select from svg.
    const parentSvg = mainGroup.node()?.closest('svg');
    if (parentSvg) {
        d3.select(parentSvg).selectAll('.node-label').each(function() {
            const el = d3.select(this);
            const ip = el.text();
            el.classed('newly-added', state.search.newlyAddedIPs && state.search.newlyAddedIPs.has(ip));
        });
    }

    if (!state.search.active || !state.search.results) {
        mainGroup.selectAll('.direction-dot').style('opacity', null);
        if (chartCol) chartCol.classList.remove('search-filter-active');
        return;
    }

    const matchedPairs = state.search.results.matchedIpPairs;
    const filterActive = state.search.filterActive;
    const ipPositions = state.layout.ipPositions;

    // Collect x/y-extent of matched circles per (pairKey, srcIp) on the source row.
    // Key by "pairKey|srcIp" so expanded sub-rows get individual boxes.
    // pairBoxes: Map<compositeKey, { srcIp, dstIp, pairKey, minX, maxX, minY, maxY, maxR }>
    const pairBoxes = new Map();

    mainGroup.selectAll('.direction-dot').each(function(d) {
        if (!d) return;
        const isCollapsed = d.ipPairKey === '__collapsed__';
        let pairKey, isMatch;

        let dstIp = d.dst_ip;
        if (isCollapsed) {
            // Collapsed circles merge multiple pairs — check if ANY merged pair matches
            const pairs = d.ipPairs || [];
            const matchedPair = pairs.find(p => {
                const pk = makeIpPairKey(p.src_ip, p.dst_ip);
                return matchedPairs.has(pk);
            });
            isMatch = !!matchedPair;
            // Use the matched pair for box grouping and arrow destination
            pairKey = matchedPair ? makeIpPairKey(matchedPair.src_ip, matchedPair.dst_ip) : null;
            if (matchedPair) dstIp = matchedPair.dst_ip;
        } else {
            pairKey = d.ipPairKey || (d.src_ip && d.dst_ip
                ? (d.src_ip < d.dst_ip ? `${d.src_ip}<->${d.dst_ip}` : `${d.dst_ip}<->${d.src_ip}`)
                : null);
            isMatch = pairKey && matchedPairs.has(pairKey);
        }

        const el = d3.select(this);

        if (isMatch) {
            const cx = +el.attr('cx'), cy = +el.attr('cy'), r = +el.attr('r') || 3;
            // Group by pairKey + srcIp so each source sub-row gets its own box
            const boxKey = `${pairKey}|${d.src_ip}`;
            if (!pairBoxes.has(boxKey)) {
                pairBoxes.set(boxKey, {
                    srcIp: d.src_ip, dstIp: dstIp, pairKey,
                    minX: cx - r, maxX: cx + r,
                    minY: cy - r, maxY: cy + r, maxR: r
                });
            } else {
                const b = pairBoxes.get(boxKey);
                b.minX = Math.min(b.minX, cx - r);
                b.maxX = Math.max(b.maxX, cx + r);
                b.minY = Math.min(b.minY, cy - r);
                b.maxY = Math.max(b.maxY, cy + r);
                b.maxR = Math.max(b.maxR, r);
            }
            el.style('opacity', null);
        } else {
            el.style('opacity', filterActive ? 0.12 : null);
        }
    });

    if (chartCol) {
        if (filterActive) {
            chartCol.classList.add('search-filter-active');
        } else {
            chartCol.classList.remove('search-filter-active');
        }
    }

    // Only draw golden boxes + arrows when "Highlight matches only" is checked
    if (!filterActive) return;

    // Draw boxes + arrows
    const firstCircleLayer = mainGroup.select('.full-domain-layer, .dynamic-layer').node();
    const boxGroup = mainGroup.insert('g', firstCircleLayer ? () => firstCircleLayer : null)
        .attr('class', 'search-highlight-box');

    const padX = 4, padY = 2;
    const arrowSize = 5;
    const gold = '#f1c40f';

    // Build a lookup of actual sub-row Y centers for destination arrows.
    // For each (dstIp, pairKey), find the center Y of circles on that dst row.
    const dstSubRowY = new Map(); // "dstIp|pairKey" → centerY
    for (const [, b] of pairBoxes) {
        // Each entry is keyed by srcIp; look for the counterpart keyed by dstIp
        const dstKey = `${b.pairKey}|${b.dstIp}`;
        if (pairBoxes.has(dstKey)) {
            const db = pairBoxes.get(dstKey);
            dstSubRowY.set(`${b.dstIp}|${b.pairKey}`, (db.minY + db.maxY) / 2);
        }
    }

    const tooltip = d3.select('#tooltip');
    const goldHover = '#e6a800';

    for (const [, b] of pairBoxes) {
        // Box spans the actual Y extent of matched circles on this sub-row
        const boxY = b.minY - padY;
        const boxH = (b.maxY - b.minY) + padY * 2;
        const srcCenterY = (b.minY + b.maxY) / 2;

        // Wrap each pair's visuals in a group for coordinated hover highlighting
        const pairG = boxGroup.append('g')
            .attr('class', 'search-highlight-pair');

        // Golden box on the source IP sub-row
        pairG.append('rect')
            .attr('class', 'search-box-rect')
            .attr('x', b.minX - padX)
            .attr('y', boxY)
            .attr('width', b.maxX - b.minX + padX * 2)
            .attr('height', boxH)
            .attr('rx', 3)
            .attr('ry', 3)
            .attr('fill', 'rgba(241, 196, 15, 0.15)')
            .attr('stroke', gold)
            .attr('stroke-width', 1.5)
            .attr('pointer-events', 'visiblePainted');

        // Arrow from box leading edge to destination IP sub-row
        const dstCenterY = dstSubRowY.get(`${b.dstIp}|${b.pairKey}`)
            ?? ipPositions.get(b.dstIp);
        if (dstCenterY != null && dstCenterY !== srcCenterY) {
            const arrowX = b.minX - padX;
            const arrowStartY = srcCenterY;
            const arrowEndY = dstCenterY;

            // Stem line
            pairG.append('line')
                .attr('x1', arrowX).attr('y1', arrowStartY)
                .attr('x2', arrowX).attr('y2', arrowEndY)
                .attr('stroke', gold)
                .attr('stroke-width', 1.5)
                .attr('stroke-dasharray', '4,3')
                .attr('pointer-events', 'none');

            // Arrowhead at destination
            const dir = arrowEndY > arrowStartY ? 1 : -1;
            const tipY = arrowEndY;
            const baseY_ = tipY - dir * arrowSize * 2;
            pairG.append('polygon')
                .attr('points', `${arrowX},${tipY} ${arrowX - arrowSize},${baseY_} ${arrowX + arrowSize},${baseY_}`)
                .attr('fill', gold)
                .attr('pointer-events', 'none');
        }

        // Hover handlers for this pair group
        const matchCount = matchedPairs.get(b.pairKey) || 0;
        const [ipA, ipB] = b.pairKey.split('<->');
        pairG
            .on('mouseover', function(event) {
                // Brighten box and arrow
                d3.select(this).select('.search-box-rect')
                    .attr('fill', 'rgba(241, 196, 15, 0.35)')
                    .attr('stroke', goldHover)
                    .attr('stroke-width', 2.5);
                d3.select(this).selectAll('line')
                    .attr('stroke', goldHover)
                    .attr('stroke-width', 2.5);
                d3.select(this).selectAll('polygon')
                    .attr('fill', goldHover);
                // Tooltip
                const html = `<b>Pattern Match</b><br>${ipA} &harr; ${ipB}<br>Matched flows: ${matchCount.toLocaleString()}`;
                tooltip.style('display', 'block').html(html)
                    .style('left', `${event.pageX + 16}px`)
                    .style('top', `${event.pageY - 40}px`);
            })
            .on('mousemove', function(event) {
                tooltip.style('left', `${event.pageX + 16}px`)
                    .style('top', `${event.pageY - 40}px`);
            })
            .on('mouseout', function() {
                // Restore default styling
                d3.select(this).select('.search-box-rect')
                    .attr('fill', 'rgba(241, 196, 15, 0.15)')
                    .attr('stroke', gold)
                    .attr('stroke-width', 1.5);
                d3.select(this).selectAll('line')
                    .attr('stroke', gold)
                    .attr('stroke-width', 1.5);
                d3.select(this).selectAll('polygon')
                    .attr('fill', gold);
                tooltip.style('display', 'none');
            });
    }
}

/**
 * Programmatically check the IPs returned by "Select matched IPs" in the sidebar.
 * @param {string[]} ips
 */
function selectMatchedIPsInSidebar(ips) {
    if (!ips || ips.length === 0) return;
    const ipSet = new Set(ips);
    const newlyAdded = new Set();

    // Additive only: check matched IPs that aren't already checked, never uncheck existing ones
    document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => {
        if (ipSet.has(cb.value) && !cb.checked) {
            cb.checked = true;
            newlyAdded.add(cb.value);
        }
    });

    // Store newly added IPs for golden label highlighting
    state.search.newlyAddedIPs = newlyAdded;

    // Auto-collapse newly added multi-pair IPs so they don't explode the layout
    if (newlyAdded.size > 0) {
        const pairCounts = computeIPPairCounts(state.data.filtered.length > 0 ? state.data.filtered : state.data.full);
        for (const ip of newlyAdded) {
            if (pairCounts.get(ip) > 1) {
                state.layout.collapsedIPs.add(ip);
            }
        }
    }

    // Trigger the IP filter update, preserving search results
    try {
        updateIPFilter({ fromSearch: true });
    } catch (e) {
        logCatchError('selectMatchedIPsInSidebar.updateIPFilter', e);
    }
}

// ─────────────────────────────────────────────────────────────────────────────

// Global update functions that preserve zoom state
let flowUpdateTimeout = null;

// Centralized helper to apply a new time domain to the main chart (keeps brush/wheel/flow zoom in sync)
// Wrapper that calls the module function with current global state
function applyZoomDomain(newDomain, source = 'program') {
    // If the source is the brush, notify overview to avoid circular updates
    if (source === 'brush') { try { setBrushUpdating(true); } catch(e) { logCatchError('setBrushUpdating', e); } }

    // Log for debugging time range issues
    if (source === 'timearcs') {
        console.log('[applyZoomDomain] Called from timearcs with:', {
            newDomain,
            'state.data.timeExtent': state.data.timeExtent,
            'state.timearcs.overviewTimeExtent': state.timearcs.overviewTimeExtent,
            'newDomain range (seconds)': (newDomain[1] - newDomain[0]) / 1_000_000,
            'timeExtent range (seconds)': state.data.timeExtent ? (state.data.timeExtent[1] - state.data.timeExtent[0]) / 1_000_000 : 'N/A'
        });
    }

    // In flow detail mode, use the flow's time extent as the base for zoom calculations
    let effectiveTimeExtent = state.data.timeExtent;
    if (state.flowDetail.mode && state.flowDetail.packets.length > 0) {
        const flowTimeExtent = d3.extent(state.flowDetail.packets, d => d.timestamp);
        const padding = Math.max(50000, (flowTimeExtent[1] - flowTimeExtent[0]) * 0.1);
        effectiveTimeExtent = [flowTimeExtent[0] - padding, flowTimeExtent[1] + padding];
    }

    applyZoomDomainFromModule(newDomain, {
        zoom,
        zoomTarget,
        xScale,
        timeExtent: effectiveTimeExtent,
        width,
        d3
    }, source);

    if (source === 'brush') {
        // Release the flag after the event loop so zoomed() can run with the guard
        setTimeout(() => { try { setBrushUpdating(false); } catch(e) { logCatchError('setBrushUpdating', e); } }, 0);
    }
}

/**
 * Convert TimeArcs range (microseconds) to data units and update state.timearcs.overviewTimeExtent.
 * Call this early after state.data.timeExtent is known, before creating overview chart.
 */
function updateOverviewTimeExtentFromTimearcs() {
    if (!state.timearcs.timeRange || !state.data.timeExtent || state.data.timeExtent[0] === state.data.timeExtent[1]) {
        return;
    }

    let { minUs, maxUs } = state.timearcs.timeRange;

    // Safety check: if min === max (single point), expand to 60 seconds
    if (minUs === maxUs) {
        console.warn('[updateOverviewTimeExtentFromTimearcs] TimeArcs range is a single point, expanding to 60 seconds');
        maxUs = minUs + 60_000_000; // Add 60 seconds in microseconds
    }

    const extentMax = Math.max(state.data.timeExtent[0], state.data.timeExtent[1]);

    let zoomMin, zoomMax;

    if (extentMax > 1e14) {
        // Data is in microseconds
        zoomMin = minUs;
        zoomMax = maxUs;
    } else if (extentMax > 1e11) {
        // Data is in milliseconds
        zoomMin = minUs / 1000;
        zoomMax = maxUs / 1000;
    } else if (extentMax > 1e8) {
        // Data is in seconds
        zoomMin = minUs / 1_000_000;
        zoomMax = maxUs / 1_000_000;
    } else {
        // Data might be in minutes
        zoomMin = minUs / 60_000_000;
        zoomMax = maxUs / 60_000_000;
    }

    // Add small padding
    const selectedRange = zoomMax - zoomMin;
    const padding = selectedRange * 0.05;
    const paddedMin = zoomMin - padding;
    const paddedMax = zoomMax + padding;

    // Clamp to data extent
    const clampedMin = Math.max(state.data.timeExtent[0], paddedMin);
    const clampedMax = Math.min(state.data.timeExtent[1], paddedMax);

    if (clampedMin < clampedMax) {
        state.timearcs.overviewTimeExtent = [clampedMin, clampedMax];
        state.timearcs.intendedZoomDomain = [clampedMin, clampedMax];
        console.log('[updateOverviewTimeExtentFromTimearcs] Set state.timearcs.overviewTimeExtent:', state.timearcs.overviewTimeExtent);
    }
}

// Apply TimeArcs time range as initial zoom (if set)
// TimeArcs passes times in microseconds, but data may be in different resolutions
function applyTimearcsTimeRangeZoom() {
    console.log('[TimeArcs Zoom] Called with:', { timeRange: state.timearcs.timeRange, timeExtent: state.data.timeExtent, zoom: !!zoom, zoomTarget: !!zoomTarget, xScale: !!xScale });

    if (!state.timearcs.timeRange) {
        console.log('[TimeArcs Zoom] No state.timearcs.timeRange set, skipping');
        return;
    }
    if (!state.data.timeExtent || state.data.timeExtent[0] === state.data.timeExtent[1]) {
        console.log('[TimeArcs Zoom] Invalid state.data.timeExtent, skipping');
        return;
    }
    if (!zoom || !zoomTarget || !xScale) {
        console.warn('[TimeArcs Zoom] Zoom not initialized yet, retrying in 200ms');
        setTimeout(() => applyTimearcsTimeRangeZoom(), 200);
        return;
    }

    let { minUs, maxUs } = state.timearcs.timeRange;

    // Safety check: if min === max (single point), expand to 60 seconds
    if (minUs === maxUs) {
        console.warn('[TimeArcs Zoom] TimeArcs range is a single point, expanding to 60 seconds');
        maxUs = minUs + 60_000_000; // Add 60 seconds in microseconds
    }

    // Infer the data's timestamp unit by examining state.data.timeExtent magnitude
    // Unix epoch in different units (approx year 2020):
    // - Microseconds: ~1.6e15
    // - Milliseconds: ~1.6e12
    // - Seconds: ~1.6e9
    // - Minutes: ~2.6e7
    const extentMax = Math.max(state.data.timeExtent[0], state.data.timeExtent[1]);

    let zoomMin, zoomMax;
    let detectedUnit = 'unknown';

    if (extentMax > 1e14) {
        // Data is in microseconds - use directly
        zoomMin = minUs;
        zoomMax = maxUs;
        detectedUnit = 'microseconds';
    } else if (extentMax > 1e11) {
        // Data is in milliseconds - convert from microseconds
        zoomMin = minUs / 1000;
        zoomMax = maxUs / 1000;
        detectedUnit = 'milliseconds';
    } else if (extentMax > 1e8) {
        // Data is in seconds - convert from microseconds
        zoomMin = minUs / 1_000_000;
        zoomMax = maxUs / 1_000_000;
        detectedUnit = 'seconds';
    } else {
        // Data might be in minutes - convert from microseconds
        zoomMin = minUs / 60_000_000;
        zoomMax = maxUs / 60_000_000;
        detectedUnit = 'minutes';
    }

    console.log(`[TimeArcs Zoom] Detected data unit: ${detectedUnit}, extentMax: ${extentMax}`);
    console.log(`[TimeArcs Zoom] TimeArcs range (us): [${minUs}, ${maxUs}]`);
    console.log(`[TimeArcs Zoom] Converted range: [${zoomMin}, ${zoomMax}]`);
    console.log(`[TimeArcs Zoom] Data timeExtent: [${state.data.timeExtent[0]}, ${state.data.timeExtent[1]}]`);

    // Add small padding based on SELECTED range (not data range)
    const selectedRange = zoomMax - zoomMin;
    const padding = selectedRange * 0.05; // 5% of selected range
    const paddedMin = zoomMin - padding;
    const paddedMax = zoomMax + padding;

    // Clamp to data extent
    const clampedMin = Math.max(state.data.timeExtent[0], paddedMin);
    const clampedMax = Math.min(state.data.timeExtent[1], paddedMax);

    console.log(`[TimeArcs Zoom] Selected range: ${selectedRange}, padding: ${padding}`);
    console.log(`[TimeArcs Zoom] After padding & clamping: [${clampedMin}, ${clampedMax}]`);

    // Only apply if range is valid
    if (clampedMin < clampedMax) {
        console.log('[TimeArcs Zoom] Applying zoom domain:', [clampedMin, clampedMax]);
        // Store as intended zoom domain (persists across operations)
        state.timearcs.intendedZoomDomain = [clampedMin, clampedMax];
        // Store as overview extent (the range shown in overview bar chart)
        state.timearcs.overviewTimeExtent = [clampedMin, clampedMax];
        console.log('[TimeArcs Zoom] Set state.timearcs.overviewTimeExtent:', state.timearcs.overviewTimeExtent);
        applyZoomDomain([clampedMin, clampedMax], 'timearcs');
        // Verify the zoom was applied
        setTimeout(() => {
            if (xScale) {
                console.log('[TimeArcs Zoom] Verify - xScale domain after zoom:', xScale.domain());
            }
        }, 100);
    } else {
        console.warn('[TimeArcs Zoom] Invalid range after clamping, skipping zoom');
    }

    // NOTE: Don't clear state.timearcs.timeRange here - it's still needed by handleFlowDataLoaded()
    // when flow data loads after packet data. The state.timearcs.intendedZoomDomain persists the zoom state.
    // state.timearcs.timeRange = null;
}

function updateTcpFlowLinesGlobalDebounced() {
    // Clear any pending update
    if (flowUpdateTimeout) {
        clearTimeout(flowUpdateTimeout);
    }
    
    // Schedule a new update after a short delay
        flowUpdateTimeout = setTimeout(() => { 
        updateTcpFlowPacketsGlobal();
        flowUpdateTimeout = null;
    }, 100); // 100ms debounce
}

// Wrapper function that uses the module function with global state
function buildSelectedFlowKeySet() {
    return buildSelectedFlowKeySetFromModule(state.flows.tcp, state.flows.selectedIds);
}

function updateTcpFlowPacketsGlobal() {
    // Hide/show dots and draw lines based on current selection
    filterPacketsBySelectedFlows();
    // If no flows selected, ensure all dots are visible in both layers
    if (!state.ui.showTcpFlows || state.flows.selectedIds.size === 0) {
        if (fullDomainLayer) {
            fullDomainLayer.selectAll('.direction-dot').style('display', 'block').style('opacity', 0.5);
            fullDomainLayer.selectAll('.bin-bar-segment').style('display', 'block').style('opacity', 0.7);
        }
        // Clear any stale selection-only marks to prevent size scale misreads
        if (dynamicLayer) {
            dynamicLayer.selectAll('.direction-dot').remove();
            dynamicLayer.selectAll('.bin-bar-segment').remove();
        }
        // Restore full-domain layer by default when no selection
        if (fullDomainLayer) fullDomainLayer.style('display', null);
        if (dynamicLayer) dynamicLayer.style('display', 'none');
    }
    drawSelectedFlowArcs();
    drawSubRowArcs();

    // If a flow selection is active, recompute bins for the selection and render in dynamic layer
    if (state.ui.showTcpFlows && state.flows.selectedIds.size > 0) {
        try { redrawSelectedFlowsView(); } catch (e) { console.warn('Redraw for selected flows failed:', e); }
    }
    // Apply invalid-reason visibility on top of any selection
    try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); }
}

// Track hidden close types (graceful, abortive) from closing legend
const hiddenCloseTypes = new Set();

// Hide/show dots, arcs, and overview bars based on invalid-reason and closing-type toggles
function applyInvalidReasonFilter() {
    // If SVG not ready, nothing to do
    if (!svg) return;

    // Helper: build a mapping from connection key -> invalid reason
    const reasonByKey = new Map();
    // Helper: build a mapping from connection key -> closeType ('graceful','abortive', etc.)
    const closeTypeByKey = new Map();
    if (Array.isArray(state.flows.tcp)) {
        for (const f of state.flows.tcp) {
            if (!f) continue;
            const key = f.key || makeConnectionKey(f.initiator, f.initiatorPort, f.responder, f.responderPort);
            if (!key) continue;
            let r = f.invalidReason;
            if (!r && (f.closeType === 'invalid' || f.state === 'invalid')) r = 'unknown_invalid';
            reasonByKey.set(key, r || null);
            // Closing-type visibility: exclude invalid flows from ongoing group
            // Map non-invalid, non-closed flows to 'open' (established) or 'incomplete'
            const isInvalid = !!r || f.closeType === 'invalid' || f.state === 'invalid';
            let ct = null;
            if (!isInvalid) {
                if (f.closeType === 'graceful' || f.closeType === 'abortive') {
                    ct = f.closeType;
                } else {
                    ct = (f.establishmentComplete === true || f.state === 'established' || f.state === 'data_transfer') ? 'open' : 'incomplete';
                }
            }
            closeTypeByKey.set(key, ct);
        }
    }

    const keyIsHidden = (key) => {
        const r = reasonByKey.get(key);
        if (r && hiddenInvalidReasons && hiddenInvalidReasons.has(r)) return true;
        // If we also hide by close type, check the flow close type
        if (hiddenCloseTypes && hiddenCloseTypes.size > 0 && key) {
            const ct = closeTypeByKey.get(key);
            if (ct && hiddenCloseTypes.has(ct)) return true;
        }
        return false;
    };

    const nothingHidden = (!hiddenInvalidReasons || hiddenInvalidReasons.size === 0) && (!hiddenCloseTypes || hiddenCloseTypes.size === 0);

    // Dots (both layers live under mainGroup)
    if (mainGroup && mainGroup.selectAll) {
        mainGroup.selectAll('.direction-dot').each(function(d) {
            let hide = false;
            if (!nothingHidden) {
                if (d && Array.isArray(d.originalPackets) && d.originalPackets.length) {
                    let allHidden = true;
                    const arr = d.originalPackets;
                    // Sample up to first 50 packets for performance
                    const len = Math.min(arr.length, 50);
                    for (let i = 0; i < len; i++) {
                        const p = arr[i];
                        const key = makeConnectionKey(p.src_ip, p.src_port || 0, p.dst_ip, p.dst_port || 0);
                        if (!keyIsHidden(key)) { allHidden = false; break; }
                    }
                    hide = allHidden;
                } else if (d) {
                    const key = makeConnectionKey(d.src_ip, d.src_port || 0, d.dst_ip, d.dst_port || 0);
                    hide = keyIsHidden(key);
                }
            }
            // Apply phase-based visibility regardless of legend toggles
            if (!hide) {
                if (d && Array.isArray(d.originalPackets) && d.originalPackets.length) {
                    let anyVisibleByPhase = false;
                    const arr = d.originalPackets;
                    const len = Math.min(arr.length, 50);
                    for (let i = 0; i < len; i++) {
                        const p = arr[i];
                        const ftype = getFlagType(p);
                        if (isFlagVisibleByPhase(ftype, { showEstablishment: state.ui.showEstablishment, showDataTransfer: state.ui.showDataTransfer, showClosing: state.ui.showClosing })) { anyVisibleByPhase = true; break; }
                    }
                    hide = !anyVisibleByPhase;
                } else if (d) {
                    const ftype = getFlagType(d);
                    hide = !isFlagVisibleByPhase(ftype, { showEstablishment: state.ui.showEstablishment, showDataTransfer: state.ui.showDataTransfer, showClosing: state.ui.showClosing });
                }
            }
            d3.select(this)
                .style('display', hide ? 'none' : null)
                .style('opacity', hide ? 0 : null);
        });
        // Also apply to stacked bar segments if present
        mainGroup.selectAll('.bin-bar-segment').each(function(w) {
            const d = w && w.datum ? w.datum : w; // our bars bind an object {datum}
            let hide = false;
            if (!nothingHidden) {
                if (d && Array.isArray(d.originalPackets) && d.originalPackets.length) {
                    let allHidden = true;
                    const arr = d.originalPackets;
                    const len = Math.min(arr.length, 50);
                    for (let i = 0; i < len; i++) {
                        const p = arr[i];
                        const key = makeConnectionKey(p.src_ip, p.src_port || 0, p.dst_ip, p.dst_port || 0);
                        if (!keyIsHidden(key)) { allHidden = false; break; }
                    }
                    hide = allHidden;
                }
            }
            if (!hide) {
                const ftype = d ? getFlagType(d) : 'OTHER';
                hide = !isFlagVisibleByPhase(ftype, { showEstablishment: state.ui.showEstablishment, showDataTransfer: state.ui.showDataTransfer, showClosing: state.ui.showClosing });
            }
            d3.select(this).style('display', hide ? 'none' : null).style('opacity', hide ? 0 : null);
        });
    }

    // Flow arcs (drawn only for selected flows)
    if (mainGroup && mainGroup.selectAll) {
        mainGroup.selectAll('.flow-arc').each(function(d) {
            let hide = false;
            if (!nothingHidden && d) {
                const key = makeConnectionKey(d.src_ip, d.src_port || 0, d.dst_ip, d.dst_port || 0);
                hide = keyIsHidden(key);
            }
            d3.select(this)
                .style('display', hide ? 'none' : null)
                .style('opacity', hide ? 0 : null);
        });
    }

    // Overview stacked histogram segments (invalid reasons)
    try { updateOverviewInvalidVisibility(); } catch(e) { logCatchError('updateOverviewInvalidVisibility', e); }

    // Update legend item styles to reflect toggled state
    const panel = document.getElementById('invalidLegendPanel');
    if (panel) {
        panel.querySelectorAll('.invalid-legend-item').forEach((el) => {
            const reason = el.getAttribute('data-reason');
            const disabled = !!(reason && hiddenInvalidReasons && hiddenInvalidReasons.has(reason));
            el.style.opacity = disabled ? '0.45' : '1';
        });
    }

    // Update closing and ongoing legend styles and hide specific closing lines
    const cpanel = document.getElementById('closingLegendPanel');
    if (cpanel) {
        cpanel.querySelectorAll('.closing-legend-item').forEach((el) => {
            const t = el.getAttribute('data-type');
            const disabled = !!(t && hiddenCloseTypes && hiddenCloseTypes.has(t));
            el.style.opacity = disabled ? '0.45' : '1';
        });
    }
    const opanel = document.getElementById('ongoingLegendPanel');
    if (opanel) {
        opanel.querySelectorAll('.closing-legend-item').forEach((el) => {
            const t = el.getAttribute('data-type');
            const disabled = !!(t && hiddenCloseTypes && hiddenCloseTypes.has(t));
            el.style.opacity = disabled ? '0.45' : '1';
        });
    }

    // Hide explicit closing line groups per type
    const closingGroup = svg.select('.closing-lines');
    if (closingGroup && !closingGroup.empty()) {
        closingGroup.selectAll('.closing-line').each(function(d){
            let hide = false;
            if (!nothingHidden && d) {
                // d.type is 'graceful_close' or 'half_close'
                if (hiddenCloseTypes && hiddenCloseTypes.size > 0) {
                    if (d.type === 'graceful_close' && hiddenCloseTypes.has('graceful')) hide = true;
                    if (d.type === 'half_close' && hiddenCloseTypes.has('abortive')) hide = true;
                }
            }
            d3.select(this).style('display', hide ? 'none' : null).style('opacity', hide ? 0 : null);
        });
    }
}

// Rebin and redraw dots specifically for currently selected flows at the current zoom domain
function redrawSelectedFlowsView() {
    if (!svg || !xScale || !dynamicLayer) return;
    // Hide cached full-domain dots; we will render fresh selection-only dots
    if (fullDomainLayer) fullDomainLayer.style('display', 'none');
    dynamicLayer.style('display', null);

    const selectedKeys = buildSelectedFlowKeySet();
    if (selectedKeys.size === 0) {
        // Nothing selected: clear dynamic layer; caller will restore full layer when appropriate
        dynamicLayer.selectAll('.direction-dot').remove();
        return;
    }

    // Compute visible packets in current domain, filtered by selected flow keys
    let visiblePackets = getVisiblePackets(state.data.filtered, xScale);
    visiblePackets = visiblePackets.filter(p => {
        if (!p || !p.src_ip || !p.dst_ip) return false;
        const key = makeConnectionKey(p.src_ip, p.src_port || 0, p.dst_ip, p.dst_port || 0);
        return selectedKeys.has(key);
    });

    if (!visiblePackets || visiblePackets.length === 0) {
        dynamicLayer.selectAll('.direction-dot').remove();
        return;
    }

    // Data is always pre-binned from multi-resolution system - just add y positions
    const binnedPackets = visiblePackets.map(d => ({
        ...d,
        yPos: findIPPosition(d.src_ip, d.src_ip, d.dst_ip, state.layout.pairs, state.layout.ipPositions),
        binCenter: d.bin_start ? (d.bin_start + (d.bin_end - d.bin_start) / 2) : d.timestamp,
        flagType: d.flagType || d.flag_type || 'OTHER',
        binned: d.binned !== false,
        count: d.count || 1,
        originalPackets: d.originalPackets || [d]
    }));
    const rScale = d3.scaleSqrt().domain([1, Math.max(1, globalMaxBinCount)]).range([RADIUS_MIN, RADIUS_MAX]);
    renderMarksForLayerLocal(dynamicLayer, binnedPackets, rScale);

    // Sync worker with updated dynamic layer data
    setTimeout(() => {
        try { syncWorkerWithRenderedData(); } catch(e) { logCatchError('syncWorkerWithRenderedData', e); }
    }, 80);
    // Re-apply legend-based filtering
    try { applyInvalidReasonFilter(); } catch(e) { logCatchError('applyInvalidReasonFilter', e); }
}

// Worker-enabled packet filtering (falls back to legacy if worker unavailable)
function filterPacketsBySelectedFlows() {
    if (!svg || !mainGroup) return;
    if (!workerManager) { 
        legacyFilterPacketsBySelectedFlows(); 
        return; 
    }
    
    // Check if we have a reasonable number of dots to match our data
    const dots = mainGroup.selectAll('.direction-dot').nodes();
    const currentMask = workerManager.getVisibilityMask();
    
    if (currentMask && dots.length !== currentMask.length) {
        // DOM has been updated, worker mask is stale - try to resync
        if (DEBUG) console.warn(`Worker mask stale (mask=${currentMask.length}, dots=${dots.length}), attempting resync`);
        syncWorkerWithRenderedData();
        
        // After resync, if still mismatched, fall back to legacy
        const newMask = workerManager.getVisibilityMask();
        if (newMask && dots.length !== newMask.length) {
            if (DEBUG) console.warn('Resync failed, using legacy filtering');
            legacyFilterPacketsBySelectedFlows();
            return;
        }
    }
    
    const showAll = !state.ui.showTcpFlows || state.flows.selectedIds.size === 0;
    const selectedKeys = showAll ? [] : Array.from(buildSelectedFlowKeySet());
    workerManager.filterByKeys(selectedKeys, showAll);
}

// Legacy in-main-thread filtering retained for fallback/debug
function legacyFilterPacketsBySelectedFlows() {
    if (!svg || !mainGroup) return;
    const allDots = mainGroup.selectAll('.direction-dot');
    if (!state.ui.showTcpFlows || state.flows.selectedIds.size === 0) {
        allDots.style('display', 'block').style('opacity', 0.5);
        // Bars as well
        try { mainGroup.selectAll('.bin-bar-segment').style('display','block').style('opacity', 0.7); } catch(e) { logCatchError('barSegmentStyle', e); }
        return;
    }
    const selectedKeys = buildSelectedFlowKeySet();
    const nodes = allDots.nodes();
    const BATCH = 2500;
    function processBatch(start) {
        const end = Math.min(start + BATCH, nodes.length);
        for (let i = start; i < end; i++) {
            const node = nodes[i];
            const d = node.__data__;
            let match = false;
            if (d && d.originalPackets && Array.isArray(d.originalPackets)) {
                const arr = d.originalPackets;
                const len = Math.min(arr.length, 50);
                for (let j = 0; j < len; j++) {
                    const p = arr[j];
                    const key = makeConnectionKey(p.src_ip, p.src_port, p.dst_ip, p.dst_port);
                    if (selectedKeys.has(key)) { match = true; break; }
                }
            } else if (d) {
                const key = makeConnectionKey(d.src_ip, d.src_port, d.dst_ip, d.dst_port);
                match = selectedKeys.has(key);
            }
            node.style.display = match ? 'block' : 'none';
            node.style.opacity = match ? 0.5 : 0.1;
        }
        if (end < nodes.length) {
            requestAnimationFrame(() => processBatch(end));
        }
    }
    requestAnimationFrame(() => processBatch(0));

    // Apply same logic for bar segments based on their bound datum
    const barNodes = mainGroup.selectAll('.bin-bar-segment').nodes();
    const BATCH2 = 2000;
    function processBars(start) {
        const end = Math.min(start + BATCH2, barNodes.length);
        for (let i = start; i < end; i++) {
            const node = barNodes[i];
            const w = node.__data__;
            const d = w && w.datum ? w.datum : w;
            let match = false;
            if (d && Array.isArray(d.originalPackets)) {
                const arr = d.originalPackets;
                const len = Math.min(arr.length, 50);
                for (let j = 0; j < len; j++) {
                    const p = arr[j];
                    const key = makeConnectionKey(p.src_ip, p.src_port, p.dst_ip, p.dst_port);
                    if (selectedKeys.has(key)) { match = true; break; }
                }
            }
            node.style.display = match ? 'block' : 'none';
            node.style.opacity = match ? 0.7 : 0.1;
        }
        if (end < barNodes.length) requestAnimationFrame(() => processBars(end));
    }
    requestAnimationFrame(() => processBars(0));
}

// Function to draw persistent lines for selected flows
function drawSelectedFlowArcs() {
    if (!svg || !mainGroup) return;

    // Clear previous persistent lines
    mainGroup.selectAll(".flow-arc").remove();

    // If TCP flows are off or nothing selected, don't draw persistent lines
    if (!state.ui.showTcpFlows || state.flows.selectedIds.size === 0 || !state.flows.tcp || state.flows.tcp.length === 0) {
        return;
    }

    // Build lookup of selected flow connection keys
    const selectedKeys = buildSelectedFlowKeySet();
    if (selectedKeys.size === 0) return;

    // Only draw lines for packets in the visible time range
    const [t0, t1] = xScale.domain();
    
    // Get visible packets for selected flows
    let visiblePackets = state.data.filtered.filter(p => {
        const ts = Math.floor(p.timestamp);
        if (ts < t0 || ts > t1) return false;
        const key = makeConnectionKey(p.src_ip, p.src_port, p.dst_ip, p.dst_port);
        return selectedKeys.has(key);
    });

    // Group packets by their pre-binned time bucket + src/dst pair + flagType
    // Data is always pre-binned, so use binCenter/binStart directly
    const arcGroups = new Map();
    for (const packet of visiblePackets) {
        // Use pre-binned time bucket (binCenter or binStart), not raw timestamp
        const timeBucket = packet.binCenter || packet.binStart || packet.bin_start || packet.timestamp;
        const flagType = packet.flagType || packet.flag_type || getFlagType(packet);
        const key = `${timeBucket}|${packet.src_ip}|${packet.src_port || 0}|${packet.dst_ip}|${packet.dst_port || 0}|${flagType}`;
        let g = arcGroups.get(key);
        if (!g) {
            g = {
                timestamp: timeBucket,
                src_ip: packet.src_ip,
                dst_ip: packet.dst_ip,
                src_port: packet.src_port || 0,
                dst_port: packet.dst_port || 0,
                flags: packet.flags,
                flagType,
                count: 0,
                originalPackets: [],
                rep: packet
            };
            arcGroups.set(key, g);
        }
        g.count += packet.count || 1;
        g.originalPackets.push(packet);
    }

    const groups = Array.from(arcGroups.values());

    // Build a bin-count map from the same binning used for dots, so widths match the circle legend
        const ARC_STROKE_WIDTH = 2;
        const countMap = new Map();
        groups.forEach(g => {
            const key = `${g.timestamp}_${g.src_ip}_${g.src_port}_${g.dst_ip}_${g.dst_port}_${getFlagType(g)}`;
            countMap.set(key, g.count);
        });

    // Build a global linear scale from 1 to globalMaxBinCount (matches circle legend)
    const MIN_THICKNESS = 0.5;
    const MAX_THICKNESS = 8;
    const thicknessScale = d3.scaleLinear()
        .domain([1, Math.max(1, globalMaxBinCount)])
        .range([MIN_THICKNESS, MAX_THICKNESS])
        .clamp(true);

    // Read actual circle positions from the DOM so arcs respect sub-row
    // expansion AND flag separation (mirrors drawSubRowArcs approach).
    const circlePosMap = buildCirclePositionMap();

    groups.forEach(g => {
        const ftype = getFlagType(g);
        if (!isFlagVisibleByPhase(ftype, { showEstablishment: state.ui.showEstablishment, showDataTransfer: state.ui.showDataTransfer, showClosing: state.ui.showClosing })) return;

        const pathPacket = g.rep;
        // srcY: actual circle position (accounts for flag separation + sub-row offset)
        const srcY = lookupCircleY(circlePosMap, g.timestamp, pathPacket.src_ip, pathPacket.dst_ip, ftype);
        // dstY: destination row sub-row center (no circle there for this specific arc)
        const dstY = getIPYWithSubRowOffset(pathPacket.dst_ip, pathPacket.src_ip, pathPacket.dst_ip);
        const path = arcPathGenerator(pathPacket, { xScale, ipPositions: state.layout.ipPositions, pairs: state.layout.pairs, findIPPosition, flagCurvature: FLAG_CURVATURE, srcY, dstY });
        if (path && pathPacket.src_ip !== pathPacket.dst_ip) {
            // Lookup bin count using the group's time bucket (g.timestamp) and the source row y position
            const yPos = findIPPosition(pathPacket.src_ip, pathPacket.src_ip, pathPacket.dst_ip, state.layout.pairs, state.layout.ipPositions);
                const thickness = ARC_STROKE_WIDTH;
            const arc = mainGroup.append("path")
                .attr("class", "flow-arc")
                .attr("d", path)
                .style("stroke", flagColors[ftype] || flagColors.OTHER)
                .style("stroke-width", `${thickness}px`)
                .style("opacity", 0.5)
                .datum(g);

            // Add interactivity: show packet info on hover
            arc.on('mouseover', (event, d) => {
                const tooltip = d3.select('#tooltip');
                tooltip.style('display', 'block').html(createTooltipHTML(d));
            }).on('mousemove', (event) => {
                const tooltip = d3.select('#tooltip');
                tooltip.style('left', `${event.pageX + 40}px`).style('top', `${event.pageY - 40}px`);
            }).on('mouseout', () => {
                d3.select('#tooltip').style('display', 'none');
            });
        }
    });
}

// Draw a permanent ghost arc for the first packet of each IP-pair sub-row.
// Shows which IPs are connected in each sub-row at a glance.
// Reads positions directly from DOM circles (same approach as hover arcs).
function drawSubRowArcs() {
    if (!svg || !mainGroup || !state.layout.ipPositions) return;
    mainGroup.selectAll('.sub-row-arc').remove();
    if (!state.ui.showSubRowArcs) return;

    // Query actual rendered circles from the DOM — same source of truth as hover arcs.
    // This gives us correct positions regardless of resolution or flag separation.
    // Prefer dynamicLayer (zoomed/current resolution) over fullDomainLayer to avoid mixing resolutions.
    const activeLayer = (dynamicLayer && dynamicLayer.style('display') !== 'none' && !dynamicLayer.selectAll('.direction-dot').empty())
        ? dynamicLayer
        : fullDomainLayer;
    if (!activeLayer) return;
    const allCircles = activeLayer.selectAll('.direction-dot');
    if (allCircles.empty()) return;

    // For each IP pair, find the earliest circle (by time) and record its datum.
    // The datum already has correct yPosWithOffset (flag-separated) and binCenter (current resolution).
    const earliestByPair = new Map(); // pairKey -> circle info
    const pairsByIp = new Map();      // srcIp -> Set of pairKeys

    // Deterministic tiebreaker: when bin centers match, prefer earlier TCP phase
    // so collapsed and expanded modes produce the same arc color
    const FLAG_RANK = { 'SYN': 0, 'SYN+ACK': 1, 'ACK': 2, 'PSH': 3, 'PSH+ACK': 4, 'FIN': 5, 'FIN+ACK': 6, 'RST': 7, 'RST+ACK': 8 };

    allCircles.each(function () {
        const d = d3.select(this).datum();
        if (!d || !d.src_ip || !d.dst_ip) return;

        const ts = d.binCenter || d.bin_start || d.timestamp || Infinity;
        const flagType = d.flagType || d.flag_type || getFlagType(d);
        const yPos = d.yPosWithOffset; // actual rendered y (accounts for flag separation)

        // Collapsed circles merge multiple IP pairs — extract all from ipPairs
        const pairs = (d.ipPairKey === '__collapsed__' && Array.isArray(d.ipPairs))
            ? d.ipPairs
            : [{ src_ip: d.src_ip, dst_ip: d.dst_ip }];

        for (const p of pairs) {
            if (!p.src_ip || !p.dst_ip || p.src_ip === p.dst_ip) continue;
            const pairKey = makeIpPairKey(p.src_ip, p.dst_ip);

            // Track pairs per source IP
            if (!pairsByIp.has(d.src_ip)) pairsByIp.set(d.src_ip, new Set());
            pairsByIp.get(d.src_ip).add(pairKey);

            const existing = earliestByPair.get(pairKey);
            const isEarlier = !existing || ts < existing.ts
                || (ts === existing.ts && (FLAG_RANK[flagType] ?? 99) < (FLAG_RANK[existing.flagType] ?? 99));
            if (isEarlier) {
                earliestByPair.set(pairKey, {
                    ts,
                    src_ip: p.src_ip,
                    dst_ip: p.dst_ip,
                    flagType,
                    flags: d.flags,
                    binned: d.binned,
                    binCenter: d.binCenter,
                    binEnd: d.bin_end,
                    timestamp: d.timestamp,
                    yPosWithOffset: yPos
                });
            }
        }
    });

    // Draw ghost arcs for IPs with multiple pairs
    const drawnPairs = new Set();
    for (const [ip, pairKeys] of pairsByIp) {
        if (pairKeys.size <= 1) continue; // only for multi-pair IPs
        for (const pairKey of pairKeys) {
            if (drawnPairs.has(pairKey)) continue;
            drawnPairs.add(pairKey);

            const circle = earliestByPair.get(pairKey);
            if (!circle) continue;

            // Source y: actual circle position (already flag-separated)
            const srcY = circle.yPosWithOffset;
            // Destination y: sub-row center (destination row may not have a circle with this flag type)
            const dstY = getIPYWithSubRowOffset(circle.dst_ip, circle.src_ip, circle.dst_ip);
            if (srcY == null || dstY == null) continue;

            // S-curve from circle position to dummy endpoint (matching hover arc style)
            const x1 = xScale(circle.binCenter || circle.timestamp);
            const binWidthPx = (circle.binCenter && circle.ts !== Infinity)
                ? Math.max(20, Math.abs(xScale(circle.binEnd || circle.binCenter) - x1))
                : 40;
            const xDummy = x1 + Math.max(20, binWidthPx);
            const midX = (x1 + xDummy) / 2;

            if (Math.abs(dstY - srcY) <= 1) continue;

            const color = flagColors[circle.flagType] || flagColors.OTHER || '#999';

            mainGroup.append('path')
                .attr('class', 'sub-row-arc')
                .attr('d', `M${x1},${srcY} C${midX},${srcY} ${midX},${dstY} ${xDummy},${dstY}`)
                .style('stroke', color)
                .style('stroke-width', '2px')
                .style('stroke-opacity', 0.8)
                .style('fill', 'none')
                .style('pointer-events', 'none');

            // Polygon arrowhead at midpoint
            const arrowLen = 5, arrowHalfW = 3;
            const a = Math.atan2(2 * (dstY - srcY), xDummy - x1);
            const ca = Math.cos(a), sa = Math.sin(a);
            const mx = midX, my = (srcY + dstY) / 2;
            mainGroup.append('polygon')
                .attr('class', 'sub-row-arc')
                .attr('points', `${mx+arrowLen*ca},${my+arrowLen*sa} ${mx-arrowLen*ca+arrowHalfW*sa},${my-arrowLen*sa-arrowHalfW*ca} ${mx-arrowLen*ca-arrowHalfW*sa},${my-arrowLen*sa+arrowHalfW*ca}`)
                .attr('fill', color)
                .attr('fill-opacity', 0.8)
                .style('pointer-events', 'none');
        }
    }
}

// Function to draw ground truth event boxes
function drawGroundTruthBoxes(selectedIPs) {
    if (!mainGroup) return;
    if (!state.ui.showGroundTruth || !state.flows.groundTruth || state.flows.groundTruth.length === 0) {
        // Remove existing ground truth boxes if not showing
        mainGroup.selectAll('.ground-truth-box').remove();
        mainGroup.selectAll('.ground-truth-label').remove();
        return;
    }

    const matchingEvents = filterGroundTruthByIPs(state.flows.groundTruth, selectedIPs);
    if (matchingEvents.length === 0) {
        mainGroup.selectAll('.ground-truth-box').remove();
        mainGroup.selectAll('.ground-truth-label').remove();
        return;
    }

    // Create ground truth group if it doesn't exist
    let groundTruthGroup = mainGroup.select('.ground-truth-group');
    if (groundTruthGroup.empty()) {
        groundTruthGroup = mainGroup.append('g').attr('class', 'ground-truth-group');
    }

    // Prepare data for boxes using new module function
    const boxData = prepareGroundTruthBoxData(matchingEvents, {
        xScale,
        findIPPosition,
        pairs: state.layout.pairs,
        ipPositions: state.layout.ipPositions,
        eventColors,
        subRowLayout: {
            ipPairOrderByRow: state.layout.ipPairOrderByRow,
            ipRowHeights: state.layout.ipRowHeights,
            subRowHeights: state.layout.subRowHeights,
            subRowOffsets: state.layout.subRowOffsets,
            rowGap: ROW_GAP
        }
    });

    // Update boxes
    const boxes = groundTruthGroup.selectAll('.ground-truth-box')
        .data(boxData, d => `${d.event.source}-${d.event.destination}-${d.event.startTimeMicroseconds}-${d.ip}-${d.isSource ? 'src' : 'dst'}-${d.pairIndex}`);

    boxes.exit().remove();

    const newBoxes = boxes.enter()
        .append('rect')
        .attr('class', 'ground-truth-box')
        .attr('fill', d => d.color)
        .attr('stroke', d => d.color);

    function formatAdjStop(adjStop, wasExpanded) {
        let s = epochMicrosecondsToUTC(adjStop).replace(' UTC','');
        if (s.includes('.')) s = s.split('.')[0];
        if (wasExpanded) s += ' (+59s)';
        return s;
    }
    function showTooltip(event, d) {
        const tooltip = d3.select('#tooltip');
        const adjStop = d.adjustedStopMicroseconds || d.event.stopTimeMicroseconds;
        const adjStart = d.adjustedStartMicroseconds || d.event.startTimeMicroseconds;
        const durationSec = Math.round((adjStop - adjStart) / 1_000_000);
        const startStr = d.event.startTime;
        const expandedStopStr = formatAdjStop(adjStop, false);
        let tooltipContent = `
            <b>${d.event.eventType}</b><br>
            IP: ${d.ip} (${d.isSource ? 'Source' : 'Destination'})<br>
            From: ${d.event.source}<br>
            To: ${d.event.destination}<br>
            Start: ${startStr}<br>
        `;
        if (d.wasExpanded) {
            tooltipContent += `Original Stop: ${d.event.stopTime}<br>`;
            tooltipContent += `Estimated Stop (+59s): ${expandedStopStr}<br>`;
            tooltipContent += `Estimated Duration: ~${durationSec}s`;
        } else {
            tooltipContent += `Stop: ${d.event.stopTime}<br>`;
            tooltipContent += `Duration: ${durationSec}s`;
        }
        tooltip.style('display','block').html(tooltipContent);
    }
    function moveTooltip(e) { d3.select('#tooltip').style('left', `${e.pageX + 40}px`).style('top', `${e.pageY - 40}px`); }
    function hideTooltip() { d3.select('#tooltip').style('display','none'); }

    function isSameEvent(a, b) {
        return a.event.source === b.event.source
            && a.event.destination === b.event.destination
            && a.event.startTimeMicroseconds === b.event.startTimeMicroseconds;
    }
    function highlightPair(event, d) {
        showTooltip(event, d);
        groundTruthGroup.selectAll('.ground-truth-box')
            .style('fill-opacity', o => isSameEvent(o, d) ? 0.55 : 0.12)
            .style('stroke-opacity', o => isSameEvent(o, d) ? 1 : 0.25);
        groundTruthGroup.selectAll('.ground-truth-label')
            .style('opacity', o => isSameEvent(o, d) ? 1 : 0.25);
    }
    function unhighlightPair() {
        hideTooltip();
        groundTruthGroup.selectAll('.ground-truth-box')
            .style('fill-opacity', null)
            .style('stroke-opacity', null);
        groundTruthGroup.selectAll('.ground-truth-label')
            .style('opacity', null);
    }
    groundTruthGroup.selectAll('.ground-truth-box')
        .on('mouseover', highlightPair)
        .on('mousemove', moveTooltip)
        .on('mouseout', unhighlightPair);

    // Update all boxes (existing and new)
    groundTruthGroup.selectAll('.ground-truth-box')
        .attr('x', d => d.x)
        .attr('y', d => d.y)
        .attr('width', d => d.width)
        .attr('height', d => d.height);

    // Sort DOM order so wider boxes are behind (rendered first) and narrower on top.
    // For same size + position on the same row, order by pairIndex.
    groundTruthGroup.selectAll('.ground-truth-box')
        .sort((a, b) => {
            // Group by row (same y = same row)
            if (Math.abs(a.y - b.y) > 0.5) return a.y - b.y;
            // Wider boxes behind (earlier in DOM)
            if (Math.abs(a.width - b.width) > 0.5) return b.width - a.width;
            // Same width: sort by x so leftmost is behind
            if (Math.abs(a.x - b.x) > 0.5) return a.x - b.x;
            // Same size and position: order by pairIndex
            return (a.pairIndex || 0) - (b.pairIndex || 0);
        });

    // Add labels for events that are wide enough (only on first sub-row of source IP to avoid duplication)
    const labels = groundTruthGroup.selectAll('.ground-truth-label')
        .data(boxData.filter(d => d.width > 50 && d.isSource && d.pairIndex <= 0), d => `${d.event.source}-${d.event.destination}-${d.event.startTimeMicroseconds}-label`);

    labels.exit().remove();

    const newLabels = labels.enter()
        .append('text')
        .attr('class', 'ground-truth-label')
        .attr('fill', '#2c3e50')
        .style('pointer-events', 'none');

    // Update all labels
    groundTruthGroup.selectAll('.ground-truth-label')
        .attr('x', d => d.x + d.width / 2)
        .attr('y', d => d.y + d.height / 2)
        .text(d => d.event.eventType.length > 20 ? 
            d.event.eventType.substring(0, 17) + '...' : 
            d.event.eventType);

    // Keep ground-truth boxes and labels above packet circles and arcs
    try { groundTruthGroup.raise(); } catch(e) { logCatchError('groundTruthGroup.raise', e); }
}

// IP selection event listeners
document.getElementById('selectAllIPs').addEventListener('click', async () => {
    document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = true);
    await updateIPFilter();
});

document.getElementById('clearAllIPs').addEventListener('click', async () => {
    document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = false);
    await updateIPFilter();
});

// IP search functionality
document.getElementById('ipSearch').addEventListener('input', (e) => {
    filterIPList(e.target.value);
});

let updateTimeout = null;

// IP Filter Controller - orchestrates IP filtering and visualization updates
// Uses lazy initialization to ensure all dependencies are available
let ipFilterController = null;

function getIPFilterController() {
    if (!ipFilterController) {
        ipFilterController = createIPFilterController({
            d3,
            getState: () => state,
            getFlowDataState: () => flowDataState,
            getAdaptiveOverviewLoader: () => adaptiveOverviewLoader,
            getFilterCache: () => filterCache,
            setMultiResSelectedIPs,
            eventColors,
            visualizeTimeArcs,
            drawFlagLegend,
            updateFlagStats,
            updateIPStats,
            applyTimearcsTimeRangeZoom,
            getXScaleDomain: () => xScale ? xScale.domain().slice() : null,
            applyZoomDomain,
            updateTcpFlowStats,
            refreshAdaptiveOverview,
            calculateGroundTruthStats,
            sbUpdateGroundTruthStatsUI,
            logCatchError
        });
    }
    return ipFilterController;
}

async function updateIPFilter({ fromSearch = false } = {}) {
    // Stale search results reference the previous IP selection — clear them
    // unless the IP change was itself triggered by the search "Select IPs" action.
    if (!fromSearch && state.search && state.search.active) {
        clearPatternSearch();
    }
    // Manual IP checkbox changes clear the "newly added" golden highlights
    if (!fromSearch && state.search.newlyAddedIPs.size > 0) {
        state.search.newlyAddedIPs.clear();
    }
    await getIPFilterController().updateIPFilter();

    // If in flow view mode, re-trigger zoom handler (FlowZoomManager handles data)
    if (state.ui.renderMode === 'flows') {
        if (flowZoomManager) flowZoomManager.invalidateCache();
        const xDomain = window.__arc_x_domain__;
        if (flowZoomManager && xDomain) {
            applyZoomDomain(xDomain, 'program');
        }
    }
}

// Delegated to control-panel.js
const createIPCheckboxes = (uniqueIPs) => sbCreateIPCheckboxes(uniqueIPs, async () => await updateIPFilter());

const updateFlagStats = (packets) => sbUpdateFlagStats(packets, getFlagType, flagColors);

const updateIPStats = (packets) => sbUpdateIPStats(packets, flagColors, formatBytes);

// TCP States (matching tcp_analysis.py) - now imported as TCP_STATES

// ---- Tunables - now imported as HANDSHAKE_TIMEOUT_MS, REORDER_WINDOW_PKTS, REORDER_WINDOW_MS

// ---- Minimal flag helpers - now imported from src/tcp/flags.js

// ---- Per-flow state --------------------------------------------------------
// HandshakeState type
// 'NEW' | 'SYN_SEEN' | 'SYNACK_SEEN' | 'ACK3_SEEN' | 'INVALID'

// InvalidReason type
// 'ack_without_handshake' | 'orphan_syn_timeout' | 'orphan_synack_timeout' | 'bad_seq_ack_numbers' | 'rst_during_handshake'

// FlowState interface
// { hs, established, syn, synAck, ack3, firstSeenTs, lastSeenTs, pending, pendingBytes, invalid, timers }

function getFlow(map, key, ts) {
    let f = map.get(key);
    if (!f) {
        f = {
            hs: 'NEW',
            established: false,
            firstSeenTs: ts,
            lastSeenTs: ts,
            pending: [],
            pendingBytes: 0,
            timers: {}
        };
        map.set(key, f);
    }
    return f;
}

function applyPacketToHandshake(flow, pkt, now) {
    flow.lastSeenTs = now;
    if (flow.hs === 'INVALID' || flow.established) return;
    if (has(pkt, 'rst') && (flow.hs !== 'ACK3_SEEN')) {
        flow.hs = 'INVALID';
        flow.invalid = { reason: 'rst_during_handshake', atTs: now };
        return;
    }
    const pushPending = () => {
        flow.pending.push(pkt);
        if (flow.pending.length > REORDER_WINDOW_PKTS) flow.pending.shift();
        const cutoff = now - REORDER_WINDOW_MS;
        while (flow.pending.length && flow.pending[0].ts < cutoff) flow.pending.shift();
    };
    if (flow.hs === 'NEW' && isACKonly(pkt)) {
        pushPending();
        const oldest = flow.pending[0]?.ts ?? now;
        if ((now - oldest) > REORDER_WINDOW_MS) {
            flow.hs = 'INVALID';
            flow.invalid = { reason: 'ack_without_handshake', atTs: now };
        }
        return;
    }
    if (isSYN(pkt)) {
        flow.syn = pkt;
        flow.hs = 'SYN_SEEN';
        flow.timers.synExpire = now + HANDSHAKE_TIMEOUT_MS;
        return;
    }
    if (isSYNACK(pkt)) {
        flow.synAck = pkt;
        if (flow.hs === 'SYN_SEEN') {
            flow.hs = 'SYNACK_SEEN';
            flow.timers.synAckExpire = now + HANDSHAKE_TIMEOUT_MS;
            return;
        }
        if (flow.hs === 'NEW') {
            pushPending();
            const oldest = flow.pending[0]?.ts ?? now;
            if ((now - oldest) > REORDER_WINDOW_MS) {
                flow.hs = 'INVALID';
                flow.invalid = { reason: 'orphan_synack_timeout', atTs: now };
            }
            return;
        }
    }
    if (has(pkt,'ack') && !has(pkt,'syn') && !has(pkt,'rst')) {
        if (flow.syn && flow.synAck) {
            const okAckToSynAckSeq   = (pkt.ackNum === (flow.synAck.seq + 1) >>> 0);
            const okAckFromSynToAck3 = (flow.synAck.ackNum === ((flow.syn.seq + 1) >>> 0));
            if (!okAckToSynAckSeq || !okAckFromSynToAck3) {
                flow.hs = 'INVALID';
                flow.invalid = { reason: 'bad_seq_ack_numbers', atTs: now };
                return;
            }
            flow.ack3 = pkt;
            flow.hs = 'ACK3_SEEN';
            flow.established = true;
            flow.timers = {};
            flow.pending = [];
            return;
        }
        if (flow.syn && !flow.synAck) {
            pushPending();
            if (flow.timers.synExpire && now > flow.timers.synExpire) {
                flow.hs = 'INVALID';
                flow.invalid = { reason: 'orphan_syn_timeout', atTs: now };
            }
            return;
        }
        if (flow.hs === 'NEW') {
            pushPending();
            const oldest = flow.pending[0]?.ts ?? now;
            if ((now - oldest) > REORDER_WINDOW_MS) {
                flow.hs = 'INVALID';
                flow.invalid = { reason: 'ack_without_handshake', atTs: now };
            }
            return;
        }
    }
    if (flow.hs === 'SYN_SEEN' && flow.timers.synExpire && now > flow.timers.synExpire) {
        flow.hs = 'INVALID';
        flow.invalid = { reason: 'orphan_syn_timeout', atTs: now };
        return;
    }
    if (flow.hs === 'SYNACK_SEEN' && flow.timers.synAckExpire && now > flow.timers.synAckExpire) {
        flow.hs = 'INVALID';
        flow.invalid = { reason: 'orphan_synack_timeout', atTs: now };
        return;
    }
}

function detectHandshakePatterns(packets) {
    const handshakes = [];
    const connectionMap = new Map();
    
    // Group packets by connection (src_ip:src_port -> dst_ip:dst_port)
    packets.forEach(packet => {
        if (packet.src_port && packet.dst_port) {
            const connectionKey = `${packet.src_ip}:${packet.src_port}-${packet.dst_ip}:${packet.dst_port}`;
            const reverseKey = `${packet.dst_ip}:${packet.dst_port}-${packet.src_ip}:${packet.src_port}`;
            
            // Use the lexicographically smaller key to ensure consistent ordering
            const key = connectionKey < reverseKey ? connectionKey : reverseKey;
            
            if (!connectionMap.has(key)) {
                connectionMap.set(key, []);
            }
            connectionMap.get(key).push(packet);
        }
    });
    
    // Analyze each connection for handshake patterns
    connectionMap.forEach((connectionPackets, connectionKey) => {
        // Sort packets by timestamp
        connectionPackets.sort((a, b) => a.timestamp - b.timestamp);

        // Look for SYN -> SYN+ACK -> ACK patterns
        const synPackets = connectionPackets.filter(p => getFlagType(p) === 'SYN');
        const synAckPackets = connectionPackets.filter(p => getFlagType(p) === 'SYN+ACK');
        const ackPackets = connectionPackets.filter(p => getFlagType(p) === 'ACK');
        
        // Try to match handshake sequences
        synPackets.forEach(synPacket => {
            // Find corresponding SYN+ACK packet
            const synAckPacket = synAckPackets.find(sa => 
                sa.timestamp > synPacket.timestamp &&
                sa.ack_num === synPacket.seq_num + 1 &&
                ((sa.src_ip === synPacket.dst_ip && sa.dst_ip === synPacket.src_ip) ||
                 (sa.src_ip === synPacket.src_ip && sa.dst_ip === synPacket.dst_ip))
            );
            
            if (synAckPacket) {
                // Find corresponding ACK packet
                const ackPacket = ackPackets.find(ack => 
                    ack.timestamp > synAckPacket.timestamp &&
                    ack.seq_num === synPacket.seq_num + 1 &&
                    ack.ack_num === synAckPacket.seq_num + 1 &&
                    ((ack.src_ip === synPacket.src_ip && ack.dst_ip === synPacket.dst_ip) ||
                     (ack.src_ip === synPacket.dst_ip && ack.dst_ip === synPacket.src_ip))
                );
                
                if (ackPacket) {
                    handshakes.push({
                        connectionKey: connectionKey,
                        syn: synPacket,
                        synAck: synAckPacket,
                        ack: ackPacket,
                        initiator: synPacket.src_ip,
                        responder: synPacket.dst_ip
                    });
                }
            }
        });
    });
    
    return handshakes;
}

function detectClosingPatterns(packets) {
    const closings = [];
    const connectionMap = new Map();
    const connectionStates = new Map(); // Track connection states like tcp_analysis.py
    
    // Group packets by connection (src_ip:src_port -> dst_ip:dst_port)
    packets.forEach(packet => {
        if (packet.src_port && packet.dst_port) {
            const connectionKey = `${packet.src_ip}:${packet.src_port}-${packet.dst_ip}:${packet.dst_port}`;
            const reverseKey = `${packet.dst_ip}:${packet.dst_port}-${packet.src_ip}:${packet.src_port}`;
            
            // Use the lexicographically smaller key to ensure consistent ordering
            const key = connectionKey < reverseKey ? connectionKey : reverseKey;
            
            if (!connectionMap.has(key)) {
                connectionMap.set(key, []);
                // Initialize connection state (matching tcp_analysis.py Conn structure)
                connectionStates.set(key, {
                    initiator: null,
                    responder: null,
                    isn_i: null,
                    isn_r: null,
                    state: TCP_STATES.S_NEW,
                    t_syn: null,
                    t_synack: null,
                    t_ack3: null,
                    t_close: null,
                    close_reason: null,
                    saw_syn_in_capture: false
                });
            }
            connectionMap.get(key).push(packet);
        }
    });
    
    // Process each connection with state machine (matching tcp_analysis.py logic)
    connectionMap.forEach((connectionPackets, connectionKey) => {
        // Sort packets by timestamp
        connectionPackets.sort((a, b) => a.timestamp - b.timestamp);
        
        let state = connectionStates.get(connectionKey);
        let fin1Packet = null, fin2Packet = null, finalAckPacket = null;
        
        // Process packets in order to build state machine
        for (const packet of connectionPackets) {
            const flags = packet.flags;
            const syn = (flags & 0x02) !== 0;
            const ackf = (flags & 0x10) !== 0;
            const fin = (flags & 0x01) !== 0;
            const rst = (flags & 0x04) !== 0;
            
            // SYN packet (handshake start)
            if (syn && !ackf && !rst) {
                if (state.initiator === null) {
                    state.initiator = [packet.src_ip, packet.src_port];
                    state.responder = [packet.dst_ip, packet.dst_port];
                    state.isn_i = packet.seq_num;
                    state.t_syn = packet.timestamp;
                    state.state = TCP_STATES.S_INIT;
                    state.saw_syn_in_capture = true;
                }
            }
            
            // SYN+ACK packet
            else if (syn && ackf && !rst && state.state === TCP_STATES.S_INIT) {
                if (packet.ack_num === state.isn_i + 1) {
                    state.isn_r = packet.seq_num;
                    state.t_synack = packet.timestamp;
                    state.state = TCP_STATES.S_SYN_RCVD;
                }
            }
            
            // Final ACK (handshake complete)
            else if (ackf && !syn && !fin && !rst && state.state === TCP_STATES.S_SYN_RCVD) {
                if (packet.ack_num === state.isn_r + 1) {
                    state.t_ack3 = packet.timestamp;
                    state.state = TCP_STATES.S_EST;
                }
            }
            
            // RST (abortive close)
            else if (rst && state.state >= TCP_STATES.S_EST) {
                state.t_close = packet.timestamp;
                state.close_reason = "rst";
                state.state = TCP_STATES.S_ABORTED;
                break; // Connection terminated
            }
            
            // FIN-based graceful close (matching tcp_analysis.py state machine)
            else if (fin && state.state >= TCP_STATES.S_EST) {
                if (state.state === TCP_STATES.S_EST) {
                    // First FIN received
                    state.state = TCP_STATES.S_FIN_1;
                    fin1Packet = packet;
                } else if (state.state === TCP_STATES.S_FIN_1) {
                    // Second FIN received (from other side)
                    state.state = TCP_STATES.S_FIN_2;
                    fin2Packet = packet;
                }
            }
            // Final ACK after second FIN (normal TCP close)
            else if (ackf && !fin && !syn && !rst && state.state === TCP_STATES.S_FIN_2) {
                state.state = TCP_STATES.S_CLOSED;
                state.t_close = packet.timestamp;
                state.close_reason = "fin";
                finalAckPacket = packet;
                break; // Connection terminated
            }
        }
        
        // If we have a complete closing sequence, add it to results
        if (state.state === TCP_STATES.S_CLOSED && state.close_reason === "fin" && fin1Packet && fin2Packet && finalAckPacket) {
            closings.push({
                connectionKey: connectionKey,
                type: 'graceful_close',
                fin1: fin1Packet,
                fin2: fin2Packet,
                ack: finalAckPacket,
                initiator: state.initiator[0],
                responder: state.responder[0],
                state: state
            });
        }
        // Handle half-close (only one FIN received before connection ends)
        else if (state.state === TCP_STATES.S_FIN_1 && fin1Packet) {
            // Look for ACK to the FIN
            const ackPacket = connectionPackets.find(p => 
                p.timestamp > fin1Packet.timestamp &&
                (p.flags & 0x10) !== 0 && // ACK flag
                p.ack_num === fin1Packet.seq_num + 1 &&
                ((p.src_ip === fin1Packet.dst_ip && p.dst_ip === fin1Packet.src_ip) ||
                 (p.src_ip === fin1Packet.src_ip && p.dst_ip === fin1Packet.dst_ip))
            );
            
            if (ackPacket) {
                closings.push({
                    connectionKey: connectionKey,
                    type: 'half_close',
                    fin1: fin1Packet,
                    ack: ackPacket,
                    initiator: state.initiator[0],
                    responder: state.responder[0],
                    state: state
                });
            }
        }
    });
    
    return closings;
}

function updateHandshakeStats(handshakes) {
    const container = document.getElementById('handshakeStats');
    if (handshakes.length === 0) {
        container.innerHTML = 'No handshakes detected';
        container.style.color = '#666';
    } else {
        container.innerHTML = `Found ${handshakes.length} handshake(s)`;
        container.style.color = '#27ae60';
        
        // Debug info
        LOG('Handshake patterns detected:', handshakes);
    }
}

function updateClosingStats(closings) {
    const container = document.getElementById('closingStats');
    if (closings.length === 0) {
        container.innerHTML = 'No closing patterns detected';
        container.style.color = '#666';
    } else {
        // Group by type
        const typeCounts = {};
        closings.forEach(closing => {
            typeCounts[closing.type] = (closing.typeCounts || 0) + 1;
        });
        
        let statsHTML = `<strong>Found ${closings.length} closing pattern(s)</strong><br>`;
        Object.entries(typeCounts).forEach(([type, count]) => {
            const typeLabel = type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase());
            statsHTML += `${typeLabel}: ${count}<br>`;
        });
        
        container.innerHTML = statsHTML;
        container.style.color = '#27ae60';
    }
}

/**
 * Update the zoom level indicator UI
 */
function updateZoomIndicator(visibleRangeUs, resolution = null) {
    const timeRangeEl = document.getElementById('zoomTimeRange');
    const resSelect = document.getElementById('zoomResolution');
    const currentResIndicator = document.getElementById('currentResolutionLabel');
    if (timeRangeEl) timeRangeEl.textContent = '';

    if (resSelect && resolution) {
        // Get the resolution label
        const resConfig = FETCH_RES_BY_NAME[resolution];
        const label = resConfig?.uiInfo?.label || resolution;
        const icon = resConfig?.uiInfo?.icon || '';

        // Determine what would be auto-selected at this zoom level
        const autoResolution = getAutoResolutionForRange(visibleRangeUs);
        const autoConfig = FETCH_RES_BY_NAME[autoResolution];
        const autoLabel = autoConfig?.uiInfo?.label || autoResolution;

        // Update current resolution indicator
        if (currentResIndicator) {
            currentResIndicator.textContent = `${icon} ${label}`.trim();

            // Style indicator based on whether manual override is active
            const indicatorEl = document.getElementById('currentResolutionIndicator');
            if (indicatorEl) {
                if (manualResolutionOverride) {
                    // Manual override active - highlight in orange
                    indicatorEl.style.background = 'rgba(255, 152, 0, 0.1)';
                    indicatorEl.style.borderColor = 'rgba(255, 152, 0, 0.4)';
                    indicatorEl.style.color = '#ff9800';
                } else {
                    // Auto mode - default blue
                    indicatorEl.style.background = 'rgba(0, 123, 255, 0.1)';
                    indicatorEl.style.borderColor = 'rgba(0, 123, 255, 0.3)';
                    indicatorEl.style.color = '#007bff';
                }
            }
        }

        // Update the "Auto" option text to show what would be auto-selected
        const autoOption = resSelect.querySelector('option[value="auto"]');
        if (autoOption) {
            autoOption.textContent = `Auto (${autoLabel})`;
        }

        // Set dropdown value based on whether manual override is active
        if (manualResolutionOverride) {
            resSelect.value = manualResolutionOverride;
        } else {
            resSelect.value = 'auto';
        }
    }

    // Update zoom button states when zoom level changes
    updateZoomButtonStates({
        getXScale: () => xScale,
        getTimeExtent: () => state.data.timeExtent
    });
}

/**
 * Get the auto-selected resolution for a given visible range (without manual override)
 * This is used to show what "Auto" would select in the dropdown label
 */
function getAutoResolutionForRange(visibleRangeUs) {
    if (!visibleRangeUs || visibleRangeUs <= 0) {
        return 'hours';
    }

    // Use threshold-based logic (same as getResolutionForVisibleRange but without override)
    for (const res of FETCH_RES_CONFIG) {
        if (res.name === 'binned') continue;
        if (visibleRangeUs > res.threshold) {
            return res.name;
        }
    }
    return '1ms';
}

/**
 * Populate the resolution dropdown with available resolutions
 */
function populateResolutionDropdown() {
    const resSelect = document.getElementById('zoomResolution');
    if (!resSelect) return;

    // Clear existing options except Auto
    while (resSelect.options.length > 1) {
        resSelect.remove(1);
    }

    // Add resolution options from config (excluding 'binned' fallback).
    // Each option acts as a ceiling — the coarsest allowed level.
    // "Raw Packets" is the finest, so no "+" suffix needed.
    const realResolutions = FETCH_RES_CONFIG.filter(r => r.name !== 'binned');
    for (let i = 0; i < realResolutions.length; i++) {
        const res = realResolutions[i];
        const option = document.createElement('option');
        option.value = res.name;
        const label = res.uiInfo?.label || res.name;
        // All levels except the finest get a "+" to indicate zoom-to-finer
        option.textContent = (i < realResolutions.length - 1) ? `${label}+` : label;
        resSelect.appendChild(option);
    }

    // Set up change handler
    resSelect.addEventListener('change', handleResolutionDropdownChange);
}

/**
 * Handle resolution dropdown change
 */
async function handleResolutionDropdownChange(event) {
    const selectedValue = event.target.value;

    if (selectedValue === 'auto') {
        manualResolutionOverride = null;
        console.log('[Resolution] Switched to auto mode');
    } else {
        manualResolutionOverride = selectedValue;
        console.log(`[Resolution] Coarsest level set to: ${selectedValue} (zoom refines to finer levels)`);
    }

    // Trigger a data refresh with the new resolution
    await refreshWithCurrentResolution();
}

/**
 * Refresh the visualization with the current (possibly overridden) resolution
 */
async function refreshWithCurrentResolution() {
    if (!xScale || !state.data.timeExtent) {
        console.warn('[Resolution] Cannot refresh - missing xScale or timeExtent');
        return;
    }

    console.log('[Resolution] Refreshing with resolution:', manualResolutionOverride || 'auto');

    let refreshedMainChart = false;

    // Re-fetch data with the new resolution
    if (typeof getMultiResData === 'function' && isMultiResAvailable && isMultiResAvailable()) {
        try {
            const result = await getMultiResData(xScale, 1);
            if (result && result.data && result.data.length > 0) {
                // Update current resolution level
                currentResolutionLevel = result.resolution;
                console.log(`[Resolution] Got ${result.data.length} data points for ${result.resolution}`);

                // Recalculate globalMaxBinCount from the new resolution's data
                const counts = result.data
                    .filter(d => d.count > 0)
                    .map(d => d.count);
                const newMaxCount = counts.length > 0 ? Math.max(...counts) : 1;
                globalMaxBinCount = Math.max(1, newMaxCount);

                // Adjust for collapsed IPs whose merged bins may exceed pre-collapse max
                if (state.layout.collapsedIPs.size > 0) {
                    const dataWithFields = result.data.map(d => ({
                        ...d,
                        binCenter: d.bin_start
                            ? (d.bin_start + (d.bin_end - d.bin_start) / 2)
                            : d.timestamp,
                        flagType: d.flagType || d.flag_type || 'OTHER'
                    }));
                    const collapsed = computeCollapsedMaxCounts(dataWithFields, state.layout.collapsedIPs);
                    if (collapsed) {
                        globalMaxBinCount = Math.max(globalMaxBinCount, collapsed.globalMax);
                    }
                }
                console.log(`[Resolution] Updated globalMaxBinCount to ${globalMaxBinCount}`);

                // Update the size legend to reflect new scale
                try {
                    sbUpdateSizeLegend(globalMaxBinCount, RADIUS_MIN, RADIUS_MAX);
                } catch (e) { logCatchError('sbUpdateSizeLegend', e); }
            } else {
                console.warn(`[Resolution] No data available for ${result?.resolution || 'unknown'} resolution, falling back`);
            }

            // Recompute stable IP pair ordering from the new resolution's data.
            // Update IN PLACE to keep closure references in renderIPRowLabels valid.
            try {
                const newOrderRes = computeIPPairOrderByRow(result.data, state.layout.ipPositions);
                state.layout.ipPairOrderByRow.clear();
                for (const [k, v] of newOrderRes) state.layout.ipPairOrderByRow.set(k, v);
                applyCollapseOverrides(state.layout.ipPairOrderByRow);
            } catch (e) { logCatchError('recomputeIpPairOrder', e); }

            // Invalidate the full domain cache so the zoom handler doesn't
            // short-circuit to the cached layer. This forces it through the
            // multi-res data loading path in its debounced section.
            fullDomainBinsCache = { version: -1, data: [], binSize: null, sorted: false };

            // Trigger the zoom handler to re-render at the new resolution.
            // Do NOT set isHardResetInProgress — that causes the zoom handler
            // to show the full domain cache (which visualizeTimeArcs rebuilds
            // from state.data.filtered, ignoring the resolution override).
            applyZoomDomain(xScale.domain(), 'program');

            // Additional updates after re-render
            try { updateTcpFlowPacketsGlobal(); } catch (e) { logCatchError('updateTcpFlowPacketsGlobal', e); }
            try { drawSelectedFlowArcs(); } catch (e) { logCatchError('drawSelectedFlowArcs', e); }
            try { drawSubRowArcs(); } catch (e) { logCatchError('drawSubRowArcs', e); }
            try { applyInvalidReasonFilter(); } catch (e) { logCatchError('applyInvalidReasonFilter', e); }

            // Update zoom indicator to show new resolution
            const visibleRangeUs = xScale.domain()[1] - xScale.domain()[0];
            const resLabel = result?.resolution || (manualResolutionOverride || 'auto');
            updateZoomIndicator(visibleRangeUs, resLabel);

            refreshedMainChart = true;
        } catch (err) {
            console.error('[Resolution] Failed to refresh data:', err);
        }
    }

    // Always refresh the overview chart (regardless of whether main chart updated)
    const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked'))
        .map(cb => cb.value);

    // Use setTimeout to ensure any pending renders complete first
    setTimeout(() => {
        console.log('[Resolution] Refreshing overview chart...');
        refreshAdaptiveOverview(selectedIPs)
            .then(() => console.log('[Resolution] Overview chart refreshed'))
            .catch(e => console.warn('[Resolution] Overview refresh failed:', e));
    }, refreshedMainChart ? 100 : 0);
}

// Wrapper for exportFlowToCSV that provides the state.data.full and helpers
function exportFlowToCSV(flow) {
    // Prefer embedded packets from flow_list CSV (fp column) when available;
    // fall back to searching state.data.full for CSV-loaded sessions.
    const packetSource = (flow._hasEmbeddedPackets && flow._embeddedPackets?.length > 0)
        ? flow._embeddedPackets
        : state.data.full;
    return exportFlowToCSVFromModule(flow, packetSource, { classifyFlags, formatTimestamp });
}

const createFlowList = (flows) => {
    // Determine if packet data is available
    // If using flow_list.json (summary mode), flows don't have phases/packet data
    const flowListLoader = getFlowListLoader();
    const usingFlowListSummary = flowListLoader.isLoaded() && flowDataState?.hasFlowList;

    // Check if any flow has phases data (indicates packet data is available)
    const flowsHavePacketData = flows.length > 0 && flows.some(f =>
        f.phases && (
            (f.phases.establishment && f.phases.establishment.length > 0) ||
            (f.phases.dataTransfer && f.phases.dataTransfer.length > 0) ||
            (f.phases.closing && f.phases.closing.length > 0)
        )
    );

    // Check if any flow has embedded packet data from flow_list CSV (fp column)
    const flowsHaveEmbeddedPackets = flows.length > 0 && flows.some(f => f._hasEmbeddedPackets);

    // Packet data available if flows have phases, embedded packets, OR if we have CSV data
    const hasPacketData = flowsHavePacketData || flowsHaveEmbeddedPackets || (state.data.full && state.data.full.length > 0);

    return sbCreateFlowListCapped(flows, state.flows.selectedIds, formatBytes, formatTimestamp, exportFlowToCSV, zoomToFlow, updateTcpFlowPacketsGlobal, flowColors, enterFlowDetailMode, hasPacketData);
};

const updateTcpFlowStats = (flows) => sbUpdateTcpFlowStats(flows, state.flows.selectedIds, formatBytes);

/**
 * Refresh the overview chart using the adaptive multi-resolution loader if available.
 * Falls back to the standard refreshFlowOverview() if adaptive loader is not initialized.
 *
 * @param {string[]} selectedIPs - Array of selected IP addresses
 * @param {[number, number]} state.data.timeExtent - Optional time extent override [start, end] in microseconds
 */
async function refreshAdaptiveOverview(selectedIPs, timeExtent = null) {
    // Check if adaptive loader is available
    if (!adaptiveOverviewLoader) {
        console.log('[AdaptiveOverview] Loader not available, falling back to refreshFlowOverview');
        try { refreshFlowOverview(); } catch (e) { console.warn('[Overview] Refresh failed:', e); }
        return;
    }

    // Get selected IPs if not provided
    if (!selectedIPs || selectedIPs.length === 0) {
        selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked'))
            .map(cb => cb.value);
    }

    // Determine time extent (needed for the 90-min threshold check below)
    const effectiveTimeExtent = timeExtent || state.timearcs.overviewTimeExtent || flowDataState?.timeExtent || adaptiveOverviewLoader.getTimeExtent();
    if (!effectiveTimeExtent) {
        console.warn('[AdaptiveOverview] No time extent available');
        try { refreshFlowOverview(); } catch (e) { console.warn('[Overview] Refresh failed:', e); }
        return;
    }

    const [timeStart, timeEnd] = effectiveTimeExtent;

    // Load all IP pairs when time range is <= 90 minutes
    const timeRangeUs = timeEnd - timeStart;
    if (timeRangeUs > 0 && timeRangeUs <= ALL_IP_PAIRS_TIME_THRESHOLD_US) {
        const allIPs = getAllFlowDataIPs();
        if (allIPs && allIPs.length >= 2) {
            console.log(`[AdaptiveOverview] Time range ${(timeRangeUs / 60_000_000).toFixed(1)} min <= 90 min — using all ${allIPs.length} IPs`);
            selectedIPs = allIPs;
        }
    }

    if (selectedIPs.length < 2) {
        console.log('[AdaptiveOverview] Need at least 2 IPs selected');
        // Still render an empty overview
        try { refreshFlowOverview(); } catch (e) { console.warn('[Overview] Refresh failed:', e); }
        return;
    }

    console.log(`[AdaptiveOverview] Refreshing with ${selectedIPs.length} IPs, time range: ${((timeEnd - timeStart) / 60_000_000).toFixed(1)} minutes`);

    // Map main chart resolution to overview chart resolution
    // Main chart: 'hours', 'minutes', 'seconds', '100ms', '10ms', '1ms', 'raw'
    // Overview chart: 'hour', '10min', '1min', '1s'
    const MAIN_TO_OVERVIEW_RESOLUTION = {
        'hours': 'hour',
        'minutes': '1min',
        '10s': '1min',
        'seconds': '1s',
        '100ms': '1s',
        '10ms': '1s',
        '1ms': '1s',
        'raw': '1s'
    };

    // Determine overview resolution - sync with main chart if manual override is active
    let overviewResolution = null;
    if (manualResolutionOverride) {
        overviewResolution = MAIN_TO_OVERVIEW_RESOLUTION[manualResolutionOverride];
        console.log(`[AdaptiveOverview] Using manual resolution override: ${manualResolutionOverride} → ${overviewResolution}`);
    }

    try {
        // Get adaptive overview data
        const adaptiveData = await adaptiveOverviewLoader.getOverviewData(
            selectedIPs,
            timeStart,
            timeEnd,
            { targetBinCount: 100, resolution: overviewResolution }
        );

        console.log(`[AdaptiveOverview] Got ${adaptiveData.bins.length} bins at ${adaptiveData.resolution} resolution`);

        // Get chart dimensions
        const container = document.getElementById('chart-container');
        const containerWidth = container ? container.clientWidth : 800;
        const margins = { left: 150, right: 120, top: 80, bottom: 50 };
        const chartWidth = Math.max(100, containerWidth - margins.left - margins.right);

        // Render using the adaptive function
        createOverviewFromAdaptive(adaptiveData, {
            timeExtent: effectiveTimeExtent,
            width: chartWidth,
            margins
        });

        console.log(`[AdaptiveOverview] Rendered overview chart with ${adaptiveData.resolution} resolution`);
    } catch (err) {
        console.error('[AdaptiveOverview] Error:', err);
        // Fall back to standard refresh
        try { refreshFlowOverview(); } catch (e) { console.warn('[Overview] Refresh failed:', e); }
    }
}

function filterIPList(searchTerm) {
    const ipItems = document.querySelectorAll('.ip-item');
    ipItems.forEach(item => {
        const ip = item.dataset.ip;
        const matches = ip.toLowerCase().includes(searchTerm.toLowerCase());
        item.style.display = matches ? 'block' : 'none';
    });
}

// createTooltipHTML is now imported from './src/rendering/tooltip.js'

/**
 * Build IP connectivity map from packet data.
 * Maps each IP to the set of IPs it communicates with.
 * @param {Array} packets - Array of packet objects with src_ip and dst_ip
 * @returns {Map<string, Set<string>>} - Map of IP -> Set of connected IPs
 */
function buildIPConnectivity(packets) {
    const connectivity = new Map();
    for (const p of packets) {
        if (!p.src_ip || !p.dst_ip) continue;
        // Add bidirectional connections
        if (!connectivity.has(p.src_ip)) connectivity.set(p.src_ip, new Set());
        if (!connectivity.has(p.dst_ip)) connectivity.set(p.dst_ip, new Set());
        connectivity.get(p.src_ip).add(p.dst_ip);
        connectivity.get(p.dst_ip).add(p.src_ip);
    }
    return connectivity;
}

// Global function to find the correct Y position for an IP (single row per IP)
function findIPPosition(ip, _src_ip, _dst_ip, _pairs, ipPositions) {
    if (!ipPositions) return 0;
    return ipPositions.get(ip) || 0;
}

// Async CSV parsing with progress tracking
async function parseCSVAsync(csvText, onProgress) {
    const lines = csvText.split('\n').filter(line => line.trim().length > 0);
    if (lines.length < 2) return [];
    
    // Parse header line
    const headerLine = lines[0];
    const headers = [];
    let current = '';
    let inQuotes = false;
    
    for (let j = 0; j < headerLine.length; j++) {
        const char = headerLine[j];
        if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
            headers.push(current.trim());
            current = '';
        } else {
            current += char;
        }
    }
    headers.push(current.trim());
    
    const packets = [];
    const totalLines = lines.length - 1; // Exclude header
    const BATCH_SIZE = 1000; // Process in batches for progress updates
    
    for (let i = 1; i < lines.length; i += BATCH_SIZE) {
        const endIndex = Math.min(i + BATCH_SIZE, lines.length);
        
        for (let lineIndex = i; lineIndex < endIndex; lineIndex++) {
            const line = lines[lineIndex];
            if (!line.trim()) continue;
            
            const values = [];
            current = '';
            inQuotes = false;
            
            for (let j = 0; j < line.length; j++) {
                const char = line[j];
                if (char === '"') {
                    inQuotes = !inQuotes;
                } else if (char === ',' && !inQuotes) {
                    values.push(current.trim());
                    current = '';
                } else {
                    current += char;
                }
            }
            values.push(current.trim());
            
            if (values.length >= headers.length) {
                const packet = {};
                for (let k = 0; k < headers.length; k++) {
                    const header = headers[k].toLowerCase().replace(/[^a-z0-9]/g, '_');
                    let value = values[k];
                    
                    // Type conversion
                    if (header.includes('time') || header.includes('timestamp')) {
                        value = parseFloat(value) || 0;
                    } else if (header.includes('length') || header.includes('size') || header.includes('port') || header.includes('seq') || header.includes('ack')) {
                        value = parseInt(value) || 0;
                    }
                    
                    packet[header] = value;
                }
                
                if (packet.src_ip && packet.dst_ip && packet.timestamp) {
                    packets.push(packet);
                }
            }
        }
        
        // Update progress
        if (onProgress) {
            const progress = (endIndex - 1) / totalLines;
            onProgress(progress, `Parsing CSV... ${(endIndex - 1).toLocaleString()}/${totalLines.toLocaleString()} lines`);
        }
        
        // Allow UI to update
        if (i % (BATCH_SIZE * 5) === 0) {
            await new Promise(resolve => setTimeout(resolve, 0));
        }
    }
    
    LOG(`Parsed ${packets.length} packets from ${lines.length - 1} CSV lines`);
    return packets;
}

// CSV parsing helper function
function parseCSV(csvText) {
    const lines = csvText.split('\n').filter(line => line.trim().length > 0);
    if (lines.length < 2) return [];
    
    // Parse header line
    const headerLine = lines[0];
    const headers = [];
    let current = '';
    let inQuotes = false;
    
    for (let j = 0; j < headerLine.length; j++) {
        const char = headerLine[j];
        if (char === '"') {
            inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
            headers.push(current.trim().replace(/"/g, ''));
            current = '';
        } else {
            current += char;
        }
    }
    headers.push(current.trim().replace(/"/g, ''));
    
    LOG(`CSV has ${headers.length} columns:`, headers.slice(0, 10));
    
    const packets = [];
    
    // Parse data lines
    for (let i = 1; i < lines.length; i++) {
        const values = [];
        const line = lines[i];
        current = '';
        inQuotes = false;
        
        // Parse each field in the line
        for (let j = 0; j < line.length; j++) {
            const char = line[j];
            if (char === '"') {
                inQuotes = !inQuotes;
            } else if (char === ',' && !inQuotes) {
                values.push(current.trim().replace(/"/g, ''));
                current = '';
            } else {
                current += char;
            }
        }
        values.push(current.trim().replace(/"/g, ''));
        
        // Only process lines with enough values
        if (values.length >= headers.length - 5) { // Allow some tolerance for missing fields
            const packet = {};
            headers.forEach((header, index) => {
                const value = values[index] || '';
                
                // Convert numeric fields
                if (['timestamp', 'src_port', 'dst_port', 'flags', 'seq_num', 'ack_num', 'length', 
                     'flow_start_time', 'flow_end_time', 'flow_total_packets', 'flow_total_bytes',
                     'establishment_packets', 'data_transfer_packets', 'closing_packets',
                     'src_sent_packets', 'src_recv_packets', 'src_sent_bytes', 'src_recv_bytes',
                     'src_first_ts', 'src_last_ts', 'dst_sent_packets', 'dst_recv_packets',
                     'dst_sent_bytes', 'dst_recv_bytes', 'dst_first_ts', 'dst_last_ts'].includes(header)) {
                    packet[header] = parseFloat(value) || 0;
                } else if (['establishment_complete', 'data_transfer_started', 'closing_started'].includes(header)) {
                    packet[header] = value.toLowerCase() === 'true';
                } else {
                    packet[header] = value || '';
                }
            });
            
            packet.timestamp = Math.floor(packet.timestamp);
            if (packet.timestamp > 0 && packet.src_ip && packet.dst_ip) {
                packets.push(packet);
            }
        }
        if (i % 10000 === 0) {
            LOG(`Parsed ${i}/${lines.length} lines...`);
        }
    }
    
    LOG(`Successfully parsed ${packets.length} packets from ${lines.length - 1} CSV lines`);
    return packets;
}

function handleFileLoad(event) {
    const file = event.target.files[0];
    if (!file) return;
    
    // Show CSV loading progress
    try { sbShowCsvProgress('Reading CSV file...', 0); } catch(e) { logCatchError('sbShowCsvProgress', e); }
    
    const reader = new FileReader();
    reader.onload = async e => {
        try {
            const csvText = e.target.result;
            
            // Update progress for parsing phase
            try { sbUpdateCsvProgress(0.1, 'Parsing CSV data...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
            
            const packets = await parseCSVAsync(csvText, (progress, label) => {
                try { sbUpdateCsvProgress(0.1 + (progress * 0.4), label); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
            });
            
            if (packets && packets.length > 0) {
                // Packets
                state.data.full = packets;
                state.data.filtered = [];

                // Process TCP flows with progress
                try { sbUpdateCsvProgress(0.5, 'Processing TCP flows...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
                try { sbShowFlowProgress('Processing flows…', 0); } catch(e) { logCatchError('sbShowFlowProgress', e); }
                const flowsFromCSV = await reconstructFlowsFromCSVAsync(packets, (processed, total) => {
                    try {
                        const pct = total > 0 ? processed / total : 0;
                        sbUpdateFlowProgress(pct, `Processing flows… ${processed.toLocaleString()}/${total.toLocaleString()}`);
                        // Update CSV progress (flows processing is 50-90% of total)
                        sbUpdateCsvProgress(0.5 + (pct * 0.4), `Processing flows… ${processed.toLocaleString()}/${total.toLocaleString()}`);
                    } catch(e) { logCatchError('flowProgressUpdate', e); }
                });
                state.flows.tcp = flowsFromCSV;
                state.flows.current = []; // Initialize as empty - will be populated when IPs are selected
                state.flows.selectedIds.clear(); // Clear selected flow IDs
                // Don't populate flow list or stats until IPs are selected
                updateTcpFlowStats(state.flows.current); // Show initial message about selecting IPs

                // IPs - extract unique IPs from packet data
                try { sbUpdateCsvProgress(0.9, 'Extracting IP addresses...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
                const uniqueIPs = Array.from(new Set(state.data.full.flatMap(p => [p.src_ip, p.dst_ip]))).filter(Boolean);
                createIPCheckboxes(uniqueIPs);

                // Apply pre-filter if opened from TimeArcs brush selection
                applyBrushSelectionPrefilter();

                // If no IPs were pre-selected (no brush), auto-select all IPs
                const anyCheckedCSV = document.querySelector('#ipCheckboxes input[type="checkbox"]:checked');
                if (!anyCheckedCSV) {
                    console.log('[CSV] No brush pre-filter — selecting all IPs');
                    document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = true);
                    setTimeout(() => updateIPFilter(), 100);
                }

                document.getElementById('loadingMessage').textContent = 'Please select 2 or more IP addresses to view connections.';
                document.getElementById('loadingMessage').style.display = 'block';
                
                LOG(`Loaded ${packets.length} packets from CSV with ${uniqueIPs.length} unique IPs`);
                
                // Verify flow-packet connection
                verifyFlowPacketConnection(packets, flowsFromCSV);
                // Initialize web worker after packets parsed - will sync with rendered data later
                try {
                    try { sbUpdateCsvProgress(0.95, 'Initializing web worker...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
                    if (!workerManager) {
                        initializeWorkerManager();
                    }
                    // Don't init packets here - will sync with rendered data after visualization is built
                } catch (err) {
                    console.error('Worker init failed', err);
                }
                
                // Complete loading
                try { sbUpdateCsvProgress(1.0, 'Loading complete!'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
                try { sbHideFlowProgress(); } catch(e) { logCatchError('sbHideFlowProgress', e); }
                setTimeout(() => {
                    try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
                }, 1000);
            } else {
                try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
                alert('Invalid CSV format: No valid packet data found.');
            }
        } catch (error) { 
            try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
            alert('Error parsing CSV file: ' + error.message); 
        }
    };
    reader.readAsText(file);
}

function highlight(selected) {
    if (!svg || !mainGroup) return;
    const hasSelection = selected && (selected.ip || selected.flag);

    // Get connected IPs for row highlighting
    const connectedIPs = hasSelection && selected.ip && state.layout.ipConnectivity
        ? state.layout.ipConnectivity.get(selected.ip) || new Set()
        : new Set();

    if (hasSelection && selected.ip && selected.pairIp) {
        // Pair-specific highlighting (sub-row hover)
        const pairKey = makeIpPairKey(selected.ip, selected.pairIp);

        // Labels: highlight the two IPs in this pair, fade others
        svg.selectAll(".node-label")
            .classed("faded", d => d !== selected.ip && d !== selected.pairIp)
            .classed("highlighted", d => d === selected.ip)
            .classed("connected", d => d === selected.pairIp);

        // Dots: only show this pair's dots
        mainGroup.selectAll(".direction-dot")
            .classed("faded", d => d.ipPairKey !== pairKey && d.ipPairKey !== '__collapsed__')
            .classed("highlighted", d => d.ipPairKey === pairKey);

        // Bar segments: same treatment (collapsed bins stay visible like dots)
        mainGroup.selectAll(".bin-bar-segment")
            .style("opacity", d => {
                const k = d.ipPairKey || (d.datum && d.datum.ipPairKey);
                return (k === pairKey || k === '__collapsed__') ? 0.8 : 0.05;
            });

        // Determine if each IP has sub-row highlights (expanded with >1 pair)
        const pairIpHasSubRows = (state.layout.ipPairCounts?.get(selected.pairIp) || 1) > 1
            && !state.layout.collapsedIPs.has(selected.pairIp);
        const selfIpHasSubRows = (state.layout.ipPairCounts?.get(selected.ip) || 1) > 1
            && !state.layout.collapsedIPs.has(selected.ip);

        // Row highlights: use full row-highlight for IPs without sub-rows
        svg.selectAll(".row-highlight")
            .classed("active", d => d === selected.pairIp && !pairIpHasSubRows)
            .classed("self", d => d === selected.ip && !selfIpHasSubRows);

        // Sub-row highlights: activate matching pair on expanded rows
        svg.selectAll(".sub-row-highlight")
            .classed("active", d => d && d.pairKey === pairKey && d.ip === selected.pairIp)
            .classed("self", d => d && d.pairKey === pairKey && d.ip === selected.ip);

    } else if (hasSelection && selected.ip) {
        // Simple IP-based highlighting
        svg.selectAll(".node-label")
            .classed("faded", d => d !== selected.ip && !connectedIPs.has(d))
            .classed("highlighted", d => d === selected.ip)
            .classed("connected", d => d !== selected.ip && connectedIPs.has(d));

        mainGroup.selectAll(".direction-dot")
            .classed("faded", d => {
                if (d.allIPs) return !d.allIPs.has(selected.ip);
                return d.src_ip !== selected.ip && d.dst_ip !== selected.ip;
            })
            .classed("highlighted", d => {
                if (d.allIPs) return d.allIPs.has(selected.ip);
                return d.src_ip === selected.ip || d.dst_ip === selected.ip;
            });

        // Highlight row backgrounds for connected IPs
        svg.selectAll(".row-highlight")
            .classed("active", d => connectedIPs.has(d))
            .classed("self", d => d === selected.ip);

        // Clear sub-row highlights
        svg.selectAll(".sub-row-highlight")
            .classed("active", false)
            .classed("self", false);

        // Clear bar segment overrides
        mainGroup.selectAll(".bin-bar-segment").style("opacity", null);

    } else if (hasSelection && selected.flag) {
        // Flag-based highlighting
        mainGroup.selectAll(".direction-dot")
            .classed("faded", d => getFlagType(d) !== selected.flag)
            .classed("highlighted", d => getFlagType(d) === selected.flag);

        // Clear row highlights
        svg.selectAll(".row-highlight")
            .classed("active", false)
            .classed("self", false);
        svg.selectAll(".sub-row-highlight")
            .classed("active", false)
            .classed("self", false);
        mainGroup.selectAll(".bin-bar-segment").style("opacity", null);
    } else {
        // No selection - reset all highlighting
        mainGroup.selectAll(".direction-dot")
            .classed("faded", false)
            .classed("highlighted", false);
        svg.selectAll(".node-label")
            .classed("faded", false)
            .classed("highlighted", false)
            .classed("connected", false);
        svg.selectAll(".row-highlight")
            .classed("active", false)
            .classed("self", false);
        svg.selectAll(".sub-row-highlight")
            .classed("active", false)
            .classed("self", false);
        mainGroup.selectAll(".bin-bar-segment").style("opacity", null);
    }

    // Update flag stats highlighting
    document.querySelectorAll('#flagStats [data-flag]').forEach(item => {
        if (hasSelection && selected.flag) {
            if (item.dataset.flag === selected.flag) {
                item.style.backgroundColor = '#e9ecef';
                item.style.fontWeight = 'bold';
            } else {
                item.style.opacity = '0.3';
            }
        } else {
            item.style.backgroundColor = '';
            item.style.fontWeight = '';
            item.style.opacity = '';
        }
    });
}


function zoomToFlow(flow) {
    if (!flow || !svg || !zoom || !xScale || !state.data.timeExtent || !Array.isArray(state.data.full)) {
        console.warn('Cannot zoom to flow: missing required objects');
        return;
    }
    let minTs = Math.floor(typeof flow.startTime === 'number' ? flow.startTime : NaN);
    let maxTs = Math.floor(typeof flow.endTime === 'number' ? flow.endTime : NaN);
    if (!Number.isFinite(minTs) || !Number.isFinite(maxTs)) {
        console.warn('zoomToFlow: Could not determine packet time range for flow', flow);
        return;
    }
    const totalRange = state.data.timeExtent[1] - state.data.timeExtent[0];
    const minPaddingUs = 50000; // 0.05s minimum margin on each side
    const paddingPixels = 2; // desired pixel padding on each side (very tight)
    const paddingPercent = 0.005; // 0.5% of the flow duration on each side (very tight)
    const timePerPixel = totalRange / Math.max(1, width);
    const paddingFromPixels = Math.ceil(paddingPixels * timePerPixel);
    const flowDuration = Math.max(1, maxTs - minTs);
    const paddingFromPercent = Math.ceil(flowDuration * paddingPercent);
    const cappedPercentPadding = Math.min(paddingFromPercent, Math.ceil(flowDuration * 0.25));
    const padding = Math.max(minPaddingUs, Math.min(paddingFromPixels, cappedPercentPadding));
    let zoomStart = minTs - padding;
    let zoomEnd = maxTs + padding;
    zoomStart = Math.max(state.data.timeExtent[0], Math.floor(zoomStart));
    zoomEnd = Math.min(state.data.timeExtent[1], Math.ceil(zoomEnd));
    if (zoomEnd <= zoomStart) zoomEnd = zoomStart + 1;
    applyZoomDomain([zoomStart, zoomEnd], 'flow');
    if (typeof updateBrushFromZoom === 'function') {
        try { window.__arc_x_domain__ = xScale.domain(); updateBrushFromZoom(); } catch(e) { logCatchError('updateBrushFromZoom', e); }
    }
}

/**
 * Load flow detail via fetch API (used when File System API is not available)
 * @param {Object} flowSummary - Flow summary with id, startTime
 * @param {Object} state - flowDataState with basePath and chunksMeta
 * @returns {Promise<Object|null>} Flow object with phases or null
 */
async function loadFlowDetailViaFetch(flowSummary, state) {
    const { basePath, chunksMeta, format, getChunkPath } = state;
    const flowId = flowSummary.id;
    const flowStartTime = flowSummary.startTime;
    const { initiator, responder, initiatorPort, responderPort } = flowSummary;

    console.log(`[FlowDetail-Fetch] ========================================`);
    console.log(`[FlowDetail-Fetch] Loading flow ${flowId} via fetch`);
    console.log(`[FlowDetail-Fetch] flowStartTime: ${flowStartTime}`);
    console.log(`[FlowDetail-Fetch] basePath: ${basePath}`);
    console.log(`[FlowDetail-Fetch] format: ${format}`);
    console.log(`[FlowDetail-Fetch] chunksMeta count: ${chunksMeta ? chunksMeta.length : 'null'}`);
    console.log(`[FlowDetail-Fetch] Connection: ${initiator}:${initiatorPort} ↔ ${responder}:${responderPort}`);

    // Find ALL chunks that could contain this flow (by time range AND IPs)
    // Note: Flow IDs do NOT map to chunk indices - chunks are organized by time, not ID
    const candidateChunks = [];
    for (const chunk of chunksMeta) {
        // Check time range - flow startTime should be within chunk's time range
        if (chunk.start <= flowStartTime && flowStartTime <= chunk.end) {
            // Also check if chunk contains both initiator and responder IPs
            const chunkIPs = chunk.ips || [];
            const hasInitiator = chunkIPs.includes(initiator);
            const hasResponder = chunkIPs.includes(responder);

            if (hasInitiator && hasResponder) {
                candidateChunks.push(chunk);
            }
        }
    }

    console.log(`[FlowDetail-Fetch] Found ${candidateChunks.length} candidate chunks`);

    if (candidateChunks.length === 0) {
        console.error(`Unable to find chunk for flow ${flowId} (${initiator} ↔ ${responder} @ ${flowStartTime})`);
        return null;
    }

    // Search through all candidate chunks until we find the flow
    for (const chunk of candidateChunks) {
        try {
            // Construct chunk path based on format
            let chunkPath;
            if (getChunkPath) {
                chunkPath = getChunkPath(chunk);
            } else if (format === 'chunked_flows_by_ip_pair' && chunk.folder) {
                chunkPath = `${basePath}/flows/by_pair/${chunk.folder}/${chunk.file}`;
            } else {
                chunkPath = `${basePath}/flows/${chunk.file}`;
            }
            console.log(`[FlowDetail-Fetch] Searching chunk ${chunk.file} at ${chunkPath}...`);
            const response = await fetch(chunkPath);
            if (!response.ok) {
                console.warn(`[FlowDetail-Fetch] Failed to load ${chunkPath}: HTTP ${response.status}`);
                continue;
            }
            const flows = await response.json();

            // Try to find by ID first
            let flow = flows.find(f => f.id === flowId);

            // If not found by ID, try matching by connection tuple + startTime
            if (!flow) {
                flow = flows.find(f =>
                    f.initiator === initiator &&
                    f.responder === responder &&
                    f.initiatorPort === initiatorPort &&
                    f.responderPort === responderPort &&
                    Math.abs(f.startTime - flowStartTime) < 1000 // Within 1ms
                );
            }

            if (flow) {
                const packetCount = countFlowPacketsLocal(flow);
                console.log(`[FlowDetail-Fetch] ✅ Found flow ${flowId} in ${chunk.file} with ${packetCount} packets`);
                console.log(`[FlowDetail-Fetch] Flow has phases:`, flow.phases ? Object.keys(flow.phases) : 'none');
                console.log(`[FlowDetail-Fetch] ========================================`);
                return flow;
            }
            console.log(`[FlowDetail-Fetch] Flow not in ${chunkPath}, continuing search...`);
        } catch (err) {
            console.warn(`[FlowDetail-Fetch] Error searching ${chunkPath}:`, err);
            // Continue to next chunk
        }
    }

    // Flow not found in any candidate chunk
    console.error(`[FlowDetail-Fetch] ❌ Flow ${flowId} not found in any of ${candidateChunks.length} candidate chunks`);
    console.log(`[FlowDetail-Fetch] ========================================`);
    return null;
}

/**
 * Extract packets from a flow's phases into a flat array (local version)
 * @param {Object} flow - Flow object with phases
 * @returns {Array} Array of packet objects
 */
function extractPacketsFromFlowLocal(flow) {
    if (!flow || !flow.phases) return [];

    const packets = [];
    const phases = ['establishment', 'dataTransfer', 'closing'];

    for (const phaseName of phases) {
        const phasePackets = flow.phases[phaseName] || [];
        for (const entry of phasePackets) {
            if (entry.packet) {
                packets.push({
                    ...entry.packet,
                    phase: phaseName,
                    phaseStep: entry.phase || entry.description || phaseName
                });
            }
        }
    }

    // Sort by timestamp
    packets.sort((a, b) => a.timestamp - b.timestamp);

    console.log(`[FlowDetail] Extracted ${packets.length} packets from flow`);
    return packets;
}

/**
 * Count packets in a flow's phases (local version)
 */
function countFlowPacketsLocal(flow) {
    if (!flow || !flow.phases) return 0;
    const est = flow.phases.establishment?.length || 0;
    const data = flow.phases.dataTransfer?.length || 0;
    const close = flow.phases.closing?.length || 0;
    return est + data + close;
}

/**
 * Enter flow detail mode - show only packets from a single flow with permanent arcs
 * @param {Object} flowSummary - Flow summary object from flow list
 */
async function enterFlowDetailMode(flowSummary) {
    console.log('[FlowDetail] enterFlowDetailMode called');
    console.log('[FlowDetail] flowSummary:', flowSummary);

    if (!flowSummary) {
        console.warn('[FlowDetail] Cannot enter flow detail mode: no flow provided');
        return;
    }

    console.log('[FlowDetail] Entering flow detail mode for:', flowSummary.id);

    // Save current state for restoration
    state.flowDetail.previousState = {
        filteredData: state.data.filtered,
        xScaleDomain: xScale ? xScale.domain().slice() : null,
        selectedFlowIds: new Set(state.flows.selectedIds),
        showTcpFlows: state.ui.showTcpFlows
    };

    // Show loading indicator
    const loadingIndicator = showFlowDetailLoading(flowSummary);

    try {
        let fullFlow = null;
        let packets = null;

        // First, check if the flow has embedded packet data (from flow_list CSV with fp column)
        if (flowSummary._hasEmbeddedPackets && flowSummary._embeddedPackets) {
            console.log('[FlowDetail] Using embedded packet data from flow_list CSV');
            const flowListLoader = getFlowListLoader();
            fullFlow = flowListLoader.buildFullFlow(flowSummary);
            if (fullFlow) {
                packets = flowSummary._embeddedPackets;
                console.log(`[FlowDetail] Built flow from ${packets.length} embedded packets`);
            }
        }

        // Try File System API if no embedded packets (folder_integration.js)
        if (!fullFlow && typeof getChunkedFlowState === 'function') {
            const chunkedState = getChunkedFlowState();
            if (chunkedState && typeof loadFlowDetailWithPackets === 'function') {
                console.log('[FlowDetail] Using File System API to load flow detail');
                fullFlow = await loadFlowDetailWithPackets(flowSummary);
            }
        }

        // Fallback to fetch API using flowDataState
        if (!fullFlow && flowDataState && flowDataState.basePath && flowDataState.chunksMeta) {
            console.log('[FlowDetail] Using fetch API to load flow detail');
            fullFlow = await loadFlowDetailViaFetch(flowSummary, flowDataState);
        }

        if (!fullFlow) {
            console.error('[FlowDetail] Failed to load flow detail - no loader available');
            hideFlowDetailLoading(loadingIndicator);
            alert('Unable to load flow detail. Please ensure a flows folder is loaded or flow list has packet data.');
            return;
        }

        // Extract packets from phases if not already set from embedded data
        if (!packets) {
            packets = extractPacketsFromFlowLocal(fullFlow);
        }
        if (!packets || packets.length === 0) {
            console.warn('[FlowDetail] No packets found in flow');
            hideFlowDetailLoading(loadingIndicator);
            return;
        }

        // Store flow detail state
        state.flowDetail.mode = true;
        state.flowDetail.flow = fullFlow;
        state.flowDetail.packets = packets;

        // Update the visualization with flow packets
        renderFlowDetailView(fullFlow, packets);

        // Show flow detail mode indicator
        showFlowDetailModeUI(fullFlow);

        hideFlowDetailLoading(loadingIndicator);
        console.log(`[FlowDetail] Now showing ${packets.length} packets for flow ${fullFlow.id}`);

    } catch (err) {
        console.error('[FlowDetail] Error entering flow detail mode:', err);
        hideFlowDetailLoading(loadingIndicator);
        state.flowDetail.mode = false;
        state.flowDetail.flow = null;
        state.flowDetail.packets = [];
    }
}

/**
 * Exit flow detail mode - restore packets folder view
 */
function exitFlowDetailMode() {
    if (!state.flowDetail.mode) return;

    console.log('[FlowDetail] Exiting flow detail mode');

    // Clear flow detail state
    state.flowDetail.mode = false;
    state.flowDetail.flow = null;
    state.flowDetail.packets = [];

    // Hide flow detail mode UI
    hideFlowDetailModeUI();

    // Restore previous state
    if (state.flowDetail.previousState) {
        state.data.filtered = state.flowDetail.previousState.filteredData;
        state.flows.selectedIds = state.flowDetail.previousState.selectedFlowIds;
        state.ui.showTcpFlows = state.flowDetail.previousState.showTcpFlows;

        // Restore zoom domain first
        if (state.flowDetail.previousState.xScaleDomain && xScale) {
            applyZoomDomain(state.flowDetail.previousState.xScaleDomain, 'restore');
        }

        // Check if we're in flow mode (folder-based data) or packet mode (CSV data)
        if (flowDataState && (flowDataState.format === 'chunked_flows' || flowDataState.format === 'chunked_flows_by_ip_pair')) {
            // Flow mode: call updateIPFilter to refresh the flow visualization
            // This will re-render the overview chart and flow bars
            console.log('[FlowDetail] Restoring flow mode visualization');
            updateIPFilter().catch(err => {
                console.error('[FlowDetail] Error restoring flow view:', err);
            });
        } else if (state.data.filtered && state.data.filtered.length > 0) {
            // Packet mode: re-render with restored packet data
            visualizeTimeArcs(state.data.filtered);
        }

        state.flowDetail.previousState = null;
    }

    console.log('[FlowDetail] Restored to normal view');
}

/**
 * Render the flow detail view with packets and permanent arcs
 */
function renderFlowDetailView(flow, packets) {
    if (!svg || !mainGroup || !xScale) return;

    // Get flow IPs
    const flowIPs = [flow.initiator, flow.responder].filter(Boolean);

    // Calculate time extent from packets with padding
    const pktTimeExtent = d3.extent(packets, d => d.timestamp);
    const duration = pktTimeExtent[1] - pktTimeExtent[0];
    const padding = Math.max(50000, duration * 0.1); // 10% padding or 50ms minimum
    const viewTimeExtent = [pktTimeExtent[0] - padding, pktTimeExtent[1] + padding];

    // Update xScale domain and sync zoom transform
    xScale.domain(viewTimeExtent);

    // Apply zoom domain to sync the zoom behavior with the new scale
    // This ensures brush interactions work correctly in flow detail mode
    applyZoomDomain(viewTimeExtent, 'flowdetail');

    // Update the brush position to show the flow's time range in the overview
    try { window.__arc_x_domain__ = viewTimeExtent; updateBrushFromZoom(); } catch(e) { logCatchError('updateBrushFromZoom', e); }

    // Clear existing visualization elements
    if (fullDomainLayer) fullDomainLayer.selectAll('*').remove();
    if (dynamicLayer) dynamicLayer.selectAll('*').remove();
    mainGroup.selectAll('.flow-arc').remove();
    mainGroup.selectAll('.flow-detail-arc').remove();
    mainGroup.selectAll('.flow-threading-arc').remove();
    mainGroup.selectAll('.flow-threading-arcs').remove();

    // Ensure IPs are in state.layout.ipPositions
    flowIPs.forEach(ip => {
        if (!state.layout.ipPositions.has(ip)) {
            const currentMax = Math.max(...Array.from(state.layout.ipPositions.values()), 0);
            state.layout.ipPositions.set(ip, currentMax + ROW_GAP);
        }
    });

    // Prepare packets for rendering - add y positions with sub-row offset and flag info
    const preparedPackets = packets.map((p, idx) => ({
        ...p,
        _packetIndex: idx,
        yPos: getIPYWithSubRowOffset(p.src_ip, p.src_ip, p.dst_ip),
        flagType: p.flag_type || classifyFlags(p.flags) || 'OTHER',
        binned: false,
        count: 1,
        originalPackets: [p]
    }));

    // Render packets as dots (no binning in detail view)
    const rScale = d3.scaleSqrt().domain([1, 10]).range([RADIUS_MIN, RADIUS_MAX]);
    renderMarksForLayerLocal(dynamicLayer, preparedPackets, rScale);
    dynamicLayer.style('display', null);

    // Draw permanent sequential arcs connecting packets
    mainGroup.selectAll('.flow-detail-arc').remove();
    mainGroup.selectAll('.flow-detail-arcs').remove();
    const fdLineGroup = mainGroup.append('g').attr('class', 'flow-detail-arcs').attr('clip-path', 'url(#clip)');
    drawFlowDetailArcs(fdLineGroup, 'flow-detail-arc', preparedPackets,
        p => xScale(p.timestamp),
        p => p.yPos || getIPYWithSubRowOffset(p.src_ip, p.src_ip, p.dst_ip));

    // For single-packet flows, draw an S-curve from source IP to destination IP
    if (preparedPackets.length === 1) {
        const p = preparedPackets[0];
        const px = xScale(p.timestamp);
        const srcY = p.yPos || getIPYWithSubRowOffset(p.src_ip, p.src_ip, p.dst_ip);
        const dstY = getIPYWithSubRowOffset(p.dst_ip, p.src_ip, p.dst_ip);
        if (srcY != null && dstY != null && Math.abs(dstY - srcY) > 1) {
            const ft = p.flagType || classifyFlags(p.flags) || 'OTHER';
            const color = flagColors[ft] || flagColors['OTHER'] || '#999';
            const trailEndX = px + 40;
            const midX = (px + trailEndX) / 2;
            fdLineGroup.append('path')
                .attr('class', 'flow-detail-arc')
                .attr('d', `M${px},${srcY} C${midX},${srcY} ${midX},${dstY} ${trailEndX},${dstY}`)
                .attr('fill', 'none')
                .attr('stroke', color)
                .attr('stroke-width', 1.5)
                .attr('stroke-opacity', 0.6);
            const arrowLen = 5, arrowHalfW = 3;
            const a = Math.atan2(2 * (dstY - srcY), trailEndX - px);
            const ca = Math.cos(a), sa = Math.sin(a);
            const mx = midX, my = (srcY + dstY) / 2;
            fdLineGroup.append('polygon')
                .attr('class', 'flow-detail-arc')
                .attr('points', `${mx+arrowLen*ca},${my+arrowLen*sa} ${mx-arrowLen*ca+arrowHalfW*sa},${my-arrowLen*sa-arrowHalfW*ca} ${mx-arrowLen*ca-arrowHalfW*sa},${my-arrowLen*sa+arrowHalfW*ca}`)
                .attr('fill', color)
                .attr('fill-opacity', 0.8);
        }
    }

    // Update x-axis with zoom-adaptive formatting
    if (bottomOverlayAxisGroup && state.data.timeExtent) {
        bottomOverlayAxisGroup.call(dualAxis);
    }

    // Update IP labels to show only relevant IPs
    updateIPLabelsForFlowDetail(flowIPs);
}

/**
 * Draw permanent lines connecting sequential packets in flow detail view
 */
/**
 * Draw sequential arcs connecting an ordered list of packets, with midpoint
 * arrowheads and a trailing dashed arc from the last packet to the
 * destination IP row.
 *
 * Single implementation used by both flow-detail mode and raw-zoom
 * auto-threading.
 *
 * @param {Object}   lineGroup - D3 <g> to append SVG elements into
 * @param {string}   cssClass  - CSS class for elements (e.g. 'flow-detail-arc')
 * @param {Array}    packets   - Time-sorted packets for one flow
 * @param {Function} getX      - (packet) => x pixel
 * @param {Function} getY      - (packet) => y pixel
 */
function drawFlowDetailArcs(lineGroup, cssClass, packets, getX, getY, { skipTrailingArc = false } = {}) {
    if (!lineGroup || packets.length < 2) return;

    const arrowLen = 5;
    const arrowHalfW = 3;

    // -- Sequential packet-to-packet arcs --
    for (let i = 0; i < packets.length - 1; i++) {
        const p1 = packets[i];
        const p2 = packets[i + 1];
        if (!p1 || !p2) continue;

        // Skip arc if either source IP is absent from the layout.
        // findIPPosition returns 0 for unknown IPs, which would draw spurious arcs at the chart top.
        if (!state.layout.ipPositions.has(p1.src_ip) || !state.layout.ipPositions.has(p2.src_ip)) continue;

        const x1 = getX(p1);
        const x2 = getX(p2);
        const y1 = getY(p1);
        const y2 = getY(p2);

        const flagType = p1.flagType || p1.flag_type || getFlagType(p1);
        const color = flagColors[flagType] || flagColors['OTHER'] || '#999';
        const pktTime = String(p1.timestamp || p1.binCenter || 0);

        const sameIP = p1.src_ip === p2.src_ip;
        let midPtX, midPtY, angle;

        if (sameIP) {
            // Route through a dummy node at the destination IP row using two S-curves.
            // This makes the flow direction visible even when consecutive packets share a source.
            const yDst = getIPYWithSubRowOffset(p1.dst_ip, p1.src_ip, p1.dst_ip);

            if (state.layout.ipPositions.has(p1.dst_ip) && yDst != null && Math.abs(yDst - y1) > 1) {
                const xDummy = (x1 + x2) / 2;

                // Curve 1: src → dummy node at dst IP row
                const midX1 = (x1 + xDummy) / 2;
                lineGroup.append('path')
                    .attr('class', cssClass)
                    .attr('data-pkt-time', pktTime)
                    .attr('d', `M${x1},${y1} C${midX1},${y1} ${midX1},${yDst} ${xDummy},${yDst}`)
                    .attr('fill', 'none')
                    .attr('stroke', color)
                    .attr('stroke-width', 1.5)
                    .attr('stroke-opacity', 0.6);

                // Arrowhead on curve 1 at its midpoint
                const a1 = Math.atan2(2 * (yDst - y1), xDummy - x1);
                const c1 = Math.cos(a1), s1 = Math.sin(a1);
                const m1x = midX1, m1y = (y1 + yDst) / 2;
                lineGroup.append('polygon')
                    .attr('class', cssClass)
                    .attr('data-pkt-time', pktTime)
                    .attr('points', `${m1x + arrowLen*c1},${m1y + arrowLen*s1} ${m1x - arrowLen*c1 + arrowHalfW*s1},${m1y - arrowLen*s1 - arrowHalfW*c1} ${m1x - arrowLen*c1 - arrowHalfW*s1},${m1y - arrowLen*s1 + arrowHalfW*c1}`)
                    .attr('fill', color)
                    .attr('fill-opacity', 0.8);

                continue; // arrowhead already drawn above
            }

            // Fallback: straight line when dst IP row is unavailable or same row
            lineGroup.append('line')
                .attr('class', cssClass)
                .attr('data-pkt-time', pktTime)
                .attr('x1', x1).attr('y1', y1)
                .attr('x2', x2).attr('y2', y2)
                .attr('stroke', color)
                .attr('stroke-width', 1.5)
                .attr('stroke-opacity', 0.6);
            midPtX = (x1 + x2) / 2;
            midPtY = (y1 + y2) / 2;
            angle = Math.atan2(y2 - y1, x2 - x1);
        } else {
            const midX = (x1 + x2) / 2;
            lineGroup.append('path')
                .attr('class', cssClass)
                .attr('data-pkt-time', pktTime)
                .attr('d', `M${x1},${y1} C${midX},${y1} ${midX},${y2} ${x2},${y2}`)
                .attr('fill', 'none')
                .attr('stroke', color)
                .attr('stroke-width', 1.5)
                .attr('stroke-opacity', 0.6);
            midPtX = midX;
            midPtY = (y1 + y2) / 2;
            angle = Math.atan2(2 * (y2 - y1), x2 - x1);
        }

        // Midpoint arrowhead
        const cos = Math.cos(angle);
        const sin = Math.sin(angle);
        const tipX = midPtX + arrowLen * cos;
        const tipY = midPtY + arrowLen * sin;
        const bx1 = midPtX - arrowLen * cos + arrowHalfW * sin;
        const by1 = midPtY - arrowLen * sin - arrowHalfW * cos;
        const bx2 = midPtX - arrowLen * cos - arrowHalfW * sin;
        const by2 = midPtY - arrowLen * sin + arrowHalfW * cos;
        lineGroup.append('polygon')
            .attr('class', cssClass)
            .attr('data-pkt-time', pktTime)
            .attr('points', `${tipX},${tipY} ${bx1},${by1} ${bx2},${by2}`)
            .attr('fill', color)
            .attr('fill-opacity', 0.8);
    }

    // -- Trailing arc: last packet → destination IP row --
    // Dashed S-curve showing where the final packet was headed (no dot).
    // Skipped when the flow continues beyond the viewport (next packet is just off-screen).
    const lastPkt = packets[packets.length - 1];
    const prevPkt = packets[packets.length - 2];
    if (!skipTrailingArc && lastPkt && prevPkt && lastPkt.src_ip !== lastPkt.dst_ip) {
        const lastX = getX(lastPkt);
        const prevX = getX(prevPkt);
        const lastY = getY(lastPkt);
        const trailDstY = getIPYWithSubRowOffset(lastPkt.dst_ip, lastPkt.src_ip, lastPkt.dst_ip);
        if (trailDstY != null && lastY != null) {
            const trailFt = lastPkt.flagType || lastPkt.flag_type || getFlagType(lastPkt);
            const trailColor = flagColors[trailFt] || flagColors['OTHER'] || '#999';
            const trailEndX = lastX + Math.max(20, Math.abs(lastX - prevX));
            const trailMidX = (lastX + trailEndX) / 2;
            lineGroup.append('path')
                .attr('class', cssClass)
                .attr('d', `M${lastX},${lastY} C${trailMidX},${lastY} ${trailMidX},${trailDstY} ${trailEndX},${trailDstY}`)
                .attr('fill', 'none')
                .attr('stroke', trailColor)
                .attr('stroke-width', 1.5)
                .attr('stroke-opacity', 0.4)
                .attr('stroke-dasharray', '3,2');

            const tMidPtX = trailMidX;
            const tMidPtY = (lastY + trailDstY) / 2;
            const tAngle = Math.atan2(2 * (trailDstY - lastY), trailEndX - lastX);
            const tCos = Math.cos(tAngle);
            const tSin = Math.sin(tAngle);
            const tTipX = tMidPtX + arrowLen * tCos;
            const tTipY = tMidPtY + arrowLen * tSin;
            const tB1x = tMidPtX - arrowLen * tCos + arrowHalfW * tSin;
            const tB1y = tMidPtY - arrowLen * tSin - arrowHalfW * tCos;
            const tB2x = tMidPtX - arrowLen * tCos - arrowHalfW * tSin;
            const tB2y = tMidPtY - arrowLen * tSin + arrowHalfW * tCos;
            lineGroup.append('polygon')
                .attr('class', cssClass)
                .attr('points', `${tTipX},${tTipY} ${tB1x},${tB1y} ${tB2x},${tB2y}`)
                .attr('fill', trailColor)
                .attr('fill-opacity', 0.5);
        }
    }
}

/**
 * Auto-draw flow threading arcs for all visible raw packets.
 * Groups packets by connection 4-tuple and draws sequential connection
 * lines (identical to drawFlowDetailArcs style) for each flow.
 * Also draws dashed continuation lines to viewport edges when a flow
 * extends beyond the visible time range.
 *
 * Called automatically by the zoom handler when resolution is 'raw'.
 *
 * @param {Array} packets - Rendered raw packets (yPosWithOffset set by circles.js)
 */
function drawAutoFlowThreading(packets) {
    if (!mainGroup || !xScale) return;

    // Clear previous threading arcs
    mainGroup.selectAll('.flow-threading-arc').remove();
    mainGroup.selectAll('.flow-threading-arcs').remove();

    if (!packets || packets.length === 0) return;

    // Group packets by connection key (4-tuple: src_ip, src_port, dst_ip, dst_port)
    const flowGroups = new Map();
    for (const p of packets) {
        if (!p || !p.src_ip || !p.dst_ip) continue;
        const key = makeConnectionKey(p.src_ip, p.src_port || 0, p.dst_ip, p.dst_port || 0);
        if (!key) continue;
        let group = flowGroups.get(key);
        if (!group) {
            group = [];
            flowGroups.set(key, group);
        }
        group.push(p);
    }

    // Sort each group by timestamp (keep single-packet groups for trailing arc)
    for (const [key, group] of flowGroups) {
        group.sort((a, b) => (a.timestamp || a.binCenter || 0) - (b.timestamp || b.binCenter || 0));
    }

    if (flowGroups.size === 0) return;

    // Build lookup from connection key → flow metadata for edge continuation
    const flowMetaByKey = new Map();
    if (Array.isArray(state.flows.tcp)) {
        for (const f of state.flows.tcp) {
            if (!f) continue;
            const fkey = f.key || makeConnectionKey(f.initiator, f.initiatorPort, f.responder, f.responderPort);
            if (fkey && flowGroups.has(fkey)) {
                flowMetaByKey.set(fkey, f);
            }
        }
    }

    // Viewport time bounds
    const [viewStart, viewEnd] = xScale.domain();
    const xLeft = xScale(viewStart);
    const xRight = xScale(viewEnd);

    // Read actual circle positions from the DOM so threading arcs respect
    // sub-row expansion AND flag separation.
    const circlePosMap = buildCirclePositionMap();

    // Create line group (clipped to chart area)
    const lineGroup = mainGroup.append('g')
        .attr('class', 'flow-threading-arcs')
        .attr('clip-path', 'url(#clip)');

    // Draw sequential arcs within each flow group
    for (const [key, group] of flowGroups) {
        const flowMeta = flowMetaByKey.get(key);

        // Always skip the built-in dashed trailing arc — we draw a solid one below instead
        drawFlowDetailArcs(lineGroup, 'flow-threading-arc', group,
            p => xScale(p.timestamp || p.binCenter),
            p => lookupCircleY(circlePosMap, p.timestamp || p.binCenter || 0, p.src_ip, p.dst_ip,
                p.flagType || p.flag_type || getFlagType(p)),
            { skipTrailingArc: true });

        // -- Solid trailing S-curve from last visible packet toward dst IP --
        // Same geometry as the built-in trailing arc but solid so it matches the other arcs.
        // Clipped naturally by clip-path when it extends past the viewport.
        const lastPkt = group[group.length - 1];
        const prevPkt = group.length >= 2 ? group[group.length - 2] : null;
        if (lastPkt && lastPkt.src_ip !== lastPkt.dst_ip) {
            const lastX = xScale(lastPkt.timestamp || lastPkt.binCenter);
            const ft = lastPkt.flagType || lastPkt.flag_type || getFlagType(lastPkt);
            const lastY = lookupCircleY(circlePosMap, lastPkt.timestamp || lastPkt.binCenter || 0, lastPkt.src_ip, lastPkt.dst_ip, ft);
            const trailDstY = getIPYWithSubRowOffset(lastPkt.dst_ip, lastPkt.src_ip, lastPkt.dst_ip);
            if (trailDstY != null && lastY != null && Math.abs(trailDstY - lastY) > 1) {
                const color = flagColors[ft] || flagColors['OTHER'] || '#999';
                const pktTime = String(lastPkt.timestamp || lastPkt.binCenter || 0);
                const gap = prevPkt ? Math.abs(lastX - xScale(prevPkt.timestamp || prevPkt.binCenter)) : 40;
                const trailEndX = lastX + Math.max(20, gap);
                const trailMidX = (lastX + trailEndX) / 2;
                lineGroup.append('path')
                    .attr('class', 'flow-threading-arc')
                    .attr('data-pkt-time', pktTime)
                    .attr('d', `M${lastX},${lastY} C${trailMidX},${lastY} ${trailMidX},${trailDstY} ${trailEndX},${trailDstY}`)
                    .attr('fill', 'none')
                    .attr('stroke', color)
                    .attr('stroke-width', 1.5)
                    .attr('stroke-opacity', 0.6);
                const arrowLen = 5, arrowHalfW = 3;
                const a = Math.atan2(2 * (trailDstY - lastY), trailEndX - lastX);
                const ca = Math.cos(a), sa = Math.sin(a);
                const mx = trailMidX, my = (lastY + trailDstY) / 2;
                lineGroup.append('polygon')
                    .attr('class', 'flow-threading-arc')
                    .attr('data-pkt-time', pktTime)
                    .attr('points', `${mx+arrowLen*ca},${my+arrowLen*sa} ${mx-arrowLen*ca+arrowHalfW*sa},${my-arrowLen*sa-arrowHalfW*ca} ${mx-arrowLen*ca-arrowHalfW*sa},${my-arrowLen*sa+arrowHalfW*ca}`)
                    .attr('fill', color)
                    .attr('fill-opacity', 0.8);
            }
        }

        // -- Edge continuation lines (dashed) --
        if (!flowMeta) continue;

        const firstPkt = group[0];

        // Left continuation: flow started before viewport
        if (flowMeta.startTime != null && flowMeta.startTime < viewStart) {
            const pktX = xScale(firstPkt.timestamp || firstPkt.binCenter);
            const ft2 = firstPkt.flagType || firstPkt.flag_type || getFlagType(firstPkt);
            const pktY = lookupCircleY(circlePosMap, firstPkt.timestamp || firstPkt.binCenter || 0, firstPkt.src_ip, firstPkt.dst_ip, ft2);
            lineGroup.append('line')
                .attr('class', 'flow-threading-arc')
                .attr('x1', xLeft).attr('y1', pktY)
                .attr('x2', pktX).attr('y2', pktY)
                .attr('stroke', '#888')
                .attr('stroke-width', 1.2)
                .attr('stroke-opacity', 0.4)
                .attr('stroke-dasharray', '4,3');
        }

        // Right continuation: flow ends after viewport
        if (flowMeta.endTime != null && flowMeta.endTime > viewEnd) {
            const pktX = xScale(lastPkt.timestamp || lastPkt.binCenter);
            const ft2 = lastPkt.flagType || lastPkt.flag_type || getFlagType(lastPkt);
            const pktY = lookupCircleY(circlePosMap, lastPkt.timestamp || lastPkt.binCenter || 0, lastPkt.src_ip, lastPkt.dst_ip, ft2);
            lineGroup.append('line')
                .attr('class', 'flow-threading-arc')
                .attr('x1', pktX).attr('y1', pktY)
                .attr('x2', xRight).attr('y2', pktY)
                .attr('stroke', '#888')
                .attr('stroke-width', 1.2)
                .attr('stroke-opacity', 0.4)
                .attr('stroke-dasharray', '4,3');
        }
    }
}

/** Clear flow threading arcs (called when leaving raw resolution). */
function clearAutoFlowThreading() {
    if (!mainGroup) return;
    mainGroup.selectAll('.flow-threading-arc').remove();
    mainGroup.selectAll('.flow-threading-arcs').remove();
}


/**
 * Re-render flow detail view when zooming (updates positions based on current xScale)
 */
function renderFlowDetailViewZoomed() {
    if (!state.flowDetail.mode || !state.flowDetail.flow || state.flowDetail.packets.length === 0) return;

    // Prepare packets with updated positions (including sub-row offset)
    const preparedPackets = state.flowDetail.packets.map((p, idx) => ({
        ...p,
        _packetIndex: idx,
        yPos: getIPYWithSubRowOffset(p.src_ip, p.src_ip, p.dst_ip),
        flagType: p.flag_type || classifyFlags(p.flags) || 'OTHER',
        binned: false,
        count: 1,
        originalPackets: [p]
    }));

    // Update dot positions
    dynamicLayer.selectAll('.direction-dot')
        .attr('cx', d => xScale(d.timestamp));

    // Redraw lines with new positions
    mainGroup.selectAll('.flow-detail-arc').remove();
    mainGroup.selectAll('.flow-detail-arcs').remove();
    const fdLineGroup2 = mainGroup.append('g').attr('class', 'flow-detail-arcs').attr('clip-path', 'url(#clip)');
    drawFlowDetailArcs(fdLineGroup2, 'flow-detail-arc', preparedPackets,
        p => xScale(p.timestamp),
        p => p.yPos || getIPYWithSubRowOffset(p.src_ip, p.src_ip, p.dst_ip));
}

/**
 * Ensure SVG arrowhead marker is defined
 */
function ensureArrowheadMarker() {
    if (!svg) return;

    let defs = svg.select('defs');
    if (defs.empty()) {
        defs = svg.append('defs');
    }

    if (defs.select('#arrowhead').empty()) {
        defs.append('marker')
            .attr('id', 'arrowhead')
            .attr('viewBox', '0 -5 10 10')
            .attr('refX', 8)
            .attr('refY', 0)
            .attr('markerWidth', 6)
            .attr('markerHeight', 6)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M0,-5L10,0L0,5')
            .attr('fill', '#666');
    }
}

/**
 * Update IP labels for flow detail view (show only flow IPs)
 */
function updateIPLabelsForFlowDetail(flowIPs) {
    if (!svg) return;

    svg.selectAll('.ip-label')
        .style('opacity', function() {
            const ip = d3.select(this).text();
            return flowIPs.includes(ip) ? 1 : 0.3;
        })
        .style('font-weight', function() {
            const ip = d3.select(this).text();
            return flowIPs.includes(ip) ? 'bold' : 'normal';
        });
}

/**
 * Show flow detail loading indicator
 */
function showFlowDetailLoading(flow) {
    const existing = document.getElementById('flowDetailLoading');
    if (existing) existing.remove();

    const indicator = document.createElement('div');
    indicator.id = 'flowDetailLoading';
    indicator.style.cssText = 'position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: rgba(255,255,255,0.95); padding: 20px 30px; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.2); z-index: 5000; text-align: center;';
    indicator.innerHTML = `
        <div style="font-size: 14px; color: #333; margin-bottom: 8px;">Loading flow detail...</div>
        <div style="font-size: 12px; color: #666;">${flow.id}</div>
    `;
    document.body.appendChild(indicator);
    return indicator;
}

/**
 * Hide flow detail loading indicator
 */
function hideFlowDetailLoading(indicator) {
    if (indicator && indicator.parentNode) {
        indicator.parentNode.removeChild(indicator);
    }
}

/**
 * Show flow detail mode UI indicator
 */
function showFlowDetailModeUI(flow) {
    const existing = document.getElementById('flowDetailModeIndicator');
    if (existing) existing.remove();

    const indicator = document.createElement('div');
    indicator.id = 'flowDetailModeIndicator';
    indicator.style.cssText = 'position: fixed; top: 10px; left: 50%; transform: translateX(-50%); background: #2196F3; color: white; padding: 8px 20px; border-radius: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.2); z-index: 4000; display: flex; align-items: center; gap: 12px; font-size: 13px;';
    indicator.innerHTML = `
        <span><strong>Flow Detail Mode:</strong> ${flow.initiator}:${flow.initiatorPort} → ${flow.responder}:${flow.responderPort}</span>
        <button id="exitFlowDetailBtn" style="background: white; color: #2196F3; border: none; padding: 4px 12px; border-radius: 12px; cursor: pointer; font-weight: bold;">Exit</button>
    `;
    document.body.appendChild(indicator);

    document.getElementById('exitFlowDetailBtn').addEventListener('click', exitFlowDetailMode);
}

/**
 * Hide flow detail mode UI indicator
 */
function hideFlowDetailModeUI() {
    const indicator = document.getElementById('flowDetailModeIndicator');
    if (indicator) indicator.remove();
}

/**
 * Check if currently in flow detail mode
 */
function isInFlowDetailMode() {
    return state.flowDetail.mode;
}

function visualizeTimeArcs(packets) {
    // 1. Reset & Validation
    d3.select("#chart").html("");
    document.getElementById('loadingMessage').style.display = 'none';
    isInitialResolutionLoad = true;
    resetResolutionTransitionState();

    if (!packets || packets.length === 0) {
        document.getElementById('loadingMessage').textContent = 'No data to visualize.';
        document.getElementById('loadingMessage').style.display = 'block';
        return;
    }

    // 2. Compute flag counts for sorting
    const flagCounts = {};
    packets.forEach(packet => {
        const flagType = getFlagType(packet);
        flagCounts[flagType] = (flagCounts[flagType] || 0) + 1;
    });

    // 3. Compute time extent with padding
    const packetTimeExtent = d3.extent(packets, d => d.timestamp);
    try {
        const span = Math.max(1, packetTimeExtent[1] - packetTimeExtent[0]);
        const pad = Math.max(1, Math.floor(span * 0.02));
        packetTimeExtent[0] = packetTimeExtent[0] - pad;
        packetTimeExtent[1] = packetTimeExtent[1] + pad;
    } catch(e) { logCatchError('packetTimeExtentPadding', e); }

    // 4. Update state time extent and sync with overview
    state.data.timeExtent = packetTimeExtent;
    updateOverviewTimeExtentFromTimearcs();

    if (state.timearcs.overviewTimeExtent && state.timearcs.overviewTimeExtent[0] < state.timearcs.overviewTimeExtent[1]) {
        state.data.timeExtent = state.timearcs.overviewTimeExtent.slice();
        console.log('[visualizeData] Using state.timearcs.overviewTimeExtent for main chart:', state.data.timeExtent);
    } else {
        state.data.timeExtent = packetTimeExtent;
    }

    fullDomainBinsCache = { version: state.data.version, data: [], binSize: null, sorted: false };

    // 5. Layout setup
    const margin = {top: 80, right: 120, bottom: 50, left: 180};
    width = d3.select("#chart-container").node().clientWidth - margin.left - margin.right;
    const DOT_RADIUS = 40;

    // 6. Compute IP positioning using extracted module
    // Auto-collapse all multi-pair IP rows on first render
    if (!defaultCollapseApplied) {
        defaultCollapseApplied = true;
        const pairCounts = computeIPPairCounts(packets);
        for (const [ip, count] of pairCounts) {
            if (count > 1) state.layout.collapsedIPs.add(ip);
        }
    }

    state.layout.ipPositions.clear();
    state.layout.subRowHeights = null;   // Reset; recomputed post-binning if separateFlags is on
    state.layout.subRowOffsets = null;
    const positioning = computeIPPositioning(packets, {
        state,
        rowGap: ROW_GAP,
        topPad: TOP_PAD,
        timearcsOrder: state.timearcs.ipOrder,
        dotRadius: DOT_RADIUS,
        collapsedIPs: state.layout.collapsedIPs
    });

    // Apply positioning to state
    applyIPPositioningToState(state, positioning);
    state.layout.activeIPs = null; // Reset: all rows visible on a new full layout.
    const { yDomain, yRange, minY, maxY } = positioning;
    height = positioning.height;

    // Build IP connectivity map for row highlighting
    state.layout.ipConnectivity = buildIPConnectivity(packets);

    if (state.timearcs.ipOrder && state.timearcs.ipOrder.length > 0) {
        console.log('[IP Order] Using TimeArcs vertical order:', state.layout.ipOrder.length, 'IPs');
    }

    // 7. Create scales
    xScale = d3.scaleLinear().domain(state.data.timeExtent).range([0, width]);
    yScale = d3.scaleLinear().domain([minY, maxY]).range([minY, maxY]);

    // 8. Create SVG structure using extracted module
    const svgResult = createSVGStructure({
        d3,
        containerId: '#chart',
        width,
        height,
        margin,
        dotRadius: DOT_RADIUS
    });
    const svgContainer = svgResult.svgContainer;
    svg = svgResult.svg;
    mainGroup = svgResult.mainGroup;
    fullDomainLayer = svgResult.fullDomainLayer;
    dynamicLayer = svgResult.dynamicLayer;

    // 10. Create bottom overlay using extracted module
    try {
        chartMarginLeft = margin.left;
        chartMarginRight = margin.right;
        const overlayResult = createBottomOverlay({
            d3,
            overlaySelector: '#chart-bottom-overlay-svg',
            width,
            chartMarginLeft,
            chartMarginRight,
            overlayHeight: bottomOverlayHeight,
            xScale,
            tickFormatter: null  // dual-band axis handles its own formatting
        });
        bottomOverlaySvg = overlayResult.bottomOverlaySvg;
        bottomOverlayRoot = overlayResult.bottomOverlayRoot;
        bottomOverlayAxisGroup = overlayResult.bottomOverlayAxisGroup;
        bottomOverlayDurationLabel = overlayResult.bottomOverlayDurationLabel;
        bottomOverlayWidth = overlayResult.bottomOverlayWidth;
        // Create dual-band axis (reused for all subsequent updates)
        dualAxis = createDualBandAxis({ scale: xScale });
        bottomOverlayAxisGroup.call(dualAxis);
    } catch (e) { LOG('Overlay init failed', e); }

    // 11. Create duration label updater using extracted module
    const updateZoomDurationLabel = createDurationLabelUpdater({
        getXScale: () => xScale,
        bottomOverlayDurationLabel
    });

    // Initial label render
    try { updateZoomDurationLabel(); } catch(e) { logCatchError('updateZoomDurationLabel', e); }

    // 12. Build IP row labels using extracted module
    try {
        renderIPRowLabels({
            d3,
            svg,
            yDomain,
            ipPositions: state.layout.ipPositions,
            chartWidth: width,
            rowHeight: ROW_GAP,
            onHighlight: (data) => highlight(data),
            onClearHighlight: () => highlight(null),
            ipPairCounts: state.layout.ipPairCounts,
            collapsedIPs: state.layout.collapsedIPs,
            ipPairOrderByRow: state.layout.ipPairOrderByRow,
            ipRowHeights: state.layout.ipRowHeights,
            subRowHeights: state.layout.subRowHeights,
            subRowOffsets: state.layout.subRowOffsets,
            onToggleCollapse: (ip) => {
                if (state.layout.collapsedIPs.has(ip)) {
                    state.layout.collapsedIPs.delete(ip);
                } else {
                    state.layout.collapsedIPs.add(ip);
                }
                const savedDomain = xScale ? xScale.domain().slice() : null;
                isHardResetInProgress = true;
                visualizeTimeArcs(state.data.filtered);
                updateTcpFlowPacketsGlobal();
                drawSelectedFlowArcs();
                applyInvalidReasonFilter();
                if (savedDomain && xScale && (savedDomain[0] !== state.data.timeExtent[0] || savedDomain[1] !== state.data.timeExtent[1])) {
                    applyZoomDomain(savedDomain, 'program');
                }
            }
        });
    } catch (e) { LOG('Failed to build IP labels', e); }

    // 12b. Create/update the floating expand-all sub-rows button
    try { createOrUpdateExpandAllBtn(margin.top); } catch (e) { LOG('Expand-all btn failed', e); }

    // 13. Sync arc domain for overview brush (do NOT recreate overview chart here)
    try { window.__arc_x_domain__ = xScale.domain(); } catch(e) { logCatchError('setArcXDomain', e); }

    LOG('SVG setup:', {
        containerWidth: width + margin.left + margin.right,
        containerHeight: height + margin.top + margin.bottom,
        chartWidth: width,
        chartHeight: height,
        margin: margin,
        xScaleDomain: state.data.timeExtent,
        yScaleDomain: yDomain,
        yScaleRange: yRange
    });

    // 13.5 IP Row Filter helpers (closures that capture this render's SVG / svgContainer).
    //
    // applyIPRowFilter   — called on every debounced zoom-in: hides rows that have no
    //                      connections in the visible time window and centres the rest.
    // restoreBaseRows    — called when zooming back to the full time extent: slides all
    //                      rows back to their original positions.
    //
    const applyIPRowFilter = (visiblePackets) => {
        try {
            if (!state.layout.basePositions || !state.layout.basePositions.size) return;
            const activeIPs = computeActiveIPsFilter(visiblePackets);
            if (activeIPs.size === 0) return; // Don't hide everything for an empty region.

            const chartContainer = d3.select('#chart-container').node();
            const containerH = chartContainer ? chartContainer.clientHeight : 600;
            const usableH = Math.max(100, containerH - margin.top - margin.bottom);

            const compact = computeCompactPositions({
                activeIPs,
                ipOrder: state.layout.ipOrder,
                baseRowHeights: state.layout.baseRowHeights,
                containerHeight: usableH,
                topPad: TOP_PAD
            });
            applyFilteredPositions(state, compact);
            state.layout.activeIPs = activeIPs;

            animateIPRowsFilter(svg, d3, activeIPs, compact.positions, compact.rowHeights, ROW_GAP);

            // Shrink SVG to match the compact layout (no extra scroll space).
            const newH = Math.max(usableH, compact.totalHeight + compact.centerOffset);
            svgContainer.attr('height', newH + margin.top + margin.bottom);
            svg.select('#clip rect').attr('height', newH + 80);

        } catch(e) { logCatchError('applyIPRowFilter', e); }
    };

    const restoreBaseRows = () => {
        try {
            if (!state.layout.basePositions || !state.layout.basePositions.size) return;

            restoreBasePositionsToState(state);
            state.layout.activeIPs = null;

            // Compute centered positions on-the-fly using the current container
            // height (which may differ from when base positions were saved).
            const chartContainer = d3.select('#chart-container').node();
            const containerH = chartContainer ? chartContainer.clientHeight : 600;
            const usableH = Math.max(100, containerH - margin.top - margin.bottom);
            const allIPs = new Set(state.layout.ipOrder);
            const compact = computeCompactPositions({
                activeIPs: allIPs,
                ipOrder: state.layout.ipOrder,
                baseRowHeights: state.layout.ipRowHeights,
                containerHeight: usableH,
                topPad: TOP_PAD,
            });

            // Apply centered positions to state (in-place).
            for (const [ip, y] of compact.positions) {
                state.layout.ipPositions.set(ip, y);
            }

            // Animate every row to centered positions with full opacity.
            animateIPRowsFilter(svg, d3, allIPs, compact.positions, compact.rowHeights, ROW_GAP);

            // Size SVG to match the container viewport.
            const newH = Math.max(usableH, compact.totalHeight + compact.centerOffset);
            svgContainer.attr('height', newH + margin.top + margin.bottom);
            svg.select('#clip rect').attr('height', newH + 80);
        } catch(e) { logCatchError('restoreBaseRows', e); }
    };

    // 14. Create zoom handler using extracted module (will be updated during zoom)
    // xAxis is now dualAxis — already created above

    const zoomed = createTimeArcsZoomHandler({
        d3,
        getXScale: () => xScale,
        getState: () => state,
        getTimeExtent: () => state.data.timeExtent,
        width,
        fullDomainLayer,
        dynamicLayer,
        mainGroup,
        bottomOverlayAxisGroup,
        bottomOverlayDurationLabel,
        getFullDomainBinsCache: () => fullDomainBinsCache,
        setFullDomainBinsCache: (cache) => { fullDomainBinsCache = cache; },
        getIsHardResetInProgress: () => isHardResetInProgress,
        setIsHardResetInProgress: (val) => { isHardResetInProgress = val; },
        xAxis: dualAxis,
        updateBrushFromZoom,
        updateZoomDurationLabel,
        updateZoomIndicator,
        getResolutionForVisibleRange,
        renderFlowDetailViewZoomed,
        drawSelectedFlowArcs,
        drawSubRowArcs,
        drawGroundTruthBoxes,
        getVisiblePackets,
        buildSelectedFlowKeySet,
        makeConnectionKey,
        findIPPosition,
        getFlagType,
        renderMarksForLayer: renderMarksForLayerLocal,
        getGlobalMaxBinCount: () => globalMaxBinCount,
        getFlagCounts: () => flagCounts,
        getMultiResData: (...args) => getMultiResData?.(...args),
        isMultiResAvailable: () => isMultiResAvailable?.(),
        getUseMultiRes: () => useMultiRes,
        setCurrentResolutionLevel: (level) => { currentResolutionLevel = level; },
        drawAutoFlowThreading,
        clearAutoFlowThreading,
        logCatchError,
        applyIPRowFilter: (visiblePackets) => applyIPRowFilter(visiblePackets),
        restoreBaseRows: () => restoreBaseRows(),
        getFlowZoomManager: () => flowZoomManager,
        getSelectedIPs: () => Array.from(
            document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')
        ).map(cb => cb.value)
    });

    // 15. Initialize zoom behavior
    zoom = createZoomBehavior({
        d3,
        scaleExtent: [1, 1e9],
        onZoom: zoomed
    });
    // Attach zoom to inner svg group (not outer svgContainer) so D3's
    // pointer-anchored zoom uses the circle coordinate system (post-margin).
    // A transparent .zoom-capture rect in svgSetup.js ensures the <g>
    // receives pointer events even in empty areas.
    zoomTarget = svg;
    zoomTarget.call(zoom);

    // 16. Enable drag-to-reorder for IP rows
    const dragBehavior = createDragReorderBehavior({
        d3,
        svg,
        ipOrder: state.layout.ipOrder,
        ipPositions: state.layout.ipPositions,
        ipRowHeights: state.layout.ipRowHeights,
        onReorder: () => {
            try { const newOrderDrag = computeIPPairOrderByRow(state.data.filtered, state.layout.ipPositions); state.layout.ipPairOrderByRow.clear(); for (const [k, v] of newOrderDrag) state.layout.ipPairOrderByRow.set(k, v); applyCollapseOverrides(state.layout.ipPairOrderByRow); } catch(e) { logCatchError('recomputeIpPairOrder', e); }
            // Save new base positions so subsequent zoom-filter uses the reordered layout.
            try { saveBasePositions(state); } catch(e) { logCatchError('saveBasePositions-drag', e); }
            try {
                // Sync row highlights with new positions
                svg.selectAll('.row-highlight')
                    .attr('y', d => (state.layout.ipPositions.get(d) || 0) - ROW_GAP / 2)
                    .attr('height', d => (state.layout.ipRowHeights && state.layout.ipRowHeights.get(d)) || ROW_GAP);
                syncSubRowHighlights(svg, state);
                // Update SVG height to fit new layout
                let maxY = TOP_PAD;
                for (const ip of state.layout.ipOrder) {
                    maxY += (state.layout.ipRowHeights && state.layout.ipRowHeights.get(ip)) || ROW_GAP;
                }
                const newHeight = Math.max(height, maxY + margin.bottom);
                svgContainer.attr('height', newHeight + margin.top + margin.bottom);
                svg.select('#clip rect').attr('height', newHeight + 80);
            } catch(e) { logCatchError('syncRowHighlightsAndHeight', e); }
            try { fullDomainBinsCache = { version: -1, data: [], binSize: null, sorted: false }; } catch(e) { logCatchError('fullDomainBinsCache.reset', e); }
            try { isHardResetInProgress = true; applyZoomDomain(xScale.domain(), 'program'); } catch(e) { logCatchError('applyZoomDomain', e); }
            try { drawSelectedFlowArcs(); } catch(e) { logCatchError('drawSelectedFlowArcs', e); }
            try { drawSubRowArcs(); } catch(e) { logCatchError('drawSubRowArcs', e); }
            try {
                if (state.ui.showGroundTruth) {
                    const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value);
                    drawGroundTruthBoxes(selectedIPs);
                }
            } catch(e) { logCatchError('drawGroundTruthBoxes', e); }
            try { updateZoomDurationLabel(); } catch(e) { logCatchError('updateZoomDurationLabel', e); }
        }
    });
    svg.selectAll('.node').call(dragBehavior).style('cursor', 'grab');

    // 17. Initial render using extracted module
    const initialVisibleRangeUs = xScale.domain()[1] - xScale.domain()[0];
    const initialResolution = getResolutionForVisibleRange(initialVisibleRangeUs);
    console.log('[visualizeTimeArcs] xScale domain:', xScale.domain(), 'visibleRange:', (initialVisibleRangeUs/60_000_000).toFixed(1), 'min', 'resolution:', initialResolution);

    const initialRenderData = prepareInitialRenderData({
        d3,
        packets,
        xScale,
        state,
        fetchResManager,
        getResolutionForVisibleRange,
        getVisiblePackets,
        buildSelectedFlowKeySet,
        makeConnectionKey,
        findIPPosition,
        getFlagType,
        flagCounts
    });

    globalMaxBinCount = initialRenderData.globalMaxBinCount;
    console.log('[visualizeTimeArcs] globalMaxBinCount set from', initialResolution, 'data:', globalMaxBinCount);

    // Adjust globalMaxBinCount and row heights for collapsed IPs whose merged bins
    // exceed the pre-collapse max (prevents circles overflowing row boundaries)
    if (state.layout.collapsedIPs.size > 0) {
        const collapsed = computeCollapsedMaxCounts(
            initialRenderData.binnedPackets, state.layout.collapsedIPs
        );
        if (collapsed) {
            globalMaxBinCount = Math.max(globalMaxBinCount, collapsed.globalMax);

            // Compute needed row heights for collapsed IPs based on max radius
            const rScaleCheck = d3.scaleSqrt()
                .domain([1, Math.max(1, globalMaxBinCount)])
                .range([RADIUS_MIN, RADIUS_MAX]);

            let positionsChanged = false;
            for (const [ip, maxCount] of collapsed.maxPerIP) {
                const radius = rScaleCheck(maxCount);
                const needed = Math.max(ROW_GAP, radius * 2 + 10);
                const current = state.layout.ipRowHeights.get(ip) || ROW_GAP;
                if (needed > current) {
                    state.layout.ipRowHeights.set(ip, needed);
                    positionsChanged = true;
                }
            }

            if (positionsChanged) {
                // Recompute cumulative y positions
                let currentY = TOP_PAD;
                state.layout.ipOrder.forEach(ip => {
                    state.layout.ipPositions.set(ip, currentY);
                    currentY += state.layout.ipRowHeights.get(ip) || ROW_GAP;
                });
                // Update bin yPos values to match new positions
                for (const d of initialRenderData.binnedPackets) {
                    if (d.src_ip) {
                        const newY = state.layout.ipPositions.get(d.src_ip);
                        if (newY !== undefined) d.yPos = newY;
                    }
                }
                // Rebuild ipPairOrderByRow with new positions so sub-row
                // offsets resolve correctly (keys are yPos-based).
                // Update IN PLACE to keep closure references in renderIPRowLabels valid.
                const newOrderCollapse = computeIPPairOrderByRow(
                    packets, state.layout.ipPositions
                );
                state.layout.ipPairOrderByRow.clear();
                for (const [k, v] of newOrderCollapse) state.layout.ipPairOrderByRow.set(k, v);
                applyCollapseOverrides(state.layout.ipPairOrderByRow);
                // Sync node label positions with updated IP positions
                svg.selectAll('.node')
                    .attr('transform', d => `translate(0,${state.layout.ipPositions.get(d)})`);
                svg.selectAll('.row-highlight')
                    .attr('y', d => (state.layout.ipPositions.get(d) || 0) - ROW_GAP / 2)
                    .attr('height', d => (state.layout.ipRowHeights && state.layout.ipRowHeights.get(d)) || ROW_GAP);
                syncSubRowHighlights(svg, state);
                // Update SVG height
                const lastIp = state.layout.ipOrder[state.layout.ipOrder.length - 1];
                const lastH = state.layout.ipRowHeights.get(lastIp) || ROW_GAP;
                const newMaxY = state.layout.ipPositions.get(lastIp) || 0;
                height = Math.max(500, newMaxY + lastH + 40 + TOP_PAD);
                // Resize SVG container and clip path to new height
                svgContainer.attr('height', height + margin.top + margin.bottom);
                svg.select('#clip rect').attr('height', height + (2 * DOT_RADIUS));
            }
        }
    }

    // Adjust row heights for flag separation based on actual per-sub-row circle stacking
    if (state.ui.separateFlags) {
        const rScaleForHeights = d3.scaleSqrt()
            .domain([1, Math.max(1, globalMaxBinCount)])
            .range([RADIUS_MIN, RADIUS_MAX]);

        const perSubRowHeight = computeFlagSeparationHeights(
            initialRenderData.binnedPackets, rScaleForHeights
        );

        const { subRowOffsets, subRowHeights, ipRowHeightUpdates } = computeSubRowLayout(
            perSubRowHeight,
            state.layout.ipPairOrderByRow,
            state.layout.ipPositions,
            state.layout.ipOrder,
            state.layout.collapsedIPs
        );

        state.layout.subRowHeights = subRowHeights;
        state.layout.subRowOffsets = subRowOffsets;

        let flagPositionsChanged = false;
        for (const [ip, neededRowHeight] of ipRowHeightUpdates) {
            const current = state.layout.ipRowHeights.get(ip) || ROW_GAP;
            if (neededRowHeight > current) {
                state.layout.ipRowHeights.set(ip, neededRowHeight);
                flagPositionsChanged = true;
            }
        }

        if (flagPositionsChanged) {
            // Recompute cumulative y positions
            let currentY = TOP_PAD;
            state.layout.ipOrder.forEach(ip => {
                state.layout.ipPositions.set(ip, currentY);
                currentY += state.layout.ipRowHeights.get(ip) || ROW_GAP;
            });
            // Update bin yPos values to match new positions
            for (const d of initialRenderData.binnedPackets) {
                if (d.src_ip) {
                    const newY = state.layout.ipPositions.get(d.src_ip);
                    if (newY !== undefined) d.yPos = newY;
                }
            }
            // Rebuild ipPairOrderByRow with new positions.
            // Update IN PLACE to keep closure references in renderIPRowLabels valid.
            const newOrderFlags = computeIPPairOrderByRow(
                packets, state.layout.ipPositions
            );
            state.layout.ipPairOrderByRow.clear();
            for (const [k, v] of newOrderFlags) state.layout.ipPairOrderByRow.set(k, v);
            applyCollapseOverrides(state.layout.ipPairOrderByRow);

            // Recompute offsets with updated ipPairOrderByRow (keys changed due to new yPos)
            const layoutResult = computeSubRowLayout(
                perSubRowHeight,
                state.layout.ipPairOrderByRow,
                state.layout.ipPositions,
                state.layout.ipOrder,
                state.layout.collapsedIPs
            );
            state.layout.subRowOffsets = layoutResult.subRowOffsets;
            state.layout.subRowHeights = layoutResult.subRowHeights;

            // Sync node label positions with updated IP positions
            svg.selectAll('.node')
                .attr('transform', d => `translate(0,${state.layout.ipPositions.get(d)})`);
            svg.selectAll('.row-highlight')
                .attr('y', d => (state.layout.ipPositions.get(d) || 0) - ROW_GAP / 2)
                .attr('height', d => (state.layout.ipRowHeights && state.layout.ipRowHeights.get(d)) || ROW_GAP);
            syncSubRowHighlights(svg, state);
            // Update SVG height
            const lastIp = state.layout.ipOrder[state.layout.ipOrder.length - 1];
            const lastH = state.layout.ipRowHeights.get(lastIp) || ROW_GAP;
            const newMaxY = state.layout.ipPositions.get(lastIp) || 0;
            height = Math.max(500, newMaxY + lastH + 40 + TOP_PAD);
            svgContainer.attr('height', height + margin.top + margin.bottom);
            svg.select('#clip rect').attr('height', height + (2 * DOT_RADIUS));
        }
    } else {
        // When separateFlags is off, clear sub-row layout overrides
        state.layout.subRowHeights = null;
        state.layout.subRowOffsets = null;
    }

    // Save base snapshots after all adjustments so the zoom-based row filter
    // can restore the full unfiltered layout.
    saveBasePositions(state);

    fullDomainBinsCache = { version: state.data.version, data: initialRenderData.binnedPackets, binSize: null, sorted: true };

    console.log('[visualizeTimeArcs] Rendering', initialRenderData.binnedPackets.length, 'binned packets to fullDomainLayer');
    performInitialRender({
        d3,
        fullDomainLayer,
        dynamicLayer,
        binnedPackets: initialRenderData.binnedPackets,
        globalMaxBinCount,
        radiusMin: RADIUS_MIN,
        radiusMax: RADIUS_MAX,
        renderMarksForLayer: renderMarksForLayerLocal
    });
    console.log('[visualizeTimeArcs] fullDomainLayer display set to visible');

    // Update zoom indicator with resolution label
    const visibleRangeUs = state.data.timeExtent[1] - state.data.timeExtent[0];
    if (visibleRangeUs > 0) {
        updateZoomIndicator(visibleRangeUs, initialResolution);
    }

    // 18. Post-render setup
    updateTcpFlowPacketsGlobal();

    // Sync worker with rendered data after initial rendering
    try {
        setTimeout(() => syncWorkerWithRenderedData(), 100);
    } catch (err) {
        console.error('Failed to sync worker after initial render:', err);
    }

    // 19. Draw legends
    try { drawSizeLegend(bottomOverlayRoot, width, bottomOverlayHeight); } catch(e) { logCatchError('drawSizeLegend', e); }
    try { drawFlagLegend(); } catch(e) { logCatchError('drawFlagLegend', e); }

    // 20. Draw overlays
    const selectedIPs = Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked'))
        .map(cb => cb.value);
    drawGroundTruthBoxes(selectedIPs);
    drawSelectedFlowArcs();
    drawSubRowArcs();

    try { drawFlagLegend(); } catch(e) { logCatchError('drawFlagLegend', e); }

    // 22. Final overlay sizing
    try {
        resizeBottomOverlay({
            d3,
            overlaySelector: '#chart-bottom-overlay-svg',
            width,
            chartMarginLeft,
            chartMarginRight,
            overlayHeight: bottomOverlayHeight,
            bottomOverlayRoot,
            bottomOverlayAxisGroup,
            xScale,
            tickFormatter: null  // dual-band axis handles formatting
        });
    } catch(e) { logCatchError('bottomOverlayResize', e); }

    // Deferred centering: the overview chart renders asynchronously, so the
    // container height isn't final when visualizeTimeArcs runs. Use a one-shot
    // ResizeObserver to detect when #chart-container shrinks (overview appears)
    // and re-centre + re-render at the correct height.
    {
        const chartEl = d3.select('#chart-container').node();
        if (chartEl) {
            const initialH = chartEl.clientHeight;
            const centerObs = new ResizeObserver(() => {
                const newH = chartEl.clientHeight;
                if (Math.abs(newH - initialH) < 10) return; // ignore tiny shifts
                centerObs.disconnect();
                try {
                    const usableH = Math.max(100, newH - margin.top - margin.bottom);
                    const allIPs = new Set(state.layout.ipOrder);
                    const compact = computeCompactPositions({
                        activeIPs: allIPs,
                        ipOrder: state.layout.ipOrder,
                        baseRowHeights: state.layout.ipRowHeights,
                        containerHeight: usableH,
                        topPad: TOP_PAD,
                    });
                    if (compact.centerOffset > TOP_PAD) {
                        for (const [ip, y] of compact.positions) {
                            state.layout.ipPositions.set(ip, y);
                        }
                        const newOrder = computeIPPairOrderByRow(packets, state.layout.ipPositions);
                        state.layout.ipPairOrderByRow.clear();
                        for (const [k, v] of newOrder) state.layout.ipPairOrderByRow.set(k, v);
                        applyCollapseOverrides(state.layout.ipPairOrderByRow);
                        // Update bin yPos and re-render circles via the normal path
                        for (const d of fullDomainBinsCache.data) {
                            if (d.src_ip) {
                                const newY = state.layout.ipPositions.get(d.src_ip);
                                if (newY !== undefined) d.yPos = newY;
                            }
                        }
                        // Re-render the fullDomainLayer properly (circles + bars)
                        const rScale = d3.scaleSqrt()
                            .domain([1, Math.max(1, globalMaxBinCount)])
                            .range([RADIUS_MIN, RADIUS_MAX]);
                        renderMarksForLayerLocal(fullDomainLayer, fullDomainBinsCache.data, rScale);
                        // Move node labels and row highlights
                        svg.selectAll('.node')
                            .attr('transform', d => `translate(0,${state.layout.ipPositions.get(d)})`);
                        svg.selectAll('.row-highlight')
                            .attr('y', d => (state.layout.ipPositions.get(d) || 0) - ROW_GAP / 2)
                            .attr('height', d => (state.layout.ipRowHeights && state.layout.ipRowHeights.get(d)) || ROW_GAP);
                        // Update SVG height
                        const svgH = Math.max(usableH, compact.totalHeight + compact.centerOffset);
                        svgContainer.attr('height', svgH + margin.top + margin.bottom);
                        svg.select('#clip rect').attr('height', svgH + (2 * DOT_RADIUS));
                        // Save centered positions as base
                        saveBasePositions(state);
                    }
                } catch(e) { logCatchError('resizeObserverCentering', e); }
            });
            centerObs.observe(chartEl);
        }
    }
}

// Make resize handler available globally for testing and debugging
window.setupWindowResizeHandler = setupWindowResizeHandler;

// Test function to manually trigger resize (for debugging)
window.testResize = function() {
    console.log('Testing manual resize...');
    const event = new Event('resize');
    window.dispatchEvent(event);
};

// Make loadFromPath available globally for manual data loading
// Usage: window.loadFromPath() or window.loadFromPath('path/to/data')
window.loadFromPath = null;  // Will be set after function is defined

// Cleanup function to remove event listeners and clear state
function cleanup() {
    console.log('Cleaning up bar visualization...');
    
    // Clear timeouts and intervals
    if (typeof resizeTimeout !== 'undefined') {
        clearTimeout(resizeTimeout);
    }
    
    // Remove event listeners
    const dataFileInput = document.getElementById('dataFile');
    if (dataFileInput) {
        dataFileInput.removeEventListener('change', handleFileLoad);
    }
    
    // Clear chart content
    const chartContainer = document.getElementById('chart');
    if (chartContainer) {
        chartContainer.innerHTML = '';
    }
    
    // Clear overview
    const overviewContainer = document.getElementById('overview-chart');
    if (overviewContainer) {
        overviewContainer.innerHTML = '';
    }
    
    // Clear bottom overlay
    const bottomOverlay = document.getElementById('chart-bottom-overlay-svg');
    if (bottomOverlay) {
        bottomOverlay.innerHTML = '';
    }
    
    // Terminate worker if exists
    if (workerManager) {
        workerManager.terminate();
        workerManager = null;
    }
    
    // Reset global state
    state.data.full = [];
    state.data.filtered = [];
    state.flows.current = [];
    state.flows.selectedIds.clear();
    
    // Clear SVG references
    svg = null;
    mainGroup = null;
}

// Global variable to store brush selection data for filtering
let brushSelectionData = null;

// Global variable to store data path from TimeArcs selection (for auto-loading)
let brushSelectionDataPath = null;

// Check if page was opened from TimeArcs brush selection
function checkForBrushSelectionData() {
    console.log('[tcp-analysis] Checking for brush selection data...');
    console.log('[tcp-analysis] Current URL:', window.location.href);
    console.log('[tcp-analysis] Search params:', window.location.search);

    const urlParams = new URLSearchParams(window.location.search);

    if (!urlParams.has('fromSelection')) {
        console.log('[tcp-analysis] No fromSelection parameter found in URL');
        return false;
    }

    // Get the storage key from URL parameter (supports multiple selections)
    const storageKey = urlParams.get('fromSelection');
    console.log('[tcp-analysis] Page opened from TimeArcs brush selection, key:', storageKey);

    try {
        // Read from localStorage (sessionStorage doesn't work across tabs)
        const storedData = localStorage.getItem(storageKey);
        if (!storedData) {
            console.warn('[tcp-analysis] No brush selection data found in localStorage for key:', storageKey);
            // Also check sessionStorage as fallback for older data
            const sessionData = sessionStorage.getItem(storageKey);
            if (sessionData) {
                console.log('[tcp-analysis] Found data in sessionStorage (legacy)');
            }
            return false;
        }

        brushSelectionData = JSON.parse(storedData);
        console.log('[tcp-analysis] Loaded brush selection data:', brushSelectionData);

        // Clear localStorage to prevent reuse (data is one-time)
        localStorage.removeItem(storageKey);
        console.log('[tcp-analysis] Cleared localStorage key:', storageKey);

        // Store IPs for pre-selection when data loads
        if (brushSelectionData.selection && brushSelectionData.selection.ips) {
            // This will be used to pre-select IPs when data is loaded
            window.brushSelectionPrefilterIPs = brushSelectionData.selection.ips;
            console.log('Pre-filter IPs set:', window.brushSelectionPrefilterIPs.length);
        }

        // Store ordered IPs from TimeArcs (if available) for vertical ordering
        if (brushSelectionData.selection && brushSelectionData.selection.ipsInOrder) {
            state.timearcs.ipOrder = brushSelectionData.selection.ipsInOrder;
            console.log('TimeArcs IP order set:', state.timearcs.ipOrder.length, 'IPs in vertical order');
        }

        // Store time range from TimeArcs (in microseconds) for initial zoom
        if (brushSelectionData.selection && brushSelectionData.selection.timeRange) {
            const tr = brushSelectionData.selection.timeRange;
            if (tr.minUs !== undefined && tr.maxUs !== undefined) {
                state.timearcs.timeRange = { minUs: tr.minUs, maxUs: tr.maxUs };
                console.log('TimeArcs time range set:', state.timearcs.timeRange, '(microseconds)');
            }
        }

        // Store data path for auto-loading (if provided by TimeArcs)
        // Prefer detailViewDataPath (multi-resolution format), fall back to baseDataPath
        if (brushSelectionData.detailViewDataPath) {
            brushSelectionDataPath = brushSelectionData.detailViewDataPath;
            console.log('TimeArcs detail view data path set:', brushSelectionDataPath);
        } else if (brushSelectionData.baseDataPath && brushSelectionData.baseDataPath !== './') {
            brushSelectionDataPath = brushSelectionData.baseDataPath;
            console.log('TimeArcs base data path set:', brushSelectionDataPath);
        }

        return true;

    } catch (e) {
        console.error('Error parsing brush selection data:', e);
        return false;
    }
}

// Apply brush selection pre-filter to IP checkboxes
function applyBrushSelectionPrefilter() {
    const prefilterIPs = window.brushSelectionPrefilterIPs;
    if (!prefilterIPs || prefilterIPs.length === 0) {
        return;
    }

    console.log('Applying brush selection pre-filter for', prefilterIPs.length, 'IPs');

    const prefilterSet = new Set(prefilterIPs);
    const checkboxes = document.querySelectorAll('#ipCheckboxes input[type="checkbox"]');
    let matchedCount = 0;

    checkboxes.forEach(cb => {
        if (prefilterSet.has(cb.value)) {
            cb.checked = true;
            matchedCount++;
        }
    });

    console.log(`Pre-filter matched ${matchedCount} of ${prefilterIPs.length} IPs`);

    // Refresh the IP collapse state to show only selected IPs (since we're coming from TimeArcs)
    sbRefreshIPCollapseState();

    // Clear the pre-filter to prevent re-application
    window.brushSelectionPrefilterIPs = null;

    // Trigger IP filter update to render the visualization
    if (matchedCount >= 2) {
        // Use setTimeout to ensure DOM updates are complete
        setTimeout(async () => {
            await updateIPFilter();
        }, 100);
    }
}

// Initialize the module
function init() {
    console.log('Initializing bar visualization...');

    // Add file input listener
    const dataFileInput = document.getElementById('dataFile');
    if (dataFileInput) {
        dataFileInput.addEventListener('change', handleFileLoad);
    }

    // Add folder data listener
    document.addEventListener('folderDataLoaded', handleFolderDataLoaded);

    // Add flow data listener (supplements existing data, doesn't reset)
    document.addEventListener('flowDataLoaded', handleFlowDataLoaded);

    // Initialize the visualization
    initializeBarVisualization();

    // Check if opened from TimeArcs brush selection
    const hasSelectionData = checkForBrushSelectionData();

    // Load ground truth data in the background
    // Load ground truth data asynchronously
    loadGroundTruthData().then(data => {
        state.flows.groundTruth = data;

        // Update ground truth stats display
        const container = document.getElementById('groundTruthStats');
        if (data.length > 0) {
            container.innerHTML = `Loaded ${data.length} ground truth events<br>Select 2+ IPs to view matching events`;
            container.style.color = '#27ae60';
        } else {
            container.innerHTML = 'Ground truth data not loaded';
            container.style.color = '#e74c3c';
        }
    });

    // Default view is flows — skip packet data load at startup and go straight to
    // flow data. Packet data is loaded lazily when the user switches to packet view.
    // If a TimeArcs brush selection path exists, fall back to the original
    // packet-first sequence since that path contains packet data, not flows.
    if (hasSelectionData && brushSelectionDataPath) {
        console.log('Auto-loading data from TimeArcs selection path:', brushSelectionDataPath);
        loadFromPath(brushSelectionDataPath).then(() => {
            return loadFlowsFromPath(DEFAULT_FLOW_DATA_PATH);
        }).then(() => {
            console.log('[Init] TimeArcs path + flow data loaded');
            setTimeout(() => _switchToFlowsAfterInit(), 300);
        }).catch(err => {
            console.warn(`Auto-load from TimeArcs path failed: ${err.message}`);
            loadFromPath(DEFAULT_DATA_PATH).then(() => loadFlowsFromPath(DEFAULT_FLOW_DATA_PATH))
                .catch(e => console.warn('Fallback also failed:', e.message));
        });
    } else {
        // Flow-only startup: load flow data, seed IPs + timeExtent, then switch view
        loadFlowsFromPath(DEFAULT_FLOW_DATA_PATH).then(async ({ flowTimeExtent }) => {
            console.log('[Init] Flow data loaded — initialising flow-only mode');
            await initFlowOnlyMode(DEFAULT_FLOW_DATA_PATH, flowTimeExtent);
            setTimeout(() => _switchToFlowsAfterInit(), 300);
        }).catch(err => {
            console.warn('Flow data auto-load failed:', err.message);
            console.log('Please use the file picker or folder selector to load data.');
        });
    }
}

/**
 * Shared post-load sequence: switch to flows view and zoom to flow extent.
 * Called after both flow-only and packet+flow startup paths finish loading.
 */
async function _switchToFlowsAfterInit() {
    try {
        await switchViewMode('flows', { force: true });
    } catch (e) {
        console.warn('[Init] switchViewMode(flows) failed:', e);
    }
    try {
        if (flowDataState && Array.isArray(flowDataState.timeExtent)
            && flowDataState.timeExtent[0] < flowDataState.timeExtent[1]
            && xScale && state.data.timeExtent) {
            const [flowStart, flowEnd] = flowDataState.timeExtent;
            const [pktStart, pktEnd] = state.data.timeExtent;
            const flowSpan = flowEnd - flowStart;
            const pktSpan = pktEnd - pktStart;
            if (flowSpan > 0 && flowSpan < pktSpan * 0.75) {
                console.log(`[Init] Flow range (${(flowSpan/60e6).toFixed(2)}m) << packet range (${(pktSpan/60e6).toFixed(2)}m) — zooming to flow extent`);
                applyZoomDomain([flowStart, flowEnd], 'program');
            }
        }
    } catch (e) {
        console.warn('[Init] zoom-to-flow-extent failed:', e);
    }
}

/**
 * Flow-only chart initializer: creates SVG, scales, IP rows, and zoom handler
 * directly from selected IPs and flow time extent. No packet data needed.
 */
function _initFlowOnlyChart(selectedIPs, timeExtent) {
    d3.select("#chart").html("");
    document.getElementById('loadingMessage').style.display = 'none';

    const ROW_GAP_CRAMPED = 0.1;
    const margin = { top: 80, right: 120, bottom: 50, left: 180 };
    const chartContainerEl = document.getElementById('chart-container');
    width = chartContainerEl.clientWidth - margin.left - margin.right;

    const span = Math.max(1, timeExtent[1] - timeExtent[0]);
    const pad = Math.max(1, Math.floor(span * 0.02));
    state.data.timeExtent = [timeExtent[0] - pad, timeExtent[1] + pad];

    state.layout.ipPositions.clear();
    state.layout.ipRowHeights = state.layout.ipRowHeights || new Map();
    state.layout.ipRowHeights.clear();
    state.layout.ipPairCounts = state.layout.ipPairCounts || new Map();
    state.layout.ipPairCounts.clear();

    state.layout.ipOrder = selectedIPs.slice();
    for (const ip of selectedIPs) state.layout.collapsedIPs.add(ip);
    let y = TOP_PAD;
    for (const ip of selectedIPs) {
        state.layout.ipPositions.set(ip, y);
        state.layout.ipRowHeights.set(ip, ROW_GAP_CRAMPED);
        state.layout.ipPairCounts.set(ip, 1);
        y += ROW_GAP_CRAMPED;
    }
    height = y + TOP_PAD;
    const minY = TOP_PAD;
    const maxY = height;

    xScale = d3.scaleLinear().domain(state.data.timeExtent).range([0, width]);
    yScale = d3.scaleLinear().domain([minY, maxY]).range([minY, maxY]);

    // Flow-only mode: create SVG structure so fullDomainLayer/dynamicLayer remain valid
    // d3 selections (renderLozenges needs a real layer to compute yPosWithOffset, which
    // is then handed to the WebGL renderer).  The SVG element is immediately removed from
    // the DOM so the browser renders nothing from it — WebGL is the sole visual renderer.
    // mainGroup is set to null so every SVG-appending function (drawGroundTruthBoxes,
    // renderIPRowLabels, drawSelectedFlowArcs, etc.) hits its early-return guard.
    const svgResult = createSVGStructure({
        d3, containerId: '#chart', width, height, margin, dotRadius: 40
    });
    svgResult.svg.remove();   // detach from DOM — no paint cost, d3 selections still live
    svg = null;
    mainGroup = null;
    fullDomainLayer = svgResult.fullDomainLayer;
    dynamicLayer = svgResult.dynamicLayer;

    try {
        chartMarginLeft = margin.left;
        chartMarginRight = margin.right;
        const overlayResult = createBottomOverlay({
            d3, overlaySelector: '#chart-bottom-overlay-svg',
            width, chartMarginLeft, chartMarginRight,
            overlayHeight: bottomOverlayHeight, xScale, tickFormatter: null
        });
        bottomOverlaySvg = overlayResult.bottomOverlaySvg;
        bottomOverlayRoot = overlayResult.bottomOverlayRoot;
        bottomOverlayAxisGroup = overlayResult.bottomOverlayAxisGroup;
        bottomOverlayDurationLabel = overlayResult.bottomOverlayDurationLabel;
        bottomOverlayWidth = overlayResult.bottomOverlayWidth;
        dualAxis = createDualBandAxis({ scale: xScale });
        bottomOverlayAxisGroup.call(dualAxis);
    } catch (e) { console.warn('[FlowOnly] Overlay init failed', e); }

    try {
        const updateLabel = createDurationLabelUpdater({ getXScale: () => xScale, bottomOverlayDurationLabel });
        updateLabel();
    } catch (e) { /* ignore */ }

    // IP labels are drawn by the canvas renderer — no SVG labels needed

    window.__arc_x_domain__ = state.data.timeExtent.slice();

    try {
        const zoomed = createTimeArcsZoomHandler({
            d3,
            getXScale: () => xScale,
            getState: () => state,
            getTimeExtent: () => state.data.timeExtent,
            width,
            fullDomainLayer,
            dynamicLayer,
            mainGroup,
            bottomOverlayAxisGroup,
            bottomOverlayDurationLabel,
            getFullDomainBinsCache: () => fullDomainBinsCache,
            setFullDomainBinsCache: (cache) => { fullDomainBinsCache = cache; },
            getIsHardResetInProgress: () => isHardResetInProgress,
            setIsHardResetInProgress: (val) => { isHardResetInProgress = val; },
            xAxis: dualAxis,
            updateBrushFromZoom,
            updateZoomDurationLabel: () => {},
            updateZoomIndicator,
            getResolutionForVisibleRange,
            renderFlowDetailViewZoomed: () => {},
            drawSelectedFlowArcs: () => {},
            drawSubRowArcs: () => {},
            drawGroundTruthBoxes: () => {},
            getVisiblePackets: () => [],
            buildSelectedFlowKeySet: () => new Set(),
            makeConnectionKey,
            findIPPosition,
            getFlagType,
            renderMarksForLayer: renderMarksForLayerLocal,
            getGlobalMaxBinCount: () => 1,
            getFlagCounts: () => ({}),
            getMultiResData: () => null,
            isMultiResAvailable: () => false,
            getUseMultiRes: () => false,
            setCurrentResolutionLevel: () => {},
            drawAutoFlowThreading: () => {},
            clearAutoFlowThreading: () => {},
            logCatchError,
            applyIPRowFilter: (v) => applyIPRowFilter(v),
            restoreBaseRows: () => restoreBaseRows(),
            getFlowZoomManager: () => flowZoomManager,
            getSelectedIPs: () => Array.from(
                document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')
            ).map(cb => cb.value)
        });
        zoom = createZoomBehavior({ d3, scaleExtent: [1, 1e9], onZoom: zoomed });
        // SVG is removed in flow-only mode; attach zoom to the chart container div instead.
        zoomTarget = d3.select(chartContainerEl);
        zoomTarget.call(zoom);
    } catch (e) { console.warn('[FlowOnly] Zoom handler init failed', e); }

    fullDomainBinsCache = { version: state.data.version, data: [], binSize: null, sorted: false };

    // Build main chart WebGL renderer (draws lozenges on top of the SVG background)
    _setupMainWebGLRenderer(margin, ROW_GAP_CRAMPED);

    // Kick an initial render if flow data is already available; otherwise the
    // regular data-load pipeline (applyZoomDomain / loadFlowViewData) will
    // trigger it.
    if (state.flowView && state.flowView.binnedData && state.flowView.binnedData.length > 0) {
        try { renderMarksForLayerLocal(fullDomainLayer, state.flowView.binnedData); } catch (e) {}
    }

    console.log(`[FlowOnly] Chart initialized: ${selectedIPs.length} IP rows, time range ${(span / 60_000_000).toFixed(1)} min`);
}

/**
 * Set up the WebGL renderer for the main chart lozenge layer.
 * The canvas sits at z-index 0 inside #chart-container, behind the SVG.
 * All SVG event handlers (zoom, drag-reorder, etc.) remain active because
 * both WebGL canvases have pointer-events:none.
 *
 * NOTE: With skipSvgRects:true passed to renderLozenges, SVG <rect class="flow-lozenge">
 * elements are NOT created. This means lozenge tooltips and hover strokes are
 * not available on the main view until a follow-up hit-testing pass is added.
 */
function _setupMainWebGLRenderer(margin, rowGap) {
    // Tear down any previous instance (e.g. chart re-init)
    if (mainWebGLRenderer) {
        try { mainWebGLRenderer.destroy(); } catch (e) {}
        mainWebGLRenderer = null;
    }

    const chartContainerEl = document.getElementById('chart-container');
    if (!chartContainerEl) return;
    if (typeof createREGL === 'undefined') {
        console.warn('[MainWebGL] regl not loaded — main chart will use SVG lozenges');
        return;
    }

    try {
        mainWebGLRenderer = new WebGLFlowRenderer(chartContainerEl, margin, width);

        // Keep WebGL canvases behind the SVG so SVG events (zoom, drag) are unaffected
        mainWebGLRenderer.canvas.style.zIndex = '0';
        mainWebGLRenderer.overlayCanvas.style.zIndex = '0';
        mainWebGLRenderer.canvas.style.pointerEvents = 'none';
        mainWebGLRenderer.overlayCanvas.style.pointerEvents = 'none';

        mainWebGLRenderer.setLayout(state.layout.ipOrder, state.layout.ipPositions, rowGap ?? ROW_GAP);

        // Re-render on scroll so the WebGL canvas tracks the scrollable SVG viewport.
        chartContainerEl.addEventListener('scroll', () => {
            if (!mainWebGLRenderer) return;
            mainWebGLRenderer.render(xScale, chartContainerEl.scrollTop, chartContainerEl.clientHeight);
        });

        // Re-render on container resize (e.g. panel open/close)
        const resizeObs = new ResizeObserver(entries => {
            if (!mainWebGLRenderer) return;
            for (const entry of entries) {
                const newWidth = entry.contentRect.width - margin.left - margin.right;
                mainWebGLRenderer.resize(newWidth);
                mainWebGLRenderer.render(xScale, chartContainerEl.scrollTop, chartContainerEl.clientHeight);
            }
        });
        resizeObs.observe(chartContainerEl);

        console.log('[MainWebGL] WebGL renderer initialized for main chart');
    } catch (e) {
        console.warn('[MainWebGL] Failed to initialize main chart WebGL renderer:', e.message);
        mainWebGLRenderer = null;
    }
}

/**
 * Draw SVG text labels for every IP row (left margin).
 */
function _renderAllIPLabels(mainMargin) {
    if (!svg) return;
    const sel = d3.select(svg.node());
    const labels = sel.selectAll('.node-label').data(state.layout.ipOrder, d => d);
    labels.exit().remove();
    const enter = labels.enter().append('text')
        .attr('class', 'node-label')
        .attr('text-anchor', 'end')
        .attr('font-size', 11)
        .attr('font-family', 'monospace')
        .attr('fill', '#212529');
    // `svg` is the translated inner <g> (transform: translate(margin.left, margin.top)).
    // x = -10 places labels in the left margin.
    enter.merge(labels)
        .attr('x', -10)
        .attr('y', d => state.layout.ipPositions.get(d) || 0)
        .attr('dy', '.35em')
        .text(d => d);
}

/**
 * Initialise the visualization for flows-only startup (no packet data loaded).
 * Fetches the IP list from the flow dataset's ips/unique_ips.json, seeds
 * state.data.timeExtent, creates IP checkboxes, and triggers updateIPFilter.
 */
async function initFlowOnlyMode(flowBasePath, flowTimeExtent) {
    // Seed time extent so xScale and overview chart have a valid range
    if (Array.isArray(flowTimeExtent) && flowTimeExtent[0] < flowTimeExtent[1]) {
        state.data.timeExtent = flowTimeExtent.slice();
        console.log('[FlowOnly] Seeded state.data.timeExtent from flow range:', state.data.timeExtent);
    }

    // Load the IP list produced alongside the flow data
    try {
        const resp = await fetch(`${flowBasePath}/ips/unique_ips.json`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const ips = await resp.json();

        // Sort IPs by first connection time
        let sortedIPs = ips;
        try {
            const statsResp = await fetch(`${flowBasePath}/ips/ip_stats.json`);
            if (statsResp.ok) {
                const ipStats = await statsResp.json();
                sortedIPs = [...ips].sort((a, b) => {
                    const ta = ipStats[a]?.first_ts ?? Infinity;
                    const tb = ipStats[b]?.first_ts ?? Infinity;
                    return ta - tb;
                });
            }
        } catch (_) { sortedIPs = ips.sort(); }

        createIPCheckboxes(sortedIPs);
        document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = true);

        // Build chart directly from flow data — no packets needed
        _initFlowOnlyChart(sortedIPs, flowTimeExtent);

        console.log(`[FlowOnly] Created checkboxes for ${ips.length} IPs`);

        const loadingMsg = document.getElementById('loadingMessage');
        if (loadingMsg) {
            loadingMsg.textContent = `Flow data ready — ${ips.length} IPs. Switch to Packets view to load packet data.`;
            loadingMsg.style.display = 'block';
        }
    } catch (e) {
        console.warn('[FlowOnly] Could not load IP list from flow data:', e.message);
    }
}

// Handle folder data loaded event
function handleFolderDataLoaded(event) {
    console.log('Folder data loaded event received:', event.detail);

    try {
        const { packets, flowsIndex, ipStats, flagStats, manifest, multiResolution, isPreBinned, uniqueIPs: preloadedUniqueIPs } = event.detail;

        // Check for multi-resolution support
        if (multiResolution?.available) {
            useMultiRes = true;
            console.log('Multi-resolution enabled:', multiResolution.info);
        } else {
            useMultiRes = false;
            console.log('Multi-resolution not available, using standard loading');
        }

        if (!packets || packets.length === 0) {
            console.error('No data in folder. Event detail:', event.detail);
            console.error('multiResolution:', multiResolution);
            console.error('isPreBinned:', isPreBinned);
            alert(`Error: No data found in folder.

Possible causes:
1. Multi-resolution seconds data failed to load (check console)
2. packets.csv is too large to load in browser
3. Folder structure doesn't match expected format

Check browser console (F12) for detailed error logs.`);
            return;
        }

        // Track if data is pre-binned (skip binning in render)
        // Check both isPreBinned and isAggregated (folder_integration uses isAggregated)
        state.data.isPreBinned = isPreBinned || event.detail.isAggregated;

        if (state.data.isPreBinned) {
            console.log(`Processing ${packets.length} pre-binned data points from folder (seconds resolution)...`);
            // Normalize pre-binned data: convert snake_case to camelCase for compatibility
            packets.forEach(p => {
                if (p.flag_type && !p.flagType) p.flagType = p.flag_type;
                if (p.bin_start !== undefined && p.binCenter === undefined) {
                    p.binCenter = p.bin_start + ((p.bin_end || p.bin_start) - p.bin_start) / 2;
                }
                if (p.binned === undefined) p.binned = true;
                if (p.count === undefined) p.count = 1;
            });
        } else {
            console.log(`Processing ${packets.length} packets from folder...`);
        }

        // Set data - for pre-binned data, this is seconds-resolution bins
        state.data.full = packets;
        state.data.filtered = [];

        // Also populate fetchResManager.singleFileData so resolution lookup works correctly
        // Check both isPreBinned and isAggregated (folder_integration uses isAggregated)
        const isPreBinnedData = isPreBinned || event.detail.isAggregated;
        if (packets.length > 0) {
            fetchResManager.singleFileData.set('seconds', packets);
            console.log(`[FolderData] Stored ${packets.length} seconds bins in fetchResManager.singleFileData`);
        }

        // Convert flows index to flow objects (simplified format for now)
        state.flows.tcp = flowsIndex.map(flowSummary => ({
            id: flowSummary.id,
            key: flowSummary.key,
            initiator: flowSummary.initiator,
            responder: flowSummary.responder,
            initiatorPort: flowSummary.initiatorPort,
            responderPort: flowSummary.responderPort,
            state: flowSummary.state,
            closeType: flowSummary.closeType,
            startTime: flowSummary.startTime,
            endTime: flowSummary.endTime,
            totalPackets: flowSummary.totalPackets,
            totalBytes: flowSummary.totalBytes,
            establishmentComplete: flowSummary.establishmentComplete,
            dataTransferStarted: flowSummary.dataTransferStarted,
            closingStarted: flowSummary.closingStarted,
            invalidReason: flowSummary.invalidReason,
            ongoing: flowSummary.ongoing,
            phases: {
                establishment: Array(flowSummary.establishment_packets || 0).fill({}),
                dataTransfer: Array(flowSummary.data_transfer_packets || 0).fill({}),
                closing: Array(flowSummary.closing_packets || 0).fill({})
            }
        }));
        
        console.log(`Loaded ${state.flows.tcp.length} flows from folder`);
        
        // Initialize state.flows.current as empty - will be populated when IPs are selected
        state.flows.current = [];
        state.flows.selectedIds.clear();
        
        // Update TCP flow stats to show initial message
        updateTcpFlowStats(state.flows.current);

        // Get unique IPs - prefer pre-loaded list, fallback to extracting from data
        let uniqueIPs;
        if (preloadedUniqueIPs && preloadedUniqueIPs.length > 0) {
            uniqueIPs = preloadedUniqueIPs;
            console.log(`Using ${uniqueIPs.length} pre-loaded unique IPs`);
        } else {
            uniqueIPs = Array.from(new Set(state.data.full.flatMap(p => [p.src_ip, p.dst_ip]))).filter(Boolean);
            console.log(`Extracted ${uniqueIPs.length} unique IPs from data`);
        }
        createIPCheckboxes(uniqueIPs);

        // Initialize web worker for packet filtering
        try {
            if (!workerManager) {
                initializeWorkerManager();
            }
            // Will sync with rendered data after visualization is built
        } catch (err) {
            console.error('Worker init failed', err);
        }

        // Auto-select all IPs (no brush pre-filter in folder path)
        const anyCheckedFolder = document.querySelector('#ipCheckboxes input[type="checkbox"]:checked');
        if (!anyCheckedFolder) {
            console.log('[FolderData] No brush pre-filter — selecting all IPs');
            document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = true);
            setTimeout(() => updateIPFilter(), 100);
        }

        document.getElementById('loadingMessage').textContent = 'Please select 2 or more IP addresses to view connections.';
        document.getElementById('loadingMessage').style.display = 'block';

        console.log(`Folder data ready with ${packets.length} ${isPreBinned ? 'pre-binned data points' : 'packets'} and ${uniqueIPs.length} unique IPs`);

        // Show initial zoom indicator with full data range
        if (state.data.timeExtent && state.data.timeExtent.length === 2) {
            const fullRangeUs = state.data.timeExtent[1] - state.data.timeExtent[0];
            updateZoomIndicator(fullRangeUs, isPreBinned ? 'seconds' : null);
        }

        // Hide progress
        try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
        
    } catch (err) {
        console.error('Error handling folder data:', err);
        alert(`Error processing folder data: ${err.message}`);
        try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
    }
}

// Store for flow data (separate from packet data)
let flowDataState = null;

// Adaptive overview loader for multi-resolution flow bins
let adaptiveOverviewLoader = null;

// Semantic zoom manager for flow view clustering
let flowZoomManager = null;

// WebGL renderer for the main chart lozenges
let mainWebGLRenderer = null;

/**
 * Handle flow data loaded event
 * This supplements existing packet data without resetting the visualization
 * Preserves current IP selection and packet data
 */
async function handleFlowDataLoaded(event) {
    console.log('Flow data loaded event received:', event.detail);

    try {
        const detail = event.detail;
        const { manifest, totalFlows, timeExtent: flowTimeExtent, format } = detail;

        computeTimeArcsRange({
            timeRange: state.timearcs.timeRange,
            flowTimeExtent,
            stateTimearcs: state.timearcs
        });

        if (format === 'flow_list_csv') {
            handleFlowListFormat(detail, manifest, totalFlows, flowTimeExtent);
        } else {
            handleMultiresFlowsFormat(detail, manifest, totalFlows, flowTimeExtent);
        }

    } catch (err) {
        console.error('Error handling flow data:', err);
        alert(`Error processing flow data: ${err.message}`);
    }
}

/**
 * Handle flow_list_csv format. AdaptiveOverviewLoader, FlowListLoader and
 * FlowZoomManager are already initialized by loadFlowsFromPath — this handler
 * just stores flowDataState and applies any pending brush pre-filter.
 */
function handleFlowListFormat(detail, manifest, totalFlows, flowTimeExtent) {
    const basePath = detail.basePath || DEFAULT_FLOW_DATA_PATH;

    flowDataState = {
        manifest,
        totalFlows,
        timeExtent: flowTimeExtent,
        format: 'flow_list_csv',
        basePath,
        hasAdaptiveOverview: !!(adaptiveOverviewLoader && adaptiveOverviewLoader.index),
        hasFlowList: getFlowListLoader().isLoaded()
    };

    // In flows mode, the authoritative time axis is the flow dataset's range, not the
    // packet dataset's. Without this, visualizeTimeArcs builds xScale around the packet
    // extent and lozenges render as an invisible sliver at the start of the x-axis.
    if (state.ui.renderMode === 'flows'
        && Array.isArray(flowTimeExtent)
        && flowTimeExtent[0] < flowTimeExtent[1]) {
        state.data.timeExtent = flowTimeExtent.slice();
        console.log('[FlowData] Flows mode: overriding state.data.timeExtent with flow range', state.data.timeExtent);
    }

    updateFlowDataUI({ totalFlows, format: 'flow_list_csv' });

    console.log('[FlowData] Flow data loaded, applying TimeArcs brush selection pre-filter...');
    applyBrushSelectionPrefilter();

    // If no IPs were pre-selected (no brush), auto-select all IPs
    const anyChecked = document.querySelector('#ipCheckboxes input[type="checkbox"]:checked');
    if (!anyChecked) {
        console.log('[FlowData] No brush pre-filter — selecting all IPs');
        document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = true);
        setTimeout(() => updateIPFilter(), 100);
    }
}

/**
 * Handle multires flows format (pre-binned overview bins)
 * @param {Object} detail - Event detail object
 * @param {Object} manifest - Data manifest
 * @param {number} totalFlows - Total flow count
 * @param {Array} flowTimeExtent - Time extent [min, max]
 */
function handleMultiresFlowsFormat(detail, manifest, totalFlows, flowTimeExtent) {
    const { overviewBins, flowResolutionState, loadFlowsForTimeRange } = detail;

    // Store flow state for on-demand loading
    flowDataState = {
        overviewBins,
        manifest,
        flowResolutionState,
        loadFlowsForTimeRange,
        totalFlows,
        timeExtent: flowTimeExtent
    };

    // Update UI
    updateFlowDataUI({ totalFlows, format: 'multires' });

    console.log(`[FlowData] Stored flow state: ${totalFlows} flows available for on-demand loading`);

    // Create the flow overview chart
    if (overviewBins && overviewBins.length > 0) {
        const { width, margins } = calculateChartDimensions();

        // Debug: check sample bin data
        const sampleBin = overviewBins[Math.floor(overviewBins.length / 2)];
        console.log('[FlowData] Sample bin:', sampleBin);
        console.log(`[FlowData] Chart dimensions: width=${width}, flowTimeExtent=`, flowTimeExtent);

        const effectiveExtent = state.timearcs.overviewTimeExtent || flowTimeExtent;
        createFlowOverviewChart(overviewBins, {
            timeExtent: effectiveExtent,
            width,
            margins,
            loadFlowsForTimeRange
        });

        console.log(`[FlowData] Created flow overview chart with ${overviewBins.length} bins`);
    } else {
        console.warn('[FlowData] No overview bins to display');
    }
}

/**
 * Get the current flow data state
 */
function getFlowDataState() {
    return flowDataState;
}

/**
 * Load flows for currently selected IPs and visible time range
 */
async function loadFlowsForCurrentView() {
    if (!flowDataState || !flowDataState.loadFlowsForTimeRange) {
        console.log('[FlowData] No flow data available');
        return [];
    }

    // Get current visible time range from the visualization
    const visibleExtent = getVisibleTimeExtent();
    if (!visibleExtent) {
        console.log('[FlowData] No visible time extent');
        return [];
    }

    console.log(`[FlowData] Loading flows for time range: ${visibleExtent[0]} - ${visibleExtent[1]}`);
    const flows = await flowDataState.loadFlowsForTimeRange(visibleExtent[0], visibleExtent[1]);

    // Bypass IP filtering when time range is <= 90 minutes (load all IP pairs)
    const timeRangeUs = visibleExtent[1] - visibleExtent[0];
    if (timeRangeUs > 0 && timeRangeUs <= ALL_IP_PAIRS_TIME_THRESHOLD_US) {
        console.log(`[FlowData] Time range ${(timeRangeUs / 60_000_000).toFixed(1)} min <= 90 min — returning all flows`);
        return flows;
    }

    // Filter by selected IPs if any
    if (selectedIPs && selectedIPs.length > 0) {
        const ipSet = new Set(selectedIPs);
        return flows.filter(f => ipSet.has(f.initiator) || ipSet.has(f.responder));
    }

    return flows;
}

/**
 * Get current visible time extent from visualization
 */
function getVisibleTimeExtent() {
    // Try to get from scales
    if (window.xScale && typeof window.xScale.domain === 'function') {
        const domain = window.xScale.domain();
        if (domain && domain.length === 2) {
            return [domain[0].getTime() * 1000, domain[1].getTime() * 1000];
        }
    }
    // Fallback to full data extent
    if (state.data.full && state.data.full.length > 0) {
        const times = state.data.full.map(d => d.timestamp || d.binStart || d.binCenter);
        return [Math.min(...times), Math.max(...times)];
    }
    return null;
}

// Default data path for auto-loading
const DEFAULT_DATA_PATH = 'packets_data/decoded_set1_90min_packets';
const DEFAULT_FLOW_DATA_PATH = '/set1_60min_flows';

// When the visible time range is <= 90 minutes, load ALL IP pairs (bypass IP selection filter)
const ALL_IP_PAIRS_TIME_THRESHOLD_US = 90 * 60 * 1_000_000; // 90 minutes in microseconds

/**
 * Extract all unique IPs from flow data metadata (pairsMeta or chunksMeta).
 * Used when loading all IP pairs for short time ranges.
 * @returns {string[]|null} Array of all IPs, or null if unavailable
 */
function getAllFlowDataIPs() {
    if (!flowDataState) return null;
    const allIPs = new Set();
    if (flowDataState.pairsMeta) {
        for (const pair of flowDataState.pairsMeta) {
            if (pair.ips) for (const ip of pair.ips) allIPs.add(ip);
        }
    } else if (flowDataState.chunksMeta) {
        for (const chunk of flowDataState.chunksMeta) {
            if (chunk.ips) for (const ip of chunk.ips) allIPs.add(ip);
        }
    }
    return allIPs.size > 0 ? Array.from(allIPs) : null;
}

// ============================================================================
// Fetch-based Multi-Resolution Manager
// Handles dynamic loading of millisecond and raw resolution data via fetch()
// ============================================================================

/**
 * Single configuration for all resolution levels (fetch-based manager).
 * Order matters: first match wins (check from top to bottom).
 *
 * Thresholds:
 * - hours: > 2 days visible
 * - minutes: > 1 hour visible
 * - 10s: > 10 minutes visible
 * - seconds: > 1 minute visible
 * - 100ms: > 10 seconds visible
 * - 10ms: > 1 second visible
 * - 1ms: > 100ms visible
 * - raw: <= 100ms visible
 */
const FETCH_RES_CONFIG = [
    {
        name: 'hours',
        dirName: 'hours',
        threshold: 2 * 24 * 60 * 60 * 1_000_000, // > 2 days visible: use hours
        binSize: 3_600_000_000,          // 1 hour in microseconds
        preBinned: true,
        isSingleFile: true,
        cacheSize: 0,
        uiInfo: { label: 'Hours', icon: '🕐', color: '#20c997' }
    },
    {
        name: 'minutes',
        dirName: 'minutes',
        threshold: 60 * 60 * 1_000_000,  // > 1 hour visible: use minutes
        binSize: 60_000_000,             // 1 minute in microseconds
        preBinned: true,
        isSingleFile: true,
        cacheSize: 0,
        uiInfo: { label: 'Minutes', icon: '🕑', color: '#17a2b8' }
    },
    {
        name: '10s',
        dirName: '10s',
        threshold: 10 * 60 * 1_000_000,  // > 10 minutes visible: use 10s
        binSize: 10_000_000,             // 10 seconds in microseconds
        preBinned: true,
        isSingleFile: true,
        cacheSize: 0,
        uiInfo: { label: '10 Seconds', icon: '⏱', color: '#20c997' }
    },
    {
        name: 'seconds',
        dirName: 'seconds',
        threshold: 60 * 1_000_000,       // > 1 minute visible: use seconds
        binSize: 1_000_000,
        preBinned: true,
        isSingleFile: true,
        cacheSize: 0,
        uiInfo: { label: 'Seconds', icon: '', color: '#28a745' }
    },
    {
        name: '100ms',
        dirName: '100ms',
        threshold: 10 * 1_000_000,       // > 10s visible: use 100ms
        binSize: 100_000,
        preBinned: true,
        isSingleFile: false,
        cacheSize: 30,
        uiInfo: { label: '100ms', icon: '⏱', color: '#17a2b8' }
    },
    {
        name: '10ms',
        dirName: '10ms',
        threshold: 1 * 1_000_000,        // > 1s visible: use 10ms
        binSize: 10_000,
        preBinned: true,
        isSingleFile: false,
        cacheSize: 40,
        uiInfo: { label: '10ms', icon: '⏱', color: '#007bff' }
    },
    {
        name: '1ms',
        dirName: '1ms',
        threshold: 100_000,              // > 100ms visible: use 1ms
        binSize: 1_000,
        preBinned: true,
        isSingleFile: false,
        cacheSize: 50,
        uiInfo: { label: '1ms', icon: '⏱', color: '#6610f2' }
    },
    {
        name: 'raw',
        dirName: 'raw',
        threshold: 0,               // < 100ms visible: use raw
        binSize: 1,
        preBinned: false,
        isSingleFile: false,
        cacheSize: 50,
        uiInfo: { label: 'Raw Packets', icon: '📦', color: '#6c757d' }
    },
    // Fallback entry for client-side binning (not a real resolution level)
    {
        name: 'binned',
        dirName: null,
        threshold: -1,
        binSize: 0,
        preBinned: false,
        isSingleFile: false,
        cacheSize: 0,
        uiInfo: { label: 'Client Binned', icon: '🔄', color: '#fd7e14' }
    }
];

// Build lookup map for quick access by name
const FETCH_RES_BY_NAME = Object.fromEntries(
    FETCH_RES_CONFIG.map(r => [r.name, r])
);

// Fetch-based resolution manager state (dynamic, config-driven)
const fetchResManager = {
    basePath: null,
    indices: new Map(),            // resolution name -> index data
    caches: new Map(),             // resolution name -> Map (chunk cache)
    singleFileData: new Map(),     // resolution name -> data array
    loadingChunks: new Set(),
    initialized: false,
    timeExtent: null,
    selectedIPs: [],
    selectedIPSet: new Set()
};

// Initialize caches based on config
for (const res of FETCH_RES_CONFIG) {
    if (!res.isSingleFile && res.cacheSize > 0) {
        fetchResManager.caches.set(res.name, new Map());
    }
}

/**
 * Set the selected IPs for filtering multi-res data
 * Called from updateIPFilter when user selects/deselects IPs
 */
function setFetchResSelectedIPs(ips) {
    fetchResManager.selectedIPs = ips || [];
    fetchResManager.selectedIPSet = new Set(fetchResManager.selectedIPs);
    console.log(`[FetchResManager] Selected IPs updated: ${fetchResManager.selectedIPs.length} IPs`);
}

/**
 * Initialize the fetch-based resolution manager
 */
async function initFetchResolutionManager(basePath) {
    console.log('[FetchResManager] Initializing...');
    fetchResManager.basePath = basePath;

    // Load indices for all resolutions based on config
    for (const res of FETCH_RES_CONFIG) {
        if (res.isSingleFile || !res.dirName) continue;  // Skip single-file and fallback entries

        try {
            const indexResp = await fetch(`${basePath}/resolutions/${res.dirName}/index.json`);
            if (indexResp.ok) {
                const index = await indexResp.json();
                fetchResManager.indices.set(res.name, index);
                console.log(`[FetchResManager] Loaded ${res.name} index: ${index.chunks?.length || 0} chunks`);
            }
        } catch (err) {
            console.warn(`[FetchResManager] Failed to load ${res.name} index:`, err);
        }
    }

    fetchResManager.initialized = true;

    // Set global functions for the zoom handler to use
    getMultiResData = fetchGetMultiResData;
    isMultiResAvailable = () => fetchResManager.initialized;
    getCurrentResolution = () => currentResolutionLevel;
    setMultiResSelectedIPs = setFetchResSelectedIPs;

    console.log('[FetchResManager] Initialization complete');
}

/**
 * Map overview chart resolution to packets view resolution
 * Overview uses: '1s', '1min', '10min', 'hour'
 * Packets use: 'seconds', 'minutes', 'hours', etc.
 */
const OVERVIEW_TO_PACKET_RESOLUTION = {
    '1s': 'seconds',
    '1min': '10s',
    '10min': 'minutes',
    'hour': 'hours'
};

/**
 * Determine which resolution to use based on visible range.
 *
 * Manual override acts as a *ceiling* (coarsest allowed level).
 * The threshold-based auto logic still runs, and zoom can go finer
 * than the ceiling, but never coarser.  For example, selecting
 * "Minutes" means the view starts at minutes and refines to
 * seconds → 100ms → 10ms → 1ms → raw as the user zooms in.
 */
function getResolutionForVisibleRange(visibleRangeUs) {
    // Sanity check
    if (!visibleRangeUs || visibleRangeUs <= 0) {
        if (manualResolutionOverride && FETCH_RES_BY_NAME[manualResolutionOverride]) {
            return manualResolutionOverride;
        }
        return 'hours';
    }

    // On initial load only: sync with overview chart resolution (when no manual override)
    if (!manualResolutionOverride && isInitialResolutionLoad &&
        adaptiveOverviewLoader && adaptiveOverviewLoader.index) {
        const timeRangeMinutes = visibleRangeUs / 60_000_000;
        const overviewRes = adaptiveOverviewLoader.selectResolution(timeRangeMinutes);
        const mappedRes = OVERVIEW_TO_PACKET_RESOLUTION[overviewRes];
        if (mappedRes && FETCH_RES_BY_NAME[mappedRes]) {
            console.log(`[Resolution] Initial load sync: ${timeRangeMinutes.toFixed(1)} min → overview=${overviewRes} → packets=${mappedRes}`);
            isInitialResolutionLoad = false;
            return mappedRes;
        }
    }

    // Threshold-based auto logic — pick the coarsest level whose
    // threshold the visible range exceeds (list is coarse-to-fine)
    let autoResolution = '1ms';
    for (const res of FETCH_RES_CONFIG) {
        if (res.name === 'binned') continue;
        if (visibleRangeUs > res.threshold) {
            autoResolution = res.name;
            break;
        }
    }

    // If a manual override is set, walk from the selected level toward finer
    // resolutions.  The selected level is "sticky" — it holds until the zoom
    // crosses the *next* finer level's threshold, then steps down one level
    // at a time.  This means selecting "Minutes+" shows minutes immediately
    // and only refines to seconds when the visible range drops below the
    // seconds threshold (1 min), not the minutes threshold (1 hour).
    //
    // Special case: raw's threshold is 0 (always matches ≥ 0), which would
    // trap the walk at 1ms forever.  We substitute the current level's own
    // threshold so the 1ms→raw transition matches auto mode.
    if (manualResolutionOverride && FETCH_RES_BY_NAME[manualResolutionOverride]) {
        const startIdx = FETCH_RES_CONFIG.findIndex(r => r.name === manualResolutionOverride);

        let currentIdx = startIdx;
        while (currentIdx < FETCH_RES_CONFIG.length - 1) {
            const nextLevel = FETCH_RES_CONFIG[currentIdx + 1];
            if (nextLevel.name === 'binned') break;

            // For raw (threshold 0), use current level's threshold so
            // 1ms→raw fires at the same point auto mode would transition
            const checkThreshold = nextLevel.threshold === 0
                ? FETCH_RES_CONFIG[currentIdx].threshold
                : nextLevel.threshold;

            if (visibleRangeUs >= checkThreshold) break; // not zoomed in enough
            currentIdx++;
        }

        const result = FETCH_RES_CONFIG[currentIdx].name;
        console.log(`[Resolution] Manual override ${manualResolutionOverride} → ${result} (walk from ${manualResolutionOverride})`);
        return result;
    }

    console.log(`[Resolution] Threshold: ${(visibleRangeUs/1_000_000).toFixed(2)}s → ${autoResolution}`);
    return autoResolution;
}

/**
 * Get data for the current zoom level (called by zoom handler)
 * @param {d3.scaleLinear} xScale - Current x scale
 * @param {number} zoomLevel - Zoom level (not directly used, we calculate from domain)
 * @returns {Promise<{data: Array, resolution: string, preBinned: boolean}>}
 */
async function fetchGetMultiResData(xScale, zoomLevel) {
    if (!fetchResManager.initialized) {
        return { data: [], resolution: 'hours', preBinned: true };
    }

    const domain = xScale.domain();
    let [start, end] = [Math.floor(domain[0]), Math.floor(domain[1])];

    // If TimeArcs selection is active, clamp to the selection time range
    // This prevents loading data outside the user's selection when panning
    if (state.timearcs.overviewTimeExtent &&
        state.timearcs.overviewTimeExtent[0] < state.timearcs.overviewTimeExtent[1]) {
        const [timeMin, timeMax] = state.timearcs.overviewTimeExtent;
        start = Math.max(start, timeMin);
        end = Math.min(end, timeMax);
        // If panned completely outside the selection, return empty
        if (start >= end) {
            return { data: [], resolution: 'hours', preBinned: true };
        }
    }

    const visibleRange = end - start;

    const resolution = getResolutionForVisibleRange(visibleRange);
    const resConfig = FETCH_RES_BY_NAME[resolution];
    console.log(`[FetchResManager] Visible range: ${(visibleRange/1_000_000).toFixed(2)}s, Resolution: ${resolution}`);

    // Helper: filter data by selected IPs (only include rows where both src and dst are selected)
    const filterBySelectedIPs = (data) => {
        const ipSet = fetchResManager.selectedIPSet;
        if (ipSet.size < 2) {
            return [];  // Need at least 2 IPs to show any connection
        }
        return data.filter(d => ipSet.has(d.src_ip) && ipSet.has(d.dst_ip));
    };

    // For single-file resolutions (hours, minutes, seconds), use pre-loaded data
    if (resConfig?.isSingleFile) {
        const preloadedData = fetchResManager.singleFileData.get(resolution);
        if (preloadedData) {
            let filtered = preloadedData.filter(d => {
                const t = d.binStart || d.timestamp;
                return t >= start && t <= end;
            });
            filtered = filterBySelectedIPs(filtered);
            return { data: filtered, resolution, preBinned: resConfig.preBinned };
        }
        // Fall back to state.data.full
        let filtered = state.data.full.filter(d => {
            const t = d.binStart || d.timestamp;
            return t >= start && t <= end;
        });
        filtered = filterBySelectedIPs(filtered);
        return { data: filtered, resolution, preBinned: true };
    }

    // For chunked resolutions, fetch from chunks
    let data = await fetchChunksForRange(start, end, resolution);
    data = filterBySelectedIPs(data);
    return { data, resolution, preBinned: resConfig?.preBinned !== false };
}

/**
 * Get index and cache for a given resolution
 */
function getIndexAndCacheForResolution(resolution) {
    return {
        index: fetchResManager.indices.get(resolution),
        cache: fetchResManager.caches.get(resolution)
    };
}

/**
 * Fetch and assemble data from chunks for a time range
 */
async function fetchChunksForRange(start, end, resolution) {
    const { index, cache } = getIndexAndCacheForResolution(resolution);

    if (!index || !index.chunks) {
        console.warn(`[FetchResManager] No ${resolution} index available`);
        return [];
    }

    // Find chunks that overlap with the requested range
    const neededChunks = index.chunks.filter(chunk =>
        chunk.end >= start && chunk.start <= end
    );

    console.log(`[FetchResManager] Need ${neededChunks.length} ${resolution} chunks for range [${start}, ${end}]`);

    // Load any chunks not in cache
    const loadPromises = [];
    for (const chunk of neededChunks) {
        if (!cache.has(chunk.file) && !fetchResManager.loadingChunks.has(chunk.file)) {
            loadPromises.push(loadChunk(chunk, resolution));
        }
    }

    // Wait for all chunks to load
    if (loadPromises.length > 0) {
        console.log(`[FetchResManager] Loading ${loadPromises.length} ${resolution} chunks...`);
        await Promise.all(loadPromises);
    }

    // Assemble data from cache
    const allData = [];
    for (const chunk of neededChunks) {
        const chunkData = cache.get(chunk.file);
        if (chunkData) {
            // Filter to exact range
            const filtered = chunkData.filter(d => {
                const t = d.binStart || d.timestamp;
                return t >= start && t <= end;
            });
            allData.push(...filtered);
        }
    }

    // Sort by timestamp
    allData.sort((a, b) => (a.timestamp || a.binStart) - (b.timestamp || b.binStart));

    console.log(`[FetchResManager] Assembled ${allData.length} ${resolution} data points`);
    return allData;
}

/**
 * Load a single chunk from the server
 */
async function loadChunk(chunk, resolution) {
    const { cache } = getIndexAndCacheForResolution(resolution);
    const resConfig = FETCH_RES_BY_NAME[resolution];

    if (!cache || !resConfig) {
        console.warn(`[FetchResManager] Unknown resolution: ${resolution}`);
        return;
    }

    fetchResManager.loadingChunks.add(chunk.file);

    try {
        const url = `${fetchResManager.basePath}/resolutions/${resConfig.dirName}/${chunk.file}`;
        console.log(`[FetchResManager] Loading: ${url}`);

        const response = await fetch(url);
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const csvText = await response.text();
        // Use config to determine parsing: preBinned uses binned parser, otherwise raw
        const data = resConfig.preBinned
            ? parseBinnedCSV(csvText, resConfig)
            : parseRawCSV(csvText, resConfig);

        // Add to cache (with LRU eviction based on config)
        const maxSize = resConfig.cacheSize || 30;
        if (cache.size >= maxSize) {
            const oldest = cache.keys().next().value;
            cache.delete(oldest);
        }
        cache.set(chunk.file, data);

        console.log(`[FetchResManager] Loaded ${chunk.file}: ${data.length} items`);

    } catch (err) {
        console.error(`[FetchResManager] Failed to load ${chunk.file}:`, err);
    } finally {
        fetchResManager.loadingChunks.delete(chunk.file);
    }
}

/**
 * Generic CSV parser for packet/bin data
 * Consolidates parseBinnedCSV, parseRawCSV, and parseSecondsCSV
 * @param {string} csvText - CSV text to parse
 * @param {Object} config - Parser configuration
 * @param {string[]} config.numericFields - Fields to parse as integers
 * @param {boolean} config.binned - Whether data is pre-binned (affects metadata)
 * @param {number} config.binSize - Bin size in microseconds (for binned data)
 * @param {string} config.resolution - Resolution name string
 * @param {number} config.progressInterval - Log progress every N lines (0 = disabled)
 * @returns {Array} Parsed data objects
 */
function parsePacketCSV(csvText, config = {}) {
    const {
        numericFields = [],
        binned = false,
        binSize = 1_000_000,
        resolution = 'unknown',
        progressInterval = 0
    } = config;

    const lines = csvText.split('\n').filter(line => line.trim().length > 0);
    if (lines.length < 2) return [];

    const headers = lines[0].split(',').map(h => h.trim());
    const data = [];
    const numericSet = new Set(numericFields);

    for (let i = 1; i < lines.length; i++) {
        const values = lines[i].split(',');
        if (values.length < headers.length) continue;

        const row = {};
        for (let j = 0; j < headers.length; j++) {
            const header = headers[j];
            let value = values[j]?.trim() || '';
            if (numericSet.has(header)) {
                value = parseInt(value) || 0;
            }
            row[header] = value;
        }

        // Common metadata
        row.binned = binned;
        row.flagType = row.flag_type || 'OTHER';
        row.resolution = resolution;

        // Binned data gets additional metadata.
        // Derive bin extents from `timestamp` (the bin's start) + the resolution's binSize,
        // so we don't need to read the `bin_start` / `bin_end` columns from the CSV.
        // We still populate `bin_start` / `bin_end` on the row (as numbers, not strings)
        // so downstream consumers that access those snake_case fields keep working.
        if (binned) {
            const halfBin = Math.floor(binSize / 2);
            row.bin_start = row.timestamp;
            row.bin_end = row.timestamp + binSize;
            row.binStart = row.timestamp;
            row.binEnd = row.timestamp + binSize;
            row.binCenter = row.timestamp + halfBin;
            row.flags = flagTypeToFlags(row.flag_type);
            row.length = row.total_bytes || 0;
            row.preBinnedSize = binSize;
        }

        data.push(row);

        // Optional progress logging
        if (progressInterval > 0 && i % progressInterval === 0) {
            console.log(`[parsePacketCSV] Parsed ${i}/${lines.length} ${resolution} rows...`);
        }
    }

    return data;
}

/** Parse binned CSV - thin wrapper for backwards compatibility */
function parseBinnedCSV(csvText, resConfig) {
    return parsePacketCSV(csvText, {
        // bin_start / bin_end intentionally omitted — binStart/binEnd/binCenter
        // are derived from `timestamp` + binSize inside parsePacketCSV.
        numericFields: ['timestamp', 'count', 'total_bytes'],
        binned: true,
        binSize: resConfig?.binSize || 1_000,
        resolution: resConfig?.name || 'unknown'
    });
}

/** Parse raw CSV (individual packets) - thin wrapper for backwards compatibility */
function parseRawCSV(csvText, resConfig = null) {
    return parsePacketCSV(csvText, {
        numericFields: ['timestamp', 'src_port', 'dst_port', 'flags', 'length'],
        binned: false,
        resolution: resConfig?.name || 'raw'
    });
}

/**
 * Load a single resolution tier via fetch, handling both single-file and chunked
 * layouts declared in the per-resolution index.json.
 *
 * Single-file layout: index.json has a `data_file` field (or falls back to data.csv).
 * Chunked layout:     index.json has a `chunks` array of { file, ... } entries.
 *
 * @param {string} basePath - Base path to the data folder
 * @param {string} resName - Resolution name (hours, minutes, 10s, seconds, ...)
 * @param {Object} [opts]
 * @param {boolean} [opts.onlySingleFile=false] - Skip chunked tiers (for preload paths)
 * @returns {Promise<Array>} Parsed packet/bin objects
 */
async function loadResolutionPackets(basePath, resName, opts = {}) {
    const { onlySingleFile = false } = opts;

    const indexResponse = await fetch(`${basePath}/resolutions/${resName}/index.json`);
    if (!indexResponse.ok) return [];
    const index = await indexResponse.json();

    // Chunked layout
    if (Array.isArray(index.chunks) && index.chunks.length > 0) {
        if (onlySingleFile) {
            console.log(`[loadResolutionPackets] ${resName} is chunked (${index.chunks.length} chunks) — skipping preload`);
            return [];
        }
        console.log(`[loadResolutionPackets] ${resName}: loading ${index.chunks.length} chunks`);
        const chunkPackets = await Promise.all(
            index.chunks.map(async (chunk) => {
                const r = await fetch(`${basePath}/resolutions/${resName}/${chunk.file}`);
                if (!r.ok) {
                    console.warn(`[loadResolutionPackets] Chunk ${chunk.file} failed: HTTP ${r.status}`);
                    return [];
                }
                const text = await r.text();
                return parseSecondsCSV(text, resName);
            })
        );
        const flat = chunkPackets.flat();
        console.log(`[loadResolutionPackets] ${resName}: parsed ${flat.length} rows from ${index.chunks.length} chunks`);
        return flat;
    }

    // Single-file layout
    const dataFile = index.data_file || 'data.csv';
    const dataResponse = await fetch(`${basePath}/resolutions/${resName}/${dataFile}`);
    if (!dataResponse.ok) return [];
    const csvText = await dataResponse.text();
    const parsed = parseSecondsCSV(csvText, resName);
    console.log(`[loadResolutionPackets] ${resName}: parsed ${parsed.length} rows from ${dataFile}`);
    return parsed;
}

/**
 * Load CSV multi-resolution data from a specific path via fetch()
 * This allows loading data without requiring File System Access API
 * @param {string} basePath - Base path to the data folder
 */
async function loadFromPath(basePath = DEFAULT_DATA_PATH) {
    console.log(`[loadFromPath] Loading data from: ${basePath}`);

    try {
        // Show loading progress
        try { sbShowCsvProgress('Loading manifest...', 0); } catch(e) { logCatchError('sbShowCsvProgress', e); }

        // Load manifest.json
        const manifestResponse = await fetch(`${basePath}/manifest.json`);
        if (!manifestResponse.ok) {
            throw new Error(`Failed to load manifest.json: ${manifestResponse.status}`);
        }
        const manifest = await manifestResponse.json();
        console.log('[loadFromPath] Loaded manifest:', manifest);

        // Check for flow-based format (from tcp_flow_detector_multires.py)
        if (manifest.format === 'multires_flows') {
            console.log('[loadFromPath] Flow-based format detected, using flow loader');
            return await loadFlowsFromPath(basePath, manifest);
        }

        // Seed state.data.timeExtent from the manifest so any early-running consumer
        // (overview refresh, zoom handler, visualizeData) has a valid range before
        // packets finish parsing. visualizeData() later overwrites this with the
        // actual parsed extent (with 2% padding).
        if (manifest.time_range && manifest.time_range.start && manifest.time_range.end) {
            state.data.timeExtent = [manifest.time_range.start, manifest.time_range.end];
            console.log('[loadFromPath] Seeded state.data.timeExtent from manifest:', state.data.timeExtent);
        }

        // Pick the right packet resolution for the dataset's full time range,
        // using the same threshold logic that the zoom handler uses later.
        // For a 90-minute capture that means 'minutes' (2 bins at hours is useless);
        // for a multi-day capture it means 'hours'; etc.
        const fullRangeUs = manifest.time_range.end - manifest.time_range.start;
        const initialResolution = getResolutionForVisibleRange(fullRangeUs);
        const rangeMinutes = fullRangeUs / 60_000_000;
        console.log(`[loadFromPath] Full time range: ${rangeMinutes.toFixed(1)} min → initial resolution: ${initialResolution}`);

        try { sbUpdateCsvProgress(0.1, `Loading ${initialResolution} data...`); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        // Load the chosen initial tier (chunked or single-file).
        const packets = await loadResolutionPackets(basePath, initialResolution);
        if (packets.length === 0) {
            throw new Error(`No data parsed from ${initialResolution} resolution at ${basePath}`);
        }
        console.log(`[loadFromPath] Parsed ${packets.length} ${initialResolution}-level bins`);

        // Opportunistically preload any *other* single-file tiers (cheap). Chunked
        // tiers are left for on-demand loading via fetchResManager — no point
        // blocking startup on them.
        const singleFilePreloads = {};
        for (const resName of ['hours', 'minutes', '10s', 'seconds']) {
            if (resName === initialResolution) continue;
            try {
                const parsed = await loadResolutionPackets(basePath, resName, { onlySingleFile: true });
                if (parsed.length > 0) singleFilePreloads[resName] = parsed;
            } catch (e) {
                console.warn(`[loadFromPath] ${resName} preload failed:`, e);
            }
        }

        try { sbUpdateCsvProgress(0.8, 'Extracting IP addresses...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        // Extract unique IPs
        const uniqueIPs = extractUniqueIPsFromPackets(packets);
        console.log(`[loadFromPath] Found ${uniqueIPs.length} unique IPs`);

        try { sbUpdateCsvProgress(0.9, 'Initializing visualization...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        // Set global data
        state.data.full = packets;
        state.data.filtered = [];
        state.data.isPreBinned = true;  // Seconds data is pre-binned
        useMultiRes = true;

        // For now, no TCP flows from this format (flows would require separate loading)
        state.flows.tcp = [];
        state.flows.current = [];
        state.flows.selectedIds.clear();

        // Create IP checkboxes
        createIPCheckboxes(uniqueIPs);

        // Update TCP flow stats
        updateTcpFlowStats(state.flows.current);

        // Initialize web worker
        try {
            if (!workerManager) {
                initializeWorkerManager();
            }
        } catch (err) {
            console.error('Worker init failed', err);
        }

        // Auto-select all IPs
        const anyCheckedPath = document.querySelector('#ipCheckboxes input[type="checkbox"]:checked');
        if (!anyCheckedPath) {
            console.log(`[loadFromPath] Auto-selecting all ${uniqueIPs.length} IPs`);
            document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = true);
            setTimeout(() => updateIPFilter(), 100);
        }

        document.getElementById('loadingMessage').textContent =
            `Loaded ${packets.length.toLocaleString()} ${initialResolution}-level bins with ${uniqueIPs.length} IPs. Please select 2+ IP addresses to view connections.`;
        document.getElementById('loadingMessage').style.display = 'block';

        try { sbUpdateCsvProgress(0.95, 'Initializing multi-resolution manager...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        // Initialize the fetch-based resolution manager for higher-resolution data on zoom.
        // Register the initial tier + any opportunistically preloaded single-file tiers.
        fetchResManager.singleFileData.set(initialResolution, packets);
        for (const [resName, resPackets] of Object.entries(singleFilePreloads)) {
            fetchResManager.singleFileData.set(resName, resPackets);
        }
        await initFetchResolutionManager(basePath);

        try { sbUpdateCsvProgress(1.0, 'Data loaded successfully!'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }

        // Hide progress after brief delay
        setTimeout(() => {
            try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
        }, 1000);

        console.log(`[loadFromPath] Successfully loaded ${packets.length} ${initialResolution}-level bins from ${basePath}`);
        console.log(`[loadFromPath] Multi-resolution manager ready with ${fetchResManager.indices.size} resolution indices`);
        const preloadedNames = [initialResolution, ...Object.keys(singleFilePreloads)];
        console.log(`[loadFromPath] Preloaded resolutions: ${preloadedNames.join(', ')}`);

        // Don't set initial zoom indicator here - wait for overview chart to determine resolution
        // The onResolutionChange callback will sync the packets view with the overview
        console.log(`[loadFromPath] Deferring zoom indicator until overview resolution is determined`);

        // Store packet time extent for later use if needed
        const packetTimeExtent = d3.extent(packets, d => d.binStart || d.timestamp);
        console.log(`[loadFromPath] Packet time extent:`, packetTimeExtent);

    } catch (err) {
        console.error('[loadFromPath] Error loading data:', err);
        try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }

        // Show error in loading message
        const loadingMsg = document.getElementById('loadingMessage');
        if (loadingMsg) {
            loadingMsg.textContent = `Error loading data: ${err.message}. Try using the file picker instead.`;
            loadingMsg.style.display = 'block';
            loadingMsg.style.color = '#e74c3c';
        }
    }
}

/**
 * Load flow data from a path using fetch (for default/auto-loading).
 * Only flow_list_csv format is supported.
 * @param {string} basePath - Path to the flow data folder
 */
async function loadFlowsFromPath(basePath = DEFAULT_FLOW_DATA_PATH) {
    console.log(`[loadFlowsFromPath] Loading flow data from: ${basePath}`);

    try {
        // Load manifest
        const manifestResponse = await fetch(`${basePath}/manifest.json`);
        if (!manifestResponse.ok) {
            throw new Error(`Failed to load manifest: ${manifestResponse.status}`);
        }
        const manifest = await manifestResponse.json();
        console.log('[loadFlowsFromPath] Loaded manifest:', manifest);

        const format = manifest.format;
        if (format !== 'flow_list_csv') {
            throw new Error(`Unsupported format: ${format}`);
        }

        // flow_list_csv: per-flow data lives in indices/flow_list/*.csv (loaded on-demand
        // by FlowListLoader). Overview bins come from indices/flow_bins_*.json via
        // AdaptiveOverviewLoader. No chunk enumeration here.
        const totalFlows = manifest.total_flows || 0;
        const flowTimeExtent = [manifest.time_range.start, manifest.time_range.end];

        console.log(`[loadFlowsFromPath] Total flows: ${totalFlows}, time extent:`, flowTimeExtent);

        // Load the flow list index so FlowListLoader is populated before FlowZoomManager is created.
        await tryLoadFlowList(basePath);

        // Initialize adaptive overview loader early for resolution sync
        // This allows the packets view to determine resolution matching the overview chart
        try {
            const indexPath = `${basePath}/indices/flow_bins_index.json`;
            console.log(`[loadFlowsFromPath] Checking for multi-resolution index at ${indexPath}...`);
            const indexResponse = await fetch(indexPath);
            if (indexResponse.ok) {
                adaptiveOverviewLoader = new AdaptiveOverviewLoader(basePath);
                await adaptiveOverviewLoader.loadIndex();

                // Override _buildSelectedPairs on this instance: return a lazy
                // filter that checks each pair key on demand instead of
                // pre-generating N^2 combinations. The bin data already has
                // pair keys — just check if both IPs are selected. O(1) per check.
                adaptiveOverviewLoader._buildSelectedPairs = function(selectedIPs) {
                    const sel = new Set(selectedIPs);
                    return {
                        has(pairKey) {
                            const s = pairKey.indexOf('<->');
                            return s !== -1 && sel.has(pairKey.slice(0, s)) && sel.has(pairKey.slice(s + 3));
                        },
                        get size() { return sel.size; }
                    };
                };

                // Set initial resolution based on full time extent - MUST happen before any IP selection
                const initialTimeRangeMinutes = (flowTimeExtent[1] - flowTimeExtent[0]) / 60_000_000;
                adaptiveOverviewLoader.currentResolution = adaptiveOverviewLoader.selectResolution(initialTimeRangeMinutes);
                console.log(`[loadFlowsFromPath] ✓ Adaptive overview loader initialized with resolutions:`,
                    Object.keys(adaptiveOverviewLoader.index.resolutions),
                    `initial resolution: ${adaptiveOverviewLoader.currentResolution} (${initialTimeRangeMinutes.toFixed(1)} min range)`);

                // Create FlowZoomManager for semantic zoom in flow view
                if (adaptiveOverviewLoader && adaptiveOverviewLoader.index) {
                    const fll = getFlowListLoader();
                    if (fll && fll.isLoaded()) {
                        flowZoomManager = new FlowZoomManager(adaptiveOverviewLoader, fll);
                        flowZoomManager.onDataLoaded = _onFlowZoomDataLoaded;
                        console.log('[FlowZoomManager] Initialized');
                    }
                }

                // Capture flow time extent for fallback
                const capturedFlowTimeExtent = flowTimeExtent.slice();

                // Set up callback to sync zoom indicator when overview resolution changes
                // The callback receives the time range directly from the overview loader
                adaptiveOverviewLoader.onResolutionChange = (newResolution, oldResolution, timeInfo) => {
                    console.log(`[Resolution Sync] Overview resolution changed: ${oldResolution} → ${newResolution}`, timeInfo);
                    const mappedRes = OVERVIEW_TO_PACKET_RESOLUTION[newResolution];
                    if (mappedRes && FETCH_RES_BY_NAME[mappedRes]) {
                        // Get visible range from timeInfo, or compute from timeStart/timeEnd
                        let visibleRangeUs = 0;
                        if (timeInfo) {
                            visibleRangeUs = timeInfo.timeRangeUs || (timeInfo.timeEnd - timeInfo.timeStart) || 0;
                        }
                        // Fallback to xScale, state.timearcs.overviewTimeExtent, or flow extent
                        if (visibleRangeUs <= 0 && xScale) {
                            try {
                                const domain = xScale.domain();
                                visibleRangeUs = domain[1] - domain[0];
                            } catch(e) { logCatchError('xScaleDomainRead', e); }
                        }
                        if (visibleRangeUs <= 0 && state.timearcs.overviewTimeExtent) {
                            visibleRangeUs = state.timearcs.overviewTimeExtent[1] - state.timearcs.overviewTimeExtent[0];
                        }
                        if (visibleRangeUs <= 0) {
                            visibleRangeUs = capturedFlowTimeExtent[1] - capturedFlowTimeExtent[0];
                        }

                        updateZoomIndicator(visibleRangeUs, mappedRes);
                        console.log(`[Resolution Sync] Updated packets view to: ${mappedRes}, range=${(visibleRangeUs/60_000_000).toFixed(1)} min`);
                    }
                };
            }
        } catch (err) {
            console.log(`[loadFlowsFromPath] No multi-resolution index found:`, err.message);
        }

        // Dispatch flowDataLoaded event with basePath for flow detail loading
        const event = new CustomEvent('flowDataLoaded', {
            detail: {
                manifest: manifest,
                totalFlows: totalFlows,
                timeExtent: flowTimeExtent,
                format: format,
                basePath: basePath
            }
        });
        document.dispatchEvent(event);

        // Update folder info display
        const folderInfo = document.getElementById('folderInfo');
        if (folderInfo) {
            folderInfo.innerHTML = `<span style="color: #28a745;">Flow data: ${totalFlows.toLocaleString()} flows</span>`;
        }

        console.log(`[loadFlowsFromPath] Flow data loaded successfully`);
        return { manifest, totalFlows, flowTimeExtent };

    } catch (err) {
        console.error('[loadFlowsFromPath] Error loading flow data:', err);
        throw err;
    }
}

/** Parse pre-binned CSV for coarse resolutions - thin wrapper for backwards compatibility */
function parseSecondsCSV(csvText, resolution = 'seconds') {
    const binSizeMap = {
        'hours': 3_600_000_000,
        'minutes': 60_000_000,
        '10s': 10_000_000,
        'seconds': 1_000_000
    };
    return parsePacketCSV(csvText, {
        // bin_start / bin_end intentionally omitted — binStart/binEnd/binCenter
        // are derived from `timestamp` + binSize inside parsePacketCSV.
        numericFields: ['timestamp', 'count', 'total_bytes'],
        binned: true,
        binSize: binSizeMap[resolution] || 1_000_000,
        resolution,
        progressInterval: 50000
    });
}

/**
 * Convert flag_type string back to flags integer for compatibility
 */
function flagTypeToFlags(flagType) {
    const flagMap = {
        'SYN': 0x02,
        'SYN+ACK': 0x12,
        'ACK': 0x10,
        'FIN': 0x01,
        'FIN+ACK': 0x11,
        'RST': 0x04,
        'RST+ACK': 0x14,
        'PSH': 0x08,
        'PSH+ACK': 0x18,
        'URG': 0x20,
        'OTHER': 0
    };
    return flagMap[flagType] || 0;
}

/**
 * Extract unique IPs from packet data
 */
function extractUniqueIPsFromPackets(packets) {
    const ips = new Set();
    for (const p of packets) {
        if (p.src_ip) ips.add(p.src_ip);
        if (p.dst_ip) ips.add(p.dst_ip);
    }
    return Array.from(ips).sort();
}

// Set the global loadFromPath reference now that the function is defined
window.loadFromPath = loadFromPath;

// Export functions for dynamic loading
export { init, cleanup, loadFromPath };

