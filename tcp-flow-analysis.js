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
import { arcPathGenerator, linkArc } from './src/rendering/arcPath.js';
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
import { ForceNetworkLayout } from './src/layout/force_network.js';
import { tryLoadFlowList, getFlowListLoader } from './src/data/flow-list-loader-tfa.js';
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
// Click-to-toggle visibility for the sidebar legend (#flagStats). Separate sets
// because Flows and Packets share the same DOM container but encode different
// keys: Flow legend uses closeType strings (graceful/abortive/open/incomplete/
// invalid sub-reasons); Packet legend uses flag-type strings (SYN/FIN/ACK/...).
const hiddenFlowLegendTypes = new Set();
const hiddenFlagLegendTypes = new Set();
function isFlowItemHiddenByLegend(d) {
    if (hiddenFlowLegendTypes.size === 0) return false;
    const ct = d && d.closeType;
    if (!ct) return false;
    if (hiddenFlowLegendTypes.has(ct)) return true;
    if (ct === 'invalid' && d.invalidReason && hiddenFlowLegendTypes.has(d.invalidReason)) return true;
    return false;
}
function isPacketItemHiddenByLegend(d) {
    if (hiddenFlagLegendTypes.size === 0) return false;
    let ft = d && (d.flagType || d.flag_type);
    if (!ft) { try { ft = getFlagType(d); } catch (e) { ft = null; } }
    if (!ft) return false;
    if (hiddenFlagLegendTypes.has(ft)) return true;
    if (!flagColors[ft] && hiddenFlagLegendTypes.has('OTHER')) return true;
    return false;
}
// Cache for IP filtered packet subsets (key: sorted IP list)
const filterCache = new Map();

// Cache for full-domain binned result to make Reset View fast (state.data.version moved to state.data)
let fullDomainBinsCache = { version: -1, data: [], binSize: null, sorted: false };
let _flowOnlyIPStats = null;
let _flowOnlyBasePath = null;
let _flowOnlyAllIPs = null;
let _flowOnlyRawTimeExtent = null;
let _flowOnlyAIOrderLive = null;     // computed from binnedData
let _flowOnlyFiedlerOrderLive = null; // spectral seriation, recomputed per filter
let _flowOnlyRegionClusterOrderLive = null; // region-membership clustering, recomputed per filter / region change
const REGION_CLUSTER_ROW_GAP = 4;     // px per region-member row in region_cluster mode (tunable)
const REGION_CLUSTER_BLOCK_GAP = 16;  // px blank gap between region blocks (tunable)
let _regionClusterBlockRanges = new Map(); // regionIndex -> {y0,y1} of its own contiguous block (region_cluster layout only)
// Region clustering as a secondary order (see _computeClusteredOrder). Owner map
// is written when the "Group rows by AI region" checkbox produces a clustered
// order, and read by _assignFlowOnlyRowPositions so order + block layout agree.
let _clusteredOwnerByIP = new Map();  // ip -> _regionBlockKey(region)
let _clusteredSharedByIP = new Map(); // shared responder ip -> Set<region block key> of all regions that share it
let _clusteringActive = false;        // true while the active row order is region-clustered
let _showInitiatorsOnly = false;

// ── Ordering-cache persistence state ──────────────────────────────────────
let _orderingFileHandle = null;           // FSA handle (from IndexedDB), cached
let _orderingDiskLoadedForId = null;      // datasetId the in-memory disk cache was loaded for
let _orderingFullOrders = { ai_live: null, fiedler: null, region_cluster: null, region_cluster_sig: null }; // full/default order arrays for current dataset
let _orderingFileWriteInFlight = false;
let _orderingFileWriteQueued = false;
const _ORDERING_CACHE_FILE = './ordering-cache.json';

// ── Magnifier disk-cache (Part B of precompute-magnifier-regions) ──────────
// Set to null on any load failure → all lookups silently fall through to live
// streaming.  Populated by _magLoadManifest() at flow-only chart init.
let _magCache = null;   // { manifest, byWindowKey: Map<key, manifestEntry>, byFullKey: Map<key, manifestEntry> }
// When set, defer hiding the load-progress bar until the first chart render
// finishes (in _updateIPFilterImpl). Clears itself after one use.
let _progressKeepOpenForRender = false;
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
        showFlowThreading: true, // Auto-draw flow threading arcs at raw resolution
        hideGtPairs: false       // Pair-level filter: hide items whose (initiator,responder) matches a GT pair
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
    if (!binned || binned.length === 0) return binned;

    // Nested Map structure groupsByIp[src_ip][t][ft] -> group.
    // Avoids per-item string-key allocation (was `${src_ip}|${t}|${yPos}|${ft}`
    // — millions of strings on large datasets). yPos isn't yet computed on flow
    // bin items so it didn't contribute uniqueness; src_ip is the outer Map key
    // which keeps groups for different IPs separated.
    const pass = [];
    const groupsByIp = new Map();
    let anyCollapsed = false;

    for (let i = 0; i < binned.length; i++) {
        const d = binned[i];
        const ip = d.src_ip;
        if (!ip || !collapsedIPs.has(ip)) {
            pass.push(d);
            continue;
        }
        anyCollapsed = true;

        const t = Number.isFinite(d.binCenter) ? Math.floor(d.binCenter)
            : (Number.isFinite(d.binTimestamp) ? Math.floor(d.binTimestamp) : Math.floor(d.timestamp));
        const ft = d.flagType || 'OTHER';

        let byT = groupsByIp.get(ip);
        if (!byT) { byT = new Map(); groupsByIp.set(ip, byT); }
        let byFt = byT.get(t);
        if (!byFt) { byFt = new Map(); byT.set(t, byFt); }
        let g = byFt.get(ft);
        if (!g) {
            // Spread happens once per group (groups << items), not per item.
            g = {
                ...d,
                count: 0,
                totalBytes: 0,
                ipPairKey: '__collapsed__',
                originalPackets: undefined,
                ipPairs: undefined,
                _seenDsts: undefined
            };
            byFt.set(ft, g);
        }
        g.count += (d.count || 1);
        const tb = d.totalBytes;
        if (tb) g.totalBytes += tb;

        const op = d.originalPackets;
        if (op && op.length) {
            if (!g.originalPackets) g.originalPackets = [];
            const dst = g.originalPackets;
            for (let j = 0; j < op.length; j++) dst.push(op[j]);
        }

        // Within a group, src_ip is fixed (it's the outer key) — so dst_ip
        // uniqueness is sufficient for deduping pairs. This eliminates the
        // makeIpPairKey() call per item (was 146ms in the profile).
        const dstIp = d.dst_ip;
        if (dstIp) {
            if (!g._seenDsts) { g._seenDsts = new Set(); g.ipPairs = []; }
            if (!g._seenDsts.has(dstIp)) {
                g._seenDsts.add(dstIp);
                g.ipPairs.push({ src_ip: ip, dst_ip: dstIp, count: d.count || 1 });
            }
        }
    }

    if (!anyCollapsed) return binned;

    for (const byT of groupsByIp.values()) {
        for (const byFt of byT.values()) {
            for (const g of byFt.values()) {
                g._seenDsts = undefined;  // drop reference; GC reclaims the Set
                pass.push(g);
            }
        }
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

    if (hiddenFlowLegendTypes.size > 0) {
        flowData = flowData.filter(d => !isFlowItemHiddenByLegend(d));
        if (flowData.length === 0) {
            if (layer) layer.selectAll('.flow-lozenge').remove();
            if (mainWebGLRenderer) {
                try { mainWebGLRenderer.setData([], new Map(), () => 0, {}); mainWebGLRenderer.render(xScale, 0, 0); } catch(e) {}
            }
            return;
        }
    }

    // Filter to IPs that have a layout position — prevents items for non-selected IPs
    // from falling through with yPosWithOffset=0 and rendering at the chart top.
    if (state.layout.ipPositions && state.layout.ipPositions.size > 0) {
        flowData = flowData.filter(d => {
            const ini = d.initiator || d.src_ip;
            const res = d.responder || d.dst_ip;
            if (!state.layout.ipPositions.has(ini)) return false;
            if (_hiddenIPs.has(ini) || (res && _hiddenIPs.has(res))) return false;
            return true;
        });
        if (flowData.length === 0) {
            if (layer) layer.selectAll('.flow-lozenge').remove();
            if (mainWebGLRenderer) {
                try { mainWebGLRenderer.setData([], new Map(), () => 0, {}); mainWebGLRenderer.render(xScale, 0, 0); } catch(e) {}
            }
            return;
        }
    }

    const chartContainer = document.getElementById('chart-container');
    const scrollTop = chartContainer ? chartContainer.scrollTop : 0;
    const viewportH = chartContainer ? chartContainer.clientHeight : 800;

    // Alias flow fields in-place so collapseSubRowsBins can read them.
    // The original spread (`{...d, src_ip, dst_ip, flagType}`) allocated a fresh
    // shallow-clone per item every call — millions of objects for large datasets,
    // gigabytes of churn. Items are idempotent: assigning the alias fields once
    // is safe across re-renders and shared with the magnifier (which still reads
    // d.initiator/d.responder).
    for (let i = 0; i < flowData.length; i++) {
        const d = flowData[i];
        if (d.src_ip === undefined) d.src_ip = d.initiator;
        if (d.dst_ip === undefined) d.dst_ip = d.responder;
        if (d.flagType === undefined) d.flagType = d.closeType;
    }
    const data = collapseSubRowsBins(flowData, state.layout.collapsedIPs);

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

// Lightweight packet loader for flow-only mode. Skips the heavy packet-mode
// init path (loadFromPath builds 19k IP checkboxes and runs visualizeTimeArcs
// which OOMs on this dataset). Just decodes the chosen resolution's parquet
// chunks and stashes the bins in state.data.full.
async function loadPacketsForFlowOnly(basePath = DEFAULT_DATA_PATH) {
    console.log(`[Packets→WebGL] Loading manifest from ${basePath}`);
    const manifestResp = await fetch(`${basePath}/manifest.json`);
    if (!manifestResp.ok) throw new Error(`manifest: HTTP ${manifestResp.status}`);
    const manifest = await manifestResp.json();

    const fullRangeUs = manifest.time_range.end - manifest.time_range.start;
    const initialResolution = getResolutionForVisibleRange(fullRangeUs);
    console.log(`[Packets→WebGL] Range ${(fullRangeUs / 60_000_000).toFixed(1)} min → resolution: ${initialResolution}`);

    const packets = await loadResolutionPackets(basePath, initialResolution);
    state.data.full = packets;
    state.data.isPreBinned = true;
    console.log(`[Packets→WebGL] Loaded ${packets.length} ${initialResolution}-level bins`);
    return packets;
}

// Render packet bins as circles via the same WebGL canvas flow mode uses.
// Circles share the lozenge regl draw command — the circle SDF is selected
// via setMarkType('circle'), which makes `height` encode the diameter and
// timeWidth is ignored so the mark is always centred on the bin start.
function renderPacketsViaWebGL() {
    if (!mainWebGLRenderer) {
        console.warn('[Packets→WebGL] mainWebGLRenderer not initialized');
        return;
    }
    const allPackets = state.data.full || [];
    const packets = hiddenFlagLegendTypes.size > 0
        ? allPackets.filter(p => !isPacketItemHiddenByLegend(p))
        : allPackets;
    if (packets.length === 0) {
        if (mainWebGLRenderer) {
            try { mainWebGLRenderer.setData([], new Map(), () => 0, { skipHitIndex: true }); mainWebGLRenderer.render(xScale, 0, 0); } catch(e) {}
        }
        return;
    }

    const colorMap = new Map();
    for (const [k, v] of Object.entries(flagColors)) colorMap.set(k, v);

    // Find max count for radius scale. We avoid building an items[] array of
    // 8M aliased objects (peak heap >1 GB); WebGLFlowRenderer.setData reads
    // src_ip directly when initiator is missing, so the original parquet
    // rows are passed through verbatim.
    let maxCount = 1;
    for (let i = 0; i < packets.length; i++) {
        const p = packets[i];
        // WebGLFlowRenderer._getColorString reads d.closeType for the colorMap
        // lookup; mirror flagType into closeType so flag colors apply.
        if (!p.closeType) p.closeType = p.flagType;
        const c = p.count;
        if (c && c > maxCount) maxCount = c;
    }

    // For circle marks the `hScale(count)` value is interpreted as diameter,
    // so we clamp it to the [2*RADIUS_MIN, 2*RADIUS_MAX] range used by the
    // SVG packet view. closeType (used for color) falls back to flagType via
    // _getColorString, so re-aliasing is unnecessary.
    const rScale = d3.scaleSqrt()
        .domain([1, Math.max(1, maxCount)])
        .range([RADIUS_MIN, RADIUS_MAX]);
    const hScale = (count) => 2 * rScale(count);

    mainWebGLRenderer.setMarkType('circle');
    mainWebGLRenderer.setData(packets, colorMap, hScale, {
        minHeight: 2 * RADIUS_MIN,
        maxHeight: 2 * RADIUS_MAX,
        skipHitIndex: true
    });
    const cont = document.getElementById('chart-container');
    const scrollTop = cont ? cont.scrollTop : 0;
    const viewportH = cont ? cont.clientHeight : 800;
    mainWebGLRenderer.render(xScale, scrollTop, viewportH);
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

// Ground-truth pair filter — time-aware, wildcard-aware.

const GT_WILDCARD_IP = '255.255.255.255';
// Match the +59s end pad used when drawing GT boxes (src/groundTruth/groundTruth.js).
// Without this, flows that fall inside the visible GT box but after the raw stop
// time slip through the filter.
const GT_END_PAD_US = 59 * 1_000_000;

// Build lookup structures from ground-truth events:
// - pairRanges:    Map<canonicalPairKey, Array<[startUs, endUs]>>  for "both endpoints specific"
//                  (canonical = alphabetically sorted "A<->B"). Used by _applyGtPairFilter.
// - ipRanges:      Map<specificIP,       Array<[startUs, endUs]>>  for "one endpoint is wildcard".
//                  Used by _applyGtPairFilter's both-side hide rule. Both wildcard → skipped.
// - directedPair:  Map<"src|dst", Array<[startUs, endUs]>>  for "both endpoints specific",
//                  keyed by the GT's actual (source, destination) — used by matchesGt to
//                  require flow.src==evt.source AND flow.dst==evt.destination.
// - srcOnly:       Map<srcIP, Array<[startUs, endUs]>>  for GTs with dst=wildcard. Match a
//                  flow when flow.src == srcIP (destination is the wildcard side, ignored).
// - dstOnly:       Map<dstIP, Array<[startUs, endUs]>>  for GTs with src=wildcard. Match a
//                  flow when flow.dst == dstIP (source is the wildcard side, ignored).
function _buildGtRangeIndex() {
    const pairRanges = new Map();
    const ipRanges = new Map();
    const directedPair = new Map();
    const srcOnly = new Map();
    const dstOnly = new Map();
    const events = state.flows && Array.isArray(state.flows.groundTruth)
        ? state.flows.groundTruth : [];
    const pushRange = (map, key, range) => {
        let arr = map.get(key);
        if (!arr) { arr = []; map.set(key, arr); }
        arr.push(range);
    };
    for (const e of events) {
        if (!e.source || !e.destination) continue;
        const start = Number(e.startTimeMicroseconds);
        const rawEnd = Number(e.stopTimeMicroseconds);
        if (!Number.isFinite(start) || !Number.isFinite(rawEnd) || rawEnd < start) continue;
        const end = rawEnd + GT_END_PAD_US;
        const srcWild = e.source === GT_WILDCARD_IP;
        const dstWild = e.destination === GT_WILDCARD_IP;
        if (srcWild && dstWild) continue;
        if (!srcWild && !dstWild) {
            const [a, b] = [e.source, e.destination].sort();
            pushRange(pairRanges, `${a}<->${b}`, [start, end]);
            pushRange(directedPair, `${e.source}|${e.destination}`, [start, end]);
        } else {
            const specificIP = srcWild ? e.destination : e.source;
            pushRange(ipRanges, specificIP, [start, end]);
            if (dstWild) pushRange(srcOnly, e.source, [start, end]);
            else pushRange(dstOnly, e.destination, [start, end]);
        }
    }
    return { pairRanges, ipRanges, directedPair, srcOnly, dstOnly };
}

// True if [s, e] overlaps any range in arr (each range is [start, end]).
function _overlapsAny(arr, s, e) {
    if (!arr) return false;
    for (let i = 0; i < arr.length; i++) {
        const r = arr[i];
        if (s <= r[1] && e >= r[0]) return true;
    }
    return false;
}

// Filter state.flowView.binnedData based on the hideGtPairs toggle.
// Time-aware: only hides flow items whose [binStart, binEnd] overlaps a GT event
// window for a matching pair. Wildcard expansion: GT events with 255.255.255.255
// on one side hide any flow whose other endpoint is the specific IP during the
// window. Stores the unfiltered original at state.flowView.binnedDataAll so the
// toggle can be reversed without re-fetching. Idempotent.
function _applyGtPairFilter() {
    if (!state.flowView) return;
    const src = state.flowView.binnedDataAll || state.flowView.binnedData;
    if (!Array.isArray(src)) return;

    if (state.ui.hideGtPairs) {
        const { pairRanges, ipRanges } = _buildGtRangeIndex();
        if (pairRanges.size === 0 && ipRanges.size === 0) return;
        if (!state.flowView.binnedDataAll) state.flowView.binnedDataAll = src;
        state.flowView.binnedData = src.filter(item => {
            const s = item.binStart, e = item.binEnd;
            if (_overlapsAny(pairRanges.get(item.pairKey), s, e)) return false;
            if (_overlapsAny(ipRanges.get(item.initiator), s, e)) return false;
            if (_overlapsAny(ipRanges.get(item.responder), s, e)) return false;
            return true;
        });
    } else {
        if (state.flowView.binnedDataAll) {
            state.flowView.binnedData = state.flowView.binnedDataAll;
            state.flowView.binnedDataAll = null;
        }
    }
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
        state.flowView.binnedDataAll = null;
        _applyGtPairFilter();
        _flowOnlyAIOrderLive = null;
        _flowOnlyFiedlerOrderLive = null;
        _flowOnlyRegionClusterOrderLive = null;
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
    state.flowView.binnedDataAll = null;
    _applyGtPairFilter();
    _flowOnlyAIOrderLive = null;
    _flowOnlyFiedlerOrderLive = null;
    _flowOnlyRegionClusterOrderLive = null;
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
    // Page-load progress was deferred for the first render — FlowZoomManager
    // has now delivered data and the zoom handler has re-rendered. Wait two
    // RAFs so the WebGL frame commits before hiding.
    if (_progressKeepOpenForRender) {
        _progressKeepOpenForRender = false;
        try { sbUpdateCsvProgress(1.0, 'Ready!'); } catch (e) {}
        requestAnimationFrame(() => requestAnimationFrame(() => {
            try { sbHideCsvProgress(); } catch (e) {}
        }));
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
        // Switch the WebGL marks back to lozenges (state.layout is shared
        // between modes — the row-order dropdown mutates it directly).
        if (mainWebGLRenderer) mainWebGLRenderer.setMarkType('lozenge');
        // Trigger zoom handler — FlowZoomManager handles all data loading
        const xDomain = window.__arc_x_domain__;
        if (flowZoomManager && xDomain) {
            applyZoomDomain(xDomain, 'program');
        } else {
            // Fallback: load binned data for initial render
            await loadFlowViewData();
            renderMarksForLayerLocal(fullDomainLayer, null, null);
            // Sync render path — close deferred progress here.
            if (_progressKeepOpenForRender) {
                _progressKeepOpenForRender = false;
                try { sbUpdateCsvProgress(1.0, 'Ready!'); } catch (e) {}
                requestAnimationFrame(() => requestAnimationFrame(() => {
                    try { sbHideCsvProgress(); } catch (e) {}
                }));
            }
        }
    } else {
        // Clear lozenge sub-row label remnants (rects are WebGL — no SVG to remove)
        if (fullDomainLayer) fullDomainLayer.selectAll('.sub-row-ip-label').remove();
        if (dynamicLayer) dynamicLayer.selectAll('.sub-row-ip-label').remove();

        // Lazy-load packet data the first time the user switches to packet view.
        // Flow mode is the default startup, so the packet manifest under
        // DEFAULT_DATA_PATH (packets_data/decoded_set1_90min_packets) is fetched
        // on demand here, never at init. Use the slim loader instead of the
        // full loadFromPath()  — that path builds 19k IP checkboxes and runs
        // visualizeTimeArcs(), which OOMs on this dataset.
        if (!state.data.full || state.data.full.length === 0) {
            console.log('[ViewMode] Packet data not loaded yet — loading now...');
            try {
                await loadPacketsForFlowOnly(DEFAULT_DATA_PATH);
            } catch (e) {
                console.error('[ViewMode] Packet load failed:', e);
                return;
            }
        }

        // Render packet bins through the same WebGL canvas used by flow mode.
        renderPacketsViaWebGL();
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
        // Restore original flag legend. Flow-only mode uses state.data.full
        // (pre-binned packets from loadPacketsForFlowOnly); state.data.filtered
        // is never populated here, so feed flag stats from .full instead and
        // unconditionally replace the flow-type HTML so the legend actually
        // swaps back when toggling Flows → Packets.
        if (flagStatsEl) {
            const label = flagStatsEl.previousElementSibling;
            if (label && label.tagName === 'LABEL') label.textContent = flagStatsEl.getAttribute('data-original-label') || 'TCP Flags';
            const packetsForStats = (state.data.filtered && state.data.filtered.length > 0)
                ? state.data.filtered
                : (state.data.full || []);
            if (typeof updateFlagStats === 'function') {
                updateFlagStats(packetsForStats);
            } else {
                flagStatsEl.innerHTML = '<div style="color: #666;">No data to display</div>';
            }
        }
        if (sizeLegendEl) {
            sizeLegendEl.previousElementSibling.textContent = 'Packet Count';
            // Sync globalMaxBinCount from packet bins so the size legend reflects
            // the actual scale used by renderPacketsViaWebGL.
            const pkts = state.data.full || [];
            if (pkts.length > 0) {
                let maxC = 1;
                for (let i = 0; i < pkts.length; i++) {
                    const c = pkts[i].count;
                    if (c && c > maxC) maxC = c;
                }
                globalMaxBinCount = Math.max(globalMaxBinCount, maxC);
            }
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

// Apply pointer/opacity styling to legend items in #flagStats based on the
// current hidden sets. Runs whenever the legend HTML is rebuilt (either by
// our own buildFlowTypeLegendHTML, by sbUpdateFlagStats from control-panel.js,
// or by ip-filter-controller.js calling updateFlagStats).
function applyLegendItemStyling() {
    const root = document.getElementById('flagStats');
    if (!root) return;
    root.querySelectorAll('.flow-legend-item[data-flow-type]').forEach(el => {
        const t = el.getAttribute('data-flow-type');
        el.style.cursor = 'pointer';
        el.style.userSelect = 'none';
        el.style.opacity = hiddenFlowLegendTypes.has(t) ? '0.45' : '1';
    });
    root.querySelectorAll('[data-flag]').forEach(el => {
        const t = el.getAttribute('data-flag');
        el.style.cursor = 'pointer';
        el.style.userSelect = 'none';
        el.style.opacity = hiddenFlagLegendTypes.has(t) ? '0.45' : '1';
    });
}

// Re-render the active view after a legend toggle changes the hidden set.
function rerenderAfterLegendToggle() {
    if (state.ui.renderMode === 'flows') {
        try {
            if (fullDomainLayer) renderLozengesWithOptions(fullDomainLayer, state.flowView.binnedData);
        } catch (e) { console.warn('[Legend] flow re-render failed', e); }
    } else {
        try { renderPacketsViaWebGL(); } catch (e) { console.warn('[Legend] packet re-render failed', e); }
    }
}

// Wire one delegated click handler + a MutationObserver to keep styling in
// sync across the various code paths that rebuild #flagStats.innerHTML.
function initLegendInteractivity() {
    const root = document.getElementById('flagStats');
    if (!root || root.__legendWired) return;
    root.__legendWired = true;
    root.addEventListener('click', async (e) => {
        const flowEl = e.target.closest('.flow-legend-item[data-flow-type]');
        if (flowEl && root.contains(flowEl)) {
            const t = flowEl.getAttribute('data-flow-type');
            if (hiddenFlowLegendTypes.has(t)) hiddenFlowLegendTypes.delete(t);
            else hiddenFlowLegendTypes.add(t);
            flowEl.style.opacity = hiddenFlowLegendTypes.has(t) ? '0.45' : '1';
            // Flow-only mode: drop now-empty rows, recompute AI order if active,
            // and sort by the current row-order mode (or visible count for the
            // non-AI fallback). Falls through to rerender for non-flow-only.
            const relaidOut = await _relayoutFlowOnlyForCloseTypeFilter();
            if (!relaidOut) rerenderAfterLegendToggle();
            _refreshAllMagnifierPanels();
            return;
        }
        const flagEl = e.target.closest('[data-flag]');
        if (flagEl && root.contains(flagEl)) {
            const t = flagEl.getAttribute('data-flag');
            if (hiddenFlagLegendTypes.has(t)) hiddenFlagLegendTypes.delete(t);
            else hiddenFlagLegendTypes.add(t);
            flagEl.style.opacity = hiddenFlagLegendTypes.has(t) ? '0.45' : '1';
            rerenderAfterLegendToggle();
            return;
        }
    });
    // Re-apply styling whenever sidebar/control-panel.js rewrites innerHTML.
    try {
        const obs = new MutationObserver(() => applyLegendItemStyling());
        obs.observe(root, { childList: true, subtree: true });
    } catch (e) { /* MutationObserver unsupported — rely on inline styling */ }
}

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
        const disabled = hiddenFlowLegendTypes.has(name);
        html += `<div class="flow-legend-item" data-flow-type="${name}" style="display: flex; align-items: center; margin-bottom: 2px; cursor: pointer; user-select: none; opacity: ${disabled ? '0.45' : '1'};">
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
            // SVG path (no-op in flow-only mode where mainGroup is null)
            drawGroundTruthBoxes(selectedIPs);
            // WebGL path: source-IP-only ground truth covering on the overlay canvas.
            applyWebGLGroundTruth();
            _refreshAllMagnifierPanels();
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

    // "Remove GT IPs" button (id retained for HTML compat) — toggles a pair-level
    // flow filter that hides items whose (initiator, responder) matches any
    // ground-truth (source, destination) pair, bidirectionally. Does NOT modify
    // IP checkboxes — victim and non-GT IPs remain visible, including any flows
    // they have with other non-GT peers.
    const removeGtBtn = document.getElementById('removeGtIPs');
    if (removeGtBtn) {
        const updateLabel = () => {
            removeGtBtn.textContent = state.ui.hideGtPairs ? 'Show GT pairs' : 'Hide GT pairs';
        };
        updateLabel();
        removeGtBtn.addEventListener('click', () => {
            const events = state.flows && Array.isArray(state.flows.groundTruth)
                ? state.flows.groundTruth : [];
            if (!state.ui.hideGtPairs && events.length === 0) {
                console.warn('[GT] No ground truth events loaded — nothing to filter');
                return;
            }
            state.ui.hideGtPairs = !state.ui.hideGtPairs;
            updateLabel();
            _applyGtPairFilter();

            // Re-render the flow-only view from the (now-filtered) binnedData.
            try {
                if (typeof renderMarksForLayerLocal === 'function' && fullDomainLayer && state.flowView.binnedData) {
                    renderMarksForLayerLocal(fullDomainLayer, state.flowView.binnedData);
                }
                if (mainWebGLRenderer) {
                    const chartContainerEl = document.getElementById('chart-container');
                    if (chartContainerEl) {
                        mainWebGLRenderer.render(xScale, chartContainerEl.scrollTop, chartContainerEl.clientHeight);
                    }
                }
            } catch (e) { console.warn('[GT] Re-render after toggle failed:', e); }

            const total = state.flowView.binnedDataAll
                ? state.flowView.binnedDataAll.length : (state.flowView.binnedData?.length || 0);
            const shown = state.flowView.binnedData?.length || 0;
            console.log(`[GT] Pair filter ${state.ui.hideGtPairs ? 'ON' : 'OFF'}: showing ${shown}/${total} items`);
        });
    }
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

// Visible band height for ground-truth covering in flow-only mode. The data
// rowGap is ROW_GAP_CRAMPED (~0.1px) here, so we use a fixed pixel height
// so source-IP bands are visible. With ~19k IPs at 0.1px spacing, a 1–2px
// band covers a handful of neighbouring rows; widening past that turns the
// overlay into a wash. Keep small.
const FLOW_ONLY_GT_BAND_PX = 2;

// Per-instance monkey-patch of WebGLFlowRenderer._drawOverlay so we can paint
// ground-truth bands at FLOW_ONLY_GT_BAND_PX height instead of rowGap. We
// don't touch the shared module — the original method is still on the
// prototype for other consumers (TimeArcs, tcp-analysis.js).
function installFlowOnlyGroundTruthOverlay(renderer) {
    if (!renderer || renderer.__flowOnlyGtPatched) return;
    renderer.__flowOnlyGtPatched = true;
    const origDrawOverlay = renderer._drawOverlay.bind(renderer);
    renderer._drawOverlay = function(xScale, scrollTop, viewportHeight, dpr) {
        // Suppress the renderer's own GT pass (which would paint at rowGap≈0.1px).
        const savedShow = this.showGroundTruth;
        this.showGroundTruth = false;
        origDrawOverlay(xScale, scrollTop, viewportHeight, dpr);
        this.showGroundTruth = savedShow;

        if (!savedShow || !this.gtBySourceIP || !xScale) return;
        const ctx = this.overlayCtx;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        const marginTop = this.margin.top;
        const marginLeft = this.margin.left;
        const bandH = FLOW_ONLY_GT_BAND_PX;
        const halfBand = bandH / 2;
        const yMin = scrollTop - marginTop - halfBand;
        const yMax = scrollTop - marginTop + viewportHeight + halfBand;
        ctx.globalAlpha = 0.6;
        for (const ip of this.ipOrder) {
            const yPos = this.ipPositions && this.ipPositions.get(ip);
            if (yPos === undefined || yPos < yMin || yPos > yMax) continue;
            const events = this.gtBySourceIP.get(ip);
            if (!events) continue;
            const screenY = yPos + marginTop - scrollTop;
            for (const evt of events) {
                const x1 = xScale(evt.startTimeMicroseconds);
                const x2 = xScale(evt.stopTimeMicroseconds || evt.startTimeMicroseconds);
                const x = Math.min(x1, x2) + marginLeft;
                const w = Math.max(2, Math.abs(x2 - x1));
                ctx.fillStyle = (this.eventColors && this.eventColors[evt.eventType]) || '#888';
                ctx.fillRect(x, screenY - halfBand, w, bandH);
            }
        }
        ctx.globalAlpha = 1.0;
    };
}

// WebGL ground-truth covering for flow-only mode. The shared SVG path
// (drawGroundTruthBoxes) early-returns when mainGroup is null, so this
// function is the only thing painting GT in flow-only mode.
//
// Coverage rule: per-side wildcard-aware. WebGLFlowRenderer.setGroundTruth
// groups each event into gtBySourceIP[evt.source] when source isn't wildcard
// AND into gtByDestIP[evt.destination] when destination isn't wildcard.
// _drawOverlay paints a band on a row whenever that row's IP appears as a
// specific side — so a both-specific event paints on both source and
// destination rows, a dst=wildcard event paints only on the source row,
// and a src=wildcard event paints only on the destination row.
function applyWebGLGroundTruth() {
    if (!mainWebGLRenderer
        || typeof mainWebGLRenderer.setGroundTruth !== 'function'
        || typeof mainWebGLRenderer.setShowGroundTruth !== 'function') {
        return;
    }
    const events = Array.isArray(state.flows.groundTruth) ? state.flows.groundTruth : [];
    mainWebGLRenderer.setGroundTruth(events, eventColors || {});
    mainWebGLRenderer.setShowGroundTruth(!!state.ui.showGroundTruth);
    // Repaint the overlay (and main marks) at the current scroll position.
    const cont = document.getElementById('chart-container');
    const scrollTop = cont ? cont.scrollTop : 0;
    const viewportH = cont ? cont.clientHeight : 800;
    if (xScale) {
        try { mainWebGLRenderer.render(xScale, scrollTop, viewportH); }
        catch (e) { console.warn('[GroundTruth] WebGL re-render failed', e); }
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

// Coalescing debounce: rapid checkbox toggles (especially Select-All / Clear-All)
// fire many calls in quick succession. We collapse them into a single trailing
// run with a short delay. The latest opts win; all callers' awaited Promises
// resolve when the coalesced run finishes.
let _ipFilterDebounceTimer = null;
let _ipFilterDebouncePending = null;
const _IP_FILTER_DEBOUNCE_MS = 30;
function updateIPFilter(opts = {}) {
    if (_ipFilterDebouncePending) {
        _ipFilterDebouncePending.opts = opts;
    } else {
        let resolve, reject;
        const promise = new Promise((res, rej) => { resolve = res; reject = rej; });
        _ipFilterDebouncePending = { opts, promise, resolve, reject };
    }
    if (_ipFilterDebounceTimer) clearTimeout(_ipFilterDebounceTimer);
    _ipFilterDebounceTimer = setTimeout(async () => {
        const pending = _ipFilterDebouncePending;
        _ipFilterDebouncePending = null;
        _ipFilterDebounceTimer = null;
        try {
            await _updateIPFilterImpl(pending.opts);
            pending.resolve();
        } catch (e) {
            pending.reject(e);
        }
    }, _IP_FILTER_DEBOUNCE_MS);
    return _ipFilterDebouncePending.promise;
}

async function _updateIPFilterImpl({ fromSearch = false } = {}) {
    // Full pipeline run: treat checkboxes as truth, so session fast-hides are reset.
    _hiddenIPs.clear();
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

    // Flow-only mode: re-init chart layout with the current IP selection so the
    // WebGL view reflects which rows should be visible.
    if (_flowOnlyAllIPs) {
        const checkedIPs = Array.from(
            document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')
        ).map(cb => cb.value);
        if (checkedIPs.length >= 1) {
            const mode = document.getElementById('ipRowOrder')?.value || 'first_seen';
            // Recompute clustering orders against the new visible-IP set
            // before sorting (cached cluster output reflects an older filter).
            if (mode === 'ai_live') await loadAIOrderLive();
            if (mode === 'fiedler') await loadFiedlerOrderLive();
            const sortedSelected = _maybeClusterOrder(sortIPsByMode(checkedIPs, mode));

            // Fast path: when the WebGL renderer is already built and the time
            // range hasn't changed, skip the full re-init (SVG/zoom/WebGL teardown)
            // and just reflow rows. Skip the data refetch when binned data covers
            // all IPs — true for the ≤90-min branch in loadFlowViewData where
            // selectedIPs is overridden to the full IP list.
            const te = _flowOnlyRawTimeExtent || state.data.timeExtent;
            const sameTimeExtent = te && state.data.timeExtent &&
                te[0] === state.data.timeExtent[0] && te[1] === state.data.timeExtent[1];
            const timeRangeUs = state.data.timeExtent
                ? state.data.timeExtent[1] - state.data.timeExtent[0] : 0;
            const dataCoversAllIPs = timeRangeUs > 0 && timeRangeUs <= ALL_IP_PAIRS_TIME_THRESHOLD_US;
            const haveBinnedData = state.flowView.binnedData && state.flowView.binnedData.length > 0;

            const fast = sameTimeExtent && _relayoutFlowOnlyForIPs(sortedSelected);
            if (!fast) {
                _initFlowOnlyChart(sortedSelected, _flowOnlyRawTimeExtent || state.data.timeExtent);
                await loadFlowViewData();
                if (state.flowView.binnedData && state.flowView.binnedData.length > 0) {
                    renderMarksForLayerLocal(fullDomainLayer, state.flowView.binnedData);
                }
            } else if (!(dataCoversAllIPs && haveBinnedData)) {
                // Fast layout succeeded but data isn't reusable — refetch and re-render.
                await loadFlowViewData();
                if (state.flowView.binnedData && state.flowView.binnedData.length > 0) {
                    renderMarksForLayerLocal(fullDomainLayer, state.flowView.binnedData);
                }
            }
        }
    }

    // If in flow view mode, re-trigger zoom handler (FlowZoomManager handles data)
    if (state.ui.renderMode === 'flows') {
        if (flowZoomManager) flowZoomManager.invalidateCache();
        const xDomain = window.__arc_x_domain__;
        if (flowZoomManager && xDomain) {
            applyZoomDomain(xDomain, 'program');
        }
    }

    // If page-load progress was deferred for the first render, close it now
    // that the WebGL view has data and the next paint will display the chart.
    if (_progressKeepOpenForRender) {
        _progressKeepOpenForRender = false;
        try { sbUpdateCsvProgress(1.0, 'Ready!'); } catch (e) {}
        // Two RAFs let the browser commit the new lozenge frame before we hide.
        requestAnimationFrame(() => requestAnimationFrame(() => {
            try { sbHideCsvProgress(); } catch (e) {}
        }));
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

    // Make sidebar legend items clickable (toggles show/hide for their type).
    initLegendInteractivity();

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

        // Push events to the WebGL overlay so source-IP covering is ready
        // the moment the user enables the ground-truth toggle. The renderer
        // groups by source IP internally (gtBySourceIP), so each event paints
        // a row-tall band on the source row only — never on the destination.
        applyWebGLGroundTruth();
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
            try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
            setTimeout(() => _switchToFlowsAfterInit(), 300);
        }).catch(err => {
            console.warn(`Auto-load from TimeArcs path failed: ${err.message}`);
            try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
            loadFromPath(DEFAULT_DATA_PATH).then(() => loadFlowsFromPath(DEFAULT_FLOW_DATA_PATH))
                .then(() => { try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); } })
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
            try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
        });
    }

    const exportBtn = document.getElementById('exportPngBtn');
    if (exportBtn) exportBtn.addEventListener('click', () => {
        exportFlowOnlyAsPNG().catch(e => { console.error('[ExportPNG]', e); alert('PNG export failed: ' + e.message); });
    });
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
    // Progress is closed by _onFlowZoomDataLoaded once FlowZoomManager actually
    // delivers data (the load-and-render is async, so closing here would fire
    // before the chart paints).
}

// Stable per-region key (independent of object identity / array index) so the
// layout-time block range and the draw-time box agree even though region objects
// are re-created on each validation pass.
function _regionBlockKey(r) {
    const ips = Array.isArray(r.ips) ? r.ips : [];
    return (typeof r.tMinUs === 'number' ? r.tMinUs : '') + '|' +
           (r.responder || '') + '|' + (ips.length ? ips[0] : '') + '|' + ips.length;
}

// Assign state.layout.ipPositions / ipRowHeights / ipPairCounts for `orderedIPs`
// and return the final y (caller adds TOP_PAD for height). Default: uniform
// `crampedGap` rows. In region_cluster mode with regions loaded, region-member
// rows get REGION_CLUSTER_ROW_GAP, a REGION_CLUSTER_BLOCK_GAP is inserted between
// region blocks (and once between the region band and the rest), and each region's
// own contiguous block y-range is recorded in _regionClusterBlockRanges so the
// overlay box can wrap just that block. Place-once: each shared IP belongs to the
// earliest region (by tMin) only, matching _computeRegionClusterOrder.
function _assignFlowOnlyRowPositions(orderedIPs, crampedGap) {
    _regionClusterBlockRanges.clear();
    const regions = _anomalyLastRegions;
    const useRegionLayout = _clusteringActive && Array.isArray(regions) && regions.length > 0
        && _clusteredOwnerByIP.size > 0;

    let y = TOP_PAD;

    if (!useRegionLayout) {
        for (const ip of orderedIPs) {
            state.layout.ipPositions.set(ip, y);
            state.layout.ipRowHeights.set(ip, crampedGap);
            state.layout.ipPairCounts.set(ip, 1);
            y += crampedGap;
        }
        return y;
    }

    // Ownership (ip -> region block key) was computed by _computeClusteredOrder,
    // which produced `orderedIPs`. Reuse it so the order and the block grouping
    // agree on which region owns each shared IP.
    const owner = _clusteredOwnerByIP;

    // Walk the (already clustered) order; group contiguous rows by owning region.
    let prevOwner = undefined; // undefined = nothing placed yet; null = in the non-region tail
    for (const ip of orderedIPs) {
        // Shared-responder bridge: a single row that extends every sharing region's box.
        if (_clusteredSharedByIP.has(ip)) {
            state.layout.ipPositions.set(ip, y);
            state.layout.ipRowHeights.set(ip, crampedGap);
            state.layout.ipPairCounts.set(ip, 1);
            for (const k of _clusteredSharedByIP.get(ip)) {
                const rng = _regionClusterBlockRanges.get(k);
                if (!rng) _regionClusterBlockRanges.set(k, { y0: y, y1: y });
                else { rng.y0 = Math.min(rng.y0, y); rng.y1 = Math.max(rng.y1, y); }
            }
            y += crampedGap;
            continue;
        }
        const own = owner.has(ip) ? owner.get(ip) : null;
        if (own !== null) {
            if (own !== prevOwner) {
                if (prevOwner !== undefined && prevOwner !== null) y += REGION_CLUSTER_BLOCK_GAP;
                if (!_regionClusterBlockRanges.has(own)) _regionClusterBlockRanges.set(own, { y0: y, y1: y });
            }
            state.layout.ipPositions.set(ip, y);
            state.layout.ipRowHeights.set(ip, crampedGap);
            state.layout.ipPairCounts.set(ip, 1);
            _regionClusterBlockRanges.get(own).y1 = y;
            y += crampedGap;
            prevOwner = own;
        } else {
            if (prevOwner !== undefined && prevOwner !== null) { y += REGION_CLUSTER_BLOCK_GAP; }
            state.layout.ipPositions.set(ip, y);
            state.layout.ipRowHeights.set(ip, crampedGap);
            state.layout.ipPairCounts.set(ip, 1);
            y += crampedGap;
            prevOwner = null;
        }
    }
    return y;
}

/**
 * Fast path for IP-filter changes: keeps the existing WebGL renderer, SVG layers,
 * zoom handler, and bottom axis; only recomputes row layout, resizes the magnifier
 * overlay, and re-renders. Returns true on success, false if the caller should fall
 * back to the full _initFlowOnlyChart path (e.g. renderer not yet built).
 *
 * Magnifier panels reference IP+time, but their edit-brush rectangles are positioned
 * in row-pixel space — after a reflow those rectangles point at different IPs, so we
 * close all panels here.
 */
function _relayoutFlowOnlyForIPs(selectedIPs) {
    if (!mainWebGLRenderer) return false;
    const chartContainerEl = document.getElementById('chart-container');
    if (!chartContainerEl) return false;
    if (!Array.isArray(selectedIPs) || selectedIPs.length === 0) return false;

    const ROW_GAP_CRAMPED = 0.1;
    const margin = { top: 80, right: 120, bottom: 50, left: 180 };

    state.layout.ipPositions.clear();
    state.layout.ipRowHeights = state.layout.ipRowHeights || new Map();
    state.layout.ipRowHeights.clear();
    state.layout.ipPairCounts = state.layout.ipPairCounts || new Map();
    state.layout.ipPairCounts.clear();

    state.layout.ipOrder = selectedIPs.slice();
    for (const ip of selectedIPs) state.layout.collapsedIPs.add(ip);
    height = _assignFlowOnlyRowPositions(selectedIPs, ROW_GAP_CRAMPED) + TOP_PAD;
    yScale = d3.scaleLinear().domain([TOP_PAD, height]).range([TOP_PAD, height]);

    try {
        mainWebGLRenderer.setLayout(state.layout.ipOrder, state.layout.ipPositions, ROW_GAP_CRAMPED);
    } catch (e) {
        console.warn('[FlowOnly] setLayout failed in fast relayout, falling back', e);
        return false;
    }

    // Remove edit-brush <g> elements (they live on the overlay SVG being rebuilt).
    // Do NOT remove panel DOM — _initMagnifierBrush saves and restores them.
    for (const entry of _magnifierBrushes.values()) {
        try { entry.editG && entry.editG.remove && entry.editG.remove(); } catch (e) {}
    }
    _initMagnifierBrush(chartContainerEl, margin);
    _anomalyRestoreOnLoad();

    if (state.flowView && state.flowView.binnedData && state.flowView.binnedData.length > 0) {
        try { renderMarksForLayerLocal(fullDomainLayer, state.flowView.binnedData); } catch (e) {}
    }
    try { mainWebGLRenderer.render(xScale, chartContainerEl.scrollTop, chartContainerEl.clientHeight); } catch (e) {}

    return true;
}

// Sweep state.flowView.binnedData and tally per-IP counts of items NOT hidden
// by the sidebar Flow Types legend (hiddenFlowLegendTypes). Restricted to the
// supplied baseIPs (typically the IP-filter result). Returns Map<ip, count>.
function _computeFlowOnlyVisibleIPCounts(baseIPs) {
    const baseSet = new Set(baseIPs);
    const counts = new Map();
    for (const ip of baseIPs) counts.set(ip, 0);

    const binnedData = state.flowView && state.flowView.binnedData;
    if (!Array.isArray(binnedData) || binnedData.length === 0) return counts;

    for (const item of binnedData) {
        if (!item || !item.initiator) continue;
        if (!baseSet.has(item.initiator)) continue;
        if (isFlowItemHiddenByLegend(item)) continue;
        counts.set(item.initiator, (counts.get(item.initiator) || 0) + (item.count || 0));
    }
    return counts;
}

// Recompute the flow-only layout when hiddenFlowLegendTypes changes: drop IPs
// whose visible bin count is zero, sort the remaining (or all checked) IPs by
// the active row-order mode, and reflow via _relayoutFlowOnlyForIPs. When the
// row-order mode is "AI (computed in-browser)", AI clustering is recomputed
// over the post-filter IPs and bins. Otherwise, when a close-type filter is
// active, IPs sort by visible bin count desc.
async function _relayoutFlowOnlyForCloseTypeFilter() {
    if (!mainWebGLRenderer) return false;
    // Gate to flow-only mode (svg is null after _initFlowOnlyChart detaches it).
    if (svg) return false;

    const checkedIPs = Array.from(
        document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')
    ).map(cb => cb.value).filter(ip => !_hiddenIPs.has(ip));
    if (checkedIPs.length === 0) return false;

    const filterActive = hiddenFlowLegendTypes && hiddenFlowLegendTypes.size > 0;
    const mode = document.getElementById('ipRowOrder')?.value || 'first_seen';

    // Drop IPs with zero visible bins under the current close-type filter.
    let pool = checkedIPs;
    if (filterActive) {
        const counts = _computeFlowOnlyVisibleIPCounts(checkedIPs);
        pool = checkedIPs.filter(ip => (counts.get(ip) || 0) > 0);
        if (pool.length === 0) pool = checkedIPs.slice(0, 1);
    }

    let baseOrder;
    if (mode === 'ai_live') {
        await loadAIOrderLive();
        baseOrder = sortIPsByMode(pool, mode);
    } else if (mode === 'fiedler') {
        await loadFiedlerOrderLive();
        baseOrder = sortIPsByMode(pool, mode);
    } else if (mode === 'dominant_close' || mode === 'burstiness') {
        // These modes already reflect filter state via isFlowItemHiddenByLegend,
        // so don't override them with the count-desc fallback.
        baseOrder = sortIPsByMode(pool, mode);
    } else if (filterActive) {
        const counts = _computeFlowOnlyVisibleIPCounts(pool);
        baseOrder = [...pool].sort((a, b) => (counts.get(b) || 0) - (counts.get(a) || 0));
    } else {
        baseOrder = sortIPsByMode(pool, mode);
    }

    return _relayoutFlowOnlyForIPs(_maybeClusterOrder(baseOrder));
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
    height = _assignFlowOnlyRowPositions(selectedIPs, ROW_GAP_CRAMPED) + TOP_PAD;
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
        zoomTarget = d3.select(chartContainerEl);
        // Flow-only WebGL view is a static overview — do not attach zoom handlers.
    } catch (e) { console.warn('[FlowOnly] Zoom handler init failed', e); }

    fullDomainBinsCache = { version: state.data.version, data: [], binSize: null, sorted: false };

    // Build main chart WebGL renderer (draws lozenges on top of the SVG background)
    _setupMainWebGLRenderer(margin, ROW_GAP_CRAMPED);

    // Kick an initial render if flow data is already available; otherwise the
    // regular data-load pipeline (applyZoomDomain / loadFlowViewData) will
    // trigger it. In packet view, re-render the cached packet bins through the
    // newly-created WebGL renderer so row reordering takes effect.
    if (state.ui.renderMode === 'packets' && state.data.full && state.data.full.length > 0) {
        try { renderPacketsViaWebGL(); } catch (e) { console.warn('[FlowOnly] packet re-render failed', e); }
    } else if (state.flowView && state.flowView.binnedData && state.flowView.binnedData.length > 0) {
        try { renderMarksForLayerLocal(fullDomainLayer, state.flowView.binnedData); } catch (e) {}
    }

    _magLoadManifest(); // non-blocking; sets _magCache or leaves it null on failure
    _initMagnifierBrush(chartContainerEl, margin);
    _anomalyRestoreOnLoad();
    _anomalyWireButton();
    _orderingWireButton();

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

        // Per-instance override of _drawOverlay so flow-only mode paints
        // ground-truth bands at a visible minimum height. The shared
        // implementation uses `this.rowGap` for the band height, which is
        // ROW_GAP_CRAMPED (≈0.1px) in flow-only mode — visually zero. We
        // disable the renderer's GT branch and paint bands ourselves at
        // FLOW_ONLY_GT_BAND_PX. Cloned-not-shared per project rule.
        installFlowOnlyGroundTruthOverlay(mainWebGLRenderer);

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

let _magnifierResizeObs = null;
let _magnifierCascade = 0;
const _magnifierBrushes = new Map();  // panelId -> { editG, panel, update, lastArgs }

// Magnifier Network-tab grouping state. Persists across panels so the user's
// chosen group mode (subnets/country/org) sticks once they pick it.
// Value is whatever ForceNetworkLayout's `groupBy` accepts — single level name
// or array of names (innermost-first).
let _magnifierNetworkGroupBy = 'none';
// When true, the magnifier Network tab pulls this region's member IPs into one
// cluster and first-degree neighbors into a separate cluster (via a custom
// separation force on the simulation), overriding subnet/country/org grouping.
let _magnifierNetworkAISeparate = false;

// Lazy-cached IP→{country, org} map (MaxMind enrichment). Loaded on first
// magnifier Network-tab render. Returns null if ip_meta_map.json isn't present,
// in which case country/org grouping degrades to flat layout silently.
let _ipMetaMapPromise = null;
function _ensureIpMetaMap() {
    if (_ipMetaMapPromise) return _ipMetaMapPromise;
    _ipMetaMapPromise = fetch('./ip_meta_map.json', { cache: 'no-store' })
        .then(r => r.ok ? r.json() : null)
        .then(obj => {
            if (!obj) return null;
            // Strip RFC1918 entries — they carry no country/org info, just
            // bloat memory. Keep entries that have at least one resolved field.
            const out = {};
            for (const [ip, meta] of Object.entries(obj)) {
                if (!meta || meta.internal) continue;
                if (meta.country || meta.org) {
                    out[ip] = { country: meta.country || null, org: meta.org || null };
                }
            }
            return out;
        })
        .catch(err => { console.warn('[Magnifier] meta map load failed:', err); return null; });
    return _ipMetaMapPromise;
}

// Colors for AI-identified attack types. The model names attack types in its OWN
// words — open vocabulary, NO predefined list. Each distinct label is assigned a
// color the first time it appears and cached, so the same label stays consistent
// across re-renders within a session (a new run with new labels gets new colors).
// User-drawn brushes (no attackType) get neutral grey.
// Used by: (1) magnifier brush rect, (2) AI hit-rect outline, (3) panel header chip.
const _USER_BRUSH_STYLE = { stroke: '#6b7280', fill: 'rgba(107, 114, 128, 0.15)', label: '' };
const _attackTypeColorCache = new Map();   // attackType label -> { stroke, fill, label }
function _attackTypeStyle(attackType) {
    const key = (typeof attackType === 'string') ? attackType.trim() : '';
    if (!key) return _USER_BRUSH_STYLE;
    let style = _attackTypeColorCache.get(key);
    if (!style) {
        const hue = Math.floor(Math.random() * 360);
        style = {
            stroke: `hsl(${hue}, 65%, 45%)`,
            fill: `hsla(${hue}, 65%, 45%, 0.18)`,
            label: key
        };
        _attackTypeColorCache.set(key, style);
    }
    return style;
}
let _magnifierPanelCounter = 0;
// Populated by _initMagnifierBrush on each chart init. Exposes the brush-spawn
// helper so other features (AI anomaly detection) can create selections
// programmatically without duplicating the brush plumbing.
let _magnifierOverlayCtx = null;  // { overlaySvg, innerW, innerH, margin, createSelection }
let _hideIPMenu = null;  // currently-open right-click hide menu, or null
const _hiddenIPs = new Set();  // session-only fast-hide set; cleared on full updateIPFilter

// "Explain this region" feature state. See the _explain* block near the
// bottom of this file. To remove the feature: delete these four lines,
// the three hook calls (_explainAttachToPanel / _explainNotifyArgsChanged /
// _explainDetach), and the _explain* function block at file tail.
let _explainApiKey = null;                 // string | null  (null = not yet fetched or last fetch failed)
let _explainApiKeyPromise = null;          // Promise<string|false> | null  (in-flight dedup)
const _explainCache = new Map();           // canonical region key -> raw response text
// Role-classification map parsed from the ```roles fenced block at the end of
// every Explain response. Keyed by the same canonical region key as
// _explainCache, so any (ips, tMin, tMax) tuple has at most one matching pair.
// Consumed by the Network tab to filter noise and group nodes by role.
const _roleMapCache = new Map();           // canonical region key -> Map<ip, role>
const _explainPanels = new WeakMap();      // panel element -> per-panel record (see _explainAttachToPanel)

function _refreshAllMagnifierPanels() {
    for (const entry of _magnifierBrushes.values()) {
        if (entry.update && entry.lastArgs) {
            try { entry.update(entry.lastArgs.ips, entry.lastArgs.tMin, entry.lastArgs.tMax); } catch (e) {}
        }
    }
}

// Log of user-drawn magnifier boxes. Each draw / resize-end appends a record and
// prints a readable summary plus a copyable JSON line. The full list is exposed at
// window._userBoxes so you can grab every box at once (e.g. `copy(_userBoxes)` in
// the console, or `JSON.stringify(_userBoxes)`).
const _userDrawnBoxes = [];
function _logUserBox(args, source) {
    const ips = [...(args.ips || [])];
    const tMin = args.tMin, tMax = args.tMax;
    const box = {
        source,                                  // 'drawn' | 'resized'
        tMinUs: tMin, tMaxUs: tMax,
        tStartUTC: new Date(tMin / 1000).toISOString(),
        tEndUTC: new Date(tMax / 1000).toISOString(),
        durationSec: Math.round((tMax - tMin) / 1e6),
        ipCount: ips.length,
        ips
    };
    _userDrawnBoxes.push(box);
    if (typeof window !== 'undefined') window._userBoxes = _userDrawnBoxes;
    console.log(`[UserBox:${source}] #${_userDrawnBoxes.length} — ${box.ipCount} IPs, ${box.durationSec}s, ` +
        `${box.tStartUTC} → ${box.tEndUTC}`);
    console.log('[UserBox] copyable:', JSON.stringify({ tMinUs: tMin, tMaxUs: tMax, ips }));
    return box;
}

/**
 * Attach a D3 2D brush overlay to the flow-only WebGL view.
 * Each completed brush spawns an in-page floating magnifier panel via
 * _spawnMagnifierPanel, showing the selected IPs and time range as
 * spacious SVG lozenges.
 *
 * The overlay SVG is a separate element (not the main SVG, which is removed
 * in flow-only mode).  The brush <g> is translated by (margin.left, margin.top)
 * so its pixel coordinates match the ipPositions values directly — both start
 * at TOP_PAD = 30 and neither has an additional offset.
 */
function _initMagnifierBrush(chartContainerEl, margin) {
    if (!chartContainerEl) return;

    if (_magnifierResizeObs) { try { _magnifierResizeObs.disconnect(); } catch(e) {} _magnifierResizeObs = null; }

    // Abort any in-flight anomaly detection from a previous chart instance.
    // Without this, _anomalyBusy stays true across re-inits (e.g. data reload
    // mid-detection) and the button is permanently disabled.
    if (_anomalyAbortController) {
        try { _anomalyAbortController.abort(); } catch (e) {}
        _anomalyAbortController = null;
    }
    _anomalyBusy = false;

    // Save panel state before clearing so we can restore after overlay rebuild.
    const savedPanels = Array.from(_magnifierBrushes.values())
        .filter(e => e.update && e.lastArgs)
        .map(e => ({ panel: e.panel, update: e.update, lastArgs: { ...e.lastArgs } }));

    // Remove edit-brush <g> elements (they live on the overlay SVG being rebuilt).
    // Panel DOM elements (fixed divs on document.body) are preserved for restore below.
    for (const entry of _magnifierBrushes.values()) {
        try { entry.editG.remove(); } catch (e) {}
    }
    _magnifierBrushes.clear();

    // Remove any previous overlay from a prior chart init.
    const existing = chartContainerEl.querySelector('.magnifier-brush-overlay');
    if (existing) existing.remove();

    const totalW = chartContainerEl.clientWidth;
    const totalH = height + margin.top + margin.bottom;  // full content height
    const innerW = totalW - margin.left - margin.right;
    const innerH = height;  // inner plot height = content minus margins

    const overlaySvg = d3.select(chartContainerEl)
        .append('svg')
        .attr('class', 'magnifier-brush-overlay')
        .attr('width', totalW)
        .attr('height', totalH)
        .style('position', 'absolute')
        .style('left', '0')
        .style('top', '0')
        .style('z-index', '5')
        .style('pointer-events', 'none');

    const brushGroup = overlaySvg.append('g')
        .attr('class', 'magnifier-brush')
        .attr('transform', `translate(${margin.left},${margin.top})`)
        .style('pointer-events', 'all');

    // Shared helper for both user-drawn selections and AI-detected anomaly
    // regions. Creates an edit-brush <g> with a pre-positioned selection rect.
    // The magnifier panel is NOT spawned until the user clicks the rect — this
    // way AI detection can pre-populate up to N rects without flooding the
    // screen with panels. If opts.existingPanel is provided (overlay rebuild
    // restoring an already-live brush), the panel is bound immediately.
    function createSelection(initialSelection, opts = {}) {
        const [[x0, y0], [x1, y1]] = initialSelection;

        const tMinUs = xScale.invert(x0);
        const tMaxUs = xScale.invert(x1);
        if (tMinUs >= tMaxUs) return null;

        // ipPositions values start at TOP_PAD = 30 and increment by ROW_GAP_CRAMPED = 0.1.
        // The brush <g> is translated by margin.top so brush-local Y equals ipPositions value.
        // For AI region activations (opts.regionIps), use the region's full membership
        // (r.ips + r.responder). For user-drawn brushes, use the Y-range.
        // Always use Y-range — show every row the box covers.
        const selectedIPsArray = state.layout.ipOrder.filter(ip => {
            const pos = state.layout.ipPositions.get(ip);
            return pos !== undefined && pos >= y0 && pos <= y1;
        });
        if (selectedIPsArray.length === 0) return null;

        const panelId = ++_magnifierPanelCounter;
        const editG = overlaySvg.append('g')
            .attr('class', `magnifier-edit-brush mag-brush-${panelId}`)
            .attr('transform', `translate(${margin.left},${margin.top})`)
            .style('pointer-events', 'all');

        const lastArgs = {
            ips: selectedIPsArray,
            tMin: Math.floor(tMinUs),
            tMax: Math.ceil(tMaxUs),
            // Optional AI-anomaly context: a free-form prose reason from the
            // anomaly detector, plus optional evidence string and numeric
            // confidence. The explain feature uses these as cross-check input.
            anomalyReason: opts.reason || (opts.existingPanel && opts.existingPanel.lastArgs && opts.existingPanel.lastArgs.anomalyReason) || '',
            anomalyEvidence: opts.evidence || (opts.existingPanel && opts.existingPanel.lastArgs && opts.existingPanel.lastArgs.anomalyEvidence) || '',
            anomalyConfidence: (opts.confidence != null) ? opts.confidence
                : ((opts.existingPanel && opts.existingPanel.lastArgs && opts.existingPanel.lastArgs.anomalyConfidence != null) ? opts.existingPanel.lastArgs.anomalyConfidence : null),
            // Structured per-region findings from the anomaly detector (the
            // "case file"). null for user-drawn brushes. Survives overlay rebuilds
            // via the same existingPanel fallback as the other anomaly* fields.
            caseFile: opts.caseFile
                || (opts.existingPanel && opts.existingPanel.lastArgs && opts.existingPanel.lastArgs.caseFile)
                || null,
            // Origin marker: 'ai' for AI-spawned regions (attackType set by the
            // anomaly detector), undefined for user-drawn brushes. The Network
            // tab consults this to decide whether to auto-run AI denoising.
            attackType: opts.attackType
                || (opts.existingPanel && opts.existingPanel.lastArgs && opts.existingPanel.lastArgs.attackType)
                || null,
            knownAttackName: opts.knownAttackName
                || (opts.existingPanel && opts.existingPanel.lastArgs && opts.existingPanel.lastArgs.knownAttackName)
                || null
        };

        // Log genuine user-drawn boxes (not AI-spawned regions, not overlay-rebuild restores).
        if (!opts.existingPanel && !opts.attackType) _logUserBox(lastArgs, 'drawn');

        // Panel / update are populated lazily on first activation. For
        // restoration, they're seeded from opts.existingPanel immediately.
        let panel = opts.existingPanel ? opts.existingPanel.panel : null;
        let update = opts.existingPanel ? opts.existingPanel.update : null;
        let rafId = null;

        const scheduleUpdate = (ips, tmin, tmax) => {
            lastArgs.ips = ips; lastArgs.tMin = tmin; lastArgs.tMax = tmax;
            if (!update) return;  // dormant — no panel yet to update
            if (rafId) cancelAnimationFrame(rafId);
            rafId = requestAnimationFrame(() => {
                rafId = null;
                update(ips, tmin, tmax);
            });
        };

        // Skip the synthetic 'brush'/'end' events fired by the initial programmatic
        // editBrush.move() below. Without this, the handler's Y-range IP recompute
        // would overwrite lastArgs.ips for AI region activations, clobbering the
        // full r.ips + r.responder membership we just set above.
        let initialBrushPositioning = true;
        const editBrush = d3.brush()
            .extent([[0, 0], [innerW, innerH]])
            .on('brush end', (editEvent) => {
                if (!editEvent.selection) return;
                if (initialBrushPositioning) return;
                const [[ex0, ey0], [ex1, ey1]] = editEvent.selection;
                const newTMin = xScale.invert(ex0);
                const newTMax = xScale.invert(ex1);
                if (newTMin >= newTMax) return;
                const newIps = state.layout.ipOrder.filter(ip => {
                    const pos = state.layout.ipPositions.get(ip);
                    return pos !== undefined && pos >= ey0 && pos <= ey1;
                });
                if (newIps.length === 0) return;
                scheduleUpdate(newIps, Math.floor(newTMin), Math.ceil(newTMax));
                // Log the final position after a move/resize (only on 'end', not every drag tick).
                if (editEvent.type === 'end') {
                    _logUserBox({ ips: newIps, tMin: Math.floor(newTMin), tMax: Math.ceil(newTMax) }, 'resized');
                }
            });

        editG.call(editBrush);
        editBrush.move(editG, [[x0, y0], [x1, y1]]);
        initialBrushPositioning = false;  // synthetic events done; real user resizes now run

        // Make the edit brush's overlay rect pass-through so the draw brush
        // can still capture new drag gestures in empty space below.
        editG.select('.overlay').style('pointer-events', 'none');

        const brushStyle = _attackTypeStyle(lastArgs.attackType);
        editG.select('.selection')
            .style('fill', brushStyle.fill)
            .style('stroke', brushStyle.stroke)
            .style('stroke-width', '1px')
            .style('cursor', panel ? 'move' : 'pointer');

        _magnifierBrushes.set(panelId, { editG, panel, update, lastArgs });

        const wireCloseBtn = () => {
            const closeBtn = panel.querySelector('.magnifier-close');
            if (!closeBtn) return;
            closeBtn.onclick = () => {
                if (rafId) cancelAnimationFrame(rafId);
                if (panel.__magnifierCleanup) panel.__magnifierCleanup();
                _explainDetach(panel);
                try { editG.remove(); } catch (e) {}
                try { panel.remove(); } catch (e) {}
                _magnifierBrushes.delete(panelId);
            };
        };

        const activate = () => {
            const entry = _magnifierBrushes.get(panelId);
            if (entry && entry.panel) return;  // already open for this region
            try {
                const result = _spawnMagnifierPanel(lastArgs.ips, lastArgs.tMin, lastArgs.tMax, {
                    attackType: lastArgs.attackType || null,
                    knownAttackName: lastArgs.knownAttackName || null,
                    anomalyReason: lastArgs.anomalyReason || ''
                });
                panel = result.panel;
                update = result.update;
                if (entry) { entry.panel = panel; entry.update = update; }
                _explainAttachToPanel(panel, lastArgs);
                editG.select('.selection').style('cursor', 'move');
                wireCloseBtn();
            } catch (e) {
                console.warn('[MagnifierBrush] Failed to spawn panel:', e);
            }
        };

        // Native click semantics: fires on mouseup-without-drag. Drag/resize
        // gestures handled by d3.brush above don't generate click events, so
        // this won't interfere with moving or resizing the rect.
        editG.select('.selection').on('click.spawn', (event) => {
            activate();
            event.stopPropagation();
        });

        if (opts.existingPanel) {
            _explainAttachToPanel(panel, lastArgs);
            wireCloseBtn();
            try { update(lastArgs.ips, lastArgs.tMin, lastArgs.tMax); } catch (e) {}
        }

        return { panelId, editG, activate };
    }

    const brush = d3.brush()
        .extent([[0, 0], [innerW, innerH]])
        .on('end', function (event) {
            if (!event.selection) return;
            try {
                createSelection(event.selection);
            } catch (e) {
                console.warn('[MagnifierBrush] Failed to create selection:', e);
            }
            // Clear the draw brush rectangle now that the edit brush owns the region.
            brushGroup.call(brush.move, null);
        });

    brushGroup.call(brush);

    // Style the draw brush selection rectangle.
    overlaySvg.select('.selection')
        .style('fill', 'rgba(74, 144, 226, 0.15)')
        .style('stroke', '#4a90e2')
        .style('stroke-width', '1px');

    _magnifierOverlayCtx = { overlaySvg, innerW, innerH, margin, createSelection };

    // Restore panels saved before the overlay was rebuilt.
    // For each saved panel: filter its IPs to those still in the new layout,
    // compute new pixel coords, then call createSelection with the saved panel
    // pair so the brush is wired straight back to its existing magnifier panel
    // (no click-to-activate needed — the panel is already live).
    for (const saved of savedPanels) {
        const validIps = (saved.lastArgs.ips || []).filter(ip => state.layout.ipPositions.has(ip));
        if (validIps.length === 0) {
            if (saved.panel.__magnifierCleanup) saved.panel.__magnifierCleanup();
            try { saved.panel.remove(); } catch (e) {}
            continue;
        }

        const ys = validIps.map(ip => state.layout.ipPositions.get(ip));
        const ex0 = Math.max(0, Math.min(innerW, xScale(saved.lastArgs.tMin)));
        const ex1 = Math.max(0, Math.min(innerW, xScale(saved.lastArgs.tMax)));
        const ey0 = Math.max(0, Math.min(innerH, Math.min(...ys) - 0.05));
        const ey1 = Math.max(0, Math.min(innerH, Math.max(...ys) + 0.05));

        try {
            createSelection([[ex0, ey0], [ex1, ey1]], { existingPanel: saved });
        } catch (e) {
            console.warn('[MagnifierBrush] Failed to restore panel:', e);
        }
    }

    // Resize the overlay when the container changes size.
    _magnifierResizeObs = new ResizeObserver(entries => {
        for (const entry of entries) {
            const newW = entry.contentRect.width;
            const newTotalH = height + margin.top + margin.bottom;
            overlaySvg.attr('width', newW).attr('height', newTotalH);
            brush.extent([[0, 0], [newW - margin.left - margin.right, height]]);
            brushGroup.call(brush);
        }
    });
    _magnifierResizeObs.observe(chartContainerEl);
}

function _openMagnifierInAnalysis(lastArgs) {
    const storageKey = `flow_magnifier_selection_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    const selectionData = {
        source: 'flow_analysis_magnifier',
        timestamp: Date.now(),
        selection: {
            ips: lastArgs.ips,
            ipsInOrder: lastArgs.ips,
            timeRange: {
                minUs: lastArgs.tMin,
                maxUs: lastArgs.tMax
            }
        },
        baseDataPath: null,
        detailViewDataPath: null,
        ipMapPath: null
    };
    try {
        localStorage.setItem(storageKey, JSON.stringify(selectionData));
    } catch (e) {
        alert('Failed to store selection data.');
        return;
    }
    const newWindow = window.open(`./tcp-analysis.html?fromSelection=${encodeURIComponent(storageKey)}`, '_blank');
    if (!newWindow) alert('Popup was blocked. Please allow popups for this site.');
}

function _showHideIPMenu(clientX, clientY, ip, onConfirm) {
    // Only one menu open at a time. Close (not just remove) so the previous
    // menu's document-level listeners are cleaned up.
    if (_hideIPMenu) _hideIPMenu._close?.();

    const menu = document.createElement('div');
    _hideIPMenu = menu;
    Object.assign(menu.style, {
        position: 'fixed', left: `${clientX}px`, top: `${clientY}px`,
        zIndex: '10000', background: '#fff', border: '1px solid #ced4da',
        borderRadius: '4px', boxShadow: '0 2px 8px rgba(0,0,0,0.18)',
        font: '12px monospace', padding: '4px 0', whiteSpace: 'nowrap'
    });

    const item = document.createElement('div');
    item.textContent = `Hide IP ${ip}`;
    Object.assign(item.style, { padding: '6px 12px', cursor: 'pointer' });
    item.addEventListener('mouseenter', () => { item.style.background = '#e9ecef'; });
    item.addEventListener('mouseleave', () => { item.style.background = ''; });
    menu.appendChild(item);
    document.body.appendChild(menu);

    // Clamp so the menu doesn't overflow the viewport on the right/bottom.
    const mw = menu.offsetWidth;
    const mh = menu.offsetHeight;
    if (clientX + mw > window.innerWidth)  menu.style.left = `${window.innerWidth  - mw - 4}px`;
    if (clientY + mh > window.innerHeight) menu.style.top  = `${window.innerHeight - mh - 4}px`;

    const close = () => {
        menu.remove();
        if (_hideIPMenu === menu) _hideIPMenu = null;
        document.removeEventListener('mousedown', outsideClick, true);
        document.removeEventListener('keydown',   onKey,        true);
    };

    menu._close = close;
    item.addEventListener('click', () => { onConfirm(); close(); });

    const outsideClick = (e) => { if (!menu.contains(e.target)) close(); };
    const onKey = (e) => { if (e.key === 'Escape') close(); };
    // Defer so the triggering contextmenu event doesn't immediately close the menu.
    setTimeout(() => {
        document.addEventListener('mousedown', outsideClick, { capture: true });
        document.addEventListener('keydown',   onKey,        { capture: true });
    }, 0);
}

function _fastHideIP(ip) {
    if (_hiddenIPs.has(ip)) return;
    _hiddenIPs.add(ip);
    const ROW_GAP_CRAMPED = 0.1;

    // Visually un-tick the checkbox without dispatching 'change' (which would
    // trigger the heavy updateIPFilter path).
    const cb = document.querySelector(`#ipCheckboxes input[type="checkbox"][value="${CSS.escape(ip)}"]`);
    if (cb) cb.checked = false;

    // Remove from layout maps and reflow remaining rows so no gap is left behind.
    if (state.layout) {
        if (Array.isArray(state.layout.ipOrder)) {
            const idx = state.layout.ipOrder.indexOf(ip);
            if (idx >= 0) state.layout.ipOrder.splice(idx, 1);
        }
        state.layout.ipPositions?.delete(ip);
        state.layout.ipRowHeights?.delete(ip);
        state.layout.ipPairCounts?.delete(ip);
        state.layout.collapsedIPs?.delete(ip);

        // Recompact Y positions of remaining rows.
        if (Array.isArray(state.layout.ipOrder) && state.layout.ipPositions) {
            let y = TOP_PAD;
            for (const remaining of state.layout.ipOrder) {
                state.layout.ipPositions.set(remaining, y);
                y += ROW_GAP_CRAMPED;
            }
            height = y + TOP_PAD;
        }
    }

    // Push the new layout to the WebGL renderer (no destroy/recreate).
    if (mainWebGLRenderer && state.layout?.ipOrder && state.layout?.ipPositions) {
        try {
            mainWebGLRenderer.setLayout(state.layout.ipOrder, state.layout.ipPositions, ROW_GAP_CRAMPED);
        } catch (e) { console.warn('[FastHide] setLayout failed', e); }
    }

    // Re-render main view from existing binnedData. The render filter
    // drops items touching hidden IPs.
    if (typeof renderMarksForLayerLocal === 'function' && fullDomainLayer && state.flowView?.binnedData) {
        try { renderMarksForLayerLocal(fullDomainLayer, state.flowView.binnedData); } catch (e) {}
    }

    // Refresh open magnifier panels in place — no overlay teardown.
    for (const entry of _magnifierBrushes.values()) {
        if (!entry.update || !entry.lastArgs) continue;
        const newIps = (entry.lastArgs.ips || []).filter(p => !_hiddenIPs.has(p));
        entry.lastArgs.ips = newIps;
        try { entry.update(newIps, entry.lastArgs.tMin, entry.lastArgs.tMax); } catch (e) {}
    }
}

// Magnifier panel: shared focus vs view time windows (option A — dimmed context).
const MAG_VIEW_MAX_US = 20 * 60_000_000;
const MAG_VIEW_MAX_SIDE_US = 10 * 60_000_000;
const MAG_VIEW_PAD_RATIO = 0.08;
const MAG_VIEW_MIN_PAD_US = 30_000_000;
const MAG_CONTEXT_OPACITY = 0.25;

/** Timestamps for member↔admitted-neighbor activity (extends view, not full capture). */
function _collectCrossBandActivityTimes(rows, memberSet, neighborSet) {
    if (!neighborSet || neighborSet.size === 0 || !rows || rows.length === 0) return [];
    const out = [];
    for (let i = 0; i < rows.length; i++) {
        const r = rows[i];
        const src = r.src_ip ?? r.initiator;
        const dst = r.dst_ip ?? r.responder;
        if (!src || !dst) continue;
        const srcM = memberSet.has(src);
        const dstM = memberSet.has(dst);
        if (srcM === dstM) continue;
        const neighborIp = srcM ? dst : src;
        if (!neighborSet.has(neighborIp)) continue;
        const t0 = Number(r.binStart ?? r.bin_start ?? r.startTime ?? r.timestamp ?? 0);
        const t1 = Number(r.binEnd ?? r.bin_end ?? r.endTime ?? t0);
        out.push(t0, t1);
    }
    return out;
}

function _computeMagnifierTimeExtents(focusMin, focusMax, activityTimes, captureExtent) {
    const cap = (captureExtent && captureExtent[0] < captureExtent[1])
        ? captureExtent
        : [Math.min(focusMin, focusMax), Math.max(focusMin, focusMax)];
    const focusLo = Math.min(focusMin, focusMax);
    const focusHi = Math.max(focusMin, focusMax);
    let viewLo = focusLo;
    let viewHi = focusHi;
    let capped = false;

    if (activityTimes && activityTimes.length > 0) {
        let actLo = Infinity;
        let actHi = -Infinity;
        for (const t of activityTimes) {
            if (t < actLo) actLo = t;
            if (t > actHi) actHi = t;
        }
        if (actLo < viewLo) viewLo = actLo;
        if (actHi > viewHi) viewHi = actHi;
    }

    // Cap only the neighbor-activity extension beyond the focus range.
    // Never shrink below the focus (box) range — the user must see everything
    // the box covers.
    if (viewHi - viewLo > MAG_VIEW_MAX_US) {
        capped = true;
        // Clamp extensions but keep at least [focusLo, focusHi].
        viewLo = Math.max(cap[0], Math.min(viewLo, focusLo));
        viewHi = Math.min(cap[1], Math.max(viewHi, focusHi));
        // If still too wide, trim the neighbor extensions symmetrically.
        if (viewHi - viewLo > MAG_VIEW_MAX_US) {
            const budget = MAG_VIEW_MAX_US - (focusHi - focusLo);
            if (budget > 0) {
                const extraLo = focusLo - viewLo;
                const extraHi = viewHi - focusHi;
                const totalExtra = extraLo + extraHi;
                const loShare = totalExtra > 0 ? (extraLo / totalExtra) * budget : budget / 2;
                const hiShare = budget - loShare;
                viewLo = focusLo - Math.min(extraLo, loShare);
                viewHi = focusHi + Math.min(extraHi, hiShare);
            } else {
                // Focus alone exceeds cap — just use focus range, no extensions.
                viewLo = focusLo;
                viewHi = focusHi;
            }
        }
    }

    const pad = Math.max(MAG_VIEW_MIN_PAD_US, (viewHi - viewLo) * MAG_VIEW_PAD_RATIO);
    viewLo = Math.max(cap[0], viewLo - pad);
    viewHi = Math.min(cap[1], viewHi + pad);

    return { focusMin: focusLo, focusMax: focusHi, viewMin: viewLo, viewMax: viewHi, capped };
}

function _magOverlapsInterval(t0, t1, lo, hi) {
    return t1 >= lo && t0 <= hi;
}

function _magItemTimeBounds(d) {
    if (d.minute != null && d.binStart == null && d.bin_start == null && d.timestamp == null) {
        const t = d.minute * 60_000_000;
        return [t, t + 60_000_000];
    }
    const t0 = Number(d.binStart ?? d.bin_start ?? d.startTime ?? d.timestamp ?? 0);
    const t1 = Number(d.binEnd ?? d.bin_end ?? d.endTime ?? t0);
    return [t0, t1];
}

function _applyMagnifierGlyphOpacity(sel, focusMin, focusMax) {
    sel.attr('opacity', d => {
        const [t0, t1] = _magItemTimeBounds(d);
        return _magOverlapsInterval(t0, t1, focusMin, focusMax) ? 1 : MAG_CONTEXT_OPACITY;
    });
}

function _magnifierBottomBarText(te) {
    const fmt = (t) => (typeof formatTimestamp === 'function')
        ? formatTimestamp(t).utcTime
        : String(t);
    let s = `Focus ${fmt(te.focusMin)} → ${fmt(te.focusMax)} · View ${fmt(te.viewMin)} → ${fmt(te.viewMax)}`;
    if (te.capped) s += ' (view capped)';
    return s;
}

function _spawnMagnifierPanel(ipSubset, tMinUs, tMaxUs, opts = {}) {
    // One magnifier window at a time: close any currently-open panel before opening a new one
    // and release its data (render closure + DOM) so panels do not pile up in memory. The
    // region box (editG) stays, so it can be re-opened; only the window and its data are freed.
    for (const [, _e] of _magnifierBrushes) {
        if (!_e || !_e.panel) continue;
        try { if (_e.panel.__magnifierCleanup) _e.panel.__magnifierCleanup(); } catch (e) {}
        try { _explainDetach(_e.panel); } catch (e) {}
        try { _e.panel.remove(); } catch (e) {}
        _e.panel = null; _e.update = null;
    }
    // No IP cap — show all rows the region covers.
    const uid = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    // Origin metadata stashed on the panel DOM so per-tab renderers (esp. the
    // Network tab's denoise gate) can tell AI-spawned panels from user-drawn
    // ones without threading args through every redraw path.
    const panelAttackType = opts.attackType || null;
    const panelOrigin = panelAttackType ? 'ai' : 'user';

    const panelW = 1000;
    const panelH = 600;
    const maxLeft = Math.max(0, window.innerWidth - panelW);
    const maxTop  = Math.max(0, window.innerHeight - panelH);
    const rawLeft = 40 + _magnifierCascade * 28;
    const rawTop  = 40 + _magnifierCascade * 28;
    _magnifierCascade = (_magnifierCascade + 1) % 8;

    const panelLeft = Math.min(rawLeft, maxLeft);
    const panelTop  = Math.min(rawTop,  maxTop);

    const panel = document.createElement('div');
    panel.className = 'magnifier-panel';
    panel.__origin = panelOrigin;
    panel.__attackType = panelAttackType;
    Object.assign(panel.style, {
        position: 'fixed', zIndex: '1000',
        background: '#fff', border: '1px solid #adb5bd',
        borderRadius: '4px', boxShadow: '0 20px 60px rgba(0,0,0,0.45), 0 8px 20px rgba(0,0,0,0.3)',
        width: `${panelW}px`, minHeight: `${panelH}px`,
        top: `${panelTop}px`, left: `${panelLeft}px`,
        display: 'flex', flexDirection: 'column'
    });

    const header = document.createElement('div');
    header.className = 'magnifier-header';
    Object.assign(header.style, {
        cursor: 'move', padding: '6px 10px', background: '#f1f3f5',
        borderBottom: '1px solid #dee2e6', display: 'flex',
        alignItems: 'center', justifyContent: 'space-between',
        fontSize: '12px', fontFamily: 'monospace', flexShrink: '0'
    });
    const headerLabel = document.createElement('span');

    // Attack-type chip (AI-spawned panels only). Sits between the label and the
    // close button; tinted with the same palette as the brush rectangle so the
    // overview rect and its panel are visually linked.
    let attackChip = null;
    const panelKnownName = opts.knownAttackName || null;
    if (panelAttackType) {
        const chipStyle = _attackTypeStyle(panelAttackType);
        attackChip = document.createElement('span');
        attackChip.className = 'magnifier-attack-chip';
        const chipLabel = panelKnownName
            ? `AI · ${panelKnownName} (${panelAttackType})`
            : 'AI · ' + (chipStyle.label || panelAttackType);
        attackChip.textContent = chipLabel;
        Object.assign(attackChip.style, {
            marginLeft: '8px', padding: '1px 6px', borderRadius: '3px',
            background: chipStyle.fill, color: chipStyle.stroke,
            border: `1px solid ${chipStyle.stroke}`,
            fontSize: '11px', fontWeight: 'bold', textTransform: 'uppercase'
        });
    }

    const closeBtn = document.createElement('button');
    closeBtn.className = 'magnifier-close';
    closeBtn.textContent = '×';
    Object.assign(closeBtn.style, {
        background: 'none', border: 'none', cursor: 'pointer',
        fontSize: '16px', lineHeight: '1', padding: '0 2px'
    });
    // closeBtn.onclick is wired by the caller (_initMagnifierBrush) after panel creation.
    // Wrap label + chip in a single flex container so `justify-content:
    // space-between` on the header doesn't push the chip into the middle.
    const headerLeft = document.createElement('span');
    Object.assign(headerLeft.style, { display: 'flex', alignItems: 'center' });
    headerLeft.appendChild(headerLabel);
    if (attackChip) headerLeft.appendChild(attackChip);
    // Neighbors on/off toggle — only meaningful for the Network and TimeArcs
    // tabs, so its visibility is driven by setActiveTab below.
    const neighborToggleWrap = document.createElement('label');
    Object.assign(neighborToggleWrap.style, {
        display: 'none', alignItems: 'center', gap: '4px',
        marginRight: '10px', cursor: 'pointer',
        fontSize: '11px', fontFamily: 'monospace', color: '#495057'
    });
    const neighborToggle = document.createElement('input');
    neighborToggle.type = 'checkbox';
    neighborToggle.checked = true;
    Object.assign(neighborToggle.style, { cursor: 'pointer', margin: '0' });
    const neighborToggleText = document.createElement('span');
    neighborToggleText.textContent = 'Neighbors';
    neighborToggleWrap.appendChild(neighborToggle);
    neighborToggleWrap.appendChild(neighborToggleText);

    // Group toggle + close on the right so justify-content:space-between keeps
    // the label flush-left and these controls flush-right.
    const headerRight = document.createElement('span');
    Object.assign(headerRight.style, { display: 'flex', alignItems: 'center' });
    headerRight.appendChild(neighborToggleWrap);
    headerRight.appendChild(closeBtn);

    header.appendChild(headerLeft);
    header.appendChild(headerRight);

    // Tab strip: Flow View (default) / Packets. Both tabs render into `body`
    // below — the active tab name is stored in `currentTab` and is consulted
    // by renderActiveTab on every redraw.
    const tabStrip = document.createElement('div');
    tabStrip.className = 'magnifier-tabs';
    Object.assign(tabStrip.style, {
        display: 'flex', gap: '0',
        borderBottom: '1px solid #dee2e6',
        background: '#f8f9fa', flexShrink: '0',
        fontSize: '12px', fontFamily: 'monospace'
    });
    const makeTabBtn = (label, name) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.dataset.tab = name;
        b.textContent = label;
        Object.assign(b.style, {
            padding: '6px 14px', border: 'none', borderRight: '1px solid #dee2e6',
            background: 'transparent', cursor: 'pointer',
            fontSize: '12px', fontFamily: 'monospace',
            borderBottom: '2px solid transparent'
        });
        return b;
    };
    const flowTabBtn = makeTabBtn('Flow View', 'flow');
    const packetTabBtn = makeTabBtn('Packets', 'packets');
    const networkTabBtn = makeTabBtn('Network', 'network');
    const timeArcsTabBtn = makeTabBtn('TimeArcs', 'timearcs');
    tabStrip.appendChild(flowTabBtn);
    tabStrip.appendChild(packetTabBtn);
    tabStrip.appendChild(networkTabBtn);
    tabStrip.appendChild(timeArcsTabBtn);

    const body = document.createElement('div');
    body.className = 'magnifier-body';
    body.id = `mag-body-${uid}`;
    // Fixed height so the explain bar growing below it does not shrink the
    // visualization. Panel uses minHeight (above) so it grows downward when the
    // explain bar gains text content. Subtract header (32) + tab strip (32) +
    // bottomBar (~24) ≈ 88, leaving ~512 for the plot area.
    Object.assign(body.style, {
        height: `${panelH - 88}px`, flexShrink: '0',
        overflow: 'auto', position: 'relative'
    });

    const bottomBar = document.createElement('div');
    Object.assign(bottomBar.style, {
        padding: '4px 10px', background: '#f1f3f5',
        borderTop: '1px solid #dee2e6',
        fontSize: '12px', fontFamily: 'monospace',
        flexShrink: '0'
    });

    panel.appendChild(header);
    panel.appendChild(tabStrip);
    panel.appendChild(body);
    panel.appendChild(bottomBar);
    document.body.appendChild(panel);

    const tooltipEl = document.getElementById('tooltip');
    const clampTooltipToPanel = () => {
        if (!tooltipEl || tooltipEl.style.display === 'none') return;
        const panelRect = panel.getBoundingClientRect();
        const ttRect = tooltipEl.getBoundingClientRect();
        const scrollX = window.scrollX || window.pageXOffset || 0;
        const scrollY = window.scrollY || window.pageYOffset || 0;
        const minLeftPage = panelRect.left + scrollX + 4;
        const maxLeftPage = panelRect.right + scrollX - ttRect.width - 4;
        const minTopPage  = panelRect.top  + scrollY + 4;
        const maxTopPage  = panelRect.bottom + scrollY - ttRect.height - 4;
        const curLeft = parseFloat(tooltipEl.style.left) || 0;
        const curTop  = parseFloat(tooltipEl.style.top)  || 0;
        const newLeft = Math.max(minLeftPage, Math.min(maxLeftPage, curLeft));
        const newTop  = Math.max(minTopPage,  Math.min(maxTopPage,  curTop));
        if (newLeft !== curLeft) tooltipEl.style.left = `${newLeft}px`;
        if (newTop  !== curTop)  tooltipEl.style.top  = `${newTop}px`;
    };
    body.addEventListener('mousemove', clampTooltipToPanel);
    body.addEventListener('mouseover', clampTooltipToPanel);
    panel.__magnifierCleanup = () => {
        // Sentinel: any in-flight async render-tab continuation (notably the
        // Network tab's denoise await) checks this before creating new state.
        // Without it, a close-during-denoise leaks a fresh ForceNetworkLayout
        // and its D3 simulation, because the existing currentTab / pending
        // guards don't fire when only the panel is closed.
        panel.__closed = true;
        body.removeEventListener('mousemove', clampTooltipToPanel);
        body.removeEventListener('mouseover', clampTooltipToPanel);
        if (networkLayout) {
            try { networkLayout.destroy(); } catch (e) { /* swallow */ }
            networkLayout = null;
        }
    };

    // Inline drag — no imports from control-panel.js
    let dragState = null;
    const onMouseMove = (e) => {
        if (!dragState) return;
        const newLeft = Math.max(0, Math.min(window.innerWidth  - 60, e.clientX - dragState.offsetX));
        const newTop  = Math.max(0, Math.min(window.innerHeight - 30, e.clientY - dragState.offsetY));
        panel.style.left = `${newLeft}px`;
        panel.style.top  = `${newTop}px`;
    };
    const onMouseUp = () => {
        dragState = null;
        document.removeEventListener('mousemove', onMouseMove);
        document.removeEventListener('mouseup', onMouseUp);
    };
    header.addEventListener('mousedown', (e) => {
        if (e.target === closeBtn || e.target === neighborToggle ||
            e.target === neighborToggleWrap || e.target === neighborToggleText ||
            e.button !== 0) return;
        const rect = panel.getBoundingClientRect();
        dragState = { offsetX: e.clientX - rect.left, offsetY: e.clientY - rect.top };
        document.addEventListener('mousemove', onMouseMove);
        document.addEventListener('mouseup', onMouseUp);
        e.preventDefault();
    });

    // Per-panel tab state. `currentTab` drives renderActiveTab; `lastArgs` lets
    // tab clicks redraw with the most recent (ips, tMin, tMax).
    let currentTab = 'flow';
    let lastArgs = null;
    // First-degree neighbor inclusion for the Network + TimeArcs tabs. Default
    // on (current behavior); toggled via the header checkbox below.
    let showNeighbors = true;
    // Packet rows for the current region: kicked off eagerly when args change
    // so the Packets tab opens without a fetch delay. `_magLoadPacketRows`
    // caches per-chunk so repeated calls overlap cleanly.
    let packetRowsPromise = null;
    let packetRowsArgsKey = null;
    // Parallel cache for minute-resolution rows used by the Network and
    // TimeArcs tabs, which must always bin per minute regardless of the
    // auto-picked resolution the Packet tab uses.
    let minutePacketRowsPromise = null;
    let minutePacketRowsArgsKey = null;
    const argsKey = (ips, tMin, tMax) => `${tMin}|${tMax}|${[...ips].sort().join(',')}`;
    const ensurePacketsLoaded = (ips, tMin, tMax) => {
        const k = argsKey(ips, tMin, tMax);
        if (packetRowsArgsKey === k && packetRowsPromise) return packetRowsPromise;
        packetRowsArgsKey = k;
        packetRowsPromise = _magLoadPacketRows(ips, tMin, tMax);
        return packetRowsPromise;
    };
    const ensureMinutePacketsLoaded = (ips, tMin, tMax) => {
        const k = argsKey(ips, tMin, tMax);
        if (minutePacketRowsArgsKey === k && minutePacketRowsPromise) return minutePacketRowsPromise;
        minutePacketRowsArgsKey = k;
        minutePacketRowsPromise = _magLoadPacketRowsAtResolution(ips, tMin, tMax, 'minutes');
        return minutePacketRowsPromise;
    };
    // Full-capture-extent rows used by Network and TimeArcs tabs so first-degree
    // neighbors outside the brushed time window are visible. Keyed only by IP
    // set (time range is always state.data.timeExtent).
    let fullExtentPacketRowsPromise = null;
    let fullExtentPacketRowsArgsKey = null;
    const ipsOnlyArgsKey = (ips) => [...ips].sort().join(',');
    const ensureFullExtentPacketsLoaded = (ips) => {
        const k = ipsOnlyArgsKey(ips);
        if (fullExtentPacketRowsArgsKey === k && fullExtentPacketRowsPromise) return fullExtentPacketRowsPromise;
        fullExtentPacketRowsArgsKey = k;
        fullExtentPacketRowsPromise = _magLoadPacketRowsFullExtent(ips);
        return fullExtentPacketRowsPromise;
    };

    const setActiveTab = (name) => {
        currentTab = name;
        for (const btn of [flowTabBtn, packetTabBtn, networkTabBtn, timeArcsTabBtn]) {
            const active = btn.dataset.tab === name;
            btn.style.background = active ? '#fff' : 'transparent';
            btn.style.borderBottom = active ? '2px solid #4a90e2' : '2px solid transparent';
            btn.style.fontWeight = active ? 'bold' : 'normal';
        }
        neighborToggleWrap.style.display = 'flex';
    };
    flowTabBtn.addEventListener('click', () => {
        if (currentTab === 'flow') return;
        setActiveTab('flow');
        if (lastArgs) renderActiveTab(lastArgs.ips, lastArgs.tMin, lastArgs.tMax);
    });
    packetTabBtn.addEventListener('click', () => {
        if (currentTab === 'packets') return;
        setActiveTab('packets');
        if (lastArgs) renderActiveTab(lastArgs.ips, lastArgs.tMin, lastArgs.tMax);
    });
    networkTabBtn.addEventListener('click', () => {
        if (currentTab === 'network') return;
        setActiveTab('network');
        if (lastArgs) renderActiveTab(lastArgs.ips, lastArgs.tMin, lastArgs.tMax);
    });
    timeArcsTabBtn.addEventListener('click', () => {
        if (currentTab === 'timearcs') return;
        setActiveTab('timearcs');
        if (lastArgs) renderActiveTab(lastArgs.ips, lastArgs.tMin, lastArgs.tMax);
    });
    neighborToggle.addEventListener('change', () => {
        showNeighbors = neighborToggle.checked;
        if (lastArgs) {
            renderActiveTab(lastArgs.ips, lastArgs.tMin, lastArgs.tMax);
        }
    });
    setActiveTab('flow');

    // Force-network layout owned by this panel. Destroyed on tab switch (so the
    // simulation doesn't keep ticking offscreen) and on panel close.
    let networkLayout = null;
    const destroyNetworkLayout = () => {
        if (networkLayout) {
            try { networkLayout.destroy(); } catch (e) { /* swallow */ }
            networkLayout = null;
        }
    };

    const buildMagTimeExtents = (memberSet, neighborsArr, focusMin, focusMax) => {
        const binnedData = state.flowView && state.flowView.binnedData;
        const activityTimes = (binnedData && binnedData.length > 0)
            ? _collectCrossBandActivityTimes(binnedData, memberSet, new Set(neighborsArr))
            : [];
        return _computeMagnifierTimeExtents(focusMin, focusMax, activityTimes, state.data && state.data.timeExtent);
    };

    const renderActiveTab = (ips, tMin, tMax) => {
        lastArgs = { ips, tMin, tMax };
        // Packet load runs inside renderPacketTab using the computed view window.
        // Tell the Explain bar (if attached) that the region args may have changed
        // so it can flag the prior result as stale. No-op when no bar is attached yet.
        _explainNotifyArgsChanged(panel);

        if (currentTab !== 'network') destroyNetworkLayout();

        if (currentTab === 'packets') {
            renderPacketTab(ips, tMin, tMax);
        } else if (currentTab === 'network') {
            renderNetworkTab(ips, tMin, tMax);
        } else if (currentTab === 'timearcs') {
            renderTimeArcsTab(ips, tMin, tMax);
        } else {
            renderFlowTab(ips, tMin, tMax);
        }
    };

    // Hook fired by _explainAcceptResult when a new explain result (and its
    // role map) lands. Refines the Network tab to apply the freshly-parsed
    // role grouping; no-op for other tabs.
    panel.__notifyExplainResult = () => {
        if (currentTab === 'network' && lastArgs) {
            renderNetworkTab(lastArgs.ips, lastArgs.tMin, lastArgs.tMax);
        }
    };

    const renderFlowTab = (ips, tMin, tMax) => {
        // Clear previous render before rebuilding so re-renders don't pile up SVG elements.
        body.innerHTML = '';

        const binnedData = state.flowView && state.flowView.binnedData;
        if (!binnedData || binnedData.length === 0) {
            body.textContent = 'No data loaded yet';
            return;
        }

        // Show all IPs the box covers — no filtering.
        let effectiveIps = ips.filter(ip => !_hiddenIPs.has(ip));

        if (effectiveIps.length === 0) {
            body.textContent = 'All IPs in this region have been hidden';
            headerLabel.textContent = '0 IPs';
            return;
        }

        // First-degree expansion: append IPs that talked WITH a region member
        // (derived from the flow binnedData, full capture extent), ranked by flow
        // volume and capped to keep the row count survivable. Rendered below the
        // members and separated by BAND_GAP. Skipped when the Neighbors toggle is off.
        const _FIRST_DEGREE_MAX_TOTAL = 350;
        const memberCount = effectiveIps.length;
        const memberSet = new Set(effectiveIps);
        let neighborsArr = [];
        if (showNeighbors) {
            const pairRows = binnedData.map(d => ({ src_ip: d.initiator, dst_ip: d.responder, count: d.count || 1 }));
            const ranked = _deriveNeighborsFromRows(memberSet, pairRows);
            for (const n of ranked) {
                if (memberCount + neighborsArr.length >= _FIRST_DEGREE_MAX_TOTAL) break;
                if (memberSet.has(n.ip)) continue;
                if (_hiddenIPs.has(n.ip)) continue;
                neighborsArr.push(n.ip);
            }
        }

        // Keep IPs in their original ipOrder sequence — same as the overview.
        const magTime = buildMagTimeExtents(memberSet, neighborsArr, tMin, tMax);
        const { focusMin, focusMax, viewMin, viewMax } = magTime;

        // Append neighbors after members (no re-sorting).
        effectiveIps = [...effectiveIps, ...neighborsArr];

        headerLabel.textContent = neighborsArr.length > 0
            ? `${memberCount} IPs + ${neighborsArr.length} neighbors`
            : `${effectiveIps.length} IPs`;
        bottomBar.textContent = _magnifierBottomBarText(magTime);

        const panelMargin = { top: 10, right: 16, bottom: 28, left: 0 };
        const bodyW  = body.clientWidth  || panelW;
        const bodyH  = body.clientHeight || (panelH - 36);

        const TOP_PAD = 20;
        const availablePlotH = bodyH - panelMargin.top - panelMargin.bottom;
        // Vertical gap separating the member rows (top) from the neighbor rows
        // (bottom). Only inserted when neighbors are present; ROW_GAP absorbs it
        // so all rows still fit the plot height.
        const BAND_GAP = neighborsArr.length > 0 ? 16 : 0;
        const ROW_GAP = Math.max(0.1, (availablePlotH - BAND_GAP) / Math.max(1, effectiveIps.length));
        const ipPositions      = new Map();
        const ipRowHeights     = new Map();
        const ipPairCounts     = new Map();
        const ipPairOrderByRow = new Map();
        let y = TOP_PAD;
        for (let i = 0; i < effectiveIps.length; i++) {
            // Drop in the gap once, between the last member and the first neighbor.
            if (BAND_GAP > 0 && i === memberCount) y += BAND_GAP;
            const ip = effectiveIps[i];
            ipPositions.set(ip, y);
            ipRowHeights.set(ip, ROW_GAP);
            ipPairCounts.set(ip, 1);
            y += ROW_GAP;
        }

        const svgHeight = bodyH;
        body.style.overflow = 'hidden';

        // body.id is stable across re-renders; createSVGStructure appends into it.
        const svgResult = createSVGStructure({
            d3,
            containerId: `#mag-body-${uid}`,
            width: bodyW,
            height: svgHeight,
            margin: panelMargin,
            dotRadius: 4
        });

        const clipId = `clip-mag-${uid}`;
        svgResult.svg.select('defs clipPath').attr('id', clipId);
        svgResult.mainGroup.attr('clip-path', `url(#${clipId})`);

        const plotW  = bodyW - panelMargin.left - panelMargin.right;
        const xScale = d3.scaleLinear().domain([viewMin, viewMax]).range([0, plotW]);

        const ipSet   = new Set(effectiveIps);
        const filtered = binnedData.filter(d => {
            const t0 = d.binStart  ?? d.startTime  ?? 0;
            const t1 = d.binEnd    ?? d.endTime    ?? t0;
            if (!ipSet.has(d.initiator)) return false;
            if (_hiddenIPs.has(d.initiator)) return false;
            if (d.responder && _hiddenIPs.has(d.responder)) return false;
            if (!_magOverlapsInterval(t0, t1, viewMin, viewMax)) return false;
            if (isFlowItemHiddenByLegend(d)) return false;
            return true;
        });

        const collapsedSet = new Set(effectiveIps);
        const aliased = filtered.map(d => ({
            ...d,
            src_ip: d.initiator,
            dst_ip: d.responder,
            flagType: d.closeType
        }));
        const items = collapseSubRowsBins(aliased, collapsedSet);

        const maxCount = state.flowView.globalMaxCount || 1;
        const MAG_LOZENGE_MIN_HEIGHT = 4;
        const MAG_LOZENGE_MAX_HEIGHT = 20;
        const hScale = d3.scaleSqrt()
            .domain([1, Math.max(1, maxCount)])
            .range([MAG_LOZENGE_MIN_HEIGHT, MAG_LOZENGE_MAX_HEIGHT]);

        const colorMap = new Map();
        if (flowColors.closing)  for (const [k, v] of Object.entries(flowColors.closing))  colorMap.set(k, v);
        if (flowColors.ongoing)  for (const [k, v] of Object.entries(flowColors.ongoing))  colorMap.set(k, v);
        if (flowColors.invalid)  for (const [k, v] of Object.entries(flowColors.invalid))  colorMap.set(k, v);

        renderLozenges(svgResult.fullDomainLayer, items, {
            xScale, hScale, flowColorMap: colorMap,
            LOZENGE_MIN_HEIGHT: MAG_LOZENGE_MIN_HEIGHT, LOZENGE_MAX_HEIGHT: MAG_LOZENGE_MAX_HEIGHT, LOZENGE_MIN_WIDTH,
            ROW_GAP, ipRowHeights, ipPairCounts,
            stableIpPairOrderByRow: ipPairOrderByRow,
            subRowHeights: null, subRowOffsets: null,
            mainGroup: svgResult.mainGroup,
            findIPPosition: ip => ipPositions.get(ip),
            ipPositions,
            createTooltipHTML: createFlowLozengeTooltipHTML,
            d3, CLOSE_TYPE_STACK_ORDER,
            separateFlags: false,
            skipSvgRects: false
        });

        // Draw faint row lines for every IP so rows without data are still visible.
        const rowLineData = effectiveIps.map(ip => ({
            ip,
            y: ipPositions.get(ip) ?? 0
        }));
        const rowLinesG = svgResult.fullDomainLayer.append('g').attr('class', 'mag-row-lines');
        rowLinesG.selectAll('.mag-row-line')
            .data(rowLineData)
            .enter().append('line')
            .attr('class', 'mag-row-line')
            .attr('x1', 0)
            .attr('x2', plotW)
            .attr('y1', d => d.y)
            .attr('y2', d => d.y)
            .attr('stroke', '#e0e0e0')
            .attr('stroke-width', 0.5)
            .style('pointer-events', 'none');
        // Move row lines behind lozenges
        rowLinesG.lower();

        const plotHFlow = svgHeight - panelMargin.top - panelMargin.bottom;
        _applyMagnifierGlyphOpacity(svgResult.fullDomainLayer.selectAll('.flow-lozenge'), focusMin, focusMax);

        if (state.ui.showGroundTruth &&
            Array.isArray(state.flows.groundTruth) && state.flows.groundTruth.length > 0) {
            // Use a relaxed filter: show a box on any row whose IP is either the source or
            // destination of a GT event — filterGroundTruthByIPs requires BOTH IPs which
            // would hide all events when the magnifier shows only a subset (e.g. initiators).
            const boxData = [];
            for (const evt of state.flows.groundTruth) {
                const adjStop = evt.stopTimeMicroseconds + 59 * 1_000_000;
                const x = xScale(evt.startTimeMicroseconds);
                const w = Math.max(1, xScale(adjStop) - x);
                const color = (eventColors && eventColors[evt.eventType]) || '#666';
                for (const [ip, isSrc] of [[evt.source, true], [evt.destination, false]]) {
                    const rowY = ipPositions.get(ip);
                    if (rowY === undefined) continue;
                    boxData.push({ evt, ip, x, y: rowY - ROW_GAP * 0.4, width: w, height: ROW_GAP * 0.8, color, isSrc });
                }
            }
            if (boxData.length > 0) {
                const gtGroup = svgResult.mainGroup.append('g').attr('class', 'ground-truth-group');
                gtGroup.selectAll('.mag-gt-box')
                    .data(boxData)
                    .enter().append('rect')
                    .attr('class', 'mag-gt-box')
                    .attr('x', d => d.x)
                    .attr('y', d => d.y)
                    .attr('width', d => d.width)
                    .attr('height', d => d.height)
                    .attr('fill', d => d.color)
                    .attr('fill-opacity', 0.25)
                    .attr('stroke', d => d.color)
                    .attr('stroke-width', 1)
                    .attr('stroke-opacity', 0.7)
                    .style('cursor', 'pointer');
                gtGroup.selectAll('.mag-gt-label')
                    .data(boxData.filter(d => d.width > 50 && d.isSrc))
                    .enter().append('text')
                    .attr('class', 'mag-gt-label')
                    .attr('x', d => d.x + d.width / 2)
                    .attr('y', d => d.y + d.height / 2)
                    .attr('text-anchor', 'middle')
                    .attr('dominant-baseline', 'middle')
                    .attr('fill', '#2c3e50')
                    .attr('font-size', '10px')
                    .style('pointer-events', 'none')
                    .text(d => d.evt.eventType.length > 20 ? d.evt.eventType.substring(0, 17) + '...' : d.evt.eventType);

                const isSameEvt = (a, b) =>
                    a.evt.source === b.evt.source &&
                    a.evt.destination === b.evt.destination &&
                    a.evt.startTimeMicroseconds === b.evt.startTimeMicroseconds;

                const tooltip = d3.select('#tooltip');
                gtGroup.selectAll('.mag-gt-box')
                    .on('mouseover', (event, d) => {
                        const adjStop = d.evt.stopTimeMicroseconds + 59 * 1_000_000;
                        const durationSec = Math.round((adjStop - d.evt.startTimeMicroseconds) / 1_000_000);
                        let stopStr = d.evt.stopTime || epochMicrosecondsToUTC(adjStop).replace(' UTC', '');
                        if (stopStr.includes('.')) stopStr = stopStr.split('.')[0];
                        tooltip.style('display', 'block').html(
                            `<b>${d.evt.eventType}</b><br>` +
                            `IP: ${d.ip} (${d.isSrc ? 'Source' : 'Destination'})<br>` +
                            `From: ${d.evt.source}<br>` +
                            `To: ${d.evt.destination}<br>` +
                            `Start: ${d.evt.startTime || ''}<br>` +
                            `Stop: ${stopStr} (+59s)<br>` +
                            `Duration: ~${durationSec}s`
                        );
                        gtGroup.selectAll('.mag-gt-box')
                            .style('fill-opacity', o => isSameEvt(o, d) ? 0.55 : 0.12)
                            .style('stroke-opacity', o => isSameEvt(o, d) ? 1 : 0.25);
                        gtGroup.selectAll('.mag-gt-label')
                            .style('opacity', o => isSameEvt(o, d) ? 1 : 0.25);
                    })
                    .on('mousemove', (event) => {
                        tooltip.style('left', `${event.pageX + 14}px`).style('top', `${event.pageY - 28}px`);
                    })
                    .on('mouseout', () => {
                        tooltip.style('display', 'none');
                        gtGroup.selectAll('.mag-gt-box')
                            .style('fill-opacity', null)
                            .style('stroke-opacity', null);
                        gtGroup.selectAll('.mag-gt-label').style('opacity', null);
                    });
            }
        }

        const axis  = d3.axisBottom(xScale).ticks(6).tickFormat(t => new Date(t / 1000).toISOString().slice(11, 19));
        svgResult.svg.append('g')
            .attr('class', 'x-axis')
            .attr('transform', `translate(0,${plotHFlow})`)
            .call(axis);

        const ipLabel = document.createElement('div');
        Object.assign(ipLabel.style, {
            position: 'absolute', top: '4px', left: '6px',
            font: '11px/1 monospace', background: 'rgba(255,255,255,0.85)',
            padding: '2px 6px', borderRadius: '2px',
            pointerEvents: 'none', display: 'none'
        });
        body.appendChild(ipLabel);

        const svgNode = svgResult.svg.node();
        svgNode.addEventListener('mousemove', (event) => {
            const [, localY] = d3.pointer(event, svgResult.mainGroup.node());
            if (localY < 0 || localY > plotHFlow) { ipLabel.style.display = 'none'; return; }
            let nearestIp = effectiveIps[0], minDist = Infinity;
            for (const ip of effectiveIps) {
                const dist = Math.abs((ipPositions.get(ip) ?? 0) - localY);
                if (dist < minDist) { minDist = dist; nearestIp = ip; }
            }
            ipLabel.textContent = nearestIp;
            ipLabel.style.display = '';
        });
        svgNode.addEventListener('mouseleave', () => { ipLabel.style.display = 'none'; });

        svgNode.addEventListener('contextmenu', (event) => {
            event.preventDefault();
            const [, localY] = d3.pointer(event, svgResult.mainGroup.node());
            let nearestIp = null, minDist = Infinity;
            for (const ip of effectiveIps) {
                const dist = Math.abs((ipPositions.get(ip) ?? 0) - localY);
                if (dist < minDist) { minDist = dist; nearestIp = ip; }
            }
            // 12px threshold so right-clicks in empty space don't trigger a menu.
            if (nearestIp === null || minDist > 12) return;
            _showHideIPMenu(event.clientX, event.clientY, nearestIp, () => {
                _fastHideIP(nearestIp);
            });
        });
    };

    // Packet tab: shows raw packet records for the same (ips, time range) as
    // the flow tab, rendered as SVG circles colored by flag type and sized by
    // packet count per bin. Data comes from the Parquet packet dataset via
    // _magLoadPacketRows. While the fetch is pending, shows a loading message;
    // on failure, shows a friendly error and leaves the panel usable.
    const renderPacketTab = async (ips, tMin, tMax) => {
        body.innerHTML = '';
        const status = document.createElement('div');
        Object.assign(status.style, {
            padding: '20px', color: '#6c757d', fontSize: '12px', fontFamily: 'monospace'
        });
        status.textContent = 'Loading packets…';
        body.appendChild(status);

        const checkedIPs = new Set(
            Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value)
        );
        let effectiveIps = ips.filter(ip => checkedIPs.has(ip) && !_hiddenIPs.has(ip));
        if (_showInitiatorsOnly) {
            const binnedData = state.flowView && state.flowView.binnedData;
            if (binnedData && binnedData.length > 0) {
                const initiatorSet = new Set(binnedData.map(d => d.initiator).filter(Boolean));
                const filtered = effectiveIps.filter(ip => initiatorSet.has(ip));
                if (filtered.length > 0) effectiveIps = filtered;
            }
        }
        if (effectiveIps.length === 0) {
            body.textContent = 'All IPs in this region have been hidden';
            headerLabel.textContent = '0 IPs';
            return;
        }

        const _FIRST_DEGREE_MAX_TOTAL = 350;
        const memberCount = effectiveIps.length;
        const memberSet = new Set(effectiveIps);
        let neighborsArr = [];
        if (showNeighbors) {
            const fdBinned = state.flowView && state.flowView.binnedData;
            const neighborRows = (fdBinned && fdBinned.length > 0)
                ? fdBinned.map(d => ({ src_ip: d.initiator, dst_ip: d.responder, count: d.count || 1 }))
                : [];
            const ranked = _deriveNeighborsFromRows(memberSet, neighborRows);
            for (const n of ranked) {
                if (memberCount + neighborsArr.length >= _FIRST_DEGREE_MAX_TOTAL) break;
                if (memberSet.has(n.ip)) continue;
                if (!checkedIPs.has(n.ip) || _hiddenIPs.has(n.ip)) continue;
                neighborsArr.push(n.ip);
            }
        }
        const magTimePkt = buildMagTimeExtents(memberSet, neighborsArr, tMin, tMax);
        const { focusMin: pktFocusMin, focusMax: pktFocusMax, viewMin: pktViewMin, viewMax: pktViewMax } = magTimePkt;

        const pending = ensurePacketsLoaded(ips, pktViewMin, pktViewMax);
        let rows;
        try {
            rows = await pending;
        } catch (e) {
            if (currentTab !== 'packets' || pending !== packetRowsPromise) return;
            status.textContent = 'Failed to load packets: ' + ((e && e.message) || e);
            status.style.color = '#b91c1c';
            return;
        }
        if (currentTab !== 'packets' || pending !== packetRowsPromise) return;
        body.innerHTML = '';

        const firstSeen = new Map();
        for (let i = 0; i < rows.length; i++) {
            const r = rows[i];
            if (!r || !r.src_ip) continue;
            const [t0, t1] = _magItemTimeBounds(r);
            if (!_magOverlapsInterval(t0, t1, pktViewMin, pktViewMax)) continue;
            const prev = firstSeen.get(r.src_ip);
            if (prev === undefined || t0 < prev) firstSeen.set(r.src_ip, t0);
        }
        const byTime = (a, b) => (firstSeen.get(a) ?? Infinity) - (firstSeen.get(b) ?? Infinity);
        const members = effectiveIps.slice().sort(byTime);
        neighborsArr.sort(byTime);
        effectiveIps = [...members, ...neighborsArr];

        const ipSet = new Set(effectiveIps);
        const filtered = [];
        for (let i = 0; i < rows.length; i++) {
            const r = rows[i];
            if (!r || !r.src_ip || !ipSet.has(r.src_ip)) continue;
            const [t0, t1] = _magItemTimeBounds(r);
            if (!_magOverlapsInterval(t0, t1, pktViewMin, pktViewMax)) continue;
            filtered.push(r);
        }

        const ipCountLabel = neighborsArr.length > 0
            ? `${memberCount} IPs + ${neighborsArr.length} neighbors`
            : `${effectiveIps.length} IPs`;
        headerLabel.textContent = `${ipCountLabel} · ${filtered.length} packets`;
        bottomBar.textContent = _magnifierBottomBarText(magTimePkt);

        if (filtered.length === 0) {
            const empty = document.createElement('div');
            Object.assign(empty.style, {
                padding: '20px', color: '#6c757d', fontSize: '12px', fontFamily: 'monospace'
            });
            empty.textContent = 'No packets matched this region (the Parquet dataset may not cover these IPs/time).';
            body.appendChild(empty);
            return;
        }

        // Same layout math as renderFlowTab so packets share the visual frame.
        const panelMargin = { top: 10, right: 16, bottom: 28, left: 0 };
        const bodyW = body.clientWidth || panelW;
        const bodyH = body.clientHeight || (panelH - 88);
        const TOP_PAD = 20;
        const availablePlotH = bodyH - panelMargin.top - panelMargin.bottom;
        // Vertical gap separating the member rows (top) from the neighbor rows
        // (bottom). Only inserted when neighbors are present; PKT_ROW_GAP absorbs
        // it so all rows still fit the plot height.
        const BAND_GAP = neighborsArr.length > 0 ? 16 : 0;
        const PKT_ROW_GAP = Math.max(0.1, (availablePlotH - BAND_GAP) / Math.max(1, effectiveIps.length));
        const ipPositions = new Map();
        const ipRowHeights = new Map();
        const ipPairCounts = new Map();
        const ipPairOrderByRow = new Map();
        let y = TOP_PAD;
        for (let i = 0; i < effectiveIps.length; i++) {
            // Drop in the gap once, between the last member and the first neighbor.
            if (BAND_GAP > 0 && i === memberCount) y += BAND_GAP;
            const ip = effectiveIps[i];
            ipPositions.set(ip, y);
            ipRowHeights.set(ip, PKT_ROW_GAP);
            ipPairCounts.set(ip, 1);
            y += PKT_ROW_GAP;
        }

        body.style.overflow = 'hidden';
        const svgResult = createSVGStructure({
            d3,
            containerId: `#mag-body-${uid}`,
            width: bodyW,
            height: bodyH,
            margin: panelMargin,
            dotRadius: 4
        });
        const clipId = `clip-mag-${uid}`;
        svgResult.svg.select('defs clipPath').attr('id', clipId);
        svgResult.mainGroup.attr('clip-path', `url(#${clipId})`);

        const plotW = bodyW - panelMargin.left - panelMargin.right;
        const xScale = d3.scaleLinear().domain([pktViewMin, pktViewMax]).range([0, plotW]);

        // Normalize loader rows so renderCircles sees the field names it expects.
        // loadResolutionPackets already returns _normalizePacketRows output, so
        // most fields are present — this is just a defensive pass for resolutions
        // that emit slightly different shapes (raw vs binned).
        const normalized = filtered.map(r => {
            const t = Number(r.binStart ?? r.bin_start ?? r.timestamp ?? 0);
            const ft = (r.flag_type || r.flagType || 'OTHER').toString().toUpperCase();
            return {
                src_ip: r.src_ip,
                dst_ip: r.dst_ip,
                count: Number(r.count) || 1,
                flagType: ft,
                flag_type: ft,
                timestamp: t,
                binStart: t,
                binCenter: t,
                bin_start: t,
                binned: true,
                length: Number(r.total_bytes) || 0,
                total_bytes: Number(r.total_bytes) || 0
            };
        });

        // Same sub-row collapse the flow tab uses, so multi-pair IPs render on
        // their primary row rather than stacking into hidden sub-lanes.
        const collapsedSet = new Set(effectiveIps);
        const collapsed = collapseSubRowsBins(normalized, collapsedSet);

        const maxCount = d3.max(collapsed, r => r.count) || 1;
        const rScale = d3.scaleSqrt()
            .domain([1, Math.max(1, maxCount)])
            .range([RADIUS_MIN, Math.max(RADIUS_MIN * 2, 6)]);

        renderCircles(svgResult.fullDomainLayer, collapsed, {
            xScale, rScale, flagColors,
            RADIUS_MIN,
            ROW_GAP: PKT_ROW_GAP,
            ipRowHeights, ipPairCounts,
            stableIpPairOrderByRow: ipPairOrderByRow,
            subRowHeights: null, subRowOffsets: null,
            mainGroup: svgResult.mainGroup,
            arcPathGenerator,
            // renderCircles invokes findIPPosition(src, src, dst, pairs, ipPositions).
            // With one row per IP here we only need the first arg.
            findIPPosition: (ip) => ipPositions.get(ip),
            pairs: new Map(),
            ipPositions,
            createTooltipHTML,
            FLAG_CURVATURE,
            d3,
            separateFlags: false
        });

        const plotHPkt = bodyH - panelMargin.top - panelMargin.bottom;
        _applyMagnifierGlyphOpacity(svgResult.fullDomainLayer.selectAll('.direction-dot'), pktFocusMin, pktFocusMax);

        const axis = d3.axisBottom(xScale).ticks(6).tickFormat(t => new Date(t / 1000).toISOString().slice(11, 19));
        svgResult.svg.append('g')
            .attr('class', 'x-axis')
            .attr('transform', `translate(0,${plotHPkt})`)
            .call(axis);

        // IP-label hover affordance, matching the flow tab.
        const ipLabel = document.createElement('div');
        Object.assign(ipLabel.style, {
            position: 'absolute', top: '4px', left: '6px',
            font: '11px/1 monospace', background: 'rgba(255,255,255,0.85)',
            padding: '2px 6px', borderRadius: '2px',
            pointerEvents: 'none', display: 'none'
        });
        body.appendChild(ipLabel);
        const svgNode = svgResult.svg.node();
        svgNode.addEventListener('mousemove', (event) => {
            const [, localY] = d3.pointer(event, svgResult.mainGroup.node());
            if (localY < 0 || localY > plotHPkt) { ipLabel.style.display = 'none'; return; }
            let nearestIp = effectiveIps[0], minDist = Infinity;
            for (const ip of effectiveIps) {
                const dist = Math.abs((ipPositions.get(ip) ?? 0) - localY);
                if (dist < minDist) { minDist = dist; nearestIp = ip; }
            }
            ipLabel.textContent = nearestIp;
            ipLabel.style.display = '';
        });
        svgNode.addEventListener('mouseleave', () => { ipLabel.style.display = 'none'; });
    };

    // Network tab: force-directed graph of IP↔IP connections derived from the
    // same packet rows the Packets tab loads. Edges are aggregated per minute
    // bin (one record per (canonical pair, minute)) and then summed by
    // ForceNetworkLayout's `aggregateForTimeRange(null)`. Only the panel's
    // selected IP subset is used as nodes; edges where both endpoints are in
    // the set are kept.
    const renderNetworkTab = async (ips, tMin, tMax) => {
        body.innerHTML = '';
        destroyNetworkLayout();

        const status = document.createElement('div');
        Object.assign(status.style, {
            padding: '20px', color: '#6c757d', fontSize: '12px', fontFamily: 'monospace'
        });
        status.textContent = 'Loading packets…';
        body.appendChild(status);

        // Use full-capture-extent rows so first-degree neighbors whose traffic
        // falls outside the brushed time window are still visible. Resolution
        // 'seconds' matches get_host_peers and avoids a raw full-capture scan.
        const pending = ensureFullExtentPacketsLoaded(ips);
        // Kick off the meta-map load in parallel with packets — first
        // magnifier render eats the fetch; subsequent renders hit cache.
        const metaPending = _ensureIpMetaMap();
        let rows;
        try {
            rows = await pending;
        } catch (e) {
            if (currentTab !== 'network' || pending !== fullExtentPacketRowsPromise) return;
            status.textContent = 'Failed to load packets: ' + ((e && e.message) || e);
            status.style.color = '#b91c1c';
            return;
        }
        if (currentTab !== 'network' || pending !== fullExtentPacketRowsPromise) return;
        const ipMetaMap = await metaPending;
        if (currentTab !== 'network' || pending !== fullExtentPacketRowsPromise) return;
        body.innerHTML = '';

        // Same IP filtering rules as the other tabs.
        const checkedIPs = new Set(
            Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value)
        );
        let effectiveIps = ips.filter(ip => checkedIPs.has(ip) && !_hiddenIPs.has(ip));
        if (_showInitiatorsOnly) {
            const binnedData = state.flowView && state.flowView.binnedData;
            if (binnedData && binnedData.length > 0) {
                const initiatorSet = new Set(binnedData.map(d => d.initiator).filter(Boolean));
                const filtered = effectiveIps.filter(ip => initiatorSet.has(ip));
                if (filtered.length > 0) effectiveIps = filtered;
            }
        }
        if (effectiveIps.length === 0) {
            body.textContent = 'All IPs in this region have been hidden';
            headerLabel.textContent = '0 IPs';
            return;
        }

        // Node and edge selection: packet-derived, single path for all regions.
        // The role map (if any) is NOT used to include/exclude nodes — it only
        // colors nodes via applyAnomalyFlagStyling below. This keeps Network and
        // TimeArcs on identical data: region members + first-degree neighbors from
        // the full-extent packet rows, capped at 350 total (highest-volume neighbors
        // win when the cap bites).
        const memberSet = new Set(effectiveIps);
        const _FIRST_DEGREE_MAX_TOTAL = 350;

        // Rank externals by volume; admit top-N that keep total ≤ cap.
        // Skipped entirely when the Neighbors toggle is off.
        const externalPartners = new Set();
        if (showNeighbors) {
            const rankedNeighbors = _deriveNeighborsFromRows(memberSet, rows);
            const sortedExternals = rankedNeighbors.map(n => n.ip);
            for (const ip of sortedExternals) {
                if (memberSet.size + externalPartners.size >= _FIRST_DEGREE_MAX_TOTAL) break;
                externalPartners.add(ip);
            }
            // Push admitted neighbors into the node list.
            for (const ip of externalPartners) effectiveIps.push(ip);
        }

        const MIN_US = 60_000_000;
        const magTimeNet = buildMagTimeExtents(memberSet, [...externalPartners], tMin, tMax);
        const netViewMinMinute = Math.floor(magTimeNet.viewMin / MIN_US);
        const netViewMaxMinute = Math.floor(magTimeNet.viewMax / MIN_US);

        // allowedPairs: every unordered pair where both endpoints are admitted
        // (either a region member or a cap-passing external).
        const allAdmitted = new Set(effectiveIps);
        const allowedPairs = new Set();
        for (let i = 0; i < rows.length; i++) {
            const r = rows[i];
            if (!r || !r.src_ip || !r.dst_ip) continue;
            if (!allAdmitted.has(r.src_ip) || !allAdmitted.has(r.dst_ip)) continue;
            const [a, b] = r.src_ip < r.dst_ip ? [r.src_ip, r.dst_ip] : [r.dst_ip, r.src_ip];
            allowedPairs.add(`${a}|${b}`);
        }

        // Two-pass direction resolution so every link carries the real TCP
        // initiator as sourceIp (SYN-only detection; lowest-ts fallback).
        // Rows span full capture; link buckets are clipped to the shared view window.
        const pairInitiator = new Map(); // 'a|b' → initiator IP (SYN-derived)
        const pairFirstTs = new Map();   // 'a|b' → lowest ts seen
        const pairFirstSrc = new Map();  // 'a|b' → src at that lowest-ts row
        for (let i = 0; i < rows.length; i++) {
            const r = rows[i];
            if (!r || !r.src_ip || !r.dst_ip) continue;
            const t = Number(r.binStart ?? r.bin_start ?? r.timestamp ?? 0);
            const [a, b] = r.src_ip < r.dst_ip ? [r.src_ip, r.dst_ip] : [r.dst_ip, r.src_ip];
            const pairKey = `${a}|${b}`;
            if (!allowedPairs.has(pairKey)) continue;
            const flags = Number(r.flags) || 0;
            const isSynOnly = (flags & 0x02) !== 0 && (flags & 0x10) === 0;
            if (isSynOnly && !pairInitiator.has(pairKey)) {
                pairInitiator.set(pairKey, r.src_ip);
            }
            const prevTs = pairFirstTs.get(pairKey);
            if (prevTs == null || t < prevTs) {
                pairFirstTs.set(pairKey, t);
                pairFirstSrc.set(pairKey, r.src_ip);
            }
        }

        // Pass 2: bucket per (pair, minute) using the resolved direction.
        const perPairMinute = new Map();
        for (let i = 0; i < rows.length; i++) {
            const r = rows[i];
            if (!r || !r.src_ip || !r.dst_ip) continue;
            const t = Number(r.binStart ?? r.bin_start ?? r.timestamp ?? 0);
            const [a, b] = r.src_ip < r.dst_ip ? [r.src_ip, r.dst_ip] : [r.dst_ip, r.src_ip];
            const pairKey = `${a}|${b}`;
            if (!allowedPairs.has(pairKey)) continue;
            const minute = Math.floor(t / MIN_US);
            if (minute < netViewMinMinute || minute > netViewMaxMinute) continue;
            const initiator = pairInitiator.get(pairKey) || pairFirstSrc.get(pairKey) || a;
            const responder = initiator === a ? b : a;
            const key = `${pairKey}|${minute}`;
            const cnt = Number(r.count) || 1;
            const prev = perPairMinute.get(key);
            if (prev) prev.count += cnt;
            else perPairMinute.set(key, { sourceIp: initiator, targetIp: responder, count: cnt, minute });
        }

        const links = Array.from(perPairMinute.values());
        const externalSuffix = externalPartners.size > 0 ? ` (+${externalPartners.size} neighbors)` : '';
        headerLabel.textContent = `${effectiveIps.length} IPs${externalSuffix} · ${links.length} pair-minutes`;
        bottomBar.textContent = _magnifierBottomBarText(magTimeNet);

        if (links.length === 0) {
            const empty = document.createElement('div');
            Object.assign(empty.style, {
                padding: '20px', color: '#6c757d', fontSize: '12px', fontFamily: 'monospace'
            });
            empty.textContent = 'No connections between the selected IPs in this time range.';
            body.appendChild(empty);
            return;
        }

        // Build a fresh SVG for the layout to render into. ForceNetworkLayout
        // appends a centered <g> to the container we pass it; it also calls
        // svg.attr('height', ...) so we hand it a d3 selection of the root SVG.
        body.style.overflow = 'hidden';

        // Group-by radio bar — only when the meta map is available (otherwise
        // Country/Org would be no-ops and we don't want to confuse the user).
        // Sits above the SVG; height accounted for in bodyH below.
        let groupBarH = 0;
        {
            const groupBar = document.createElement('div');
            Object.assign(groupBar.style, {
                display: 'flex', gap: '12px', alignItems: 'center',
                padding: '6px 10px', borderBottom: '1px solid #e9ecef',
                background: '#f8f9fa', fontSize: '11px', fontFamily: 'sans-serif',
                userSelect: 'none', flex: '0 0 auto'
            });
            const radioName = `magGroupBy-${Math.random().toString(36).slice(2, 7)}`;
            // Option value → groupBy arg passed to ForceNetworkLayout.setGroupBy.
            // 'none' = flat layout. 'ai' is a sentinel handled locally (separation
            // force), not a real groupBy level. Country/Org only when the meta map
            // is loaded (otherwise they'd be no-ops).
            const OPTIONS = [
                { key: 'none', label: 'None', value: 'none' },
                { key: 'ai', label: 'AI region', value: 'none' },
                { key: 'subnets', label: 'Subnets', value: ['subnet24', 'subnet16', 'internal'] },
            ];
            if (ipMetaMap) {
                OPTIONS.push({ key: 'country', label: 'Country', value: ['subnet24', 'country', 'internal'] });
                OPTIONS.push({ key: 'org', label: 'Org', value: ['subnet24', 'org', 'internal'] });
            }
            // Match current state to one option. AI-separation mode wins; otherwise
            // match the stored groupBy value, falling back to the first option.
            const isSameValue = (a, b) => JSON.stringify(a) === JSON.stringify(b);
            let currentKey;
            if (_magnifierNetworkAISeparate) {
                currentKey = 'ai';
            } else {
                currentKey = (OPTIONS.find(o => o.key !== 'ai' && isSameValue(o.value, _magnifierNetworkGroupBy)) || OPTIONS[0]).key;
            }
            const label = document.createElement('span');
            label.textContent = 'Group:';
            label.style.fontWeight = '600';
            groupBar.appendChild(label);
            for (const opt of OPTIONS) {
                const lab = document.createElement('label');
                Object.assign(lab.style, { display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer' });
                const radio = document.createElement('input');
                radio.type = 'radio';
                radio.name = radioName;
                radio.value = opt.key;
                radio.checked = opt.key === currentKey;
                radio.addEventListener('change', () => {
                    if (!radio.checked) return;
                    if (opt.key === 'ai') {
                        _magnifierNetworkAISeparate = true;
                        _magnifierNetworkGroupBy = 'none';
                    } else {
                        _magnifierNetworkAISeparate = false;
                        _magnifierNetworkGroupBy = opt.value;
                    }
                    if (networkLayout && typeof networkLayout.setGroupBy === 'function') {
                        try {
                            networkLayout.setGroupBy(_magnifierNetworkGroupBy);
                            // setGroupBy rebuilds _nodeData with fresh objects, so the
                            // AI-flagged pinning + red coloring applied after the
                            // initial render are gone. Re-apply on every switch.
                            applyAnomalyFlagStyling();
                            applyAISeparation();
                        } catch (e) { console.warn('[Magnifier] setGroupBy failed:', e); }
                    }
                });
                lab.appendChild(radio);
                const t = document.createElement('span');
                t.textContent = opt.label;
                lab.appendChild(t);
                groupBar.appendChild(lab);
            }
            body.appendChild(groupBar);
            // Measure once after attach so SVG sizing below subtracts the bar's height.
            groupBarH = groupBar.getBoundingClientRect().height || 32;
        }

        const bodyW = body.clientWidth || panelW;
        const bodyH = (body.clientHeight || (panelH - 88)) - groupBarH;
        const margin = { top: 10, right: 10, bottom: 10, left: 10 };

        const svgSel = d3.select(body).append('svg')
            .attr('width', bodyW)
            .attr('height', bodyH)
            .style('display', 'block');
        // Zoom/pan target: ForceNetworkLayout appends a centered <g> into
        // `container`; wrapping it in a zoomable <g> lets the user navigate
        // without disturbing the simulation's internal transforms.
        const zoomG = svgSel.append('g').attr('class', 'mag-network-zoom');
        const container = zoomG.append('g');
        const zoomBehavior = d3.zoom()
            .scaleExtent([0.2, 8])
            .on('zoom', (event) => zoomG.attr('transform', event.transform));
        svgSel.call(zoomBehavior).on('dblclick.zoom', null);

        const tooltip = document.getElementById('tooltip');
        const showTooltip = (tip, event, html) => {
            if (!tip) return;
            tip.innerHTML = html;
            tip.style.display = 'block';
            tip.style.left = (event.clientX + 10) + 'px';
            tip.style.top = (event.clientY + 10) + 'px';
        };
        const hideTooltip = (tip) => { if (tip) tip.style.display = 'none'; };

        const panelDetectedColor = panelAttackType
            ? _attackTypeStyle(panelAttackType).stroke
            : '#dc2626';

        networkLayout = new ForceNetworkLayout({
            d3,
            svg: svgSel,
            width: bodyW,
            // ForceNetworkLayout sizes height from window.innerHeight; cap by
            // passing our body height so it doesn't push the panel taller.
            height: bodyH,
            margin,
            colorForAttack: () => panelDetectedColor,
            tooltip,
            showTooltip,
            hideTooltip,
            // Subnet combos: /24 inside /16 inside Internal. The user can
            // switch to Country or Org via the radio bar above; setGroupBy
            // re-renders the same layout with a different level catalog.
            groupBy: _magnifierNetworkGroupBy,
            // Enables `country` and `org` level defs in ForceNetworkLayout's
            // instance-scoped _levelDefs. Null is fine — those levels just
            // resolve to empty / no-op grouping.
            ipMetaMap: ipMetaMap || null,
            // In the magnifier panel the dataset is small and most solos
            // have moderate degree — hide all solo labels by default so
            // only group/anchor labels are visible until hovered.
            labelDegreeThreshold: Infinity,
        });
        // Noise filter only — no extra grouping layers. effectiveIps was
        // already pruned to AI- or GT-classified survivors above. The layout
        // groups by whatever the user picked in the radio bar (subnets /
        // country / org); no role or AI/GT buckets are added on top.
        // Override the viewport-based height calc by patching margin so the
        // class's `Math.max(400, viewportH - 160)` is still bounded by our SVG.
        // (No clean hook exists; rely on the SVG's fixed height clipping content.)
        function ensureMemberNodeColorHook() {
            if (!networkLayout || networkLayout._magMemberColorHooked) return;
            const orig = networkLayout._nodeColor.bind(networkLayout);
            networkLayout._magOrigNodeColor = orig;
            networkLayout._nodeColor = (nodeData) =>
                memberSet.has(nodeData.id) ? panelDetectedColor : orig(nodeData);
            networkLayout._magMemberColorHooked = true;
        }
        function attachNetworkHoverStylingGuard() {
            if (!networkLayout?._nodeSel || !networkLayout?._linkSel) return;
            const reapply = () => applyAnomalyFlagStyling();
            networkLayout._linkSel
                .on('mouseover.magstyling', reapply)
                .on('mouseout.magstyling', reapply);
            networkLayout._nodeSel.on('mouseout.magstyling', reapply);
        }
        ensureMemberNodeColorHook();
        networkLayout.setData(links, effectiveIps, null, null, 'attack_group');
        networkLayout.aggregateForTimeRange({ min: netViewMinMinute, max: netViewMaxMinute });
        networkLayout.render(container);

        // ForceNetworkLayout sizes its drawing area to the viewport
        // (`Math.max(400, innerHeight-160)`) and resizes the SVG to match,
        // which overflows the panel body. Constrain it to our body size and
        // re-trigger auto-fit so nodes scale into the visible area.
        const fitW = bodyW - margin.left - margin.right;
        const fitH = bodyH - margin.top - margin.bottom;
        networkLayout._drawWidth = fitW;
        networkLayout._drawHeight = fitH;
        networkLayout._cx = margin.left + fitW / 2;
        networkLayout._cy = margin.top + fitH / 2;
        svgSel.attr('height', bodyH);
        if (typeof networkLayout._autoFit === 'function') networkLayout._autoFit();

        // Highlight AI-flagged IPs by recoloring their circles/labels with the
        // panel's AI attack CATEGORY color — the same encoding the TimeArcs tab
        // uses for detected connections (and the header chip / brush rect).
        // User-drawn panels have no category, so fall back to red.
        // IMPORTANT: do NOT pin flagged nodes to a fixed point. Pinning many
        // nodes to the same {fx,fy} stacks them at one coordinate (overlap) and
        // creates a charge-force singularity that flings the remaining nodes
        // around so the layout never settles. When a region is loaded from
        // detector-results.json every member IP is flagged, which made the whole
        // member set collapse onto the center. Clustering of flagged IPs is the
        // job of the "AI region" group mode; here we only recolor.
        // Also actively clear any stale pins so re-renders can't carry them over.
        function applyAnomalyFlagStyling() {
            if (!networkLayout || !networkLayout._nodeData) return;
            ensureMemberNodeColorHook();
            const flagged = _anomalyFlaggedIPs;
            if (flagged) {
                for (const nd of networkLayout._nodeData) {
                    if (flagged.has(nd.id)) { nd.fx = null; nd.fy = null; }
                }
            }
            if (networkLayout._nodeSel) {
                networkLayout._nodeSel.select('circle')
                    .attr('fill', d => networkLayout._nodeColor(d));
                networkLayout._nodeSel.select('text').each(function (d) {
                    const sel = d3.select(this);
                    if (flagged && flagged.has(d.id)) {
                        sel.style('fill', panelDetectedColor).style('font-weight', 'bold');
                    } else {
                        sel.style('fill', '#333').style('font-weight', null);
                    }
                });
            }
            attachNetworkHoverStylingGuard();
        }
        // Pull region members (memberSet) into a left cluster and first-degree
        // neighbors into a right cluster via a custom x-attraction force, while
        // the existing charge/link forces still spread nodes within each side.
        // Toggled by the "AI region" radio; clears the force when off.
        function applyAISeparation() {
            if (!networkLayout || !networkLayout._simulation || !networkLayout._nodeData) return;
            const sim = networkLayout._simulation;
            if (!_magnifierNetworkAISeparate) {
                // Only reheat if we actually have a separation force to tear down.
                // Otherwise the normal (None/Subnets/etc.) initial render must not
                // restart the simulation — doing so makes nodes perpetually jitter.
                if (sim.force('aiSep')) {
                    sim.force('aiSep', null);
                    sim.alpha(0.4).restart();
                }
                return;
            }
            // Centered sim coords: origin = panel center. Offset each cluster from it.
            const offset = Math.max(80, (networkLayout._drawWidth || 400) * 0.28);
            const nodes = networkLayout._nodeData;
            const sepForce = (alpha) => {
                const k = alpha * 0.35;
                for (const nd of nodes) {
                    const targetX = memberSet.has(nd.id) ? -offset : offset;
                    nd.vx = (nd.vx || 0) + (targetX - nd.x) * k;
                }
            };
            sim.force('aiSep', sepForce);
            sim.alpha(0.7).restart();
        }
        applyAnomalyFlagStyling();
        applyAISeparation();

        // Settle the force simulation synchronously so the panel opens with a
        // stable, spread-out layout instead of a live animation. The layout's
        // per-tick handler re-runs _autoFit every frame, which makes the whole
        // graph rescale/recenter continuously ("jumping"); at the clumped start
        // nodes also overlap (dragging one off the pile makes hidden nodes appear
        // to "spawn"). Ticking to completion with the timer stopped, then painting
        // once via _ticked, avoids both. sim.stop() cancels the not-yet-fired
        // animation timer, so no live frame ever runs. Drag still reheats normally.
        {
            const settleSim = networkLayout && networkLayout._simulation;
            if (settleSim) {
                settleSim.stop();
                const decay = settleSim.alphaDecay();
                const nTicks = (decay > 0)
                    ? Math.ceil(Math.log(settleSim.alphaMin()) / Math.log(1 - decay))
                    : 300;
                for (let i = 0; i < nTicks; i++) settleSim.tick();
                // _ticked paints node/link positions AND runs _placePackedMembers,
                // _drawHulls and a final _autoFit, so one call fully syncs the DOM.
                if (typeof networkLayout._ticked === 'function') networkLayout._ticked();
            }
        }
    };

    // TimeArcs tab: minute-binned link arcs between IP rows. Region members
    // (AI-flagged) occupy the top band inside a tinted box; first-degree
    // neighbors sit below a vertical gap. Arcs are black; the tinted box encodes
    // the AI region.
    const renderTimeArcsTab = async (ips, tMin, tMax) => {
        body.innerHTML = '';
        const status = document.createElement('div');
        Object.assign(status.style, {
            padding: '20px', color: '#6c757d', fontSize: '12px', fontFamily: 'monospace'
        });
        status.textContent = 'Loading packets…';
        body.appendChild(status);

        const pending = ensureFullExtentPacketsLoaded(ips);
        let rows;
        try {
            rows = await pending;
        } catch (e) {
            if (currentTab !== 'timearcs' || pending !== fullExtentPacketRowsPromise) return;
            status.textContent = 'Failed to load packets: ' + ((e && e.message) || e);
            status.style.color = '#b91c1c';
            return;
        }
        if (currentTab !== 'timearcs' || pending !== fullExtentPacketRowsPromise) return;
        body.innerHTML = '';

        const checkedIPs = new Set(
            Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')).map(cb => cb.value)
        );
        let effectiveIps = ips.filter(ip => checkedIPs.has(ip) && !_hiddenIPs.has(ip));
        if (_showInitiatorsOnly) {
            const binnedData = state.flowView && state.flowView.binnedData;
            if (binnedData && binnedData.length > 0) {
                const initiatorSet = new Set(binnedData.map(d => d.initiator).filter(Boolean));
                const filtered = effectiveIps.filter(ip => initiatorSet.has(ip));
                if (filtered.length > 0) effectiveIps = filtered;
            }
        }
        if (effectiveIps.length === 0) {
            body.textContent = 'All IPs in this region have been hidden';
            headerLabel.textContent = '0 IPs';
            return;
        }

        // First-degree expansion: include IPs that talked WITH a region member
        // anywhere in the full capture, so neighbors whose traffic falls outside
        // the brushed time window still appear. Capped to keep the row count
        // survivable. Skipped when the Neighbors toggle is off.
        const _FIRST_DEGREE_MAX_TOTAL = 350;
        const memberCount = effectiveIps.length;
        const memberSet = new Set(effectiveIps);
        let neighborsArr = [];
        if (showNeighbors) {
            const neighbors = new Set();
            for (let i = 0; i < rows.length; i++) {
                if (memberCount + neighbors.size >= _FIRST_DEGREE_MAX_TOTAL) break;
                const r = rows[i];
                if (!r || !r.src_ip || !r.dst_ip) continue;
                // No t < tMin / t > tMax guard — full-extent rows.
                const srcInSet = memberSet.has(r.src_ip);
                const dstInSet = memberSet.has(r.dst_ip);
                if (srcInSet && !dstInSet) neighbors.add(r.dst_ip);
                else if (dstInSet && !srcInSet) neighbors.add(r.src_ip);
            }
            neighborsArr = [...neighbors].filter(ip => checkedIPs.has(ip) && !_hiddenIPs.has(ip));
            effectiveIps = [...effectiveIps, ...neighborsArr];
        }

        const magTimeTa = buildMagTimeExtents(memberSet, neighborsArr, tMin, tMax);

        // Bucket per (directed pair, minute). Floor timestamps client-side so
        // minute bins are produced regardless of the loader's resolution.
        // Direction is preserved because linkArc's curvature flips with
        // source.y < target.y, encoding initiator visually.
        // No t < tMin / t > tMax guard — full-extent rows.
        const ipSet = new Set(effectiveIps);
        const MIN_US = 60_000_000;
        const perKey = new Map();
        for (let i = 0; i < rows.length; i++) {
            const r = rows[i];
            if (!r || !r.src_ip || !r.dst_ip) continue;
            if (!ipSet.has(r.src_ip) || !ipSet.has(r.dst_ip)) continue;
            const t = Number(r.binStart ?? r.bin_start ?? r.timestamp ?? 0);
            const minute = Math.floor(t / MIN_US);
            const key = `${r.src_ip}|${r.dst_ip}|${minute}`;
            const cnt = Number(r.count) || 1;
            const prev = perKey.get(key);
            if (prev) prev.count += cnt;
            else perKey.set(key, { src: r.src_ip, dst: r.dst_ip, minute, count: cnt });
        }

        const taViewMinMinute = Math.floor(magTimeTa.viewMin / MIN_US);
        const taViewMaxMinute = Math.ceil(magTimeTa.viewMax / MIN_US);
        const aggregated = Array.from(perKey.values()).filter(d =>
            d.minute >= taViewMinMinute && d.minute <= taViewMaxMinute
        );
        headerLabel.textContent = `${memberCount} IPs + ${neighborsArr.length} neighbors · ${aggregated.length} arcs`;
        bottomBar.textContent = _magnifierBottomBarText(magTimeTa);

        if (aggregated.length === 0) {
            const empty = document.createElement('div');
            Object.assign(empty.style, {
                padding: '20px', color: '#6c757d', fontSize: '12px', fontFamily: 'monospace'
            });
            empty.textContent = 'No connections between the selected IPs in this time range.';
            body.appendChild(empty);
            return;
        }

        // Same row layout as renderPacketTab so visuals stay consistent.
        // left gutter holds the per-row IP labels.
        const panelMargin = { top: 10, right: 16, bottom: 28, left: 110 };
        const bodyW = body.clientWidth || panelW;
        const bodyH = body.clientHeight || (panelH - 88);
        const TOP_PAD = 20;
        const availablePlotH = bodyH - panelMargin.top - panelMargin.bottom;
        // Vertical gap separating the member rows (top) from the neighbor rows
        // (bottom). Only inserted when neighbors are present; ROW_GAP absorbs it
        // so all rows still fit the plot height.
        const BAND_GAP = neighborsArr.length > 0 ? 28 : 0;
        const ROW_GAP = Math.max(0.1, (availablePlotH - BAND_GAP) / Math.max(1, effectiveIps.length));
        const ipPositions = new Map();
        let y = TOP_PAD;
        for (let i = 0; i < effectiveIps.length; i++) {
            // Drop in the gap once, between the last member and the first neighbor.
            if (BAND_GAP > 0 && i === memberCount) y += BAND_GAP;
            ipPositions.set(effectiveIps[i], y);
            y += ROW_GAP;
        }
        const memberBandTop = memberCount > 0
            ? ipPositions.get(effectiveIps[0]) - ROW_GAP / 2
            : TOP_PAD;
        const memberBandBottom = memberCount > 0
            ? ipPositions.get(effectiveIps[memberCount - 1]) + ROW_GAP / 2
            : TOP_PAD;

        body.style.overflow = 'hidden';
        const svgRoot = d3.select(body).append('svg')
            .attr('width', bodyW)
            .attr('height', bodyH)
            .style('display', 'block');
        // Zoom/pan wrapper — same UX as the Network tab.
        const zoomG = svgRoot.append('g').attr('class', 'mag-timearcs-zoom');
        const plotG = zoomG.append('g')
            .attr('transform', `translate(${panelMargin.left},${panelMargin.top})`);
        svgRoot.call(
            d3.zoom().scaleExtent([0.5, 20])
              .on('zoom', (event) => zoomG.attr('transform', event.transform))
        ).on('dblclick.zoom', null);

        const plotW = bodyW - panelMargin.left - panelMargin.right;
        const plotH = bodyH - panelMargin.top - panelMargin.bottom;
        const xScale = d3.scaleLinear().domain([magTimeTa.viewMin, magTimeTa.viewMax]).range([0, plotW]);

        const maxCount = d3.max(aggregated, d => d.count) || 1;
        const strokeScale = d3.scaleSqrt().domain([1, Math.max(1, maxCount)]).range([0.6, 3.5]);

        const ARC_STROKE = '#111';
        const panelStyle = panelAttackType
            ? _attackTypeStyle(panelAttackType)
            : { stroke: '#dc2626', fill: 'rgba(220, 38, 38, 0.08)' };
        const detectedColor = panelStyle.stroke;
        const isMemberArc = (d) => memberSet.has(d.src) && memberSet.has(d.dst);

        // Box around the AI-flagged member band (top rows). Neighbor rows sit
        // below the band gap; arcs that cross the gap are drawn on top of the box.
        if (memberCount > 0) {
            const boxPadX = 6;
            const boxPadY = Math.max(3, ROW_GAP * 0.2);
            plotG.append('rect')
                .attr('class', 'ai-region-box')
                .attr('x', -boxPadX)
                .attr('y', memberBandTop - boxPadY)
                .attr('width', plotW + boxPadX * 2)
                .attr('height', memberBandBottom - memberBandTop + boxPadY * 2)
                .attr('fill', panelStyle.fill || 'rgba(220, 38, 38, 0.08)')
                .attr('stroke', detectedColor)
                .attr('stroke-width', 1)
                .attr('stroke-opacity', 0.55)
                .attr('rx', 4)
                .attr('pointer-events', 'none');
        }
        if (BAND_GAP > 0 && memberCount > 0 && neighborsArr.length > 0) {
            const divY = (memberBandBottom + ipPositions.get(neighborsArr[0]) - ROW_GAP / 2) / 2;
            plotG.append('line')
                .attr('class', 'band-divider')
                .attr('x1', 0).attr('x2', plotW)
                .attr('y1', divY).attr('y2', divY)
                .attr('stroke', '#cbd5e1')
                .attr('stroke-width', 1)
                .attr('stroke-dasharray', '4,3')
                .attr('pointer-events', 'none');
        }

        // Light row guides so very thin rows are still discernible.
        plotG.append('g').selectAll('line.row-guide')
            .data(effectiveIps)
            .join('line')
            .attr('class', 'row-guide')
            .attr('x1', 0).attr('x2', plotW)
            .attr('y1', ip => ipPositions.get(ip))
            .attr('y2', ip => ipPositions.get(ip))
            .attr('stroke', ip => memberSet.has(ip) ? 'rgba(0,0,0,0.06)' : '#eee')
            .attr('stroke-width', 0.5);

        // Build linkArc-shaped objects ({source:{x,y}, target:{x,y}}) from
        // (src,dst,minute) so linkArc's existing geometry produces the arc.
        const arcRecords = aggregated.map(d => {
            // d.minute is a bucket index (floor(t/MIN_US)); convert to µs and
            // shift to bin center.
            const t = d.minute * MIN_US + MIN_US / 2;
            const x = xScale(t);
            const ys = ipPositions.get(d.src);
            const yt = ipPositions.get(d.dst);
            return { ...d, source: { x, y: ys }, target: { x, y: yt } };
        }).filter(d => d.source.y !== d.target.y);
        const memberArcRecords = arcRecords.filter(isMemberArc);
        const crossArcRecords = arcRecords.filter(d => !isMemberArc(d));

        const drawArcLayer = (parent, records, layerCls) =>
            parent.selectAll(`path.${layerCls}`)
                .data(records)
                .join('path')
                .attr('class', `timearc ${layerCls}`)
                .attr('d', d => linkArc(d))
                .attr('fill', 'none')
                .attr('stroke', ARC_STROKE)
                .attr('stroke-width', d => strokeScale(d.count))
                .attr('stroke-opacity', 0.55)
                .attr('pointer-events', 'none');

        // Member-only arcs render inside the AI box; cross-band arcs on top.
        const arcGroup = plotG.append('g');
        const memberArcSel = drawArcLayer(arcGroup, memberArcRecords, 'timearc-member');
        const crossArcSel = drawArcLayer(arcGroup, crossArcRecords, 'timearc-cross');
        const arcSel = memberArcSel.merge(crossArcSel);
        _applyMagnifierGlyphOpacity(arcSel, magTimeTa.focusMin, magTimeTa.focusMax);

        // Connection tooltip on hover. Uses the shared #tooltip element (same
        // pattern as the Network tab's showTooltip). Positioned at the cursor in
        // viewport coords; clampTooltipToPanel keeps it inside the panel.
        const arcTooltip = document.getElementById('tooltip');
        const fmtArcTs = (us) =>
            (typeof formatTimestamp === 'function') ? formatTimestamp(us).utcTime
            : new Date(us / 1000).toISOString().slice(11, 19);
        const arcTooltipHTML = (d) => {
            const isCross = !isMemberArc(d);
            const kind = isCross ? 'cross-band (member ↔ neighbor)'
                : (panelAttackType ? `AI · ${panelAttackType}` : 'AI-flagged coordination');
            const t0 = d.minute * MIN_US;
            return (
                `<div style="font-family:monospace;font-size:11px;line-height:1.5;">`
                + `<div><strong>${d.src}</strong> &rarr; <strong>${d.dst}</strong></div>`
                + `<div>${fmtArcTs(t0)} &ndash; ${fmtArcTs(t0 + MIN_US)}</div>`
                + `<div>count: ${d.count}</div>`
                + `<div>${kind}</div>`
                + `</div>`
            );
        };

        // Transparent wider hit paths carry the hover interaction.
        arcGroup.selectAll('path.timearc-hit')
            .data(arcRecords)
            .join('path')
            .attr('class', 'timearc-hit')
            .attr('d', d => linkArc(d))
            .attr('fill', 'none')
            .attr('stroke', 'transparent')
            .attr('stroke-width', d => Math.max(8, strokeScale(d.count) + 6))
            .attr('pointer-events', 'stroke')
            .style('cursor', 'pointer')
            .on('mouseover', function (event, d) {
                // Highlight the matching visible arc (same datum object).
                arcSel.filter(a => a === d)
                    .attr('stroke-opacity', 1)
                    .attr('stroke-width', a => strokeScale(a.count) + 1.5);
                if (arcTooltip) {
                    arcTooltip.innerHTML = arcTooltipHTML(d);
                    arcTooltip.style.display = 'block';
                    arcTooltip.style.left = (event.clientX + 12) + 'px';
                    arcTooltip.style.top = (event.clientY + 12) + 'px';
                }
            })
            .on('mousemove', (event) => {
                if (arcTooltip && arcTooltip.style.display === 'block') {
                    arcTooltip.style.left = (event.clientX + 12) + 'px';
                    arcTooltip.style.top = (event.clientY + 12) + 'px';
                }
            })
            .on('mouseout', function (event, d) {
                arcSel.filter(a => a === d)
                    .attr('stroke-opacity', 0.55)
                    .attr('stroke-width', a => strokeScale(a.count));
                if (arcTooltip) arcTooltip.style.display = 'none';
            });

        // Per-row IP labels in the left gutter. Members use the panel attack
        // color; neighbors use neutral grey.
        const labelFontPx = Math.max(5, Math.min(11, ROW_GAP - 1));
        plotG.append('g').attr('class', 'mag-timearcs-labels')
            .selectAll('text.row-label')
            .data(effectiveIps)
            .join('text')
            .attr('class', 'row-label')
            .attr('x', -6)
            .attr('y', ip => ipPositions.get(ip))
            .attr('text-anchor', 'end')
            .attr('dominant-baseline', 'middle')
            .attr('font-family', 'monospace')
            .attr('font-size', `${labelFontPx}px`)
            .attr('fill', ip => memberSet.has(ip) ? detectedColor : '#64748b')
            .attr('font-weight', ip => memberSet.has(ip) ? '600' : 'normal')
            .text(ip => ip);

        // Axis along the bottom of the plot (sits in plotG so it pans/zooms with the arcs).
        const axis = d3.axisBottom(xScale).ticks(6)
            .tickFormat(t => new Date(t / 1000).toISOString().slice(11, 19));
        plotG.append('g')
            .attr('class', 'x-axis')
            .attr('transform', `translate(0,${plotH})`)
            .call(axis);

        // IP-label hover affordance, matching other tabs.
        const ipLabel = document.createElement('div');
        Object.assign(ipLabel.style, {
            position: 'absolute', top: '4px', left: '6px',
            font: '11px/1 monospace', background: 'rgba(255,255,255,0.85)',
            padding: '2px 6px', borderRadius: '2px',
            pointerEvents: 'none', display: 'none'
        });
        body.appendChild(ipLabel);
        const svgNode = svgRoot.node();
        svgNode.addEventListener('mousemove', (event) => {
            const [, localY] = d3.pointer(event, plotG.node());
            if (localY < 0 || localY > plotH) { ipLabel.style.display = 'none'; return; }
            let nearestIp = effectiveIps[0], minDist = Infinity;
            for (const ip of effectiveIps) {
                const dist = Math.abs((ipPositions.get(ip) ?? 0) - localY);
                if (dist < minDist) { minDist = dist; nearestIp = ip; }
            }
            ipLabel.textContent = nearestIp
                + (memberSet.has(nearestIp) ? ' (AI region)' : ' (neighbor)');
            ipLabel.style.color = memberSet.has(nearestIp) ? detectedColor : '#64748b';
            ipLabel.style.display = '';
        });
        svgNode.addEventListener('mouseleave', () => { ipLabel.style.display = 'none'; });
    };


    renderActiveTab(ipSubset, tMinUs, tMaxUs);

    return { panel, update: renderActiveTab };
}

// ============================================================================
// Magnifier disk-cache helpers (precompute-magnifier-regions build output).
//
// Cache key algorithm — MUST stay byte-for-byte identical to makeCacheKey()
// in precompute-magnifier-regions.mjs so keys match across build and runtime.
// Algorithm: SHA-1 hex of "<sortedIps.join(',')>|<tMin>|<tMax>|<resolution>".
// ---------------------------------------------------------------------------

// Compute a 40-char hex cache key from call arguments.
// sortedIps must already be sorted.
async function _magMakeCacheKey(sortedIps, tMinUs, tMaxUs, resolution) {
    const payload   = sortedIps.join(',') + '|' + tMinUs + '|' + tMaxUs + '|' + resolution;
    const encoded   = new TextEncoder().encode(payload);
    const hashBuf   = await crypto.subtle.digest('SHA-1', encoded);
    const hex       = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, '0')).join('');
    return hex;
}

// Rehydrate a compact shard row (stored by the build script) back into the
// full _normalizePacketRows output shape.  Must produce byte-identical results
// to _normalizePacketRows for the same source data.
function _magRehydrateRow(c) {
    const binSize   = RES_BIN_SIZE_US[c.resolution] || 1_000_000;
    const binned    = c.binned;
    const halfBin   = Math.floor(binSize / 2);
    const row = {
        timestamp:    c.ts,
        src_ip:       c.src_ip,
        dst_ip:       c.dst_ip,
        count:        c.count,
        total_bytes:  c.total_bytes,
        flag_type:    c.flag_type,
        flagType:     c.flag_type,
        binned,
        resolution:   c.resolution
    };
    if (binned) {
        row.bin_start     = c.ts;
        row.bin_end       = c.ts + binSize;
        row.binStart      = c.ts;
        row.binEnd        = c.ts + binSize;
        row.binCenter     = c.ts + halfBin;
        row.flags         = flagTypeToFlags(c.flag_type);
        row.length        = c.total_bytes;
        row.preBinnedSize = binSize;
    }
    if (c.src_port !== undefined) row.src_port = c.src_port;
    if (c.dst_port !== undefined) row.dst_port = c.dst_port;
    return row;
}

// Load and index the precomputed manifest.  Called once at flow-only chart
// init.  Any failure → _magCache stays null (silent fallback everywhere).
async function _magLoadManifest() {
    _magCache = null;
    const id = _anomalyDatasetId ? _anomalyDatasetId() : null;
    if (!id) return;
    const url = `./magnifier-cache/${id}/manifest.json`;
    try {
        const resp = await fetch(url, { cache: 'no-store' });
        if (!resp.ok) { console.log(`[MagCache] No manifest at ${url} (HTTP ${resp.status}) — live streaming only.`); return; }
        const manifest = await resp.json();
        const byWindowKey  = new Map();
        const byFullKey    = new Map();
        for (const entry of (manifest.regions || [])) {
            if (entry.packets   && entry.packets.key)    byWindowKey.set(entry.packets.key,    entry);
            if (entry.fullExtent && entry.fullExtent.key) byFullKey.set(entry.fullExtent.key,   entry);
        }
        _magCache = { manifest, byWindowKey, byFullKey };
        console.log(`[MagCache] Loaded: ${manifest.regions.length} regions (${byWindowKey.size} window shards, ${byFullKey.size} full-extent shards).`);
    } catch (e) {
        console.log(`[MagCache] Manifest load failed (${e.message}) — live streaming only.`);
    }
}

// Fetch a shard from the cache directory and rehydrate rows.
// Returns null on any error (caller should fall back to live streaming).
async function _magFetchShard(id, shardFile) {
    const url = `./magnifier-cache/${id}/${shardFile}`;
    try {
        const resp = await fetch(url);
        if (!resp.ok) return null;
        const compact = await resp.json();
        return compact.map(_magRehydrateRow);
    } catch (e) {
        return null;
    }
}

// ---------------------------------------------------------------------------
// Load packet rows for a (ips, time range) region. Delegates to the canonical
// loadResolutionPackets with a range filter so chunk-level caching and row
// normalization are shared with the main packet view. Caller filters by IP
// from the returned rows.
//
// Cache-aware: if a precomputed shard exists for (ips, tMin, tMax) it is
// served immediately without hitting parquet.  On any mismatch or fetch error
// the existing live-streaming path runs unchanged.
async function _magLoadPacketRows(ips, tMin, tMax) {
    const durationUs = Math.max(1, tMax - tMin);
    const resolution = _explainPickBytesResolution(durationUs);

    // Cache lookup
    if (_magCache) {
        try {
            const sortedIps = [...ips].sort();
            const key       = await _magMakeCacheKey(sortedIps, tMin, tMax, resolution);
            const entry     = _magCache.byWindowKey.get(key);
            if (entry && entry.packets && entry.packets.shard) {
                const rows = await _magFetchShard(_magCache.manifest.datasetId, entry.packets.shard);
                if (rows !== null) {
                    console.log(`[MagCache] HIT window ${entry.id}: ${rows.length} rows`);
                    return rows;
                }
            }
        } catch (e) {
            // silent — fall through to live streaming
        }
    }

    const ipSet = new Set(ips);
    const acc = [];
    try {
        await streamResolutionPackets(_EXPLAIN_PACKETS_PATH, resolution, { range: [tMin, tMax] }, async (rows) => {
            for (const r of rows) {
                if (r && (ipSet.has(r.src_ip) || ipSet.has(r.dst_ip))) acc.push(r);
            }
        });
    } catch (e) {
        console.warn('[_magLoadPacketRows] stream failed:', e);
    }
    return acc;
}

// Variant of _magLoadPacketRows that pins the loader to a specific resolution
// (e.g. 'minutes') instead of letting _explainPickBytesResolution pick. Used
// by the Network and TimeArcs tabs, which always want minute-binned rows.
// No disk cache for this variant — it uses explicit (tMin, tMax, resolution)
// which may differ from the stored window shard.
async function _magLoadPacketRowsAtResolution(ips, tMin, tMax, resolution) {
    const ipSet = new Set(ips);
    const acc = [];
    try {
        await streamResolutionPackets(_EXPLAIN_PACKETS_PATH, resolution, { range: [tMin, tMax] }, async (rows) => {
            for (const r of rows) {
                if (r && (ipSet.has(r.src_ip) || ipSet.has(r.dst_ip))) acc.push(r);
            }
        });
    } catch (e) {
        console.warn('[_magLoadPacketRowsAtResolution] stream failed:', e);
    }
    return acc;
}

// Load packet rows for a set of IPs over the FULL capture extent (not just the
// brushed time window). Used by the Network and TimeArcs tabs so that first-
// degree neighbors whose traffic falls before or after the brushed window are
// still visible. Uses 'minutes' resolution over state.data.timeExtent.
//
// Cache-aware: if a precomputed full-extent shard exists for this IP set it is
// served immediately.  Any mismatch or fetch error falls back to live streaming.
async function _magLoadPacketRowsFullExtent(ips) {
    const extent = (state.data && state.data.timeExtent) || [0, Date.now() * 1000];

    // Cache lookup
    if (_magCache) {
        try {
            const sortedIps = [...ips].sort();
            const key       = await _magMakeCacheKey(sortedIps, extent[0], extent[1], 'minutes');
            const entry     = _magCache.byFullKey.get(key);
            if (entry && entry.fullExtent && entry.fullExtent.shard) {
                const rows = await _magFetchShard(_magCache.manifest.datasetId, entry.fullExtent.shard);
                if (rows !== null) {
                    console.log(`[MagCache] HIT fullExtent ${entry.id}: ${rows.length} rows`);
                    return rows;
                }
            }
        } catch (e) {
            // silent — fall through to live streaming
        }
    }

    const ipSet = new Set(ips);
    const acc = [];
    try {
        await streamResolutionPackets(_EXPLAIN_PACKETS_PATH, 'minutes', { range: extent }, async (rows) => {
            for (const r of rows) {
                if (r && (ipSet.has(r.src_ip) || ipSet.has(r.dst_ip))) acc.push(r);
            }
        });
    } catch (e) {
        console.warn('[_magLoadPacketRowsFullExtent] stream failed:', e);
    }
    return acc;
}

// Rank a region's first-degree neighbors from already-loaded packet rows.
// "Neighbor" = an IP that appears opposite a region member in a row where
// EXACTLY ONE endpoint is a member. Ranked by summed packet count (volume),
// descending. Also tracks direction (member as src => outbound to neighbor;
// member as dst => inbound from neighbor). Shared by the Network tab and the
// Explain payload so both see identical neighbors.
function _deriveNeighborsFromRows(memberSet, rows) {
    const agg = new Map(); // ip -> {flows, inFlows, outFlows}
    for (let i = 0; i < rows.length; i++) {
        const r = rows[i];
        if (!r || !r.src_ip || !r.dst_ip) continue;
        const srcIn = memberSet.has(r.src_ip);
        const dstIn = memberSet.has(r.dst_ip);
        if (srcIn === dstIn) continue; // need exactly one member endpoint
        const neighborIp = srcIn ? r.dst_ip : r.src_ip;
        if (!neighborIp) continue;
        const cnt = Number(r.count) || 1;
        let e = agg.get(neighborIp);
        if (!e) { e = { flows: 0, inFlows: 0, outFlows: 0 }; agg.set(neighborIp, e); }
        e.flows += cnt;
        if (srcIn) e.outFlows += cnt; else e.inFlows += cnt; // member->neighbor = outbound
    }
    return Array.from(agg.entries())
        .map(([ip, e]) => ({
            ip,
            flows: e.flows,
            inFlows: e.inFlows,
            outFlows: e.outFlows,
            direction: (e.outFlows > 0 && e.inFlows > 0) ? 'both' : (e.outFlows > 0 ? 'outbound' : 'inbound')
        }))
        .sort((a, b) => b.flows - a.flows);
}

async function exportFlowOnlyAsPNG() {
    if (!mainWebGLRenderer || !mainWebGLRenderer.canvas) {
        alert('WebGL view not initialized');
        return;
    }
    if (!xScale || !xScale.domain) {
        alert('Scale not ready');
        return;
    }

    const chartContainerEl = document.getElementById('chart-container');
    if (!chartContainerEl) {
        alert('Chart container missing');
        return;
    }

    // Build the download filename up front.
    const now = new Date();
    const pad = v => String(v).padStart(2, '0');
    const stamp = `${now.getFullYear()}${pad(now.getMonth()+1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
    const filename = `tcp-flow-export-${stamp}.png`;

    // Acquire the save target NOW, within the user-activation window and BEFORE
    // the heavy render/encode. Writing through a file handle goes straight to
    // disk and creates no "download" event, so download-manager extensions
    // can't intercept and rename it (the bug that saved exports as a blob UUID
    // with no .png extension). Falls back to an anchor download if unsupported.
    let fileHandle = null;
    if (window.showSaveFilePicker) {
        try {
            fileHandle = await window.showSaveFilePicker({
                suggestedName: filename,
                types: [{ description: 'PNG image', accept: { 'image/png': ['.png'] } }]
            });
        } catch (e) {
            // Includes AbortError. Do NOT dead-end here: an AbortError can mean
            // the picker couldn't be shown (not just a user cancel), so always
            // fall through to the anchor download so the user still gets a file.
            console.warn('[ExportPNG] showSaveFilePicker did not return a handle, falling back to anchor download:', e && e.name, e && e.message);
            fileHandle = null;
        }
    } else {
        console.warn('[ExportPNG] showSaveFilePicker not available — using anchor download');
    }

    // Full content dimensions — exactly what the user scrolls through.
    const margin = mainWebGLRenderer.margin;
    const chartWidth = mainWebGLRenderer.chartWidth;
    const fullWidth = margin.left + chartWidth + margin.right;
    const fullHeight = height + margin.top + margin.bottom;  // `height` is the module-level plot height

    // Save current render state so we can restore after the snapshot.
    const prevScrollTop = chartContainerEl.scrollTop;
    const prevViewportH = chartContainerEl.clientHeight;

    // STEP 1 — force a full-height render. No yields after this until drawImage completes.
    mainWebGLRenderer.render(xScale, 0, fullHeight);

    // STEP 2 — immediately blit the WebGL canvas to a 2D canvas (same tick).
    const out = document.createElement('canvas');
    out.width  = mainWebGLRenderer.canvas.width;
    out.height = mainWebGLRenderer.canvas.height;
    const ctx = out.getContext('2d');
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, out.width, out.height);
    ctx.drawImage(mainWebGLRenderer.canvas, 0, 0);
    // Also blit the overlay canvas (ground-truth boxes, etc.) if it's visible.
    if (mainWebGLRenderer.overlayCanvas) {
        ctx.drawImage(mainWebGLRenderer.overlayCanvas, 0, 0);
    }

    // STEP 3 — restore the live WebGL render so the user's view is unaffected.
    mainWebGLRenderer.render(xScale, prevScrollTop, prevViewportH);

    // STEP 4 — draw IP labels and x-axis on the 2D canvas in CSS-pixel space.
    // The WebGL canvas backing store is scaled by devicePixelRatio, so apply a matching transform.
    const dpr = window.devicePixelRatio || 1;
    ctx.save();
    ctx.scale(dpr, dpr);

    // IP labels — right-aligned in the left margin, at each ipPositions[ip] (margin.top already
    // applied inside the WebGL shader via offsetY = margin.top - scrollTop, so add it here too).
    ctx.fillStyle = '#212529';
    ctx.font = '10px monospace';
    ctx.textAlign = 'end';
    ctx.textBaseline = 'middle';
    for (const ip of state.layout.ipOrder) {
        const yPos = state.layout.ipPositions.get(ip);
        if (yPos == null) continue;
        ctx.fillText(ip, margin.left - 4, margin.top + yPos);
    }

    // X-axis at the bottom of the plot.
    const axisY = margin.top + height;
    const [r0, r1] = xScale.range();
    ctx.strokeStyle = '#666';
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(margin.left + r0, axisY);
    ctx.lineTo(margin.left + r1, axisY);
    ctx.stroke();
    ctx.fillStyle = '#333';
    ctx.font = '10px sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    const ticks = xScale.ticks(8);
    const tickFormat = xScale.tickFormat(8);
    for (const t of ticks) {
        const tx = margin.left + xScale(t);
        ctx.beginPath();
        ctx.moveTo(tx, axisY);
        ctx.lineTo(tx, axisY + 5);
        ctx.stroke();
        ctx.fillText(tickFormat(t), tx, axisY + 8);
    }

    ctx.restore();

    // STEP 4.5 — composite the AI region / anomaly rectangles. They live as SVG
    // rects in the content-sized `.magnifier-brush-overlay` (same coordinate
    // space as the WebGL render), so redraw them from their computed styles.
    // Serializing the SVG would drop the d3-brush styling, hence the manual redraw.
    const overlayEl = chartContainerEl.querySelector('.magnifier-brush-overlay');
    if (overlayEl) {
        const ovRect = overlayEl.getBoundingClientRect();
        ctx.save();
        ctx.scale(dpr, dpr);
        overlayEl.querySelectorAll('rect.selection, rect.mag-anomaly-hit').forEach(r => {
            const rb = r.getBoundingClientRect();
            if (rb.width < 1 || rb.height < 1) return;
            const x = rb.left - ovRect.left;
            const y = rb.top - ovRect.top;
            const cs = getComputedStyle(r);
            const fill = r.getAttribute('fill') || cs.fill;
            const stroke = r.getAttribute('stroke') || cs.stroke;
            const sw = parseFloat(r.getAttribute('stroke-width') || cs.strokeWidth) || 1;
            const so = parseFloat(r.getAttribute('stroke-opacity') ?? cs.strokeOpacity);
            const fo = parseFloat(r.getAttribute('fill-opacity') ?? cs.fillOpacity);
            if (fill && fill !== 'none' && fill !== 'rgba(0, 0, 0, 0)') {
                ctx.globalAlpha = isNaN(fo) ? 1 : fo;
                ctx.fillStyle = fill;
                ctx.fillRect(x, y, rb.width, rb.height);
            }
            if (stroke && stroke !== 'none' && stroke !== 'rgba(0, 0, 0, 0)') {
                ctx.globalAlpha = isNaN(so) ? 1 : so;
                ctx.strokeStyle = stroke;
                ctx.lineWidth = sw;
                ctx.strokeRect(x, y, rb.width, rb.height);
            }
            ctx.globalAlpha = 1;
        });
        ctx.restore();
    }

    // STEP 5 — encode, then save. Prefer a direct disk write via the file handle
    // (bypasses download-manager extensions); fall back to an anchor download.
    const blob = await new Promise(resolve => out.toBlob(resolve, 'image/png'));
    if (!blob) {
        alert('PNG export failed (toBlob returned null — canvas may exceed browser limits)');
        return;
    }
    console.log('[ExportPNG] encoded blob', (blob.size / 1048576).toFixed(2), 'MB as', filename);

    if (fileHandle) {
        try {
            const writable = await fileHandle.createWritable();
            await writable.write(blob);
            await writable.close();
            console.log('[ExportPNG] saved via file handle (no download-history entry is expected)');
            return;
        } catch (e) {
            console.error('[ExportPNG] file-handle write failed, falling back to anchor:', e);
            // fall through to anchor download
        }
    }

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 60000);
}

// --- AI ordering helpers (in-browser replication of order_ips_by_pattern.py) ---

// One-time cache for the finest flow_bins file (large; re-fetching wastes time
// on every filter change). The cache is binData-only — the cluster order is
// always recomputed because it depends on the current visible IPs / hidden
// flow legend types.
let _aiOrderBinDataCache = null;
async function _aiOrderEnsureBinData() {
    if (_aiOrderBinDataCache) return _aiOrderBinDataCache;
    _aiOrderBinDataCache = await _aiOrderLoadFinestBinFile();
    return _aiOrderBinDataCache;
}

// Pick the finest-resolution flow_bins file from flow_bins_index.json and
// return its v2 array data. Mirrors the Python script which reads per-flow
// parquet rows: at 1s resolution, each bin's per-pair counts equal the number
// of flows that started in that bin, so re-quantizing to 10s reproduces the
// Python sparse matrix exactly.
async function _aiOrderLoadFinestBinFile() {
    const base = _flowOnlyBasePath || (typeof DEFAULT_FLOW_DATA_PATH !== 'undefined' ? DEFAULT_FLOW_DATA_PATH : null);
    if (!base) return null;

    let resolutions = null;
    if (adaptiveOverviewLoader && adaptiveOverviewLoader.index) {
        resolutions = adaptiveOverviewLoader.index.resolutions;
    } else {
        try {
            const r = await fetch(`${base}/indices/flow_bins_index.json`);
            if (!r.ok) return null;
            const idx = await r.json();
            resolutions = idx && idx.resolutions;
        } catch (e) { return null; }
    }
    if (!resolutions) return null;

    let finestKey = null, finestFile = null, finestWidth = Infinity;
    for (const [key, cfg] of Object.entries(resolutions)) {
        const w = cfg && cfg.bin_width_us;
        if (w && w < finestWidth) { finestWidth = w; finestKey = key; finestFile = cfg.file; }
    }
    if (!finestKey) return null;

    if (adaptiveOverviewLoader && adaptiveOverviewLoader.loadResolution) {
        try { return await adaptiveOverviewLoader.loadResolution(finestKey); }
        catch (e) { /* fall through to direct fetch */ }
    }
    if (!finestFile) return null;
    try {
        const r = await fetch(`${base}/indices/${finestFile}`);
        if (!r.ok) return null;
        if (finestFile.endsWith('.gz')) {
            const stream = r.body.pipeThrough(new DecompressionStream('gzip'));
            return JSON.parse(await new Response(stream).text());
        }
        return await r.json();
    } catch (e) { return null; }
}

// Build a sparse matrix row → {cols, vals} from a v2 flow_bins array
// ([{bin, start, end, flows_by_ip_pair: {pairKey: {graceful, abortive,
// ongoing, open, invalid:{...}}}}]). Each per-pair total contributes to both
// IPs' rows at the 10s bin index, matching order_ips_by_pattern.py.
function _aiOrderBuildSparse(binData, tStart, nBins) {
    const BIN_WIDTH_US = 10_000_000;
    const acc = new Map();
    const addTo = (ip, bin, v) => {
        let row = acc.get(ip);
        if (!row) { row = new Map(); acc.set(ip, row); }
        row.set(bin, (row.get(bin) || 0) + v);
    };
    if (Array.isArray(binData)) {
        for (const bin of binData) {
            if (!bin || !bin.flows_by_ip_pair) continue;
            const binIdx = Math.min(nBins - 1, Math.max(0, Math.floor((bin.start - tStart) / BIN_WIDTH_US)));
            for (const [pairKey, pairData] of Object.entries(bin.flows_by_ip_pair)) {
                if (!pairData) continue;
                let total = (pairData.graceful || 0) + (pairData.abortive || 0)
                          + (pairData.ongoing || 0)  + (pairData.open || 0);
                if (pairData.invalid) {
                    for (const v of Object.values(pairData.invalid)) total += v || 0;
                }
                if (total <= 0) continue;
                const sep = pairKey.indexOf('<->');
                if (sep < 0) continue;
                const ip1 = pairKey.slice(0, sep);
                const ip2 = pairKey.slice(sep + 3);
                addTo(ip1, binIdx, total);
                addTo(ip2, binIdx, total);
            }
        }
    }
    const ipList = [...acc.keys()];
    const rows = ipList.map(ip => {
        const m = acc.get(ip);
        const cols = new Int32Array(m.size);
        const vals = new Float64Array(m.size);
        let i = 0;
        for (const [c, v] of m) { cols[i] = c; vals[i] = v; i++; }
        return { cols, vals };
    });
    return { ipList, rows };
}

// Variant of _aiOrderBuildSparse that restricts rows to the given visibleIPSet
// and skips per-pair counts whose closeType is in hiddenFlowLegendTypes. When
// visibleIPSet is null, all IPs in the data are considered. Used to recompute
// AI ordering on the post-filter subset rather than the full dataset.
function _aiOrderBuildSparseFiltered(binData, tStart, nBins, visibleIPSet) {
    const BIN_WIDTH_US = 10_000_000;
    const acc = new Map();
    const addTo = (ip, bin, v) => {
        let row = acc.get(ip);
        if (!row) { row = new Map(); acc.set(ip, row); }
        row.set(bin, (row.get(bin) || 0) + v);
    };
    const hideGraceful = hiddenFlowLegendTypes.has('graceful');
    const hideAbortive = hiddenFlowLegendTypes.has('abortive');
    const hideOngoing  = hiddenFlowLegendTypes.has('ongoing') || hiddenFlowLegendTypes.has('incomplete');
    const hideOpen     = hiddenFlowLegendTypes.has('open');
    if (Array.isArray(binData)) {
        for (const bin of binData) {
            if (!bin || !bin.flows_by_ip_pair) continue;
            const binIdx = Math.min(nBins - 1, Math.max(0, Math.floor((bin.start - tStart) / BIN_WIDTH_US)));
            for (const [pairKey, pairData] of Object.entries(bin.flows_by_ip_pair)) {
                if (!pairData) continue;
                let total = 0;
                if (!hideGraceful) total += pairData.graceful || 0;
                if (!hideAbortive) total += pairData.abortive || 0;
                if (!hideOngoing)  total += pairData.ongoing  || 0;
                if (!hideOpen)     total += pairData.open     || 0;
                if (pairData.invalid) {
                    for (const [reason, v] of Object.entries(pairData.invalid)) {
                        if (!hiddenFlowLegendTypes.has(reason)) total += v || 0;
                    }
                }
                if (total <= 0) continue;
                const sep = pairKey.indexOf('<->');
                if (sep < 0) continue;
                const ip1 = pairKey.slice(0, sep);
                const ip2 = pairKey.slice(sep + 3);
                if (!visibleIPSet || visibleIPSet.has(ip1)) addTo(ip1, binIdx, total);
                if (!visibleIPSet || visibleIPSet.has(ip2)) addTo(ip2, binIdx, total);
            }
        }
    }
    const ipList = [...acc.keys()];
    const rows = ipList.map(ip => {
        const m = acc.get(ip);
        const cols = new Int32Array(m.size);
        const vals = new Float64Array(m.size);
        let i = 0;
        for (const [c, v] of m) { cols[i] = c; vals[i] = v; i++; }
        return { cols, vals };
    });
    return { ipList, rows };
}

// log1p + L2-normalize rows in-place. Returns false for zero-norm rows (marks them).
function _aiOrderNormalizeRows(rows) {
    const keep = new Uint8Array(rows.length);
    for (let r = 0; r < rows.length; r++) {
        const { vals } = rows[r];
        let norm2 = 0;
        for (let i = 0; i < vals.length; i++) {
            vals[i] = Math.log1p(vals[i]);
            norm2 += vals[i] * vals[i];
        }
        if (norm2 === 0) { keep[r] = 0; continue; }
        keep[r] = 1;
        const inv = 1 / Math.sqrt(norm2);
        for (let i = 0; i < vals.length; i++) vals[i] *= inv;
    }
    return keep;
}

// Sparse M*v product (length nRows).
function _sparseMv(rows, v) {
    const u = new Float64Array(rows.length);
    for (let r = 0; r < rows.length; r++) {
        const { cols, vals } = rows[r];
        let s = 0;
        for (let i = 0; i < cols.length; i++) s += vals[i] * v[cols[i]];
        u[r] = s;
    }
    return u;
}

// Sparse M^T * u product (length nBins).
function _sparseMTu(rows, u, nBins) {
    const v = new Float64Array(nBins);
    for (let r = 0; r < rows.length; r++) {
        const { cols, vals } = rows[r];
        const ur = u[r];
        if (ur === 0) continue;
        for (let i = 0; i < cols.length; i++) v[cols[i]] += vals[i] * ur;
    }
    return v;
}

// Dot product of two Float64Arrays.
function _dot(a, b) {
    let s = 0;
    for (let i = 0; i < a.length; i++) s += a[i] * b[i];
    return s;
}

// L2 norm of a Float64Array.
function _norm(a) {
    let s = 0;
    for (let i = 0; i < a.length; i++) s += a[i] * a[i];
    return Math.sqrt(s);
}

// Normalize a Float64Array in-place; returns the original norm.
function _normalizeVec(a) {
    const n = _norm(a);
    if (n > 0) for (let i = 0; i < a.length; i++) a[i] /= n;
    return n;
}

// Truncated SVD via power iteration with implicit deflation.
// Returns reduced matrix: Float64Array of shape [nRows * k] (row-major).
function _aiOrderSVD(rows, nRows, nBins, k) {
    k = Math.min(k, nRows - 1, nBins - 1, nRows, nBins);
    if (k <= 0) return { reduced: new Float64Array(nRows), k: 1 };

    const deflations = []; // [{u, v, sigma}]
    const reduced = new Float64Array(nRows * k);

    // Deterministic LCG seed for reproducible v init.
    let lcgState = 1234567891;
    const lcgNext = () => {
        lcgState = (Math.imul(1664525, lcgState) + 1013904223) >>> 0;
        return lcgState / 0x100000000;
    };

    for (let comp = 0; comp < k; comp++) {
        // Random init for v
        let v = new Float64Array(nBins);
        for (let i = 0; i < nBins; i++) v[i] = lcgNext() - 0.5;
        _normalizeVec(v);

        // Power iterations with deflation
        for (let iter = 0; iter < 50; iter++) {
            // Apply deflations to v: v_eff = v - Σ (v_j·v) v_j * sigma_j / ...
            // We use: Mv_eff = sparseMv(v) - Σ_j sigma_j * u_j * (v_j · v)
            let u = _sparseMv(rows, v);
            for (const d of deflations) {
                const vj_dot_v = _dot(d.v, v);
                const scale = d.sigma * vj_dot_v;
                for (let i = 0; i < u.length; i++) u[i] -= scale * d.u[i];
            }

            // v_new = M^T u_eff = sparseMTu(u) - Σ_j sigma_j * v_j * (u_j · u)
            let vNew = _sparseMTu(rows, u, nBins);
            for (const d of deflations) {
                const uj_dot_u = _dot(d.u, u);
                const scale = d.sigma * uj_dot_u;
                for (let i = 0; i < vNew.length; i++) vNew[i] -= scale * d.v[i];
            }

            const norm = _normalizeVec(vNew);
            if (norm === 0) break;

            // Convergence check
            let diff = 0;
            for (let i = 0; i < nBins; i++) diff += (vNew[i] - v[i]) ** 2;
            v = vNew;
            if (Math.sqrt(diff) < 1e-6) break;
        }

        // Compute sigma and u for this component
        let uFinal = _sparseMv(rows, v);
        for (const d of deflations) {
            const vj_dot_v = _dot(d.v, v);
            const scale = d.sigma * vj_dot_v;
            for (let i = 0; i < uFinal.length; i++) uFinal[i] -= scale * d.u[i];
        }
        const sigma = _norm(uFinal);
        if (sigma < 1e-12) break; // deflated to nothing
        const uUnit = new Float64Array(uFinal.length);
        for (let i = 0; i < uFinal.length; i++) uUnit[i] = uFinal[i] / sigma;

        // Store reduced coords: reduced[i*k + comp] = sigma * u[i]
        for (let i = 0; i < nRows; i++) reduced[i * k + comp] = sigma * uUnit[i];

        deflations.push({ u: uUnit, v: v.slice(), sigma });
    }

    return { reduced, k };
}

// Ward hierarchical clustering → DFS leaf order.
// reduced is Float64Array [nRows * k], row-major.
// Uses nearest-neighbor-chain Ward (same Lance-Williams criterion scipy uses)
// on the reduced k-dim embedding directly, so memory is O(n*k) instead of
// O(n²) — required to scale past ~1k IPs without OOM. Falls back to argsort
// by component 0 only on exception. Yields to the UI thread every YIELD_EVERY
// merges so a progress bar can repaint.
async function _aiOrderWard(reduced, nRows, k, onProgress) {
    if (nRows <= 1) return nRows === 1 ? [0] : [];

    try {
        const maxNodes = 2 * nRows - 1;
        const centroids = new Float64Array(maxNodes * k);
        centroids.set(reduced.subarray(0, nRows * k));
        const sizes = new Int32Array(maxNodes);
        const active = new Uint8Array(maxNodes);
        const childL = new Int32Array(maxNodes); childL.fill(-1);
        const childR = new Int32Array(maxNodes); childR.fill(-1);
        for (let i = 0; i < nRows; i++) { sizes[i] = 1; active[i] = 1; }

        // Active cluster ids; max 2n-1 entries before any compaction.
        const activeIds = new Int32Array(maxNodes);
        for (let i = 0; i < nRows; i++) activeIds[i] = i;
        let nActive = nRows;

        const chain = new Int32Array(maxNodes);
        let chainLen = 0;

        let nextNode = nRows;
        let mergesDone = 0;
        const COMPACT_EVERY = 1024;
        const YIELD_EVERY = 500;
        let lastCompact = 0;
        let lastYield = 0;

        while (mergesDone < nRows - 1) {
            if (chainLen === 0) {
                let start = -1;
                for (let i = 0; i < nActive; i++) {
                    if (active[activeIds[i]]) { start = activeIds[i]; break; }
                }
                if (start < 0) break;
                chain[chainLen++] = start;
            }

            const top = chain[chainLen - 1];
            const prev = chainLen >= 2 ? chain[chainLen - 2] : -1;
            const topBase = top * k;
            const topSize = sizes[top];

            // Find Ward-NN of top among active clusters.
            let nn = -1, nnDist = Infinity;
            for (let i = 0; i < nActive; i++) {
                const j = activeIds[i];
                if (!active[j] || j === top) continue;
                const jBase = j * k;
                const jSize = sizes[j];
                let sum = 0;
                for (let c = 0; c < k; c++) {
                    const d = centroids[topBase + c] - centroids[jBase + c];
                    sum += d * d;
                }
                const dist = (topSize * jSize) / (topSize + jSize) * sum;
                if (dist < nnDist) { nnDist = dist; nn = j; }
                else if (dist === nnDist && j === prev) { nn = j; }
            }
            if (nn < 0) break;

            if (nn === prev) {
                // Reciprocal pair → merge
                chainLen -= 2;
                const a = top, b = nn;
                const merged = nextNode++;
                const na = sizes[a], nb = sizes[b];
                const total = na + nb;
                const aBase = a * k, bBase = b * k, mBase = merged * k;
                for (let c = 0; c < k; c++) {
                    centroids[mBase + c] = (centroids[aBase + c] * na + centroids[bBase + c] * nb) / total;
                }
                sizes[merged] = total;
                active[a] = 0;
                active[b] = 0;
                active[merged] = 1;
                activeIds[nActive++] = merged;
                childL[merged] = a;
                childR[merged] = b;
                mergesDone++;

                if (mergesDone - lastCompact >= COMPACT_EVERY) {
                    let w = 0;
                    for (let r = 0; r < nActive; r++) {
                        const id = activeIds[r];
                        if (active[id]) activeIds[w++] = id;
                    }
                    nActive = w;
                    lastCompact = mergesDone;
                }
                if (mergesDone - lastYield >= YIELD_EVERY) {
                    lastYield = mergesDone;
                    if (onProgress) {
                        try { onProgress(mergesDone, nRows - 1); } catch (e) {}
                    }
                    await new Promise(r => setTimeout(r, 0));
                }
            } else {
                chain[chainLen++] = nn;
            }
        }
        if (onProgress) {
            try { onProgress(nRows - 1, nRows - 1); } catch (e) {}
        }

        // DFS leaf order from root
        const root = nextNode - 1;
        const order = new Array(nRows);
        let oi = 0;
        const stack = new Int32Array(maxNodes);
        let sp = 0;
        stack[sp++] = root;
        while (sp > 0) {
            const node = stack[--sp];
            if (node < nRows) { order[oi++] = node; continue; }
            const r = childR[node];
            const l = childL[node];
            if (r >= 0) stack[sp++] = r;
            if (l >= 0) stack[sp++] = l;
        }
        return order;
    } catch (e) {
        console.warn('[FlowOnly] Ward clustering failed, falling back to SVD sort:', e);
        const idx = Array.from({ length: nRows }, (_, i) => i);
        idx.sort((a, b) => reduced[a * k] - reduced[b * k]);
        return idx;
    }
}

async function loadAIOrderLive() {
    // ── Ordering cache: serve cached result for full/default view ──────────
    await _orderingEnsureLoaded();
    if (_orderingIsFullDefault() && Array.isArray(_orderingFullOrders.ai_live) && _orderingFullOrders.ai_live.length) {
        _flowOnlyAIOrderLive = _orderingFullOrders.ai_live.slice();
        return _flowOnlyAIOrderLive;
    }

    let progressOpen = false;
    const showStep = (label, pct) => {
        try {
            if (!progressOpen) { sbShowCsvProgress(label, pct); progressOpen = true; }
            else { sbUpdateCsvProgress(pct, label); }
        } catch (e) {}
    };
    const closeProgress = () => {
        if (progressOpen) {
            try { sbHideCsvProgress(); } catch (e) {}
            progressOpen = false;
        }
    };
    // Yield to the UI thread so the progress bar can repaint between phases.
    const yieldToUI = () => new Promise(r => requestAnimationFrame(() => r()));

    console.time('[FlowOnly] AI ordering');
    try {
        showStep('AI ordering: loading flow bins…', 0.05);
        await yieldToUI();
        const binData = await _aiOrderEnsureBinData();
        if (!Array.isArray(binData) || binData.length === 0) {
            console.warn('[FlowOnly] loadAIOrderLive: finest flow_bins file unavailable, cannot compute AI order');
            console.timeEnd('[FlowOnly] AI ordering');
            closeProgress();
            return null;
        }

        const [tStart, tEnd] = _flowOnlyRawTimeExtent || state.data.timeExtent || [0, 1];
        const BIN_WIDTH_US = 10_000_000;
        const nBins = Math.max(1, Math.ceil((tEnd - tStart) / BIN_WIDTH_US));

        // Restrict the IP×time matrix to the currently visible IPs (passed the
        // IP filter and not right-click hidden) and skip per-pair counts whose
        // closeType is hidden by the Flow Types legend. Falls back to all IPs
        // when no checkboxes exist yet (initial load before UI is wired).
        const checkedIPs = Array.from(
            document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')
        ).map(cb => cb.value).filter(ip => !_hiddenIPs.has(ip));
        const visibleIPSet = checkedIPs.length > 0 ? new Set(checkedIPs) : null;

        showStep('AI ordering: building IP×time matrix…', 0.15);
        await yieldToUI();
        const { ipList, rows } = _aiOrderBuildSparseFiltered(binData, tStart, nBins, visibleIPSet);
        const nIps = ipList.length;
        if (nIps === 0) { console.timeEnd('[FlowOnly] AI ordering'); closeProgress(); return null; }

        showStep(`AI ordering: normalizing ${nIps} rows…`, 0.20);
        await yieldToUI();
        const keep = _aiOrderNormalizeRows(rows);
        const keptIPs = ipList.filter((_, i) => keep[i]);
        const keptRows = rows.filter((_, i) => keep[i]);
        const nKept = keptIPs.length;
        if (nKept === 0) { console.timeEnd('[FlowOnly] AI ordering'); closeProgress(); return null; }

        showStep(`AI ordering: SVD on ${nKept} IPs × ${nBins} bins…`, 0.25);
        await yieldToUI();
        const K = 16;
        const { reduced, k } = _aiOrderSVD(keptRows, nKept, nBins, K);

        showStep(`AI ordering: Ward clustering ${nKept} IPs (this may take a minute)…`, 0.40);
        await yieldToUI();
        const leafOrder = await _aiOrderWard(reduced, nKept, k, (done, total) => {
            const pct = 0.40 + (total > 0 ? (done / total) * 0.55 : 0);
            showStep(`AI ordering: Ward clustering ${done.toLocaleString()} / ${total.toLocaleString()} merges…`, pct);
        });

        _flowOnlyAIOrderLive = leafOrder.map(i => keptIPs[i]);
        // ── Ordering cache: persist result when no filter is active ──────
        if (_orderingIsFullDefault() && Array.isArray(_flowOnlyAIOrderLive) && _flowOnlyAIOrderLive.length) {
            _orderingFullOrders.ai_live = _flowOnlyAIOrderLive.slice();
            _orderingDiskLoadedForId = _anomalyDatasetId();
            _orderingPersistSave();
            try { _orderingWriteToLinkedFile(); } catch (e) {}
        }
        showStep('AI ordering: done', 1.0);
        setTimeout(closeProgress, 400);
    } catch (e) {
        console.warn('[FlowOnly] AI ordering failed:', e);
        _flowOnlyAIOrderLive = null;
        closeProgress();
    }
    console.timeEnd('[FlowOnly] AI ordering');
    return _flowOnlyAIOrderLive;
}

// Compute the Fiedler vector of the normalized graph Laplacian
// L_sym = I − D^{−1/2} W' D^{−1/2}, where W' is the IP×IP cosine similarity
// matrix WITH ITS DIAGONAL ZEROED (W' = X·Xᵀ − I, since rows of X are
// L2-normalized so W[i,i] = 1). Removing self-loops sharpens the spectral
// gap: the principal eigenvector v0 ∝ √d′ is more dominant relative to the
// Fiedler, which makes deflated power iteration converge crisper and lets
// smaller off-axis clusters separate instead of blending into the principal
// gradient. The trick is to power-iterate on M = D^{−1/2} W' D^{−1/2}
// (largest eigenvalue 1, eigenvector v0), deflating against v0 each step;
// the iterate converges to L_sym's Fiedler. Memory is O(n + nnz); the n×n
// similarity matrix is never materialized.
async function _aiOrderFiedler(rows, nRows, nBins, progress) {
    const yieldToUI = () => new Promise(r => requestAnimationFrame(() => r()));

    // Off-diagonal degree d′[i] = (W − I)·1 [i] = (X · Xᵀ · 1)[i] − 1, since
    // L2-normalized rows give W[i,i] = 1. Guard against negative/zero d′ from
    // floating-point noise or genuinely isolated nodes (W = identity row).
    const ones = new Float64Array(nRows);
    for (let i = 0; i < nRows; i++) ones[i] = 1;
    const xt1 = _sparseMTu(rows, ones, nBins);   // length nBins
    const d   = _sparseMv(rows, xt1);            // length nRows; d_i = (X Xᵀ 1)_i
    for (let i = 0; i < nRows; i++) d[i] = Math.max(0, d[i] - 1);

    const dinv_sqrt = new Float64Array(nRows);
    for (let i = 0; i < nRows; i++) {
        dinv_sqrt[i] = d[i] > 0 ? 1 / Math.sqrt(d[i]) : 0;
    }

    // Principal eigenvector of M (eigenvalue 1): v0 ∝ sqrt(d′).
    const v0 = new Float64Array(nRows);
    let v0Norm2 = 0;
    for (let i = 0; i < nRows; i++) {
        const s = Math.sqrt(d[i]);
        v0[i] = s;
        v0Norm2 += s * s;
    }
    if (v0Norm2 === 0) {
        // Degenerate: empty / fully-disconnected graph. Return identity order.
        const order = new Array(nRows);
        for (let i = 0; i < nRows; i++) order[i] = i;
        return order;
    }
    const v0NormInv = 1 / Math.sqrt(v0Norm2);
    for (let i = 0; i < nRows; i++) v0[i] *= v0NormInv;

    // Random init, deflate, normalize.
    let x = new Float64Array(nRows);
    for (let i = 0; i < nRows; i++) x[i] = Math.random() - 0.5;
    let proj = _dot(v0, x);
    for (let i = 0; i < nRows; i++) x[i] -= proj * v0[i];
    if (_normalizeVec(x) === 0) {
        // Extremely unlucky init landed exactly on v0 — re-seed.
        for (let i = 0; i < nRows; i++) x[i] = (i + 1) % 2 - 0.5;
        proj = _dot(v0, x);
        for (let i = 0; i < nRows; i++) x[i] -= proj * v0[i];
        _normalizeVec(x);
    }

    const ITERS = 120;
    const tmp = new Float64Array(nRows);
    for (let iter = 0; iter < ITERS; iter++) {
        // y = M·x = D^{−1/2} ⊙ ((W − I) · (D^{−1/2} ⊙ x))
        //        = D^{−1/2} ⊙ (X·Xᵀ·tmp − tmp), where tmp = D^{−1/2} ⊙ x.
        for (let i = 0; i < nRows; i++) tmp[i] = dinv_sqrt[i] * x[i];
        const intermediate = _sparseMTu(rows, tmp, nBins);
        const y = _sparseMv(rows, intermediate);
        for (let i = 0; i < nRows; i++) y[i] = dinv_sqrt[i] * (y[i] - tmp[i]);
        // Deflate against v0 (Rayleigh-quotient subtraction).
        proj = _dot(v0, y);
        for (let i = 0; i < nRows; i++) y[i] -= proj * v0[i];
        if (_normalizeVec(y) === 0) break;
        x = y;
        if (progress && (iter % 10 === 0)) {
            progress(iter, ITERS);
            await yieldToUI();
        }
    }
    if (progress) progress(ITERS, ITERS);

    // Sort indices by Fiedler-vector value (ascending). This is the natural
    // sweep through the graph implied by L_sym.
    const order = new Array(nRows);
    for (let i = 0; i < nRows; i++) order[i] = i;
    order.sort((a, b) => x[a] - x[b]);
    return order;
}

// Async loader for spectral / Fiedler ordering. Mirrors loadAIOrderLive: uses
// the cached binData, builds an IP×time sparse matrix restricted to currently
// visible IPs and visible close-types, normalizes rows, then runs the Fiedler
// power iteration. Always recomputes — the result depends on filter state.
async function loadFiedlerOrderLive() {
    // ── Ordering cache: serve cached result for full/default view ──────────
    await _orderingEnsureLoaded();
    if (_orderingIsFullDefault() && Array.isArray(_orderingFullOrders.fiedler) && _orderingFullOrders.fiedler.length) {
        _flowOnlyFiedlerOrderLive = _orderingFullOrders.fiedler.slice();
        return _flowOnlyFiedlerOrderLive;
    }

    let progressOpen = false;
    const showStep = (label, pct) => {
        try {
            if (!progressOpen) { sbShowCsvProgress(label, pct); progressOpen = true; }
            else { sbUpdateCsvProgress(pct, label); }
        } catch (e) {}
    };
    const closeProgress = () => {
        if (progressOpen) {
            try { sbHideCsvProgress(); } catch (e) {}
            progressOpen = false;
        }
    };
    const yieldToUI = () => new Promise(r => requestAnimationFrame(() => r()));

    console.time('[FlowOnly] Fiedler ordering');
    try {
        showStep('Spectral ordering: loading flow bins…', 0.05);
        await yieldToUI();
        const binData = await _aiOrderEnsureBinData();
        if (!Array.isArray(binData) || binData.length === 0) {
            console.warn('[FlowOnly] loadFiedlerOrderLive: finest flow_bins file unavailable');
            console.timeEnd('[FlowOnly] Fiedler ordering');
            closeProgress();
            return null;
        }

        const [tStart, tEnd] = _flowOnlyRawTimeExtent || state.data.timeExtent || [0, 1];
        const BIN_WIDTH_US = 10_000_000;
        const nBins = Math.max(1, Math.ceil((tEnd - tStart) / BIN_WIDTH_US));

        const checkedIPs = Array.from(
            document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')
        ).map(cb => cb.value).filter(ip => !_hiddenIPs.has(ip));
        const visibleIPSet = checkedIPs.length > 0 ? new Set(checkedIPs) : null;

        showStep('Spectral ordering: building IP×time matrix…', 0.15);
        await yieldToUI();
        const { ipList, rows } = _aiOrderBuildSparseFiltered(binData, tStart, nBins, visibleIPSet);
        const nIps = ipList.length;
        if (nIps === 0) { console.timeEnd('[FlowOnly] Fiedler ordering'); closeProgress(); return null; }

        showStep(`Spectral ordering: normalizing ${nIps} rows…`, 0.20);
        await yieldToUI();
        const keep = _aiOrderNormalizeRows(rows);
        const keptIPs = ipList.filter((_, i) => keep[i]);
        const keptRows = rows.filter((_, i) => keep[i]);
        const nKept = keptIPs.length;
        if (nKept < 2) { console.timeEnd('[FlowOnly] Fiedler ordering'); closeProgress(); return null; }

        showStep(`Spectral ordering: power iteration on ${nKept} IPs…`, 0.30);
        await yieldToUI();
        const order = await _aiOrderFiedler(keptRows, nKept, nBins, (done, total) => {
            const pct = 0.30 + (total > 0 ? (done / total) * 0.65 : 0);
            showStep(`Spectral ordering: iteration ${done}/${total}…`, pct);
        });

        _flowOnlyFiedlerOrderLive = order.map(i => keptIPs[i]);
        // ── Ordering cache: persist result when no filter is active ──────
        if (_orderingIsFullDefault() && Array.isArray(_flowOnlyFiedlerOrderLive) && _flowOnlyFiedlerOrderLive.length) {
            _orderingFullOrders.fiedler = _flowOnlyFiedlerOrderLive.slice();
            _orderingDiskLoadedForId = _anomalyDatasetId();
            _orderingPersistSave();
            try { _orderingWriteToLinkedFile(); } catch (e) {}
        }
        showStep('Spectral ordering: done', 1.0);
        setTimeout(closeProgress, 400);
    } catch (e) {
        console.warn('[FlowOnly] Fiedler ordering failed:', e);
        _flowOnlyFiedlerOrderLive = null;
        closeProgress();
    }
    console.timeEnd('[FlowOnly] Fiedler ordering');
    return _flowOnlyFiedlerOrderLive;
}

// Async loader for the region_cluster ordering. Mirrors loadFiedlerOrderLive:
// serves the cached full/default order when the region signature matches,
// otherwise computes via _computeRegionClusterOrder and persists (full/default
// only). Cheap to compute, but cached for parity with the other orders so the
// committed ordering-cache.json carries it too.
async function loadRegionClusterOrderLive() {
    await _orderingEnsureLoaded();
    const sig = _regionClusterSignature(_anomalyLastRegions);
    if (sig !== ''
        && _orderingIsFullDefault()
        && Array.isArray(_orderingFullOrders.region_cluster) && _orderingFullOrders.region_cluster.length
        && _orderingFullOrders.region_cluster_sig === sig) {
        _flowOnlyRegionClusterOrderLive = _orderingFullOrders.region_cluster.slice();
        return _flowOnlyRegionClusterOrderLive;
    }

    const ips = (getEffectiveFlowIPs() || _flowOnlyAllIPs || []).slice();
    const firstTs = new Map(ips.map(ip => [ip, _flowOnlyIPStats?.[ip]?.first_ts ?? null]));
    const order = _computeRegionClusterOrder(ips, _anomalyLastRegions, firstTs);
    _flowOnlyRegionClusterOrderLive = order; // null when no usable regions

    if (order && order.length && sig !== '' && _orderingIsFullDefault()) {
        _orderingFullOrders.region_cluster = order.slice();
        _orderingFullOrders.region_cluster_sig = sig;
        _orderingDiskLoadedForId = _anomalyDatasetId();
        _orderingPersistSave();
        try { _orderingWriteToLinkedFile(); } catch (e) {}
    }
    return _flowOnlyRegionClusterOrderLive;
}

// For each IP in `ips`, find the dominant visible close-type bucket and sort
// by (bucket priority, total visible count desc). Anomalous categories
// (invalid_*, abortive) bubble to the top so attack-like IPs cluster first.
// Reads state.flowView.binnedData and respects the Flow Types legend via
// isFlowItemHiddenByLegend — items in hidden buckets are skipped.
function _sortByDominantCloseType(ips) {
    const ipSet = new Set(ips);
    const tally = new Map();      // ip -> Map<bucket, count>
    const totalByIP = new Map();  // ip -> sum of visible counts
    const binnedData = state.flowView && state.flowView.binnedData;
    if (Array.isArray(binnedData)) {
        for (const item of binnedData) {
            if (!item || !item.initiator || !ipSet.has(item.initiator)) continue;
            if (isFlowItemHiddenByLegend(item)) continue;
            const bucket = item.closeType;
            if (!bucket) continue;
            const c = item.count || 0;
            if (c <= 0) continue;
            const ip = item.initiator;
            let buckets = tally.get(ip);
            if (!buckets) { buckets = new Map(); tally.set(ip, buckets); }
            buckets.set(bucket, (buckets.get(bucket) || 0) + c);
            totalByIP.set(ip, (totalByIP.get(ip) || 0) + c);
        }
    }
    const dominantByIP = new Map();
    for (const [ip, buckets] of tally) {
        let best = null, bestCount = -1;
        for (const [bucket, count] of buckets) {
            if (count > bestCount) { bestCount = count; best = bucket; }
        }
        dominantByIP.set(ip, best);
    }
    // Lower priority = sorts to top.
    const priorityOf = (bucket) => {
        if (!bucket) return 99;
        if (bucket === 'graceful') return 5;
        if (bucket === 'open') return 4;
        if (bucket === 'ongoing') return 3;
        if (bucket === 'incomplete') return 2;
        if (bucket === 'abortive') return 1;
        // Anything else (invalid_ack, rst_during_handshake, incomplete_no_synack,
        // incomplete_no_ack, invalid_synack, unknown_invalid, …) is treated as
        // "anomalous" and surfaces first.
        return 0;
    };
    return [...ips].sort((a, b) => {
        const pa = priorityOf(dominantByIP.get(a));
        const pb = priorityOf(dominantByIP.get(b));
        if (pa !== pb) return pa - pb;
        return (totalByIP.get(b) || 0) - (totalByIP.get(a) || 0);
    });
}

// For each IP in `ips`, build a per-time-bin total (across visible close-types)
// and compute coefficient of variation CV = std/mean over the universe of
// distinct binStart values present in state.flowView.binnedData. Sorting by CV
// desc surfaces IPs whose activity is concentrated in few bins. Inactive bins
// count as zeros, so a single-burst IP has CV ≫ 1 while a steady-rate IP has
// CV ≈ 0. IPs with no visible bins sort to the bottom.
function _sortByBurstiness(ips) {
    const ipSet = new Set(ips);
    const seriesByIP = new Map();    // ip -> Map<binStart, count>
    const allBinStarts = new Set();  // universe of bins (for counting zeros)
    const binnedData = state.flowView && state.flowView.binnedData;
    if (Array.isArray(binnedData)) {
        for (const item of binnedData) {
            if (!item || item.binStart === undefined) continue;
            if (isFlowItemHiddenByLegend(item)) continue;
            allBinStarts.add(item.binStart);
            if (!ipSet.has(item.initiator)) continue;
            const c = item.count || 0;
            if (c <= 0) continue;
            const ip = item.initiator;
            let series = seriesByIP.get(ip);
            if (!series) { series = new Map(); seriesByIP.set(ip, series); }
            series.set(item.binStart, (series.get(item.binStart) || 0) + c);
        }
    }
    const nBins = Math.max(1, allBinStarts.size);
    const cvByIP = new Map();
    for (const ip of ips) {
        const series = seriesByIP.get(ip);
        if (!series || series.size === 0) { cvByIP.set(ip, -Infinity); continue; }
        let sum = 0, sumSq = 0;
        for (const v of series.values()) { sum += v; sumSq += v * v; }
        const mean = sum / nBins;
        if (mean === 0) { cvByIP.set(ip, -Infinity); continue; }
        // Var(X) = E[X²] − E[X]², treating bins without a series entry as 0.
        const variance = Math.max(0, sumSq / nBins - mean * mean);
        cvByIP.set(ip, Math.sqrt(variance) / mean);
    }
    return [...ips].sort((a, b) => (cvByIP.get(b) ?? -Infinity) - (cvByIP.get(a) ?? -Infinity));
}

// Compact signature of the AI regions used to build a region_cluster order.
// The clustered order depends on region membership (unlike Ward/Fiedler, which
// depend only on flow data), so the disk cache is invalidated when this changes.
function _regionClusterSignature(regions) {
    if (!Array.isArray(regions) || regions.length === 0) return '';
    const parts = regions.map(r => {
        const ips = Array.isArray(r.ips) ? r.ips : [];
        const first = ips.length ? ips[0] : '';
        const last = ips.length ? ips[ips.length - 1] : '';
        return (typeof r.tMinUs === 'number' ? r.tMinUs : '') + '|' +
               (r.responder || '') + '|' + ips.length + '|' + first + '|' + last;
    }).sort();
    const s = parts.join(';');
    let h = 5381;
    for (let i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
    return (h >>> 0).toString(36) + ':' + regions.length;
}

// Secondary grouping pass: reorder an existing base order so each AI region's
// members form a contiguous block, anchored at the block's earliest (lowest
// base-rank) owned member. Ungrouped IPs interleave by base rank. Shared IPs are
// owned place-once by the region with the lowest anchor. Records ip->region-key
// ownership in _clusteredOwnerByIP and sets _clusteringActive so the variable-gap
// region layout + tight overlay boxes apply. Returns baseOrder unchanged (and
// clears clustered state) when no region has any member in the pool.
function _computeClusteredOrder(baseOrder, regions) {
    _clusteredSharedByIP.clear();
    const baseRank = new Map(baseOrder.map((ip, i) => [ip, i]));
    const pool = new Set(baseOrder);

    // Anchor a block by its ATTACKERS only: a long-lived victim ("responder")
    // often has very small first_seen and would otherwise drag the whole block
    // to its position even though the anomaly is the attackers. The responder
    // stays a block member (placed contiguously), it just doesn't drive WHERE.
    const attackerAnchor = (members, respKey) => {
        let a = Infinity;
        for (const ip of members) if (ip !== respKey) a = Math.min(a, baseRank.get(ip));
        // Fallback for the rare region whose only usable member is the responder.
        if (a === Infinity) for (const ip of members) a = Math.min(a, baseRank.get(ip));
        return a;
    };

    const respByKey = new Map();
    const regs = regions.map((r, idx) => {
        const members = [];
        const seen = new Set();
        const add = ip => { if (ip && pool.has(ip) && !seen.has(ip)) { seen.add(ip); members.push(ip); } };
        if (Array.isArray(r.ips)) r.ips.forEach(add);
        if (r.responder) add(r.responder);
        const key = _regionBlockKey(r);
        const respKey = (typeof r.responder === 'string' && pool.has(r.responder)) ? r.responder : null;
        respByKey.set(key, respKey);
        const anchor = attackerAnchor(members, respKey);
        return { idx, key, anchor, count: members.length, members };
    }).filter(reg => reg.count > 0);

    if (regs.length === 0) {
        _clusteredOwnerByIP.clear();
        _clusteredSharedByIP.clear();
        _clusteringActive = false;
        return baseOrder;
    }

    // Identify shared responders: responder IPs that appear as responder in >=2 regions
    // that each have pool members. Build a map of responder -> Set of all sharing region keys.
    const respRegionKeys = new Map(); // responder ip -> [regionKey, anchor] pairs
    for (const reg of regs) {
        const respKey = respByKey.get(reg.key);
        if (respKey !== null) {
            if (!respRegionKeys.has(respKey)) respRegionKeys.set(respKey, []);
            respRegionKeys.get(respKey).push({ regionKey: reg.key, anchor: reg.anchor });
        }
    }
    const sharedResp = new Set();
    const newSharedByIP = new Map();
    for (const [ip, entries] of respRegionKeys) {
        if (entries.length >= 2) {
            sharedResp.add(ip);
            newSharedByIP.set(ip, new Set(entries.map(e => e.regionKey)));
        }
    }

    // Place-once ownership: smallest region wins so a small specific region's
    // members aren't stripped by a large meta-region they happen to overlap with.
    // Ties: earlier attacker-anchor wins, then region order.
    // Shared responders are excluded from ownership — they get bridge units instead.
    regs.sort((a, b) => (a.count - b.count) || (a.anchor - b.anchor) || (a.idx - b.idx));
    const owner = new Map();
    const ownedMembers = new Map();   // region key -> [owned ips]
    for (const reg of regs) {
        for (const ip of reg.members) {
            if (sharedResp.has(ip)) continue; // skip shared responders from place-once ownership
            if (!owner.has(ip)) {
                owner.set(ip, reg.key);
                if (!ownedMembers.has(reg.key)) ownedMembers.set(reg.key, []);
                ownedMembers.get(reg.key).push(ip);
            }
        }
    }

    // Interleave units: ungrouped IP at its base rank, block at its attacker-anchor,
    // and bridge units for shared responders anchored at the min anchor of sharing regions.
    const units = [];
    for (const ip of baseOrder) {
        if (!owner.has(ip) && !sharedResp.has(ip)) units.push({ key: baseRank.get(ip), ip });
    }
    for (const [key, ips] of ownedMembers) {
        if (!ips.length) continue;
        const anchor = attackerAnchor(ips, respByKey.get(key));
        const sorted = ips.slice().sort((a, b) => baseRank.get(a) - baseRank.get(b));
        units.push({ key: anchor, block: sorted });
    }
    // Bridge units for shared responders: anchor at the minimum attacker-anchor of sharing regions
    for (const [ip, sharingKeys] of newSharedByIP) {
        let minAnchor = Infinity;
        for (const reg of regs) {
            if (sharingKeys.has(reg.key)) minAnchor = Math.min(minAnchor, reg.anchor);
        }
        if (minAnchor === Infinity) minAnchor = baseRank.has(ip) ? baseRank.get(ip) : 0;
        units.push({ key: minAnchor, bridge: ip });
    }
    units.sort((a, b) => a.key - b.key);   // Array.prototype.sort is stable in V8

    const order = [];
    for (const u of units) {
        if (u.bridge) { order.push(u.bridge); }
        else if (u.block) { for (const ip of u.block) order.push(ip); }
        else order.push(u.ip);
    }

    _clusteredOwnerByIP = owner;
    _clusteredSharedByIP = newSharedByIP;
    _clusteringActive = true;
    return order;
}

// Apply region grouping to a base order iff the "Group rows by AI region"
// checkbox is on AND a detection has produced regions. Otherwise returns the
// base order untouched and clears the clustered-layout state.
function _maybeClusterOrder(baseOrder) {
    const on = document.getElementById('groupByRegion')?.checked;
    if (on && Array.isArray(_anomalyLastRegions) && _anomalyLastRegions.length
        && Array.isArray(baseOrder) && baseOrder.length) {
        return _computeClusteredOrder(baseOrder, _anomalyLastRegions);
    }
    _clusteredOwnerByIP.clear();
    _clusteredSharedByIP.clear();
    _clusteringActive = false;
    return baseOrder;
}

// Build a row order that gathers each AI region's members (its attackers
// `region.ips` plus its victim `region.responder`) into a contiguous block.
// Regions are laid down in ascending tMinUs order so concurrent/overlapping
// regions sit adjacent; an IP claimed by an earlier region is not moved again.
// `firstTs` is a Map<ip, first_seen_us|null> used for stable intra-block order.
// Returns null when there are no usable regions (caller falls back).
function _computeRegionClusterOrder(ips, regions, firstTs) {
    if (!Array.isArray(regions) || regions.length === 0) return null;
    const pool = new Set(ips);
    const ftsOf = ip => {
        const v = firstTs.get(ip);
        return (v === undefined || v === null) ? Infinity : v;
    };
    const byTime = (a, b) => (ftsOf(a) - ftsOf(b)) || (a < b ? -1 : a > b ? 1 : 0);

    const regs = regions.map((r, idx) => {
        const members = [];
        const seen = new Set();
        const add = ip => {
            if (ip && pool.has(ip) && !seen.has(ip)) { seen.add(ip); members.push(ip); }
        };
        if (Array.isArray(r.ips)) r.ips.forEach(add);
        if (r.responder) add(r.responder);
        const tMin = (typeof r.tMinUs === 'number') ? r.tMinUs : Infinity;
        return { idx, tMin, count: members.length, members };
    }).filter(reg => reg.count > 0);

    if (regs.length === 0) return null;

    regs.sort((a, b) => (a.tMin - b.tMin) || (b.count - a.count) || (a.idx - b.idx));

    const placed = new Set();
    const order = [];
    for (const reg of regs) {
        const block = reg.members.filter(ip => !placed.has(ip)).sort(byTime);
        for (const ip of block) { placed.add(ip); order.push(ip); }
    }
    const rest = ips.filter(ip => !placed.has(ip)).sort(byTime);
    for (const ip of rest) order.push(ip);
    return order;
}

function sortIPsByMode(ips, mode) {
    const stats = _flowOnlyIPStats;
    if (mode === 'activity_total' && stats) {
        return [...ips].sort((a, b) => {
            const va = (stats[a]?.sent_packets ?? 0) + (stats[a]?.recv_packets ?? 0);
            const vb = (stats[b]?.sent_packets ?? 0) + (stats[b]?.recv_packets ?? 0);
            return vb - va;
        });
    }
    if (mode === 'activity_initiator' && stats) {
        return [...ips].sort((a, b) => {
            const va = stats[a]?.sent_packets ?? 0;
            const vb = stats[b]?.sent_packets ?? 0;
            return vb - va;
        });
    }
    if (mode === 'flow_count' && Array.isArray(state.flowView?.binnedData) && state.flowView.binnedData.length > 0) {
        const counts = new Map();
        for (const item of state.flowView.binnedData) {
            if (!item || !item.initiator) continue;
            counts.set(item.initiator, (counts.get(item.initiator) || 0) + (item.count || 0));
        }
        return [...ips].sort((a, b) => (counts.get(b) || 0) - (counts.get(a) || 0));
    }
    if (mode === 'dominant_close') return _sortByDominantCloseType(ips);
    if (mode === 'burstiness') return _sortByBurstiness(ips);
    if (mode === 'ai_live' && _flowOnlyAIOrderLive) {
        const rank = new Map(_flowOnlyAIOrderLive.map((ip, i) => [ip, i]));
        return [...ips].sort((a, b) => (rank.get(a) ?? Infinity) - (rank.get(b) ?? Infinity));
    }
    if (mode === 'fiedler' && _flowOnlyFiedlerOrderLive) {
        const rank = new Map(_flowOnlyFiedlerOrderLive.map((ip, i) => [ip, i]));
        return [...ips].sort((a, b) => (rank.get(a) ?? Infinity) - (rank.get(b) ?? Infinity));
    }
    if (mode === 'region_cluster') {
        if (_flowOnlyRegionClusterOrderLive && _flowOnlyRegionClusterOrderLive.length) {
            const rank = new Map(_flowOnlyRegionClusterOrderLive.map((ip, i) => [ip, i]));
            return [...ips].sort((a, b) => (rank.get(a) ?? Infinity) - (rank.get(b) ?? Infinity));
        }
        // Loader hasn't run (or no regions) — compute directly so ordering still works.
        const firstTs = new Map(ips.map(ip => [ip, stats?.[ip]?.first_ts ?? null]));
        const order = _computeRegionClusterOrder(ips, _anomalyLastRegions, firstTs);
        if (order) return order;
        console.warn('[RegionCluster] No AI regions available — falling back to first_seen order.');
        // fall through to the first_seen fallback below
    }
    if (stats) {
        return [...ips].sort((a, b) => {
            const ta = stats[a]?.first_ts ?? Infinity;
            const tb = stats[b]?.first_ts ?? Infinity;
            return ta - tb;
        });
    }
    return [...ips].sort();
}

function getEffectiveFlowIPs() {
    if (!_showInitiatorsOnly || !_flowOnlyAllIPs) return _flowOnlyAllIPs;
    const binnedData = state.flowView && state.flowView.binnedData;
    if (!binnedData || binnedData.length === 0) return _flowOnlyAllIPs;
    const initiatorSet = new Set(binnedData.map(d => d.initiator).filter(Boolean));
    return _flowOnlyAllIPs.filter(ip => initiatorSet.has(ip));
}

async function applyIPRowOrder() {
    if (!_flowOnlyAllIPs || !(_flowOnlyRawTimeExtent || state.data.timeExtent)) return;
    const mode = document.getElementById('ipRowOrder')?.value || 'first_seen';

    // Always recompute clustering orders so they reflect the current visible
    // IPs and hidden close types (no cache reuse — see load*OrderLive).
    if (mode === 'ai_live') await loadAIOrderLive();
    if (mode === 'fiedler') await loadFiedlerOrderLive();

    const checked = new Set(
        Array.from(document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked'))
             .map(cb => cb.value)
    );

    // Full list (sorted) drives the checkbox UI so the user can re-check anything;
    // layout uses only the visible subset (checked AND not right-click hidden) so
    // unchecked rows don't waste 0.1-px slots.
    const sortedIPs = sortIPsByMode(getEffectiveFlowIPs() || _flowOnlyAllIPs, mode);
    const visibleIPs = sortedIPs.filter(ip =>
        (checked.size === 0 || checked.has(ip)) && !_hiddenIPs.has(ip)
    );

    createIPCheckboxes(sortedIPs);
    document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => {
        cb.checked = checked.size === 0 ? true : checked.has(cb.value);
    });

    const layoutBase = visibleIPs.length > 0 ? visibleIPs : sortedIPs;
    const layoutIPs = _maybeClusterOrder(layoutBase);
    // Fast path: just reflow rows when only the order changed (reuses the
    // WebGL renderer, SVG layers, zoom handler, and binned data). Falls back
    // to a full re-init if the renderer hasn't been built yet (first call).
    if (!_relayoutFlowOnlyForIPs(layoutIPs)) {
        _initFlowOnlyChart(layoutIPs, (_flowOnlyRawTimeExtent || state.data.timeExtent));
    }
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
        _flowOnlyRawTimeExtent = flowTimeExtent.slice();
        console.log('[FlowOnly] Seeded state.data.timeExtent from flow range:', state.data.timeExtent);
    }

    // Load the IP list produced alongside the flow data
    try {
        try { sbUpdateCsvProgress(0.85, 'Loading IP list...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
        _flowOnlyBasePath = flowBasePath;
        const resp = await fetch(`${flowBasePath}/ips/unique_ips.json`);
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const ips = await resp.json();
        _flowOnlyAllIPs = ips;

        try {
            const statsResp = await fetch(`${flowBasePath}/ips/ip_stats.json`);
            if (statsResp.ok) _flowOnlyIPStats = await statsResp.json();
        } catch (_) { _flowOnlyIPStats = null; }

        const mode = document.getElementById('ipRowOrder')?.value || 'first_seen';
        if (mode === 'ai_live') await loadAIOrderLive();
        if (mode === 'fiedler') await loadFiedlerOrderLive();
        const sortedIPs = sortIPsByMode(ips, mode);

        createIPCheckboxes(sortedIPs);
        document.querySelectorAll('#ipCheckboxes input[type="checkbox"]').forEach(cb => cb.checked = true);

        const orderSel = document.getElementById('ipRowOrder');
        if (orderSel && !orderSel.dataset.bound) {
            orderSel.addEventListener('change', applyIPRowOrder);
            orderSel.dataset.bound = '1';
        }

        const groupByRegionCb = document.getElementById('groupByRegion');
        if (groupByRegionCb && !groupByRegionCb.dataset.bound) {
            groupByRegionCb.addEventListener('change', applyIPRowOrder);
            groupByRegionCb.dataset.bound = '1';
        }

        const initiatorsOnlyCb = document.getElementById('showInitiatorsOnly');
        if (initiatorsOnlyCb && !initiatorsOnlyCb.dataset.bound) {
            initiatorsOnlyCb.addEventListener('change', () => {
                _showInitiatorsOnly = initiatorsOnlyCb.checked;
                applyIPRowOrder();
            });
            initiatorsOnlyCb.dataset.bound = '1';
        }

        // Build chart directly from flow data — no packets needed.
        // Use sbShowCsvProgress (not sbUpdateCsvProgress) since loadAIOrderLive
        // may have hidden the bar; show* re-displays it.
        try { sbShowCsvProgress('Building chart…', 0.95); } catch(e) { logCatchError('sbShowCsvProgress', e); }
        _initFlowOnlyChart(_maybeClusterOrder(sortedIPs), flowTimeExtent);

        console.log(`[FlowOnly] Created checkboxes for ${ips.length} IPs`);

        const loadingMsg = document.getElementById('loadingMessage');
        if (loadingMsg) {
            loadingMsg.textContent = `Flow data ready — ${ips.length} IPs. Switch to Packets view to load packet data.`;
            loadingMsg.style.display = 'block';
        }

        // Keep the progress bar open through the first render — _updateIPFilterImpl
        // (kicked off by handleFlowListFormat's setTimeout) will hide it after the
        // WebGL view paints.
        try { sbShowCsvProgress('Rendering chart…', 0.97); } catch(e) { logCatchError('sbShowCsvProgress', e); }
        _progressKeepOpenForRender = true;
        // Safety net: if no render path runs (e.g. brush-prefilter mismatch), hide
        // the bar after a generous timeout so it doesn't stay open forever.
        setTimeout(() => {
            if (_progressKeepOpenForRender) {
                _progressKeepOpenForRender = false;
                try { sbHideCsvProgress(); } catch(e) {}
            }
        }, 30000);
    } catch (e) {
        console.warn('[FlowOnly] Could not load IP list from flow data:', e.message);
        _progressKeepOpenForRender = false;
        try { sbHideCsvProgress(); } catch(err) { logCatchError('sbHideCsvProgress', err); }
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

        if (format === 'flow_list_csv' || format === 'flow_shards_parquet') {
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
    const format = (detail.format === 'flow_shards_parquet' || manifest?.format === 'flow_shards_parquet')
        ? 'flow_shards_parquet'
        : 'flow_list_csv';

    flowDataState = {
        manifest,
        totalFlows,
        timeExtent: flowTimeExtent,
        format,
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

    updateFlowDataUI({ totalFlows, format });

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
const DEFAULT_FLOW_DATA_PATH = 'packets_data/flows_set1_90min';

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
let _hyparquetPromise = null;
async function _getHyparquet() {
    if (!_hyparquetPromise) {
        _hyparquetPromise = import('https://esm.sh/hyparquet@1.25.6');
    }
    return _hyparquetPromise;
}

const RES_BIN_SIZE_US = {
    'hours': 3_600_000_000,
    'minutes': 60_000_000,
    '10s': 10_000_000,
    'seconds': 1_000_000,
    '100ms': 100_000,
    '10ms': 10_000,
    '1ms': 1_000,
    'raw': 1
};

// Convert hyparquet rows (already plain objects keyed by column name) into
// the same row shape parsePacketCSV produces, so downstream code (binning,
// IP extraction, fetchResManager) doesn't care about source format.
function _normalizePacketRows(rows, resName) {
    const binSize = RES_BIN_SIZE_US[resName] || 1_000_000;
    const binned = resName !== 'raw';
    const halfBin = Math.floor(binSize / 2);
    const out = new Array(rows.length);
    for (let i = 0; i < rows.length; i++) {
        const r = rows[i];
        // hyparquet returns int64 fields as BigInt — coerce to Number so
        // downstream arithmetic (xScale, binStart + binSize, etc.) works.
        const ts = typeof r.timestamp === 'bigint' ? Number(r.timestamp) : (r.timestamp | 0 || +r.timestamp || 0);
        const count = typeof r.count === 'bigint' ? Number(r.count) : (+r.count || 0);
        const totalBytes = typeof r.total_bytes === 'bigint' ? Number(r.total_bytes) : (+r.total_bytes || 0);
        const flagType = r.flag_type || 'OTHER';
        const row = {
            timestamp: ts,
            src_ip: r.src_ip || '',
            dst_ip: r.dst_ip || '',
            count,
            total_bytes: totalBytes,
            flag_type: flagType,
            flagType,
            binned,
            resolution: resName
        };
        if (binned) {
            row.bin_start = ts;
            row.bin_end = ts + binSize;
            row.binStart = ts;
            row.binEnd = ts + binSize;
            row.binCenter = ts + halfBin;
            row.flags = flagTypeToFlags(flagType);
            row.length = totalBytes;
            row.preBinnedSize = binSize;
        }
        if (r.src_port !== undefined && r.src_port !== null) {
            row.src_port = typeof r.src_port === 'bigint' ? Number(r.src_port) : (+r.src_port || 0);
        }
        if (r.dst_port !== undefined && r.dst_port !== null) {
            row.dst_port = typeof r.dst_port === 'bigint' ? Number(r.dst_port) : (+r.dst_port || 0);
        }
        out[i] = row;
    }
    return out;
}

// Per-chunk and per-resolution-index caches keep repeated calls cheap. Both
// caches store Promises so concurrent callers share the same in-flight request.
const _packetChunkCache = new Map();   // url -> Promise<normalizedRows[]>
const _packetIndexCache = new Map();   // basePath|resName -> Promise<indexJson>

// Evict only the heavy raw/seconds packet chunks, preserving the small shared
// minute-tier chunk that the neighbor/peer/byte enrichments all reuse. clear()
// was nuking minutes too, forcing per-region re-fetches that intermittently
// truncated (ERR_CONTENT_LENGTH_MISMATCH) and zeroed out the neighbor list.
function _evictHeavyPacketChunks() {
    for (const url of Array.from(_packetChunkCache.keys())) {
        if (url.includes('/resolutions/raw/') || url.includes('/resolutions/seconds/')) {
            _packetChunkCache.delete(url);
        }
    }
}

async function _loadOnePacketChunk(url, resName) {
    if (_packetChunkCache.has(url)) return _packetChunkCache.get(url);
    const promise = (async () => {
        const r = await fetch(url);
        if (!r.ok) {
            console.warn(`[loadResolutionPackets] Chunk ${url} failed: HTTP ${r.status}`);
            return [];
        }
        if (url.endsWith('.parquet')) {
            const buf = await r.arrayBuffer();
            const hp = await _getHyparquet();
            const rows = await hp.parquetReadObjects({ file: buf });
            return _normalizePacketRows(rows, resName);
        }
        const text = await r.text();
        return parseSecondsCSV(text, resName);
    })();
    _packetChunkCache.set(url, promise);
    promise.catch(() => _packetChunkCache.delete(url));
    return promise;
}

// Fetch+parse+normalize ONE chunk WITHOUT caching it (the per-port tiers are
// ~5M rows/chunk; caching parsed rows is what blows memory). Browser HTTP cache
// still serves the bytes fast on re-fetch.
async function _loadOnePacketChunkUncached(url, resName) {
    const r = await fetch(url);
    if (!r.ok) { console.warn(`[stream] chunk ${url} HTTP ${r.status}`); return []; }
    if (url.endsWith('.parquet')) {
        const buf = await r.arrayBuffer();
        const hp = await _getHyparquet();
        const rows = await hp.parquetReadObjects({ file: buf });
        return _normalizePacketRows(rows, resName);
    }
    const text = await r.text();
    return parseSecondsCSV(text, resName);
}

// Stream a resolution tier one chunk at a time. Calls onRows(rowsForThisChunk)
// per chunk (already row-range-filtered if range given), then releases the chunk
// before loading the next. Peak memory ~= one chunk. Use this instead of
// loadResolutionPackets for full-extent / large-window aggregations.
async function streamResolutionPackets(basePath, resName, opts, onRows) {
    const { range = null } = opts || {};
    const index = await _loadResolutionIndex(basePath, resName);
    if (!index) return;
    if (Array.isArray(index.chunks) && index.chunks.length > 0) {
        let toLoad = index.chunks;
        if (range) {
            const [tMin, tMax] = range;
            toLoad = index.chunks.filter(c =>
                typeof c.start === 'number' && typeof c.end === 'number' &&
                c.end >= tMin && c.start <= tMax
            );
        }
        for (const chunk of toLoad) {
            const url = `${basePath}/resolutions/${resName}/${chunk.file}`;
            let rows = await _loadOnePacketChunkUncached(url, resName);
            if (range) {
                const [tMin, tMax] = range;
                rows = rows.filter(r => {
                    const t = Number(r.binStart ?? r.bin_start ?? r.timestamp ?? 0);
                    return t >= tMin && t <= tMax;
                });
            }
            await onRows(rows);
            rows = null; // release before next chunk
        }
        return;
    }
    // single-file layout
    const dataFile = index.data_file || 'data.csv';
    let rows = await _loadOnePacketChunkUncached(`${basePath}/resolutions/${resName}/${dataFile}`, resName);
    if (range) {
        const [tMin, tMax] = range;
        rows = rows.filter(r => {
            const t = Number(r.binStart ?? r.bin_start ?? r.timestamp ?? 0);
            return t >= tMin && t <= tMax;
        });
    }
    await onRows(rows);
}

async function _loadResolutionIndex(basePath, resName) {
    const key = `${basePath}|${resName}`;
    if (_packetIndexCache.has(key)) return _packetIndexCache.get(key);
    const promise = (async () => {
        const resp = await fetch(`${basePath}/resolutions/${resName}/index.json`);
        if (!resp.ok) return null;
        return await resp.json();
    })();
    _packetIndexCache.set(key, promise);
    promise.catch(() => _packetIndexCache.delete(key));
    return promise;
}

/**
 * Load normalized packet rows for a resolution tier. Pass `opts.range = [tMin, tMax]`
 * (microseconds) to fetch only chunks overlapping that window and additionally
 * row-filter by time after normalization. Without range, loads every chunk for
 * the resolution (matches the original behavior for the main packet view).
 *
 * Pass `opts.onlySingleFile = true` to skip chunked layouts entirely (used by
 * preload paths that only want eager single-file resolutions).
 */
async function loadResolutionPackets(basePath, resName, opts = {}) {
    const { onlySingleFile = false, range = null } = opts;

    const index = await _loadResolutionIndex(basePath, resName);
    if (!index) return [];

    // Chunked layout
    if (Array.isArray(index.chunks) && index.chunks.length > 0) {
        if (onlySingleFile) {
            console.log(`[loadResolutionPackets] ${resName} is chunked (${index.chunks.length} chunks) — skipping preload`);
            return [];
        }
        let chunksToLoad = index.chunks;
        if (range) {
            const [tMin, tMax] = range;
            chunksToLoad = index.chunks.filter(c =>
                typeof c.start === 'number' && typeof c.end === 'number' &&
                c.end >= tMin && c.start <= tMax
            );
            console.log(`[loadResolutionPackets] ${resName}: range filter → ${chunksToLoad.length}/${index.chunks.length} chunks`);
        } else {
            console.log(`[loadResolutionPackets] ${resName}: loading ${index.chunks.length} chunks`);
        }
        if (chunksToLoad.length === 0) return [];
        const chunkPackets = await Promise.all(
            chunksToLoad.map((chunk) =>
                _loadOnePacketChunk(`${basePath}/resolutions/${resName}/${chunk.file}`, resName)
            )
        );
        let flat = chunkPackets.flat();
        if (range) {
            // Row-level filter: chunks may straddle the range boundary.
            const [tMin, tMax] = range;
            flat = flat.filter(r => {
                const t = Number(r.binStart ?? r.bin_start ?? r.timestamp ?? 0);
                return t >= tMin && t <= tMax;
            });
        }
        console.log(`[loadResolutionPackets] ${resName}: parsed ${flat.length} rows from ${chunksToLoad.length} chunks`);
        return flat;
    }

    // Single-file layout
    const dataFile = index.data_file || 'data.csv';
    let parsed = await _loadOnePacketChunk(`${basePath}/resolutions/${resName}/${dataFile}`, resName);
    if (range) {
        const [tMin, tMax] = range;
        parsed = parsed.filter(r => {
            const t = Number(r.binStart ?? r.bin_start ?? r.timestamp ?? 0);
            return t >= tMin && t <= tMax;
        });
    }
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
    try { sbShowCsvProgress('Loading flow manifest...', 0); } catch(e) { logCatchError('sbShowCsvProgress', e); }

    try {
        // Load manifest
        const manifestResponse = await fetch(`${basePath}/manifest.json`);
        if (!manifestResponse.ok) {
            throw new Error(`Failed to load manifest: ${manifestResponse.status}`);
        }
        const manifest = await manifestResponse.json();
        console.log('[loadFlowsFromPath] Loaded manifest:', manifest);

        const format = manifest.format;
        if (format !== 'flow_list_csv' && format !== 'flow_shards_parquet') {
            throw new Error(`Unsupported format: ${format}`);
        }

        // flow_list_csv: per-flow data lives in indices/flow_list/*.csv (loaded on-demand
        // by FlowListLoader). Overview bins come from indices/flow_bins_*.json via
        // AdaptiveOverviewLoader. No chunk enumeration here.
        const totalFlows = manifest.total_flows || 0;
        const flowTimeExtent = [manifest.time_range.start, manifest.time_range.end];

        console.log(`[loadFlowsFromPath] Total flows: ${totalFlows}, time extent:`, flowTimeExtent);

        // Load the flow list index so FlowListLoader is populated before FlowZoomManager is created.
        try { sbUpdateCsvProgress(0.3, 'Loading flow list index...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
        await tryLoadFlowList(basePath);

        // Initialize adaptive overview loader early for resolution sync
        // This allows the packets view to determine resolution matching the overview chart
        try {
            const indexPath = `${basePath}/indices/flow_bins_index.json`;
            console.log(`[loadFlowsFromPath] Checking for multi-resolution index at ${indexPath}...`);
            const indexResponse = await fetch(indexPath);
            if (indexResponse.ok) {
                adaptiveOverviewLoader = new AdaptiveOverviewLoader(basePath);
                try { sbUpdateCsvProgress(0.6, 'Initializing adaptive overview...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
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
        try { sbUpdateCsvProgress(0.8, 'Flow data loaded...'); } catch(e) { logCatchError('sbUpdateCsvProgress', e); }
        return { manifest, totalFlows, flowTimeExtent };

    } catch (err) {
        console.error('[loadFlowsFromPath] Error loading flow data:', err);
        try { sbHideCsvProgress(); } catch(e) { logCatchError('sbHideCsvProgress', e); }
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

// ============================================================================
// "Explain this region" — LLM-backed inline assistant for magnifier panels.
//
// Self-contained block. To remove the feature in its entirety:
//   1. Delete this entire block.
//   2. Delete the four _explain* declarations near _magnifierBrushes.
//   3. Delete the three hook calls in _initMagnifierBrush and _spawnMagnifierPanel:
//        _explainAttachToPanel(panel, lastArgs)
//        _explainNotifyArgsChanged(panel)
//        _explainDetach(panel)
//
// Architecture: flat _explainXxx helpers (matches the file's style) with state
// keyed by panel DOM element via a WeakMap so cleanup is automatic. The bar
// lives as a 4th panel child between body and bottomBar so it survives the
// body.innerHTML='' wipe that runs on every brush edit.
// ============================================================================

const _EXPLAIN_KEY_PATH = './anthropic_key.txt';
const _EXPLAIN_PROMPT_PATH = './explain_system_prompt.txt';
const _EXPLAIN_PACKETS_PATH = './packets_data/decoded_set1_90min_packets';
// Opaque-id mapping for GT eventTypes. Sent to the LLM in place of the raw
// eventType string so that suggestive labels like "ddos" cannot anchor the
// hypothesis. The UI / a second pass can resolve labelId -> real eventType
// using this same file.
const _EXPLAIN_EVENT_MAPPING_PATH = './event_type_mapping.json';
const _EXPLAIN_MODEL = 'claude-sonnet-4-6';
const _EXPLAIN_API_URL = 'https://api.anthropic.com/v1/messages';
// Auto-detect provider from URL: anything not api.anthropic.com is OpenAI-compatible (LM Studio, etc.)
const _AI_PROVIDER = _EXPLAIN_API_URL.includes('api.anthropic.com') ? 'anthropic' : 'openai';
const _EXPLAIN_TOP_PAIRS = 10;
const _EXPLAIN_TOP_GT_EVENTS = 5;
const _EXPLAIN_MAX_IPS_IN_PAYLOAD = 50;
const _EXPLAIN_TOP_NEIGHBORS = 15;
// Cap the number of distinct neighbor keys tracked during the main loop to
// avoid unbounded Map growth on large datasets (~1M binnedData rows).
const _EXPLAIN_MAX_NEIGHBORS_TRACKED = 5000;
const _EXPLAIN_TOP_PIVOTS = 8;            // max pivot hosts emitted
const _EXPLAIN_MAX_PIVOT_PARTNERS = 50;   // max distinct in-sources / out-dests tracked per member
const _EXPLAIN_MAX_PIVOT_MEMBERS_TRACKED = 5000; // memory cap on distinct members tracked
// 4096 leaves room for the four-paragraph prose (~600 tokens) plus the
// ```roles fenced JSON block (each IP entry is ~30 tokens; 4096 handles a few
// hundred IPs comfortably). Truncation here = an unclosed fence = no role
// parse + the partial fence leaks into the displayed prose.
const _EXPLAIN_MAX_TOKENS = 4096;

// Packet caching for byte-aggregation now lives in loadResolutionPackets
// (_packetChunkCache and _packetIndexCache), shared with the main packet view
// and the magnifier packet tab.

async function _explainFetchKey() {
    if (_explainApiKey) return _explainApiKey;            // cached success
    if (_explainApiKeyPromise) return _explainApiKeyPromise; // in-flight dedup
    _explainApiKeyPromise = (async () => {
        try {
            const resp = await fetch(_EXPLAIN_KEY_PATH, { cache: 'no-store' });
            if (!resp.ok) return false;                   // don't cache failure — let next click retry
            const text = (await resp.text()).trim();
            if (text.length === 0) return false;          // empty file: also retry next time
            _explainApiKey = text;
            return text;
        } catch (e) {
            return false;
        } finally {
            _explainApiKeyPromise = null;
        }
    })();
    return _explainApiKeyPromise;
}

// Generic cached text fetcher used by both the explain and anomaly features
// for their system-prompt files. Caller passes a holder object { value, promise }
// — value caches a successful read; promise dedups concurrent in-flight reads.
// Failure to read or empty file returns false and is not cached, so the next
// call retries.
async function _fetchCachedText(path, holder) {
    if (holder.value) return holder.value;
    if (holder.promise) return holder.promise;
    holder.promise = (async () => {
        try {
            const resp = await fetch(path, { cache: 'no-store' });
            if (!resp.ok) return false;
            const text = (await resp.text()).trim();
            if (text.length === 0) return false;
            holder.value = text;
            return text;
        } catch (e) {
            return false;
        } finally {
            holder.promise = null;
        }
    })();
    return holder.promise;
}

const _explainSystemPromptHolder = { value: null, promise: null };
async function _explainFetchSystemPrompt() {
    return _fetchCachedText(_EXPLAIN_PROMPT_PATH, _explainSystemPromptHolder);
}

// Load the eventType -> numeric-id mapping. Cached after first success; failures
// are not cached so the next call retries. Returns the parsed object or false.
const _explainEventMappingHolder = { value: null, promise: null };
async function _explainFetchEventMapping() {
    if (_explainEventMappingHolder.value) return _explainEventMappingHolder.value;
    if (_explainEventMappingHolder.promise) return _explainEventMappingHolder.promise;
    _explainEventMappingHolder.promise = (async () => {
        try {
            const resp = await fetch(_EXPLAIN_EVENT_MAPPING_PATH, { cache: 'no-store' });
            if (!resp.ok) return false;
            const obj = await resp.json();
            if (!obj || typeof obj !== 'object') return false;
            _explainEventMappingHolder.value = obj;
            return obj;
        } catch (e) {
            console.warn('[Explain] event mapping load failed:', e);
            return false;
        } finally {
            _explainEventMappingHolder.promise = null;
        }
    })();
    return _explainEventMappingHolder.promise;
}

function _explainCacheKey(ips, tMin, tMax) {
    return `${tMin}|${tMax}|${[...ips].sort().join(',')}`;
}

// Extract the ```roles fenced JSON block from an Explain response. Returns
// { prose, roleMap } where prose has the block stripped (for display) and
// roleMap is a Map<ip,role> (or null if the block was missing/malformed).
// Roles outside the known set are coerced to 'noise'.
function _extractRoleBlock(text) {
    if (typeof text !== 'string') return { prose: '', roleMap: null };
    const fenceMatch = text.match(/```roles\s*([\s\S]*?)\s*```/i);
    if (!fenceMatch) return { prose: text.trim(), roleMap: null };
    const proseStripped = text.replace(fenceMatch[0], '').trim();
    let parsed;
    try { parsed = JSON.parse(fenceMatch[1].trim()); }
    catch (e) {
        console.warn('[Explain] role block JSON parse failed:', e);
        return { prose: proseStripped, roleMap: null };
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        return { prose: proseStripped, roleMap: null };
    }
    const roleMap = new Map();
    for (const [ip, roleRaw] of Object.entries(parsed)) {
        const role = typeof roleRaw === 'string' ? roleRaw.trim().toLowerCase() : '';
        roleMap.set(ip, _DENOISE_ROLES.has(role) ? role : 'noise');
    }
    return { prose: proseStripped, roleMap };
}

// Wrapper around the raw _explainCache that also populates _roleMapCache and
// notifies the panel so any open Network tab re-renders with the new role map.
// Used by both the fresh-fetch and cache-hit paths in _explainRun.
function _explainAcceptResult(panel, cacheKey, fullText) {
    _explainCache.set(cacheKey, fullText);
    const { prose, roleMap } = _extractRoleBlock(fullText);
    if (roleMap) _roleMapCache.set(cacheKey, roleMap);
    if (panel && typeof panel.__notifyExplainResult === 'function') {
        try { panel.__notifyExplainResult(); } catch (e) { console.warn('[Explain] notify failed:', e); }
    }
    _anomalyPersistSave();
    try { _anomalyWriteToLinkedFile(); } catch (e) {}
    return prose;
}

// Pick the coarsest packet-tier whose bin width is small enough to give the
// region a useful number of bins. Mirrors the auto-resolution policy elsewhere
// in the file but uses the multires_packets tier names directly.
function _explainPickBytesResolution(durationUs) {
    if (durationUs > 24 * 3600 * 1_000_000) return 'hours';
    if (durationUs > 3600 * 1_000_000)      return 'minutes';
    if (durationUs > 600 * 1_000_000)       return '10s';
    if (durationUs > 60 * 1_000_000)        return 'seconds';
    if (durationUs > 10 * 1_000_000)        return '100ms';
    if (durationUs > 1_000_000)             return '10ms';
    if (durationUs > 100_000)               return '1ms';
    return 'raw';
}

// Aggregate bytes for a region. Returns:
//   { totalBytes, bytesByPair: Map<"a|b"-sorted, bytes>, resolution }
// A row "matches the region" when at least one of (src_ip, dst_ip) is in the
// caller's IP set. Range filtering and chunk caching happen inside
// loadResolutionPackets — see that function for the loader/cache layer.
//
// Always loads at 'minutes' resolution. The downsampled minute-tier schema
// carries total_bytes, so per-pair sums are accurate enough for the Explain
// case-builder. The 'seconds' tier (~8.9M rows) that _explainPickBytesResolution
// would return for a typical ~6-min region OOM-crashed the tab on every click;
// 'minutes' is already cached by _explainBuildPayload's neighbor-chunk load so
// this adds zero new network cost.
async function _explainAggregateBytes(ips, tMin, tMax) {
    const resolution = 'minutes';
    const ipSet = new Set(ips);
    const bytesByPair = new Map();
    let totalBytes = 0;

    try {
        await streamResolutionPackets(_EXPLAIN_PACKETS_PATH, resolution, { range: [tMin, tMax] }, async (rows) => {
            for (const r of rows) {
                const src = r.src_ip;
                const dst = r.dst_ip;
                if (!src || !dst) continue;
                if (!ipSet.has(src) && !ipSet.has(dst)) continue;
                const bytes = Number(r.total_bytes) || 0;
                if (bytes <= 0) continue;
                totalBytes += bytes;
                const key = src < dst ? `${src}|${dst}` : `${dst}|${src}`;
                bytesByPair.set(key, (bytesByPair.get(key) || 0) + bytes);
            }
        });
    } catch (e) {
        console.warn('[Explain] byte aggregation failed:', e);
        return { totalBytes: 0, bytesByPair: new Map(), resolution };
    }
    return { totalBytes, bytesByPair, resolution };
}

function _explainFormatUTC(us) {
    try {
        const s = epochMicrosecondsToUTC(us);
        return typeof s === 'string' ? s.replace(' UTC', '') : String(us);
    } catch (e) {
        return String(us);
    }
}

// --- Geo/org enrichment helpers (Explain-only) -----------------------------
// Reference data only: country/org NEVER feeds the suspicion judgment (that is
// the detector's behavior-first job). These helpers classify an IP for the
// case-builder's "Attribution" narrative.

// RFC1918 private-range test. The MaxMind meta map strips internal IPs, so an
// IP absent from the map is either RFC1918 ("private") or public-but-unresolved
// ("unknown"); this lets the two be told apart.
function _isRfc1918(ip) {
    if (typeof ip !== 'string') return false;
    if (ip.startsWith('10.')) return true;
    if (ip.startsWith('192.168.')) return true;
    if (ip.startsWith('172.')) {
        const second = parseInt(ip.split('.')[1], 10);
        return second >= 16 && second <= 31;
    }
    return false;
}

// Returns { country?, org? } when the IP resolves (null fields omitted), else
// { geo: 'private' } for RFC1918 or { geo: 'unknown' } for unresolved public IPs.
function _explainGeoForIp(ip, metaMap) {
    const m = metaMap && metaMap[ip];
    if (m && (m.country || m.org)) {
        const out = {};
        if (m.country) out.country = m.country;
        if (m.org) out.org = m.org;
        return out;
    }
    return { geo: _isRfc1918(ip) ? 'private' : 'unknown' };
}

// Accumulate {ips, flows} for one histogram key.
function _explainGeoBump(map, key, flows) {
    let e = map.get(key);
    if (!e) { e = { ips: 0, flows: 0 }; map.set(key, e); }
    e.ips += 1;
    e.flows += flows;
}

// Sort a {key -> {ips, flows}} map into a capped array of {value, ips, flows},
// ordered by distinct IP count (desc), flows as tiebreak.
function _explainGeoTopBuckets(map, maxResults) {
    return Array.from(map.entries())
        .map(([value, v]) => ({ value, ips: v.ips, flows: v.flows }))
        .sort((a, b) => (b.ips - a.ips) || (b.flows - a.flows))
        .slice(0, maxResults);
}

// Build a country/org histogram over a Map<ip, flowCount>.
function _explainGeoHistogram(ipFlowMap, metaMap, dim, maxResults) {
    const acc = { country: new Map(), org: new Map() };
    let resolved = 0, priv = 0, unknown = 0, total = 0;
    for (const [ip, flows] of ipFlowMap) {
        total += 1;
        const g = _explainGeoForIp(ip, metaMap);
        if (g.geo === 'private') { priv += 1; continue; }
        if (g.geo === 'unknown') { unknown += 1; continue; }
        resolved += 1;
        if (g.country) _explainGeoBump(acc.country, g.country, flows);
        if (g.org) _explainGeoBump(acc.org, g.org, flows);
    }
    const out = {
        totalIps: total, resolvedIps: resolved, privateIps: priv, unknownIps: unknown,
        coverage: total ? +(resolved / total).toFixed(3) : 0
    };
    if (dim === 'country' || dim === 'both') out.country = _explainGeoTopBuckets(acc.country, maxResults);
    if (dim === 'org' || dim === 'both') out.org = _explainGeoTopBuckets(acc.org, maxResults);
    return out;
}

// Region-scoped country/org histograms for the case-builder. ipSet = region
// initiators; targets = responders those initiators talked to within [tMin,tMax].
// Pure read of state.flowView.binnedData; metaMap preloaded by the caller.
function _explainToolGeoBreakdown(ipSet, tMin, tMax, metaMap, args) {
    if (!metaMap) return { available: false, reason: 'no geo resolved (meta map unavailable)' };
    const a = args || {};
    const side = ['source', 'target', 'both'].includes(a.side) ? a.side : 'both';
    const dim = ['country', 'org', 'both'].includes(a.dimension) ? a.dimension : 'both';
    const maxResults = Math.max(1, Math.min(40, Number(a.max_results) || 15));
    const binnedData = (state.flowView && state.flowView.binnedData) || [];

    const sourceFlows = new Map();   // initiator -> flowCount
    const targetFlows = new Map();   // responder -> flowCount
    for (let i = 0; i < binnedData.length; i++) {
        const d = binnedData[i];
        if (!d || !ipSet.has(d.initiator)) continue;
        const t0 = d.binStart ?? d.startTime ?? 0;
        const t1 = d.binEnd ?? d.endTime ?? t0;
        if (t1 < tMin || t0 > tMax) continue;
        const c = d.count || 0;
        sourceFlows.set(d.initiator, (sourceFlows.get(d.initiator) || 0) + c);
        if (d.responder) targetFlows.set(d.responder, (targetFlows.get(d.responder) || 0) + c);
    }

    const result = { available: true, side, dimension: dim };
    if (side === 'source' || side === 'both') {
        result.source = _explainGeoHistogram(sourceFlows, metaMap, dim, maxResults);
    }
    if (side === 'target' || side === 'both') {
        result.target = _explainGeoHistogram(targetFlows, metaMap, dim, maxResults);
    }
    const srcResolved = result.source ? result.source.resolvedIps : null;
    const tgtResolved = result.target ? result.target.resolvedIps : null;
    const allUnresolved =
        (srcResolved === null || srcResolved === 0) &&
        (tgtResolved === null || tgtResolved === 0);
    if (allUnresolved) {
        return { available: false, reason: 'no geo resolved (all IPs internal or unknown)' };
    }
    result.note = 'Counts are reference attribution only — never evidence of malice. ' +
        'Buckets ordered by distinct IP count; coverage = resolved/total IPs.';
    return result;
}

// ----------------------------------------------------------------------------
// _explainToolTargetPorts — destination-port histogram for a single responder.
//
// WHY raw-only: the downsampled resolutions (seconds, 10s, minutes, …) drop the
// src_port/dst_port columns entirely; their rows only have
// [timestamp, src_ip, dst_ip, count, total_bytes, flag_type]. Port data only
// exists at resolution 'raw', which carries the full per-packet schema:
// [timestamp, src_ip, dst_ip, src_port, dst_port, flags, flag_type, length].
//
// WHY _packetChunkCache.clear() in finally: the chunk cache is unbounded and
// never evicted. Each raw read pulls ~6.5M-row chunks. Clearing in finally
// matches the pattern established in _explainAggregateBytes and prevents the
// progressive OOM that crashed the tab on repeated Explain calls.
//
// Duration cap: raw chunks cover ~4.5 min each. A 15-min window hits ~3-4
// chunks — manageable. Wider windows risk loading the entire 125M-row dataset,
// so we bail early rather than read nothing useful at huge cost.
// ----------------------------------------------------------------------------
async function _explainToolTargetPorts(responder, tMin, tMax, args) {
    const a = args || {};
    const synOnly    = a.syn_only !== false;            // default true
    const maxResults = Math.max(1, Math.min(40, Number(a.max_results) || 12));
    const portCounts = new Map();   // dst_port (number) -> summed packet count
    let totalPackets = 0;
    try {
        await streamResolutionPackets(_EXPLAIN_PACKETS_PATH, 'minutes', { range: [tMin, tMax] }, async (rows) => {
            for (const r of rows) {
                if (r.dst_ip !== responder) continue;
                if (synOnly && r.flag_type !== 'SYN') continue;
                const port = Number(r.dst_port);
                if (!Number.isFinite(port)) continue;
                const c = Number(r.count) || 0;             // minute-tier bin packet count
                totalPackets += c;
                portCounts.set(port, (portCounts.get(port) || 0) + c);
            }
        });
    } catch (e) {
        return { available: false, reason: 'minute-tier port analysis failed: ' + (e && e.message || String(e)) };
    }
    if (totalPackets === 0) {
        return { available: true, responder, synOnly, totalPackets: 0, topPorts: [],
                 note: 'no inbound ' + (synOnly ? 'SYN ' : '') + 'packets to this responder at minute resolution in the window' };
    }
    const topPorts = Array.from(portCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, maxResults)
        .map(([port, packets]) => ({ port, packets, share: Math.round((packets / totalPackets) * 1000) / 1000 }));
    return {
        available: true, responder, synOnly, totalPackets, topPorts,
        note: 'dst_port histogram of ' + (synOnly ? 'SYN' : 'all') + ' packets sent TO this responder, ' +
              'from minute-tier aggregates (per-port packet counts summed over the region window). ' +
              'A single dominant low port (80/443/53/22/3306/...) identifies the targeted service; ' +
              'a flat spread suggests random/non-service-specific flooding.'
    };
}

// ----------------------------------------------------------------------------
// _explainToolHostPeers — org/country histogram of a HOST's OWN peers across
// the FULL capture, using per-peer VOLUME to separate flood peers from the
// host's everyday legitimate clientele.
//
// WHY full-capture (not [tMin, tMax]):
//   Legitimate background traffic (a DoD scanner, a CDN health-check, a cloud
//   monitoring agent) is present throughout the entire 90-minute trace but is
//   utterly drowned in the attack window by millions of flood packets. Scanning
//   only the attack window surfaces the attackers and nothing else. The full
//   extent gives the legitimate tail a fair count.
//
// WHY 'seconds' resolution:
//   Has columns [timestamp, src_ip, dst_ip, count, flag_type] — exactly what
//   we need for peer-pair enumeration and packet-count accumulation. Port data
//   is NOT needed here (get_target_ports handles that). The 'seconds' parquet
//   is only ~2 chunks / ~8.9M rows — cheap to scan in full.
//
// WHY volume-based separation (NOT region-membership exclusion):
//   The old approach excluded peers that appeared in the region's IP set.
//   For a convergence-victim region the system auto-expands the region's `ips`
//   to include EVERY initiator that hit the victim — i.e. essentially the
//   victim's entire inbound peer set. Excluding all region IPs therefore deleted
//   legitimate clientele (DoD, Amazon, Microsoft, etc.) along with the flood
//   sources, leaving only a couple of private RFC1918 stragglers and a false
//   result of "no resolvable peers." Flag-based separation doesn't work either —
//   all peers show non-SYN traffic in per-second aggregation.
//   Volume-based separation is robust: flood peers each accumulate 100k+ packets
//   while legitimate peers stay below ~1600. The median peer volume is ~161,
//   so a multiplier of 10-50× (default 20×) cleanly isolates exactly the 6
//   flood sources and leaves the full legitimate tail intact. The gap is so
//   large that the multiplier is insensitive. Flood classification is PER-IP;
//   org histograms are built AFTER partitioning, so an org like DoD whose
//   traffic is spread across many low-volume IPs survives correctly.
//
// ORG = ASN REGISTRANT CAVEAT:
//   The org field is the registered owner of the IP block (e.g. "US Department
//   of Defense DoD", "Amazon.com", "Microsoft Corporation"). In anonymized or
//   remapped captures the IP→org mapping reflects the original block owner, NOT
//   a verified operational relationship with the host. Treat org as attribution
//   color — never as evidence of malice or operational control.
//
// MEMORY DISCIPLINE:
//   _packetChunkCache is unbounded and never evicted automatically. Clearing it
//   in finally matches the pattern in _explainToolTargetPorts and prevents
//   progressive OOM on repeated Explain calls.
// ----------------------------------------------------------------------------
async function _explainToolHostPeers(ip, metaMap, args) {
    if (!metaMap) return { available: false, reason: 'no geo resolved (meta map unavailable)' };

    const a = args || {};
    const floodMultiple  = Math.max(2, Math.min(1000, Number(a.flood_multiple) || 20));
    const separateFlood  = a.separate_flood !== false;   // default true
    const maxResults     = Math.max(1, Math.min(40, Number(a.max_results) || 15));

    // Deliberately use the FULL capture extent, not the region window.
    const ext = state.data.timeExtent || [0, 0];

    // Build a combined peer→packetCount map over BOTH directions.
    // A peer that both sends to and receives from ip accumulates both — that
    // is intentional; total exchange volume is the right flood signal.
    const peerVol = new Map();   // peerIp → total packet count (both directions)

    try {
        try {
            await streamResolutionPackets(_EXPLAIN_PACKETS_PATH, 'minutes', { range: ext }, async (rows) => {
                for (const r of rows) {
                    if (!r) continue;
                    const cnt = Number(r.count) || 1;

                    // inbound: dst_ip === ip, peer = src_ip
                    if (r.dst_ip === ip && r.src_ip && r.src_ip !== ip) {
                        peerVol.set(r.src_ip, (peerVol.get(r.src_ip) || 0) + cnt);
                    }

                    // outbound: src_ip === ip, peer = dst_ip
                    if (r.src_ip === ip && r.dst_ip && r.dst_ip !== ip) {
                        peerVol.set(r.dst_ip, (peerVol.get(r.dst_ip) || 0) + cnt);
                    }
                }
            });
        } catch (loadErr) {
            return { available: false, reason: `packet load failed: ${loadErr && loadErr.message || String(loadErr)}` };
        }

        if (peerVol.size === 0) {
            return {
                available: true,
                ip,
                scope: 'full-capture',
                method: separateFlood ? 'volume-separated' : 'all-peers',
                medianPeerVolume: 0,
                floodCutoff: null,
                legitimateClientele: { totalPeers: 0, resolvedPeers: 0, privatePeers: 0, unknownPeers: 0, topOrgs: [], topCountries: [] },
                floodSources: null,
                note: 'no peers found'
            };
        }

        // Compute median of all peer volumes.
        const volArray = Array.from(peerVol.values()).sort((a, b) => a - b);
        const mid = Math.floor(volArray.length / 2);
        const median = volArray.length % 2 === 1
            ? volArray[mid]
            : (volArray[mid - 1] + volArray[mid]) / 2;

        // Flood cutoff: floodMultiple × median, with an absolute floor to guard
        // against a near-zero median collapsing the cutoff.
        const cutoff = separateFlood ? Math.max(floodMultiple * median, 100) : Infinity;

        // Partition peers into legitimate (low-volume) and flood (high-volume).
        const legit = [];
        const flood = [];
        for (const [peerIp, vol] of peerVol) {
            if (vol >= cutoff) {
                flood.push(peerIp);
            } else {
                legit.push(peerIp);
            }
        }

        // Build org+country histogram for a list of peer IPs.
        function orgCountryHistogram(peerIps) {
            let totalPeers = 0, resolvedPeers = 0, privatePeers = 0, unknownPeers = 0;
            const orgAcc     = new Map();   // org → {peers, packets}
            const countryAcc = new Map();   // country → {peers, packets}

            for (const peerIp of peerIps) {
                totalPeers++;
                const packets = peerVol.get(peerIp) || 0;
                const g = _explainGeoForIp(peerIp, metaMap);
                if (g.geo === 'private') { privatePeers++; continue; }
                if (g.geo === 'unknown') { unknownPeers++; continue; }
                resolvedPeers++;
                if (g.org) {
                    const e = orgAcc.get(g.org) || { peers: 0, packets: 0 };
                    e.peers++;  e.packets += packets;
                    orgAcc.set(g.org, e);
                }
                if (g.country) {
                    const e = countryAcc.get(g.country) || { peers: 0, packets: 0 };
                    e.peers++;  e.packets += packets;
                    countryAcc.set(g.country, e);
                }
            }

            // Sort by distinct peer count desc, packets as tiebreak; cap at maxResults.
            const sortedOrgs = Array.from(orgAcc.entries())
                .map(([org, v]) => ({ org, peers: v.peers, packets: v.packets }))
                .sort((a, b) => (b.peers - a.peers) || (b.packets - a.packets))
                .slice(0, maxResults);

            const sortedCountries = Array.from(countryAcc.entries())
                .map(([country, v]) => ({ country, peers: v.peers, packets: v.packets }))
                .sort((a, b) => (b.peers - a.peers) || (b.packets - a.packets))
                .slice(0, maxResults);

            return { totalPeers, resolvedPeers, privatePeers, unknownPeers, topOrgs: sortedOrgs, topCountries: sortedCountries };
        }

        // Build flood org histogram (sorted by packets desc — flood is all about volume).
        let floodSources = null;
        if (separateFlood) {
            const floodOrgAcc = new Map();
            for (const peerIp of flood) {
                const packets = peerVol.get(peerIp) || 0;
                const g = _explainGeoForIp(peerIp, metaMap);
                if (g.org) {
                    const e = floodOrgAcc.get(g.org) || { peers: 0, packets: 0 };
                    e.peers++;  e.packets += packets;
                    floodOrgAcc.set(g.org, e);
                }
            }
            const floodTopOrgs = Array.from(floodOrgAcc.entries())
                .map(([org, v]) => ({ org, peers: v.peers, packets: v.packets }))
                .sort((a, b) => (b.packets - a.packets) || (b.peers - a.peers))
                .slice(0, maxResults);
            floodSources = { peerCount: flood.length, topOrgs: floodTopOrgs };
        }

        return {
            available: true,
            ip,
            scope: 'full-capture',
            method: separateFlood ? 'volume-separated' : 'all-peers',
            medianPeerVolume: median,
            floodCutoff: separateFlood ? cutoff : null,
            legitimateClientele: orgCountryHistogram(legit),
            floodSources,
            note: "Organization profile of this host's own peers across the FULL capture. " +
                  "Peers are split by per-IP exchange volume: 'floodSources' are the few extreme-volume peers " +
                  "(the attack itself, which you have already characterized behaviorally); " +
                  "'legitimateClientele' is the host's everyday clientele — use it to characterize WHAT the host " +
                  "is and why it is a high-value target. " +
                  "org = ASN registrant: in anonymized/remapped captures this reflects the IP block's registered " +
                  "owner, NOT verified operational control. Attribution color only; never evidence of malice."
        };

    } catch (e) {
        console.warn('[Explain] get_host_peers failed:', e);
        return { available: false, reason: 'host-peers computation failed: ' + (e && e.message || String(e)) };
    }
    // No cache eviction here: _explainToolHostPeers loads the 'minutes' tier,
    // which is the same shared chunk used by _magLoadPacketRowsFullExtent.
    // Retaining it avoids a re-fetch on the next region's Explain call.
}

async function _explainBuildPayload(ips, tMin, tMax) {
    const binnedData = (state.flowView && state.flowView.binnedData) || [];
    const groundTruth = Array.isArray(state.flows && state.flows.groundTruth)
        ? state.flows.groundTruth : [];
    const ipSet = new Set(ips);

    const closeTypeSummary = Object.create(null);
    const pairAgg = new Map();
    const ipFlowCount = new Map();
    const ipCloseByIp = new Map();
    // pivot detection: region members that are BOTH a responder (received inbound)
    // and an initiator (sent outbound) in this window. ip -> {inFlows, outFlows,
    // inSources: Map<srcIp,count>, outDests: Map<dstIp,count>}
    const memberRole = new Map();
    let totalFlows = 0;

    for (let i = 0; i < binnedData.length; i++) {
        const d = binnedData[i];
        if (!d || !d.initiator) continue;
        // Broaden: process records where a region member is on EITHER side.
        const initIn = ipSet.has(d.initiator);
        const respIn = !!d.responder && ipSet.has(d.responder);
        if (!initIn && !respIn) continue;

        const count = d.count || 0;

        const t0 = d.binStart ?? d.startTime ?? 0;
        const t1 = d.binEnd ?? d.endTime ?? t0;
        if (t1 < tMin || t0 > tMax) continue;

        const ct = d.closeType || 'unknown';

        // totalFlows and closeTypeSummary count ALL region-relevant flows so
        // that an inbound flood against victim-region members appears in the
        // close-type composition.
        totalFlows += count;
        closeTypeSummary[ct] = (closeTypeSummary[ct] || 0) + count;

        // pairAgg tracks all region-relevant pairs (inbound + outbound).
        const pk = `${d.initiator}|${d.responder || ''}|${ct}`;
        let pr = pairAgg.get(pk);
        if (!pr) {
            // totalBytes intentionally omitted here; enriched below from the
            // packet parquet dataset if available. JSON.stringify will drop the
            // field entirely when undefined, so the LLM never sees a stale 0.
            pr = { initiator: d.initiator, responder: d.responder || '',
                   closeType: ct, totalFlows: 0 };
            pairAgg.set(pk, pr);
        }
        pr.totalFlows += count;

        // topInitiators contract: only region members acting as initiators.
        // External attackers must NOT leak in here — tools and the system
        // prompt treat topInitiators as "region-member initiators."
        if (initIn) {
            ipFlowCount.set(d.initiator, (ipFlowCount.get(d.initiator) || 0) + count);
            let cm = ipCloseByIp.get(d.initiator);
            if (!cm) { cm = Object.create(null); ipCloseByIp.set(d.initiator, cm); }
            cm[ct] = (cm[ct] || 0) + count;
        }

        // ── Member dual-role (pivot) tracking (single-pass, capped) ──
        // Region member as initiator → it sent outbound traffic.
        if (initIn) {
            let mr = memberRole.get(d.initiator);
            if (!mr && memberRole.size < _EXPLAIN_MAX_PIVOT_MEMBERS_TRACKED) {
                mr = { inFlows: 0, outFlows: 0, inSources: new Map(), outDests: new Map() };
                memberRole.set(d.initiator, mr);
            }
            if (mr) {
                mr.outFlows += count;
                if (d.responder && (mr.outDests.has(d.responder) || mr.outDests.size < _EXPLAIN_MAX_PIVOT_PARTNERS)) {
                    mr.outDests.set(d.responder, (mr.outDests.get(d.responder) || 0) + count);
                }
            }
        }
        // Region member as responder → it received inbound traffic.
        if (respIn) {
            let mr = memberRole.get(d.responder);
            if (!mr && memberRole.size < _EXPLAIN_MAX_PIVOT_MEMBERS_TRACKED) {
                mr = { inFlows: 0, outFlows: 0, inSources: new Map(), outDests: new Map() };
                memberRole.set(d.responder, mr);
            }
            if (mr) {
                mr.inFlows += count;
                if (mr.inSources.has(d.initiator) || mr.inSources.size < _EXPLAIN_MAX_PIVOT_PARTNERS) {
                    mr.inSources.set(d.initiator, (mr.inSources.get(d.initiator) || 0) + count);
                }
            }
        }
    }

    const topPairs = Array.from(pairAgg.values())
        .sort((a, b) => b.totalFlows - a.totalFlows)
        .slice(0, _EXPLAIN_TOP_PAIRS);

    const topInitiators = Array.from(ipFlowCount.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, _EXPLAIN_TOP_PAIRS)
        .map(([ip, flows]) => {
            const cm = ipCloseByIp.get(ip) || {};
            let best = null, bestN = -1;
            for (const k in cm) { if (cm[k] > bestN) { bestN = cm[k]; best = k; } }
            return { ip, flows, dominantCloseType: best || 'unknown' };
        });

    // Derive firstDegreeNeighbors via the same loader + helper used by the Network
    // tab (_magLoadPacketRowsFullExtent + _deriveNeighborsFromRows). Using the
    // shared path means both surfaces see identical neighbors and the minute-tier
    // chunk is reused from cache rather than re-fetched per region.
    let firstDegreeNeighbors = [];
    let neighborCount = 0;
    try {
        const nbRows = await _magLoadPacketRowsFullExtent(ips);
        const ranked = _deriveNeighborsFromRows(new Set(ips), nbRows);
        neighborCount = ranked.length;
        firstDegreeNeighbors = ranked
            .slice(0, _EXPLAIN_TOP_NEIGHBORS)
            .map(n => ({ ip: n.ip, flows: n.flows, direction: n.direction }));
    } catch (err) {
        console.warn('[Explain] firstDegreeNeighbors load failed; neighbors omitted:', err);
        firstDegreeNeighbors = [];
        neighborCount = 0;
    }

    // pivotHosts: members with BOTH inbound and outbound activity (compromise-pivot
    // / attack-chain signature). topInboundSources = who connected to it;
    // topOutboundDests = who it connected to. Dominant-by-flow, capped.
    const pivotEntries = [];
    for (const [ip, mr] of memberRole) {
        if (mr.inFlows > 0 && mr.outFlows > 0) pivotEntries.push([ip, mr]);
    }
    const pivotCount = pivotEntries.length;
    const topPartners = (m) => Array.from(m.entries())
        .sort((a, b) => b[1] - a[1]).slice(0, 5)
        .map(([pip, flows]) => ({ ip: pip, flows }));
    const pivotHosts = pivotEntries
        .sort((a, b) => (b[1].inFlows + b[1].outFlows) - (a[1].inFlows + a[1].outFlows))
        .slice(0, _EXPLAIN_TOP_PIVOTS)
        .map(([ip, mr]) => ({
            ip,
            inboundFlows: mr.inFlows,
            outboundFlows: mr.outFlows,
            topInboundSources: topPartners(mr.inSources),
            topOutboundDests: topPartners(mr.outDests)
        }));

    // Geo/org enrichment (Explain-only, attribution color). Map is memoized
    // (_ensureIpMetaMap caches its promise), so this await never re-fetches even
    // though the breakdown tool awaits the same map. null map => fields omitted.
    const metaMap = await _ensureIpMetaMap();
    if (metaMap) {
        for (const it of topInitiators) {
            Object.assign(it, _explainGeoForIp(it.ip, metaMap));
        }
        for (const pr of topPairs) {
            pr.initiatorGeo = _explainGeoForIp(pr.initiator, metaMap);
            if (pr.responder) pr.responderGeo = _explainGeoForIp(pr.responder, metaMap);
        }
        // Enrich first-degree neighbors with geo/org (same pattern, same helper).
        for (const n of firstDegreeNeighbors) {
            Object.assign(n, _explainGeoForIp(n.ip, metaMap));
        }
        // Enrich pivot hosts and their partner IPs with geo/org.
        for (const p of pivotHosts) {
            Object.assign(p, _explainGeoForIp(p.ip, metaMap));
            for (const s of p.topInboundSources) Object.assign(s, _explainGeoForIp(s.ip, metaMap));
            for (const d2 of p.topOutboundDests) Object.assign(d2, _explainGeoForIp(d2.ip, metaMap));
        }
    }

    // Aggregate all overlapping ground-truth events by eventType so that a
    // large cluster (e.g. 200 individual "ddos" rows) surfaces as a single
    // high-cardinality entry rather than being starved out by unrelated rows
    // that appear earlier in CSV order.
    const _gtByType = new Map();
    for (let i = 0; i < groundTruth.length; i++) {
        const evt = groundTruth[i];
        if (!evt) continue;
        const evStart = evt.startTimeMicroseconds;
        const evStop = evt.stopTimeMicroseconds;
        if (typeof evStart !== 'number' || typeof evStop !== 'number') continue;
        if (evStop < tMin || evStart > tMax) continue;
        if (!ipSet.has(evt.source) && !ipSet.has(evt.destination)) continue;
        const key = evt.eventType || 'unknown';
        let agg = _gtByType.get(key);
        if (!agg) {
            agg = {
                eventType: key,
                count: 0,
                uniqueSources: new Set(),
                uniqueDestinations: new Set(),
                minStartUs: evStart,
                maxStopUs: evStop
            };
            _gtByType.set(key, agg);
        }
        agg.count++;
        if (evt.source) agg.uniqueSources.add(evt.source);
        if (evt.destination) agg.uniqueDestinations.add(evt.destination);
        if (evStart < agg.minStartUs) agg.minStartUs = evStart;
        if (evStop > agg.maxStopUs) agg.maxStopUs = evStop;
    }
    // De-bias: replace the human-readable eventType ("ddos", "scan /usr/bin/nmap"
    // …) with an opaque labelId ("gt-18", "gt-0") sourced from
    // event_type_mapping.json. The LLM cannot anchor on the word; the UI
    // resolves labelId -> real eventType separately. If the mapping file fails
    // to load, GT entries are emitted with labelId 'gt-unknown' rather than
    // falling back to the raw eventType — preserving the de-biasing guarantee.
    const eventMapping = await _explainFetchEventMapping();
    const gtOverlap = Array.from(_gtByType.values())
        .sort((a, b) => b.count - a.count)
        .slice(0, _EXPLAIN_TOP_GT_EVENTS)
        .map(agg => {
            const id = eventMapping ? eventMapping[agg.eventType] : undefined;
            const labelId = id !== undefined ? `gt-${id}` : 'gt-unknown';
            return {
                labelId,
                count: agg.count,
                uniqueSources: agg.uniqueSources.size,
                uniqueDestinations: agg.uniqueDestinations.size,
                sampleSources: Array.from(agg.uniqueSources).slice(0, 5),
                sampleDestinations: Array.from(agg.uniqueDestinations).slice(0, 5),
                startUTC: _explainFormatUTC(agg.minStartUs),
                stopUTC: _explainFormatUTC(agg.maxStopUs)
            };
        });

    const ipSample = ips.slice(0, _EXPLAIN_MAX_IPS_IN_PAYLOAD);
    const result = {
        timeRange: {
            startUTC: _explainFormatUTC(tMin),
            endUTC: _explainFormatUTC(tMax),
            durationSec: Math.max(0, Math.round((tMax - tMin) / 1_000_000))
        },
        ipCount: ips.length,
        ipSample,
        ipSampleTruncated: ips.length > ipSample.length,
        closeTypeSummary,
        totalFlows,
        topInitiators,
        topPairs,
        firstDegreeNeighbors,
        neighborCount,
        pivotHosts,
        pivotCount,
        groundTruthOverlap: gtOverlap
    };

    // Best-effort byte enrichment from the packet parquet dataset. Failures
    // here (dataset unreachable, hyparquet load error, parse error) downgrade
    // gracefully: topPairs keep no totalBytes field; the LLM sees no byte data
    // at all, which is honest. A console warn captures the cause for debugging.
    try {
        const byteInfo = await _explainAggregateBytes(ips, tMin, tMax);
        for (const pair of topPairs) {
            const a = pair.initiator;
            const b = pair.responder;
            if (!a || !b) continue;
            const key = a < b ? `${a}|${b}` : `${b}|${a}`;
            const bytes = byteInfo.bytesByPair.get(key);
            if (bytes !== undefined) pair.totalBytes = bytes;
        }
        result.regionTotalBytes = byteInfo.totalBytes;
        result.bytesResolution = byteInfo.resolution;
    } catch (err) {
        console.warn('[Explain] byte aggregation failed; payload omits byte counts:', err);
    }

    return result;
}

function _explainBuildPrompt(payload, systemPrompt, anomalyCtx) {
    const system = systemPrompt;

    const dataBlock = {
        closeTypeSummary: payload.closeTypeSummary,
        topInitiators: payload.topInitiators,
        topPairs: payload.topPairs,
        firstDegreeNeighbors: payload.firstDegreeNeighbors,
        neighborCount: payload.neighborCount,
        pivotHosts: payload.pivotHosts,
        pivotCount: payload.pivotCount,
        ipSample: payload.ipSample,
        groundTruthOverlap: payload.groundTruthOverlap
    };

    // If this panel was spawned by the AI anomaly detector, surface its
    // reasoning as cross-check context. The explainer is asked to verify or
    // refute it against the data, not to take it at face value.
    let anomalyBlock = '';
    if (anomalyCtx && (anomalyCtx.anomalyReason || anomalyCtx.anomalyEvidence)) {
        const parts = [];
        if (anomalyCtx.anomalyReason) parts.push(`reason: ${anomalyCtx.anomalyReason}`);
        if (anomalyCtx.anomalyEvidence) parts.push(`evidence: ${anomalyCtx.anomalyEvidence}`);
        if (anomalyCtx.anomalyConfidence != null) {
            parts.push(`confidence: ${anomalyCtx.anomalyConfidence}`);
        }
        anomalyBlock =
            `\nAn AI anomaly detector flagged this region with the following ` +
            `assessment (treat as a hypothesis to verify against the data below, ` +
            `not as ground truth — agree, disagree, or refine):\n  ` +
            parts.join('\n  ') + `\n`;
    }

    // Structured findings the detector recorded for this region (the "case file").
    // Framed as claims to verify/quantify with tools, not to re-litigate.
    let caseFileBlock = '';
    if (anomalyCtx && Array.isArray(anomalyCtx.caseFile) && anomalyCtx.caseFile.length > 0) {
        const lines = anomalyCtx.caseFile.map(f => {
            const bits = [];
            if (f.tool) bits.push(f.tool);
            if (f.metric) bits.push(f.metric);
            if (f.entity) bits.push(`entity=${f.entity}`);
            if (f.value != null) bits.push(`value=${f.value}`);
            if (f.baseline) bits.push(`baseline=${f.baseline}`);
            if (f.note) bits.push(`(${f.note})`);
            return '  - ' + bits.join(' ');
        });
        caseFileBlock =
            `\nThe detector recorded these findings for this region (its "case file" — ` +
            `verify and quantify them with your tools, then build the explanation; you may ` +
            `note discrepancies but do not re-litigate the verdict):\n` +
            lines.join('\n') + `\n`;
    }

    const user =
        `Region under inspection:\n` +
        `- Time window: ${payload.timeRange.startUTC} -> ${payload.timeRange.endUTC} ` +
        `(${payload.timeRange.durationSec}s)\n` +
        `- IP count: ${payload.ipCount}` +
        `${payload.ipSampleTruncated ? ' (sample shown)' : ''}\n` +
        `- Total flows in region: ${payload.totalFlows}\n` +
        anomalyBlock +
        caseFileBlock +
        `\nData:\n${JSON.stringify(dataBlock)}\n\n` +
        `Explain this region.`;

    return { system, user };
}

function _explainAttachToPanel(panel, lastArgs) {
    // Re-attach path: panel was restored on overlay rebuild. Refresh the lastArgs
    // reference (the original closure's lastArgs is now stale) and re-evaluate
    // staleness, but don't rebuild the bar or rewire the click handler.
    const existing = _explainPanels.get(panel);
    if (existing) {
        existing.lastArgs = lastArgs;
        _explainNotifyArgsChanged(panel);
        return;
    }

    // First-time attach. Panel children layout (from _spawnMagnifierPanel):
    //   [0] header, [1] tabStrip, [2] body, [3] bottomBar.
    // The explain panel is mounted as an absolutely positioned right-side column
    // spanning the body region. Body gets a right margin to make room.
    const header    = panel.children[0];
    const tabStrip  = panel.children[1];
    const body      = panel.children[2];
    const bottomBar = panel.children[3];
    if (!body || !bottomBar) return;

    const EXPLAIN_W = 320;
    const topOffset = (header ? header.offsetHeight : 0) + (tabStrip ? tabStrip.offsetHeight : 0);
    const bottomOffset = bottomBar.offsetHeight;

    const prevBodyMarginRight = body.style.marginRight || '';
    // Snapshot the panel's width on first attach so collapse/expand can grow
    // or restore it without compounding. Read offsetWidth (already rendered)
    // rather than parsing inline style, since the latter is set as "1000px"
    // but rounded layout values can differ slightly.
    const origPanelW = panel.offsetWidth;
    // Start collapsed — body keeps its full width until the user clicks the button.

    const explainBar = document.createElement('div');
    explainBar.className = 'magnifier-explain-bar';
    // Collapsed initial style: small floating button at the top-right of the
    // body region. setExpanded(true) below switches it to the full side column.
    Object.assign(explainBar.style, {
        position: 'absolute',
        top: `${topOffset + 6}px`, right: '6px',
        bottom: 'auto', width: 'auto',
        padding: '0', background: 'transparent',
        border: 'none',
        fontSize: '12px', fontFamily: 'sans-serif',
        display: 'flex', flexDirection: 'column', gap: '6px',
        overflow: 'visible', boxSizing: 'border-box'
    });

    const controls = document.createElement('div');
    Object.assign(controls.style, {
        display: 'flex', alignItems: 'center', gap: '10px',
        justifyContent: 'flex-end', flexWrap: 'wrap'
    });

    const runBtn = document.createElement('button');
    runBtn.type = 'button';
    runBtn.textContent = 'Explain this region';
    Object.assign(runBtn.style, {
        padding: '3px 10px', fontSize: '12px', cursor: 'pointer',
        border: '1px solid #adb5bd', borderRadius: '3px',
        background: '#fff', fontFamily: 'inherit'
    });

    const staleEl = document.createElement('span');
    staleEl.textContent = '⚠ region changed';
    Object.assign(staleEl.style, { color: '#b45309', fontSize: '11px', display: 'none' });

    const statusEl = document.createElement('span');
    Object.assign(statusEl.style, { color: '#6c757d', fontSize: '11px' });

    controls.appendChild(runBtn);
    controls.appendChild(staleEl);
    controls.appendChild(statusEl);

    const textEl = document.createElement('div');
    Object.assign(textEl.style, {
        whiteSpace: 'pre-wrap', lineHeight: '1.4',
        color: '#212529', fontSize: '12px', fontFamily: 'sans-serif',
        display: 'none'
    });

    explainBar.appendChild(controls);
    explainBar.appendChild(textEl);
    panel.appendChild(explainBar);

    const setExpanded = (val) => {
        if (val) {
            Object.assign(explainBar.style, {
                top: `${topOffset}px`, bottom: `${bottomOffset}px`, right: '0',
                width: `${EXPLAIN_W}px`,
                padding: '8px 10px', background: '#f8f9fa',
                border: 'none', borderLeft: '1px solid #dee2e6',
                overflow: 'auto'
            });
            // Grow the panel rightward by EXPLAIN_W so the body keeps its
            // original visualization width. body.marginRight reserves the
            // EXPLAIN_W column at the right edge for the absolutely-positioned
            // explainBar; without it, the body would stretch under the bar.
            panel.style.width = `${origPanelW + EXPLAIN_W}px`;
            body.style.marginRight = `${EXPLAIN_W}px`;
            // If the expanded panel would overflow the right edge of the
            // viewport, slide it left so it stays on-screen. User can still
            // drag it back.
            const panelLeft = parseFloat(panel.style.left) || 0;
            const overflow = (panelLeft + origPanelW + EXPLAIN_W) - window.innerWidth;
            if (overflow > 0) {
                panel.style.left = `${Math.max(0, panelLeft - overflow)}px`;
            }
            textEl.style.display = '';
            controls.style.justifyContent = 'flex-end';
        } else {
            Object.assign(explainBar.style, {
                top: `${topOffset + 6}px`, bottom: 'auto', right: '6px',
                width: 'auto',
                padding: '0', background: 'transparent',
                border: 'none', borderLeft: 'none',
                overflow: 'visible'
            });
            panel.style.width = `${origPanelW}px`;
            body.style.marginRight = prevBodyMarginRight;
            textEl.style.display = 'none';
        }
    };

    const record = {
        explainBar, runBtn, staleEl, statusEl, textEl,
        body, prevBodyMarginRight, setExpanded,
        panel, origPanelW,
        lastArgs, lastFetchedKey: null, abortController: null, busy: false
    };
    _explainPanels.set(panel, record);

    runBtn.addEventListener('click', () => {
        setExpanded(true);
        _explainRun(panel);
    });
}

function _explainNotifyArgsChanged(panel) {
    const rec = _explainPanels.get(panel);
    if (!rec || rec.busy) return;
    // No prior result: leave button at its default visible state; no stale badge.
    if (!rec.lastFetchedKey) { rec.staleEl.style.display = 'none'; return; }
    const key = _explainCacheKey(rec.lastArgs.ips, rec.lastArgs.tMin, rec.lastArgs.tMax);
    if (key === rec.lastFetchedKey) {
        // Current region matches what is displayed: hide both badge and button.
        rec.staleEl.style.display = 'none';
        rec.runBtn.style.display = 'none';
    } else {
        // Current region differs from what is displayed: show button + stale badge.
        rec.staleEl.style.display = '';
        rec.runBtn.style.display = '';
        rec.runBtn.textContent = 'Refresh explanation';
    }
}

function _explainDetach(panel) {
    const rec = _explainPanels.get(panel);
    if (!rec) return;
    try { if (rec.abortController) rec.abortController.abort(); } catch (e) {}
    try { rec.explainBar.remove(); } catch (e) {}
    try { if (rec.body) rec.body.style.marginRight = rec.prevBodyMarginRight || ''; } catch (e) {}
    // Restore the panel's pre-expansion width. If the user closes the panel
    // while the explain bar is expanded, leaving the panel widened would
    // strand the next-rendered panel (panel re-use after a brush restore).
    try { if (rec.panel && rec.origPanelW) rec.panel.style.width = `${rec.origPanelW}px`; } catch (e) {}
    _explainPanels.delete(panel);
}

function _explainRenderResult(rec, text, isError) {
    rec.textEl.style.color = isError ? '#b91c1c' : '#212529';
    rec.textEl.textContent = text;
    rec.statusEl.textContent = '';
    if (!isError) {
        rec.staleEl.style.display = 'none';
        rec.runBtn.style.display = 'none';   // result matches current region: hide button
    } else {
        rec.runBtn.style.display = '';        // error: keep button visible for retry
    }
    rec.runBtn.disabled = false;
    rec.busy = false;
}

async function _explainRun(panel) {
    const rec = _explainPanels.get(panel);
    if (!rec || rec.busy) return;

    const ips = rec.lastArgs.ips;
    const tMin = rec.lastArgs.tMin;
    const tMax = rec.lastArgs.tMax;
    // Optional context from the AI anomaly detector (empty strings / null when
    // this panel was opened by a user-drawn brush rather than an AI region).
    const anomalyReason = rec.lastArgs.anomalyReason || '';
    const anomalyEvidence = rec.lastArgs.anomalyEvidence || '';
    const anomalyConfidence = rec.lastArgs.anomalyConfidence;
    const caseFile = rec.lastArgs.caseFile || null;

    if (!Array.isArray(ips) || ips.length === 0) {
        _explainRenderResult(rec, 'No IPs in this region to explain.', true);
        return;
    }
    if (typeof tMin !== 'number' || typeof tMax !== 'number' || tMin >= tMax) {
        _explainRenderResult(rec, 'Invalid time range.', true);
        return;
    }

    const cacheKey = _explainCacheKey(ips, tMin, tMax);
    const cached = _explainCache.get(cacheKey);
    if (cached) {
        rec.lastFetchedKey = cacheKey;
        rec.runBtn.textContent = 'Refresh explanation';
        // Re-run extract + notify on cache hit too, in case _roleMapCache lost
        // its entry (e.g. across a page reload — _explainCache currently
        // persists only in module scope, but defensively re-extract).
        const prose = _explainAcceptResult(panel, cacheKey, cached);
        _explainRenderResult(rec, prose, false);
        return;
    }

    rec.busy = true;
    rec.runBtn.disabled = true;
    rec.staleEl.style.display = 'none';
    rec.statusEl.textContent = 'Analyzing…';
    rec.textEl.style.color = '#6c757d';
    rec.textEl.textContent = '';

    const key = await _explainFetchKey();
    if (!key) {
        _explainRenderResult(rec,
            'No API key found. Create anthropic_key.txt in the project root containing ' +
            'your Anthropic API key on a single line.', true);
        return;
    }

    const systemPrompt = await _explainFetchSystemPrompt();
    if (!systemPrompt) {
        _explainRenderResult(rec,
            'System prompt file missing or empty. Create explain_system_prompt.txt in ' +
            'the project root.', true);
        return;
    }

    const payload = await _explainBuildPayload(ips, tMin, tMax);
    if (payload.totalFlows === 0) {
        _explainRenderResult(rec, 'No flows in this region — nothing to explain.', true);
        return;
    }
    const prompt = _explainBuildPrompt(payload, systemPrompt, {
        anomalyReason, anomalyEvidence, anomalyConfidence, caseFile
    });

    rec.abortController = new AbortController();
    try {
        const scopedDispatch = makeExplainDispatch(ips, tMin, tMax, await _ensureIpMetaMap());
        const text = await _aiAgenticLoop({
            label: 'Explain',
            systemPrompt: prompt.system,
            userMessage: prompt.user,
            key,
            maxTurns: _EXPLAIN_MAX_TURNS,
            maxTokens: _EXPLAIN_MAX_TOKENS,
            tools: _EXPLAIN_TOOLS,
            dispatchTool: scopedDispatch,
            abortSignal: rec.abortController.signal,
            onTurn: (turn) => { rec.statusEl.textContent = `Analyzing… (step ${turn}/${_EXPLAIN_MAX_TURNS})`; }
        });
        rec.lastFetchedKey = cacheKey;
        rec.runBtn.textContent = 'Refresh explanation';
        const prose = _explainAcceptResult(panel, cacheKey, text);
        _explainRenderResult(rec, prose, false);
    } catch (err) {
        if (err && err.name === 'AbortError') return;  // panel closed mid-fetch
        const msg = String((err && err.message) || err);
        let display;
        if (msg.includes('HTTP 401')) {
            display = 'API key rejected (401). Check anthropic_key.txt.';
            _explainApiKey = null;  // force re-read of the key file on the next attempt
        } else if (msg.includes('HTTP 429')) {
            display = 'Rate limit hit (429). Wait a moment and try again.';
        } else if (msg.includes('HTTP 529')) {
            display = 'API overloaded (529). Try again in a moment.';
        } else if (/HTTP 5\d\d/.test(msg)) {
            display = 'Anthropic service error. Try again later.';
        } else if (msg.includes('exceeded') && msg.includes('turns')) {
            display = "Couldn't complete the analysis (too many steps). Try again.";
        } else if (msg === 'empty' || msg.includes('empty')) {
            display = 'Empty response from API. Try again.';
        } else {
            display = `Network error: ${msg}`;
        }
        _explainRenderResult(rec, display, true);
    } finally {
        rec.abortController = null;
    }
}

// ============================================================================
// Headless single-region explain — same logic as _explainRun but with no panel
// UI. Called by the batch "Explain all regions" driver below.
// ============================================================================

async function _explainRunHeadless(lastArgs, abortSignal, opts = {}) {
    const ips              = lastArgs.ips;
    const tMin             = lastArgs.tMin;
    const tMax             = lastArgs.tMax;
    const anomalyReason    = lastArgs.anomalyReason    || '';
    const anomalyEvidence  = lastArgs.anomalyEvidence  || '';
    const anomalyConfidence = lastArgs.anomalyConfidence;
    const caseFile         = lastArgs.caseFile         || null;

    if (!Array.isArray(ips) || ips.length === 0) return { status: 'skip' };
    if (typeof tMin !== 'number' || typeof tMax !== 'number' || tMin >= tMax) return { status: 'skip' };

    const cacheKey = _explainCacheKey(ips, tMin, tMax);
    // When force is requested, evict both the explanation and the role-map
    // from cache before the .has check so the run proceeds unconditionally.
    if (opts.force) {
        _explainCache.delete(cacheKey);
        _roleMapCache.delete(cacheKey);
    }
    if (_explainCache.has(cacheKey)) return { status: 'cached' };

    const key = await _explainFetchKey();
    if (!key) return { status: 'error', reason: 'key' };

    const systemPrompt = await _explainFetchSystemPrompt();
    if (!systemPrompt) return { status: 'error', reason: 'prompt' };

    const payload = await _explainBuildPayload(ips, tMin, tMax);
    if (payload.totalFlows === 0) return { status: 'skip' };

    const prompt = _explainBuildPrompt(payload, systemPrompt, {
        anomalyReason, anomalyEvidence, anomalyConfidence, caseFile
    });

    const scopedDispatch = makeExplainDispatch(ips, tMin, tMax, await _ensureIpMetaMap());

    try {
        const text = await _aiAgenticLoop({
            label: 'Explain',
            systemPrompt: prompt.system,
            userMessage: prompt.user,
            key,
            maxTurns: _EXPLAIN_MAX_TURNS,
            maxTokens: _EXPLAIN_MAX_TOKENS,
            tools: _EXPLAIN_TOOLS,
            dispatchTool: scopedDispatch,
            abortSignal
        });
        _explainAcceptResult(null, cacheKey, text);
        return { status: 'done' };
    } catch (err) {
        if (err && err.name === 'AbortError') throw err;  // let batch loop catch this
        console.warn('[ExplainAll] Region explain failed:', err);
        return { status: 'failed', error: String(err && err.message || err) };
    }
}

// ============================================================================
// Shared AI helpers — used by both the anomaly detector and the network-tab
// denoiser. Both features call the same Claude messages endpoint with the same
// tools, so the agentic loop and the JSON-fence stripper are factored out.
// ============================================================================

// Anthropic returns 429 (rate limit), 529 (overloaded), or 5xx (service) on
// transient capacity errors. The shared agentic loop retries these with
// exponential backoff. Non-retryable codes (401 auth, 400 bad request, etc.)
// fail fast.
const _AI_RETRYABLE_STATUSES = new Set([429, 500, 502, 503, 504, 529]);
const _AI_MAX_RETRIES = 3;
const _AI_RETRY_BASE_MS = 1000;  // 1s, 2s, 4s

// Promise-based sleep that aborts if the caller's signal aborts. The agentic
// loop passes abortSignal into fetch; threading it into the retry sleep too
// keeps panel-close / tab-switch responsive even during a backoff wait.
function _aiSleepWithAbort(ms, abortSignal) {
    return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
            if (abortSignal) abortSignal.removeEventListener('abort', onAbort);
            resolve();
        }, ms);
        const onAbort = () => {
            clearTimeout(timer);
            reject(new DOMException('Aborted', 'AbortError'));
        };
        if (abortSignal) {
            if (abortSignal.aborted) { clearTimeout(timer); onAbort(); return; }
            abortSignal.addEventListener('abort', onAbort, { once: true });
        }
    });
}

// fetch wrapper with retry on transient Anthropic errors. Returns the final
// Response on success or throws Error('HTTP NNN: …') on a non-retryable
// failure / exhausted retries.
async function _aiFetchWithRetry(url, init, label) {
    let lastStatus = 0;
    let lastBody = '';
    for (let attempt = 0; attempt <= _AI_MAX_RETRIES; attempt++) {
        const resp = await fetch(url, init);
        if (resp.ok) return resp;
        // Read the body now (consumable once); use for both retry-log and final throw.
        const body = await resp.text().catch(() => '');
        lastStatus = resp.status;
        lastBody = body;
        if (_AI_RETRYABLE_STATUSES.has(resp.status) && attempt < _AI_MAX_RETRIES) {
            const wait = _AI_RETRY_BASE_MS * Math.pow(2, attempt);
            console.warn(`[${label}] HTTP ${resp.status} — retrying in ${wait}ms (attempt ${attempt + 1}/${_AI_MAX_RETRIES})`);
            await _aiSleepWithAbort(wait, init.signal);
            continue;
        }
        // Non-retryable, or retries exhausted.
        throw new Error(`HTTP ${resp.status}: ${body.slice(0, 200)}`);
    }
    // Unreachable, but keep TS-style invariant.
    throw new Error(`HTTP ${lastStatus}: ${lastBody.slice(0, 200)}`);
}

// Strip markdown ```json fences if present and return the inner text trimmed.
// Returns '' for non-string input.
function _stripJsonFences(text) {
    if (typeof text !== 'string') return '';
    let candidate = text.trim();
    const fenceMatch = candidate.match(/```(?:json)?\s*([\s\S]*?)\s*```/i);
    if (fenceMatch) candidate = fenceMatch[1].trim();
    return candidate;
}

// Generic Claude tool-use loop. Caller supplies the system prompt, the initial
// user message, the tool list, and a synchronous tool dispatcher. Returns the
// final assistant text once the loop reaches a non-tool_use stop_reason.
// Throws on HTTP error, malformed response, or turn-ceiling exhaustion.
// AbortSignal is propagated to fetch.
// Convert Anthropic tool schema to OpenAI function-calling tool schema.
function _anthropicToolsToOpenAI(tools) {
    return tools.map(t => ({
        type: 'function',
        function: {
            name: t.name,
            description: t.description || '',
            parameters: t.input_schema || { type: 'object', properties: {} }
        }
    }));
}

async function _aiAgenticLoop(opts) {
    const { label, systemPrompt, userMessage, key, maxTurns, maxTokens,
            tools, dispatchTool, abortSignal, onTurn } = opts;
    const messages = [{ role: 'user', content: userMessage }];
    console.groupCollapsed(`[${label}] Tool-use session`);
    try {
        for (let turn = 1; turn <= maxTurns; turn++) {
            if (onTurn) onTurn(turn);

            let data;
            if (_AI_PROVIDER === 'openai') {
                // --- OpenAI-compatible path (LM Studio, etc.) ---
                const openaiMessages = [
                    { role: 'system', content: systemPrompt },
                    ...messages
                ];
                const resp = await _aiFetchWithRetry(_EXPLAIN_API_URL, {
                    method: 'POST',
                    headers: {
                        'content-type': 'application/json',
                        'Authorization': `Bearer ${key}`
                    },
                    body: JSON.stringify({
                        model: _EXPLAIN_MODEL,
                        max_tokens: maxTokens,
                        temperature: 0,
                        messages: openaiMessages,
                        tools: _anthropicToolsToOpenAI(tools)
                    }),
                    signal: abortSignal
                }, label);
                const raw = await resp.json();
                const choice = raw.choices && raw.choices[0];
                if (!choice) throw new Error('empty');
                const msg = choice.message;
                // Convert to Anthropic-shaped content blocks so downstream
                // logging + tool-dispatch code stays identical.
                const content = [];
                if (msg.content) content.push({ type: 'text', text: msg.content });
                if (msg.tool_calls) {
                    for (const tc of msg.tool_calls) {
                        let parsedInput = {};
                        try { parsedInput = JSON.parse(tc.function.arguments); } catch { /* ignore */ }
                        content.push({ type: 'tool_use', id: tc.id, name: tc.function.name, input: parsedInput });
                    }
                }
                const stop_reason = choice.finish_reason === 'tool_calls' ? 'tool_use' : choice.finish_reason;
                data = { content, stop_reason };
                // Store the assistant turn in OpenAI's native shape so subsequent
                // requests to the same endpoint remain well-formed.
                const historyMsg = { role: 'assistant', content: msg.content || '' };
                if (msg.tool_calls) historyMsg.tool_calls = msg.tool_calls;
                messages.push(historyMsg);
            } else {
                // --- Anthropic path (unchanged) ---
                const resp = await _aiFetchWithRetry(_EXPLAIN_API_URL, {
                    method: 'POST',
                    headers: {
                        'content-type': 'application/json',
                        'x-api-key': key,
                        'anthropic-version': '2023-06-01',
                        'anthropic-dangerous-direct-browser-access': 'true'
                    },
                    body: JSON.stringify({
                        model: _EXPLAIN_MODEL,
                        max_tokens: maxTokens,
                        temperature: 0,
                        system: [{ type: 'text', text: systemPrompt, cache_control: { type: 'ephemeral' } }],
                        tools: tools.map((t, i) => i === tools.length - 1
                            ? { ...t, cache_control: { type: 'ephemeral' } }
                            : t),
                        messages
                    }),
                    signal: abortSignal
                }, label);
                data = await resp.json();
                if (data.usage) {
                    const u = data.usage;
                    console.log(`[turn ${turn}] usage: input=${u.input_tokens} cache_create=${u.cache_creation_input_tokens || 0} cache_read=${u.cache_read_input_tokens || 0} output=${u.output_tokens}`);
                }
                const content = Array.isArray(data && data.content) ? data.content : null;
                if (!content) throw new Error('empty');
                data = { content, stop_reason: data.stop_reason };
                messages.push({ role: 'assistant', content });
            }

            // --- Shared logging ---
            const content = data.content;
            for (const block of content) {
                if (block.type === 'text' && block.text) {
                    console.log(`[turn ${turn}] reasoning:`, block.text);
                } else if (block.type === 'tool_use') {
                    console.log(`[turn ${turn}] tool_use:`, block.name, block.input);
                }
            }

            // --- Shared tool-dispatch ---
            if (data.stop_reason === 'tool_use') {
                const toolUses = content.filter(b => b && b.type === 'tool_use');
                if (toolUses.length === 0) break;

                if (_AI_PROVIDER === 'openai') {
                    // OpenAI: each tool result is a separate {role:'tool'} message
                    for (const tu of toolUses) {
                        const result = await dispatchTool(tu.name, tu.input || {});
                        const resultStr = JSON.stringify(result);
                        const preview = resultStr.length > 600
                            ? resultStr.slice(0, 600) + ` … (${resultStr.length} chars total)`
                            : resultStr;
                        console.log(`[turn ${turn}] tool_result(${tu.name}):`, preview);
                        messages.push({ role: 'tool', tool_call_id: tu.id, content: resultStr });
                    }
                } else {
                    // Anthropic: all tool results in a single user message
                    const toolResults = await Promise.all(toolUses.map(async tu => {
                        const result = await dispatchTool(tu.name, tu.input || {});
                        const resultStr = JSON.stringify(result);
                        const preview = resultStr.length > 600
                            ? resultStr.slice(0, 600) + ` … (${resultStr.length} chars total)`
                            : resultStr;
                        console.log(`[turn ${turn}] tool_result(${tu.name}):`, preview);
                        return { type: 'tool_result', tool_use_id: tu.id, content: resultStr };
                    }));
                    messages.push({ role: 'user', content: toolResults });
                }
                continue;
            }

            const text = content.filter(b => b && b.type === 'text').map(b => b.text || '').join('\n');
            console.log(`[turn ${turn}] FINAL (stop_reason=${data.stop_reason}):`, text);
            return text;
        }
        throw new Error(`Tool-use loop exceeded ${maxTurns} turns`);
    } finally {
        console.groupEnd();
    }
}

// ============================================================================
// "Detect anomalies" feature — agentic tool-use.
//
// Claude is given query tools over state.flowView.binnedData and decides for
// itself how to scan the data. The loop iterates assistant <-> tool_result
// until Claude returns a final assistant message (text) containing the JSON
// regions. Each region becomes a dormant edit-brush rectangle via
// _magnifierOverlayCtx.createSelection — the same code path a user-drawn
// brush goes through. Clicking the rect spawns the magnifier panel.
//
// Reuses the explain feature's API key file (anthropic_key.txt). System
// prompt lives in anomaly_system_prompt.txt. To remove the feature: delete
// the state declarations below, this block, the #detectAnomaliesBtn wiring
// near _initFlowOnlyChart, and the button element in tcp-flow-analysis.html.
// ============================================================================

const _ANOMALY_PROMPT_PATH = './anomaly_system_prompt.txt';
const _ANOMALY_MAX_TOKENS = 16384;
const _ANOMALY_MAX_TURNS = 40;  // hard ceiling on tool-use rounds

const _anomalySystemPromptHolder = { value: null, promise: null };
let _anomalyBusy = false;
let _anomalyAbortController = null;
// Union of IPs flagged by the most recent AI anomaly detection run. Read by
// the magnifier Network tab to color/pin those IPs in the force graph.
const _anomalyFlaggedIPs = new Set();

async function _anomalyFetchSystemPrompt() {
    // Always re-fetch so prompt edits take effect without page reload.
    // Anthropic API prompt caching (cache_control) still works — it's hash-based.
    _anomalySystemPromptHolder.value = null;
    return _fetchCachedText(_ANOMALY_PROMPT_PATH, _anomalySystemPromptHolder);
}

// --- Packet-derived feature artifact (offline; see build_anomaly_features.py) ---
// Loaded lazily at the start of a detection run. Optional & ADDITIVE: if the file is
// absent or its time range doesn't match the loaded dataset, _anomalyFeatures stays
// null and the packet-backed tools report {available:false}, leaving the original
// flow-level detector completely unchanged (no-regression guarantee).
const _ANOMALY_FEATURES_PATH = './anomaly_features.json';
let _anomalyFeatures = null;        // { timeRange, responders[], portCoordination[] } | null
let _anomalyFeaturesIndex = null;   // { byResponderIp:Map<ip,rec[]> }
let _anomalyFeaturesPromise = null;

async function _anomalyLoadFeatures() {
    if (_anomalyFeatures) return _anomalyFeatures;
    if (_anomalyFeaturesPromise) return _anomalyFeaturesPromise;
    _anomalyFeaturesPromise = (async () => {
        try {
            const resp = await fetch(_ANOMALY_FEATURES_PATH, { cache: 'no-store' });
            if (!resp.ok) {
                console.log('[Anomaly] No packet feature artifact (HTTP ' + resp.status + ') — flow-level tools only.');
                return null;
            }
            const data = await resp.json();
            // Validate the artifact matches the loaded dataset (>50% time-extent overlap).
            const ext = state.data.timeExtent || [0, 0];
            const tr = data && data.timeRange;
            const span = ext[1] - ext[0];
            const overlaps = tr && span > 0 &&
                (Math.min(tr.end, ext[1]) - Math.max(tr.start, ext[0])) > 0.5 * span;
            if (!overlaps) {
                console.warn('[Anomaly] Feature artifact timeRange', tr,
                    'does not match loaded extent', ext, '— ignoring artifact.');
                return null;
            }
            const byResponderIp = new Map();
            for (const r of data.responders || []) {
                if (!byResponderIp.has(r.ip)) byResponderIp.set(r.ip, []);
                byResponderIp.get(r.ip).push(r);
            }
            _anomalyFeatures = data;
            _anomalyFeaturesIndex = { byResponderIp };
            console.log(`[Anomaly] Loaded packet features: ${(data.responders || []).length} responder-buckets, ` +
                `${(data.portCoordination || []).length} coordinated ports.`);
            return data;
        } catch (e) {
            console.warn('[Anomaly] Failed to load feature artifact:', e);
            return null;
        } finally {
            _anomalyFeaturesPromise = null;
        }
    })();
    return _anomalyFeaturesPromise;
}

// ============================================================================
// ALGORITHM-EXECUTION DETECTION (Approach C / Option 1)
// Deterministic scorers Claude runs via run_* tools. See
// docs/superpowers/specs/2026-05-21-anomaly-detection-algorithm-tools-design.md
// ============================================================================

// One-sided upper-tail probability of the standard normal at z, i.e. P(Z >= z).
// Abramowitz & Stegun 7.1.26 erf approximation (abs error < 1.5e-7). Used to turn
// a robust-z score into a p-value for ranked-outlier reporting.
function _anomalyNormalUpperTail(z) {
    if (!Number.isFinite(z)) return z > 0 ? 0 : 1;
    const x = Math.abs(z) / Math.SQRT2;
    const t = 1 / (1 + 0.3275911 * x);
    const erf = 1 - ((((1.061405429 * t - 1.453152027) * t + 1.421413741) * t
        - 0.284496736) * t + 0.254829592) * t * Math.exp(-x * x);
    const upperPos = 0.5 * (1 - erf);   // P(Z >= |z|)
    return z >= 0 ? upperPos : 1 - upperPos;
}

// Upper-tail Poisson probability P(X >= k | lambda). Exact summation for small
// lambda; normal approximation with continuity correction for large lambda to
// avoid factorial overflow. Used by the burst scorer.
function _anomalyPoissonUpperTail(k, lambda) {
    if (lambda <= 0) return k > 0 ? 0 : 1;
    if (k <= 0) return 1;
    if (lambda > 1000) {
        return _anomalyNormalUpperTail((k - 0.5 - lambda) / Math.sqrt(lambda));
    }
    let term = Math.exp(-lambda);   // i = 0 term
    let cdf = term;
    for (let i = 1; i < k; i++) { term *= lambda / i; cdf += term; }
    return Math.max(0, 1 - cdf);
}

// Aggregate snapshot consumed by every scorer. Optional [t0,t1] restricts the
// flow-level aggregation to a window (packet-level inputs stay full-extent).
function _anomalyBuildFeatureTable(t0, t1) {
    const binnedData = (state.flowView && state.flowView.binnedData) || [];
    const timeExtent = state.data.timeExtent || [0, 0];
    const lo = Number.isFinite(Number(t0)) ? Number(t0) : timeExtent[0];
    const hi = Number.isFinite(Number(t1)) ? Number(t1) : timeExtent[1];
    const GRACEFUL = 'graceful';
    const initiators = new Map();   // ip -> {total, nonGraceful, responders:Set, tmin, tmax}
    const respFlow = new Map();     // ip -> {total, initiators:Set}
    for (const d of binnedData) {
        if (!d) continue;
        const c = d.count || 0;
        if (c === 0) continue;
        const bs = d.binStart ?? d.startTime ?? 0;
        const be = d.binEnd ?? d.endTime ?? bs;
        if (be < lo || bs > hi) continue;
        const ct = d.closeType || 'unknown';
        if (d.initiator) {
            let a = initiators.get(d.initiator);
            if (!a) { a = { total: 0, nonGraceful: 0, responders: new Set(), tmin: Infinity, tmax: -Infinity }; initiators.set(d.initiator, a); }
            a.total += c;
            if (ct !== GRACEFUL) a.nonGraceful += c;
            if (d.responder) a.responders.add(d.responder);
            if (bs < a.tmin) a.tmin = bs;
            if (be > a.tmax) a.tmax = be;
        }
        if (d.responder) {
            let r = respFlow.get(d.responder);
            if (!r) { r = { total: 0, initiators: new Set() }; respFlow.set(d.responder, r); }
            r.total += c;
            if (d.initiator) r.initiators.add(d.initiator);
        }
    }
    return {
        timeExtent: [lo, hi],
        initiators, respFlow,
        responderBuckets: (_anomalyFeatures && _anomalyFeatures.responders) || null,
        portCoordination: (_anomalyFeatures && _anomalyFeatures.portCoordination) || null
    };
}

// Rank entities by robust-z (Iglewicz-Hoaglin, reusing _anomalyRobustZ). Returns
// the uniform scorer row shape: {entity, value, score, pValue, rank, total, window}.
function _anomalyRankByRobustZ(pairs, window) {
    const vals = pairs.map(p => p.value);
    const med = _anomalyMedian(vals);
    const mad = _anomalyMedian(vals.map(v => Math.abs(v - med)));
    const total = pairs.length;
    const rows = pairs.map(p => {
        const z = _anomalyRobustZ(p.value, med, mad, vals);
        return {
            entity: p.entity, value: p.value,
            score: Number.isFinite(z) ? Number(z.toFixed(3)) : 999,
            pValue: _anomalyNormalUpperTail(z), window
        };
    });
    rows.sort((a, b) => b.score - a.score);
    rows.forEach((r, i) => { r.rank = i + 1; r.total = total; });
    return rows;
}

// Registry of deterministic scorers. Each: (featureTable, params) -> rankedRows.
// A future run_code tool (Option 2) registers one more key here; nothing else changes.
const _ANOMALY_SCORERS = {
    // Per-initiator non-graceful flow volume.
    volume(ft) {
        const pairs = [];
        for (const [ip, a] of ft.initiators) pairs.push({ entity: ip, value: a.nonGraceful });
        return _anomalyRankByRobustZ(pairs, ft.timeExtent);
    },
    // Per-initiator distinct responders touched (scan / spray signal).
    fanout(ft) {
        const pairs = [];
        for (const [ip, a] of ft.initiators) pairs.push({ entity: ip, value: a.responders.size });
        return _anomalyRankByRobustZ(pairs, ft.timeExtent);
    },
    // Per-responder fan-in: distinct initiators converging on a target. Prefers the
    // packet-feature peak-per-bucket value; falls back to flow-level distinct count.
    fanin(ft) {
        const peak = new Map();
        if (ft.responderBuckets) {
            for (const rec of ft.responderBuckets) {
                const c = peak.get(rec.ip) || 0;
                if (rec.distinctInitiators > c) peak.set(rec.ip, rec.distinctInitiators);
            }
        } else {
            for (const [ip, r] of ft.respFlow) peak.set(ip, r.initiators.size);
        }
        const pairs = [...peak.entries()].map(([ip, v]) => ({ entity: ip, value: v }));
        return _anomalyRankByRobustZ(pairs, ft.timeExtent);
    },
    // Per-time-bucket total flow count; Poisson upper-tail p-value vs the mean rate.
    // params.close_type optional (filter to one close-type); params.resolution = bucket count.
    burst(ft, params) {
        const binnedData = (state.flowView && state.flowView.binnedData) || [];
        const filterCt = params && params.close_type ? String(params.close_type) : null;
        const n = Math.max(2, Math.min(500, Number(params && params.resolution) || 120));
        const [tMin, tMax] = ft.timeExtent;
        const span = Math.max(1, tMax - tMin);
        const w = span / n;
        const counts = new Array(n).fill(0);
        for (const d of binnedData) {
            if (!d) continue;
            if (filterCt && (d.closeType || 'unknown') !== filterCt) continue;
            const bs = d.binStart ?? d.startTime ?? 0;
            if (bs < tMin || bs > tMax) continue;
            const idx = Math.min(n - 1, Math.max(0, Math.floor((bs - tMin) / w)));
            counts[idx] += d.count || 0;
        }
        const total = counts.reduce((a, b) => a + b, 0);
        const lambda = total / n;
        const rows = counts.map((c, i) => {
            const p = _anomalyPoissonUpperTail(c, lambda);
            return {
                entity: `bucket#${i}`, value: c,
                score: Number((p > 0 ? -Math.log10(p) : 300).toFixed(3)), pValue: p,
                window: [Math.round(tMin + i * w), Math.round(tMin + (i + 1) * w)]
            };
        });
        rows.sort((a, b) => b.score - a.score);
        rows.forEach((r, i) => { r.rank = i + 1; r.total = n; });
        return rows;
    },
    // Per-destination-port internal-host convergence (packet artifact). Score combines
    // the peak/median spike with the internal:responder concentration ratio.
    coordination(ft, params) {
        if (!ft.portCoordination) return [];
        const minInternal = Math.max(1, Number(params && params.min_internal) || 3);
        const rows = ft.portCoordination
            .filter(p => p.windowInternalInitiators >= minInternal)
            .map(p => {
                const spike = p.medianInternalInitiators > 0
                    ? p.peakInternalInitiators / p.medianInternalInitiators
                    : p.peakInternalInitiators;
                const concentration = p.windowDistinctResponders > 0
                    ? p.windowInternalInitiators / p.windowDistinctResponders
                    : p.windowInternalInitiators;
                return {
                    entity: `port:${p.port}`, port: p.port, value: p.windowInternalInitiators,
                    score: Number((Math.log2(1 + spike) * Math.log2(1 + concentration)).toFixed(3)),
                    pValue: null,
                    windowInternalInitiators: p.windowInternalInitiators,
                    windowDistinctResponders: p.windowDistinctResponders,
                    peakInternalInitiators: p.peakInternalInitiators,
                    medianInternalInitiators: p.medianInternalInitiators,
                    window: [p.peakTStartUs, p.peakTEndUs]
                };
            });
        rows.sort((a, b) => b.score - a.score);
        rows.forEach((r, i) => { r.rank = i + 1; r.total = rows.length; });
        return rows;
    }
};

// --- Tool definitions sent to Claude ---------------------------------------

const _ANOMALY_TOOLS = [
    {
        name: 'run_outlier_detection',
        description: 'PRIMARY DISCOVERY TOOL. Runs a deterministic outlier-detection algorithm across the WHOLE population and returns entities ranked by anomaly score. metric: "volume" (per-initiator non-graceful flows), "fanin" (per-responder distinct initiators — catches DDoS/convergence victims), or "fanout" (per-initiator distinct responders — catches scans). method: "robust_z" (Iglewicz-Hoaglin). Each row has {entity, value, score (robust-z; higher=more anomalous), pValue, rank, total}. Trust the computed score/rank — do not apply your own threshold. Optionally restrict to a time window with t_start_us/t_end_us.',
        input_schema: {
            type: 'object',
            properties: {
                metric: { type: 'string', description: '"volume" | "fanin" | "fanout".' },
                method: { type: 'string', description: 'Currently "robust_z" (default).' },
                t_start_us: { type: 'number', description: 'Optional window start; omit for full extent.' },
                t_end_us: { type: 'number', description: 'Optional window end; omit for full extent.' },
                max_results: { type: 'integer', description: 'Max ranked rows. Default 25, cap 100.' }
            },
            required: ['metric']
        }
    },
    {
        name: 'run_burst_detection',
        description: 'Runs Poisson burst detection over per-time-bucket flow counts and returns buckets ranked by surprise. score = -log10(Poisson upper-tail p-value of the bucket count given the mean rate); higher = more anomalous burst. Optionally filter to one close_type. resolution = number of time buckets (default 120).',
        input_schema: {
            type: 'object',
            properties: {
                close_type: { type: 'string', description: 'Optional close-type filter; omit for all flows.' },
                resolution: { type: 'integer', description: 'Number of time buckets. Default 120.' },
                max_results: { type: 'integer', description: 'Max ranked buckets. Default 25, cap 100.' }
            },
            required: []
        }
    },
    {
        name: 'run_coordination_scan',
        description: 'PACKET-DERIVED. Scores destination ports by internal-host convergence: combines the peak-vs-median spike with the internal-initiator:responder concentration ratio. High score = many internal hosts funneling into few responders on one service (spambot/worm coordination). Returns ports ranked by score with their raw fields. Returns an empty list if the packet feature artifact is not loaded.',
        input_schema: {
            type: 'object',
            properties: {
                min_internal: { type: 'integer', description: 'Min distinct internal initiators over the window. Default 3.' },
                max_results: { type: 'integer', description: 'Max ranked ports. Default 40, cap 80.' }
            },
            required: []
        }
    },
    {
        name: 'cluster_cohort',
        description: 'Groups a provided list of candidate IPs into coordinated cohorts by shared /24 (by="subnet24") or /16 (by="subnet16"). Use after a run_* tool surfaces many similar outliers, to decide whether they form one coordinated group (emit one region over the cohort) rather than many singletons.',
        input_schema: {
            type: 'object',
            properties: {
                entities: { type: 'array', items: { type: 'string' }, description: 'Candidate IPs to group.' },
                by: { type: 'string', description: '"subnet24" (default) or "subnet16".' }
            },
            required: ['entities']
        }
    },
    {
        name: 'get_overview',
        description: 'Get global statistics for the entire flow dataset: total flows, close-type counts (graceful, abortive, rst_during_handshake, invalid_synack, invalid_ack, incomplete_no_synack, incomplete_no_ack, unknown_invalid, open), time extent in microseconds, and number of distinct initiator IPs. Call this first.',
        input_schema: { type: 'object', properties: {}, required: [] }
    },
    {
        name: 'get_close_type_over_time',
        description: 'Get a time-series of flow counts for a specific close-type, divided into N equal-width buckets over the full time extent. Use this to spot temporal bursts of a given close-type.',
        input_schema: {
            type: 'object',
            properties: {
                close_type: { type: 'string', description: "e.g. 'rst_during_handshake', 'abortive', 'invalid_synack', 'incomplete_no_ack', 'graceful'." },
                bucket_count: { type: 'integer', description: 'Number of equal-width time buckets. Use 60-200 for high temporal resolution.' }
            },
            required: ['close_type', 'bucket_count']
        }
    },
    {
        name: 'get_initiators_in_window',
        description: 'Get the top initiator IPs contributing flows within a time window, optionally filtered to a single close-type. Returns each IP\'s flow count for that window. Use after spotting a burst to find who caused it.',
        input_schema: {
            type: 'object',
            properties: {
                t_start_us: { type: 'number', description: 'Window start (microseconds epoch).' },
                t_end_us: { type: 'number', description: 'Window end (microseconds epoch).' },
                close_type: { type: 'string', description: 'Optional close-type filter; omit to count all close-types.' },
                max_results: { type: 'integer', description: 'Max initiators to return. Default 20.' }
            },
            required: ['t_start_us', 't_end_us']
        }
    },
    {
        name: 'get_initiator_profile',
        description: 'Get the close-type breakdown over time for a specific initiator IP: total per-close-type counts plus per-bucket close-type counts. Use to validate that a candidate IP really shows anomalous behavior.',
        input_schema: {
            type: 'object',
            properties: {
                ip: { type: 'string' },
                bucket_count: { type: 'integer', description: 'Number of time buckets. Default 30.' }
            },
            required: ['ip']
        }
    },
    {
        name: 'get_responder_fanout',
        description: 'CONFIRM-ONLY (not for discovery — use run_* tools to discover). For an initiator IP, return how many distinct responders it touched and how concentrated the traffic is (Gini coefficient over responder counts). Use to detect host sweeps / scans (many distinct responders, low Gini) or hammering (few responders, high Gini). Optionally filter to a time window and/or close-type.',
        input_schema: {
            type: 'object',
            properties: {
                ip: { type: 'string', description: 'Initiator IP.' },
                t_start_us: { type: 'number', description: 'Optional window start. Omit for full extent.' },
                t_end_us: { type: 'number', description: 'Optional window end. Omit for full extent.' },
                close_type: { type: 'string', description: 'Optional close-type filter.' },
                max_results: { type: 'integer', description: 'Max responders in topResponders. Default 20.' }
            },
            required: ['ip']
        }
    },
    {
        name: 'get_flow_rate',
        description: 'CONFIRM-ONLY (not for discovery — use run_* tools to discover). Get flow rate over time for an initiator IP: per-bucket counts plus flows-per-second, peak/mean rates, and peak-to-mean ratio. Use to detect bursty automation (high peak-to-mean indicates non-human bursts). Optionally filter to a close-type.',
        input_schema: {
            type: 'object',
            properties: {
                ip: { type: 'string', description: 'Initiator IP.' },
                bucket_count: { type: 'integer', description: 'Number of time buckets. Default 60.' },
                close_type: { type: 'string', description: 'Optional close-type filter.' }
            },
            required: ['ip']
        }
    },
    {
        name: 'get_responder_attackers',
        description: 'Inverse of get_initiators_in_window: given a responder (target) IP, return how many distinct initiators hit it in a time window and the top contributors. Use to detect coordinated attacks against a target (many distinct initiators converging on one responder).',
        input_schema: {
            type: 'object',
            properties: {
                responder: { type: 'string', description: 'Responder (target) IP.' },
                t_start_us: { type: 'number', description: 'Optional window start. Omit for full extent.' },
                t_end_us: { type: 'number', description: 'Optional window end. Omit for full extent.' },
                close_type: { type: 'string', description: 'Optional close-type filter.' },
                max_results: { type: 'integer', description: 'Max initiators in topInitiators. Default 20.' }
            },
            required: ['responder']
        }
    },
    {
        name: 'get_population_stats',
        description: 'CONFIRM-ONLY (not for discovery — use run_* tools to discover). Get population-wide per-initiator statistics for a close-type: mean, stddev, and percentiles (p50/p90/p99/max) of per-IP flow counts. Use as a baseline to judge whether a specific IP\'s count is unusually high (e.g. above p99).',
        input_schema: {
            type: 'object',
            properties: {
                close_type: { type: 'string', description: 'Close-type to compute stats for.' }
            },
            required: ['close_type']
        }
    },
    {
        name: 'get_responder_fanin',
        description: 'CONFIRM-ONLY (not for discovery — use run_* tools to discover). PACKET-DERIVED. Returns responders ranked by fan-in — the number of distinct initiators that connected to them within a time bucket. Each carries completionRatio (SYN-ACK sent back / SYN received: near 0 means incoming handshakes are not completing; near 1 means they are), bytesIn, and synIn. These are raw measured features, not classifications — interpret them yourself and do not assume a category. Confirm the contributing initiators with get_responder_attackers / get_initiators_in_window before emitting a region. Returns {available:false} if the packet feature artifact is not loaded.',
        input_schema: {
            type: 'object',
            properties: {
                min_initiators: { type: 'integer', description: 'Only return responder-buckets with at least this many distinct initiators. Default 8.' },
                max_completion_ratio: { type: 'number', description: 'Optional: only buckets with completionRatio <= this. Omit for all.' },
                max_results: { type: 'integer', description: 'Max results. Default 25, hard cap 50.' }
            },
            required: []
        }
    },
    {
        name: 'get_port_coordination',
        description: 'CONFIRM-ONLY (not for discovery — use run_* tools to discover). PACKET-DERIVED. Returns destination ports ranked by how many distinct INTERNAL hosts (RFC1918: 10/8, 172.16-31, 192.168/16) initiated connections to them, with: windowInternalInitiators (distinct internal hosts over the whole window), windowDistinctResponders (how many responders those hosts hit), peakInternalInitiators and medianInternalInitiators (per-bucket peak vs typical — a peak >> median is a spike). A spike of internal hosts converging on a port, especially toward FEW responders, indicates coordinated internal behavior on that service (whatever the port). Normal client traffic (e.g. web) shows many internal hosts spread across many responders with no spike. These are raw measured features, not classifications — interpret them yourself. Returns {available:false} if the artifact is not loaded.',
        input_schema: {
            type: 'object',
            properties: {
                min_internal: { type: 'integer', description: 'Only return ports with at least this many distinct internal initiators over the window. Default 3.' },
                max_results: { type: 'integer', description: 'Max ports. Default 40, hard cap 80.' }
            },
            required: []
        }
    },
    {
        name: 'get_entity_features',
        description: 'PACKET-DERIVED per-IP drill-down: the IP as a responder (per-bucket distinctInitiators, completionRatio, bytesIn — for victim confirmation). Use to validate a candidate before emitting a region. Returns {available:false} if the artifact is not loaded.',
        input_schema: {
            type: 'object',
            properties: { ip: { type: 'string', description: 'IP to profile.' } },
            required: ['ip']
        }
    },
    {
        name: 'get_flows',
        description: 'EVIDENCE/TRIAGE ONLY — not for discovery. Returns up to max_rows individual flow rows (initiator, responder, closeType, count, time bucket) matching a narrow filter, so you can confirm an already-identified candidate and cite concrete examples in reason/evidence. Row-capped; do NOT use it to scan or re-aggregate — trust the aggregate tools for counts.',
        input_schema: {
            type: 'object',
            properties: {
                initiator: { type: 'string', description: 'Optional initiator IP filter.' },
                responder: { type: 'string', description: 'Optional responder IP filter.' },
                t_start_us: { type: 'number', description: 'Window start (microseconds epoch).' },
                t_end_us: { type: 'number', description: 'Window end (microseconds epoch).' },
                close_type: { type: 'string', description: 'Optional close-type filter.' },
                max_rows: { type: 'integer', description: 'Max rows. Default 20, hard cap 100.' }
            },
            required: ['t_start_us', 't_end_us']
        }
    }
];

// --- Tool implementations (sync, operate on state.flowView.binnedData) -----

function _anomalyToolGetOverview() {
    const binnedData = (state.flowView && state.flowView.binnedData) || [];
    const timeExtent = state.data.timeExtent || [0, 0];
    const closeTypeSummary = Object.create(null);
    let totalFlows = 0;
    const ipSet = new Set();
    for (const d of binnedData) {
        if (!d || !d.initiator) continue;
        const count = d.count || 0;
        if (count === 0) continue;
        const ct = d.closeType || 'unknown';
        closeTypeSummary[ct] = (closeTypeSummary[ct] || 0) + count;
        totalFlows += count;
        ipSet.add(d.initiator);
    }
    return {
        timeExtent: { startUs: timeExtent[0], endUs: timeExtent[1],
                      durationSec: Math.max(0, Math.round((timeExtent[1] - timeExtent[0]) / 1_000_000)) },
        totalFlows,
        distinctInitiators: ipSet.size,
        closeTypeSummary
    };
}

function _anomalyToolGetCloseTypeOverTime(args) {
    const closeType = String(args.close_type || '');
    const n = Math.max(1, Math.min(500, Number(args.bucket_count) || 60));
    const binnedData = (state.flowView && state.flowView.binnedData) || [];
    const timeExtent = state.data.timeExtent || [0, 0];
    const tMin = timeExtent[0];
    const tMax = timeExtent[1];
    const span = Math.max(1, tMax - tMin);
    const w = span / n;
    const counts = new Array(n).fill(0);
    let total = 0;
    for (const d of binnedData) {
        if (!d) continue;
        if ((d.closeType || 'unknown') !== closeType) continue;
        const t0 = d.binStart ?? d.startTime ?? 0;
        const idx = Math.min(n - 1, Math.max(0, Math.floor((t0 - tMin) / w)));
        const c = d.count || 0;
        counts[idx] += c;
        total += c;
    }
    return {
        closeType,
        bucketCount: n,
        totalForCloseType: total,
        buckets: counts.map((c, i) => ({
            i,
            tStartUs: Math.round(tMin + i * w),
            tEndUs: Math.round(tMin + (i + 1) * w),
            count: c
        }))
    };
}

function _anomalyToolGetInitiatorsInWindow(args) {
    const t0 = Number(args.t_start_us);
    const t1 = Number(args.t_end_us);
    const filterCt = args.close_type ? String(args.close_type) : null;
    const maxResults = Math.max(1, Math.min(200, Number(args.max_results) || 20));
    const binnedData = (state.flowView && state.flowView.binnedData) || [];
    const counts = new Map();
    let total = 0;
    for (const d of binnedData) {
        if (!d || !d.initiator) continue;
        if (filterCt && (d.closeType || 'unknown') !== filterCt) continue;
        const bs = d.binStart ?? d.startTime ?? 0;
        const be = d.binEnd ?? d.endTime ?? bs;
        if (be < t0 || bs > t1) continue;
        const c = d.count || 0;
        counts.set(d.initiator, (counts.get(d.initiator) || 0) + c);
        total += c;
    }
    const top = Array.from(counts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, maxResults)
        .map(([ip, count]) => ({ ip, count }));
    return {
        tStartUs: t0,
        tEndUs: t1,
        closeType: filterCt,
        totalFlowsInWindow: total,
        distinctInitiators: counts.size,
        topInitiators: top
    };
}

function _anomalyToolGetInitiatorProfile(args) {
    const ip = String(args.ip || '');
    const n = Math.max(1, Math.min(200, Number(args.bucket_count) || 30));
    const binnedData = (state.flowView && state.flowView.binnedData) || [];
    const timeExtent = state.data.timeExtent || [0, 0];
    const tMin = timeExtent[0];
    const tMax = timeExtent[1];
    const span = Math.max(1, tMax - tMin);
    const w = span / n;
    const closeTypeSummary = Object.create(null);
    const bucketByCloseType = new Array(n).fill(null);
    let total = 0;
    for (const d of binnedData) {
        if (!d || d.initiator !== ip) continue;
        const c = d.count || 0;
        if (c === 0) continue;
        const ct = d.closeType || 'unknown';
        closeTypeSummary[ct] = (closeTypeSummary[ct] || 0) + c;
        total += c;
        const t0 = d.binStart ?? d.startTime ?? 0;
        const idx = Math.min(n - 1, Math.max(0, Math.floor((t0 - tMin) / w)));
        if (!bucketByCloseType[idx]) bucketByCloseType[idx] = Object.create(null);
        bucketByCloseType[idx][ct] = (bucketByCloseType[idx][ct] || 0) + c;
    }
    return {
        ip,
        totalFlows: total,
        closeTypeSummary,
        bucketCount: n,
        timeBuckets: bucketByCloseType.map((bm, i) => ({
            i,
            tStartUs: Math.round(tMin + i * w),
            tEndUs: Math.round(tMin + (i + 1) * w),
            byCloseType: bm || {}
        }))
    };
}

function _anomalyToolGetResponderFanout(args) {
    const ip = String(args.ip || '');
    const filterCt = args.close_type ? String(args.close_type) : null;
    const maxResults = Math.max(1, Math.min(200, Number(args.max_results) || 20));
    const timeExtent = state.data.timeExtent || [0, 0];
    const t0 = Number.isFinite(Number(args.t_start_us)) ? Number(args.t_start_us) : timeExtent[0];
    const t1 = Number.isFinite(Number(args.t_end_us)) ? Number(args.t_end_us) : timeExtent[1];
    const binnedData = (state.flowView && state.flowView.binnedData) || [];
    const counts = new Map();
    let total = 0;
    for (const d of binnedData) {
        if (!d || d.initiator !== ip || !d.responder) continue;
        if (filterCt && (d.closeType || 'unknown') !== filterCt) continue;
        const bs = d.binStart ?? d.startTime ?? 0;
        const be = d.binEnd ?? d.endTime ?? bs;
        if (be < t0 || bs > t1) continue;
        const c = d.count || 0;
        counts.set(d.responder, (counts.get(d.responder) || 0) + c);
        total += c;
    }
    // Gini coefficient over per-responder counts. 0 = perfectly even, 1 = all on one.
    let gini = 0;
    const vals = Array.from(counts.values()).sort((a, b) => a - b);
    if (vals.length > 1 && total > 0) {
        let cumDiff = 0;
        for (let i = 0; i < vals.length; i++) cumDiff += (2 * (i + 1) - vals.length - 1) * vals[i];
        gini = cumDiff / (vals.length * total);
    }
    const top = Array.from(counts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, maxResults)
        .map(([responder, count]) => ({ responder, count }));
    return {
        ip, tStartUs: t0, tEndUs: t1, closeType: filterCt,
        totalFlows: total,
        distinctResponders: counts.size,
        giniCoefficient: Number(gini.toFixed(4)),
        topResponders: top
    };
}

function _anomalyToolGetFlowRate(args) {
    const ip = String(args.ip || '');
    const n = Math.max(1, Math.min(500, Number(args.bucket_count) || 60));
    const filterCt = args.close_type ? String(args.close_type) : null;
    const binnedData = (state.flowView && state.flowView.binnedData) || [];
    const timeExtent = state.data.timeExtent || [0, 0];
    const tMin = timeExtent[0];
    const tMax = timeExtent[1];
    const span = Math.max(1, tMax - tMin);
    const w = span / n;
    const wSec = w / 1_000_000;
    const counts = new Array(n).fill(0);
    let total = 0;
    for (const d of binnedData) {
        if (!d || d.initiator !== ip) continue;
        if (filterCt && (d.closeType || 'unknown') !== filterCt) continue;
        const t0 = d.binStart ?? d.startTime ?? 0;
        const idx = Math.min(n - 1, Math.max(0, Math.floor((t0 - tMin) / w)));
        const c = d.count || 0;
        counts[idx] += c;
        total += c;
    }
    let peak = 0;
    for (const c of counts) if (c > peak) peak = c;
    const meanCount = total / n;
    const peakFps = wSec > 0 ? peak / wSec : 0;
    const meanFps = wSec > 0 ? meanCount / wSec : 0;
    const peakToMean = meanCount > 0 ? peak / meanCount : 0;
    return {
        ip, closeType: filterCt,
        bucketCount: n,
        bucketWidthSec: Number(wSec.toFixed(6)),
        totalFlows: total,
        peakFlowsPerSec: Number(peakFps.toFixed(3)),
        meanFlowsPerSec: Number(meanFps.toFixed(3)),
        peakToMeanRatio: Number(peakToMean.toFixed(2)),
        buckets: counts.map((c, i) => ({
            i,
            tStartUs: Math.round(tMin + i * w),
            tEndUs: Math.round(tMin + (i + 1) * w),
            count: c,
            flowsPerSec: wSec > 0 ? Number((c / wSec).toFixed(3)) : 0
        }))
    };
}

function _anomalyToolGetResponderAttackers(args) {
    const responder = String(args.responder || '');
    const filterCt = args.close_type ? String(args.close_type) : null;
    const maxResults = Math.max(1, Math.min(200, Number(args.max_results) || 20));
    const timeExtent = state.data.timeExtent || [0, 0];
    const t0 = Number.isFinite(Number(args.t_start_us)) ? Number(args.t_start_us) : timeExtent[0];
    const t1 = Number.isFinite(Number(args.t_end_us)) ? Number(args.t_end_us) : timeExtent[1];
    const binnedData = (state.flowView && state.flowView.binnedData) || [];
    const counts = new Map();
    let total = 0;
    for (const d of binnedData) {
        if (!d || d.responder !== responder || !d.initiator) continue;
        if (filterCt && (d.closeType || 'unknown') !== filterCt) continue;
        const bs = d.binStart ?? d.startTime ?? 0;
        const be = d.binEnd ?? d.endTime ?? bs;
        if (be < t0 || bs > t1) continue;
        const c = d.count || 0;
        counts.set(d.initiator, (counts.get(d.initiator) || 0) + c);
        total += c;
    }
    const top = Array.from(counts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, maxResults)
        .map(([ip, count]) => ({ ip, count }));
    return {
        responder, tStartUs: t0, tEndUs: t1, closeType: filterCt,
        totalFlows: total,
        distinctInitiators: counts.size,
        topInitiators: top
    };
}

function _anomalyToolGetPopulationStats(args) {
    const closeType = String(args.close_type || '');
    const binnedData = (state.flowView && state.flowView.binnedData) || [];
    const perIp = new Map();
    for (const d of binnedData) {
        if (!d || !d.initiator) continue;
        if ((d.closeType || 'unknown') !== closeType) continue;
        const c = d.count || 0;
        if (c === 0) continue;
        perIp.set(d.initiator, (perIp.get(d.initiator) || 0) + c);
    }
    const vals = Array.from(perIp.values()).sort((a, b) => a - b);
    const n = vals.length;
    if (n === 0) {
        return { closeType, distinctInitiators: 0, mean: 0, stddev: 0, p50: 0, p90: 0, p99: 0, max: 0 };
    }
    const sum = vals.reduce((a, b) => a + b, 0);
    const mean = sum / n;
    let variance = 0;
    for (const v of vals) variance += (v - mean) * (v - mean);
    variance /= n;
    const pct = (p) => vals[Math.min(n - 1, Math.max(0, Math.floor(p * (n - 1))))];
    return {
        closeType,
        distinctInitiators: n,
        mean: Number(mean.toFixed(2)),
        stddev: Number(Math.sqrt(variance).toFixed(2)),
        p50: pct(0.50),
        p90: pct(0.90),
        p99: pct(0.99),
        max: vals[n - 1]
    };
}

// --- Packet-feature tool implementations (read _anomalyFeatures; degrade gracefully) ---
// These return RAW measured features only. They never classify, score, rank by a
// derived verdict, or hint an attack category — that judgment is the model's.

function _anomalyToolGetResponderFanin(args) {
    if (!_anomalyFeatures) return { available: false, note: 'Packet feature artifact not loaded.' };
    const minInit = Math.max(1, Number(args.min_initiators) || 8);
    const maxComp = Number.isFinite(Number(args.max_completion_ratio)) ? Number(args.max_completion_ratio) : null;
    const maxResults = Math.max(1, Math.min(50, Number(args.max_results) || 25));
    let rows = (_anomalyFeatures.responders || []).filter(r =>
        r.distinctInitiators >= minInit && (maxComp === null || r.completionRatio <= maxComp));
    rows.sort((a, b) => b.distinctInitiators - a.distinctInitiators);
    const totalMatching = rows.length;
    const responders = rows.slice(0, maxResults).map(r => ({
        responder: r.ip, tStartUs: r.tStartUs, tEndUs: r.tEndUs,
        distinctInitiators: r.distinctInitiators, completionRatio: r.completionRatio,
        bytesIn: r.bytesIn, synIn: r.synIn
    }));
    return {
        available: true, totalMatching, returned: responders.length, responders,
        note: 'Raw measured features (distinct initiators, completionRatio, bytesIn). Interpret them yourself; confirm contributing initiators with get_responder_attackers before emitting.'
    };
}

function _anomalyToolGetPortCoordination(args) {
    if (!_anomalyFeatures) return { available: false, note: 'Packet feature artifact not loaded.' };
    const minInternal = Math.max(1, Number(args.min_internal) || 3);
    const maxResults = Math.max(1, Math.min(80, Number(args.max_results) || 40));
    let rows = (_anomalyFeatures.portCoordination || []).filter(p => p.windowInternalInitiators >= minInternal);
    rows.sort((a, b) => b.windowInternalInitiators - a.windowInternalInitiators);
    const totalMatching = rows.length;
    const ports = rows.slice(0, maxResults).map(p => ({
        port: p.port,
        windowInternalInitiators: p.windowInternalInitiators,
        windowDistinctResponders: p.windowDistinctResponders,
        peakInternalInitiators: p.peakInternalInitiators,
        medianInternalInitiators: p.medianInternalInitiators,
        peakDistinctResponders: p.peakDistinctResponders,
        peakTStartUs: p.peakTStartUs, peakTEndUs: p.peakTEndUs,
        internalInitiators: Array.isArray(p.internalInitiators) ? p.internalInitiators : [],
        responders: Array.isArray(p.responders) ? p.responders : []
    }));
    return {
        available: true, totalMatching, returned: ports.length, ports,
        note: 'Raw measured features per destination port. Concentration (many internal initiators, few responders) and a peak >> median spike stand out from normal client traffic (many initiators spread across many responders). Confirm specific initiators with get_responder_attackers / get_flows on a responder before emitting.'
    };
}

function _anomalyToolGetEntityFeatures(args) {
    if (!_anomalyFeatures) return { available: false, note: 'Packet feature artifact not loaded.' };
    const ip = String(args.ip || '');
    const idx = _anomalyFeaturesIndex || { byResponderIp: new Map() };
    const asResponder = (idx.byResponderIp.get(ip) || []).map(r => ({
        tStartUs: r.tStartUs, tEndUs: r.tEndUs, distinctInitiators: r.distinctInitiators,
        completionRatio: r.completionRatio, bytesIn: r.bytesIn, synIn: r.synIn
    })).slice(0, 40);
    return {
        available: true, ip, asResponder,
        note: asResponder.length ? undefined
            : 'No responder-side packet features for this IP (below artifact thresholds).'
    };
}

function _anomalyToolGetFlows(args) {
    const binnedData = (state.flowView && state.flowView.binnedData) || [];
    const initiator = args.initiator ? String(args.initiator) : null;
    const responder = args.responder ? String(args.responder) : null;
    const filterCt = args.close_type ? String(args.close_type) : null;
    const timeExtent = state.data.timeExtent || [0, 0];
    const t0 = Number.isFinite(Number(args.t_start_us)) ? Number(args.t_start_us) : timeExtent[0];
    const t1 = Number.isFinite(Number(args.t_end_us)) ? Number(args.t_end_us) : timeExtent[1];
    const maxRows = Math.max(1, Math.min(100, Number(args.max_rows) || 20));
    const rows = [];
    let totalMatching = 0;
    for (const d of binnedData) {
        if (!d) continue;
        if (initiator && d.initiator !== initiator) continue;
        if (responder && d.responder !== responder) continue;
        if (filterCt && (d.closeType || 'unknown') !== filterCt) continue;
        const bs = d.binStart ?? d.startTime ?? 0;
        const be = d.binEnd ?? d.endTime ?? bs;
        if (be < t0 || bs > t1) continue;
        totalMatching++;
        if (rows.length < maxRows) {
            rows.push({
                initiator: d.initiator, responder: d.responder,
                closeType: d.closeType || 'unknown', count: d.count || 0,
                tStartUs: bs, tEndUs: be
            });
        }
    }
    return { returned: rows.length, totalMatching, truncated: totalMatching > rows.length, rows };
}

function _anomalyToolRunOutlierDetection(args) {
    const metric = String(args.metric || '');
    const method = String(args.method || 'robust_z');
    if (method !== 'robust_z') return { error: `Unknown method: ${method}` };
    if (!['volume', 'fanin', 'fanout'].includes(metric)) return { error: `Unknown metric: ${metric}` };
    const maxResults = Math.max(1, Math.min(100, Number(args.max_results) || 25));
    const ft = _anomalyBuildFeatureTable(args.t_start_us, args.t_end_us);
    const rows = _ANOMALY_SCORERS[metric](ft, args);
    return {
        metric, method, window: ft.timeExtent, total: rows.length,
        returned: Math.min(maxResults, rows.length), rows: rows.slice(0, maxResults),
        note: 'Ranked outliers: score = robust-z, pValue = normal upper tail. Higher score = more anomalous. Confirm contributing IPs with the drill-down tools (get_responder_attackers / get_flows) before emitting a region.'
    };
}

function _anomalyToolRunBurstDetection(args) {
    const maxResults = Math.max(1, Math.min(100, Number(args.max_results) || 25));
    const ft = _anomalyBuildFeatureTable();
    const rows = _ANOMALY_SCORERS.burst(ft, args);
    return {
        closeType: args.close_type || null, resolution: rows.length,
        returned: Math.min(maxResults, rows.length), rows: rows.slice(0, maxResults),
        note: 'Ranked time buckets: score = -log10(Poisson upper-tail p). Use the window of a high-score bucket with get_initiators_in_window to find who caused the burst.'
    };
}

function _anomalyToolRunCoordinationScan(args) {
    if (!_anomalyFeatures) return { available: false, note: 'Packet feature artifact not loaded.' };
    const maxResults = Math.max(1, Math.min(80, Number(args.max_results) || 40));
    const ft = _anomalyBuildFeatureTable();
    const rows = _ANOMALY_SCORERS.coordination(ft, args);
    return {
        available: true, total: rows.length, returned: Math.min(maxResults, rows.length),
        ports: rows.slice(0, maxResults),
        note: 'Ranked ports by internal-host convergence score. Confirm the converging internal initiators with get_responder_attackers / get_flows before emitting.'
    };
}

function _anomalyToolClusterCohort(args) {
    const entities = Array.isArray(args.entities) ? args.entities.filter(x => typeof x === 'string') : [];
    const by = args.by === 'subnet16' ? 'subnet16' : 'subnet24';
    const keyFn = by === 'subnet16'
        ? (ip) => { const p = ip.split('.'); return p.length >= 2 ? `${p[0]}.${p[1]}` : ip; }
        : (ip) => { const p = ip.split('.'); return p.length >= 3 ? `${p[0]}.${p[1]}.${p[2]}` : ip; };
    const groups = new Map();
    for (const ip of entities) {
        const k = keyFn(ip);
        if (!groups.has(k)) groups.set(k, []);
        groups.get(k).push(ip);
    }
    const cohorts = [...groups.entries()]
        .map(([subnet, ips]) => ({ subnet, size: ips.length, ips }))
        .sort((a, b) => b.size - a.size);
    return { by, cohortCount: cohorts.length, cohorts };
}

function _anomalyDispatchTool(name, input) {
    try {
        switch (name) {
            case 'get_overview':              return _anomalyToolGetOverview();
            case 'get_close_type_over_time':  return _anomalyToolGetCloseTypeOverTime(input || {});
            case 'get_initiators_in_window':  return _anomalyToolGetInitiatorsInWindow(input || {});
            case 'get_initiator_profile':     return _anomalyToolGetInitiatorProfile(input || {});
            case 'get_responder_fanout':      return _anomalyToolGetResponderFanout(input || {});
            case 'get_flow_rate':             return _anomalyToolGetFlowRate(input || {});
            case 'get_responder_attackers':   return _anomalyToolGetResponderAttackers(input || {});
            case 'get_population_stats':      return _anomalyToolGetPopulationStats(input || {});
            case 'get_responder_fanin':       return _anomalyToolGetResponderFanin(input || {});
            case 'get_port_coordination':     return _anomalyToolGetPortCoordination(input || {});
            case 'get_entity_features':       return _anomalyToolGetEntityFeatures(input || {});
            case 'get_flows':                 return _anomalyToolGetFlows(input || {});
            case 'run_outlier_detection':     return _anomalyToolRunOutlierDetection(input || {});
            case 'run_burst_detection':       return _anomalyToolRunBurstDetection(input || {});
            case 'run_coordination_scan':     return _anomalyToolRunCoordinationScan(input || {});
            case 'cluster_cohort':            return _anomalyToolClusterCohort(input || {});
            default: return { error: `Unknown tool: ${name}` };
        }
    } catch (e) {
        return { error: String((e && e.message) || e) };
    }
}

// ============================================================================
// Region-scoped tools for the case-builder Explain. Explain reuses the detector's
// tool DEFINITIONS and IMPLEMENTATIONS, restricted to a region-scoped subset and
// bounded by a hybrid clamp: per-entity/per-window tools are clamped to the
// region's IP set + [tMin,tMax]; get_population_stats stays global so the
// case-builder can cite a population baseline. See the detective→case-builder design.
// ============================================================================
const _EXPLAIN_TOOL_NAMES = new Set([
    'run_outlier_detection', 'get_flows', 'get_initiator_profile',
    'get_responder_fanout', 'get_flow_rate', 'get_entity_features',
    'get_population_stats', 'get_geo_breakdown', 'get_target_ports', 'get_host_peers'
]);
// Explain-only tool (NOT in _ANOMALY_TOOLS — the detector stays behavior-first).
const _EXPLAIN_GEO_TOOL = {
    name: 'get_geo_breakdown',
    description: 'ATTRIBUTION ONLY (never evidence of malice). Returns country and organization histograms over this region: "source" = the region\'s initiator IPs, "target" = the responder IPs those initiators connected to in-window. Each bucket has {value, ips (distinct), flows}; each side also reports resolvedIps/privateIps/unknownIps and coverage. Use to characterize WHO and WHERE (e.g. dominant source country/operator, or the ownership of the targeted hosts). The behavioral case must stand on its own; do NOT treat a country or org as proof of an attack.',
    input_schema: {
        type: 'object',
        properties: {
            side: { type: 'string', description: '"source" | "target" | "both". Default "both".' },
            dimension: { type: 'string', description: '"country" | "org" | "both". Default "both".' },
            max_results: { type: 'integer', description: 'Max buckets per histogram. Default 15, cap 40.' }
        },
        required: []
    }
};
// Explain-only tool: raw-packet port histogram for a single responder.
// This is the ONLY way to learn which service/port an internal victim is being
// flooded on — geo/org data is unavailable for RFC1918 hosts, and binnedData
// carries no port column. Reads at 'raw' resolution (dst_port only exists there).
const _EXPLAIN_TARGET_PORTS_TOOL = {
    name: 'get_target_ports',
    description: 'Returns the destination-port histogram of packets sent TO a given responder IP in this region, read from raw packet data. This is the ONE way to learn what service/port an internal victim is being attacked on — binnedData carries no port column, and geo/org attribution is unavailable for RFC1918 hosts. Use this whenever the victim is internal (RFC1918) and you need to characterize what is being denied. Default is SYN-only (connection-initiation packets), which cleanly identifies the targeted service. A single dominant low port (e.g. 80, 443, 53, 22, 3306) identifies the targeted service; a flat spread suggests non-service-specific flooding. Window must be ≤15 min or the tool returns unavailable.',
    input_schema: {
        type: 'object',
        properties: {
            responder: {
                type: 'string',
                description: 'The responder IP to inspect — must be an IP in this region.'
            },
            syn_only: {
                type: 'boolean',
                description: 'If true (default), count only SYN packets (flag_type === "SYN") — cleanest signal for targeted-service identification. Set false to count all inbound packets.'
            },
            max_results: {
                type: 'integer',
                description: 'Max port entries to return, sorted by packet count descending. Default 12, clamp 1–40.'
            }
        },
        required: ['responder']
    }
};
// Explain-only tool: peer-org histogram for a single HOST across the full
// capture, with flood peers separated from legitimate clientele by per-IP
// exchange volume. Distinct from get_geo_breakdown (which profiles the
// region's attackers) — this reveals the HOST's own everyday clientele so the
// analyst can characterize what an internal victim IS and why it is a target.
const _EXPLAIN_HOST_PEERS_TOOL = {
    name: 'get_host_peers',
    description: 'Returns the org/country histogram of a HOST\'s own peers across the FULL capture, split by per-IP exchange volume into "floodSources" (the few extreme-volume peers — the attack itself) and "legitimateClientele" (the host\'s everyday peers). READ "legitimateClientele" to characterize what an internal victim IS and why it is a high-value target (e.g. "normally accessed by the US DoD and cloud providers, consistent with a high-value internal asset"). This is distinct from get_geo_breakdown, which profiles the region\'s attack sources, not the victim\'s own identity. Call this on an internal victim after get_target_ports to build a full picture: port = what service is being attacked; host_peers = what kind of host this normally is. IMPORTANT: org = ASN registrant (IP block owner), NOT a verified operational relationship. Attribution color only — never evidence of malice; do NOT infer guilt from org identity.',
    input_schema: {
        type: 'object',
        properties: {
            ip: {
                type: 'string',
                description: 'The host IP to profile — must be a region IP.'
            },
            flood_multiple: {
                type: 'number',
                description: 'Per-peer volume cutoff multiplier: a peer is classified as a flood peer if its total exchange volume >= flood_multiple × medianPeerVolume (floored at 100). Default 20, clamp 2–1000. The gap between flood peers and legitimate peers is typically enormous so the exact value is insensitive.'
            },
            separate_flood: {
                type: 'boolean',
                description: 'If true (default), split peers into floodSources (high-volume, the attack) vs legitimateClientele (low-volume, the host\'s everyday peers) using per-IP volume. Set false to treat ALL peers as legitimate — useful when no flood is expected or as an escape hatch.'
            },
            max_results: {
                type: 'integer',
                description: 'Max org/country entries to return, sorted by distinct peer count descending. Default 15, clamp 1–40.'
            }
        },
        required: ['ip']
    }
};
const _EXPLAIN_TOOLS = [
    ..._ANOMALY_TOOLS.filter(t => _EXPLAIN_TOOL_NAMES.has(t.name)),
    _EXPLAIN_GEO_TOOL,
    _EXPLAIN_TARGET_PORTS_TOOL,
    _EXPLAIN_HOST_PEERS_TOOL
];
const _EXPLAIN_MAX_TURNS = 12;  // case-builder is region-scoped; far fewer turns than detection
// Tools whose t_start_us/t_end_us are clamped into the region window.
const _EXPLAIN_WINDOW_TOOLS = new Set(['run_outlier_detection', 'get_responder_fanout', 'get_flows']);
// Tools whose `ip` arg must lie inside the region.
const _EXPLAIN_IP_TOOLS = new Set(['get_initiator_profile', 'get_responder_fanout', 'get_flow_rate', 'get_entity_features']);

// Returns a dispatchTool(name, input) bound to one region. Rejects out-of-subset
// tools and out-of-region IPs; clamps time windows; passes population stats through.
function makeExplainDispatch(regionIps, tMin, tMax, metaMap) {
    const ipSet = new Set(regionIps);
    return function explainDispatch(name, input) {
        if (!_EXPLAIN_TOOL_NAMES.has(name)) {
            return { error: `Tool '${name}' is not available to Explain (region-scoped subset).` };
        }
        if (name === 'get_geo_breakdown') {
            return _explainToolGeoBreakdown(ipSet, tMin, tMax, metaMap, input || {});
        }
        if (name === 'get_target_ports') {
            const responder = (input || {}).responder;
            if (typeof responder !== 'string' || !ipSet.has(responder)) {
                return { error: `responder '${responder}' is outside this region.` };
            }
            return _explainToolTargetPorts(responder, tMin, tMax, input || {});
        }
        if (name === 'get_host_peers') {
            const hostIp = (input || {}).ip;
            if (typeof hostIp !== 'string' || !ipSet.has(hostIp)) {
                return { error: `ip '${hostIp}' is outside this region.` };
            }
            return _explainToolHostPeers(hostIp, metaMap, input || {});
        }
        const args = Object.assign({}, input || {});
        if (_EXPLAIN_WINDOW_TOOLS.has(name)) {
            const s = Number.isFinite(args.t_start_us) ? args.t_start_us : tMin;
            const e = Number.isFinite(args.t_end_us) ? args.t_end_us : tMax;
            args.t_start_us = Math.max(tMin, Math.min(s, e));
            args.t_end_us = Math.min(tMax, Math.max(s, e));
        }
        if (_EXPLAIN_IP_TOOLS.has(name) && typeof args.ip === 'string' && !ipSet.has(args.ip)) {
            return { error: `IP '${args.ip}' is outside this region; query only region IPs.` };
        }
        if (name === 'get_flows') {
            if (typeof args.initiator === 'string' && !ipSet.has(args.initiator)) {
                return { error: `initiator '${args.initiator}' is outside this region.` };
            }
            if (typeof args.responder === 'string' && !ipSet.has(args.responder)) {
                return { error: `responder '${args.responder}' is outside this region.` };
            }
        }
        return _anomalyDispatchTool(name, args);
    };
}

if (typeof window !== 'undefined') {
    window._explainDebug = {
        tools: () => _EXPLAIN_TOOLS.map(t => t.name),
        dispatch: async (ips, tMin, tMax, name, input) =>
            makeExplainDispatch(ips, tMin, tMax, await _ensureIpMetaMap())(name, input)
    };
}

// --- Agentic loop ----------------------------------------------------------

async function _anomalyCallAnthropicAgentic(systemPrompt, key, abortSignal, onTurn) {
    return _aiAgenticLoop({
        label: 'Anomaly',
        systemPrompt, key, abortSignal, onTurn,
        userMessage: 'Identify anomalous regions in the flow data using the available tools. When done, respond with the JSON array of regions only.',
        maxTurns: _ANOMALY_MAX_TURNS,
        maxTokens: _ANOMALY_MAX_TOKENS,
        tools: _ANOMALY_TOOLS,
        dispatchTool: _anomalyDispatchTool
    });
}

// Extract a JSON array from the model's response. Accepts raw JSON, a
// fenced ```json block, or JSON embedded in surrounding prose. Returns []
// on any parse failure rather than throwing.
function _anomalyParseRegions(text) {
    let candidate = _stripJsonFences(text);
    if (!candidate) return [];
    // If still not an array, locate the first '[' ... last ']' span.
    if (!candidate.startsWith('[') && !candidate.startsWith('{')) {
        const start = candidate.indexOf('[');
        const end = candidate.lastIndexOf(']');
        if (start >= 0 && end > start) candidate = candidate.slice(start, end + 1);
    }
    let parsed;
    try { parsed = JSON.parse(candidate); } catch (e) {
        console.warn('[Anomaly] JSON parse failed:', e, '\nRaw text:', text.slice(0, 500));
        return [];
    }
    // Accept either a bare array or an object with a `regions` array.
    const arr = Array.isArray(parsed) ? parsed :
                (parsed && Array.isArray(parsed.regions) ? parsed.regions : []);
    return arr;
}

// Runtime safety floor: any responder whose fan-in robust-z is this extreme is ALWAYS
// emitted as a region, even if the model didn't name it — a deterministic net against
// catastrophic misses. Calibrated against the GT gate; both GT DDoS victims clear it.
// The floor only ADDS regions; it never removes the model's.
// _ANOMALY_FLOOR_FANIN_Z removed — convergence floor deleted
// _ANOMALY_FLOOR_COORD_Z removed — coordination floor deleted

// Both safety floors (convergence + coordination) removed — the AI should find
// all anomalies via run_outlier_detection and run_coordination_scan.
// If it misses them, fix the prompt, don't hardcode.
function _anomalySafetyFloorRaw() {
    return [];
}

// Append floor regions whose responder is not already covered by a model region.
function _anomalyMergeRaw(raw, floor) {
    const covered = new Set();
    for (const r of raw) {
        if (!r) continue;
        if (typeof r.responder === 'string') covered.add(r.responder);
        if (Array.isArray(r.ips)) for (const ip of r.ips) covered.add(ip);
    }
    const merged = Array.isArray(raw) ? raw.slice() : [];
    let added = 0;
    for (const f of floor) if (!covered.has(f.responder)) { merged.push(f); added++; }
    if (added > 0) console.log(`[Anomaly] Safety floor added ${added} region(s) the model did not name.`);
    return merged;
}

function _anomalyMergeOverlapping(regions) {
    // Collapse regions that describe the SAME event into one box, so the overview is not
    // buried under near-duplicate overlays. Two regions are the same event if their time
    // windows overlap AND either their IP sets overlap a lot (model emitting one attack
    // several ways) OR their responders share a /16 (one sweep against an external block,
    // split by the floor into one region per target). General; no hardcoded IPs.
    const slash16 = (ip) => { const q = String(ip || "").split("."); return q.length >= 2 ? (q[0] + "." + q[1]) : ""; };
    const tOverlap = (a, b) => a.tMinUs <= b.tMaxUs && b.tMinUs <= a.tMaxUs;
    const jac = (a, b) => {
        const B = new Set(b.ips); let inter = 0;
        for (const x of a.ips) if (B.has(x)) inter++;
        const uni = a.ips.length + b.ips.length - inter;
        return uni ? inter / uni : 0;
    };
    // Same event = overlapping in time AND describing the same TARGET. If BOTH regions name a
    // responder (target), they merge ONLY when those targets share a /16 -- so distinct attacks
    // that merely share attacker hosts (internal bots hitting many external blocks) do NOT chain
    // into one mega-region. If exactly ONE has a responder, merge only if the non-responder
    // region's IPs are a SUBSET of the responder region (e.g. heavy-hitter facet of a DDoS).
    // If NEITHER has a responder (model facet regions), fall back to IP overlap (>=0.5).
    // Check if `noResp` region is a facet of `withResp` region (same attack, different
    // angle). Requires: (1) ≥80% of noResp IPs are in withResp, AND (2) both regions share
    // the same attackType direction prefix (inbound/outbound) to avoid merging structurally
    // different patterns that happen to share IPs (e.g. outbound_high_volume vs convergence).
    const isFacetOf = (noResp, withResp) => {
        const B = new Set(withResp.ips); let hit = 0;
        for (const x of noResp.ips) if (B.has(x)) hit++;
        if (noResp.ips.length === 0 || hit / noResp.ips.length < 0.8) return false;
        // Direction check: both must share the same direction prefix, or the facet must
        // have no direction (generic label). Prevents outbound volume merging with inbound DDoS.
        const dirA = (noResp.attackType || '').split('_')[0];
        const dirB = (withResp.attackType || '').split('_')[0];
        if (dirA && dirB && dirA !== dirB) return false;
        return true;
    };
    const sameEvent = (a, b) => tOverlap(a, b) && (
        (a.responder && b.responder)
            ? (slash16(a.responder) !== "" && slash16(a.responder) === slash16(b.responder))
            : (a.responder && !b.responder) ? isFacetOf(b, a)
            : (!a.responder && b.responder) ? isFacetOf(a, b)
            : jac(a, b) >= 0.5
    );
    const n = regions.length;
    const parent = regions.map((_, i) => i);
    const find = (x) => { while (parent[x] !== x) { parent[x] = parent[parent[x]]; x = parent[x]; } return x; };
    for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) if (sameEvent(regions[i], regions[j])) parent[find(i)] = find(j);
    const groups = new Map();
    for (let i = 0; i < n; i++) { const r = find(i); if (!groups.has(r)) groups.set(r, []); groups.get(r).push(regions[i]); }
    const merged = [];
    for (const grp of groups.values()) {
        if (grp.length === 1) { merged.push(grp[0]); continue; }
        const ipset = new Set(); let tMin = Infinity, tMax = -Infinity, conf = 0, resp = null;
        const types = new Map();
        for (const g of grp) {
            for (const ip of g.ips) ipset.add(ip);
            if (g.tMinUs < tMin) tMin = g.tMinUs;
            if (g.tMaxUs > tMax) tMax = g.tMaxUs;
            if ((g.confidence || 0) > conf) conf = g.confidence || 0;
            if (!resp && g.responder) resp = g.responder;
            types.set(g.attackType, (types.get(g.attackType) || 0) + 1);
        }
        const at = Array.from(types.entries()).sort((a, b) => b[1] - a[1])[0][0];
        merged.push({
            ips: Array.from(ipset), tMinUs: tMin, tMaxUs: tMax,
            attackType: at, confidence: conf, responder: resp, evidence: "",
            reason: "Merged " + grp.length + " overlapping regions (" + Array.from(types.keys()).join(", ") + "). " + (grp[0].reason || "")
        });
    }
    if (merged.length !== regions.length) console.log("[Anomaly] Merged " + regions.length + " -> " + merged.length + " regions (collapsed " + (regions.length - merged.length) + " overlapping).");

    return merged;
}

function _anomalyMedian(arr) {
    if (!arr.length) return 0;
    const s = [...arr].sort((a, b) => a - b);
    const n = s.length;
    return n % 2 ? s[(n - 1) / 2] : (s[n / 2 - 1] + s[n / 2]) / 2;
}

// Robust z-score (Iglewicz-Hoaglin): how many MADs above the median, scaled to be
// comparable to a normal sigma. Falls back to mean-absolute-deviation when MAD==0
// (common when most values are identical). This is a DATA-RELATIVE outlier measure —
// the cutoff that qualifies is derived from the population, not a hardcoded count.
function _anomalyRobustZ(x, med, mad, vals) {
    if (mad > 0) return (x - med) / (1.4826 * mad);
    const meanAbsDev = vals.length ? vals.reduce((s, v) => s + Math.abs(v - med), 0) / vals.length : 0;
    if (meanAbsDev > 0) return (x - med) / (1.2533 * meanAbsDev);
    return x > med ? Infinity : 0;
}

// Sanitize a raw region's caseFile into a capped array of small finding objects.
// Each finding: {tool, metric, entity, value, baseline, note}. Strings are trimmed
// and length-capped; non-object entries are dropped; the array is capped. Returns
// [] for missing/invalid input. This is the structured evidence the detector hands
// to the case-builder Explain (see the detective→case-builder design).
const _ANOMALY_CASEFILE_MAX = 12;
function _anomalySanitizeCaseFile(raw) {
    if (!Array.isArray(raw)) return [];
    const out = [];
    const str = (v, n) => (typeof v === 'string' ? v.trim().slice(0, n) : undefined);
    for (const f of raw) {
        if (!f || typeof f !== 'object') continue;
        const finding = {};
        const tool = str(f.tool, 40); if (tool) finding.tool = tool;
        const metric = str(f.metric, 40); if (metric) finding.metric = metric;
        const entity = str(f.entity, 60); if (entity) finding.entity = entity;
        if (typeof f.value === 'number' && Number.isFinite(f.value)) finding.value = f.value;
        else { const vs = str(f.value, 40); if (vs) finding.value = vs; }
        const baseline = str(f.baseline, 80); if (baseline) finding.baseline = baseline;
        const note = str(f.note, 120); if (note) finding.note = note;
        if (Object.keys(finding).length > 0) out.push(finding);
        if (out.length >= _ANOMALY_CASEFILE_MAX) break;
    }
    return out;
}

// ============================================================================
// Attack Classification Post-Pass
// Deterministic lookup table mapping behavioral patterns to known attack names.
// Runs after region assembly in _anomalyValidateRegions. Falls back to AI
// classification (Layer C) for unmatched regions.
// ============================================================================

const _ATTACK_SIGNATURES = [
    {
        match: (r, ctx) => ctx.direction === 'inbound' && ctx.dominantClose === 'incomplete_no_synack'
            && ctx.fanIn > 10,
        name: 'SYN Flood DDoS',
        category: 'dos'
    },
    {
        match: (r, ctx) => ctx.direction === 'inbound' && ctx.dominantClose === 'incomplete_no_synack'
            && ctx.fanIn >= 1 && ctx.fanIn <= 10,
        name: 'Targeted SYN Flood',
        category: 'dos'
    },
    {
        match: (r, ctx) => ctx.structure === 'sweep' && ctx.dominantClose === 'rst_during_handshake'
            && ctx.flowsPerPeer < 3,
        name: 'SYN Scan (Half-Open)',
        category: 'reconnaissance'
    },
    {
        match: (r, ctx) => ctx.structure === 'sweep' && ctx.dominantClose === 'graceful'
            && ctx.flowsPerPeer < 3,
        name: 'TCP Connect Scan',
        category: 'reconnaissance'
    },
    {
        match: (r, ctx) => ctx.structure === 'sweep' && ctx.dominantClose === 'incomplete_no_synack',
        name: 'Host Sweep (No Response)',
        category: 'reconnaissance'
    },
    {
        match: (r, ctx) => ctx.structure === 'coordination' && ctx.dominantPort === 25,
        name: 'Spambot / Mass Mailer',
        category: 'malware'
    },
    {
        match: (r, ctx) => ctx.structure === 'coordination' && ctx.dominantPort === 21,
        name: 'FTP Worm Propagation',
        category: 'malware'
    },
    {
        match: (r, ctx) => ctx.structure === 'coordination' && ctx.dominantPort === 22
            && ctx.distinctResponders <= 5,
        name: 'SSH Brute Force',
        category: 'credential_attack'
    },
    {
        match: (r, ctx) => ctx.structure === 'coordination' && (ctx.dominantPort === 139 || ctx.dominantPort === 445),
        name: 'SMB Worm / Lateral Movement',
        category: 'lateral_movement'
    },
    {
        match: (r, ctx) => ctx.direction === 'outbound' && ctx.dominantClose === 'rst_during_handshake'
            && ctx.fanIn > 3,
        name: 'Coordinated Port Probe',
        category: 'reconnaissance'
    },
    {
        match: (r, ctx) => ctx.direction === 'outbound' && ctx.dominantClose === 'incomplete_no_synack'
            && ctx.fanIn > 3,
        name: 'Coordinated Outbound Probe',
        category: 'reconnaissance'
    },
    {
        match: (r, ctx) => ctx.dominantClose === 'invalid_ack' && ctx.totalFlows > 1000,
        name: 'ACK Flood',
        category: 'dos'
    }
];

function _anomalyBuildClassificationCtx(region) {
    const ips = new Set(region.ips || []);
    const pairs = region.flaggedPairs || [];
    const internalInitiators = new Set();
    const externalInitiators = new Set();
    const responders = new Set();
    const closeCounts = {};
    const portCounts = {};
    let totalFlows = 0;

    for (const p of pairs) {
        if (_isRfc1918(p.i)) internalInitiators.add(p.i); else externalInitiators.add(p.i);
        responders.add(p.r);
        closeCounts[p.ct] = (closeCounts[p.ct] || 0) + p.c;
        totalFlows += p.c;
        if (p.dp != null) portCounts[p.dp] = (portCounts[p.dp] || 0) + p.c;
    }

    // Direction
    let direction;
    if (externalInitiators.size > internalInitiators.size) {
        direction = 'inbound';
    } else if (internalInitiators.size > 0 && region.responder && !_isRfc1918(region.responder)) {
        direction = 'outbound';
    } else if (internalInitiators.size > 0 && externalInitiators.size === 0) {
        // All initiators internal — check if responders are also internal
        let allRespInternal = true;
        for (const r of responders) { if (!_isRfc1918(r)) { allRespInternal = false; break; } }
        direction = allRespInternal ? 'internal' : 'outbound';
    } else {
        direction = 'unknown';
    }

    const closeEntries = Object.entries(closeCounts).sort((a, b) => b[1] - a[1]);
    const dominantClose = closeEntries.length > 0 ? closeEntries[0][0] : 'unknown';

    const portEntries = Object.entries(portCounts).sort((a, b) => b[1] - a[1]);
    const dominantPort = portEntries.length > 0 ? Number(portEntries[0][0])
        : (region._port != null ? Number(region._port) : null);

    // Structure inference from attackType label or shape
    const at = (region.attackType || '').toLowerCase();
    let structure;
    if (at.includes('coordination') || at.includes('coord') || at.includes('spambot') || at.includes('worm')) {
        structure = 'coordination';
    } else if (at.includes('sweep') || at.includes('fanout') || at.includes('scan')) {
        structure = 'sweep';
    } else if (region.responder && ips.size > 3) {
        structure = 'convergence';
    } else {
        structure = 'unknown';
    }

    const fanIn = region.responder ? ips.size : internalInitiators.size + externalInitiators.size;

    return {
        direction,
        dominantClose,
        dominantPort,
        structure,
        fanIn,
        totalFlows,
        distinctResponders: responders.size,
        flowsPerPeer: responders.size ? totalFlows / responders.size : 0
    };
}

function _anomalyClassifyRegion(region) {
    const ctx = _anomalyBuildClassificationCtx(region);
    for (const sig of _ATTACK_SIGNATURES) {
        try {
            if (sig.match(region, ctx)) {
                region.knownAttackName = sig.name;
                region.attackCategory = sig.category;
                console.log(`[Anomaly] Classification: "${region.attackType}" → "${sig.name}" (${sig.category}) [ctx: dir=${ctx.direction}, close=${ctx.dominantClose}, struct=${ctx.structure}, fanIn=${ctx.fanIn}, port=${ctx.dominantPort}]`);
                return;
            }
        } catch (e) { /* skip broken matcher */ }
    }
    region.knownAttackName = null;
    region.attackCategory = null;
    console.log(`[Anomaly] Classification: "${region.attackType}" → no signature match [ctx: dir=${ctx.direction}, close=${ctx.dominantClose}, struct=${ctx.structure}, fanIn=${ctx.fanIn}, port=${ctx.dominantPort}]`);
}

// Layer C: AI fallback for regions that don't match any signature.
// Single-turn lightweight call. Results cached per attackType to avoid duplicates.
const _attackClassificationCache = new Map();

async function _anomalyClassifyViaAI(regions, apiKey) {
    const unmatched = regions.filter(r => r.knownAttackName == null && (r.confidence || 0) >= 0.5);
    if (unmatched.length === 0) return;

    // Group by attackType+port to avoid duplicate calls (port matters for coordination)
    const byType = new Map();
    for (const r of unmatched) {
        const port = r._port != null ? r._port : '';
        const key = (r.attackType || 'unknown') + (port ? ':' + port : '');
        if (_attackClassificationCache.has(key)) {
            const cached = _attackClassificationCache.get(key);
            r.knownAttackName = cached.name;
            r.attackCategory = cached.category;
            continue;
        }
        if (!byType.has(key)) byType.set(key, []);
        byType.get(key).push(r);
    }

    for (const [attackType, group] of byType) {
        const r = group[0];
        const ctx = _anomalyBuildClassificationCtx(r);
        const prompt = `Given this network anomaly region:
- Direction: ${ctx.direction}
- Dominant close type: ${ctx.dominantClose}
- Fan-in: ${ctx.fanIn}, Distinct responders: ${ctx.distinctResponders}
- Total flows: ${ctx.totalFlows}
- Dominant port: ${ctx.dominantPort || 'unknown'}
- AI behavioral label: ${r.attackType}
- Reason: ${(r.reason || '').slice(0, 300)}

What is the most specific known network attack name for this behavior? Reply with ONLY a JSON object: {"name": "...", "category": "..."}
Where category is one of: dos, reconnaissance, malware, credential_attack, lateral_movement, exfiltration, other.`;

        try {
            const resp = await fetch('https://api.anthropic.com/v1/messages', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-api-key': apiKey,
                    'anthropic-version': '2023-06-01',
                    'anthropic-dangerous-direct-browser-access': 'true'
                },
                body: JSON.stringify({
                    model: 'claude-haiku-4-5-20251001',
                    max_tokens: 100,
                    messages: [{ role: 'user', content: prompt }]
                })
            });
            if (!resp.ok) { console.warn(`[Anomaly] AI classify HTTP ${resp.status}`); continue; }
            const data = await resp.json();
            const text = (data.content && data.content[0] && data.content[0].text) || '';
            const match = text.match(/\{[^}]+\}/);
            if (match) {
                const parsed = JSON.parse(match[0]);
                const result = {
                    name: typeof parsed.name === 'string' ? parsed.name.slice(0, 60) : null,
                    category: typeof parsed.category === 'string' ? parsed.category.slice(0, 30) : null
                };
                _attackClassificationCache.set(attackType, result);
                for (const reg of group) {
                    reg.knownAttackName = result.name;
                    reg.attackCategory = result.category;
                }
                console.log(`[Anomaly] AI classification: "${attackType}" → "${result.name}" (${result.category})`);
            }
        } catch (e) {
            console.warn('[Anomaly] AI classify failed for', attackType, e);
        }
    }
}

// Validate regions against the current layout and return a list of
// well-formed {ips, tMinUs, tMaxUs} entries clamped to the time extent and
// filtered to known IPs.
function _anomalyValidateRegions(rawRegions) {
    const timeExtent = state.data.timeExtent || [0, 0];
    const knownIps = state.layout.ipPositions;
    const out = [];
    let droppedNoIps = 0, droppedBadTime = 0, droppedEmptyWindow = 0;
    const droppedIpExamples = [];

    // Population baseline for convergence-outlier detection (data-relative, no fixed
    // count cutoff). Per-responder peak fan-in across the whole capture, taken from the
    // packet feature artifact. A region IP is treated as a convergence target only if its
    // fan-in is a statistical OUTLIER vs this population (robust z ≥ 3.5, the standard
    // Iglewicz-Hoaglin outlier threshold — dataset-independent; the qualifying count
    // emerges from this capture's own median/MAD).
    const _OUTLIER_Z = 3.5;
    const _faninPeakByResp = new Map();
    const _evidenceSpanByResp = new Map();   // responder -> {tmin,tmax} active span (gentle clamp)
    if (_anomalyFeatures && Array.isArray(_anomalyFeatures.responders)) {
        for (const rec of _anomalyFeatures.responders) {
            const c = _faninPeakByResp.get(rec.ip) || 0;
            if (rec.distinctInitiators > c) _faninPeakByResp.set(rec.ip, rec.distinctInitiators);
            let sp = _evidenceSpanByResp.get(rec.ip);
            if (!sp) { sp = { tmin: Infinity, tmax: -Infinity }; _evidenceSpanByResp.set(rec.ip, sp); }
            if (rec.tStartUs < sp.tmin) sp.tmin = rec.tStartUs;
            if (rec.tEndUs > sp.tmax) sp.tmax = rec.tEndUs;
        }
    }
    const _faninPop = [..._faninPeakByResp.values()];
    const _faninMed = _anomalyMedian(_faninPop);
    const _faninMad = _anomalyMedian(_faninPop.map(v => Math.abs(v - _faninMed)));

    for (const r of rawRegions) {
        if (!r) continue;
        const requestedIps = Array.isArray(r.ips) ? r.ips : [];
        const ips = requestedIps.filter(ip => knownIps.has(ip));
        if (ips.length === 0) {
            droppedNoIps++;
            const missing = requestedIps.filter(ip => !knownIps.has(ip));
            if (droppedIpExamples.length < 5) {
                droppedIpExamples.push({ requestedIps, missing, reason: r.reason || '' });
            }
            continue;
        }
        if (ips.length < requestedIps.length) {
            const missing = requestedIps.filter(ip => !knownIps.has(ip));
            console.warn(`[Anomaly] Region partially pruned — ${missing.length}/${requestedIps.length} IPs not in layout:`, missing);
        }
        const tMinRaw = Number(r.tStartUs ?? r.tMinUs ?? r.startUs);
        const tMaxRaw = Number(r.tEndUs ?? r.tMaxUs ?? r.endUs);
        if (!Number.isFinite(tMinRaw) || !Number.isFinite(tMaxRaw)) { droppedBadTime++; continue; }
        const tMin = Math.max(timeExtent[0], Math.min(tMinRaw, tMaxRaw));
        const tMax = Math.min(timeExtent[1], Math.max(tMinRaw, tMaxRaw));
        if (tMax <= tMin) { droppedEmptyWindow++; continue; }
        const reason = typeof r.reason === 'string' ? r.reason.trim() : '';
        const evidence = typeof r.evidence === 'string' ? r.evidence.trim() : '';
        const confidenceRaw = Number(r.confidence);
        const confidence = Number.isFinite(confidenceRaw)
            ? Math.max(0, Math.min(1, confidenceRaw))
            : null;
        // Open vocabulary: keep the AI's own attackType label verbatim (just trimmed
        // and length-capped). No predefined set, no coercion to 'other'.
        const attackTypeRaw = typeof r.attackType === 'string' ? r.attackType.trim() : '';
        const attackType = attackTypeRaw ? attackTypeRaw.slice(0, 40) : 'unspecified';

        // Deterministic region completion. Expand `ips` to every initiator that hit a
        // convergence target within the window, so a many-source (distributed) attack is
        // fully covered even when the model listed only the few heaviest attackers. A
        // target is either:
        //   (1) an explicit `responder` field the model set, OR
        //   (2) any IP the model put in `ips` that is ITSELF a high-fan-in responder
        //       (>= FANIN_EXPAND_MIN distinct initiators in the window) — e.g. a region of
        //       just [victimIP]. No AI field needed for (2), so it works even when the model
        //       only flags the victim. The model still does the detecting; code finishes the
        //       attacker list. Capped so a popular service can't blow up the region.
        // Safety bound only (NOT a detection threshold): never let one region balloon past
        // this many IPs, in case a popular service slips through.
        const EXPAND_SAFETY_CAP = 6000;
        // Floor regions carry _floor:true. Their window is the per-minute fan-in evidence
        // span (set in _anomalySafetyFloorRaw); the expansion below adds attacker IPs but
        // must NOT widen that window with the victim background-traffic flow span.
        const isFloor = r._floor === true;
        const responder = (typeof r.responder === 'string' && knownIps.has(r.responder.trim()))
            ? r.responder.trim() : null;
        let finalIps = ips, finalTMin = tMin, finalTMax = tMax;
        {
            const binnedData = (state.flowView && state.flowView.binnedData) || [];
            const watch = new Set(ips);
            if (responder) watch.add(responder);
            // Collect over the FULL extent (NOT the region's narrow window): a distributed
            // convergence is spread across time, so the burst window only holds the heavy
            // hitters. Per watched responder, gather all its initiators + their time span.
            const agg = new Map();   // responder -> { inits:Set, tmin, tmax }
            for (const d of binnedData) {
                if (!d || !d.responder || !d.initiator || !watch.has(d.responder)) continue;
                let a = agg.get(d.responder);
                if (!a) { a = { inits: new Set(), tmin: Infinity, tmax: -Infinity }; agg.set(d.responder, a); }
                a.inits.add(d.initiator);
                const bs = d.binStart ?? d.startTime ?? 0;
                const be = d.binEnd ?? d.endTime ?? bs;
                if (bs < a.tmin) a.tmin = bs;
                if (be > a.tmax) a.tmax = be;
            }
            const conv = new Set(ips);
            const expanded = [];
            let spanMin = tMin, spanMax = tMax;
            let evMin = Infinity, evMax = -Infinity;   // gentle clamp: evidence span of fired targets
            for (const [resp, a] of agg) {
                // A region IP is a convergence target if it was named as `responder`, OR its
                // fan-in is a statistical OUTLIER vs the population (data-relative, no fixed count).
                const peakFanin = _faninPeakByResp.get(resp) ?? a.inits.size;
                const z = _anomalyRobustZ(peakFanin, _faninMed, _faninMad, _faninPop);
                const isOutlier = _faninPop.length > 0 && z >= _OUTLIER_Z;
                if (resp !== responder && !isOutlier) continue;
                if (conv.size + a.inits.size > EXPAND_SAFETY_CAP) {
                    console.warn(`[Anomaly] convergence target ${resp}: ${a.inits.size} initiators — over safety cap, not expanding.`);
                    continue;
                }
                for (const i of a.inits) conv.add(i);
                if (!isFloor) spanMin = Math.min(spanMin, a.tmin);
                if (!isFloor) spanMax = Math.max(spanMax, a.tmax);
                const ev = _evidenceSpanByResp.get(resp);
                if (ev) { if (ev.tmin < evMin) evMin = ev.tmin; if (ev.tmax > evMax) evMax = ev.tmax; }
                expanded.push(`${resp}(+${a.inits.size}, faninZ=${z.toFixed(1)})`);
            }
            if (conv.size !== ips.length) {
                finalIps = Array.from(conv);
                finalTMin = Math.max(timeExtent[0], spanMin);
                finalTMax = Math.min(timeExtent[1], spanMax);
                console.log(`[Anomaly] region expanded ips ${ips.length} → ${finalIps.length}, ` +
                    `window → [${finalTMin}, ${finalTMax}] via convergence outlier(s): ${expanded.join(', ')}`);
            }
            // Gentle clamp: a convergence region cannot extend beyond the window when the
            // victim was actually active (packet evidence). Trims model regions that overshoot
            // into dead time at the capture edges; floor regions are already inside their
            // evidence so this is a no-op. Only narrows, never widens; skipped if empty.
            if (evMin <= evMax) {
                const cMin = Math.max(finalTMin, evMin);
                const cMax = Math.min(finalTMax, evMax);
                if (cMax > cMin && (cMin > finalTMin || cMax < finalTMax)) {
                    console.log("[Anomaly] region window clamped to evidence: [" + finalTMin + ", " + finalTMax + "] -> [" + cMin + ", " + cMax + "]");
                    finalTMin = cMin; finalTMax = cMax;
                }
            }
        }
        const caseFile = _anomalySanitizeCaseFile(r.caseFile);

        // Compute flaggedPairs: edges (initiator ∈ finalIps, responder ∉ finalIps)
        // whose bin overlaps [finalTMin, finalTMax] and closeType !== 'graceful'.
        // One entry per distinct (initiator, responder) pair; count summed; dominant
        // closeType = the one with the highest count (ties → first encountered).
        const flaggedPairs = [];
        {
            const binnedData = (state.flowView && state.flowView.binnedData) || [];
            if (binnedData.length > 0) {
                const memberSet = new Set(finalIps);
                const pairAgg = new Map(); // key "i\0r" → {i, r, counts: Map<ct, n>}
                for (const d of binnedData) {
                    if (!d || !d.initiator || !d.responder) continue;
                    if (!memberSet.has(d.initiator)) continue;
                    if (memberSet.has(d.responder)) continue; // skip intra-region
                    const ct = d.closeType || 'unknown';
                    if (ct === 'graceful') continue;
                    const cnt = d.count || 0;
                    if (cnt === 0) continue;
                    const bs = d.binStart ?? d.startTime ?? 0;
                    const be = d.binEnd ?? d.endTime ?? bs;
                    if (be < finalTMin || bs > finalTMax) continue;
                    const key = d.initiator + '\0' + d.responder;
                    let agg = pairAgg.get(key);
                    if (!agg) {
                        agg = { i: d.initiator, r: d.responder, counts: new Map(), portCounts: new Map() };
                        pairAgg.set(key, agg);
                    }
                    agg.counts.set(ct, (agg.counts.get(ct) || 0) + cnt);
                    const dp = d.dst_port ?? d.dstPort ?? d.responderPort;
                    if (dp != null) agg.portCounts.set(dp, (agg.portCounts.get(dp) || 0) + cnt);
                }
                for (const agg of pairAgg.values()) {
                    let totalC = 0;
                    let dominantCt = null, dominantN = 0;
                    for (const [ct, n] of agg.counts) {
                        totalC += n;
                        if (n > dominantN) { dominantN = n; dominantCt = ct; }
                    }
                    let dominantPort = null, dominantPortN = 0;
                    for (const [port, n] of agg.portCounts) {
                        if (n > dominantPortN) { dominantPortN = n; dominantPort = port; }
                    }
                    flaggedPairs.push({ i: agg.i, r: agg.r, c: totalC, ct: dominantCt, dp: dominantPort });
                }
            }
        }

        const portHint = r._port != null ? Number(r._port) : null;
        const regionObj = { ips: finalIps, tMinUs: finalTMin, tMaxUs: finalTMax, reason, evidence, confidence, attackType, responder, caseFile, flaggedPairs, _port: portHint };
        _anomalyClassifyRegion(regionObj);
        // Preserve stored knownAttackName when classifier can't match (e.g. reload from file with no flaggedPairs)
        if (!regionObj.knownAttackName && typeof r.knownAttackName === 'string') {
            regionObj.knownAttackName = r.knownAttackName;
            regionObj.attackCategory = r.attackCategory || null;
        }
        out.push(regionObj);
    }
    console.log(`[Anomaly] Validation: ${rawRegions.length} raw -> ${out.length} kept ` +
        `(dropped ${droppedNoIps} no-known-IPs, ${droppedBadTime} bad-time, ${droppedEmptyWindow} empty-window). ` +
        `layout.ipPositions.size=${knownIps.size}`);
    if (droppedIpExamples.length > 0) {
        console.warn('[Anomaly] Regions dropped because their IPs were not in state.layout.ipPositions ' +
            '(reorder/filter/Fiedler may have removed them). Examples:', droppedIpExamples);
    }
    return out;
}

// Clear AI-tagged brushes that haven't been activated yet. We deliberately
// leave activated panels alone — the user may be analyzing them.
function _anomalyClearDormantPriors() {
    const toRemove = [];
    for (const [panelId, entry] of _magnifierBrushes.entries()) {
        if (!entry.editG) continue;
        if (entry.panel) continue;  // activated by user — keep
        if (!entry.editG.classed || !entry.editG.classed('mag-anomaly-ai')) continue;
        toRemove.push(panelId);
    }
    for (const panelId of toRemove) {
        const entry = _magnifierBrushes.get(panelId);
        try { entry.editG.remove(); } catch (e) {}
        _magnifierBrushes.delete(panelId);
    }
}

// AI-detected regions can be arbitrarily thin (single-IP rows are 0.1 px tall
// in cramped layout, time windows can be a few pixels wide). The brush itself
// stays at the AI's exact coords — so the magnifier panel opens with the
// intended IPs/time — but we add a visible sibling rect padded out to a
// minimum clickable size that activates the brush on click.
const _ANOMALY_MIN_HIT_PX = 14;

// Compute the overlay box coords for a validated region. Returns null when the
// region has no known IPs or collapses to a degenerate (zero-area) box.
function _anomalyRegionBoxCoords(r, ctx) {
    // region_cluster layout records each region's own contiguous block y-range;
    // wrap just that block so overlapping regions don't balloon across the gaps.
    const block = _regionClusterBlockRanges.get(_regionBlockKey(r));
    let y0, y1;
    if (block) {
        y0 = Math.max(0, Math.min(ctx.innerH, block.y0 - 1));
        y1 = Math.max(0, Math.min(ctx.innerH, block.y1 + 1));
    } else {
        const memberIps = Array.isArray(r.ips) ? r.ips.slice() : [];
        if (r.responder) memberIps.push(r.responder);
        const ys = memberIps.map(ip => state.layout.ipPositions.get(ip)).filter(v => v !== undefined);
        if (!ys.length) return null;
        y0 = Math.max(0, Math.min(ctx.innerH, Math.min(...ys) - 0.05));
        y1 = Math.max(0, Math.min(ctx.innerH, Math.max(...ys) + 0.05));
    }
    const x0 = Math.max(0, Math.min(ctx.innerW, xScale(r.tMinUs)));
    const x1 = Math.max(0, Math.min(ctx.innerW, xScale(r.tMaxUs)));
    if (x1 <= x0 || y1 <= y0) return null;
    return { x0, y0, x1, y1, cx: (x0 + x1) / 2, cy: (y0 + y1) / 2 };
}

function _anomalyDrawRegions(regions) {
    const ctx = _magnifierOverlayCtx;
    if (!ctx) {
        console.warn('[Anomaly] Magnifier overlay not initialized; cannot draw regions.');
        return 0;
    }
    _anomalyClearDormantPriors();
    _anomalyFlaggedIPs.clear();
    _anomalyRegionViews = [];
    for (const r of regions) {
        if (r && Array.isArray(r.ips)) {
            for (const ip of r.ips) _anomalyFlaggedIPs.add(ip);
        }
    }
    let drawn = 0;
    for (const r of regions) {
        const box = _anomalyRegionBoxCoords(r, ctx);
        if (!box) continue;
        const { x0, y0, x1, y1, cx, cy } = box;
        const result = ctx.createSelection([[x0, y0], [x1, y1]], {
            reason: r.reason || '',
            evidence: r.evidence || '',
            confidence: r.confidence != null ? r.confidence : null,
            attackType: r.attackType || 'other',
            knownAttackName: r.knownAttackName || null,
            caseFile: Array.isArray(r.caseFile) ? r.caseFile : null,
            regionIps: Array.isArray(r.ips) ? r.ips.slice() : [],
            regionResponder: typeof r.responder === 'string' ? r.responder : null
        });
        if (!result) continue;
        result.editG.classed('mag-anomaly-ai', true);

        // Hit target: padded to MIN_HIT_PX, centered on the true rect. Visible
        // (dashed outline) so the user can see thin regions; clicking activates
        // the underlying brush and removes the hit rect so normal d3.brush
        // drag/resize takes over.
        const hitStyle = _attackTypeStyle(r.attackType);
        const hw = Math.max(x1 - x0, _ANOMALY_MIN_HIT_PX) / 2;
        const hh = Math.max(y1 - y0, _ANOMALY_MIN_HIT_PX) / 2;
        const hit = result.editG.append('rect')
            .attr('class', 'mag-anomaly-hit')
            .attr('x', cx - hw).attr('y', cy - hh)
            .attr('width', hw * 2).attr('height', hh * 2)
            .style('fill', hitStyle.fill)
            .style('stroke', hitStyle.stroke)
            .style('stroke-width', '1.5px')
            .style('stroke-dasharray', '4,2')
            .style('cursor', 'pointer')
            .style('pointer-events', 'all');
        // Native tooltip so the user can preview the AI's reason without
        // activating the panel.
        if (r.reason) {
            const conf = r.confidence != null ? ` (confidence ${r.confidence.toFixed(2)})` : '';
            const atLabel = r.knownAttackName ? `${r.knownAttackName} (${r.attackType})` : (hitStyle.label || r.attackType);
            const at = r.attackType ? `${atLabel} · ` : '';
            hit.append('title').text(`AI anomaly · ${at}${r.reason}${conf}`);
        }
        hit.on('mousedown click', (event) => {
            // Stop propagation BEFORE any DOM mutation so the parent <g>'s d3-brush
            // pointer handlers don't fire on a now-removed element (would crash
            // reading event.type / selection in d3.brush internals).
            event.stopPropagation();
            event.preventDefault();
            if (event.type !== 'click') return;
            try { result.activate(); } catch (e) { console.warn('[Anomaly] activate failed:', e); }
            try { hit.remove(); } catch (e) {}
        });

        _anomalyRegionViews.push({ region: r, result, hit, box });
        drawn++;
    }
    _anomalyUpdateRegionsBtn();
    return drawn;
}

function _anomalySetStatus(text, isError) {
    const btn = document.getElementById('detectAnomaliesBtn');
    if (!btn) return;
    btn.textContent = text;
    btn.style.color = isError ? '#b91c1c' : '';
}

// ── AI Regions list panel ──────────────────────────────────────────────────
// Module-level state for the floating regions list and hover callout.
let _anomalyRegionViews = [];        // parallel to drawn regions: { region, result, hit, box }
let _anomalyRegionsListPanel = null; // floating list panel DOM, or null when closed
let _anomalyRegionHoverG = null;     // reusable <g> on overlay for hover callout/emphasis

// Update the "Regions (N)" button label and, if the list panel is open,
// re-render its body.
function _anomalyUpdateRegionsBtn() {
    const rb = document.getElementById('regionsListBtn');
    if (rb) rb.textContent = 'Regions (' + _anomalyRegionViews.length + ')';
    if (_anomalyRegionsListPanel) {
        if (_anomalyRegionsListPanel.__titleSpan) {
            _anomalyRegionsListPanel.__titleSpan.textContent = 'AI Regions (' + _anomalyRegionViews.length + ')';
        }
        if (_anomalyRegionsListPanel.__bodyEl) {
            _anomalyRenderRegionsList(_anomalyRegionsListPanel.__bodyEl);
        }
    }
}

function _anomalyToggleRegionsList() {
    if (_anomalyRegionsListPanel) {
        _anomalyCloseRegionsList();
    } else {
        _anomalyOpenRegionsList();
    }
}

function _anomalyOpenRegionsList() {
    if (_anomalyRegionsListPanel) {
        // Already open — refresh label + body (idempotent).
        _anomalyUpdateRegionsBtn();
        return;
    }
    const panel = document.createElement('div');
    panel.className = 'anomaly-regions-panel';
    Object.assign(panel.style, {
        position: 'fixed', top: '90px', right: '20px',
        width: '360px', maxHeight: '72vh', zIndex: '1001',
        background: '#fff', border: '1px solid #adb5bd', borderRadius: '4px',
        boxShadow: '0 20px 60px rgba(0,0,0,0.45), 0 8px 20px rgba(0,0,0,0.3)',
        display: 'flex', flexDirection: 'column',
        fontFamily: 'monospace', fontSize: '12px'
    });

    // Header
    const header = document.createElement('div');
    header.className = 'anomaly-regions-header';
    Object.assign(header.style, {
        cursor: 'move', padding: '6px 10px', background: '#f1f3f5',
        borderBottom: '1px solid #dee2e6', display: 'flex',
        alignItems: 'center', justifyContent: 'space-between', flex: '0 0 auto'
    });
    const titleSpan = document.createElement('span');
    titleSpan.textContent = 'AI Regions (' + _anomalyRegionViews.length + ')';
    const closeBtn = document.createElement('button');
    closeBtn.className = 'anomaly-regions-close';
    closeBtn.textContent = '×';
    Object.assign(closeBtn.style, {
        background: 'none', border: 'none', cursor: 'pointer',
        fontSize: '16px', lineHeight: '1', padding: '0 2px'
    });
    closeBtn.addEventListener('click', _anomalyCloseRegionsList);
    header.appendChild(titleSpan);
    header.appendChild(closeBtn);

    // Body
    const body = document.createElement('div');
    body.className = 'anomaly-regions-body';
    Object.assign(body.style, {
        overflow: 'auto', flex: '1 1 auto', padding: '0'
    });
    panel.__bodyEl = body;
    panel.__titleSpan = titleSpan;

    panel.appendChild(header);
    panel.appendChild(body);

    // Drag behavior (mirrors magnifier panel pattern). Named handlers so they
    // can be removed on close — anonymous document listeners would leak across
    // open/close cycles.
    let dragging = false, dragOffX = 0, dragOffY = 0;
    header.addEventListener('mousedown', (e) => {
        if (e.target === closeBtn) return;
        dragging = true;
        // Switch to left-based positioning for drag
        const rect = panel.getBoundingClientRect();
        panel.style.right = 'auto';
        panel.style.left = rect.left + 'px';
        panel.style.top = rect.top + 'px';
        dragOffX = e.clientX - rect.left;
        dragOffY = e.clientY - rect.top;
        e.preventDefault();
    });
    const onDragMove = (e) => {
        if (!dragging) return;
        let nx = e.clientX - dragOffX;
        let ny = e.clientY - dragOffY;
        const pw = panel.offsetWidth, ph = panel.offsetHeight;
        nx = Math.max(0, Math.min(window.innerWidth - pw, nx));
        ny = Math.max(0, Math.min(window.innerHeight - ph, ny));
        panel.style.left = nx + 'px';
        panel.style.top = ny + 'px';
    };
    const onDragUp = () => { dragging = false; };
    document.addEventListener('mousemove', onDragMove);
    document.addEventListener('mouseup', onDragUp);
    panel.__removeDragListeners = () => {
        document.removeEventListener('mousemove', onDragMove);
        document.removeEventListener('mouseup', onDragUp);
    };

    document.body.appendChild(panel);
    _anomalyRegionsListPanel = panel;
    _anomalyRenderRegionsList(body);
}

function _anomalyCloseRegionsList() {
    _anomalyRegionHoverOff();
    if (_anomalyRegionsListPanel) {
        if (_anomalyRegionsListPanel.__removeDragListeners) _anomalyRegionsListPanel.__removeDragListeners();
        _anomalyRegionsListPanel.remove();
        _anomalyRegionsListPanel = null;
    }
}

function _anomalyRenderRegionsList(bodyEl) {
    // Clear
    while (bodyEl.firstChild) bodyEl.removeChild(bodyEl.firstChild);

    if (_anomalyRegionViews.length === 0) {
        const empty = document.createElement('div');
        Object.assign(empty.style, { padding: '12px', color: '#6c757d' });
        empty.textContent = 'No regions — run Detect anomalies.';
        bodyEl.appendChild(empty);
        return;
    }

    // Sort by confidence descending; null/undefined sorts last
    const sorted = _anomalyRegionViews.slice().sort((a, b) => {
        const ca = (a.region.confidence != null) ? a.region.confidence : -1;
        const cb = (b.region.confidence != null) ? b.region.confidence : -1;
        return cb - ca;
    });

    for (const view of sorted) {
        const region = view.region;
        const style = _attackTypeStyle(region.attackType);

        const row = document.createElement('div');
        row.className = 'anomaly-region-row';
        Object.assign(row.style, {
            padding: '8px 10px', borderBottom: '1px solid #e9ecef',
            cursor: 'pointer', display: 'flex', flexDirection: 'column', gap: '3px'
        });

        // Line 1: badge + confidence
        const line1 = document.createElement('div');
        Object.assign(line1.style, {
            display: 'flex', alignItems: 'center', gap: '6px', justifyContent: 'space-between'
        });
        const badge = document.createElement('span');
        badge.textContent = region.knownAttackName
            ? `${region.knownAttackName} (${region.attackType})`
            : (style.label || region.attackType || 'other');
        Object.assign(badge.style, {
            background: style.fill, color: style.stroke,
            border: '1px solid ' + style.stroke, borderRadius: '3px',
            padding: '1px 6px', fontWeight: 'bold'
        });
        const confSpan = document.createElement('span');
        confSpan.style.color = '#868e96';
        confSpan.textContent = region.confidence != null
            ? 'conf ' + region.confidence.toFixed(2)
            : 'conf —';
        line1.appendChild(badge);
        line1.appendChild(confSpan);

        // Line 2: responder + attacker count
        const line2 = document.createElement('div');
        line2.style.color = '#495057';
        line2.textContent = '▸ ' + (region.responder || 'n/a') + ' · ' +
            region.ips.length + ' attacker' + (region.ips.length === 1 ? '' : 's');

        // Line 3: truncated reason
        const line3 = document.createElement('div');
        Object.assign(line3.style, {
            color: '#6c757d', fontSize: '11px', lineHeight: '1.35', whiteSpace: 'normal'
        });
        const reason = region.reason || '';
        line3.textContent = reason.slice(0, 110) + (reason.length > 110 ? '…' : '');

        row.appendChild(line1);
        row.appendChild(line2);
        row.appendChild(line3);

        // Hover / click events
        row.addEventListener('mouseenter', () => {
            row.style.background = '#f1f3f5';
            _anomalyRegionHoverOn(view);
        });
        row.addEventListener('mouseleave', () => {
            row.style.background = row.__selected ? '#e3f2fd' : '';
            _anomalyRegionHoverOff();
        });
        row.addEventListener('click', () => {
            // Clear selection on all siblings
            const allRows = bodyEl.querySelectorAll('.anomaly-region-row');
            allRows.forEach(r => { r.__selected = false; r.style.background = ''; });
            row.__selected = true;
            row.style.background = '#e3f2fd';
            _anomalyActivateView(view);
        });

        bodyEl.appendChild(row);
    }
}

// Re-open a magnifier panel for the given region view. Handles stale
// result handles after a chart/overlay rebuild by recomputing from region coords.
function _anomalyActivateView(view) {
    if (view.result && view.result.editG &&
        view.result.editG.node() && document.contains(view.result.editG.node())) {
        try { view.result.activate(); } catch (e) { console.warn('[Anomaly] activate failed:', e); }
        return;
    }
    // Stale — recompute from region data
    const ctx = _magnifierOverlayCtx;
    if (!ctx) return;
    const r = view.region;
    const box = _anomalyRegionBoxCoords(r, ctx);
    if (!box) return;
    view.box = box;
    const result = ctx.createSelection([[box.x0, box.y0], [box.x1, box.y1]], {
        reason: r.reason || '', evidence: r.evidence || '',
        confidence: r.confidence != null ? r.confidence : null,
        attackType: r.attackType || 'other',
        knownAttackName: r.knownAttackName || null,
        caseFile: Array.isArray(r.caseFile) ? r.caseFile : null,
        regionIps: Array.isArray(r.ips) ? r.ips.slice() : [],
        regionResponder: typeof r.responder === 'string' ? r.responder : null
    });
    if (result) {
        result.editG.classed('mag-anomaly-ai', true);
        view.result = result;
        try { result.activate(); } catch (e) { console.warn('[Anomaly] activate failed (rebuilt):', e); }
    }
}

// Emphasize the hovered region on the overlay: dim others, raise and highlight
// the hovered hit rect, draw a callout annotation, and scroll it into view.
function _anomalyRegionHoverOn(view) {
    const ctx = _magnifierOverlayCtx;
    if (!ctx) return;
    const m = ctx.margin;
    const region = view.region;
    const style = _attackTypeStyle(region.attackType);
    const b = view.box;

    // (1) Emphasize: dim all hit rects, raise the hovered one
    ctx.overlaySvg.selectAll('.mag-anomaly-hit').style('opacity', 0.2);
    const hitAttached = view.hit && view.hit.node() && document.contains(view.hit.node());
    if (hitAttached) {
        view.hit.style('opacity', 1).style('stroke-width', '2.5px');
        if (view.result && view.result.editG) view.result.editG.raise();
    }

    // (2) Annotation callout in a reusable hover <g> translated by margin
    if (!_anomalyRegionHoverG || !_anomalyRegionHoverG.node() ||
        !document.contains(_anomalyRegionHoverG.node())) {
        _anomalyRegionHoverG = ctx.overlaySvg.append('g')
            .attr('class', 'region-hover-overlay')
            .attr('transform', 'translate(' + m.left + ',' + m.top + ')')
            .style('pointer-events', 'none');
    } else {
        _anomalyRegionHoverG.raise();
    }
    _anomalyRegionHoverG.selectAll('*').remove();

    // Fallback emphasis rect when the hit is already detached (panel opened earlier)
    if (!hitAttached) {
        _anomalyRegionHoverG.append('rect')
            .attr('x', b.x0).attr('y', b.y0)
            .attr('width', Math.max(b.x1 - b.x0, 14))
            .attr('height', Math.max(b.y1 - b.y0, 14))
            .style('fill', 'none')
            .style('stroke', style.stroke)
            .style('stroke-width', '2.5px')
            .style('stroke-dasharray', '4,2');
    }

    // Label inside the box at the top-left corner
    const attackLabel = region.knownAttackName
        ? `${region.knownAttackName} (${region.attackType})`
        : (style.label || region.attackType || 'other');
    const labelText = attackLabel +
        (region.confidence != null ? ' · conf ' + region.confidence.toFixed(2) : '');

    const inset = 4;
    const labelG = _anomalyRegionHoverG.append('g');
    labelG.append('text')
        .attr('x', 0).attr('y', 0)
        .attr('font-size', '11px')
        .attr('font-family', 'monospace')
        .attr('font-weight', 'bold')
        .attr('fill', style.stroke)
        .text(labelText);

    // Insert background rect behind the text
    let bbox;
    try { bbox = labelG.node().getBBox(); } catch (e) { bbox = { x: 0, y: 0, width: 80, height: 12 }; }
    labelG.insert('rect', ':first-child')
        .attr('x', bbox.x - 3).attr('y', bbox.y - 2)
        .attr('width', bbox.width + 6).attr('height', bbox.height + 4)
        .attr('fill', '#fff').attr('rx', 2)
        .style('opacity', 0.88);

    // Position at top-left inside the box
    labelG.attr('transform', 'translate(' + (b.x0 + inset) + ',' + (b.y0 + inset + 11) + ')');

    // (3) Auto-scroll the region into view
    const cont = document.getElementById('chart-container');
    if (cont) {
        const targetTop = m.top + b.cy - cont.clientHeight / 2;
        const maxTop = cont.scrollHeight - cont.clientHeight;
        cont.scrollTo({ top: Math.max(0, Math.min(maxTop, targetTop)), behavior: 'smooth' });
    }
}

// Restore normal hit-rect opacity and clear the hover callout group.
function _anomalyRegionHoverOff() {
    const ctx = _magnifierOverlayCtx;
    if (ctx) {
        ctx.overlaySvg.selectAll('.mag-anomaly-hit')
            .style('opacity', 1)
            .style('stroke-width', '1.5px');
    }
    if (_anomalyRegionHoverG) {
        _anomalyRegionHoverG.selectAll('*').remove();
    }
}

// ── Anomaly persistence helpers ────────────────────────────────────────────
// Holds the last validated+drawn regions so that explanation-time saves can
// include them without re-running detection.
let _anomalyLastRegions = [];

// ── FSA / IndexedDB file-handle store ─────────────────────────────────────
// Module-level cache so we don't hit IDB on every write.
let _anomalyFileHandle = null;
// In-flight / queued write coalescing guards.
let _anomalyFileWriteInFlight = false;
let _anomalyFileWriteQueued  = false;

async function _anomalyIdbOpen() {
    return new Promise((resolve, reject) => {
        try {
            const req = indexedDB.open('tcp-detector', 1);
            req.onupgradeneeded = (ev) => {
                try { ev.target.result.createObjectStore('handles'); } catch (e) {}
            };
            req.onsuccess = (ev) => resolve(ev.target.result);
            req.onerror   = (ev) => reject(ev.target.error);
        } catch (e) { reject(e); }
    });
}

async function _anomalyIdbGetHandle() {
    try {
        const db = await _anomalyIdbOpen();
        return new Promise((resolve) => {
            try {
                const tx  = db.transaction('handles', 'readonly');
                const req = tx.objectStore('handles').get('detector-results');
                req.onsuccess = (ev) => resolve(ev.target.result || null);
                req.onerror   = ()   => resolve(null);
            } catch (e) { resolve(null); }
        });
    } catch (e) { return null; }
}

async function _anomalyIdbSetHandle(handle) {
    try {
        const db = await _anomalyIdbOpen();
        return new Promise((resolve) => {
            try {
                const tx  = db.transaction('handles', 'readwrite');
                const req = tx.objectStore('handles').put(handle, 'detector-results');
                req.onsuccess = () => resolve(true);
                req.onerror   = () => resolve(false);
            } catch (e) { resolve(false); }
        });
    } catch (e) { return false; }
}

// Returns true if permission is already granted; prompts only when allowPrompt
// is true (must be called from a user-gesture path in that case).
async function _anomalyVerifyPermission(handle, withWrite, allowPrompt) {
    try {
        const opts = { mode: withWrite ? 'readwrite' : 'read' };
        if (await handle.queryPermission(opts) === 'granted') return true;
        if (allowPrompt && await handle.requestPermission(opts) === 'granted') return true;
        return false;
    } catch (e) { return false; }
}

// Silent write: resolves handle, checks permission without prompting, merges
// current entry into the container, then writes. Coalesces concurrent calls.
async function _anomalyWriteToLinkedFile() {
    // Resolve handle
    const handle = _anomalyFileHandle || (await _anomalyIdbGetHandle());
    if (!handle) return false;
    _anomalyFileHandle = handle;

    // Gate on data being available
    if (!_anomalyDatasetId()) return false;
    if (!_anomalyLastRegions || _anomalyLastRegions.length === 0) return false;

    // Silent permission check — no prompt
    if (!(await _anomalyVerifyPermission(handle, true, false))) return false;

    // Coalescing: if a write is in flight, queue one more then bail
    if (_anomalyFileWriteInFlight) { _anomalyFileWriteQueued = true; return false; }

    _anomalyFileWriteInFlight = true;
    try {
        // Build container by reading existing file first to preserve other datasets
        let container = { version: 1, format: 'tcp-detector-results', datasets: {} };
        try {
            const file = await handle.getFile();
            const text = await file.text();
            if (text) {
                const j = JSON.parse(text);
                if (j && j.datasets && typeof j.datasets === 'object') container = j;
            }
        } catch (e) { /* empty or corrupt — start fresh */ }

        container.datasets[_anomalyDatasetId()] = _anomalyBuildEntry();

        const w = await handle.createWritable();
        await w.write(JSON.stringify(container, null, 2));
        await w.close();
        return true;
    } catch (e) {
        console.warn('[Anomaly] linked-file write failed:', e);
        return false;
    } finally {
        _anomalyFileWriteInFlight = false;
        if (_anomalyFileWriteQueued) {
            _anomalyFileWriteQueued = false;
            // One coalesced follow-up write (fire-and-forget)
            _anomalyWriteToLinkedFile();
        }
    }
}

// Restore from linked file (no prompt). Returns true if data was applied.
// Returns false if no handle, permission denied, or data not found.
// Side-effect: caches _anomalyFileHandle when read permission is granted.
async function _anomalyRestoreFromLinkedFile() {
    try {
        const handle = await _anomalyIdbGetHandle();
        if (!handle) return false;
        if (!(await _anomalyVerifyPermission(handle, false, false))) return false;
        _anomalyFileHandle = handle;
        const file = await handle.getFile();
        const text = await file.text();
        if (!text) return false;
        const j = JSON.parse(text);
        const id = _anomalyDatasetId();
        if (!id) return false;
        const entry = j && j.datasets && j.datasets[id];
        if (!entry || !Array.isArray(entry.regions)) return false;
        const res = _anomalyApplyRestoredEntry(entry);
        if (res.applied) {
            _anomalySetStatus('Loaded ' + res.drawn + ' region' + (res.drawn === 1 ? '' : 's') + ' from linked detector-results.json — re-run to refresh', false);
            return true;
        }
        return false;
    } catch (e) {
        console.warn('[Anomaly] linked-file restore failed:', e);
        return false;
    }
}

function _anomalyDatasetId() {
    const ext = state.data.timeExtent || [0, 0];
    if (ext[0] === 0 && ext[1] === 0) return null;
    return ext[0] + '-' + ext[1];
}

function _anomalyStorageKey() {
    const id = _anomalyDatasetId();
    return id ? ('tcp-detector-results:v1:' + id) : null;
}

function _anomalyPersistSave() {
    const key = _anomalyStorageKey();
    if (!key) return;
    const id = _anomalyDatasetId();
    const blob = {
        version: 1,
        datasetId: id,
        savedAt: Date.now(),
        regions: _anomalyLastRegions,
        explainCache: Array.from(_explainCache.entries()),
        roleMaps: Array.from(_roleMapCache.entries()).map(([k, m]) => [k, Array.from(m.entries())])
    };
    try {
        localStorage.setItem(key, JSON.stringify(blob));
    } catch (e) {
        // Quota or private-mode failure — retry with regions only
        try {
            const regionsOnly = { version: 1, datasetId: id, savedAt: Date.now(), regions: _anomalyLastRegions };
            localStorage.setItem(key, JSON.stringify(regionsOnly));
        } catch (e2) {
            console.warn('[Anomaly] persist failed:', e2);
        }
    }
}

// ── TASK 1: shared apply helper ───────────────────────────────────────────
// Applies one result-set entry ({ regions, explainCache, roleMaps }) to the
// live caches and, if the overlay is ready, draws the regions. Returns
// { applied: bool, drawn: number }. Never throws.
function _anomalyApplyRestoredEntry(entry) {
    // Restore explain cache
    _explainCache.clear();
    if (Array.isArray(entry.explainCache)) {
        for (const [k, text] of entry.explainCache) {
            if (typeof k === 'string' && typeof text === 'string') _explainCache.set(k, text);
        }
    }
    // Restore role-map cache
    _roleMapCache.clear();
    if (Array.isArray(entry.roleMaps)) {
        for (const [k, pairs] of entry.roleMaps) {
            if (typeof k === 'string' && Array.isArray(pairs)) {
                _roleMapCache.set(k, new Map(pairs));
            }
        }
    }

    if (!_magnifierOverlayCtx) {
        // Overlay not ready yet — caches restored, drawing deferred
        return { applied: false, drawn: 0 };
    }

    try {
        const valid = _anomalyValidateRegions(entry.regions || []);
        if (valid.length) {
            const drawn = _anomalyDrawRegions(valid);
            _anomalyLastRegions = valid;
            return { applied: true, drawn };
        }
        return { applied: false, drawn: 0 };
    } catch (e) {
        console.warn('[Anomaly] apply draw failed:', e);
        return { applied: false, drawn: 0 };
    }
}

function _anomalyRestoreResults() {
    const key = _anomalyStorageKey();
    if (!key) return false;
    let blob;
    try {
        const s = localStorage.getItem(key);
        if (!s) return false;
        blob = JSON.parse(s);
    } catch (e) {
        console.warn('[Anomaly] restore parse failed:', e);
        return false;
    }
    if (!blob || blob.version !== 1 || !Array.isArray(blob.regions)) return false;

    const res = _anomalyApplyRestoredEntry(blob);
    if (res.applied) {
        _anomalySetStatus('Restored ' + res.drawn + ' saved region' + (res.drawn === 1 ? '' : 's') + ' — re-run to refresh', false);
    }
    return true;
}

// ── TASK 2: file constant + entry builder ─────────────────────────────────
const _ANOMALY_RESULTS_FILE = './detector-results.json';

// Builds the per-dataset entry that goes into the file container's datasets map.
// Mirrors the shape _anomalyPersistSave uses for localStorage.
function _anomalyBuildEntry() {
    return {
        datasetId: _anomalyDatasetId(),
        savedAt: Date.now(),
        regions: _anomalyLastRegions,
        explainCache: Array.from(_explainCache.entries()),
        roleMaps: Array.from(_roleMapCache.entries()).map(([k, m]) => [k, Array.from(m.entries())])
    };
}

// ── TASK 3: download (merge into multi-dataset container) ─────────────────
async function _anomalyDownloadResults() {
    const id = _anomalyDatasetId();
    if (!id) { _anomalySetStatus('No dataset to save', true); return; }
    if (!_anomalyLastRegions || _anomalyLastRegions.length === 0) {
        _anomalySetStatus('No regions to save — detect first', true);
        return;
    }

    // Try to fetch an existing file to preserve other datasets in it.
    let container = { version: 1, format: 'tcp-detector-results', datasets: {} };
    try {
        const r = await fetch(_ANOMALY_RESULTS_FILE, { cache: 'no-store' });
        if (r.ok) {
            const j = await r.json();
            if (j && j.datasets && typeof j.datasets === 'object') container = j;
        }
    } catch (e) { /* missing file or parse error — start fresh */ }

    container.datasets[id] = _anomalyBuildEntry();

    try {
        const json = JSON.stringify(container, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'detector-results.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        // Briefly relabel the download button to confirm success.
        const dlBtn = document.getElementById('downloadDetectorResultsBtn');
        if (dlBtn) {
            const orig = dlBtn.textContent;
            dlBtn.textContent = 'Downloaded ✓';
            setTimeout(() => { const b = document.getElementById('downloadDetectorResultsBtn'); if (b) b.textContent = orig; }, 2000);
        }
    } catch (e) {
        console.warn('[Anomaly] download failed:', e);
    }
}

// ── TASK 4: restore-from-file + combined on-load ──────────────────────────
async function _anomalyRestoreFromFile() {
    const id = _anomalyDatasetId();
    if (!id) return false;
    try {
        const r = await fetch(_ANOMALY_RESULTS_FILE, { cache: 'no-store' });
        if (!r.ok) return false;
        const j = await r.json();
        const entry = j && j.datasets && j.datasets[id];
        if (!entry || !Array.isArray(entry.regions)) return false;
        const res = _anomalyApplyRestoredEntry(entry);
        if (res.applied) {
            _anomalySetStatus('Loaded ' + res.drawn + ' region' + (res.drawn === 1 ? '' : 's') + ' from detector-results.json — re-run to refresh', false);
            return true;
        }
        return false;
    } catch (e) {
        console.warn('[Anomaly] file restore failed:', e);
        return false;
    }
}

// Combined on-load restore: linked file (FSA/IDB) wins first; then static
// file fetch; then localStorage. Fire-and-forget (async, self-guarded).
async function _anomalyRestoreOnLoad() {
    try { if (await _anomalyRestoreFromLinkedFile()) return; } catch (e) {}
    try { if (await _anomalyRestoreFromFile()) return; } catch (e) {}
    try { _anomalyRestoreResults(); } catch (e) { console.warn('[Anomaly] restore failed:', e); }
}
// ── End anomaly persistence helpers ───────────────────────────────────────

async function _anomalyRun() {
    if (_anomalyBusy) return;
    if (!_magnifierOverlayCtx) {
        _anomalySetStatus('Detect anomalies (no chart)', true);
        return;
    }
    const binnedData = (state.flowView && state.flowView.binnedData) || [];
    if (binnedData.length === 0) {
        _anomalySetStatus('Detect anomalies (no data)', true);
        return;
    }

    _anomalyBusy = true;
    const btn = document.getElementById('detectAnomaliesBtn');
    if (btn) btn.disabled = true;
    _anomalySetStatus('Detecting…', false);
    _anomalyAbortController = new AbortController();

    // Diagnostic: snapshot the inputs that determine what the AI sees and what
    // the validator will accept. Compare across runs (e.g. before/after a row
    // reorder) to tell input-change apart from LLM non-determinism.
    const distinctInitiatorsInData = new Set(binnedData.map(d => d && d.initiator).filter(Boolean)).size;
    console.log(`[Anomaly] Run start — binnedData.items=${binnedData.length}, ` +
        `distinctInitiatorsInData=${distinctInitiatorsInData}, ` +
        `layout.ipPositions.size=${state.layout.ipPositions.size}, ` +
        `layout.ipOrder.length=${state.layout.ipOrder.length}, ` +
        `timeExtent=[${(state.data.timeExtent || [0,0]).join(', ')}]`);

    try {
        const key = await _explainFetchKey();
        if (!key) { _anomalySetStatus('Detect anomalies (missing key)', true); return; }
        const systemPrompt = await _anomalyFetchSystemPrompt();
        if (!systemPrompt) { _anomalySetStatus('Detect anomalies (missing prompt)', true); return; }

        // Optional packet-derived features. Tools degrade gracefully if this is null.
        await _anomalyLoadFeatures();

        const text = await _anomalyCallAnthropicAgentic(
            systemPrompt,
            key,
            _anomalyAbortController.signal,
            (turn) => _anomalySetStatus(`Detecting… (step ${turn}/${_ANOMALY_MAX_TURNS})`, false)
        );
        const modelRaw = _anomalyParseRegions(text);
        const raw = _anomalyMergeRaw(modelRaw, _anomalySafetyFloorRaw());
        const valid = _anomalyMergeOverlapping(_anomalyValidateRegions(raw));
        // Layer C: AI fallback classification for unmatched regions
        try { await _anomalyClassifyViaAI(valid, key); } catch (e) { console.warn('[Anomaly] AI classify pass failed:', e); }
        console.log('[Anomaly] Parsed regions:', raw);
        console.log('[Anomaly] Validated regions (passed to draw):', valid);
        valid.forEach((r, i) => console.log(
            `[Anomaly] region ${i + 1}/${valid.length}: attackType="${r.attackType}" conf=${r.confidence} ` +
            `ips=[${(r.ips || []).join(', ')}] | ${(r.reason || '').slice(0, 160)}`));
        if (raw.length !== valid.length) {
            console.warn(`[Anomaly] Dropped ${raw.length - valid.length} region(s) during validation (unknown IPs, out-of-extent time, or degenerate).`);
        }
        if (valid.length === 0) {
            _anomalySetStatus('No anomalies found', false);
            return;
        }
        const drawn = _anomalyDrawRegions(valid);
        _anomalyLastRegions = valid;
        _anomalyPersistSave();
        try { _anomalyWriteToLinkedFile(); } catch (e) {}
        // If row grouping is on, re-apply the order so the new regions form tight
        // blocks. The relayout's _anomalyRestoreOnLoad redraws the boxes at the
        // new (now contiguous) positions, replacing the draw above.
        if (document.getElementById('groupByRegion')?.checked) {
            try { await applyIPRowOrder(); } catch (e) { console.warn('[Anomaly] regroup after detect failed:', e); }
        }
        _anomalySetStatus(`Detected ${drawn} region${drawn === 1 ? '' : 's'} — re-run to refresh`, false);
        if (drawn > 0) { try { _anomalyOpenRegionsList(); } catch (e) { console.warn('[Anomaly] open regions list failed:', e); } }
    } catch (e) {
        if (e && e.name === 'AbortError') {
            _anomalySetStatus('Detect anomalies', false);
            return;
        }
        console.warn('[Anomaly] Detection failed:', e);
        const msg = String(e && e.message || e);
        if (msg.includes('HTTP 401')) _anomalySetStatus('Detect anomalies (auth error)', true);
        else if (msg.includes('HTTP 429')) _anomalySetStatus('Detect anomalies (rate limited — retry later)', true);
        else if (msg.includes('HTTP 529')) _anomalySetStatus('Detect anomalies (API overloaded — retry in a moment)', true);
        else if (msg.includes('HTTP 5')) _anomalySetStatus('Detect anomalies (service error)', true);
        else _anomalySetStatus('Detect anomalies (failed)', true);
    } finally {
        _anomalyBusy = false;
        _anomalyAbortController = null;
        if (btn) btn.disabled = false;
    }
}

// Debug hook for validating the anomaly tools from the DevTools console WITHOUT
// spending an API call, e.g.:
//   await _anomalyDebug.loadFeatures();
//   _anomalyDebug.dispatch('get_responder_fanin', { max_completion_ratio: 0.5 });
//   _anomalyDebug.dispatch('get_port_coordination', {});
//   _anomalyDebug.dispatch('get_entity_features', { ip: '172.28.4.7' });
if (typeof window !== 'undefined') {
    window._anomalyDebug = {
        loadFeatures: _anomalyLoadFeatures,
        dispatch: _anomalyDispatchTool,
        features: () => _anomalyFeatures,
        sanitizeCaseFile: _anomalySanitizeCaseFile,
    };
}

// ============================================================================
// Batch "Explain all regions" — iterates all AI-spawned entries in
// _magnifierBrushes and runs _explainRunHeadless on each sequentially,
// caching results and flushing to disk via _explainAcceptResult.
// ============================================================================

let _anomalyExplainAllBusy = false;
let _anomalyExplainAllAbort = null;

async function _anomalyExplainAllRegions(force = false) {
    if (_anomalyExplainAllBusy) return;

    // Collect AI regions (attackType non-null) that have lastArgs.
    const targets = [];
    for (const entry of _magnifierBrushes.values()) {
        if (entry.lastArgs && entry.lastArgs.attackType != null) {
            targets.push(entry);
        }
    }

    if (targets.length === 0) {
        _anomalySetStatus('No regions to explain — detect or load first', true);
        return;
    }

    const N = targets.length;
    _anomalyExplainAllBusy = true;
    _anomalyExplainAllAbort = new AbortController();

    const btn = document.getElementById('explainAllRegionsBtn');
    if (btn) { btn.textContent = 'Cancel explain-all'; }

    let done = 0, cached = 0, skipped = 0, failed = 0;
    let aborted = false;

    try {
        for (let i = 0; i < targets.length; i++) {
            _anomalySetStatus(`Explaining region ${i + 1}/${N}…`, false);
            let res;
            try {
                res = await _explainRunHeadless(targets[i].lastArgs, _anomalyExplainAllAbort.signal, { force });
            } catch (err) {
                if (err && err.name === 'AbortError') {
                    aborted = true;
                    break;
                }
                console.warn('[ExplainAll] Unexpected error in batch loop:', err);
                failed++;
                continue;
            }

            if (res.status === 'error') {
                // Missing key or prompt — global issue; abort the whole batch.
                const reason = res.reason === 'key'
                    ? 'missing API key'
                    : 'missing system prompt';
                _anomalySetStatus(`Explain all stopped — ${reason}`, true);
                return;
            } else if (res.status === 'done') {
                done++;
            } else if (res.status === 'cached') {
                cached++;
            } else if (res.status === 'skip') {
                skipped++;
            } else if (res.status === 'failed') {
                failed++;
            }
        }

        if (aborted) {
            _anomalySetStatus('Explain all cancelled', false);
            return;
        }

        // Build a terse summary, omitting zero-count categories.
        const parts = [];
        if (done)    parts.push(`${done} explained`);
        if (cached)  parts.push(`${cached} cached`);
        if (skipped) parts.push(`${skipped} skipped`);
        if (failed)  parts.push(`${failed} failed`);
        _anomalySetStatus(`Explain all done — ${parts.join(', ')} — saved`, false);
    } finally {
        _anomalyExplainAllBusy = false;
        _anomalyExplainAllAbort = null;
        const b = document.getElementById('explainAllRegionsBtn');
        if (b) { b.textContent = 'Explain all regions'; b.disabled = false; }
    }
}

// Make a dynamically-created sibling button visually match the detect button.
function _anomalyMirrorBtnStyle(newBtn, refBtn) {
    if (refBtn.className) newBtn.className = refBtn.className;
    else newBtn.style.cssText = refBtn.style.cssText || 'font:inherit;font-size:inherit;padding:4px 10px;cursor:pointer;';
}

// Wire the button on module load. Use a one-time DOM-ready hook; the button
// lives in tcp-flow-analysis.html and exists by the time init() runs.
function _anomalyWireButton() {
    const btn = document.getElementById('detectAnomaliesBtn');
    if (!btn) return;
    if (btn.__anomalyWired) return;
    btn.__anomalyWired = true;
    btn.addEventListener('click', _anomalyRun);

    // ── TASK 6: "Download results" button ─────────────────────────────────
    // Guard against double-wiring (e.g. chart re-init).
    if (document.getElementById('downloadDetectorResultsBtn')) return;
    const dl = document.createElement('button');
    dl.id = 'downloadDetectorResultsBtn';
    dl.textContent = 'Download results';
    // Mirror the detect button's className; fall back to matching its computed style.
    _anomalyMirrorBtnStyle(dl, btn);
    btn.insertAdjacentElement('afterend', dl);
    dl.addEventListener('click', () => { _anomalyDownloadResults(); });

    // ── "Regions (N)" list popup button ──────────────────────────────────
    if (!document.getElementById('regionsListBtn')) {
        const rb = document.createElement('button');
        rb.id = 'regionsListBtn';
        rb.textContent = 'Regions (0)';
        _anomalyMirrorBtnStyle(rb, btn);
        dl.insertAdjacentElement('afterend', rb);
        rb.addEventListener('click', _anomalyToggleRegionsList);
    }

    // ── FSA "Link results file" button ────────────────────────────────────
    // Guard against double-wiring and feature-detect FSA availability.
    if (document.getElementById('linkResultsFileBtn')) return;
    if (!window.showSaveFilePicker) return;  // FSA unsupported in this browser

    const lb = document.createElement('button');
    lb.id = 'linkResultsFileBtn';
    lb.textContent = 'Link results file';
    _anomalyMirrorBtnStyle(lb, btn);
    dl.insertAdjacentElement('afterend', lb);

    lb.addEventListener('click', async () => {
        try {
            let handle = await _anomalyIdbGetHandle();
            if (handle) {
                // Already linked — just re-grant permission (gesture path: allowPrompt=true)
                const ok = await _anomalyVerifyPermission(handle, true, true);
                if (!ok) { _anomalySetStatus('Could not get permission for linked file', true); return; }
                _anomalyFileHandle = handle;
                // Pull any newer data from the file, then flush current state
                try { await _anomalyRestoreFromLinkedFile(); } catch (e) {}
                await _anomalyWriteToLinkedFile();
            } else {
                // First time — open save picker
                handle = await window.showSaveFilePicker({
                    suggestedName: 'detector-results.json',
                    types: [{ description: 'JSON', accept: { 'application/json': ['.json'] } }]
                });
                await _anomalyIdbSetHandle(handle);
                _anomalyFileHandle = handle;
                await _anomalyVerifyPermission(handle, true, true);
                await _anomalyWriteToLinkedFile();
            }

            lb.textContent = 'Auto-save linked ✓';
            setTimeout(() => {
                const b = document.getElementById('linkResultsFileBtn');
                if (b) b.textContent = 'Re-link results file';
            }, 2000);
            _anomalySetStatus('Auto-save to detector-results.json enabled', false);
        } catch (e) {
            if (e && e.name === 'AbortError') return;  // user cancelled picker
            console.warn('[Anomaly] link-file error:', e);
            _anomalySetStatus('Could not link results file', true);
        }
    });

    // Async label update: if a handle is stored but permission isn't yet granted,
    // show 'Reconnect results file' so the user knows one click restores auto-save.
    (async () => {
        try {
            const h = await _anomalyIdbGetHandle();
            if (!h) return;
            const status = await h.queryPermission({ mode: 'readwrite' });
            if (status !== 'granted') {
                const b = document.getElementById('linkResultsFileBtn');
                if (b) b.textContent = 'Reconnect results file';
            }
        } catch (e) {}
    })();

    // ── "Explain all regions" button ─────────────────────────────────────────
    if (document.getElementById('explainAllRegionsBtn')) return;
    const eab = document.createElement('button');
    eab.id = 'explainAllRegionsBtn';
    eab.textContent = 'Explain all regions';
    _anomalyMirrorBtnStyle(eab, btn);
    // Place after the link button if it exists, else after the download button.
    const refBtn = document.getElementById('linkResultsFileBtn') || document.getElementById('downloadDetectorResultsBtn');
    if (refBtn) {
        refBtn.insertAdjacentElement('afterend', eab);
    } else {
        btn.insertAdjacentElement('afterend', eab);
    }
    eab.addEventListener('click', () => {
        if (_anomalyExplainAllBusy) {
            if (_anomalyExplainAllAbort) _anomalyExplainAllAbort.abort();
            eab.textContent = 'Explain all regions';
        } else {
            _anomalyExplainAllRegions();
        }
    });
}

// ── Ordering-cache persistence helpers ────────────────────────────────────
// Mirrors the anomaly-results persistence pattern but for IP row orders.
// Only the FULL/DEFAULT (unfiltered) order is cached; any active filter
// (hidden IPs, hidden close-types, hidden invalid-reasons, unchecked
// checkboxes) causes the cache to be bypassed entirely.

function _orderingIsFullDefault() {
    if (_hiddenIPs && _hiddenIPs.size > 0) return false;
    if (typeof hiddenCloseTypes !== 'undefined' && hiddenCloseTypes && hiddenCloseTypes.size > 0) return false;
    if (typeof hiddenInvalidReasons !== 'undefined' && hiddenInvalidReasons && hiddenInvalidReasons.size > 0) return false;
    const boxes = document.querySelectorAll('#ipCheckboxes input[type="checkbox"]');
    if (boxes.length === 0) return true; // UI not wired yet — treat as full
    let checkedCount = 0;
    for (const cb of boxes) { if (cb.checked) checkedCount++; }
    return checkedCount === boxes.length;
}

async function _orderingIdbGetHandle() {
    try {
        const db = await _anomalyIdbOpen();
        return new Promise((resolve) => {
            try {
                const tx  = db.transaction('handles', 'readonly');
                const req = tx.objectStore('handles').get('ordering-cache');
                req.onsuccess = (ev) => resolve(ev.target.result || null);
                req.onerror   = ()   => resolve(null);
            } catch (e) { resolve(null); }
        });
    } catch (e) { return null; }
}

async function _orderingIdbSetHandle(handle) {
    try {
        const db = await _anomalyIdbOpen();
        return new Promise((resolve) => {
            try {
                const tx  = db.transaction('handles', 'readwrite');
                const req = tx.objectStore('handles').put(handle, 'ordering-cache');
                req.onsuccess = () => resolve(true);
                req.onerror   = () => resolve(false);
            } catch (e) { resolve(false); }
        });
    } catch (e) { return false; }
}

function _orderingResetIfDatasetChanged() {
    if (_anomalyDatasetId() !== _orderingDiskLoadedForId) {
        _orderingFullOrders = { ai_live: null, fiedler: null, region_cluster: null, region_cluster_sig: null };
        _orderingDiskLoadedForId = null;
    }
}

async function _orderingEnsureLoaded() {
    _orderingResetIfDatasetChanged();
    const id = _anomalyDatasetId();
    if (!id) return;
    if (_orderingDiskLoadedForId === id) return; // already loaded for this dataset

    // Try sources in order; take first that yields a valid entry for this id.
    let entry = null;

    // (a) Linked FSA file
    if (!entry) {
        try {
            const h = _orderingFileHandle || await _orderingIdbGetHandle();
            if (h && (await _anomalyVerifyPermission(h, false, false))) {
                _orderingFileHandle = h;
                const file = await h.getFile();
                const text = await file.text();
                const j = text ? JSON.parse(text) : null;
                if (j && j.datasets && j.datasets[id]) entry = j.datasets[id];
            }
        } catch (e) { /* no linked file or unreadable */ }
    }

    // (b) Static fetch
    if (!entry) {
        try {
            const resp = await fetch(_ORDERING_CACHE_FILE, { cache: 'no-store' });
            if (resp.ok) {
                const j = await resp.json();
                if (j && j.datasets && j.datasets[id]) entry = j.datasets[id];
            }
        } catch (e) { /* file not present or invalid JSON */ }
    }

    // (c) localStorage
    if (!entry) {
        try {
            const raw = localStorage.getItem('tcp-ordering-cache:v1:' + id);
            if (raw) {
                const j = JSON.parse(raw);
                // localStorage stores the entry blob directly (no outer container)
                if (j && j.datasetId === id) entry = j;
            }
        } catch (e) { /* ignore */ }
    }

    // Apply whatever we found (partial is fine — one method may be cached while the other isn't)
    if (entry && entry.orders) {
        if (Array.isArray(entry.orders.ai_live) && entry.orders.ai_live.length > 0) {
            _orderingFullOrders.ai_live = entry.orders.ai_live;
        }
        if (Array.isArray(entry.orders.fiedler) && entry.orders.fiedler.length > 0) {
            _orderingFullOrders.fiedler = entry.orders.fiedler;
        }
        if (Array.isArray(entry.orders.region_cluster) && entry.orders.region_cluster.length > 0) {
            _orderingFullOrders.region_cluster = entry.orders.region_cluster;
            _orderingFullOrders.region_cluster_sig = entry.regionClusterSig || null;
        }
    }

    // Mark loaded for this dataset regardless (don't refetch every call even if empty)
    _orderingDiskLoadedForId = id;
}

function _orderingBuildEntry() {
    return {
        datasetId: _anomalyDatasetId(),
        savedAt: Date.now(),
        orders: {
            ai_live: _orderingFullOrders.ai_live || null,
            fiedler: _orderingFullOrders.fiedler || null,
            region_cluster: _orderingFullOrders.region_cluster || null
        },
        regionClusterSig: _orderingFullOrders.region_cluster_sig || null
    };
}

function _orderingPersistSave() {
    const id = _anomalyDatasetId();
    if (!id) return;
    try {
        localStorage.setItem('tcp-ordering-cache:v1:' + id, JSON.stringify(_orderingBuildEntry()));
    } catch (e) {
        console.warn('[Ordering] localStorage persist failed:', e);
    }
}

async function _orderingWriteToLinkedFile() {
    const handle = _orderingFileHandle || await _orderingIdbGetHandle();
    if (!handle) return false;
    _orderingFileHandle = handle;

    if (!_anomalyDatasetId()) return false;
    if (_orderingFullOrders.ai_live === null && _orderingFullOrders.fiedler === null && _orderingFullOrders.region_cluster === null) return false;

    if (!(await _anomalyVerifyPermission(handle, true, false))) return false;

    if (_orderingFileWriteInFlight) { _orderingFileWriteQueued = true; return false; }

    _orderingFileWriteInFlight = true;
    try {
        let container = { version: 1, format: 'tcp-ordering-cache', datasets: {} };
        try {
            const file = await handle.getFile();
            const text = await file.text();
            if (text) {
                const j = JSON.parse(text);
                if (j && j.datasets && typeof j.datasets === 'object') container = j;
            }
        } catch (e) { /* empty or corrupt — start fresh */ }

        container.datasets[_anomalyDatasetId()] = _orderingBuildEntry();

        const w = await handle.createWritable();
        await w.write(JSON.stringify(container, null, 2));
        await w.close();
        return true;
    } catch (e) {
        console.warn('[Ordering] linked-file write failed:', e);
        return false;
    } finally {
        _orderingFileWriteInFlight = false;
        if (_orderingFileWriteQueued) {
            _orderingFileWriteQueued = false;
            _orderingWriteToLinkedFile();
        }
    }
}

async function _orderingWireButton() {
    // Guard against double-wire (e.g. chart re-init)
    if (document.getElementById('linkOrderingFileBtn')) return;
    // Feature-detect FSA
    if (!window.showSaveFilePicker) return;

    const sel = document.getElementById('ipRowOrder');
    if (!sel) return;

    const btn = document.createElement('button');
    btn.id = 'linkOrderingFileBtn';
    btn.textContent = 'Link orderings file';
    btn.style.cssText = 'font-size:11px;margin-bottom:6px;padding:3px 5px;cursor:pointer;';
    sel.insertAdjacentElement('afterend', btn);

    btn.addEventListener('click', async () => {
        try {
            let handle = await _orderingIdbGetHandle();
            if (handle) {
                // Already linked — re-grant permission in this user gesture
                const ok = await _anomalyVerifyPermission(handle, true, true);
                if (!ok) { console.warn('[Ordering] permission denied for linked orderings file'); return; }
                _orderingFileHandle = handle;
                await _orderingEnsureLoaded();
                await _orderingWriteToLinkedFile();
            } else {
                handle = await window.showSaveFilePicker({
                    suggestedName: 'ordering-cache.json',
                    types: [{ description: 'JSON', accept: { 'application/json': ['.json'] } }]
                });
                await _orderingIdbSetHandle(handle);
                _orderingFileHandle = handle;
                await _anomalyVerifyPermission(handle, true, true);
                await _orderingWriteToLinkedFile();
            }

            btn.textContent = 'Orderings linked ✓';
            setTimeout(() => {
                const b = document.getElementById('linkOrderingFileBtn');
                if (b) b.textContent = 'Re-link orderings file';
            }, 2000);
        } catch (e) {
            if (e && e.name === 'AbortError') return; // user cancelled picker
            console.warn('[Ordering] link-file error:', e);
        }
    });

    // Async label update: show 'Reconnect' if a handle exists but permission isn't granted
    (async () => {
        try {
            const h = await _orderingIdbGetHandle();
            if (!h) return;
            const status = await h.queryPermission({ mode: 'readwrite' });
            if (status !== 'granted') {
                const b = document.getElementById('linkOrderingFileBtn');
                if (b) b.textContent = 'Reconnect orderings file';
            }
        } catch (e) {}
    })();
}

// ============================================================================
// FORCE-NETWORK ROLE GROUPING — adds 'role' as an outermost grouping level
// when a role map is available for the region (parsed from the Explain
// response's ```roles fenced block). The Network tab consults _roleMapCache;
// if a map exists, it filters 'noise' IPs out and patches the
// ForceNetworkLayout instance via _denoisePatchLayoutForRoles. The role-map
// production lives in the Explain feature (single API call → prose + roles).
// ============================================================================

const _DENOISE_ROLES = new Set(['scanner', 'attacker', 'c2', 'victim', 'infrastructure', 'noise']);

// Visual palette for role super-nodes shown in the force-network. Reserved
// for a future legend; not currently consumed by the layout itself.
const _ROLE_COLORS = {
    scanner:        '#f59e0b',
    attacker:       '#dc2626',
    c2:             '#7c3aed',
    victim:         '#0891b2',
    infrastructure: '#6b7280',
    noise:          '#94a3b8'
};

// Reconstructed level defs for ForceNetworkLayout._levels patching.
// force_network.js's LEVEL_DEFS map is module-private; rather than modify
// shared code (project rule: tcp-flow-analysis.js stays isolated), we
// reconstruct the subnet24/subnet16 defs locally and add a 'role' def on top.
// SHAPE must match force_network.js exactly: { name, suffix, keyFn }.
const _DENOISE_SUBNET24_DEF = {
    name: 'subnet24', suffix: '.0/24',
    keyFn: (ip) => {
        const p = ip.split('.');
        return p.length >= 3 ? `${p[0]}.${p[1]}.${p[2]}` : ip;
    }
};
const _DENOISE_SUBNET16_DEF = {
    name: 'subnet16', suffix: '.0.0/16',
    keyFn: (ip) => {
        const p = ip.split('.');
        return p.length >= 2 ? `${p[0]}.${p[1]}` : ip;
    }
};
function _denoiseMakeRoleLevelDef(roleMap, gtSet) {
    return {
        name: 'role',
        suffix: '',
        // AI-named IPs cluster by their AI role (scanner, attacker, victim, ...).
        // GT-cited IPs that AI didn't name cluster together under 'gt' so they
        // form a single visible bucket rather than scattering as solos.
        keyFn: (ip) => roleMap.get(ip) || (gtSet && gtSet.has(ip) ? 'gt' : null)
    };
}

// Collect IPs that appear as source or destination in any ground-truth event
// overlapping this region (same overlap test the Explain payload uses). The
// regionIpSet is the brush's IP set — only GT events touching at least one
// brushed IP are considered "in the region", so unrelated GT events elsewhere
// in the dataset do not pollute the AI-vs-GT comparison.
function _denoiseComputeRegionGtIps(regionIpSet, tMin, tMax) {
    const groundTruth = (state.flows && Array.isArray(state.flows.groundTruth))
        ? state.flows.groundTruth : [];
    const gtIps = new Set();
    for (let i = 0; i < groundTruth.length; i++) {
        const evt = groundTruth[i];
        if (!evt) continue;
        const evStart = evt.startTimeMicroseconds;
        const evStop = evt.stopTimeMicroseconds;
        if (typeof evStart !== 'number' || typeof evStop !== 'number') continue;
        if (evStop < tMin || evStart > tMax) continue;
        if (evt.source) gtIps.add(evt.source);
        if (evt.destination) gtIps.add(evt.destination);
    }
    return gtIps;
}

// Patch a freshly-constructed ForceNetworkLayout instance to add a 'role'
// grouping level OUTSIDE the existing /24,/16. Must be called BEFORE setData.
// The noise-filter survivor logic in renderNetworkTab already removes IPs that
// are neither AI- nor GT-classified; this just adds role clustering to the
// surviving set. No outer AI/GT bucket — that was confusing because Claude
// omits noise IPs from its role block by design.
//
// _levels is innermost-first; appending makes a level outermost. _ipGroupKeys
// returns outermost-first.
function _denoisePatchLayoutForRoles(networkLayout, roleMap, gtSet) {
    const roleDef = _denoiseMakeRoleLevelDef(roleMap, gtSet);
    networkLayout._levels = [_DENOISE_SUBNET24_DEF, _DENOISE_SUBNET16_DEF, roleDef];
    networkLayout._minGroupSize = { ...networkLayout._minGroupSize, role: 1 };

    // Outermost-first: role → /16 → /24. Mirrors force_network.js's
    // _ipGroupKeys including the _excludesIp check so any future use of the
    // class's nestingExclusions option continues to work after patching.
    const orderedLevels = [roleDef, _DENOISE_SUBNET16_DEF, _DENOISE_SUBNET24_DEF];
    networkLayout._ipGroupKeys = function (ip) {
        const keys = [];
        for (const lvl of orderedLevels) {
            if (this._excludesIp(lvl.name, ip)) continue;
            const key = lvl.keyFn(ip);
            if (key == null) continue; // IP doesn't participate at this level
            keys.push({ level: lvl, key });
        }
        return keys;
    };
}

// Set the global loadFromPath reference now that the function is defined
window.loadFromPath = loadFromPath;

// Export functions for dynamic loading
export { init, cleanup, loadFromPath };

