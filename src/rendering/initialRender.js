// src/rendering/initialRender.js
// Initial render pipeline for TimeArcs visualization

/**
 * Prepare data for initial rendering.
 *
 * @param {Object} options - Configuration options
 * @param {Object} options.d3 - D3 library reference
 * @param {Array} options.packets - Raw packet data passed to visualize
 * @param {Function} options.xScale - X scale with current domain
 * @param {Object} options.state - Global state object
 * @param {Object} options.fetchResManager - Resolution manager with singleFileData
 * @param {Function} options.getResolutionForVisibleRange - Function to determine resolution
 * @param {Function} options.getVisiblePackets - Function to filter packets by scale
 * @param {Function} options.buildSelectedFlowKeySet - Function to build flow key set
 * @param {Function} options.makeConnectionKey - Function to create connection keys
 * @param {Function} options.findIPPosition - Function to get y position for IP
 * @param {Function} options.getFlagType - Function to classify packet flag type
 * @param {Map} options.flagCounts - Map of flag type -> count
 * @returns {Object} { binnedPackets, globalMaxBinCount, resolution }
 */
export function prepareInitialRenderData(options) {
    const {
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
    } = options;

    // Determine correct resolution based on visible time range
    const initialVisibleRangeUs = xScale.domain()[1] - xScale.domain()[0];
    const initialResolution = getResolutionForVisibleRange(initialVisibleRangeUs);

    // Get data from the correct resolution, filtered by selected IPs
    let resolutionData = fetchResManager?.singleFileData?.get(initialResolution);

    if (!resolutionData || resolutionData.length === 0) {
        // Fall back to passed packets (already filtered by selected IPs)
        resolutionData = packets;
    } else {
        // Filter by selected IPs (must have both src and dst in selected set)
        const selectedIPSet = fetchResManager?.selectedIPSet;
        if (selectedIPSet && selectedIPSet.size >= 2) {
            resolutionData = resolutionData.filter(d =>
                selectedIPSet.has(d.src_ip) && selectedIPSet.has(d.dst_ip)
            );
        }
    }

    // Get visible packets
    let initialVisiblePackets = getVisiblePackets(resolutionData, xScale);

    // Apply flow filtering if active
    if (state.ui.showTcpFlows && state.flows.selectedIds.size > 0 && state.flows.tcp.length > 0) {
        const selectedKeys = buildSelectedFlowKeySet();
        initialVisiblePackets = initialVisiblePackets.filter(packet => {
            if (!packet || !packet.src_ip || !packet.dst_ip) return false;
            const key = makeConnectionKey(
                packet.src_ip,
                packet.src_port || 0,
                packet.dst_ip,
                packet.dst_port || 0
            );
            return selectedKeys.has(key);
        });
    }

    // Add y positions to data (data is always pre-binned from multi-resolution system).
    // NOTE: explicit field assignment instead of `{...d}` spread. At 8M+ items the
    // spread-copy allocates a new object per item, doubles memory, and blows the heap.
    // Also DROP `originalPackets: [d]` — that line used to allocate a single-element
    // array per item (8M arrays, ~660 MB pure overhead) and nothing reads it on the
    // binned path anyway.
    const n = initialVisiblePackets.length;
    const binnedPackets = new Array(n);
    let globalMaxBinCount = 1;
    const pairs = state.layout.pairs;
    const ipPositions = state.layout.ipPositions;
    for (let i = 0; i < n; i++) {
        const d = initialVisiblePackets[i];
        const count = d.count || 1;
        if (count > globalMaxBinCount) globalMaxBinCount = count;
        binnedPackets[i] = {
            src_ip: d.src_ip,
            dst_ip: d.dst_ip,
            src_port: d.src_port,
            dst_port: d.dst_port,
            timestamp: d.timestamp,
            bin_start: d.bin_start,
            bin_end: d.bin_end,
            flag_type: d.flag_type,
            total_bytes: d.total_bytes,
            yPos: findIPPosition(d.src_ip, d.src_ip, d.dst_ip, pairs, ipPositions),
            binCenter: d.bin_start != null
                ? (d.bin_start + (d.bin_end - d.bin_start) / 2)
                : d.timestamp,
            flagType: d.flagType || d.flag_type || 'OTHER',
            binned: d.binned !== false,
            count
        };
    }

    // Sort by flag type (most common first) then timestamp
    // flagCounts can be either a Map or a plain object
    const getCount = (flag) => {
        if (flagCounts instanceof Map) {
            return flagCounts.get(flag) || 0;
        }
        return flagCounts[flag] || 0;
    };

    binnedPackets.sort((a, b) => {
        const flagA = a.flagType;
        const flagB = b.flagType;
        const countA = getCount(flagA);
        const countB = getCount(flagB);
        if (countA !== countB) return countB - countA;
        return a.timestamp - b.timestamp;
    });

    return {
        binnedPackets,
        globalMaxBinCount,
        resolution: initialResolution,
        visibleRangeUs: initialVisibleRangeUs
    };
}

/**
 * Prepare flow bin data for the lozenge renderer.
 * Parallel to prepareInitialRenderData but for flow view mode.
 *
 * @param {Object} options
 * @param {Array} options.flowItems - Items from AdaptiveOverviewLoader.getFlowBinsByPair()
 * @param {number} options.globalMaxCount - Max count across all items
 * @param {Function} options.findIPPosition - function(ip) => yPos
 * @param {Object} options.state - Global state object
 * @returns {Object} { binnedFlows, globalMaxCount }
 */
export function prepareFlowRenderData({ flowItems, globalMaxCount, findIPPosition, state }) {
    if (!flowItems || flowItems.length === 0) {
        return { binnedFlows: [], globalMaxCount: 0 };
    }

    const selectedIPSet = new Set();
    document.querySelectorAll('#ipCheckboxes input[type="checkbox"]:checked')
        .forEach(cb => selectedIPSet.add(cb.value));

    // Filter to only items where both IPs are selected and add yPos
    const binnedFlows = flowItems
        .filter(d => selectedIPSet.has(d.initiator) && selectedIPSet.has(d.responder))
        .map(d => ({
            ...d,
            yPos: findIPPosition(d.initiator)
        }));

    return { binnedFlows, globalMaxCount };
}

/**
 * Perform initial render to the full domain layer.
 *
 * @param {Object} options - Configuration options
 * @param {Object} options.d3 - D3 library reference
 * @param {Object} options.fullDomainLayer - D3 selection for full domain layer
 * @param {Object} options.dynamicLayer - D3 selection for dynamic layer
 * @param {Array} options.binnedPackets - Prepared and sorted binned packets
 * @param {number} options.globalMaxBinCount - Maximum bin count for radius scaling
 * @param {number} options.radiusMin - Minimum radius
 * @param {number} options.radiusMax - Maximum radius
 * @param {Function} options.renderMarksForLayer - Function to render marks
 */
export function performInitialRender(options) {
    const {
        d3,
        fullDomainLayer,
        dynamicLayer,
        binnedPackets,
        globalMaxBinCount,
        radiusMin,
        radiusMax,
        renderMarksForLayer
    } = options;

    // Create radius scale
    const rScale = d3.scaleSqrt()
        .domain([1, globalMaxBinCount])
        .range([radiusMin, radiusMax]);

    // Render marks to full domain layer
    renderMarksForLayer(fullDomainLayer, binnedPackets, rScale);

    // Show full domain layer, hide dynamic layer
    if (fullDomainLayer) fullDomainLayer.style('display', null);
    if (dynamicLayer) dynamicLayer.style('display', 'none');
}

/**
 * Create a radius scale based on global max bin count.
 *
 * @param {Object} d3 - D3 library reference
 * @param {number} globalMaxBinCount - Maximum bin count
 * @param {number} radiusMin - Minimum radius
 * @param {number} radiusMax - Maximum radius
 * @returns {Function} D3 sqrt scale for radius
 */
export function createRadiusScale(d3, globalMaxBinCount, radiusMin, radiusMax) {
    return d3.scaleSqrt()
        .domain([1, Math.max(1, globalMaxBinCount)])
        .range([radiusMin, radiusMax]);
}
