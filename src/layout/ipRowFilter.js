// src/layout/ipRowFilter.js
// Dynamic IP row filtering based on the visible time window.
//
// When the user zooms into a time range, only IP rows that have connections
// in that window are shown. Remaining rows compact together and are centred
// vertically in the container. Transitions are animated.

import { ROW_GAP, TOP_PAD } from '../config/constants.js';

/** Transition duration for IP row slide/fade animations (ms). */
const FILTER_TRANSITION_MS = 300;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Compute the set of IPs that have packets in the visible time window.
 * Both src_ip and dst_ip of each visible packet are considered active so
 * that target IPs (which may only appear as dst) are still shown.
 *
 * @param {Array} visiblePackets - Packets currently in the visible time range.
 * @returns {Set<string>} Set of IP addresses with visible connections.
 */
export function computeActiveIPs(visiblePackets) {
    const active = new Set();
    if (!visiblePackets) return active;
    for (const p of visiblePackets) {
        if (p.src_ip) active.add(p.src_ip);
        if (p.dst_ip) active.add(p.dst_ip);
    }
    return active;
}

/**
 * Compute compact Y positions for the active IPs, centred in the available
 * container height. Inactive IPs are not included; their rows will be hidden
 * via opacity by `animateIPRows`.
 *
 * @param {object}   opts
 * @param {Set<string>}        opts.activeIPs       - IPs to show.
 * @param {string[]}           opts.ipOrder         - Full ordered list of all IPs.
 * @param {Map<string,number>} opts.baseRowHeights   - ip → row height in px.
 * @param {number}             opts.containerHeight  - Usable height (px) excluding
 *                                                     margin.top + margin.bottom.
 * @param {number}             [opts.topPad]         - Top padding inside the chart.
 * @returns {{ positions: Map<string,number>,
 *             rowHeights: Map<string,number>,
 *             totalHeight: number,
 *             centerOffset: number,
 *             activeOrder: string[] }}
 */
export function computeCompactPositions({
    activeIPs,
    ipOrder,
    baseRowHeights,
    containerHeight,
    topPad = TOP_PAD
}) {
    // Preserve original vertical ordering, keep only active IPs.
    const activeOrder = ipOrder.filter(ip => activeIPs.has(ip));

    // Total pixel height of stacked active rows.
    let totalHeight = 0;
    for (const ip of activeOrder) {
        totalHeight += baseRowHeights.get(ip) || ROW_GAP;
    }

    // Centre the rows when they fit; otherwise stack from topPad.
    const usableHeight = Math.max(0, containerHeight - topPad);
    const centerOffset = totalHeight < usableHeight
        ? topPad + (usableHeight - totalHeight) / 2
        : topPad;

    // Assign cumulative Y positions to active IPs.
    const positions = new Map();
    const rowHeights = new Map();
    let currentY = centerOffset;
    for (const ip of activeOrder) {
        const h = baseRowHeights.get(ip) || ROW_GAP;
        positions.set(ip, currentY);
        rowHeights.set(ip, h);
        currentY += h;
    }

    return { positions, rowHeights, totalHeight, centerOffset, activeOrder };
}

/**
 * Mutate `state.layout.ipPositions` and `state.layout.ipPairOrderByRow`
 * in-place to reflect the compact (filtered + centred) layout.
 *
 * ipPairOrderByRow is keyed by Y position, so every time positions change
 * the Map must be rebuilt with the new Y keys.  This is done in-place to
 * preserve closures captured by `renderIPRowLabels`.
 *
 * @param {object} state - Global app state.
 * @param {{ positions: Map, rowHeights: Map, activeOrder: string[] }} compact
 *   Result from `computeCompactPositions`.
 */
export function applyFilteredPositions(state, compact) {
    const { positions, rowHeights, activeOrder } = compact;
    const { basePositions, basePairOrderByRow } = state.layout;

    if (!basePositions || !basePositions.size) return; // Not yet initialised.

    // Update ipPositions in-place: active IPs move to compact Y values.
    // Inactive IPs keep their base Y values (hidden via opacity, harmless
    // for yPos lookups because they won't appear in visible binnedPackets).
    for (const [ip, y] of positions) {
        state.layout.ipPositions.set(ip, y);
    }

    // Update ipRowHeights in-place for active IPs.
    for (const [ip, h] of rowHeights) {
        state.layout.ipRowHeights.set(ip, h);
    }

    // Rebuild ipPairOrderByRow in-place with the new Y keys.
    // Old entries are cleared; only active IPs are re-inserted using their
    // new compact Y as the key.
    state.layout.ipPairOrderByRow.clear();
    for (const ip of activeOrder) {
        const newY = positions.get(ip);
        if (newY === undefined) continue;
        const baseY = basePositions.get(ip);
        if (baseY === undefined) continue;
        const pairOrdering = basePairOrderByRow.get(baseY);
        if (pairOrdering) {
            state.layout.ipPairOrderByRow.set(newY, pairOrdering);
        }
    }
}

/**
 * Restore `state.layout.ipPositions`, `state.layout.ipRowHeights`, and
 * `state.layout.ipPairOrderByRow` back to their saved base values (all in-place).
 *
 * @param {object} state - Global app state.
 */
export function restoreBasePositionsToState(state) {
    const { basePositions, baseRowHeights, basePairOrderByRow } = state.layout;
    if (!basePositions || !basePositions.size) return;

    // Restore ipPositions in-place.
    state.layout.ipPositions.clear();
    for (const [ip, y] of basePositions) {
        state.layout.ipPositions.set(ip, y);
    }

    // Restore ipRowHeights in-place.
    state.layout.ipRowHeights.clear();
    for (const [ip, h] of baseRowHeights) {
        state.layout.ipRowHeights.set(ip, h);
    }

    // Restore ipPairOrderByRow in-place (deep copy of base).
    state.layout.ipPairOrderByRow.clear();
    for (const [yPos, { order, count }] of basePairOrderByRow) {
        state.layout.ipPairOrderByRow.set(yPos, { order: new Map(order), count });
    }
}

/**
 * Animate IP row DOM elements to reflect a new filtered/compact layout.
 *
 * Active rows slide to their new Y positions and become fully opaque.
 * Inactive rows fade out and become non-interactive.
 * Any ongoing transitions on the same elements are interrupted first.
 *
 * @param {object}             svg        - D3 selection for the chart's `<g>`.
 * @param {object}             d3         - D3 library reference.
 * @param {Set<string>}        activeIPs  - IPs currently visible.
 * @param {Map<string,number>} positions  - New Y positions for active IPs.
 * @param {Map<string,number>} rowHeights - Row heights for active IPs.
 * @param {number}             rowGap     - Fallback row height when not in map.
 * @param {number}             [duration] - Transition duration in ms.
 */
export function animateIPRows(
    svg, d3, activeIPs, positions, rowHeights, rowGap,
    duration = FILTER_TRANSITION_MS
) {
    // Interrupt stale transitions before starting new ones.
    svg.selectAll('.node').interrupt();
    svg.selectAll('.row-highlight').interrupt();

    // Animate each .node group (IP label + toggle + sub-row labels).
    svg.selectAll('.node').each(function(ip) {
        const sel = d3.select(this);
        const isActive = activeIPs.has(ip);

        if (!isActive) {
            sel.transition().duration(duration)
                .style('opacity', 0)
                .style('pointer-events', 'none');
        } else {
            const y = positions.get(ip);
            if (y === undefined) return;
            sel.transition().duration(duration)
                .attr('transform', `translate(0,${y})`)
                .style('opacity', 1)
                .style('pointer-events', null);
        }
    });

    // Animate .row-highlight rectangles.
    svg.selectAll('.row-highlight').each(function(ip) {
        const sel = d3.select(this);
        const isActive = activeIPs.has(ip);

        if (!isActive) {
            sel.transition().duration(duration).style('opacity', 0);
        } else {
            const y = positions.get(ip);
            const h = rowHeights.get(ip) || rowGap;
            if (y === undefined) return;
            // Row highlight rect is positioned at baseY − h/2.
            sel.transition().duration(duration)
                .attr('y', y - h / 2)
                .attr('height', h)
                .style('opacity', 0); // Keep row highlight hidden (hover-only).
        }
    });
}
