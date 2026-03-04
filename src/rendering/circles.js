// src/rendering/circles.js
// Circle rendering for packet visualization

import { getFlagType } from '../tcp/flags.js';
import { SUB_ROW_HEIGHT, SUB_ROW_GAP } from '../config/constants.js';

/**
 * Build an index of bins grouped by src_ip for fast parent/child lookup.
 * Used during resolution transitions to match fine bins to coarse bins.
 */
function buildBinIndex(data) {
    const byIp = new Map();
    for (const d of data) {
        if (!d.src_ip) continue;
        if (!byIp.has(d.src_ip)) byIp.set(d.src_ip, []);
        byIp.get(d.src_ip).push(d);
    }
    for (const bins of byIp.values()) {
        bins.sort((a, b) => (a.bin_start || a.binCenter || 0) - (b.bin_start || b.binCenter || 0));
    }
    return byIp;
}

/**
 * Binary search for the bin containing a given time for a specific IP.
 */
function findContainingBin(srcIp, time, index) {
    const bins = index.get(srcIp);
    if (!bins || bins.length === 0) return null;
    let lo = 0, hi = bins.length - 1;
    while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        const bin = bins[mid];
        const start = bin.bin_start != null ? bin.bin_start : bin.binCenter;
        const end = bin.bin_end != null ? bin.bin_end : start + 1;
        if (time >= start && time < end) return bin;
        if (time < start) hi = mid - 1;
        else lo = mid + 1;
    }
    return null;
}

// Canonical flag ordering for vertical separation (TCP lifecycle order)
const FLAG_PHASE_ORDER = [
    'SYN', 'SYN+ACK',
    'ACK', 'PSH', 'PSH+ACK',
    'FIN', 'FIN+ACK',
    'RST', 'RST+ACK',
    'OTHER'
];
const FLAG_ORDER_MAP = new Map(FLAG_PHASE_ORDER.map((f, i) => [f, i]));

/**
 * Create IP pair key from src and dst IPs (alphabetically ordered for consistency).
 * @param {string} srcIp - Source IP
 * @param {string} dstIp - Destination IP
 * @returns {string} Canonical IP pair key
 */
function makeIpPairKey(srcIp, dstIp) {
    if (!srcIp || !dstIp) return 'unknown';
    return srcIp < dstIp ? `${srcIp}<->${dstIp}` : `${dstIp}<->${srcIp}`;
}

/**
 * Render circles for binned items into a layer.
 * @param {Object} layer - D3 selection (g element)
 * @param {Array} binned - Binned packet data
 * @param {Object} options - Rendering options
 */
export function renderCircles(layer, binned, options) {
    const {
        xScale,
        rScale,
        flagColors,
        RADIUS_MIN,
        ROW_GAP,
        ipRowHeights,
        ipPairCounts,
        stableIpPairOrderByRow,
        subRowHeights,
        subRowOffsets,
        mainGroup,
        arcPathGenerator,
        findIPPosition,
        pairs,
        ipPositions,
        createTooltipHTML,
        FLAG_CURVATURE,
        d3,
        separateFlags = false,
        onCircleHighlight = null,
        onCircleClearHighlight = null,
        transitionOpts = null
    } = options;

    if (!layer) return;

    // Clear bar segments in this layer
    try { layer.selectAll('.bin-bar-segment').remove(); } catch {}
    try { layer.selectAll('.bin-stack').remove(); } catch {}

    const tooltip = d3.select('#tooltip');

    const items = (binned || []).filter(d => d);

    // Use stable pair ordering if provided (prevents row jumping on zoom),
    // otherwise fall back to computing from visible data
    let ipPairOrderByRow = stableIpPairOrderByRow;
    if (!ipPairOrderByRow || ipPairOrderByRow.size === 0) {
        // Fallback: compute from visible data
        const ipPairsByRow = new Map();
        for (const d of items) {
            const yPos = d.yPos !== undefined ? d.yPos : findIPPosition(d.src_ip, d.src_ip, d.dst_ip, pairs, ipPositions);
            const ipPairKey = makeIpPairKey(d.src_ip, d.dst_ip);
            if (!ipPairsByRow.has(yPos)) {
                ipPairsByRow.set(yPos, new Map());
            }
            const pairMap = ipPairsByRow.get(yPos);
            const timestamp = d.binCenter || d.binTimestamp || d.timestamp || Infinity;
            if (!pairMap.has(ipPairKey) || timestamp < pairMap.get(ipPairKey)) {
                pairMap.set(ipPairKey, timestamp);
            }
        }
        ipPairOrderByRow = new Map();
        for (const [yPos, pairTimestamps] of ipPairsByRow) {
            const orderedPairs = Array.from(pairTimestamps.entries())
                .sort((a, b) => a[1] - b[1])
                .map(([pair]) => pair);
            const orderMap = new Map();
            orderedPairs.forEach((pair, idx) => orderMap.set(pair, idx));
            ipPairOrderByRow.set(yPos, { order: orderMap, count: orderedPairs.length });
        }
    }

    // Helper function to calculate y position with offset for an IP pair on a given row
    const calculateYPosWithOffset = (ip, ipPairKey) => {
        const baseY = ipPositions.get(ip);
        if (baseY === undefined) return null;

        const pairInfo = ipPairOrderByRow.get(baseY) || { order: new Map(), count: 1 };
        const pairIndex = pairInfo.order.get(ipPairKey) || 0;

        // Use precomputed per-sub-row offset (variable heights) when available
        const offsetKey = `${ip}|${ipPairKey}`;
        const offset = subRowOffsets && subRowOffsets.get(offsetKey);
        return baseY + (offset ?? pairIndex * (SUB_ROW_HEIGHT + SUB_ROW_GAP));
    };

    // Ensure each item has yPos and calculate offset
    const processed = items.map((d, idx) => {
        const yPos = d.yPos !== undefined ? d.yPos : findIPPosition(d.src_ip, d.src_ip, d.dst_ip, pairs, ipPositions);
        // Preserve '__collapsed__' sentinel from collapseSubRowsBins so highlighting works
        const ipPairKey = d.ipPairKey === '__collapsed__' ? '__collapsed__' : makeIpPairKey(d.src_ip, d.dst_ip);
        const pairInfo = ipPairOrderByRow.get(yPos) || { order: new Map(), count: 1 };
        const pairIndex = pairInfo.order.get(ipPairKey) || 0;

        // First pair (pairIndex 0) aligns with baseline (yPos) where label is
        // Subsequent pairs grow DOWNWARD from there
        // Use precomputed per-sub-row offset (variable heights) when available
        const offsetKey = `${d.src_ip}|${ipPairKey}`;
        const offset = subRowOffsets && subRowOffsets.get(offsetKey);
        const pairCenterY = yPos + (offset ?? pairIndex * (SUB_ROW_HEIGHT + SUB_ROW_GAP));

        return {
            ...d,
            yPos,
            yPosWithOffset: pairCenterY,
            ipPairKey,
            ipPairs: d.ipPairs || [{ src_ip: d.src_ip, dst_ip: d.dst_ip, count: d.count || 1 }],
            _idx: idx
        };
    });

    // --- Flag separation: spread co-located flag circles vertically ---
    if (separateFlags) {
        // Group by (rounded binCenter, yPosWithOffset) to find overlapping circles
        const colocated = new Map();
        for (const d of processed) {
            const tKey = Math.floor(d.binned && Number.isFinite(d.binCenter) ? d.binCenter : d.timestamp);
            const key = `${tKey}|${Math.round(d.yPosWithOffset)}`;
            if (!colocated.has(key)) colocated.set(key, []);
            colocated.get(key).push(d);
        }
        for (const group of colocated.values()) {
            if (group.length <= 1) continue;
            // Sort by TCP lifecycle phase order
            group.sort((a, b) => {
                const fa = a.flagType || a.flag_type || getFlagType(a);
                const fb = b.flagType || b.flag_type || getFlagType(b);
                return (FLAG_ORDER_MAP.get(fa) ?? 99) - (FLAG_ORDER_MAP.get(fb) ?? 99);
            });
            const n = group.length;
            const center = group[0].yPosWithOffset;

            // Sequential packing: place circles touching each other (no overlap)
            // Each circle's center is offset by the sum of its own radius and the
            // previous circle's radius, so the total span = sum of all diameters.
            const radii = group.map(d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN);
            const totalSpan = radii.reduce((sum, r) => sum + 2 * r, 0);

            // For collapsed rows, clamp the span to the available row height
            let effectiveSpan = totalSpan;
            if (group[0].ipPairKey === '__collapsed__') {
                const ip = group[0].src_ip;
                const rowHeight = (ipRowHeights && ipRowHeights.get(ip)) || (ROW_GAP || 30);
                effectiveSpan = Math.min(totalSpan, Math.max(20, rowHeight - 6));
            }

            if (effectiveSpan < totalSpan) {
                // Not enough space — fall back to even spacing within available range
                const step = effectiveSpan / n;
                for (let i = 0; i < n; i++) {
                    group[i].yPosWithOffset = center + (i - (n - 1) / 2) * step;
                }
            } else {
                // Sequential packing: position each circle after the previous one
                let cursor = -totalSpan / 2;
                for (let i = 0; i < n; i++) {
                    cursor += radii[i]; // move to center of this circle
                    group[i].yPosWithOffset = center + cursor;
                    cursor += radii[i]; // move past this circle's edge
                }
            }
        }
    }

    // Sort by radius descending so bigger circles render behind smaller ones
    processed.sort((a, b) => {
        const rA = a.binned && a.count > 1 ? rScale(a.count) : RADIUS_MIN;
        const rB = b.binned && b.count > 1 ? rScale(b.count) : RADIUS_MIN;
        return rB - rA;
    });

    // Key function
    const getDataKey = d => {
        if (d.binned) {
            const flagStr = d.flagType || d.flag_type || getFlagType(d);
            return `bin_${Math.floor(d.binCenter || d.timestamp)}_${Math.round(d.yPos)}_${flagStr}_${d._idx}`;
        }
        return `${d.src_ip}-${d.dst_ip}-${d.timestamp}-${d.src_port || 0}-${d.dst_port || 0}_${d._idx}`;
    };

    // Helper to get flag color
    const getFlagColor = d => {
        const flagStr = d.flagType || d.flag_type || getFlagType(d);
        return flagColors[flagStr] || flagColors.OTHER;
    };

    // Helper to compute final cx for a datum
    const getFinalCx = d => xScale(Math.floor(d.binned && Number.isFinite(d.binCenter) ? d.binCenter : d.timestamp));

    // Cancel any in-flight transitions from previous renders
    layer.selectAll('.direction-dot').interrupt();

    // Build animation maps if resolution is transitioning
    let enterStartCx = null;   // zoom-in: entering circles start at parent coarse bin cx
    let exitTargetIndex = null; // zoom-out: exiting circles converge to target coarse bin

    if (transitionOpts?.previousData?.length > 0) {
        if (transitionOpts.type === 'zoom-in') {
            const parentIndex = buildBinIndex(transitionOpts.previousData);
            enterStartCx = new Map();
            for (const fine of processed) {
                const time = fine.binCenter || fine.timestamp;
                const parent = findContainingBin(fine.src_ip, time, parentIndex);
                if (parent) {
                    enterStartCx.set(getDataKey(fine), xScale(Math.floor(parent.binCenter)));
                }
            }
            if (enterStartCx.size === 0) enterStartCx = null;
        } else if (transitionOpts.type === 'zoom-out') {
            exitTargetIndex = buildBinIndex(processed.map(d => ({
                src_ip: d.src_ip,
                bin_start: d.bin_start,
                bin_end: d.bin_end,
                binCenter: d.binCenter
            })));
        }
    }

    const transitionDuration = transitionOpts?.duration || 250;

    // --- Hover event handlers (defined per render so closures capture current xScale, ipPositions, etc.) ---
    const handleMousemove = e => {
        tooltip.style('left', `${e.pageX + 40}px`).style('top', `${e.pageY - 40}px`);
    };
    const handleMouseout = e => {
        const dot = d3.select(e.currentTarget);
        dot.classed('highlighted', false).style('stroke', null).style('stroke-width', null);
        const baseR = +dot.attr('data-orig-r') || RADIUS_MIN; dot.attr('r', baseR);
        mainGroup.selectAll('.hover-arc').remove(); tooltip.style('display', 'none');
        if (onCircleClearHighlight) onCircleClearHighlight();
    };
    const handleMouseover = (event, d) => {
        const dot = d3.select(event.currentTarget);
        dot.classed('highlighted', true).style('stroke', '#000').style('stroke-width', '2px');
        const baseR = +dot.attr('data-orig-r') || +dot.attr('r') || RADIUS_MIN;
        dot.attr('r', baseR);

        // S-curve hover: find the next circle in the same directional flow and draw an S-curve to it.
        // In binned state each circle represents packets in a time window; consecutive circles in the
        // same src→dst IP pair are connected by the same S-curve geometry used in drawFlowDetailArcs.
        mainGroup.selectAll('.hover-arc').remove();
        const color = getFlagColor(d);
        const pairKey = makeIpPairKey(d.src_ip, d.dst_ip);
        const arrowLen = 5, arrowHalfW = 3;

        // Synthesize dummy node: project forward from the hovered circle.
        // Use bin width if available (scales with resolution), otherwise a fixed minimum.
        const x1 = xScale(Math.floor(d.binned && Number.isFinite(d.binCenter) ? d.binCenter : d.timestamp));
        const y1 = d.yPosWithOffset;
        const yDst = calculateYPosWithOffset(d.dst_ip, pairKey);
        const binWidthPx = (d.bin_start != null && d.bin_end != null)
            ? Math.abs(xScale(d.bin_end) - xScale(d.bin_start))
            : 40;
        const xDummy = x1 + Math.max(20, binWidthPx);
        const midX = (x1 + xDummy) / 2;

        if (yDst != null && Math.abs(yDst - y1) > 1) {
            mainGroup.append('path').attr('class', 'hover-arc')
                .attr('d', `M${x1},${y1} C${midX},${y1} ${midX},${yDst} ${xDummy},${yDst}`)
                .attr('fill', 'none').attr('stroke', color)
                .attr('stroke-width', 2).attr('stroke-opacity', 0.8)
                .style('pointer-events', 'none');
            const a = Math.atan2(2 * (yDst - y1), xDummy - x1);
            const ca = Math.cos(a), sa = Math.sin(a);
            const mx = midX, my = (y1 + yDst) / 2;
            mainGroup.append('polygon').attr('class', 'hover-arc')
                .attr('points', `${mx+arrowLen*ca},${my+arrowLen*sa} ${mx-arrowLen*ca+arrowHalfW*sa},${my-arrowLen*sa-arrowHalfW*ca} ${mx-arrowLen*ca-arrowHalfW*sa},${my-arrowLen*sa+arrowHalfW*ca}`)
                .attr('fill', color).attr('fill-opacity', 0.8).style('pointer-events', 'none');
        }

        tooltip.style('display', 'block').html(createTooltipHTML(d));
        if (onCircleHighlight) {
            const dstIps = new Set((d.ipPairs || [{ dst_ip: d.dst_ip }]).map(p => p.dst_ip));
            onCircleHighlight(d.src_ip, dstIps);
        }
    };

    layer.selectAll('.direction-dot')
        .data(processed, getDataKey)
        .join(
            enter => {
                const sel = enter.append('circle')
                .attr('class', d => `direction-dot ${d.binned && d.count > 1 ? 'binned' : ''}`)
                .attr('r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('data-orig-r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('fill', getFlagColor)
                .attr('cx', d => {
                    // For zoom-in: start at parent coarse circle's position
                    if (enterStartCx) {
                        const startX = enterStartCx.get(getDataKey(d));
                        if (startX !== undefined) return startX;
                    }
                    return getFinalCx(d);
                })
                .attr('cy', d => d.yPosWithOffset)
                .style('cursor', 'pointer')
                .style('opacity', enterStartCx ? 0.3 : null)
                .on('mouseover', handleMouseover)
                .on('mousemove', handleMousemove)
                .on('mouseout', handleMouseout);

                // Animate entering circles from parent position (zoom-in)
                if (enterStartCx) {
                    sel.transition().duration(transitionDuration)
                        .attr('cx', getFinalCx)
                        .style('opacity', 1);
                }
                return sel;
            },
            update => update
                .attr('class', d => `direction-dot ${d.binned && d.count > 1 ? 'binned' : ''}`)
                .attr('r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('data-orig-r', d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN)
                .attr('fill', getFlagColor)
                .attr('cx', getFinalCx)
                .attr('cy', d => d.yPosWithOffset)
                .style('cursor', 'pointer')
                .on('mouseover', handleMouseover)
                .on('mousemove', handleMousemove)
                .on('mouseout', handleMouseout),
            exit => {
                // Zoom-out: converge exiting fine circles toward their coarse parent
                if (transitionOpts?.type === 'zoom-out' && exitTargetIndex) {
                    exit.each(function(d) {
                        const time = d.binCenter || d.timestamp;
                        const target = findContainingBin(d.src_ip, time, exitTargetIndex);
                        const node = d3.select(this);
                        if (target) {
                            node.transition().duration(transitionDuration)
                                .attr('cx', xScale(Math.floor(target.binCenter)))
                                .style('opacity', 0)
                                .remove();
                        } else {
                            node.transition().duration(transitionDuration * 0.6)
                                .style('opacity', 0)
                                .remove();
                        }
                    });
                    return exit;
                }
                // Zoom-in: quickly fade out old coarse circles
                if (transitionOpts?.type === 'zoom-in') {
                    return exit.transition().duration(transitionDuration * 0.5)
                        .style('opacity', 0).remove();
                }
                // No transition: instant removal
                return exit.remove();
            }
        );

    // --- Sub-row labels: show target IP in front of first circle of each expanded sub-row ---
    layer.selectAll('.sub-row-ip-label').remove();

    if (ipPairOrderByRow) {
        // Find the leftmost circle per sub-row (keyed by "src_ip|ipPairKey")
        const subRowInfo = new Map();
        for (const d of processed) {
            if (d.ipPairKey === '__collapsed__') continue;
            const key = `${d.src_ip}|${d.ipPairKey}`;
            const cx = getFinalCx(d);
            const r = d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN;
            if (!subRowInfo.has(key)) {
                subRowInfo.set(key, { src_ip: d.src_ip, ipPairKey: d.ipPairKey, minCx: cx, radius: r, yPos: d.yPos });
            } else if (cx < subRowInfo.get(key).minCx) {
                subRowInfo.get(key).minCx = cx;
                subRowInfo.get(key).radius = r;
            }
        }

        // Count visible sub-rows per source IP to identify multi-pair rows
        const subRowCountByIp = new Map();
        for (const info of subRowInfo.values()) {
            subRowCountByIp.set(info.src_ip, (subRowCountByIp.get(info.src_ip) || 0) + 1);
        }

        // Render labels only for expanded multi-pair rows
        for (const [, info] of subRowInfo) {
            if ((subRowCountByIp.get(info.src_ip) || 0) <= 1) continue;

            // Extract target IP from the canonical pair key
            const parts = info.ipPairKey.split('<->');
            const targetIp = parts[0] === info.src_ip ? parts[1] : parts[0];

            // Compute stable sub-row center Y (not affected by flag separation)
            const pairEntry = ipPairOrderByRow.get(info.yPos);
            const pairIndex = pairEntry ? (pairEntry.order.get(info.ipPairKey) || 0) : 0;
            const labelOffsetKey = `${info.src_ip}|${info.ipPairKey}`;
            const labelOffset = subRowOffsets && subRowOffsets.get(labelOffsetKey);
            const labelY = info.yPos + (labelOffset ?? pairIndex * (SUB_ROW_HEIGHT + SUB_ROW_GAP));

            layer.append('text')
                .attr('class', 'sub-row-ip-label')
                .attr('x', info.minCx - info.radius - 4)
                .attr('y', labelY)
                .attr('dy', '.35em')
                .attr('text-anchor', 'end')
                .text(targetIp)
                .style('font-size', '9px')
                .style('fill', '#888')
                .style('font-style', 'italic')
                .style('pointer-events', 'none');
        }
    }

    // Return processed data so callers can access final positions (with flag separation)
    return processed;
}
