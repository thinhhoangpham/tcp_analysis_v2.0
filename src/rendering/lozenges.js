// src/rendering/lozenges.js
// Lozenge (rounded rectangle) renderer for TCP flow visualization.
// Each lozenge represents a binned flow (or individual flow) spanning a time range,
// colored by close type. Mirrors the renderCircles() pattern in circles.js.

import { SUB_ROW_HEIGHT, SUB_ROW_GAP } from '../config/constants.js';

/**
 * Render lozenges for flow items into a layer.
 * @param {Object} layer - D3 selection (g element)
 * @param {Array} items - Flow data (binned or individual)
 * @param {Object} options - Rendering options
 * @returns {Array} processed array with computed positions
 */
export function renderLozenges(layer, items, options) {
    const {
        xScale,
        hScale,
        flowColorMap,
        LOZENGE_MIN_HEIGHT,
        LOZENGE_MAX_HEIGHT,
        LOZENGE_MIN_WIDTH,
        ROW_GAP,
        ipRowHeights,
        ipPairCounts,
        stableIpPairOrderByRow,
        subRowHeights,
        subRowOffsets,
        mainGroup,
        findIPPosition,
        ipPositions,
        createTooltipHTML,
        d3,
        CLOSE_TYPE_STACK_ORDER,
        separateFlags = false,
        onLozengeHighlight = null,
        onLozengeClearHighlight = null,
        transitionOpts = null,
        skipSvgRects = false
    } = options;

    if (!layer) return [];

    // Clear circles and other remnants from mode switching
    try { layer.selectAll('.direction-dot').remove(); } catch {}
    try { layer.selectAll('.bin-bar-segment').remove(); } catch {}
    try { layer.selectAll('.bin-stack').remove(); } catch {}
    try { layer.selectAll('.sub-row-ip-label').remove(); } catch {}

    const tooltip = d3.select('#tooltip');

    const inputItems = (items || []).filter(d => d);

    // --- Build stable IP pair order by row ---
    // Use the provided stable ordering when available (prevents row jumping on zoom),
    // falling back to computing from visible data.
    let ipPairOrderByRow = stableIpPairOrderByRow;
    if (!ipPairOrderByRow || ipPairOrderByRow.size === 0) {
        const ipPairsByRow = new Map();
        for (const d of inputItems) {
            const ip = d.initiator;
            if (!ip) continue;
            const yPos = ipPositions ? ipPositions.get(ip) : undefined;
            if (yPos === undefined) continue;
            const pairKey = d.pairKey;
            if (!ipPairsByRow.has(yPos)) ipPairsByRow.set(yPos, new Map());
            const pairMap = ipPairsByRow.get(yPos);
            const t = d.binStart || d.startTime || Infinity;
            if (!pairMap.has(pairKey) || t < pairMap.get(pairKey)) {
                pairMap.set(pairKey, t);
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

    // --- Process items: compute yPos, yPosWithOffset, ipPairKey ---
    const processed = inputItems.map((d, idx) => {
        const ip = d.src_ip || d.initiator;
        // Preserve '__collapsed__' sentinel from collapseSubRowsBins
        const pairKey = d.ipPairKey === '__collapsed__' ? '__collapsed__' : (d.pairKey || d.ipPairKey);

        const yPos = (ipPositions && ip) ? ipPositions.get(ip) : undefined;
        if (yPos === undefined) {
            return { ...d, yPos: 0, yPosWithOffset: 0, ipPairKey: pairKey, _idx: idx };
        }

        // Collapsed items sit at base yPos with no sub-row offset
        let yPosWithOffset;
        if (pairKey === '__collapsed__') {
            yPosWithOffset = yPos;
        } else {
            const pairInfo = ipPairOrderByRow.get(yPos) || { order: new Map(), count: 1 };
            const pairIndex = pairInfo.order.get(pairKey) ?? 0;
            const offsetKey = `${ip}|${pairKey}`;
            const offset = subRowOffsets && subRowOffsets.get(offsetKey);
            yPosWithOffset = yPos + (offset ?? pairIndex * (SUB_ROW_HEIGHT + SUB_ROW_GAP));
        }

        return {
            ...d,
            yPos,
            yPosWithOffset,
            ipPairKey: pairKey,
            _idx: idx
        };
    });

    // --- Close type separation (only when separateFlags is on) ---
    // Assign each close type its own sub-row lane within the IP row,
    // so different close types don't overlap vertically.
    if (separateFlags) {
        const closeTypeOrderMap = new Map(
            (CLOSE_TYPE_STACK_ORDER || []).map((ct, i) => [ct, i])
        );

        // Collect unique close types per IP row (keyed by yPos)
        const closeTypesPerRow = new Map();
        for (const d of processed) {
            const ct = d.closeType || 'unknown';
            if (!closeTypesPerRow.has(d.yPos)) closeTypesPerRow.set(d.yPos, new Set());
            closeTypesPerRow.get(d.yPos).add(ct);
        }

        // Build sorted close type list and lane offset for each row
        const laneOffsets = new Map(); // yPos → Map(closeType → offset)
        for (const [yPos, ctSet] of closeTypesPerRow) {
            const sorted = [...ctSet].sort((a, b) =>
                (closeTypeOrderMap.get(a) ?? 999) - (closeTypeOrderMap.get(b) ?? 999)
            );
            const ip = processed.find(d => d.yPos === yPos)?.src_ip || processed.find(d => d.yPos === yPos)?.initiator;
            const rowHeight = (ipRowHeights && ip && ipRowHeights.get(ip)) || (ROW_GAP || 30);
            const laneHeight = Math.min(SUB_ROW_HEIGHT, rowHeight / Math.max(1, sorted.length));
            const totalSpan = laneHeight * sorted.length;
            const offsets = new Map();
            for (let i = 0; i < sorted.length; i++) {
                offsets.set(sorted[i], (i - (sorted.length - 1) / 2) * laneHeight);
            }
            laneOffsets.set(yPos, offsets);
        }

        // Apply lane offsets to each item
        for (const d of processed) {
            const offsets = laneOffsets.get(d.yPos);
            if (offsets) {
                const ct = d.closeType || 'unknown';
                const laneOffset = offsets.get(ct) ?? 0;
                d.yPosWithOffset = d.yPosWithOffset + laneOffset;
            }
        }
    }

    // --- Color resolver ---
    const getColor = d => {
        if (!flowColorMap) return '#adb5bd';
        if (typeof flowColorMap === 'function') return flowColorMap(d.closeType, d.invalidReason);
        if (flowColorMap instanceof Map) return flowColorMap.get(d.closeType) || '#adb5bd';
        return (flowColorMap)[d.closeType] || '#adb5bd';
    };

    // --- Geometry helpers ---
    const getLozoX = d => xScale(d.binStart ?? d.startTime ?? d.binCenter ?? 0);
    const getLozoW = d => {
        const start = d.binStart ?? d.startTime ?? d.binCenter ?? 0;
        const end = d.binEnd ?? d.endTime ?? start;
        return Math.max(LOZENGE_MIN_WIDTH, xScale(end) - xScale(start));
    };
    const getLozoH = d => {
        return hScale ? Math.max(LOZENGE_MIN_HEIGHT, Math.min(LOZENGE_MAX_HEIGHT, hScale(d.count || 1)))
                      : LOZENGE_MIN_HEIGHT;
    };

    // --- Key function ---
    const getDataKey = d => {
        const t = Math.floor(d.binStart ?? d.startTime ?? 0);
        return `loz_${t}_${d.initiator}_${d.responder || ''}_${d.closeType}_${d._idx}`;
    };

    const transitionDuration = transitionOpts?.duration || 250;

    // --- Hover event handlers ---
    // Defined per render so closures capture current xScale and ipPositions.

    const handleMousemove = e => {
        tooltip.style('left', `${e.pageX + 40}px`).style('top', `${e.pageY - 40}px`);
    };

    const handleMouseout = e => {
        d3.select(e.currentTarget)
            .classed('highlighted', false)
            .style('stroke', null)
            .style('stroke-width', null);
        mainGroup.selectAll('.hover-line').remove();
        tooltip.style('display', 'none');
        if (onLozengeClearHighlight) onLozengeClearHighlight();
    };

    const handleMouseover = (event, d) => {
        const loz = d3.select(event.currentTarget);
        const color = getColor(d);

        loz.classed('highlighted', true)
            .style('stroke', d3.color(color) ? d3.color(color).darker(1).toString() : '#333')
            .style('stroke-width', '1.5px');

        // Draw straight line from lozenge center to responder's row
        mainGroup.selectAll('.hover-line').remove();

        if (d.responder && ipPositions) {
            const responderY = ipPositions.get(d.responder);
            const initiatorY = d.yPosWithOffset;

            if (responderY !== undefined && Math.abs(responderY - initiatorY) > 1) {
                const lozengeX = getLozoX(d) + getLozoW(d) / 2; // horizontal center
                mainGroup.append('line')
                    .attr('class', 'hover-line')
                    .attr('x1', lozengeX)
                    .attr('y1', initiatorY)
                    .attr('x2', lozengeX)
                    .attr('y2', responderY)
                    .attr('stroke', color)
                    .attr('stroke-width', 1.5)
                    .attr('stroke-opacity', 0.5)
                    .style('pointer-events', 'none');
            }
        }

        tooltip.style('display', 'block').html(createTooltipHTML(d));

        if (onLozengeHighlight) {
            onLozengeHighlight(d.initiator, new Set([d.responder].filter(Boolean)));
        }
    };

    // --- Z-order: sort by descending height so smaller lozenges render on top ---
    processed.sort((a, b) => getLozoH(b) - getLozoH(a));

    if (skipSvgRects) {
        // WebGL caller: remove any stale SVG rects from previous renders and skip the D3 join.
        // All other processing (positions, sub-row labels) still runs normally.
        layer.selectAll('.flow-lozenge').interrupt();
        layer.selectAll('.flow-lozenge').remove();
    } else {
        // Cancel any in-flight transitions from previous renders
        layer.selectAll('.flow-lozenge').interrupt();

        // Debug: check abortive items at render stage
        const abortiveRendered = processed.filter(d => (d.closeType || d.flagType) === 'abortive');
        if (abortiveRendered.length > 0) {
            const d0 = abortiveRendered[0];
            console.log(`[lozenges] xScale domain: ${xScale.domain()}, range: ${xScale.range()}`);
            console.log(`[lozenges] abortive[0]: binStart=${d0.binStart}, binEnd=${d0.binEnd}, xS=${xScale(d0.binStart)}, xE=${xScale(d0.binEnd)}, w=${getLozoW(d0)}`);
        }

        // --- D3 join ---
        layer.selectAll('.flow-lozenge')
            .data(processed, getDataKey)
            .join(
                enter => {
                    const sel = enter.append('rect')
                        .attr('class', 'flow-lozenge')
                        .attr('x', d => getLozoX(d))
                        .attr('y', d => d.yPosWithOffset - getLozoH(d) / 2)
                        .attr('width', getLozoW)
                        .attr('height', getLozoH)
                        .attr('rx', d => getLozoH(d) / 2)
                        .attr('ry', d => getLozoH(d) / 2)
                        .attr('fill', getColor)
                        .style('cursor', 'pointer')
                        .style('opacity', transitionOpts?.type === 'zoom-in' ? 0.3 : null)
                        .on('mouseover', handleMouseover)
                        .on('mousemove', handleMousemove)
                        .on('mouseout', handleMouseout);

                    if (transitionOpts?.type === 'zoom-in') {
                        sel.transition().duration(transitionDuration)
                            .style('opacity', 1);
                    }
                    return sel;
                },
                update => update
                    .attr('class', 'flow-lozenge')
                    .attr('x', d => getLozoX(d))
                    .attr('y', d => d.yPosWithOffset - getLozoH(d) / 2)
                    .attr('width', getLozoW)
                    .attr('height', getLozoH)
                    .attr('rx', d => getLozoH(d) / 2)
                    .attr('ry', d => getLozoH(d) / 2)
                    .attr('fill', getColor)
                    .style('cursor', 'pointer')
                    .on('mouseover', handleMouseover)
                    .on('mousemove', handleMousemove)
                    .on('mouseout', handleMouseout),
                exit => {
                    if (transitionOpts?.type === 'zoom-out') {
                        return exit.transition().duration(transitionDuration * 0.6)
                            .style('opacity', 0)
                            .remove();
                    }
                    if (transitionOpts?.type === 'zoom-in') {
                        return exit.transition().duration(transitionDuration * 0.5)
                            .style('opacity', 0)
                            .remove();
                    }
                    return exit.remove();
                }
            );
    }

    // --- Sub-row IP labels ---
    // Show the responder IP in front of the leftmost lozenge for multi-pair rows.
    // This mirrors the sub-row label logic in circles.js lines 430-482.
    layer.selectAll('.sub-row-ip-label').remove();

    if (ipPairOrderByRow) {
            // Find the leftmost lozenge per sub-row (keyed by "initiator|pairKey")
            const subRowInfo = new Map();
            for (const d of processed) {
                if (d.ipPairKey === '__collapsed__') continue;
                const key = `${d.initiator}|${d.ipPairKey}`;
                const x = getLozoX(d);
                if (!subRowInfo.has(key)) {
                    subRowInfo.set(key, {
                        initiator: d.initiator,
                        responder: d.responder,
                        ipPairKey: d.ipPairKey,
                        minX: x,
                        yPos: d.yPos,
                        yPosWithOffset: d.yPosWithOffset
                    });
                } else if (x < subRowInfo.get(key).minX) {
                    subRowInfo.get(key).minX = x;
                }
            }

            // Count visible sub-rows per initiator IP to identify multi-pair rows
            const subRowCountByIp = new Map();
            for (const info of subRowInfo.values()) {
                subRowCountByIp.set(info.initiator, (subRowCountByIp.get(info.initiator) || 0) + 1);
            }

            // Render labels only for expanded multi-pair rows
            for (const [, info] of subRowInfo) {
                if ((subRowCountByIp.get(info.initiator) || 0) <= 1) continue;

                // Use the stable sub-row center Y (not affected by stacking)
                const pairEntry = ipPairOrderByRow.get(info.yPos);
                const pairIndex = pairEntry ? (pairEntry.order.get(info.ipPairKey) ?? 0) : 0;
                const labelOffsetKey = `${info.initiator}|${info.ipPairKey}`;
                const labelOffset = subRowOffsets && subRowOffsets.get(labelOffsetKey);
                const labelY = info.yPos + (labelOffset ?? pairIndex * (SUB_ROW_HEIGHT + SUB_ROW_GAP));

                // Target IP label is the responder
                const targetIp = info.responder ||
                    (() => {
                        const parts = info.ipPairKey.split('<->');
                        return parts[0] === info.initiator ? parts[1] : parts[0];
                    })();

                layer.append('text')
                    .attr('class', 'sub-row-ip-label')
                    .attr('x', info.minX - 4)
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

    return processed;
}
