// src/rendering/circles-webgl-bridge.tcpflow.js
// tcp-flow-analysis-only bridge: clones the position-computation logic from
// src/rendering/circles.js, then hands the processed array to a WebGL
// renderer instead of doing a D3 join. Sub-row IP labels are still SVG.
//
// This file mirrors the preprocessing in circles.js so the two pipelines
// produce identical visual layouts. Only the actual circle rasterization
// is moved off SVG.

import { getFlagType } from '../tcp/flags.js';
import { SUB_ROW_HEIGHT, SUB_ROW_GAP } from '../config/constants.js';

const FLAG_PHASE_ORDER = [
    'SYN', 'SYN+ACK',
    'ACK', 'PSH', 'PSH+ACK',
    'FIN', 'FIN+ACK',
    'RST', 'RST+ACK',
    'OTHER'
];
const FLAG_ORDER_MAP = new Map(FLAG_PHASE_ORDER.map((f, i) => [f, i]));

function makeIpPairKey(srcIp, dstIp) {
    if (!srcIp || !dstIp) return 'unknown';
    return srcIp < dstIp ? `${srcIp}<->${dstIp}` : `${dstIp}<->${srcIp}`;
}

/**
 * Render packet circles via WebGL. The signature mirrors renderCircles() in
 * src/rendering/circles.js so callers can swap implementations.
 *
 * Returns the processed items array (same fields as circles.js: yPos,
 * yPosWithOffset, ipPairKey, _idx) so callers can reuse it for arc drawing,
 * search highlighting, etc.
 */
export function renderCirclesWebGL(layer, binned, options) {
    const {
        xScale,
        rScale,
        flagColors,
        RADIUS_MIN,
        ROW_GAP,
        ipRowHeights,
        subRowOffsets,
        ipPositions,
        findIPPosition,
        pairs,
        stableIpPairOrderByRow,
        separateFlags = false,
        d3,
        webglRenderer
    } = options;

    if (!webglRenderer) return [];

    const items = (binned || []).filter(d => d);

    // --- Resolve stable sub-row order (same as circles.js) ---
    let ipPairOrderByRow = stableIpPairOrderByRow;
    if (!ipPairOrderByRow || ipPairOrderByRow.size === 0) {
        const ipPairsByRow = new Map();
        for (const d of items) {
            const yPos = d.yPos !== undefined
                ? d.yPos
                : findIPPosition(d.src_ip, d.src_ip, d.dst_ip, pairs, ipPositions);
            const ipPairKey = makeIpPairKey(d.src_ip, d.dst_ip);
            if (!ipPairsByRow.has(yPos)) ipPairsByRow.set(yPos, new Map());
            const pairMap = ipPairsByRow.get(yPos);
            const ts = d.binCenter || d.binTimestamp || d.timestamp || Infinity;
            if (!pairMap.has(ipPairKey) || ts < pairMap.get(ipPairKey)) {
                pairMap.set(ipPairKey, ts);
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

    const processed = items;
    const emptyPairInfo = { order: new Map(), count: 1 };
    for (let i = 0; i < processed.length; i++) {
        const d = processed[i];
        const yPos = d.yPos !== undefined
            ? d.yPos
            : findIPPosition(d.src_ip, d.src_ip, d.dst_ip, pairs, ipPositions);
        const ipPairKey = d.ipPairKey === '__collapsed__'
            ? '__collapsed__'
            : makeIpPairKey(d.src_ip, d.dst_ip);
        const pairInfo = ipPairOrderByRow.get(yPos) || emptyPairInfo;
        const pairIndex = pairInfo.order.get(ipPairKey) || 0;
        const offsetKey = `${d.src_ip}|${ipPairKey}`;
        const offset = subRowOffsets && subRowOffsets.get(offsetKey);
        const pairCenterY = yPos + (offset ?? pairIndex * (SUB_ROW_HEIGHT + SUB_ROW_GAP));
        d.yPos = yPos;
        d.yPosWithOffset = pairCenterY;
        d.ipPairKey = ipPairKey;
        d._idx = i;
    }

    // --- Flag separation (mirrors circles.js) ---
    if (separateFlags) {
        const colocated = new Map();
        for (const d of processed) {
            const tKey = Math.floor(d.binned && Number.isFinite(d.binCenter) ? d.binCenter : d.timestamp);
            const key = `${tKey}|${Math.round(d.yPosWithOffset)}`;
            if (!colocated.has(key)) colocated.set(key, []);
            colocated.get(key).push(d);
        }
        for (const group of colocated.values()) {
            if (group.length <= 1) continue;
            group.sort((a, b) => {
                const fa = a.flagType || a.flag_type || getFlagType(a);
                const fb = b.flagType || b.flag_type || getFlagType(b);
                return (FLAG_ORDER_MAP.get(fa) ?? 99) - (FLAG_ORDER_MAP.get(fb) ?? 99);
            });
            const n = group.length;
            const center = group[0].yPosWithOffset;
            const radii = group.map(d => d.binned && d.count > 1 ? rScale(d.count) : RADIUS_MIN);
            const totalSpan = radii.reduce((sum, r) => sum + 2 * r, 0);
            let effectiveSpan = totalSpan;
            if (group[0].ipPairKey === '__collapsed__') {
                const ip = group[0].src_ip;
                const rowHeight = (ipRowHeights && ipRowHeights.get(ip)) || (ROW_GAP || 30);
                effectiveSpan = Math.min(totalSpan, Math.max(20, rowHeight - 6));
            }
            if (effectiveSpan < totalSpan) {
                const step = effectiveSpan / n;
                for (let i = 0; i < n; i++) {
                    group[i].yPosWithOffset = center + (i - (n - 1) / 2) * step;
                }
            } else {
                let cursor = -totalSpan / 2;
                for (let i = 0; i < n; i++) {
                    cursor += radii[i];
                    group[i].yPosWithOffset = center + cursor;
                    cursor += radii[i];
                }
            }
        }
    }

    // Sort big circles to the back so smaller ones overdraw them. WebGL has
    // no z-test in our setup; draw order = array order.
    processed.sort((a, b) => {
        const rA = a.binned && a.count > 1 ? rScale(a.count) : RADIUS_MIN;
        const rB = b.binned && b.count > 1 ? rScale(b.count) : RADIUS_MIN;
        return rB - rA;
    });
    for (let i = 0; i < processed.length; i++) processed[i]._idx = i;

    // Hand off to WebGL renderer.
    webglRenderer.setData(processed, {
        rScale,
        RADIUS_MIN,
        flagColors,
        getFlagType
    });

    // --- Sub-row IP labels (kept as SVG text — small count, needs text layout) ---
    if (layer) {
        layer.selectAll('.sub-row-ip-label').remove();
        if (ipPairOrderByRow) {
            const subRowInfo = new Map();
            const getFinalCx = d => xScale(Math.floor(d.binned && Number.isFinite(d.binCenter) ? d.binCenter : d.timestamp));
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
            const subRowCountByIp = new Map();
            for (const info of subRowInfo.values()) {
                subRowCountByIp.set(info.src_ip, (subRowCountByIp.get(info.src_ip) || 0) + 1);
            }
            for (const [, info] of subRowInfo) {
                if ((subRowCountByIp.get(info.src_ip) || 0) <= 1) continue;
                const parts = info.ipPairKey.split('<->');
                const targetIp = parts[0] === info.src_ip ? parts[1] : parts[0];
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
    }

    return processed;
}
