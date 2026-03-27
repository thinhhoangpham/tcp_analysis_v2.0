// ─── Flow Arc Abstractor ─────────────────────────────────────────────────────
//
// Transforms _linksWithNodes (flow-mode arc bins) into Level 4 phase sequences
// per IP pair. Each phase represents a consecutive run of the same close_type.
//
// Pipeline:
//   1. Group links by canonical pair key
//   2. Sort each pair's bins by minute
//   3. Collapse consecutive same-closeType bins into phases
//   4. Apply noise tolerance (absorb minority bins)
//   5. Assign volumeLabel using pre-computed percentiles

import { CLOSE_TYPE_TOKENS } from './flow-arc-presets.js';

// ─── Helpers ─────────────────────────────────────────────────────────────────

function canonicalPairKey(src, tgt) {
    const a = src < tgt ? src : tgt;
    const b = src < tgt ? tgt : src;
    return a + '<->' + b;
}

function volumeLabel(count, percentiles) {
    if (!percentiles) return 'medium';
    if (count >= percentiles.p75) return 'high';
    if (count >= percentiles.p50) return 'medium';
    return 'low';
}

// ─── Percentile computation ──────────────────────────────────────────────────

/**
 * Compute count percentiles across all flow-mode links.
 * @param {Array} linksWithNodes - Arc link objects with { count }
 * @returns {{ p25: number, p50: number, p75: number, p90: number }}
 */
export function computeVolumePercentiles(linksWithNodes) {
    if (!linksWithNodes || linksWithNodes.length === 0) {
        return { p25: 0, p50: 0, p75: 0, p90: 0 };
    }
    const counts = linksWithNodes.map(l => l.count).sort((a, b) => a - b);
    const pct = (p) => {
        const idx = Math.floor(p * counts.length);
        return counts[Math.min(idx, counts.length - 1)];
    };
    return { p25: pct(0.25), p50: pct(0.5), p75: pct(0.75), p90: pct(0.9) };
}

// ─── Phase collapsing with noise tolerance ───────────────────────────────────

/**
 * Collapse sorted bins into phases. A phase is a consecutive run of the same
 * close_type. Noise tolerance absorbs minority bins (1-2 bins with low count
 * surrounded by a different dominant type).
 *
 * @param {Array} bins - Sorted array of { closeType, minute, count }
 * @param {number} noiseRatio - Threshold for noise absorption (default 0.1)
 * @returns {Array} phases - [{ closeType, minuteStart, minuteEnd, totalCount, binCount, counts[] }]
 */
function collapsePhases(bins, noiseRatio = 0.1) {
    if (bins.length === 0) return [];

    // Pass 1: group consecutive same-type bins into raw phases
    let phases = [];
    let current = {
        closeType: bins[0].closeType,
        minuteStart: bins[0].minute,
        minuteEnd: bins[0].minute,
        totalCount: bins[0].count,
        binCount: 1,
        counts: [bins[0].count],
        portCounts: new Map(bins[0].dst_port ? [[bins[0].dst_port, bins[0].count]] : [])
    };

    for (let i = 1; i < bins.length; i++) {
        const bin = bins[i];
        if (bin.closeType === current.closeType) {
            current.minuteEnd = bin.minute;
            current.totalCount += bin.count;
            current.binCount++;
            current.counts.push(bin.count);
            if (bin.dst_port) current.portCounts.set(bin.dst_port, (current.portCounts.get(bin.dst_port) || 0) + bin.count);
        } else {
            phases.push(current);
            current = {
                closeType: bin.closeType,
                minuteStart: bin.minute,
                minuteEnd: bin.minute,
                totalCount: bin.count,
                binCount: 1,
                counts: [bin.count],
                portCounts: new Map(bin.dst_port ? [[bin.dst_port, bin.count]] : [])
            };
        }
    }
    phases.push(current);

    if (phases.length <= 2) return phases;

    // Pass 2: absorb noise phases (1-2 bins with low count relative to neighbors)
    // Run up to 3 passes to handle cascading absorptions
    for (let pass = 0; pass < 3; pass++) {
        let absorbed = false;
        const newPhases = [];

        for (let i = 0; i < phases.length; i++) {
            const phase = phases[i];

            // Only consider short phases (1-2 bins) as noise candidates
            if (phase.binCount <= 2 && i > 0 && i < phases.length - 1) {
                const prevAvg = phases[i - 1].totalCount / phases[i - 1].binCount;
                const nextAvg = phases[i + 1].totalCount / phases[i + 1].binCount;
                const neighborAvg = (prevAvg + nextAvg) / 2;
                const phaseAvg = phase.totalCount / phase.binCount;

                if (phaseAvg < noiseRatio * neighborAvg) {
                    // Absorb into preceding phase
                    const prev = newPhases[newPhases.length - 1];
                    prev.minuteEnd = phase.minuteEnd;
                    prev.totalCount += phase.totalCount;
                    prev.binCount += phase.binCount;
                    prev.counts.push(...phase.counts);
                    if (phase.portCounts) for (const [p, c] of phase.portCounts) prev.portCounts.set(p, (prev.portCounts.get(p) || 0) + c);
                    absorbed = true;
                    continue;
                }
            }
            newPhases.push(phase);
        }

        // Pass 3: merge adjacent same-type phases (from absorptions)
        phases = [];
        for (const p of newPhases) {
            const last = phases[phases.length - 1];
            if (last && last.closeType === p.closeType) {
                last.minuteEnd = p.minuteEnd;
                last.totalCount += p.totalCount;
                last.binCount += p.binCount;
                last.counts.push(...p.counts);
                if (p.portCounts) for (const [pt, c] of p.portCounts) last.portCounts.set(pt, (last.portCounts.get(pt) || 0) + c);
            } else {
                phases.push(p);
            }
        }

        if (!absorbed) break;
    }

    return phases;
}

// ─── Per-bin classification ──────────────────────────────────────────────────

/**
 * Convert links into classified bins for phase collapsing.
 *
 * In flow mode, each link is already a unique (pair, minute, close_type) with
 * its own count and port. We emit one bin per link so that different close_types
 * within the same minute become separate events in the sequence. This allows
 * patterns like GRACEFUL[port=25] -> RST_HANDSHAKE[port=113] to match even
 * when both events occur in the same minute.
 *
 * Within a minute, bins are sorted by count descending so the dominant type
 * comes first (consistent with how the original dominant-type classification
 * would have ordered them).
 *
 * @param {Array} pairLinks - All links for one IP pair, sorted by minute
 * @returns {Array} bins - [{ closeType, minute, count, ratio, dst_port }]
 */
function classifyBins(pairLinks) {
    const bins = [];
    for (const link of pairLinks) {
        bins.push({
            closeType: CLOSE_TYPE_TOKENS[link.attack] || (link.attack || '').toUpperCase(),
            minute: link.minute,
            count: link.count || 1,
            ratio: 1,
            dst_port: link.dst_port || 0
        });
    }
    // Sort by minute, then by count descending (dominant first within same minute)
    bins.sort((a, b) => a.minute - b.minute || b.count - a.count);
    return bins;
}

// ─── Main API ────────────────────────────────────────────────────────────────

/**
 * Build phase sequences for all IP pairs from flow-mode links.
 *
 * @param {Array} linksWithNodes - From TimearcsLayout._linksWithNodes
 * @param {Object} options
 * @param {number} options.noiseRatio - Noise absorption threshold (default 0.1)
 * @param {Object} options.percentiles - Pre-computed volume percentiles (optional)
 * @returns {Map<string, { src, tgt, phases, rawBins }>}
 */
export function buildPairPhaseMap(linksWithNodes, options = {}) {
    const { noiseRatio = 0.1 } = options;
    const percentiles = options.percentiles || computeVolumePercentiles(linksWithNodes);

    // Group links by canonical pair key
    const pairGroups = new Map();
    for (const link of linksWithNodes) {
        const src = link.sourceIp || link.sourceNode?.name || link.source?.name;
        const tgt = link.targetIp || link.targetNode?.name || link.target?.name;
        if (!src || !tgt) continue;

        const pk = canonicalPairKey(src, tgt);
        if (!pairGroups.has(pk)) {
            pairGroups.set(pk, { src, tgt, links: [] });
        }
        pairGroups.get(pk).links.push(link);
    }

    // Build phase map
    const result = new Map();
    for (const [pk, { src, tgt, links }] of pairGroups) {
        // Sort by minute
        links.sort((a, b) => a.minute - b.minute);

        // Classify each minute bin by dominant close_type
        const rawBins = classifyBins(links);

        // Collapse into phases with noise tolerance
        const rawPhases = collapsePhases(rawBins, noiseRatio);

        // Assign volume labels and compute ratios
        const phases = abstractPairToLevel4(rawPhases, percentiles);

        result.set(pk, { src, tgt, phases, rawBins });
    }

    return result;
}

/**
 * Convert raw phases into Level 4 events with volume labels.
 *
 * @param {Array} phases - From collapsePhases()
 * @param {Object} percentiles - From computeVolumePercentiles()
 * @returns {Array} Level 4 events: [{ closeType, minuteStart, minuteEnd, totalCount, binCount, ratio, volumeLabel }]
 */
export function abstractPairToLevel4(phases, percentiles) {
    return phases.map(p => {
        // Resolve dominant port from phase portCounts
        let dominantPort = 0, maxPC = 0;
        if (p.portCounts) {
            for (const [port, cnt] of p.portCounts) {
                if (cnt > maxPC) { maxPC = cnt; dominantPort = port; }
            }
        }
        return {
            closeType: p.closeType,
            minuteStart: p.minuteStart,
            minuteEnd: p.minuteEnd,
            totalCount: p.totalCount,
            binCount: p.binCount,
            ratio: p.binCount > 0 ? p.totalCount / p.binCount : 0,
            volumeLabel: volumeLabel(p.totalCount / Math.max(1, p.binCount), percentiles),
            port: dominantPort
        };
    });
}

export { canonicalPairKey };
