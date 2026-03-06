// src/search/flow-abstractor.js
// Transforms flows into abstract event sequences at each abstraction level.
// Level 1 (Packet), Level 2 (Phase), Level 3 (Outcome).

import { classifyFlags, flagPhase, flowToOutcome, TCP_PHASES } from '../tcp/flags.js';

// Map classifyFlags() output (uses '+') to DSL names (uses '_')
const FLAG_TO_DSL = {
    'SYN':     'SYN',
    'SYN+ACK': 'SYN_ACK',
    'ACK':     'ACK',
    'PSH+ACK':     'PSH_ACK',
    'PSH':         'PSH_ACK',   // treat bare PSH as PSH_ACK (rare)
    'ACK+FIN+PSH': 'ACK_FIN_PSH',
    'FIN':         'FIN',
    'FIN+ACK':     'FIN_ACK',
    'RST':         'RST',
    'RST+ACK':     'RST_ACK',
    'OTHER':       'OTHER'
};

/**
 * Map a DSL event name back to the '+'-separated form used by classifyFlags().
 * Used by the abstractor test helpers — not required at runtime.
 */
export const DSL_TO_FLAG = {
    'SYN':     'SYN',
    'SYN_ACK': 'SYN+ACK',
    'ACK':     'ACK',
    'PSH_ACK':     'PSH+ACK',
    'ACK_FIN_PSH': 'ACK+FIN+PSH',
    'FIN':         'FIN',
    'FIN_ACK':     'FIN+ACK',
    'RST':         'RST',
    'RST_ACK':     'RST+ACK',
    'OTHER':       'OTHER'
};

// ─── Level 1: Packet abstraction ─────────────────────────────────────────────

/**
 * Abstract flow embedded packets into Level 1 (Packet) event sequence.
 *
 * Each element:
 *   { flagType: string (DSL name), dir: 'out'|'in', deltaTime: number (us) }
 *
 * 'out' = from the flow initiator, 'in' = from the responder.
 * deltaTime is relative to the previous packet (0 for the first).
 *
 * @param {Object[]} packets - Embedded packets from flow-list-loader.js
 *   Each packet: { flags: number (bitmask), _fromInitiator: boolean, timestamp: number }
 * @returns {Object[]} Level 1 event sequence
 */
export function abstractToLevel1(packets) {
    if (!packets || packets.length === 0) return [];

    const events = [];
    let prevTimestamp = 0;

    for (let i = 0; i < packets.length; i++) {
        const pkt = packets[i];
        const rawFlagType = classifyFlags(pkt.flags);
        const flagType = FLAG_TO_DSL[rawFlagType] || 'OTHER';
        const dir = pkt._fromInitiator ? 'out' : 'in';
        const deltaTime = i === 0 ? 0 : (pkt.timestamp - prevTimestamp);

        events.push({ flagType, dir, deltaTime });
        prevTimestamp = pkt.timestamp;
    }

    return events;
}

// ─── Level 2: Phase abstraction ───────────────────────────────────────────────

/**
 * Abstract flow embedded packets into Level 2 (Phase) event sequence.
 *
 * Groups consecutive packets by flagPhase() result, then collapses each
 * contiguous run into one phase event. The 'closing' phase is split into
 * FIN_CLOSE or RST_CLOSE based on whether any RST flags appear in the run.
 *
 * Each element:
 *   { phase: string (TCP_PHASES value), packetCount: number, duration: number (us), hasRst: boolean }
 *
 * @param {Object[]} packets - Embedded packets from flow-list-loader.js
 * @returns {Object[]} Level 2 event sequence
 */
export function abstractToLevel2(packets) {
    if (!packets || packets.length === 0) return [];

    const events = [];
    let runStart = 0;

    // Determine the phase bucket for a packet using flagPhase() on its DSL name.
    // flagPhase() accepts the '+'-notation names from classifyFlags().
    const getPhase = (pkt) => flagPhase(classifyFlags(pkt.flags));

    while (runStart < packets.length) {
        const currentPhase = getPhase(packets[runStart]);
        let runEnd = runStart + 1;
        let hasRst = (packets[runStart].flags & 0x04) !== 0;

        while (runEnd < packets.length && getPhase(packets[runEnd]) === currentPhase) {
            if ((packets[runEnd].flags & 0x04) !== 0) hasRst = true;
            runEnd++;
        }

        const firstPkt = packets[runStart];
        const lastPkt  = packets[runEnd - 1];
        const duration = lastPkt.timestamp - firstPkt.timestamp;
        const packetCount = runEnd - runStart;

        let phase;
        if (currentPhase === 'establishment') {
            phase = TCP_PHASES.HANDSHAKE;
        } else if (currentPhase === 'data') {
            phase = TCP_PHASES.DATA;
        } else {
            // closing — split on RST presence
            phase = hasRst ? TCP_PHASES.RST_CLOSE : TCP_PHASES.FIN_CLOSE;
        }

        events.push({ phase, packetCount, duration, hasRst });
        runStart = runEnd;
    }

    return events;
}

// ─── Level 3: Outcome abstraction ────────────────────────────────────────────

/**
 * Abstract a flow into Level 3 (Outcome) — a single-element sequence.
 *
 * @param {Object} flow - Flow object with closeType and invalidReason fields
 * @returns {{ outcome: string }} Single outcome event (one of FLOW_OUTCOMES values)
 */
export function abstractToLevel3(flow) {
    return { outcome: flowToOutcome(flow) };
}
