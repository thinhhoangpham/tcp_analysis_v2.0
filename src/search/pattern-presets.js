// src/search/pattern-presets.js
// Built-in pattern library for the TCP Flow Pattern Search feature.
// Phase 1 provides Level 1 (Packet) presets only.
// Level 2 (Phase) and Level 3 (Outcome) presets are placeholders for future phases.

export const PATTERN_PRESETS = {
    outcome: [
        // Phase 3 — Level 3 presets (will be enabled later)
        { id: 'failed_handshake',  label: 'Failed Handshakes',       level: 3, pattern: 'RST_HANDSHAKE | NO_SYNACK | NO_ACK' },
        { id: 'graceful',          label: 'Graceful Closes',          level: 3, pattern: 'COMPLETE_GRACEFUL' },
        { id: 'aborted',           label: 'Aborted Connections',      level: 3, pattern: 'COMPLETE_ABORTED' },
        { id: 'ongoing',           label: 'Ongoing Connections',      level: 3, pattern: 'ONGOING' },
        { id: 'all_invalid',       label: 'All Invalid Flows',        level: 3, pattern: 'RST_HANDSHAKE | NO_SYNACK | NO_ACK | INVALID_ACK | INVALID_SYNACK | UNKNOWN_INVALID' },
        { id: 'rst_handshake',     label: 'RST During Handshake',     level: 3, pattern: 'RST_HANDSHAKE' },
        { id: 'no_synack',         label: 'No SYN+ACK',               level: 3, pattern: 'NO_SYNACK' },
        { id: 'invalid_ack',       label: 'Invalid ACK',              level: 3, pattern: 'INVALID_ACK' }
    ],

    phase: [
        // Phase 2 — Level 2 presets (will be enabled later)
        { id: 'normal_flow',       label: 'Normal TCP Flow',          level: 2, pattern: 'HANDSHAKE -> DATA+ -> FIN_CLOSE' },
        { id: 'scan_pattern',      label: 'Port Scan (no data)',      level: 2, pattern: 'HANDSHAKE -> RST_CLOSE' },
        { id: 'handshake_only',    label: 'Handshake Only (no data)', level: 2, pattern: 'HANDSHAKE -> FIN_CLOSE' },
        { id: 'rst_after_data',    label: 'Aborted After Data',       level: 2, pattern: 'HANDSHAKE -> DATA+ -> RST_CLOSE' },
        { id: 'data_only',         label: 'Data Without Handshake',   level: 2, pattern: 'DATA+' },
        { id: 'long_session',      label: 'Long Data Session (>60s)', level: 2, pattern: 'HANDSHAKE -> DATA[dur>60s] -> *' }
    ],

    packet: [
        // Phase 1 — Level 1 presets (active)
        // ALL patterns verified against flow_list CSV embedded packets (the actual
        // data source the search engine matches against — NOT chunk/phase data).
        //
        // Full connection (370 graceful flows):
        //   100% start SYN->SYN_ACK->ACK, 100% have PSH_ACK data in middle
        //   95.1% close with FIN_ACK, 4.9% close with ACK_FIN_PSH (piggybacked FIN)
        //   .{1,} bridges data phase; greedy backtracking finds last FIN before final ACK
        //   $ end anchor ensures close is the LAST thing — excludes abortive flows with mid-flow FIN
        { id: 'full_connection',   label: 'Full Graceful Close',           level: 1, pattern: 'SYN -> SYN_ACK -> ACK -> .{1,} -> (FIN_ACK | ACK_FIN_PSH) -> ACK{1,} -> $' },
        // Full abortive: handshake + data + RST at the end.
        //   Python closeType='abortive' fires on ANY RST after handshake.
        //   classifyFlags() distinguishes RST (0x04) from RST_ACK (0x14) — must match both.
        //   .{1,} bridges data phase; $ ensures RST is the final packet.
        { id: 'full_abortive',     label: 'Full Abortive Connection',   level: 1, pattern: 'SYN -> SYN_ACK -> ACK -> .{1,} -> (RST | RST_ACK) -> $' },
        // Attack/invalid patterns (ordered by frequency in dataset)
        { id: 'syn_retransmit',    label: 'SYN Retransmit (no SYN+ACK)', level: 1, pattern: 'SYN -> SYN' },
        { id: 'rst_during_hs',     label: 'RST During Handshake',      level: 1, pattern: 'SYN -> SYN_ACK -> RST' },
        { id: 'syn_rst_ack',       label: 'SYN Rejected (RST+ACK)',    level: 1, pattern: 'SYN -> RST_ACK' },
        { id: 'synack_retransmit', label: 'SYN+ACK Retransmit',        level: 1, pattern: 'SYN_ACK -> SYN_ACK' },
        { id: 'syn_flood',         label: 'SYN Flood (5+ SYNs)',       level: 1, pattern: 'SYN{5,}' },
        { id: 'rst_flood',         label: 'RST Flood (3+ consecutive)', level: 1, pattern: 'RST{3,}' }
    ]
};

/**
 * Get presets for a given level.
 * @param {number} level - 1, 2, or 3
 * @returns {Object[]} Array of preset objects
 */
export function getPresetsForLevel(level) {
    const levelMap = { 1: 'packet', 2: 'phase', 3: 'outcome' };
    const key = levelMap[level];
    return key ? PATTERN_PRESETS[key] : [];
}

/**
 * Event names valid at each level (for autocomplete).
 */
export const LEVEL_EVENT_NAMES = {
    1: ['SYN', 'SYN_ACK', 'ACK', 'PSH_ACK', 'ACK_FIN_PSH', 'FIN_ACK', 'RST', 'RST_ACK'],
    2: ['HANDSHAKE', 'DATA', 'FIN_CLOSE', 'RST_CLOSE'],
    3: ['COMPLETE_GRACEFUL', 'COMPLETE_ABORTED', 'ONGOING', 'RST_HANDSHAKE',
        'INVALID_ACK', 'INVALID_SYNACK', 'NO_SYNACK', 'NO_ACK', 'UNKNOWN_INVALID']
};
