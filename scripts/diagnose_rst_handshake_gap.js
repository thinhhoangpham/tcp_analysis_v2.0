#!/usr/bin/env node
// Diagnose gap for RST During Handshake: SYN -> SYN_ACK -> RST
import { readFileSync } from 'fs';
import { join } from 'path';

const BASE = join(import.meta.dirname, '..', 'packets_data', 'attack_flows_day1to5', 'indices', 'flow_list');

function classifyFlags(flags) {
    if (flags === undefined || flags === null) return 'OTHER';
    const flagMap = { 0x01: 'FIN', 0x02: 'SYN', 0x04: 'RST', 0x08: 'PSH', 0x10: 'ACK' };
    const setFlags = Object.entries(flagMap)
        .filter(([val]) => (flags & parseInt(val)) > 0)
        .map(([, name]) => name).sort();
    if (setFlags.length === 0) return 'OTHER';
    const flagStr = setFlags.join('+');
    if (flagStr === 'ACK+SYN') return 'SYN_ACK';
    if (flagStr === 'ACK+FIN') return 'FIN_ACK';
    if (flagStr === 'ACK+PSH') return 'PSH_ACK';
    if (flagStr === 'ACK+RST') return 'RST_ACK';
    return flagStr;
}

const FLAG_TO_DSL = {
    'SYN': 'SYN', 'SYN_ACK': 'SYN_ACK', 'ACK': 'ACK',
    'PSH_ACK': 'PSH_ACK', 'PSH': 'PSH_ACK',
    'ACK+FIN+PSH': 'ACK_FIN_PSH', 'FIN': 'FIN',
    'FIN_ACK': 'FIN_ACK', 'RST': 'RST', 'RST_ACK': 'RST_ACK', 'OTHER': 'OTHER'
};

// Note: classifyFlags already normalizes, just map to DSL
function toDSL(flags) {
    const raw = classifyFlags(flags);
    return FLAG_TO_DSL[raw] || raw;
}

function parseCSVLine(line) {
    const fields = []; let current = ''; let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
        const c = line[i];
        if (c === '"') { if (inQuotes && line[i+1] === '"') { current += '"'; i++; } else inQuotes = !inQuotes; }
        else if (c === ',' && !inQuotes) { fields.push(current); current = ''; }
        else current += c;
    }
    fields.push(current);
    return fields;
}

const CLOSE_TYPE_DECODING = [
    '', 'graceful', 'abortive', 'ongoing',
    'rst_during_handshake', 'invalid_ack', 'invalid_synack',
    'incomplete_no_synack', 'incomplete_no_ack', 'unknown_invalid'
];

const index = JSON.parse(readFileSync(join(BASE, 'index.json'), 'utf-8'));

let totalRstHS = 0;
let matched = 0;
let unmatched = 0;
const unmatchedFlows = [];

for (const pairInfo of index.pairs) {
    let csv;
    try { csv = readFileSync(join(BASE, pairInfo.file), 'utf-8'); } catch { continue; }
    const lines = csv.split('\n');
    for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;
        const fields = parseCSVLine(line);
        const ctCode = parseInt(fields[3], 10) || 0;
        if (ctCode !== 4) continue; // 4 = rst_during_handshake

        totalRstHS++;
        const packetsStr = fields[4];
        if (!packetsStr) { unmatched++; unmatchedFlows.push({ pair: pairInfo.pair, seq: '(no packets)' }); continue; }

        const parts = packetsStr.split(',');
        const seq = parts.map(p => {
            const f = parseInt(p.trim().split(':')[1], 10) || 0;
            return toDSL(f);
        });

        // Pattern: SYN -> SYN_ACK -> RST (anywhere in the sequence as subsequence? No, strict adjacency)
        // Check if seq contains SYN at [0], SYN_ACK at [1], RST at [2]
        const matches = seq.length >= 3 && seq[0] === 'SYN' && seq[1] === 'SYN_ACK' && seq[2] === 'RST';
        // Actually the pattern SYN -> SYN_ACK -> RST just requires these 3 as a contiguous subsequence starting at any position
        // But matchPattern scans from all starting positions. Let's check if ANY contiguous triple matches
        let found = false;
        for (let j = 0; j <= seq.length - 3; j++) {
            if (seq[j] === 'SYN' && seq[j+1] === 'SYN_ACK' && (seq[j+2] === 'RST')) {
                found = true; break;
            }
        }

        if (found) { matched++; }
        else {
            unmatched++;
            unmatchedFlows.push({ pair: pairInfo.pair, seq: seq.join(' -> '), len: seq.length });
        }
    }
}

console.log(`\n=== RST During Handshake Gap Analysis ===`);
console.log(`Total rst_during_handshake in CSVs: ${totalRstHS}`);
console.log(`Matched by SYN->SYN_ACK->RST:      ${matched}`);
console.log(`NOT matched:                        ${unmatched}`);

// Group by sequence
const bySeq = {};
for (const f of unmatchedFlows) {
    if (!bySeq[f.seq]) bySeq[f.seq] = [];
    bySeq[f.seq].push(f);
}
console.log(`\n--- Unmatched sequences (grouped) ---`);
const sorted = Object.entries(bySeq).sort((a, b) => b[1].length - a[1].length);
for (const [seq, flows] of sorted) {
    console.log(`\n[${flows.length} flows] ${seq}`);
    console.log(`  Example: ${flows[0].pair}`);
}

// Also check: does the pattern also match RST_ACK instead of plain RST?
let matchedWithRstAck = 0;
for (const pairInfo of index.pairs) {
    let csv;
    try { csv = readFileSync(join(BASE, pairInfo.file), 'utf-8'); } catch { continue; }
    const lines = csv.split('\n');
    for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;
        const fields = parseCSVLine(line);
        const ctCode = parseInt(fields[3], 10) || 0;
        if (ctCode !== 4) continue;
        const packetsStr = fields[4];
        if (!packetsStr) continue;
        const parts = packetsStr.split(',');
        const seq = parts.map(p => toDSL(parseInt(p.trim().split(':')[1], 10) || 0));
        for (let j = 0; j <= seq.length - 3; j++) {
            if (seq[j] === 'SYN' && seq[j+1] === 'SYN_ACK' && (seq[j+2] === 'RST' || seq[j+2] === 'RST_ACK')) {
                matchedWithRstAck++; break;
            }
        }
    }
}
console.log(`\nWith RST_ACK included: ${matchedWithRstAck} matched`);
