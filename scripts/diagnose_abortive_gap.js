#!/usr/bin/env node
// Diagnose the 10-flow gap between overview abortive count (1,943) and pattern search (1,933).
// Reads flow_list CSVs, finds abortive flows, checks which don't match the pattern.

import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

const BASE = join(import.meta.dirname, '..', 'packets_data', 'attack_flows_day1to5', 'indices', 'flow_list');

// ─── Inline classifyFlags (from src/tcp/flags.js) ───
function classifyFlags(flags) {
    if (flags === undefined || flags === null) return 'OTHER';
    const flagMap = { 0x01: 'FIN', 0x02: 'SYN', 0x04: 'RST', 0x08: 'PSH', 0x10: 'ACK' };
    const setFlags = Object.entries(flagMap)
        .filter(([val]) => (flags & parseInt(val)) > 0)
        .map(([, name]) => name)
        .sort();
    if (setFlags.length === 0) return 'OTHER';
    const flagStr = setFlags.join('+');
    if (flagStr === 'ACK+SYN') return 'SYN+ACK';
    if (flagStr === 'ACK+FIN') return 'FIN+ACK';
    if (flagStr === 'ACK+PSH') return 'PSH+ACK';
    if (flagStr === 'ACK+RST') return 'RST+ACK';
    return flagStr;
}

const FLAG_TO_DSL = {
    'SYN': 'SYN', 'SYN+ACK': 'SYN_ACK', 'ACK': 'ACK',
    'PSH+ACK': 'PSH_ACK', 'PSH': 'PSH_ACK',
    'ACK+FIN+PSH': 'ACK_FIN_PSH', 'FIN': 'FIN',
    'FIN+ACK': 'FIN_ACK', 'RST': 'RST', 'RST+ACK': 'RST_ACK', 'OTHER': 'OTHER'
};

const CLOSE_TYPE_DECODING = [
    '', 'graceful', 'abortive', 'ongoing',
    'rst_during_handshake', 'invalid_ack', 'invalid_synack',
    'incomplete_no_synack', 'incomplete_no_ack', 'unknown_invalid'
];

// ─── CSV parsing ───
function parseCSVLine(line) {
    const fields = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
        const char = line[i];
        if (char === '"') {
            if (inQuotes && line[i + 1] === '"') { current += '"'; i++; }
            else inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
            fields.push(current); current = '';
        } else {
            current += char;
        }
    }
    fields.push(current);
    return fields;
}

// ─── Abstract to Level 1 ───
function abstractToLevel1(packetsStr, flowStartTime) {
    if (!packetsStr) return [];
    const parts = packetsStr.split(',');
    const events = [];
    for (const part of parts) {
        const fields = part.trim().split(':');
        const delta = parseInt(fields[0], 10) || 0;
        const flags = parseInt(fields[1], 10) || 0;
        const dir = fields[2] === '1' ? 'out' : 'in';
        const rawFlag = classifyFlags(flags);
        const dslFlag = FLAG_TO_DSL[rawFlag] || 'OTHER';
        events.push({ flagType: dslFlag, dir, timestamp: flowStartTime + delta });
    }
    return events;
}

// ─── Pattern check: SYN -> SYN_ACK -> ACK -> .{1,} -> (RST | RST_ACK) -> $ ───
function matchesAbortivePattern(events) {
    const n = events.length;
    if (n < 5) return false; // minimum: SYN, SYN_ACK, ACK, <something>, RST

    // Check handshake prefix
    if (events[0].flagType !== 'SYN') return false;
    if (events[1].flagType !== 'SYN_ACK') return false;
    if (events[2].flagType !== 'ACK') return false;

    // Last event must be RST or RST_ACK
    const last = events[n - 1].flagType;
    if (last !== 'RST' && last !== 'RST_ACK') return false;

    // .{1,} — at least one event between ACK (index 2) and the last event (index n-1)
    // That means n-1 - 3 >= 1, i.e. n >= 5 (already checked)
    if (n - 1 - 3 < 1) return false;

    return true;
}

// ─── Main ───
const index = JSON.parse(readFileSync(join(BASE, 'index.json'), 'utf-8'));
const pairs = index.pairs;

let totalAbortive = 0;
let matched = 0;
let unmatched = 0;
const unmatchedFlows = [];

for (const pairInfo of pairs) {
    const csvPath = join(BASE, pairInfo.file);
    let csvContent;
    try { csvContent = readFileSync(csvPath, 'utf-8'); }
    catch { continue; }

    const lines = csvContent.split('\n');
    // Skip header
    for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;

        const fields = parseCSVLine(line);
        const closeTypeCode = parseInt(fields[3], 10) || 0;
        if (closeTypeCode !== 2) continue; // only abortive

        totalAbortive++;
        const startTime = parseInt(fields[0], 10);
        const packetsStr = fields[4];
        const events = abstractToLevel1(packetsStr, startTime);
        const seq = events.map(e => e.flagType);

        if (matchesAbortivePattern(events)) {
            matched++;
        } else {
            unmatched++;
            unmatchedFlows.push({
                pair: pairInfo.pair,
                startTime,
                packetCount: events.length,
                sequence: seq.join(' -> '),
                shortSeq: seq.length > 15
                    ? seq.slice(0, 6).join('->') + ' ... ' + seq.slice(-4).join('->')
                    : seq.join(' -> ')
            });
        }
    }
}

console.log(`\n=== Abortive Flow Gap Analysis ===`);
console.log(`Total abortive flows in CSVs: ${totalAbortive}`);
console.log(`Matched by pattern:           ${matched}`);
console.log(`NOT matched:                  ${unmatched}`);
console.log(`\n--- Unmatched flows ---`);

// Group by pattern signature
const bySignature = {};
for (const f of unmatchedFlows) {
    const sig = f.sequence;
    if (!bySignature[sig]) bySignature[sig] = [];
    bySignature[sig].push(f);
}

const sorted = Object.entries(bySignature).sort((a, b) => b[1].length - a[1].length);
for (const [sig, flows] of sorted) {
    console.log(`\n[${flows.length} flows] Sequence: ${flows[0].shortSeq}`);
    console.log(`  Full: ${sig}`);
    console.log(`  Packet count: ${flows[0].packetCount}`);
    console.log(`  Example pair: ${flows[0].pair}`);
}
