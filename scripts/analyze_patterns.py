#!/usr/bin/env python3
"""
Comprehensive analysis of all flow_list CSV files to extract:
1. All unique close_type values and counts
2. All unique TCP flag bitmask values and counts
3. Common opening sequences (first 5 packets)
4. Common closing sequences (last 3 packets)
5. Flag transitions (bigrams) across all flows
6. Gap analysis: flags/patterns in data vs DSL coverage
"""

import json
import csv
import os
import sys

csv.field_size_limit(10 * 1024 * 1024)  # 10MB - some packet columns are huge
from collections import Counter, defaultdict
from pathlib import Path

BASE = Path(__file__).parent.parent / 'packets_data' / 'attack_flows_day1to5' / 'indices' / 'flow_list'
INDEX_PATH = BASE / 'index.json'

# Close type code mapping (from generate_flow_data.py)
CLOSE_TYPE_MAP = {
    0: '(empty)',
    1: 'graceful',
    2: 'abortive',
    3: 'ongoing',
    4: 'rst_during_handshake',
    5: 'invalid_ack',
    6: 'invalid_synack',
    7: 'incomplete_no_synack',
    8: 'incomplete_no_ack',
    9: 'unknown_invalid',
}

# TCP flag constants
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80


def classify_flags(flags):
    """Mirrors classifyFlags() in src/tcp/flags.js"""
    parts = []
    if flags & SYN: parts.append('SYN')
    if flags & ACK: parts.append('ACK')
    if flags & PSH: parts.append('PSH')
    if flags & FIN: parts.append('FIN')
    if flags & RST: parts.append('RST')
    if flags & URG: parts.append('URG')
    if flags & ECE: parts.append('ECE')
    if flags & CWR: parts.append('CWR')
    if not parts:
        return f'0x{flags:02x}'
    s = '+'.join(parts)
    # Normalize common combos to match JS classifyFlags output
    norm = {
        'SYN+ACK': 'SYN+ACK',
        'ACK+PSH': 'PSH+ACK',
        'ACK+FIN': 'FIN+ACK',
        'ACK+RST': 'RST+ACK',
        'ACK+PSH+FIN': 'ACK+FIN+PSH',
    }
    return norm.get(s, s)


# DSL token mapping (from flow-abstractor.js)
FLAG_TO_DSL = {
    'SYN': 'SYN', 'SYN+ACK': 'SYN_ACK', 'ACK': 'ACK',
    'PSH+ACK': 'PSH_ACK', 'PSH': 'PSH_ACK',
    'ACK+FIN+PSH': 'ACK_FIN_PSH', 'FIN': 'FIN', 'FIN+ACK': 'FIN_ACK',
    'RST': 'RST', 'RST+ACK': 'RST_ACK',
}


def parse_packets(packets_str):
    """Parse 'delta_ts:flags:dir,...' into list of flag ints."""
    if not packets_str:
        return []
    flags = []
    for entry in packets_str.split(','):
        parts = entry.split(':')
        if len(parts) >= 2:
            flags.append(int(parts[1]))
    return flags


def main():
    with open(INDEX_PATH, 'r') as f:
        index = json.load(f)

    print(f"Dataset: {index['total_flows']} flows across {index['total_pairs']} IP pairs\n")

    close_type_counts = Counter()
    flag_counts = Counter()
    opening_seq_counts = Counter()
    closing_seq_counts = Counter()
    bigram_counts = Counter()
    flow_length_by_close = defaultdict(Counter)
    total_flows = 0
    total_packets = 0
    unusual_flows = []  # flows not starting with SYN

    for i, pair_info in enumerate(index['pairs']):
        csv_path = BASE / pair_info['file']
        if not csv_path.exists():
            continue

        with open(csv_path, 'r', newline='') as f:
            reader = csv.reader(f)
            header = next(reader, None)
            for row in reader:
                if len(row) < 4:
                    continue

                close_code = int(row[3]) if row[3] else 0
                close_type = CLOSE_TYPE_MAP.get(close_code, f'unknown_code_{close_code}')
                close_type_counts[close_type] += 1

                packets_str = row[4] if len(row) > 4 else ''
                flags = parse_packets(packets_str)
                pkt_count = len(flags)
                total_packets += pkt_count

                # Flow length buckets
                if pkt_count <= 3:
                    bucket = str(pkt_count)
                elif pkt_count <= 10:
                    bucket = '4-10'
                elif pkt_count <= 50:
                    bucket = '11-50'
                else:
                    bucket = '51+'
                flow_length_by_close[close_type][bucket] += 1

                # Flag bitmask counts
                for fl in flags:
                    flag_counts[fl] += 1

                if flags:
                    # Opening sequence (first 5)
                    open_seq = ' -> '.join(classify_flags(f) for f in flags[:5])
                    opening_seq_counts[open_seq] += 1

                    # Closing sequence (last 3)
                    close_seq = ' -> '.join(classify_flags(f) for f in flags[-3:])
                    closing_seq_counts[close_seq] += 1

                    # Bigrams
                    for j in range(len(flags) - 1):
                        bigram = f'{classify_flags(flags[j])} -> {classify_flags(flags[j+1])}'
                        bigram_counts[bigram] += 1

                    # Track unusual: not starting with SYN
                    if flags[0] != SYN and len(unusual_flows) < 30:
                        unusual_flows.append({
                            'pair': pair_info['pair'],
                            'close_type': close_type,
                            'first_flags': [f'{classify_flags(f)}(0x{f:02x})' for f in flags[:5]],
                            'pkt_count': pkt_count,
                        })

                total_flows += 1

        if (i + 1) % 100 == 0:
            print(f'  Processed {i+1}/{len(index["pairs"])} files...', file=sys.stderr)

    # ── Reports ──────────────────────────────────────────────────────────

    print('=' * 80)
    print('1. CLOSE TYPE DISTRIBUTION')
    print('=' * 80)
    for ct, count in close_type_counts.most_common():
        pct = count / total_flows * 100
        print(f'  {ct:<30} {count:>10,}  ({pct:.2f}%)')
    print(f'  {"TOTAL":<30} {total_flows:>10,}')

    print('\n' + '=' * 80)
    print('2. TCP FLAG BITMASK VALUES (all unique flags in data)')
    print('=' * 80)
    for flag, count in flag_counts.most_common():
        name = classify_flags(flag)
        dsl = FLAG_TO_DSL.get(name, 'OTHER')
        pct = count / total_packets * 100
        print(f'  0x{flag:02x} = {name:<15} DSL: {dsl:<12} {count:>12,} packets ({pct:.3f}%)')
    print(f'  {"TOTAL PACKETS":<35} {total_packets:>12,}')

    print('\n' + '=' * 80)
    print('3. TOP 40 OPENING SEQUENCES (first 5 packets)')
    print('=' * 80)
    for seq, count in opening_seq_counts.most_common(40):
        pct = count / total_flows * 100
        print(f'  {count:>10,} ({pct:>6.2f}%)  {seq}')

    print('\n' + '=' * 80)
    print('4. TOP 40 CLOSING SEQUENCES (last 3 packets)')
    print('=' * 80)
    for seq, count in closing_seq_counts.most_common(40):
        pct = count / total_flows * 100
        print(f'  {count:>10,} ({pct:>6.2f}%)  {seq}')

    print('\n' + '=' * 80)
    print('5. ALL FLAG BIGRAMS (consecutive flag pairs)')
    print('=' * 80)
    for bigram, count in bigram_counts.most_common():
        pct = count / total_packets * 100
        print(f'  {count:>12,} ({pct:>6.3f}%)  {bigram}')

    print('\n' + '=' * 80)
    print('6. FLOW LENGTH DISTRIBUTION BY CLOSE TYPE')
    print('=' * 80)
    bucket_order = ['1', '2', '3', '4-10', '11-50', '51+']
    for ct in sorted(flow_length_by_close):
        print(f'  {ct}:')
        for bucket in bucket_order:
            count = flow_length_by_close[ct].get(bucket, 0)
            if count:
                print(f'    {bucket:<8} packets: {count:>10,}')

    print('\n' + '=' * 80)
    print('7. UNUSUAL FLOWS (not starting with SYN) - first 30 examples')
    print('=' * 80)
    for uf in unusual_flows:
        print(f'  {uf["pair"]} [{uf["close_type"]}] {uf["pkt_count"]} pkts: {" -> ".join(uf["first_flags"])}')

    print('\n' + '=' * 80)
    print('8. GAP ANALYSIS: Flags in data vs DSL coverage')
    print('=' * 80)
    all_flag_names = set(classify_flags(int(f)) for f in flag_counts)
    for name in sorted(all_flag_names):
        dsl = FLAG_TO_DSL.get(name)
        flag_val = next((f for f in flag_counts if classify_flags(f) == name), None)
        count = flag_counts.get(flag_val, 0)
        if dsl:
            print(f'  [COVERED]  {name:<15} -> DSL: {dsl:<12} ({count:>10,} occurrences)')
        else:
            print(f'  [MISSING]  {name:<15} -> NO DSL TOKEN  ({count:>10,} occurrences)')

    print('\n' + '=' * 80)
    print('9. OPENING SEQUENCES NOT STARTING WITH SYN (potential gaps)')
    print('=' * 80)
    non_syn_total = 0
    for seq, count in opening_seq_counts.most_common():
        if not seq.startswith('SYN ') and seq != 'SYN':
            pct = count / total_flows * 100
            print(f'  {count:>10,} ({pct:.2f}%)  {seq}')
            non_syn_total += count
    print(f'  {"TOTAL non-SYN-start":<30} {non_syn_total:>10,} ({non_syn_total/total_flows*100:.2f}%)')

    print('\n' + '=' * 80)
    print('10. CLOSE TYPE x CLOSING SEQUENCE CROSS-TAB (top combos)')
    print('=' * 80)
    # Re-scan is expensive, so let's approximate from existing data
    # Actually we need a separate counter for this — let me just report what we have
    print('  (See sections 1 + 4 for close type and closing sequence independently)')


if __name__ == '__main__':
    main()
