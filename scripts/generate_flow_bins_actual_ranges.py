#!/usr/bin/env python3
"""
generate_flow_bins_actual_ranges.py

Creates pre-binned flow data where each bin's time range reflects the actual
flow start/end times instead of fixed grid boundaries.

Input:  packets_data/attack_flows_day1to5/indices/flow_list/ (CSVs + index.json)
Output: packets_data/attack_flows_day1to5/indices/flow_bins_*_actual.json
        packets_data/attack_flows_day1to5/indices/flow_bins_index_actual.json

Usage:
    python scripts/generate_flow_bins_actual_ranges.py
"""

import csv
csv.field_size_limit(10_000_000)  # flow_list CSVs have large packet columns
import json
import os
import sys
import time
from collections import defaultdict

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
INDICES_DIR = os.path.join(REPO_ROOT, "packets_data", "attack_flows_day1to5", "indices")
FLOW_LIST_DIR = os.path.join(INDICES_DIR, "flow_list")
FLOW_LIST_INDEX = os.path.join(FLOW_LIST_DIR, "index.json")
FLOW_BINS_INDEX = os.path.join(INDICES_DIR, "flow_bins_index.json")

# ---------------------------------------------------------------------------
# Resolutions
# ---------------------------------------------------------------------------
RESOLUTIONS = [
    ("1s",    1_000_000),
    ("10s",   10_000_000),
    ("1min",  60_000_000),
    ("10min", 600_000_000),
    ("hour",  3_600_000_000),
]

# ---------------------------------------------------------------------------
# Close-type decoding
# Index matches the integer close_type value stored in the CSV.
# ---------------------------------------------------------------------------
CLOSE_TYPE_NAMES = [
    "",                     # 0 → open / unknown (treated as "open")
    "graceful",             # 1
    "abortive",             # 2
    "ongoing",              # 3
    "rst_during_handshake", # 4  → invalid sub-type
    "invalid_ack",          # 5  → invalid sub-type
    "invalid_synack",       # 6  → invalid sub-type
    "incomplete_no_synack", # 7  → invalid sub-type
    "incomplete_no_ack",    # 8  → invalid sub-type
    "unknown_invalid",      # 9  → invalid sub-type
]

# Close types whose counts live under the top-level "invalid" dict.
INVALID_SUBTYPES = {
    "rst_during_handshake",
    "invalid_ack",
    "invalid_synack",
    "incomplete_no_synack",
    "incomplete_no_ack",
    "unknown_invalid",
}

# Top-level category keys that are NOT "invalid" and NOT "initiated_by".
TOP_LEVEL_CATEGORIES = {"graceful", "abortive", "ongoing", "open"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def decode_close_type(raw_value: str) -> str:
    """Convert the integer close_type string to its canonical name."""
    try:
        idx = int(raw_value)
    except (ValueError, TypeError):
        return "open"
    if idx < 0 or idx >= len(CLOSE_TYPE_NAMES):
        return "unknown_invalid"
    name = CLOSE_TYPE_NAMES[idx]
    return name if name else "open"


def parse_packets_last_delta(packets_str: str) -> int:
    """
    Extract the delta_ts of the last packet from the packets column.

    The column may be surrounded by quotes (handled by the CSV reader) and
    contains entries separated by commas:  delta_ts:flags:dir,...

    Returns the delta_ts of the final entry (microseconds relative to
    flow start), or 0 if the string is empty / unparseable.
    """
    packets_str = packets_str.strip()
    if not packets_str:
        return 0
    # Entries are comma-separated; each entry is  delta:flags:dir
    # We only need the last entry's first field.
    last_entry = packets_str.rsplit(",", 1)[-1]
    parts = last_entry.split(":", 2)
    try:
        return int(parts[0])
    except (ValueError, IndexError):
        return 0


def parse_first_packet_dir(packets_str: str) -> int:
    """
    Return the direction of the first packet (0 or 1), or -1 on error.

    dir=1 means ip1 → ip2 (ip1 is the initiator).
    dir=0 means ip2 → ip1 (ip2 is the initiator).
    """
    packets_str = packets_str.strip()
    if not packets_str:
        return -1
    first_entry = packets_str.split(",", 1)[0]
    parts = first_entry.split(":", 2)
    try:
        return int(parts[2])
    except (ValueError, IndexError):
        return -1


def pair_ips_from_filename(filename: str):
    """
    Derive (ip1, ip2) from a filename like '172-28-4-7__192-168-1-1.csv'.
    Dashes inside an octet group are dots; double-underscore separates the
    two IPs.
    """
    base = os.path.splitext(os.path.basename(filename))[0]
    # Strip _partN suffix from split files (e.g., "172-28-4-7__192-168-1-1_part1")
    import re
    base = re.sub(r'_part\d+$', '', base)
    halves = base.split("__", 1)
    if len(halves) != 2:
        return None, None
    ip1 = halves[0].replace("-", ".")
    ip2 = halves[1].replace("-", ".")
    return ip1, ip2


def pair_key(ip1: str, ip2: str) -> str:
    """Return the canonical 'ip1<->ip2' pair key (already alphabetical from filename)."""
    return f"{ip1}<->{ip2}"


# ---------------------------------------------------------------------------
# Flow record (lightweight named tuple alternative)
# ---------------------------------------------------------------------------

class Flow:
    __slots__ = ("start_time", "end_time", "close_type_name", "initiator_ip", "pair_key")

    def __init__(self, start_time, end_time, close_type_name, initiator_ip, pk):
        self.start_time = start_time
        self.end_time = end_time
        self.close_type_name = close_type_name
        self.initiator_ip = initiator_ip
        self.pair_key = pk


# ---------------------------------------------------------------------------
# CSV parsing
# ---------------------------------------------------------------------------

def read_flows_from_csv(filepath: str, ip1: str, ip2: str, pk: str):
    """
    Generator that yields Flow objects from a single pair CSV file.

    Handles the optional surrounding quotes on the packets column that may
    appear when the CSV was written without proper quoting.
    """
    with open(filepath, newline="", encoding="utf-8") as fh:
        reader = csv.reader(fh)
        try:
            header = next(reader)  # skip header row
        except StopIteration:
            return

        # Column indices (header: start_time,src_port,dst_port,close_type,packets)
        try:
            idx_start = header.index("start_time")
            idx_ct = header.index("close_type")
            idx_pkt = header.index("packets")
        except ValueError:
            # Malformed header; skip file
            return

        for row in reader:
            if len(row) <= idx_pkt:
                continue

            try:
                start_time = int(row[idx_start])
            except ValueError:
                continue

            close_type_name = decode_close_type(row[idx_ct])

            packets_str = row[idx_pkt]

            last_delta = parse_packets_last_delta(packets_str)
            end_time = start_time + last_delta

            first_dir = parse_first_packet_dir(packets_str)
            if first_dir == 1:
                initiator_ip = ip1
            elif first_dir == 0:
                initiator_ip = ip2
            else:
                initiator_ip = ip1  # fallback

            yield Flow(start_time, end_time, close_type_name, initiator_ip, pk)


# ---------------------------------------------------------------------------
# Bin accumulator
# ---------------------------------------------------------------------------

def make_pair_bucket():
    """Return a fresh per-IP-pair accumulator dict."""
    return {
        "graceful": 0,
        "abortive": 0,
        "invalid": defaultdict(int),
        "ongoing": 0,
        "open": 0,
        "initiated_by": defaultdict(lambda: defaultdict(int)),
        # Per-close-type time ranges: {closeType: [minStart, maxEnd]}
        "_ranges": defaultdict(lambda: [None, None]),
    }


def accumulate_flow(bucket: dict, flow: Flow):
    """Tally a single flow into its pair bucket."""
    ct = flow.close_type_name
    initiator = flow.initiator_ip

    # Track time range per close type
    r = bucket["_ranges"][ct]
    if r[0] is None or flow.start_time < r[0]:
        r[0] = flow.start_time
    if r[1] is None or flow.end_time > r[1]:
        r[1] = flow.end_time

    if ct in INVALID_SUBTYPES:
        bucket["invalid"][ct] += 1
        bucket["initiated_by"][initiator][ct] += 1
    elif ct in TOP_LEVEL_CATEGORIES:
        bucket[ct] += 1
        bucket["initiated_by"][initiator][ct] += 1
    else:
        # Defensive fallback
        bucket["open"] += 1
        bucket["initiated_by"][initiator]["open"] += 1


def bucket_to_json(bucket: dict, ip1: str, ip2: str) -> dict:
    """Convert an accumulator bucket into the serialisable output structure."""
    initiated_by_out = {}
    for ip in (ip1, ip2):
        counts = dict(bucket["initiated_by"].get(ip, {}))
        initiated_by_out[ip] = counts

    # Per-close-type time ranges
    ranges_out = {}
    for ct, (s, e) in bucket["_ranges"].items():
        if s is not None:
            ranges_out[ct] = [s, e]

    return {
        "graceful": bucket["graceful"],
        "abortive": bucket["abortive"],
        "invalid": dict(bucket["invalid"]),
        "ongoing": bucket["ongoing"],
        "open": bucket["open"],
        "initiated_by": initiated_by_out,
        "ranges": ranges_out,
    }


# ---------------------------------------------------------------------------
# Main logic
# ---------------------------------------------------------------------------

def load_all_flows(flow_list_dir: str, index: dict):
    """
    Read every pair CSV and return a flat list of Flow objects.
    Logs progress every 500k flows.
    """
    pairs = index["pairs"]
    total_pairs = len(pairs)
    all_flows = []
    total_flows_read = 0
    t0 = time.time()

    print(f"Loading flows from {total_pairs} pair CSV files...")

    for pair_num, pair_entry in enumerate(pairs, 1):
        pair_str = pair_entry["pair"]          # e.g. "1.101.50.36<->172.28.4.7"
        filename = pair_entry["file"]
        filepath = os.path.join(flow_list_dir, filename)

        if not os.path.exists(filepath):
            print(f"  WARNING: missing file {filename}, skipping", file=sys.stderr)
            continue

        # Derive ip1/ip2 from filename (authoritative alphabetical order)
        ip1, ip2 = pair_ips_from_filename(filename)
        if ip1 is None:
            print(f"  WARNING: could not parse IPs from {filename}, skipping", file=sys.stderr)
            continue

        pk = pair_key(ip1, ip2)

        for flow in read_flows_from_csv(filepath, ip1, ip2, pk):
            all_flows.append(flow)
            total_flows_read += 1
            if total_flows_read % 500_000 == 0:
                elapsed = time.time() - t0
                rate = total_flows_read / elapsed if elapsed > 0 else 0
                pct_pairs = pair_num / total_pairs * 100
                print(
                    f"  {total_flows_read:,} flows read "
                    f"({pct_pairs:.1f}% of pairs, {rate:,.0f} flows/s, "
                    f"{elapsed:.1f}s elapsed)"
                )

    elapsed = time.time() - t0
    print(f"Done loading: {total_flows_read:,} flows in {elapsed:.1f}s")
    return all_flows


def build_bins_for_resolution(
    flows,
    dataset_start: int,
    bin_width: int,
    res_name: str,
):
    """
    Bin all flows at a single resolution.

    Returns a list of bin dicts sorted by bin index.
    Also returns total unique IP pairs seen.
    """
    print(f"  Binning at {res_name} resolution (bin_width={bin_width:,} µs)...")
    t0 = time.time()

    # Two-level dict: bin_idx → pair_key → bucket
    bins = defaultdict(lambda: defaultdict(make_pair_bucket))

    # Per-bin actual time range (across ALL pairs in that bin)
    bin_actual_start = {}  # bin_idx → min startTime
    bin_actual_end = {}    # bin_idx → max endTime

    for flow in flows:
        bin_idx = (flow.start_time - dataset_start) // bin_width

        # Track actual time extent for this bin (global, not per-pair)
        if bin_idx not in bin_actual_start:
            bin_actual_start[bin_idx] = flow.start_time
            bin_actual_end[bin_idx] = flow.end_time
        else:
            if flow.start_time < bin_actual_start[bin_idx]:
                bin_actual_start[bin_idx] = flow.start_time
            if flow.end_time > bin_actual_end[bin_idx]:
                bin_actual_end[bin_idx] = flow.end_time

        accumulate_flow(bins[bin_idx][flow.pair_key], flow)

    # Serialise
    output = []
    all_pair_keys = set()

    for bin_idx in sorted(bins.keys()):
        pair_buckets = bins[bin_idx]
        flows_by_ip_pair = {}

        for pk, bucket in pair_buckets.items():
            all_pair_keys.add(pk)
            # Reconstruct ip1/ip2 from pair key
            parts = pk.split("<->", 1)
            ip1, ip2 = (parts[0], parts[1]) if len(parts) == 2 else (pk, pk)
            flows_by_ip_pair[pk] = bucket_to_json(bucket, ip1, ip2)

        output.append({
            "bin": bin_idx,
            "start": bin_actual_start[bin_idx],
            "end": bin_actual_end[bin_idx],
            "flows_by_ip_pair": flows_by_ip_pair,
        })

    elapsed = time.time() - t0
    print(f"    -> {len(output)} bins, {len(all_pair_keys)} IP pairs ({elapsed:.1f}s)")
    return output, len(all_pair_keys)


def write_json(path: str, data):
    """Write data as compact JSON (no indent for large files, saves space)."""
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, separators=(",", ":"))
    size_mb = os.path.getsize(path) / 1_048_576
    print(f"    Wrote {path} ({size_mb:.1f} MB)")


def main():
    # ------------------------------------------------------------------
    # Load indices
    # ------------------------------------------------------------------
    if not os.path.exists(FLOW_LIST_INDEX):
        print(f"ERROR: flow_list index not found at {FLOW_LIST_INDEX}", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(FLOW_BINS_INDEX):
        print(f"ERROR: flow_bins_index not found at {FLOW_BINS_INDEX}", file=sys.stderr)
        sys.exit(1)

    with open(FLOW_LIST_INDEX, encoding="utf-8") as fh:
        flow_list_index = json.load(fh)

    with open(FLOW_BINS_INDEX, encoding="utf-8") as fh:
        bins_index = json.load(fh)

    # dataset_start is the authoritative epoch anchor for bin calculations.
    # Use the value from the existing flow_bins_index.json (microseconds).
    dataset_start = bins_index["time_range"]["start_us"]
    print(f"Dataset start (from flow_bins_index): {dataset_start}")
    print(f"Total flows in index: {flow_list_index['total_flows']:,}")

    # ------------------------------------------------------------------
    # Load all flows
    # ------------------------------------------------------------------
    all_flows = load_all_flows(FLOW_LIST_DIR, flow_list_index)

    if not all_flows:
        print("ERROR: no flows loaded, aborting", file=sys.stderr)
        sys.exit(1)

    # Compute dataset-wide actual time range from loaded flows
    actual_start = min(f.start_time for f in all_flows)
    actual_end = max(f.end_time for f in all_flows)
    duration_minutes = (actual_end - actual_start) / 60_000_000
    print(f"Actual time range: {actual_start} -> {actual_end} ({duration_minutes:.1f} min)")

    # ------------------------------------------------------------------
    # Generate one output file per resolution
    # ------------------------------------------------------------------
    index_resolutions = {}

    for res_name, bin_width in RESOLUTIONS:
        output_filename = f"flow_bins_{res_name}_actual.json"
        output_path = os.path.join(INDICES_DIR, output_filename)

        bins, num_pairs = build_bins_for_resolution(
            all_flows,
            dataset_start,
            bin_width,
            res_name,
        )

        write_json(output_path, bins)

        # Build resolution metadata for the index file, mirroring the
        # existing flow_bins_index.json format as closely as possible.
        entry = {
            "file": output_filename,
            "bin_width_us": bin_width,
            "bins_with_data": len(bins),
        }

        # Add human-readable bin_width_seconds / bin_width_minutes to match
        # the style of the existing index (seconds for sub-minute, minutes
        # for minute+).
        if bin_width < 60_000_000:
            entry["bin_width_seconds"] = bin_width // 1_000_000
        else:
            entry["bin_width_minutes"] = bin_width // 60_000_000

        # Copy the use_when thresholds from the existing index if present.
        existing_res = bins_index["resolutions"].get(res_name, {})
        for key in ("use_when_range_minutes_lte", "use_when_range_minutes_gt"):
            if key in existing_res:
                entry[key] = existing_res[key]

        index_resolutions[res_name] = entry

    # ------------------------------------------------------------------
    # Write the actual-ranges index file
    # ------------------------------------------------------------------
    actual_index = {
        "resolutions": index_resolutions,
        "time_range": {
            "start_us": actual_start,
            "end_us": actual_end,
            "duration_minutes": round(duration_minutes, 1),
        },
        "total_flows": len(all_flows),
        "total_ip_pairs": len({f.pair_key for f in all_flows}),
        "note": "Bin start/end times reflect actual flow start/end times, not fixed grid boundaries.",
    }

    index_path = os.path.join(INDICES_DIR, "flow_bins_index_actual.json")
    with open(index_path, "w", encoding="utf-8") as fh:
        json.dump(actual_index, fh, indent=2)
    print(f"Wrote index: {index_path}")

    print("\nAll done.")


if __name__ == "__main__":
    main()
