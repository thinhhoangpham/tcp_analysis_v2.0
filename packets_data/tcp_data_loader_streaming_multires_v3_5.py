#!/usr/bin/env python3
"""
TCP Data Loader - Multi-Resolution Packet View Only (v3.5)

Changes from v3.4:
- The protocol-aware flag_type computation was vectorized (zip over numpy
  arrays instead of DataFrame.apply(axis=1)) for speed; output is unchanged.
- Non-TCP packets are now labeled by their IP protocol (UDP/ICMP/PROTO_n)
  instead of being TCP-flag-classified. Previously classify_tcp_flags() ran on
  every packet regardless of protocol, so non-TCP packets (e.g. UDP protocol=17,
  which carry TCP-flags=0) were mislabeled "NONE". A new classify_protocol_flags()
  wrapper checks the IP protocol first: TCP (proto 6) is flag-classified as
  before; known non-TCP protocols map to names (UDP/ICMP/IGMP/GRE/ESP/AH/ICMPv6);
  other protocols become "PROTO_<n>"; missing/unparseable protocol becomes
  "PROTO_MISSING".
- Output files written as Parquet (.parquet) instead of CSV at every resolution
  (uses pandas.DataFrame.to_parquet; requires pyarrow or fastparquet installed)
- Chunk flushing is now driven by *target file size* (default 50 MB) instead of
  bin/row counts. All resolutions, including raw, use size-based chunking.
  Each candidate flush serializes the in-memory bins to a BytesIO buffer to
  measure the actual on-disk Parquet size; if the buffer reaches the target,
  the buffer is written verbatim to disk and the bin dict is cleared.
  Probe cadence is controlled by --probe-every (bins/packets accumulated
  between size checks) to limit serialization overhead.
- Removed src_port/dst_port from the aggregation bin key and columns so
  aggregated bins are keyed by (bin, src_ip, dst_ip, flag_type) again,
  restoring correct per-(src,dst,flag) aggregation (matching v3.4). An
  earlier v3.5 build had erroneously added ports to the key, which
  shattered aggregation (e.g. a SYN flood with a fresh source port per
  SYN produced one count=1 bin per packet instead of a single aggregated
  bin per second). The 'raw' resolution still buffers whole packets and
  retains ports; only the aggregated resolutions (hours..1ms) drop ports.

Generates multi-resolution packet data for visualization:
- resolutions/hours/: Hour-level aggregated packets (Parquet)
- resolutions/minutes/: Minute-level aggregated packets (Parquet)
- resolutions/10s/: 10-second-level aggregated packets (Parquet)
- resolutions/seconds/: Second-level aggregated packets (Parquet)
- resolutions/100ms/: 100ms (1/10th second) aggregated packets (Parquet chunks)
- resolutions/10ms/: 10ms (1/100th second) aggregated packets (Parquet chunks)
- resolutions/1ms/: 1ms (millisecond) aggregated packets (Parquet chunks)
- resolutions/raw/: Raw packets (Parquet chunks)

No flow detection - pure packet-level multi-resolution output.
"""

import pandas as pd
import numpy as np
import json
import sys
import io
import argparse
from pathlib import Path
from collections import defaultdict
import time

# TCP flag constants
FIN, SYN, RST, PSH, ACK, URG, ECE, CWR = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80

def load_ip_mapping(ip_map_file):
    """Load IP mapping from JSON file"""
    try:
        with open(ip_map_file, 'r') as f:
            ip_map = json.load(f)
        # Create reverse mapping (int -> ip_str)
        int_to_ip = {v: k for k, v in ip_map.items()}
        return ip_map, int_to_ip
    except Exception as e:
        print(f"Error loading IP mapping: {e}", file=sys.stderr)
        return {}, {}

def classify_tcp_flags(flag_val):
    """Classify TCP flags into readable format"""
    if pd.isna(flag_val):
        return "INVALID"

    try:
        flag_val = int(flag_val)
    except:
        return "INVALID"

    # TCP flag constants
    flags = {
        "FIN": 0x01, "SYN": 0x02, "RST": 0x04, "PSH": 0x08,
        "ACK": 0x10, "URG": 0x20, "ECE": 0x40, "CWR": 0x80
    }

    # Common combinations
    combinations = {
        (flags["SYN"] | flags["ACK"]): "SYN+ACK",
        (flags["FIN"] | flags["ACK"]): "FIN+ACK",
        (flags["PSH"] | flags["ACK"]): "PSH+ACK",
        (flags["RST"] | flags["ACK"]): "RST+ACK",
    }

    if flag_val in combinations:
        return combinations[flag_val]

    # Individual flags
    set_flags = [name for name, val in flags.items() if flag_val & val]
    if set_flags:
        return "+".join(sorted(set_flags))

    return "NONE" if flag_val == 0 else f"OTHER_{flag_val}"

# Known non-TCP IP protocol numbers -> human-readable labels
NON_TCP_PROTOCOL_NAMES = {
    17: "UDP",
    1: "ICMP",
    2: "IGMP",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
}

def classify_protocol_flags(flags, protocol):
    """Classify a packet by protocol, only running TCP-flag classification for TCP.

    - protocol == 6 (TCP): classify by TCP flags via classify_tcp_flags().
    - Known non-TCP protocol number: return its name (UDP/ICMP/...).
    - Any other non-null protocol number: return "PROTO_<n>".
    - Missing/None/NaN/unparseable protocol: return "PROTO_MISSING".

    Prevents non-TCP packets (which have TCP-flags=0) from being mislabeled
    "NONE" by TCP-flag classification.
    """
    # Resolve protocol to an int, or mark as missing.
    proto_int = None
    try:
        if protocol is None or pd.isna(protocol):
            proto_int = None
        elif isinstance(protocol, str) and protocol.strip() == '':
            proto_int = None
        else:
            proto_int = int(protocol)
    except Exception:
        proto_int = None

    if proto_int is None:
        return "PROTO_MISSING"
    if proto_int == 6:
        return classify_tcp_flags(flags)
    if proto_int in NON_TCP_PROTOCOL_NAMES:
        return NON_TCP_PROTOCOL_NAMES[proto_int]
    return f"PROTO_{proto_int}"

def _safe_int(val, default=0):
    """Safely convert to int, handling NaN/None/empty."""
    try:
        if pd.isna(val):
            return default
    except Exception:
        pass
    try:
        return int(val)
    except Exception:
        return default


def _bins_to_records(bins):
    """Materialize a bin dict into a list of plain dict records."""
    records = []
    for key, b in bins.items():
        flag_type_key = key[-1] if len(key) >= 1 else 'UNKNOWN'
        records.append({
            'timestamp': b['timestamp'],
            'src_ip': b['src_ip'],
            'dst_ip': b['dst_ip'],
            'count': b['count'],
            'total_bytes': b['total_bytes'],
            'flag_type': b.get('flag_type', flag_type_key),
        })
    return records


def _maybe_flush_bins(bins, output_dir, counter, chunk_index,
                     target_bytes, label, force=False):
    """Serialize aggregated bins to a Parquet buffer; if size >= target_bytes
    (or force), write the buffer to chunk_NNNNNN.parquet and clear the bin dict.

    Returns (new_counter, flushed_bool).
    """
    if not bins:
        return counter, False

    records = _bins_to_records(bins)
    df = pd.DataFrame(records)
    buf = io.BytesIO()
    df.to_parquet(buf, index=False)
    size = buf.tell()

    if not force and size < target_bytes:
        # Not big enough yet — discard buffer, keep accumulating in `bins`.
        return counter, False

    chunk_filename = f"chunk_{counter:06d}.parquet"
    chunk_path = output_dir / chunk_filename
    with open(chunk_path, 'wb') as f:
        f.write(buf.getvalue())

    chunk_index.append({
        'file': chunk_filename,
        'index': counter,
        'start': int(min(r['timestamp'] for r in records)),
        'end': int(max(r['timestamp'] for r in records)),
        'count': len(records),
    })
    print(f"  -> Flushed {len(records):,} {label} bins "
          f"({size/1048576:.2f} MB) to {chunk_filename}")
    bins.clear()
    return counter + 1, True


def _maybe_flush_raw(buffer, output_dir, counter, chunk_index,
                    target_bytes, force=False):
    """Serialize raw packet buffer to a Parquet buffer; if size >= target_bytes
    (or force), write to chunk_NNNNNN.parquet and clear the buffer.

    Returns (new_counter, new_buffer, flushed_bool).
    """
    if not buffer:
        return counter, buffer, False

    sorted_buf = sorted(buffer, key=lambda x: x['timestamp'])
    df = pd.DataFrame(sorted_buf)
    buf = io.BytesIO()
    df.to_parquet(buf, index=False)
    size = buf.tell()

    if not force and size < target_bytes:
        return counter, buffer, False

    chunk_filename = f"chunk_{counter:06d}.parquet"
    chunk_path = output_dir / chunk_filename
    with open(chunk_path, 'wb') as f:
        f.write(buf.getvalue())

    chunk_index.append({
        'file': chunk_filename,
        'index': counter,
        'start': int(sorted_buf[0]['timestamp']),
        'end': int(sorted_buf[-1]['timestamp']),
        'count': len(sorted_buf),
    })
    print(f"  -> Flushed raw chunk: {len(sorted_buf):,} packets "
          f"({size/1048576:.2f} MB) to {chunk_filename}")
    return counter + 1, [], True


def process_multires_packets(data_file, ip_map_file, output_dir, max_records=None,
                              chunk_read_size=500000,
                              target_chunk_mb=50.0, probe_every=200000):
    """
    Process packets and generate multi-resolution outputs (Parquet format).

    Args:
        data_file: Input CSV file path
        ip_map_file: IP mapping JSON file path
        output_dir: Output directory path
        max_records: Maximum records to process (None = all)
        chunk_read_size: CSV rows per read chunk (default: 500000)
        target_chunk_mb: Target output chunk file size in MB (default: 50.0)
        probe_every: Bins/packets accumulated between size probes (default: 200000)
    """

    target_bytes = int(target_chunk_mb * 1024 * 1024)

    # Create output directory structure
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Multi-resolution directories
    resolutions_dir = output_path / 'resolutions'
    resolutions_dir.mkdir(exist_ok=True)
    (resolutions_dir / 'hours').mkdir(exist_ok=True)
    (resolutions_dir / 'minutes').mkdir(exist_ok=True)
    (resolutions_dir / '10s').mkdir(exist_ok=True)
    (resolutions_dir / 'seconds').mkdir(exist_ok=True)
    (resolutions_dir / '100ms').mkdir(exist_ok=True)
    (resolutions_dir / '10ms').mkdir(exist_ok=True)
    (resolutions_dir / '1ms').mkdir(exist_ok=True)
    (resolutions_dir / 'raw').mkdir(exist_ok=True)

    print(f"Loading IP mapping from {ip_map_file}...")
    ip_map, int_to_ip = load_ip_mapping(ip_map_file)

    print(f"Processing packets from {data_file} in chunks of {chunk_read_size:,} rows...")
    print(f"Target chunk size: {target_chunk_mb} MB; probe every {probe_every:,} bins/packets")

    # State for multi-resolution aggregation
    hour_bins = defaultdict(lambda: {
        'timestamp': None, 'src_ip': None, 'dst_ip': None,
        'count': 0, 'total_bytes': 0, 'flag_counts': defaultdict(int)
    })
    minute_bins = defaultdict(lambda: {
        'timestamp': None, 'src_ip': None, 'dst_ip': None,
        'count': 0, 'total_bytes': 0, 'flag_counts': defaultdict(int)
    })
    tensecond_bins = defaultdict(lambda: {
        'timestamp': None, 'src_ip': None, 'dst_ip': None,
        'count': 0, 'total_bytes': 0, 'flag_counts': defaultdict(int)
    })
    second_bins = defaultdict(lambda: {
        'timestamp': None, 'src_ip': None, 'dst_ip': None,
        'count': 0, 'total_bytes': 0, 'flag_counts': defaultdict(int)
    })
    bins_100ms = defaultdict(lambda: {
        'timestamp': None, 'src_ip': None, 'dst_ip': None,
        'count': 0, 'total_bytes': 0, 'flag_counts': defaultdict(int)
    })
    bins_10ms = defaultdict(lambda: {
        'timestamp': None, 'src_ip': None, 'dst_ip': None,
        'count': 0, 'total_bytes': 0, 'flag_counts': defaultdict(int)
    })
    bins_1ms = defaultdict(lambda: {
        'timestamp': None, 'src_ip': None, 'dst_ip': None,
        'count': 0, 'total_bytes': 0, 'flag_counts': defaultdict(int)
    })

    # Raw packet buffer
    raw_packet_buffer = []

    # Per-resolution chunk counters and indices
    chunk_hours_counter = 0;   chunk_hours_index = []
    chunk_minutes_counter = 0; chunk_minutes_index = []
    chunk_10s_counter = 0;     chunk_10s_index = []
    chunk_seconds_counter = 0; chunk_seconds_index = []
    chunk_100ms_counter = 0;   chunk_100ms_index = []
    chunk_10ms_counter = 0;    chunk_10ms_index = []
    chunk_1ms_counter = 0;     chunk_1ms_index = []
    raw_chunk_counter = 0;     raw_chunk_index = []

    # Per-resolution probe gating: only attempt a size probe once `next_probe_*`
    # bins have accumulated. After a probe (whether or not it flushes) the
    # gate is updated to require another `probe_every` of growth.
    next_probe_hours   = probe_every
    next_probe_minutes = probe_every
    next_probe_10s     = probe_every
    next_probe_seconds = probe_every
    next_probe_100ms   = probe_every
    next_probe_10ms    = probe_every
    next_probe_1ms     = probe_every
    next_probe_raw     = probe_every

    total_packets = 0
    missing_protocol_count = 0
    chunk_number = 0
    unique_ips = set()
    all_timestamps = []

    # Helper function to convert IP columns
    def _convert_ip_column(df_chunk, col_name):
        if col_name not in df_chunk.columns:
            return
        series = df_chunk[col_name]
        if series.dtype == object:
            mask_numeric_like = series.str.fullmatch(r'\d+')
            if mask_numeric_like is not None and mask_numeric_like.any():
                numeric = pd.to_numeric(series.where(mask_numeric_like), errors='coerce')
                mapped = []
                for v in numeric:
                    if pd.isna(v):
                        mapped.append('')
                        continue
                    ival = int(v)
                    mapped.append(int_to_ip.get(ival, str(ival)))
                series = series.mask(mask_numeric_like, pd.Series(mapped, index=series.index))
            df_chunk[col_name] = series.fillna('').astype(str)
            return
        if series.dtype.kind in 'fi':
            numeric = pd.to_numeric(series, errors='coerce')
            out = []
            for v in numeric:
                if pd.isna(v):
                    out.append('')
                    continue
                ival = int(v)
                out.append(int_to_ip.get(ival, str(ival)))
            df_chunk[col_name] = pd.Series(out, index=series.index).fillna('').astype(str)
        else:
            df_chunk[col_name] = series.astype(str).fillna('')

    # Process CSV in chunks
    try:
        compression = 'gzip' if data_file.endswith('.gz') else None
        csv_iterator = pd.read_csv(data_file, chunksize=chunk_read_size, compression=compression)

        for df_chunk in csv_iterator:
            chunk_number += 1

            # Robust timestamp cleaning
            if 'timestamp' in df_chunk.columns:
                df_chunk['timestamp'] = pd.to_numeric(df_chunk['timestamp'], errors='coerce')
                df_chunk = df_chunk[df_chunk['timestamp'].notna() & np.isfinite(df_chunk['timestamp'])]

            # Convert integer IPs to dotted notation
            _convert_ip_column(df_chunk, 'src_ip')
            _convert_ip_column(df_chunk, 'dst_ip')

            # Process flags. Non-TCP packets are labeled by protocol instead of
            # being TCP-flag-classified (see classify_protocol_flags).
            if 'flags' in df_chunk.columns:
                if 'protocol' in df_chunk.columns:
                    df_chunk['flag_type'] = [
                        classify_protocol_flags(f, p)
                        for f, p in zip(df_chunk['flags'].to_numpy(),
                                        df_chunk['protocol'].to_numpy())
                    ]
                else:
                    # No protocol column: preserve prior behavior (TCP-flag only).
                    df_chunk['flag_type'] = df_chunk['flags'].apply(classify_tcp_flags)

            # Convert chunk to list of dictionaries
            chunk_records = []
            for _, row in df_chunk.iterrows():
                # Protocol: flag missing/invalid, do not fabricate.
                _proto_raw = row.get('protocol', None)
                _proto_missing = False
                try:
                    if _proto_raw is None or pd.isna(_proto_raw):
                        _proto_missing = True
                except Exception:
                    _proto_missing = False
                if not _proto_missing and isinstance(_proto_raw, str) and _proto_raw.strip() == '':
                    _proto_missing = True
                if _proto_missing:
                    protocol = None
                    missing_protocol_count += 1
                else:
                    try:
                        protocol = int(_proto_raw)
                    except Exception:
                        protocol = None
                        missing_protocol_count += 1

                record = {
                    'timestamp': _safe_int(row.get('timestamp', 0), 0),
                    'src_ip': str(row.get('src_ip', '')),
                    'dst_ip': str(row.get('dst_ip', '')),
                    'src_port': _safe_int(row.get('src_port', 0), 0),
                    'dst_port': _safe_int(row.get('dst_port', 0), 0),
                    'flags': _safe_int(row.get('flags', 0), 0),
                    'flag_type': row.get('flag_type', 'UNKNOWN'),
                    'length': _safe_int(row.get('length', 0), 0),
                    'protocol': protocol,
                }
                chunk_records.append(record)

            # Apply max_records limit
            if max_records and total_packets + len(chunk_records) > max_records:
                chunk_records = chunk_records[:max_records - total_packets]

            total_packets += len(chunk_records)

            # Update unique IPs and timestamps
            unique_ips.update([r['src_ip'] for r in chunk_records])
            unique_ips.update([r['dst_ip'] for r in chunk_records])
            all_timestamps.extend([r['timestamp'] for r in chunk_records])

            # Multi-resolution processing
            for pkt in chunk_records:
                ts = pkt['timestamp']
                src_ip = pkt['src_ip']
                dst_ip = pkt['dst_ip']
                flag_type = pkt.get('flag_type', 'UNKNOWN')
                length = pkt.get('length', 0)
                src_port = pkt.get('src_port', 0)
                dst_port = pkt.get('dst_port', 0)

                hour_bin = (ts // 3_600_000_000) * 3_600_000_000
                hr_key = (hour_bin, src_ip, dst_ip, flag_type)
                hb = hour_bins[hr_key]
                if hb['timestamp'] is None:
                    hb['timestamp'] = hour_bin
                    hb['src_ip'] = src_ip
                    hb['dst_ip'] = dst_ip
                    hb['flag_type'] = flag_type
                hb['count'] += 1
                hb['total_bytes'] += length
                hb['flag_counts'][flag_type] += 1

                minute_bin = (ts // 60_000_000) * 60_000_000
                min_key = (minute_bin, src_ip, dst_ip, flag_type)
                mb = minute_bins[min_key]
                if mb['timestamp'] is None:
                    mb['timestamp'] = minute_bin
                    mb['src_ip'] = src_ip
                    mb['dst_ip'] = dst_ip
                    mb['flag_type'] = flag_type
                mb['count'] += 1
                mb['total_bytes'] += length
                mb['flag_counts'][flag_type] += 1

                tensecond_bin = (ts // 10_000_000) * 10_000_000
                ts_key = (tensecond_bin, src_ip, dst_ip, flag_type)
                tsb = tensecond_bins[ts_key]
                if tsb['timestamp'] is None:
                    tsb['timestamp'] = tensecond_bin
                    tsb['src_ip'] = src_ip
                    tsb['dst_ip'] = dst_ip
                    tsb['flag_type'] = flag_type
                tsb['count'] += 1
                tsb['total_bytes'] += length
                tsb['flag_counts'][flag_type] += 1

                second_bin = (ts // 1_000_000) * 1_000_000
                sec_key = (second_bin, src_ip, dst_ip, flag_type)
                sb = second_bins[sec_key]
                if sb['timestamp'] is None:
                    sb['timestamp'] = second_bin
                    sb['src_ip'] = src_ip
                    sb['dst_ip'] = dst_ip
                    sb['flag_type'] = flag_type
                sb['count'] += 1
                sb['total_bytes'] += length
                sb['flag_counts'][flag_type] += 1

                bin_100ms = (ts // 100_000) * 100_000
                key_100ms = (bin_100ms, src_ip, dst_ip, flag_type)
                b100 = bins_100ms[key_100ms]
                if b100['timestamp'] is None:
                    b100['timestamp'] = bin_100ms
                    b100['src_ip'] = src_ip
                    b100['dst_ip'] = dst_ip
                    b100['flag_type'] = flag_type
                b100['count'] += 1
                b100['total_bytes'] += length
                b100['flag_counts'][flag_type] += 1

                bin_10ms = (ts // 10_000) * 10_000
                key_10ms = (bin_10ms, src_ip, dst_ip, flag_type)
                b10 = bins_10ms[key_10ms]
                if b10['timestamp'] is None:
                    b10['timestamp'] = bin_10ms
                    b10['src_ip'] = src_ip
                    b10['dst_ip'] = dst_ip
                    b10['flag_type'] = flag_type
                b10['count'] += 1
                b10['total_bytes'] += length
                b10['flag_counts'][flag_type] += 1

                bin_1ms = (ts // 1_000) * 1_000
                key_1ms = (bin_1ms, src_ip, dst_ip, flag_type)
                b1 = bins_1ms[key_1ms]
                if b1['timestamp'] is None:
                    b1['timestamp'] = bin_1ms
                    b1['src_ip'] = src_ip
                    b1['dst_ip'] = dst_ip
                    b1['flag_type'] = flag_type
                b1['count'] += 1
                b1['total_bytes'] += length
                b1['flag_counts'][flag_type] += 1

                raw_packet_buffer.append(pkt)

            # Size-based probe + flush for each resolution. After every probe
            # (flush or no-flush) the gate is bumped by `probe_every` so we
            # don't re-probe on every CSV chunk for slow-growing resolutions.
            if len(hour_bins) >= next_probe_hours:
                chunk_hours_counter, flushed = _maybe_flush_bins(
                    hour_bins, resolutions_dir / 'hours',
                    chunk_hours_counter, chunk_hours_index, target_bytes, 'hours')
                next_probe_hours = (probe_every if flushed
                                    else len(hour_bins) + probe_every)

            if len(minute_bins) >= next_probe_minutes:
                chunk_minutes_counter, flushed = _maybe_flush_bins(
                    minute_bins, resolutions_dir / 'minutes',
                    chunk_minutes_counter, chunk_minutes_index, target_bytes, 'minutes')
                next_probe_minutes = (probe_every if flushed
                                      else len(minute_bins) + probe_every)

            if len(tensecond_bins) >= next_probe_10s:
                chunk_10s_counter, flushed = _maybe_flush_bins(
                    tensecond_bins, resolutions_dir / '10s',
                    chunk_10s_counter, chunk_10s_index, target_bytes, '10s')
                next_probe_10s = (probe_every if flushed
                                  else len(tensecond_bins) + probe_every)

            if len(second_bins) >= next_probe_seconds:
                chunk_seconds_counter, flushed = _maybe_flush_bins(
                    second_bins, resolutions_dir / 'seconds',
                    chunk_seconds_counter, chunk_seconds_index, target_bytes, 'seconds')
                next_probe_seconds = (probe_every if flushed
                                      else len(second_bins) + probe_every)

            if len(bins_100ms) >= next_probe_100ms:
                chunk_100ms_counter, flushed = _maybe_flush_bins(
                    bins_100ms, resolutions_dir / '100ms',
                    chunk_100ms_counter, chunk_100ms_index, target_bytes, '100ms')
                next_probe_100ms = (probe_every if flushed
                                    else len(bins_100ms) + probe_every)

            if len(bins_10ms) >= next_probe_10ms:
                chunk_10ms_counter, flushed = _maybe_flush_bins(
                    bins_10ms, resolutions_dir / '10ms',
                    chunk_10ms_counter, chunk_10ms_index, target_bytes, '10ms')
                next_probe_10ms = (probe_every if flushed
                                   else len(bins_10ms) + probe_every)

            if len(bins_1ms) >= next_probe_1ms:
                chunk_1ms_counter, flushed = _maybe_flush_bins(
                    bins_1ms, resolutions_dir / '1ms',
                    chunk_1ms_counter, chunk_1ms_index, target_bytes, '1ms')
                next_probe_1ms = (probe_every if flushed
                                  else len(bins_1ms) + probe_every)

            if len(raw_packet_buffer) >= next_probe_raw:
                raw_chunk_counter, raw_packet_buffer, flushed = _maybe_flush_raw(
                    raw_packet_buffer, resolutions_dir / 'raw',
                    raw_chunk_counter, raw_chunk_index, target_bytes)
                next_probe_raw = (probe_every if flushed
                                  else len(raw_packet_buffer) + probe_every)

            print(f"Chunk {chunk_number}: processed {len(chunk_records):,} packets, total: {total_packets:,}")

            # Check if we've reached max_records limit
            if max_records and total_packets >= max_records:
                print(f"Reached max_records limit of {max_records:,}")
                break

    except Exception as e:
        print(f"Error reading CSV: {e}", file=sys.stderr)
        raise

    # Finalize multi-resolution outputs — force-flush whatever is left.
    print(f"\nFinalizing multi-resolution outputs...")

    raw_chunk_counter, raw_packet_buffer, _ = _maybe_flush_raw(
        raw_packet_buffer, resolutions_dir / 'raw',
        raw_chunk_counter, raw_chunk_index, target_bytes, force=True)

    chunk_100ms_counter, _ = _maybe_flush_bins(
        bins_100ms, resolutions_dir / '100ms',
        chunk_100ms_counter, chunk_100ms_index, target_bytes, '100ms', force=True)

    chunk_10ms_counter, _ = _maybe_flush_bins(
        bins_10ms, resolutions_dir / '10ms',
        chunk_10ms_counter, chunk_10ms_index, target_bytes, '10ms', force=True)

    chunk_1ms_counter, _ = _maybe_flush_bins(
        bins_1ms, resolutions_dir / '1ms',
        chunk_1ms_counter, chunk_1ms_index, target_bytes, '1ms', force=True)

    chunk_hours_counter, _ = _maybe_flush_bins(
        hour_bins, resolutions_dir / 'hours',
        chunk_hours_counter, chunk_hours_index, target_bytes, 'hours', force=True)

    chunk_minutes_counter, _ = _maybe_flush_bins(
        minute_bins, resolutions_dir / 'minutes',
        chunk_minutes_counter, chunk_minutes_index, target_bytes, 'minutes', force=True)

    chunk_10s_counter, _ = _maybe_flush_bins(
        tensecond_bins, resolutions_dir / '10s',
        chunk_10s_counter, chunk_10s_index, target_bytes, '10s', force=True)

    chunk_seconds_counter, _ = _maybe_flush_bins(
        second_bins, resolutions_dir / 'seconds',
        chunk_seconds_counter, chunk_seconds_index, target_bytes, 'seconds', force=True)

    # Write per-resolution index.json files
    def _write_index(dirpath, resolution_label, resolution_us, chunk_index):
        index_path = dirpath / 'index.json'
        index_data = {
            'resolution': resolution_label,
            'resolution_microseconds': resolution_us,
            'total_count': sum(c['count'] for c in chunk_index),
            'time_range': {
                'start': int(chunk_index[0]['start']) if chunk_index else 0,
                'end':   int(chunk_index[-1]['end'])   if chunk_index else 0,
            },
            'chunks': chunk_index,
        }
        with open(index_path, 'w') as f:
            json.dump(index_data, f, indent=2)
        print(f"  {resolution_label}: {len(chunk_index)} chunks, "
              f"{index_data['total_count']} total bins/packets")
        return index_data

    raw_index_data       = _write_index(resolutions_dir / 'raw',     'raw',     1,             raw_chunk_index)
    index_data_100ms     = _write_index(resolutions_dir / '100ms',   '100ms',   100_000,       chunk_100ms_index)
    index_data_10ms      = _write_index(resolutions_dir / '10ms',    '10ms',    10_000,        chunk_10ms_index)
    index_data_1ms       = _write_index(resolutions_dir / '1ms',     '1ms',     1_000,         chunk_1ms_index)
    hr_index_data        = _write_index(resolutions_dir / 'hours',   'hours',   3_600_000_000, chunk_hours_index)
    min_index_data       = _write_index(resolutions_dir / 'minutes', 'minutes', 60_000_000,    chunk_minutes_index)
    tensec_index_data    = _write_index(resolutions_dir / '10s',     '10s',     10_000_000,    chunk_10s_index)
    sec_index_data       = _write_index(resolutions_dir / 'seconds', 'seconds', 1_000_000,     chunk_seconds_index)

    # Calculate time range
    time_start = min(all_timestamps) if all_timestamps else 0
    time_end = max(all_timestamps) if all_timestamps else 0

    # Save manifest.json
    manifest = {
        'version': '3.5',
        'format': 'multires_packets',
        'created': pd.Timestamp.now().isoformat(),
        'source_file': str(data_file),
        'total_packets': total_packets,
        'missing_protocol_count': missing_protocol_count,
        'unique_ips': len(unique_ips),
        'target_chunk_mb': target_chunk_mb,
        'time_range': {
            'start': int(time_start),
            'end': int(time_end),
            'duration': int(time_end - time_start)
        },
        'resolutions': {
            'hours': {
                'resolution_microseconds': 3_600_000_000,
                'total_bins': hr_index_data['total_count'],
                'total_chunks': len(chunk_hours_index),
                'index': 'resolutions/hours/index.json'
            },
            'minutes': {
                'resolution_microseconds': 60_000_000,
                'total_bins': min_index_data['total_count'],
                'total_chunks': len(chunk_minutes_index),
                'index': 'resolutions/minutes/index.json'
            },
            '10s': {
                'resolution_microseconds': 10_000_000,
                'total_bins': tensec_index_data['total_count'],
                'total_chunks': len(chunk_10s_index),
                'index': 'resolutions/10s/index.json'
            },
            'seconds': {
                'resolution_microseconds': 1_000_000,
                'total_bins': sec_index_data['total_count'],
                'total_chunks': len(chunk_seconds_index),
                'index': 'resolutions/seconds/index.json'
            },
            '100ms': {
                'resolution_microseconds': 100_000,
                'total_bins': index_data_100ms['total_count'],
                'total_chunks': len(chunk_100ms_index),
                'index': 'resolutions/100ms/index.json'
            },
            '10ms': {
                'resolution_microseconds': 10_000,
                'total_bins': index_data_10ms['total_count'],
                'total_chunks': len(chunk_10ms_index),
                'index': 'resolutions/10ms/index.json'
            },
            '1ms': {
                'resolution_microseconds': 1_000,
                'total_bins': index_data_1ms['total_count'],
                'total_chunks': len(chunk_1ms_index),
                'index': 'resolutions/1ms/index.json'
            },
            'raw': {
                'resolution_microseconds': 1,
                'total_packets': raw_index_data['total_count'],
                'total_chunks': len(raw_chunk_index),
                'index': 'resolutions/raw/index.json'
            }
        }
    }

    print(f"Saving manifest to {output_path / 'manifest.json'}...")
    with open(output_path / 'manifest.json', 'w') as f:
        json.dump(manifest, f, indent=2)

    print(f"WARNING: {missing_protocol_count} packets had a missing/invalid protocol field (stored as null)")

    print(f"\nSuccessfully processed data:")
    print(f"  - Total packets: {total_packets:,}")
    print(f"  - Unique IPs: {len(unique_ips):,}")
    print(f"  - Time range: {time_start} to {time_end}")
    print(f"  - Hours chunks: {len(chunk_hours_index)}")
    print(f"  - Minutes chunks: {len(chunk_minutes_index)}")
    print(f"  - 10s chunks: {len(chunk_10s_index)}")
    print(f"  - Seconds chunks: {len(chunk_seconds_index)}")
    print(f"  - 100ms chunks: {len(chunk_100ms_index)}")
    print(f"  - 10ms chunks: {len(chunk_10ms_index)}")
    print(f"  - 1ms chunks: {len(chunk_1ms_index)}")
    print(f"  - Raw chunks: {len(raw_chunk_index)}")
    print(f"  - Output directory: {output_path}")

    return {
        'output_dir': str(output_path),
        'total_packets': total_packets,
        'unique_ips': len(unique_ips),
        'manifest': manifest
    }

def main():
    parser = argparse.ArgumentParser(
        description='Generate multi-resolution packet data (hours, minutes, 10s, seconds, 100ms, 10ms, 1ms, raw) in Parquet format. '
                    'Chunks are flushed to disk when their serialized Parquet size reaches --target-chunk-mb. '
                    'No flow detection - pure packet-level output.')
    parser.add_argument('--data', required=True,
                       help='Input TCP data file (CSV or CSV.GZ)')
    parser.add_argument('--ip-map', required=True, help='IP mapping JSON file')
    parser.add_argument('--output-dir', required=True, help='Output directory')
    parser.add_argument('--max-records', type=int, help='Maximum number of records to process')
    parser.add_argument('--chunk-read-size', type=int, default=500000,
                       help='Number of CSV rows to read per chunk (default: 500000)')
    parser.add_argument('--target-chunk-mb', type=float, default=50.0,
                       help='Target output chunk file size in MB (default: 50.0)')
    parser.add_argument('--probe-every', type=int, default=200000,
                       help='Bins/packets accumulated between size probes (default: 200000). '
                            'Lower = tighter size cap but more serialization overhead.')

    args = parser.parse_args()

    # Check if input files exist
    if not Path(args.data).exists():
        print(f"Error: Data file '{args.data}' not found", file=sys.stderr)
        sys.exit(1)

    if not Path(args.ip_map).exists():
        print(f"Error: IP mapping file '{args.ip_map}' not found", file=sys.stderr)
        sys.exit(1)

    try:
        process_multires_packets(args.data, args.ip_map, args.output_dir,
                                  args.max_records, args.chunk_read_size,
                                  args.target_chunk_mb, args.probe_every)
    except Exception as e:
        print(f"Error processing data: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
