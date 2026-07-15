// src/data/bin-columns.tcpflow.js
// Columnar storage for parquet-loaded packet bin data — used only by
// tcp-flow-analysis.js. Replaces the array-of-objects shape that turns
// 50 MB of parquet into 1.5 GB of JS heap.
//
// Layout:
//   timestamps  : Float64Array(n)
//   srcIpIds    : Uint32Array(n)   -> ipDict[id]
//   dstIpIds    : Uint32Array(n)   -> ipDict[id]
//   counts      : Uint32Array(n)
//   totalBytes  : Uint32Array(n)
//   flagIds     : Uint8Array(n)    -> flagDict[id]
//
// Total per-row: 8+4+4+4+4+1 = 25 bytes typed-array storage, plus tiny
// shared dictionaries. For 8.2M rows that's ~200 MB instead of ~1.5 GB.
//
// API:
//   .length                          number of rows
//   .row(i)                          materialize a row-shaped plain object
//   .forEach(fn)                     fn(rowSnapshot, i) — fresh object per call
//   .filter(fn)                      returns a new BinColumns subset
//   .map(fn)                         returns a plain Array (escapes columns)
//   for (const r of cols) { ... }    yields fresh row objects
//   .srcIp(i), .dstIp(i), .flagType(i), .timestamp(i), .count(i),
//   .totalBytes(i), .binCenter(i), .binStart(i), .binEnd(i)
//                                    direct column access for hot paths

const ROW_PROTO_FIELDS = [
    'src_ip', 'dst_ip', 'timestamp', 'count', 'total_bytes', 'flag_type',
    'flagType', 'binned', 'binStart', 'binEnd', 'binCenter',
    'length', 'preBinnedSize', 'resolution'
];

export class BinColumns {
    constructor({
        length,
        timestamps,
        srcIpIds,
        dstIpIds,
        counts,
        totalBytes,
        flagIds,
        ipDict,
        flagDict,
        binSize,
        resolution
    }) {
        this.length      = length;
        this.timestamps  = timestamps;
        this.srcIpIds    = srcIpIds;
        this.dstIpIds    = dstIpIds;
        this.counts      = counts;
        this.totalBytes  = totalBytes;
        this.flagIds     = flagIds;
        this.ipDict      = ipDict;
        this.flagDict    = flagDict;
        this.binSize     = binSize;
        this.halfBinSize = Math.floor(binSize / 2);
        this.resolution  = resolution;
        // Marker so consumers can branch on shape without instanceof imports.
        this.__isBinColumns = true;
        // Lazily-built reverse index for fast `ipDict[id] -> id` lookups.
        this._ipIndex = null;
    }

    _buildIpIndex() {
        const m = new Map();
        for (let i = 0; i < this.ipDict.length; i++) m.set(this.ipDict[i], i);
        this._ipIndex = m;
    }

    /** Numeric ID for an IP string, or -1 if absent. O(1) after first call. */
    ipIdOf(ip) {
        if (!this._ipIndex) this._buildIpIndex();
        const v = this._ipIndex.get(ip);
        return v === undefined ? -1 : v;
    }

    /**
     * Filter to rows whose src_ip OR dst_ip is in the given Set of IP strings.
     * Column-aware — never materializes row objects, so it's safe to call on
     * 8 M-row tables.
     */
    filterByIpRowSet(ipStringSet) {
        if (!ipStringSet) return this;
        const ids = new Set();
        for (const ip of ipStringSet) {
            const id = this.ipIdOf(ip);
            if (id >= 0) ids.add(id);
        }
        if (ids.size === 0) return this._subset(new Uint32Array(0));
        const n = this.length;
        const keep = new Uint32Array(n);
        let m = 0;
        const sip = this.srcIpIds, dip = this.dstIpIds;
        for (let i = 0; i < n; i++) {
            if (ids.has(sip[i]) || ids.has(dip[i])) keep[m++] = i;
        }
        if (m === n) return this;
        return this._subset(keep.subarray(0, m));
    }

    /**
     * Column-aware filter by time range. Uses the timestamps Float64Array
     * directly — never materializes row objects.
     */
    filterByTimeRange(start, end) {
        const ts = this.timestamps;
        const n = this.length;
        const keep = new Uint32Array(n);
        let m = 0;
        for (let i = 0; i < n; i++) {
            const t = ts[i];
            if (t >= start && t <= end) keep[m++] = i;
        }
        if (m === n) return this;
        return this._subset(keep.subarray(0, m));
    }

    /**
     * Column-aware filter requiring BOTH src_ip AND dst_ip to be in the
     * given Set of IP strings (used for selected-IP-pair filtering).
     */
    filterByIpPair(ipStringSet) {
        if (!ipStringSet || ipStringSet.size < 2) return this._subset(new Uint32Array(0));
        const ids = new Set();
        for (const ip of ipStringSet) {
            const id = this.ipIdOf(ip);
            if (id >= 0) ids.add(id);
        }
        if (ids.size < 2) return this._subset(new Uint32Array(0));
        const n = this.length;
        const keep = new Uint32Array(n);
        const sip = this.srcIpIds, dip = this.dstIpIds;
        let m = 0;
        for (let i = 0; i < n; i++) {
            if (ids.has(sip[i]) && ids.has(dip[i])) keep[m++] = i;
        }
        if (m === n) return this;
        return this._subset(keep.subarray(0, m));
    }

    /**
     * Materialize all rows as a plain Array. Use only after column-aware
     * filtering has reduced the size to something manageable.
     */
    toRowArray() {
        const out = new Array(this.length);
        for (let i = 0; i < this.length; i++) out[i] = this.row(i);
        return out;
    }

    flatMap(fn) {
        const out = [];
        for (let i = 0; i < this.length; i++) {
            const v = fn(this.row(i), i);
            if (Array.isArray(v)) {
                for (let j = 0; j < v.length; j++) out.push(v[j]);
            } else {
                out.push(v);
            }
        }
        return out;
    }

    // ===== Direct column access (hot paths) =====
    srcIp(i)      { return this.ipDict[this.srcIpIds[i]]; }
    dstIp(i)      { return this.ipDict[this.dstIpIds[i]]; }
    flagType(i)   { return this.flagDict[this.flagIds[i]]; }
    timestamp(i)  { return this.timestamps[i]; }
    count(i)      { return this.counts[i]; }
    totalByte(i)  { return this.totalBytes[i]; }
    binStart(i)   { return this.timestamps[i]; }
    binEnd(i)     { return this.timestamps[i] + this.binSize; }
    binCenter(i)  { return this.timestamps[i] + this.halfBinSize; }

    // ===== Array-like compatibility =====

    /**
     * Materialize one row as a plain object. Allocates — only call when
     * downstream code needs an actual JS object reference.
     */
    row(i) {
        const ts = this.timestamps[i];
        const flag = this.flagDict[this.flagIds[i]];
        const tb = this.totalBytes[i];
        const binEnd = ts + this.binSize;
        return {
            src_ip:        this.ipDict[this.srcIpIds[i]],
            dst_ip:        this.ipDict[this.dstIpIds[i]],
            timestamp:     ts,
            count:         this.counts[i],
            total_bytes:   tb,
            flag_type:     flag,
            flagType:      flag,
            binned:        true,
            binStart:      ts,
            bin_start:     ts,
            binEnd,
            bin_end:       binEnd,
            binCenter:     ts + this.halfBinSize,
            length:        tb,
            preBinnedSize: this.binSize,
            resolution:    this.resolution
        };
    }

    *[Symbol.iterator]() {
        for (let i = 0; i < this.length; i++) yield this.row(i);
    }

    forEach(fn) {
        for (let i = 0; i < this.length; i++) fn(this.row(i), i);
    }

    /**
     * Returns a new BinColumns containing only rows where fn(row, i) is truthy.
     * fn receives a *fresh row object* per call — do not retain.
     */
    filter(fn) {
        const n = this.length;
        // First pass: collect indices.
        const keep = new Uint32Array(n); // upper bound; trim after
        let m = 0;
        for (let i = 0; i < n; i++) {
            if (fn(this.row(i), i)) keep[m++] = i;
        }
        if (m === n) return this; // nothing dropped
        return this._subset(keep.subarray(0, m));
    }

    /**
     * Returns a regular Array of mapped values — escapes columnar layout.
     * Use sparingly.
     */
    map(fn) {
        const out = new Array(this.length);
        for (let i = 0; i < this.length; i++) out[i] = fn(this.row(i), i);
        return out;
    }

    /**
     * Build a new BinColumns from this one keeping only rows at the given
     * indices (Uint32Array). Reuses the same shared dictionaries — no
     * string copying.
     */
    _subset(indices) {
        const m = indices.length;
        const ts  = new Float64Array(m);
        const sip = new Uint32Array(m);
        const dip = new Uint32Array(m);
        const cnt = new Uint32Array(m);
        const tb  = new Uint32Array(m);
        const fl  = new Uint8Array(m);
        for (let k = 0; k < m; k++) {
            const i = indices[k];
            ts[k]  = this.timestamps[i];
            sip[k] = this.srcIpIds[i];
            dip[k] = this.dstIpIds[i];
            cnt[k] = this.counts[i];
            tb[k]  = this.totalBytes[i];
            fl[k]  = this.flagIds[i];
        }
        return new BinColumns({
            length: m,
            timestamps: ts,
            srcIpIds: sip,
            dstIpIds: dip,
            counts: cnt,
            totalBytes: tb,
            flagIds: fl,
            ipDict: this.ipDict,
            flagDict: this.flagDict,
            binSize: this.binSize,
            resolution: this.resolution
        });
    }

    /**
     * Concatenate multiple BinColumns into one. Dictionaries from later
     * sources are remapped onto the first source's dict.
     */
    static concat(parts) {
        parts = parts.filter(p => p && p.length > 0);
        if (parts.length === 0) return BinColumns.empty();
        if (parts.length === 1) return parts[0];

        // Use the first part's dicts as the canonical ones; build remap tables
        // for subsequent parts.
        const first = parts[0];
        const ipDict = first.ipDict.slice();
        const ipIndex = new Map();
        for (let i = 0; i < ipDict.length; i++) ipIndex.set(ipDict[i], i);
        const flagDict = first.flagDict.slice();
        const flagIndex = new Map();
        for (let i = 0; i < flagDict.length; i++) flagIndex.set(flagDict[i], i);

        let total = 0;
        for (const p of parts) total += p.length;

        const ts  = new Float64Array(total);
        const sip = new Uint32Array(total);
        const dip = new Uint32Array(total);
        const cnt = new Uint32Array(total);
        const tb  = new Uint32Array(total);
        const fl  = new Uint8Array(total);

        let off = 0;
        for (const p of parts) {
            // Build remap from p's dict to canonical dict.
            const ipRemap = new Uint32Array(p.ipDict.length);
            for (let i = 0; i < p.ipDict.length; i++) {
                const s = p.ipDict[i];
                let id = ipIndex.get(s);
                if (id === undefined) { id = ipDict.length; ipDict.push(s); ipIndex.set(s, id); }
                ipRemap[i] = id;
            }
            const flagRemap = new Uint8Array(p.flagDict.length);
            for (let i = 0; i < p.flagDict.length; i++) {
                const s = p.flagDict[i];
                let id = flagIndex.get(s);
                if (id === undefined) { id = flagDict.length; flagDict.push(s); flagIndex.set(s, id); }
                flagRemap[i] = id;
            }
            const n = p.length;
            for (let i = 0; i < n; i++) {
                ts[off + i]  = p.timestamps[i];
                sip[off + i] = ipRemap[p.srcIpIds[i]];
                dip[off + i] = ipRemap[p.dstIpIds[i]];
                cnt[off + i] = p.counts[i];
                tb[off + i]  = p.totalBytes[i];
                fl[off + i]  = flagRemap[p.flagIds[i]];
            }
            off += n;
        }

        return new BinColumns({
            length: total,
            timestamps: ts,
            srcIpIds: sip,
            dstIpIds: dip,
            counts: cnt,
            totalBytes: tb,
            flagIds: fl,
            ipDict,
            flagDict,
            binSize: first.binSize,
            resolution: first.resolution
        });
    }

    static empty() {
        return new BinColumns({
            length: 0,
            timestamps: new Float64Array(0),
            srcIpIds: new Uint32Array(0),
            dstIpIds: new Uint32Array(0),
            counts: new Uint32Array(0),
            totalBytes: new Uint32Array(0),
            flagIds: new Uint8Array(0),
            ipDict: [],
            flagDict: ['OTHER'],
            binSize: 1,
            resolution: 'unknown'
        });
    }

    /**
     * Build a BinColumns from an array of plain row objects. Used by callers
     * that already have row arrays (CSV path, in-memory tests).
     */
    static fromRows(rows, { binSize = 60_000_000, resolution = 'minutes' } = {}) {
        const n = rows.length;
        const ts  = new Float64Array(n);
        const sip = new Uint32Array(n);
        const dip = new Uint32Array(n);
        const cnt = new Uint32Array(n);
        const tb  = new Uint32Array(n);
        const fl  = new Uint8Array(n);
        const ipDict = [];
        const ipIndex = new Map();
        const flagDict = [];
        const flagIndex = new Map();
        const internIp = (s) => {
            let id = ipIndex.get(s);
            if (id === undefined) { id = ipDict.length; ipDict.push(s); ipIndex.set(s, id); }
            return id;
        };
        const internFlag = (s) => {
            let id = flagIndex.get(s);
            if (id === undefined) { id = flagDict.length; flagDict.push(s); flagIndex.set(s, id); }
            return id;
        };
        for (let i = 0; i < n; i++) {
            const r = rows[i];
            ts[i]  = +r.timestamp || +r.binStart || 0;
            sip[i] = internIp(String(r.src_ip || ''));
            dip[i] = internIp(String(r.dst_ip || ''));
            cnt[i] = +r.count || 0;
            tb[i]  = +r.total_bytes || 0;
            fl[i]  = internFlag(String(r.flag_type || r.flagType || 'OTHER'));
        }
        return new BinColumns({
            length: n,
            timestamps: ts,
            srcIpIds: sip,
            dstIpIds: dip,
            counts: cnt,
            totalBytes: tb,
            flagIds: fl,
            ipDict,
            flagDict,
            binSize,
            resolution
        });
    }
}

/**
 * Quick check used at branch points throughout tcp-flow-analysis.js.
 * Works through Proxy too (the proxy forwards property reads to the target).
 */
export function isBinColumns(x) {
    return !!(x && x.__isBinColumns === true);
}

/**
 * Wrap a BinColumns in a Proxy so `cols[i]` materializes a row on demand.
 * This is the minimal compatibility shim for shared code that uses indexed
 * access on packet arrays. Slower than direct access (proxy traps every
 * read), but only a small set of hot loops use `[i]` — most code goes
 * through `for-of`, `.length`, `.filter`, etc., which all bypass the trap.
 *
 * The wrapped value still passes `isBinColumns()` and exposes every method
 * and column array of the underlying instance.
 */
export function asArrayLike(cols) {
    return new Proxy(cols, {
        get(target, prop, receiver) {
            if (typeof prop === 'string') {
                // Hot path: numeric index → row materialization
                const code = prop.charCodeAt(0);
                if (code >= 48 && code <= 57) { // starts with digit
                    const n = +prop;
                    if (Number.isInteger(n) && n >= 0 && n < target.length) {
                        return target.row(n);
                    }
                }
            }
            return Reflect.get(target, prop, target);
        },
        has(target, prop) {
            if (typeof prop === 'string') {
                const code = prop.charCodeAt(0);
                if (code >= 48 && code <= 57) {
                    const n = +prop;
                    if (Number.isInteger(n) && n >= 0 && n < target.length) return true;
                }
            }
            return Reflect.has(target, prop);
        }
    });
}
