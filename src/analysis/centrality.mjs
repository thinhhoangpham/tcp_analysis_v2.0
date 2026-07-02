// src/analysis/centrality.mjs
// Pure-JS graph-analysis (centrality) measures for the region-cola graph.
// Directed, unweighted. Edge list uses integer node indices: { s, t }.
// Reimplements the measures ReGraph documents (Degrees, Betweenness,
// Closeness, Eigencentrality, PageRank) with no external dependency.

// Build directed out-adjacency, in/out degree counts, and a symmetric
// (undirected) neighbor-set list. Self-loops (s === t) are ignored.
export function buildAdjacency(n, links) {
    const out = Array.from({ length: n }, () => []);
    const outdeg = new Int32Array(n);
    const indeg = new Int32Array(n);
    const undirSet = Array.from({ length: n }, () => new Set());
    for (const lk of links) {
        const s = lk.s, t = lk.t;
        if (s === t) continue;
        out[s].push(t);
        outdeg[s]++;
        indeg[t]++;
        undirSet[s].add(t);
        undirSet[t].add(s);
    }
    const undirected = undirSet.map(set => [...set]);
    return { out, outdeg, indeg, undirected };
}

// Total degree = in-degree + out-degree.
export function degrees(n, adj) {
    const deg = new Int32Array(n);
    for (let v = 0; v < n; v++) deg[v] = adj.indeg[v] + adj.outdeg[v];
    return deg;
}

// Brandes' algorithm (directed, unweighted) — accumulates betweenness, and
// folds component-normalized closeness into the same BFS pass (each source's
// BFS already yields distances + reachable count).
//
// Per-source state is reused across sources: full-array resets are O(n) per
// source (O(n^2) total — negligible next to the BFS edge work), and the
// predecessor lists P[w] are cleared lazily as each node is discovered.
export function brandes(n, out) {
    const btw = new Float64Array(n);
    const clo = new Float64Array(n);
    const sigma = new Float64Array(n);
    const dist = new Int32Array(n);
    const delta = new Float64Array(n);
    const P = Array.from({ length: n }, () => []); // predecessors, reused
    const Q = new Int32Array(n);                   // BFS queue
    const S = new Int32Array(n);                   // BFS visitation order (stack)

    for (let s = 0; s < n; s++) {
        dist.fill(-1);
        sigma.fill(0);
        delta.fill(0);
        sigma[s] = 1;
        dist[s] = 0;
        P[s].length = 0;
        let head = 0, tail = 0, sCount = 0;
        Q[tail++] = s;
        let sumDist = 0, reach = 0;

        while (head < tail) {
            const v = Q[head++];
            S[sCount++] = v;
            const adj = out[v];
            const dv = dist[v];
            const sv = sigma[v];
            for (let j = 0; j < adj.length; j++) {
                const w = adj[j];
                if (w === v) continue;            // skip self-loop
                if (dist[w] < 0) {                 // first time we see w
                    dist[w] = dv + 1;
                    Q[tail++] = w;
                    sumDist += dist[w];
                    reach++;
                    P[w].length = 0;
                }
                if (dist[w] === dv + 1) {          // shortest-path edge
                    sigma[w] += sv;
                    P[w].push(v);
                }
            }
        }

        clo[s] = reach > 0 ? reach / sumDist : 0;

        for (let i = sCount - 1; i >= 0; i--) {
            const w = S[i];
            const Pw = P[w];
            const coeff = (1 + delta[w]) / sigma[w];
            for (let j = 0; j < Pw.length; j++) {
                const v = Pw[j];
                delta[v] += sigma[v] * coeff;
            }
            if (w !== s) btw[w] += delta[w];
        }
    }
    return { btw, clo };
}

// Eigencentrality via power iteration on the UNDIRECTED adjacency (ReGraph's
// eigencentrality exposes no direction option). We iterate x' = (A + I)·x
// (each node keeps its own value, then adds its neighbours') rather than plain
// x' = A·x. A+I shares its eigenvectors with A, so the centrality ranking is
// unchanged — but the dominant eigenvalue becomes λ+1, which strictly exceeds
// |−λ+1|. Plain A·x oscillates forever on bipartite graphs (e.g. a star, whose
// spectrum is ±λ); the +I shift guarantees convergence to the Perron vector.
// L2-normalized each iteration, until the L1 change is below tol or maxIters.
export function eigenCentrality(n, undirected, { maxIters = 100, tol = 1e-6 } = {}) {
    let x = new Float64Array(n).fill(1 / Math.sqrt(n));
    for (let it = 0; it < maxIters; it++) {
        const next = new Float64Array(n);
        for (let v = 0; v < n; v++) {
            const adj = undirected[v];
            let s = x[v]; // (A + I): keep own value, then add neighbours
            for (let j = 0; j < adj.length; j++) s += x[adj[j]];
            next[v] = s;
        }
        let norm = 0;
        for (let v = 0; v < n; v++) norm += next[v] * next[v];
        norm = Math.sqrt(norm) || 1;
        let diff = 0;
        for (let v = 0; v < n; v++) {
            next[v] /= norm;
            diff += Math.abs(next[v] - x[v]);
        }
        x = next;
        if (diff < tol) break;
    }
    return x;
}

// PageRank via power iteration (directed). Damping d=0.85. Dangling nodes
// (outdeg 0) have their mass redistributed uniformly each iteration so the
// vector stays a probability distribution (sums to ~1). `outdeg` must match
// the self-loop-skipping convention used when building `out` (buildAdjacency).
export function pageRank(n, out, outdeg, { d = 0.85, maxIters = 100, tol = 1e-6 } = {}) {
    // In-adjacency, skipping self-loops to match buildAdjacency / outdeg.
    const inAdj = Array.from({ length: n }, () => []);
    for (let v = 0; v < n; v++) {
        const adj = out[v];
        for (let j = 0; j < adj.length; j++) {
            const w = adj[j];
            if (w !== v) inAdj[w].push(v);
        }
    }
    let pr = new Float64Array(n).fill(1 / n);
    for (let it = 0; it < maxIters; it++) {
        let dangling = 0;
        for (let v = 0; v < n; v++) if (outdeg[v] === 0) dangling += pr[v];
        const base = (1 - d) / n + d * dangling / n;
        const next = new Float64Array(n);
        for (let v = 0; v < n; v++) {
            const inv = inAdj[v];
            let sum = 0;
            for (let j = 0; j < inv.length; j++) {
                const u = inv[j];
                sum += pr[u] / outdeg[u];
            }
            next[v] = base + d * sum;
        }
        let diff = 0;
        for (let v = 0; v < n; v++) diff += Math.abs(next[v] - pr[v]);
        pr = next;
        if (diff < tol) break;
    }
    return pr;
}

// Orchestrator: compute all five measures on a directed, unweighted edge list.
// Returns typed arrays of length n keyed by measure.
export function computeCentrality(n, links) {
    const adj = buildAdjacency(n, links);
    const { btw, clo } = brandes(n, adj.out);
    const eig = eigenCentrality(n, adj.undirected);
    const pr = pageRank(n, adj.out, adj.outdeg);
    const deg = degrees(n, adj);
    return { deg, indeg: adj.indeg, outdeg: adj.outdeg, btw, clo, eig, pr };
}

// Self-test on the 5-node bridge graph with known values. Throws on mismatch.
// Called at precompute startup so we never emit centrality from a broken build.
export function assertSelfTest() {
    const N = 5;
    const LINKS = [{ s: 0, t: 2 }, { s: 1, t: 2 }, { s: 2, t: 3 }, { s: 2, t: 4 }];
    const c = computeCentrality(N, LINKS);
    const eq = (a, b) => Math.abs(a - b) < 1e-9;
    const fail = (msg) => { throw new Error(`centrality self-test failed: ${msg}`); };

    if (![...c.deg].every((v, i) => v === [1, 1, 4, 1, 1][i])) fail(`deg=${[...c.deg]}`);
    if (![...c.btw].every((v, i) => eq(v, [0, 0, 4, 0, 0][i]))) fail(`btw=${[...c.btw]}`);
    if (!eq(c.clo[0], 0.6) || !eq(c.clo[2], 1.0) || c.clo[3] !== 0) fail(`clo=${[...c.clo]}`);
    for (const leaf of [0, 1, 3, 4]) if (!(c.eig[2] > c.eig[leaf])) fail(`eig hub not max: ${[...c.eig]}`);
    let sum = 0; for (let v = 0; v < N; v++) sum += c.pr[v];
    if (Math.abs(sum - 1) > 1e-6) fail(`pr sum=${sum}`);
    if (Math.abs(c.pr[0] - c.pr[1]) > 1e-6) fail(`pr symmetry: ${[...c.pr]}`);
}
