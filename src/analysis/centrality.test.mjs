import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildAdjacency, degrees } from './centrality.mjs';
import { brandes } from './centrality.mjs';
import { eigenCentrality } from './centrality.mjs';
import { pageRank } from './centrality.mjs';
import { computeCentrality, assertSelfTest } from './centrality.mjs';

// Toy directed graph: 0→2, 1→2, 2→3, 2→4  (hub/bridge at node 2)
const N = 5;
const LINKS = [{ s: 0, t: 2 }, { s: 1, t: 2 }, { s: 2, t: 3 }, { s: 2, t: 4 }];

test('buildAdjacency: out lists, in/out degree, undirected neighbors', () => {
  const a = buildAdjacency(N, LINKS);
  assert.deepEqual(a.out[2], [3, 4]);
  assert.deepEqual([...a.outdeg], [1, 1, 2, 0, 0]);
  assert.deepEqual([...a.indeg], [0, 0, 2, 1, 1]);
  assert.deepEqual([...a.undirected[2]].sort((x, y) => x - y), [0, 1, 3, 4]);
});

test('degrees: total = in + out', () => {
  const a = buildAdjacency(N, LINKS);
  assert.deepEqual([...degrees(N, a)], [1, 1, 4, 1, 1]);
});

test('brandes: betweenness identifies the bridge node', () => {
  const a = buildAdjacency(N, LINKS);
  const { btw } = brandes(N, a.out);
  assert.deepEqual([...btw], [0, 0, 4, 0, 0]);
});

test('brandes: component-normalized closeness', () => {
  const a = buildAdjacency(N, LINKS);
  const { clo } = brandes(N, a.out);
  const approx = (x, y) => Math.abs(x - y) < 1e-9;
  assert.ok(approx(clo[0], 0.6), `clo[0]=${clo[0]}`);
  assert.ok(approx(clo[1], 0.6), `clo[1]=${clo[1]}`);
  assert.ok(approx(clo[2], 1.0), `clo[2]=${clo[2]}`);
  assert.equal(clo[3], 0);
  assert.equal(clo[4], 0);
});

test('eigenCentrality: hub is max, leaves equal (undirected star)', () => {
  const a = buildAdjacency(N, LINKS);
  const eig = eigenCentrality(N, a.undirected);
  for (const leaf of [0, 1, 3, 4]) assert.ok(eig[2] > eig[leaf], `hub ${eig[2]} > leaf ${eig[leaf]}`);
  const approx = (x, y) => Math.abs(x - y) < 1e-6;
  assert.ok(approx(eig[0], eig[1]) && approx(eig[1], eig[3]) && approx(eig[3], eig[4]),
    `leaves: ${eig[0]},${eig[1]},${eig[3]},${eig[4]}`);
});

test('pageRank: sums to 1 and respects symmetry', () => {
  const a = buildAdjacency(N, LINKS);
  const pr = pageRank(N, a.out, a.outdeg);
  let sum = 0;
  for (let v = 0; v < N; v++) sum += pr[v];
  const approx = (x, y, e = 1e-6) => Math.abs(x - y) < e;
  assert.ok(approx(sum, 1, 1e-6), `sum=${sum}`);
  assert.ok(approx(pr[0], pr[1]), `pr[0]=${pr[0]} pr[1]=${pr[1]}`);
  assert.ok(approx(pr[3], pr[4]), `pr[3]=${pr[3]} pr[4]=${pr[4]}`);
});

test('computeCentrality: returns all five measures with correct lengths', () => {
  const c = computeCentrality(N, LINKS);
  for (const key of ['deg', 'indeg', 'outdeg', 'btw', 'clo', 'eig', 'pr']) {
    assert.equal(c[key].length, N, `${key} length`);
  }
  assert.deepEqual([...c.deg], [1, 1, 4, 1, 1]);
  assert.deepEqual([...c.btw], [0, 0, 4, 0, 0]);
});

test('assertSelfTest: passes on the known toy graph', () => {
  assert.doesNotThrow(() => assertSelfTest());
});
