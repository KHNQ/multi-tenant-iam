/**
 * Deterministic PRNG (mulberry32) so a load test run with the same --seed
 * produces the same user/role assignment and the same sequence of chaos
 * mutations — needed to make "before vs after a code change" comparisons
 * meaningful instead of comparing against different random noise each time.
 */

function mulberry32(seed) {
  let a = seed >>> 0;
  return function rand() {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function makeRng(seed = 42) {
  const rand = mulberry32(seed);
  return {
    float: () => rand(),
    int: (min, max) => min + Math.floor(rand() * (max - min + 1)),
    pick: (arr) => arr[Math.floor(rand() * arr.length)],
    pickN(arr, n) {
      const pool = [...arr];
      const out = [];
      for (let i = 0; i < n && pool.length; i++) {
        const idx = Math.floor(rand() * pool.length);
        out.push(pool.splice(idx, 1)[0]);
      }
      return out;
    },
    chance: (p) => rand() < p,
  };
}

module.exports = { makeRng };
