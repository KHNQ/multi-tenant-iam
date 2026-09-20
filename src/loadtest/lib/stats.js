function percentile(sortedArr, p) {
  if (sortedArr.length === 0) return 0;
  const idx = Math.min(sortedArr.length - 1, Math.floor((p / 100) * sortedArr.length));
  return sortedArr[idx];
}

function summarizeLatencies(latencies) {
  const sorted = [...latencies].sort((a, b) => a - b);
  const sum = sorted.reduce((a, b) => a + b, 0);
  return {
    count: sorted.length,
    min: sorted[0] || 0,
    max: sorted[sorted.length - 1] || 0,
    mean: sorted.length ? sum / sorted.length : 0,
    p50: percentile(sorted, 50),
    p90: percentile(sorted, 90),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
  };
}

/** Buckets samples (each with a `t` epoch-ms field) into fixed-width windows. */
function bucketize(samples, bucketMs, startT, endT) {
  const buckets = [];
  for (let t = startT; t <= endT; t += bucketMs) {
    buckets.push({ t, samples: [] });
  }
  for (const s of samples) {
    const idx = Math.floor((s.t - startT) / bucketMs);
    if (idx >= 0 && idx < buckets.length) buckets[idx].samples.push(s);
  }
  return buckets;
}

module.exports = { percentile, summarizeLatencies, bucketize };
