/**
 * Runs `worker` over `items` with at most `concurrency` in flight at once.
 * Plain Promise.all(items.map(worker)) would fire all 1000 requests
 * simultaneously — fine for the load-test phase (that's the point), but
 * wrong for setup (1000 simultaneous Argon2 hashes would just thrash the
 * gateway's libuv threadpool instead of measuring anything useful).
 */
async function runPool(items, worker, concurrency) {
  const results = new Array(items.length);
  let idx = 0;

  async function lane() {
    while (idx < items.length) {
      const i = idx++;
      results[i] = await worker(items[i], i);
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, lane));
  return results;
}

module.exports = { runPool };
