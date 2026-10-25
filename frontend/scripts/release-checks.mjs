import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { pathToFileURL } from 'node:url'
import { spawnSync } from 'node:child_process'
import { writeReleaseFiles, publishRelease } from './release-files.mjs'

async function fixture(t, source = 'export const init = () => "first"; export const get = () => "mount";') {
  const root = await mkdtemp(path.join(tmpdir(), 'iam-release-check-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const stage = path.join(root, 'stage')
  const live = path.join(root, 'live')
  const history = path.join(root, 'history')
  await mkdir(stage)
  await mkdir(live)
  await mkdir(path.join(stage, 'assets'))
  await writeFile(path.join(stage, 'assets/new.js'), 'new asset')
  await writeFile(path.join(stage, 'remoteEntry.js'), source)
  await writeFile(path.join(stage, 'index.html'), '<html>new</html>')
  const manifest = await writeReleaseFiles(stage)
  return { root, stage, live, history, manifest }
}

test('publication retains old assets and backs up the previous release pointer', async (t) => {
  const { stage, live, history, manifest } = await fixture(t)
  await mkdir(path.join(live, 'assets'))
  await writeFile(path.join(live, 'assets/old.js'), 'open tab asset')
  await writeFile(path.join(live, 'iam-release.json'), '{"previous":true}')
  await writeFile(path.join(live, 'index.html'), '<html>old</html>')
  const { backup } = await publishRelease(stage, live, history)
  assert.deepEqual(JSON.parse(await readFile(path.join(live, 'iam-release.json'), 'utf8')), manifest)
  assert.equal(await readFile(path.join(live, 'assets/old.js'), 'utf8'), 'open tab asset')
  assert.equal(await readFile(path.join(backup, 'iam-release.json'), 'utf8'), '{"previous":true}')
  assert.equal(await readFile(path.join(live, manifest.entry), 'utf8'), await readFile(path.join(stage, 'remoteEntry.js'), 'utf8'))
})

test('a damaged release entry leaves the active release unchanged', async (t) => {
  const { stage, live, history, manifest } = await fixture(t)
  await writeFile(path.join(live, 'iam-release.json'), 'previous')
  await writeFile(path.join(stage, manifest.entry), 'damaged')
  await assert.rejects(publishRelease(stage, live, history), /checksum mismatch/)
  assert.equal(await readFile(path.join(live, 'iam-release.json'), 'utf8'), 'previous')
})

test('asset collisions fail before updating any active entry', async (t) => {
  const { stage, live, history } = await fixture(t)
  await mkdir(path.join(live, 'assets'))
  await writeFile(path.join(live, 'assets/new.js'), 'different bytes')
  await writeFile(path.join(live, 'index.html'), '<html>old</html>')
  await assert.rejects(publishRelease(stage, live, history), /Immutable asset collision/)
  assert.equal(await readFile(path.join(live, 'index.html'), 'utf8'), '<html>old</html>')
})

test('the unchanged loader resolves the next manifest on the next page load', async (t) => {
  const { stage, manifest } = await fixture(t)
  let current = manifest
  const requests = []
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    requests.push({ url: String(url), options })
    return { ok: true, json: async () => current }
  })
  const loader = pathToFileURL(path.join(stage, 'autoEntry.js'))
  const first = await import(`${loader}?page=1`)
  assert.equal(first.init(), 'first')
  await writeFile(path.join(stage, 'remoteEntry.js'), 'export const init = () => "second"; export const get = () => "new mount";')
  current = await writeReleaseFiles(stage)
  const second = await import(`${loader}?page=2`)
  assert.equal(second.init(), 'second')
  assert.equal(second.get(), 'new mount')
  assert.equal(first.get(), 'mount')
  assert.equal(requests.length, 2)
  assert.equal(requests[0].options.cache, 'no-store')
  assert.match(requests[0].url, /\/iam-release\.json$/)
})

test('loader rejects a manifest pointing outside the versioned entries', async (t) => {
  const { stage } = await fixture(t)
  t.mock.method(globalThis, 'fetch', async () => ({ ok: true, json: async () => ({ entry: 'https://other.invalid/entry.js' }) }))
  await assert.rejects(import(`${pathToFileURL(path.join(stage, 'autoEntry.js'))}?invalid`), /Invalid IAM release entry/)
})

async function deploymentFixture(t) {
  const { root } = await fixture(t)
  await mkdir(path.join(root, 'scripts'))
  await mkdir(path.join(root, 'dist'))
  for (const name of ['deploy.mjs', 'release-files.mjs']) {
    await writeFile(path.join(root, 'scripts', name), await readFile(new URL(name, import.meta.url)))
  }
  await writeFile(path.join(root, 'dist/iam-release.json'), 'active release')
  await writeFile(path.join(root, 'package.json'), JSON.stringify({ scripts: { test: 'node -e "process.exit(23)"' } }))
  const run = () => spawnSync(process.execPath, [path.join(root, 'scripts/deploy.mjs')], {
    encoding: 'utf8', env: { ...process.env, IAM_INSTALL_DEPENDENCIES: '0' },
  })
  return { root, run }
}

test('test failure aborts the deployment and releases its lock', async (t) => {
  const { root, run } = await deploymentFixture(t)
  const result = run()
  assert.equal(result.status, 1)
  assert.match(result.stderr, /active release unchanged/)
  assert.equal(await readFile(path.join(root, 'dist/iam-release.json'), 'utf8'), 'active release')
  await assert.rejects(readFile(path.join(root, '.iam-release.lock')), { code: 'ENOENT' })
})

test('concurrent deployment fails without removing the other deployment lock', async (t) => {
  const { root, run } = await deploymentFixture(t)
  await writeFile(path.join(root, '.iam-release.lock'), 'other deployment')
  const result = run()
  assert.equal(result.status, 1)
  assert.match(result.stderr, /Another release holds/)
  assert.equal(await readFile(path.join(root, '.iam-release.lock'), 'utf8'), 'other deployment')
  assert.equal(await readFile(path.join(root, 'dist/iam-release.json'), 'utf8'), 'active release')
})
