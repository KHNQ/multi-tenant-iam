import { createHash, randomUUID } from 'node:crypto'
import { readFile, writeFile, mkdir, rename, readdir, access } from 'node:fs/promises'
import path from 'node:path'

export const loaderSource = `// Permanent federation entry: resolves one release per page load.
const response = await fetch(new URL('./iam-release.json', import.meta.url), { cache: 'no-store', credentials: 'same-origin' });
if (!response.ok) throw new Error('IAM release manifest unavailable: ' + response.status);
const release = await response.json();
if (!/^remoteEntry\\.[a-f0-9]{64}\\.js$/.test(release.entry)) throw new Error('Invalid IAM release entry');
const remote = await import(new URL(release.entry, import.meta.url).href);
// Expose release diagnostics without adding anything to the visible UI.
if (typeof document !== 'undefined') {
  document.documentElement.dataset.iamRelease = release.version;
  document.documentElement.dataset.iamReleaseBuiltAt = release.builtAt;
}
export const init = (...args) => remote.init(...args);
export const get = (...args) => remote.get(...args);
`

export const digest = (bytes) => createHash('sha256').update(bytes).digest('hex')

export async function writeReleaseFiles(directory) {
  const bytes = await readFile(path.join(directory, 'remoteEntry.js'))
  const version = digest(bytes)
  const entry = `remoteEntry.${version}.js`
  await writeFile(path.join(directory, entry), bytes)
  await writeFile(path.join(directory, 'autoEntry.js'), loaderSource)
  const manifest = { schema: 1, version, entry, builtAt: new Date().toISOString() }
  await writeFile(path.join(directory, 'iam-release.json'), JSON.stringify(manifest, null, 2) + '\n')
  return manifest
}

export function releasePlugin() {
  return {
    name: 'iam-release-manifest',
    apply: 'build',
    async writeBundle(options) {
      await writeReleaseFiles(path.resolve(options.dir))
    },
  }
}

const mutable = new Set(['index.html', 'remoteEntry.js', 'autoEntry.js', 'iam-release.json'])

async function files(directory, prefix = '') {
  const result = []
  for (const item of await readdir(path.join(directory, prefix), { withFileTypes: true })) {
    const name = path.join(prefix, item.name)
    if (item.isDirectory()) result.push(...await files(directory, name))
    else if (item.isFile()) result.push(name)
    else throw new Error(`Unsupported release file: ${name}`)
  }
  return result
}

export async function atomicWrite(filename, bytes) {
  const temporary = `${filename}.${randomUUID()}.tmp`
  await writeFile(temporary, bytes)
  await rename(temporary, filename)
}

export async function publishRelease(stage, destination, history) {
  const names = await files(stage)
  const manifest = JSON.parse(await readFile(path.join(stage, 'iam-release.json'), 'utf8'))
  if (!/^remoteEntry\.[a-f0-9]{64}\.js$/.test(manifest.entry) || manifest.entry !== `remoteEntry.${manifest.version}.js`) {
    throw new Error('Invalid release manifest')
  }
  if (digest(await readFile(path.join(stage, manifest.entry))) !== manifest.version) throw new Error('Release entry checksum mismatch')
  for (const name of mutable) await access(path.join(stage, name))
  if (!(await readFile(path.join(stage, 'index.html'), 'utf8')).includes('<html')) throw new Error('Invalid release index')

  // Preflight all immutable files before changing the active release.
  for (const name of names.filter((name) => !mutable.has(name))) {
    const bytes = await readFile(path.join(stage, name))
    try {
      if (!(await readFile(path.join(destination, name))).equals(bytes)) throw new Error(`Immutable asset collision: ${name}`)
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
  }

  const backup = path.join(history, `${new Date().toISOString().replace(/[:.]/g, '-')}-${randomUUID()}`)
  await mkdir(backup, { recursive: true })
  for (const name of mutable) {
    try { await writeFile(path.join(backup, name), await readFile(path.join(destination, name))) }
    catch (error) { if (error.code !== 'ENOENT') throw error }
  }
  await writeFile(path.join(backup, 'published-release.json'), JSON.stringify(manifest, null, 2) + '\n')
  await mkdir(destination, { recursive: true })
  for (const name of names.filter((name) => !mutable.has(name))) {
    await mkdir(path.dirname(path.join(destination, name)), { recursive: true })
    await atomicWrite(path.join(destination, name), await readFile(path.join(stage, name)))
  }
  // Keep Caddy's mounted directory and old chunks for open tabs and rollback.
  for (const name of ['autoEntry.js', 'remoteEntry.js', 'index.html', 'iam-release.json']) {
    await atomicWrite(path.join(destination, name), await readFile(path.join(stage, name)))
  }
  return { manifest, backup }
}
