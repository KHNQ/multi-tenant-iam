import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import path from 'node:path'
import { open, mkdtemp, rm } from 'node:fs/promises'
import { publishRelease } from './release-files.mjs'

const root = fileURLToPath(new URL('../', import.meta.url))
const lockPath = path.join(root, '.iam-release.lock')
let lock
let stage
try {
  lock = await open(lockPath, 'wx')
  await lock.writeFile(JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }))
  stage = await mkdtemp(path.join(root, '.iam-stage-'))
  const commands = [
    ['test'],
    ['run', 'test:release'],
    ['run', 'build', '--', '--outDir', stage, '--emptyOutDir'],
  ]
  if (process.env.IAM_INSTALL_DEPENDENCIES === '1') {
    commands.unshift(['ci', ...(process.env.OFFLINE === '1' ? ['--offline'] : [])])
  }
  for (const args of commands) {
    const result = spawnSync('npm', args, { cwd: root, stdio: 'inherit' })
    if (result.error) throw result.error
    if (result.status !== 0) throw new Error(`npm ${args.join(' ')} failed; active release unchanged`)
  }
  const { manifest, backup } = await publishRelease(stage, path.join(root, 'dist'), path.join(root, '.iam-release-history'))
  console.log(`Published IAM ${manifest.version}\nMapDashboard auto entry: /iam/ui/autoEntry.js\nPrevious entry files: ${backup}`)
} catch (error) {
  console.error(error.code === 'EEXIST' ? `Another release holds ${lockPath}. Check it before removing a stale lock.` : error.message)
  process.exitCode = 1
} finally {
  if (stage) await rm(stage, { recursive: true, force: true })
  if (lock) { await lock.close(); await rm(lockPath, { force: true }) }
}
