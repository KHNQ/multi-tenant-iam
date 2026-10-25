import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { federation } from '@module-federation/vite'
import { releasePlugin } from './scripts/release-files.mjs'

export default defineConfig({
  // Served under /ui/ so Keycloak keeps ownership of /realms, /admin and /resources.
  base: '/ui/',
  plugins: [
    vue(),
    tailwindcss(),
    releasePlugin(),
    // Microfrontend remote: hosts load /ui/remoteEntry.js and call the framework-neutral
    // mount/unmount contract in src/mount.js. Vue is not shared - a React or Angular host
    // has none to offer, and bundling our own keeps the remote self-contained.
    federation({
      name: 'iamConsole',
      filename: 'remoteEntry.js',
      exposes: { './mount': './src/mount.js' },
      shared: {},
      dts: false,
    }),
  ],
  experimental: {
    // Chunks reference each other relatively, so the same build works at /ui/ on the
    // IAM origin and behind a host's proxy path (e.g. /iam/ui/).
    renderBuiltUrl(_filename, { hostType }) {
      return hostType === 'js' ? { relative: true } : undefined
    },
  },
  build: {
    // Module Federation remotes are ES modules loaded by the host at runtime.
    target: 'esnext',
  },
  resolve: {
    alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) },
  },
  test: {
    environment: 'jsdom',
  },
})
