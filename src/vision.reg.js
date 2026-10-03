/**
 * Standalone Mock Server for Vision Services
 * Now self-registers with the Service Registry on startup.
 * Run with: node vision.js
 */

require('./local-env'); // .env, when run by hand
const express = require('express');
const { createLogger } = require('./logger');
const { createRegistryClient } = require('./registry-client');

const log = createLogger('vision');
const app = express();
const PORT = 8081;
const REGISTRY_URL = process.env.REGISTRY_URL || 'http://localhost:3001';

app.use(express.json());
app.use(log.requestLogger());

// --- CATALOG METADATA ---
const SERVICE_CATALOG = {
  name: 'vision',
  baseUrl: `http://localhost:${PORT}`,
  version: 'v1.5',
  owner: 'cv_team',
  endpoints: [
    '/vision/service1',
    '/vision/service2',
    '/vision/service3',
    '/vision/facecheck',
  ],
};

// --- CATALOG ENDPOINT (Required by Registry for health checks) ---
app.get('/catalog', (req, res) => {
  res.json(SERVICE_CATALOG);
});

// --- MOCK ENDPOINTS ---
app.get('/vision/service1', (req, res) =>
  res.json({ source: 'Vision Service 1', type: 'object_detection' }),
);

app.get('/vision/service2', (req, res) =>
  res.json({ source: 'Vision Service 2', type: 'ocr' }),
);

app.get('/vision/service3', (req, res) =>
  res.json({ source: 'Vision Service 3', type: 'facial_recognition' }),
);

app.get('/vision/facecheck', (req, res) =>
  res.json({
    source: 'Vision Facecheck',
    type: 'facial_recognition',
    response: 'face checked',
  }),
);

// --- REGISTRATION ---
// Registering, renewing on restart, pushing a changed catalog and
// deregistering are the registry client's job (see registry-client.js); this
// service only says what it is.
const registry = createRegistryClient({ registryUrl: REGISTRY_URL, log });

const announce = () => registry.announce({
  name: SERVICE_CATALOG.name,
  baseUrl: SERVICE_CATALOG.baseUrl,
  // Where the registry probes this service for liveness
  catalogUrl: `${SERVICE_CATALOG.baseUrl}/catalog`,
  owner: SERVICE_CATALOG.owner,
  version: SERVICE_CATALOG.version,
  endpoints: SERVICE_CATALOG.endpoints,
});

// --- GRACEFUL DEREGISTRATION ON SHUTDOWN ---
process.on('SIGINT', async () => {
  await registry.deregister(SERVICE_CATALOG.name);
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await registry.deregister(SERVICE_CATALOG.name);
  process.exit(0);
});

// --- START SERVER THEN REGISTER ---
app.listen(PORT, async () => {
  console.log(`\n👁️  Vision Mock Server running on port ${PORT}`);
  console.log(`   Catalog: http://localhost:${PORT}/catalog`);
  await announce();
});
