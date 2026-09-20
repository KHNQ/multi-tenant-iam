/**
 * Standalone Mock Server for Vision Services
 * Now self-registers with the Service Registry on startup.
 * Run with: node vision.js
 */

const express = require('express');
const { createLogger } = require('./logger');

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

// --- SELF-REGISTRATION LOGIC ---
async function registerWithRegistry(retries = 5, delayMs = 2000) {
  const { default: fetch } = await import('node-fetch');

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const response = await fetch(`${REGISTRY_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: SERVICE_CATALOG.name,
          baseUrl: SERVICE_CATALOG.baseUrl,
          catalogUrl: `${SERVICE_CATALOG.baseUrl}/catalog`,
          owner: SERVICE_CATALOG.owner,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}`);
      }

      log.audit('registration', `Registered with Service Registry`, {
        version: SERVICE_CATALOG.version, endpoints: SERVICE_CATALOG.endpoints,
      });
      return;
    } catch (err) {
      log.warn('registration', `Registration attempt ${attempt} failed: ${err.message}`, { attempt });

      if (attempt < retries) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      } else {
        log.error('registration', `All registration attempts failed. Running unregistered.`);
      }
    }
  }
}

// --- GRACEFUL DEREGISTRATION ---
async function deregisterFromRegistry() {
  try {
    const { default: fetch } = await import('node-fetch');
    await fetch(`${REGISTRY_URL}/services/${SERVICE_CATALOG.name}`, {
      method: 'DELETE',
    });
    log.audit('registration', 'Deregistered from Service Registry');
  } catch (err) {
    log.warn('registration', `Could not deregister: ${err.message}`);
  }
}

process.on('SIGINT', async () => {
  await deregisterFromRegistry();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  await deregisterFromRegistry();
  process.exit(0);
});

// --- START SERVER THEN REGISTER ---
app.listen(PORT, async () => {
  console.log(`\n👁️  Vision Mock Server running on port ${PORT}`);
  console.log(`   Catalog: http://localhost:${PORT}/catalog`);
  await registerWithRegistry();
});
