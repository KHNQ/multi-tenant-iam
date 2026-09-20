/**
 * Standalone Mock Server for LLM Services
 * Now self-registers with the Service Registry on startup.
 * Run with: node llm.js
 */

const express = require('express');
const { createLogger } = require('./logger');

const log = createLogger('llm');
const app = express();
const PORT = 8080;
const REGISTRY_URL = process.env.REGISTRY_URL || 'http://localhost:3001';

app.use(express.json());
app.use(log.requestLogger());

// --- CATALOG METADATA ---
// Single source of truth for this service's metadata
const SERVICE_CATALOG = {
  name: 'llm',
  baseUrl: `http://localhost:${PORT}`,
  version: 'v2.0',
  owner: 'ai_team',
  endpoints: ['/llm/gemini', '/llm/gpt', '/llm/claude'],
};

// --- CATALOG ENDPOINT (Required by Registry for health checks) ---
app.get('/catalog', (req, res) => {
  res.json(SERVICE_CATALOG);
});

// --- MOCK ENDPOINTS ---
app.get('/llm/gemini', (req, res) =>
  res.json({
    source: 'LLM 1 - Gemini',
    status: 'operational',
    response: 'This is from Gemini: What can I help you with?',
  }),
);

app.get('/llm/gpt', (req, res) =>
  res.json({
    source: 'LLM 2 - GPT',
    status: 'operational',
    response: 'This is from GPT: What can I help you with?',
  }),
);

app.get('/llm/claude', (req, res) =>
  res.json({
    source: 'LLM 3 - Claude',
    status: 'operational',
    response: 'This is from Claude: What can I help you with?',
  }),
);

// --- SELF-REGISTRATION LOGIC ---
async function registerWithRegistry(retries = 5, delayMs = 2000) {
  const { default: fetch } = await import('node-fetch');

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      console.log(
        `[LLM] Registering with Service Registry (attempt ${attempt}/${retries})...`,
      );

      const response = await fetch(`${REGISTRY_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: SERVICE_CATALOG.name,
          baseUrl: SERVICE_CATALOG.baseUrl,
          // Tell registry where to fetch our catalog for health checks
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
      return; // Success, exit retry loop
    } catch (err) {
      log.warn('registration', `Registration attempt ${attempt} failed: ${err.message}`, { attempt });

      if (attempt < retries) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      } else {
        // Non-fatal: service still runs, registry just won't know about it yet
        log.error('registration', `All registration attempts failed. Running unregistered.`);
      }
    }
  }
}

// --- GRACEFUL DEREGISTRATION ON SHUTDOWN ---
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
  console.log(`\n🧠 LLM Mock Server running on port ${PORT}`);
  console.log(`   Catalog: http://localhost:${PORT}/catalog`);
  // Register after server is fully listening
  await registerWithRegistry();
});
