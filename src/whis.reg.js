/**
 * Standalone Mock Server for LLM Services
 * Now self-registers with the Service Registry on startup.
 * Run with: node llm.js
 */

require("./local-env"); // .env, when run by hand
const express = require("express");
const { createLogger } = require("./logger");
const { createRegistryClient } = require("./registry-client");

const log = createLogger("llm");
const app = express();
const PORT = 8023;
const REGISTRY_URL = process.env.REGISTRY_URL || "http://localhost:3001";

app.use(express.json());
app.use(log.requestLogger());

// --- CATALOG METADATA ---
// Single source of truth for this service's metadata
const SERVICE_CATALOG = {
  name: "whis",
  baseUrl: `http://localhost:${PORT}`,
  version: "v2.0",
  owner: "whispers",
  endpoints: ["/whis/eng", "/whis/persian"],
};

// --- CATALOG ENDPOINT (Required by Registry for health checks) ---
app.get("/catalog", (req, res) => {
  res.json(SERVICE_CATALOG);
});

// --- MOCK ENDPOINTS ---
app.get("/whis/eng", (req, res) =>
  res.json({
    source: "This comes from the whisper engine that handle english",
    status: "operational",
    response: "This is from whisper: You saied : What can I help you with?",
  }),
);
app.get("/whis/eng", (req, res) =>
  res.json({
    source: "This comes from the whisper engine that handle persian",
    status: "operational",
    response:
      "This is from whisper: You saied : What can I help you with? in persian.",
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
process.on("SIGINT", async () => {
  await registry.deregister(SERVICE_CATALOG.name);
  process.exit(0);
});

process.on("SIGTERM", async () => {
  await registry.deregister(SERVICE_CATALOG.name);
  process.exit(0);
});

// --- START SERVER THEN REGISTER ---
app.listen(PORT, async () => {
  console.log(`\n🧠 LLM Mock Server running on port ${PORT}`);
  console.log(`   Catalog: http://localhost:${PORT}/catalog`);
  // Register after server is fully listening
  await announce();
});
