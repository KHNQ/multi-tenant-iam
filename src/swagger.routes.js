/**
 * Swagger route definitions
 * These are NOT real route handlers — they only provide OpenAPI metadata.
 * Actual routing lives in main.js / registry.js.
 */

const {
  // ─── AUTH ────────────────────────────────────────────────────────────────
  /**
   * @swagger
   * /auth/signup:
   *   post:
   *     tags: [Auth]
   *     summary: Register a new user
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required: [username, password]
   *             properties:
   *               username: { type: string, minLength: 3 }
   *               password: { type: string, minLength: 6 }
   *     responses:
   *       201: { description: User registered }
   *       400: { description: Missing credentials }
   *       409: { description: User already exists }
   */
  // eslint-disable-next-line no-unused-vars
  _signup: null,

  /**
   * @swagger
   * /auth/login:
   *   post:
   *     tags: [Auth]
   *     summary: Login and receive a JWT token
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required: [username, password]
   *             properties:
   *               username: { type: string }
   *               password: { type: string }
   *     responses:
   *       200:
   *         description: Login successful
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 token:  { type: string }
   *                 message: { type: string }
   *       401: { description: Invalid credentials }
   */
  // eslint-disable-next-line no-unused-vars
  _login: null,

  // ─── ADMIN ──────────────────────────────────────────────────────────────
  /**
   * @swagger
   * /admin/roles:
   *   post:
   *     tags: [Admin]
   *     summary: Assign a role to an existing user
   *     security: [{ BearerAuth: [] }]
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required: [username, role]
   *             properties:
   *               username: { type: string }
   *               role:     { type: string }
   *     responses:
   *       200: { description: Role assigned }
   *       401: { description: Missing token }
   *       403: { description: Admin required }
   */
  // eslint-disable-next-line no-unused-vars
  _adminRoles: null,

  /**
   * @swagger
   * /admin/policies:
   *   post:
   *     tags: [Admin]
   *     summary: Add a Casbin policy (subject + resource + action)
   *     security: [{ BearerAuth: [] }]
   *     requestBody:
   *       required: true
   *       content:
   *         application/json:
   *           schema:
   *             type: object
   *             required: [subject, resource, action]
   *             properties:
   *               subject:  { type: string, description: "Role or username" }
   *               resource: { type: string, description: "URL path pattern, e.g. /llm/gemini" }
   *               action:   { type: string, enum: [get, post, put, delete, patch] }
   *     responses:
   *       200: { description: Policy added }
   *       401: { description: Missing token }
   *       403: { description: Admin required }
   */
  // eslint-disable-next-line no-unused-vars
  _adminPolicies: null,

  /**
   * @swagger
   * /admin/services:
   *   get:
   *     tags: [Admin]
   *     summary: Force-refresh the service cache and return current state
   *     security: [{ BearerAuth: [] }]
   *     responses:
   *       200:
   *         description: Current service cache
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 lastSyncTime: { type: string, format: date-time }
   *                 registryUrl:  { type: string }
   *                 count:        { type: integer }
   *                 services:
   *                   type: array
   *                   items:
   *                     $ref: '#/components/schemas/ServiceEntry'
   *       401: { description: Missing token }
   *       403: { description: Admin required }
   */
  // eslint-disable-next-line no-unused-vars
  _adminServices: null,

  // ─── GATEWAY ─────────────────────────────────────────────────────────────
  /**
   * @swagger
   * /gateway/{serviceName}:
   *   get:
   *     tags: [Gateway]
   *     summary: Proxy GET request to a downstream service
   *     security: [{ BearerAuth: [] }]
   *     parameters:
   *       - in: path
   *         name: serviceName
   *         required: true
   *         schema: { type: string }
   *         example: llm
   *     responses:
   *       200: { description: Proxied response from downstream service }
   *       403: { description: Policy denies this user }
   *       404: { description: Service not found or inactive }
   */
  _gatewayGet: null,

  /**
   * @swagger
   * /gateway/{serviceName}:
   *   post:
   *     tags: [Gateway]
   *     summary: Proxy POST request to a downstream service
   *     security: [{ BearerAuth: [] }]
   *     parameters:
   *       - in: path
   *         name: serviceName
   *         required: true
   *         schema: { type: string }
   *     requestBody:
   *       content:
   *         application/json:
   *           schema: { type: object }
   *     responses:
   *       200: { description: Proxied response from downstream service }
   *       403: { description: Policy denies this user }
   *       404: { description: Service not found or inactive }
   */
  _gatewayPost: null,

  // ─── REGISTRY ─────────────────────────────────────────────────────────────
  /**
   * @swagger
   * /services:
   *   get:
   *     tags: [Registry]
   *     summary: List all registered services
   *     parameters:
   *       - in: query
   *         name: status
   *         schema: { type: string, enum: [active, inactive] }
   *         description: Filter by service status
   *     responses:
   *       200:
   *         description: Service list
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 count: { type: integer }
   *                 services:
   *                   type: array
   *                   items:
   *                     $ref: '#/components/schemas/ServiceEntry'
   */
  _registryServices: null,

  /**
   * @swagger
   * /services/{name}:
   *   get:
   *     tags: [Registry]
   *     summary: Get a single service by name
   *     parameters:
   *       - in: path
   *         name: name
   *         required: true
   *         schema: { type: string }
   *     responses:
   *       200:
   *         description: Service details
   *         content:
   *           application/json:
   *             schema:
   *               $ref: '#/components/schemas/ServiceEntry'
   *       404: { description: Service not found }
   */
  _registryServiceByName: null,

  /**
   * @swagger
   * /health:
   *   get:
   *     tags: [Registry]
   *     summary: Registry health check
   *     responses:
   *       200:
   *         description: Health status
   *         content:
   *           application/json:
   *             schema:
   *               type: object
   *               properties:
   *                 status:              { type: string }
   *                 redis:              { type: string }
   *                 registeredServices: { type: integer }
   *                 uptime:             { type: number }
   */
  _health: null,
};
