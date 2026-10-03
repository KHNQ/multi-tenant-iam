
/**
 * swagger.js — inline OpenAPI 3.0.3 specification
 * Served by main.js at GET /docs and GET /docs.json
 */

const spec = {
  openapi: '3.0.3',
  info: {
    title: 'IAM API Gateway',
    version: '1.0.0',
    description:
      'Multi-tenant IAM API Gateway with dynamic service discovery.\n\n' +
      'Authenticate at /auth/login and pass the JWT as `Authorization: Bearer <token>`. ' +
      'Applications sign people in with OpenID Connect instead (Authorization Code + PKCE; see /.well-known/openid-configuration).\n\n' +
      '**Two levels of administration.** Every registered service is a *tenant* that runs its own ' +
      'roles, policies and user list under `/tenants/{id}/…`; the platform admin handles tenant ' +
      'lifecycle and cross-tenant oversight under `/admin/…`. A tenant admin has full authority ' +
      'inside their own tenant and none outside it.',
  },
  servers: [
    { url: 'http://localhost:3000', description: 'API Gateway (this server)' },
    { url: 'http://localhost:3001', description: 'Service Registry' },
  ],
  tags: [
    { name: 'Auth',     description: 'Signup and login — no token required' },
    { name: 'OpenID Connect', description: 'Standard sign-in for applications: Authorization Code flow with PKCE. The gateway is the provider' },
    { name: 'Self-Service', description: 'Any authenticated user — browse the catalog and request roles/services' },
    { name: 'Admin',    description: 'Platform-wide administration and tenant lifecycle — platform admin JWT required' },
    { name: 'Tenants',  description: 'Multi-tenancy — every registered service is a tenant that governs its own roles, policies and users' },
    { name: 'Gateway',  description: 'Proxied downstream calls — JWT + Casbin policy required' },
    { name: 'Registry', description: 'Service Registry API (port 3001)' },
    { name: 'Operations', description: 'Metrics for a monitoring system' },
  ],
  components: {
    securitySchemes: {
      BearerAuth: {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        description: 'Token from /auth/login — do not include the "Bearer " prefix here',
      },
    },
    schemas: {
      Condition: {
        description:
          'An attribute condition: the policy grants only while it holds. A tree of `all` / `any` / `not` ' +
          'and comparisons. `attr` is `subject.*` (id, username, attributes set by a platform admin), ' +
          '`resource.*` (service, path, attributes of the owning tenant), `request.*` (method, ip) or ' +
          '`env.*` (time, hour, weekday — UTC). `value` is a string, number, boolean, a list of those, ' +
          'or `{ "ref": "resource.department" }` to compare with another attribute. An absent attribute ' +
          'satisfies no comparison. At most 5 levels and 40 nodes.',
        type: 'object',
        example: {
          all: [
            { attr: 'subject.department', op: 'eq', value: { ref: 'resource.department' } },
            { attr: 'subject.clearance', op: 'gte', value: 2 },
          ],
        },
      },
      Error: {
        type: 'object',
        properties: {
          error: { type: 'string', example: 'Something went wrong' },
        },
      },
      Credentials: {
        type: 'object',
        required: ['username', 'password'],
        properties: {
          username: { type: 'string', example: 'alice' },
          password: { type: 'string', example: 'SecurePass123!' },
        },
      },
      LoginResponse: {
        type: 'object',
        properties: {
          token:   { type: 'string', example: 'eyJhbGci...' },
          message: { type: 'string', example: 'Login successful' },
          mustChangePassword: {
            type: 'boolean',
            description:
              'Present (and true) only when the account still holds a temporary password. ' +
              'The token then opens nothing except `POST /auth/change-password` and `POST /auth/logout`; ' +
              'every other route answers 403 with `code: "PASSWORD_CHANGE_REQUIRED"`.',
          },
        },
      },
      RoleAssignment: {
        type: 'object',
        required: ['username', 'role'],
        properties: {
          username: { type: 'string', example: 'alice' },
          role: {
            type: 'string',
            example: 'blue_role',
            enum: ['user', 'blue_role', 'red_role', 'green_role', 'admin'],
          },
        },
      },
      PolicyRule: {
        type: 'object',
        required: ['subject', 'resource', 'action'],
        properties: {
          subject: {
            type: 'string',
            description:
              'A bare name is always a platform ROLE (`blue_role`). A tenant role is `t:{tenant}:{role}`. ' +
              'To target one account, say so explicitly: `user:{username}`. A username on its own is ' +
              'never a subject, so an account cannot acquire a role\'s policies by being named after it.',
            example: 'blue_role',
          },
          resource: { type: 'string', description: 'URL path pattern', example: '/llm/claude' },
          action: {
            type: 'string',
            enum: ['get', 'post', 'put', 'delete', 'patch'],
            example: 'get',
          },
        },
      },
      ServiceEntry: {
        type: 'object',
        properties: {
          name:         { type: 'string',  example: 'llm' },
          baseUrl:      { type: 'string',  example: 'http://localhost:8080' },
          catalogUrl:   { type: 'string',  example: 'http://localhost:8080/catalog' },
          version:      { type: 'string',  example: 'v2.0' },
          owner:        { type: 'string',  example: 'ai_team' },
          endpoints: {
            type: 'array',
            items: { type: 'string' },
            example: ['/llm/gemini', '/llm/claude', '/llm/gpt'],
          },
          status:        { type: 'string', enum: ['active', 'inactive'] },
          registeredAt:  { type: 'string', format: 'date-time' },
          lastSeen:      { type: 'string', format: 'date-time' },
        },
      },
      UserEntry: {
        type: 'object',
        properties: {
          username: { type: 'string', example: 'alice' },
          role:     { type: 'string', description: 'Flat role field used for the JWT admin gate', example: 'blue_role' },
          roles: {
            type: 'array',
            items: { type: 'string' },
            description: 'All Casbin roles currently assigned to this user',
            example: ['blue_role', 'red_role'],
          },
        },
      },
      PolicyEntry: {
        type: 'object',
        properties: {
          subject:  { type: 'string', example: 'blue_role' },
          resource: { type: 'string', example: '/llm/claude' },
          action:   { type: 'string', example: 'get' },
        },
      },
      RoleEntry: {
        type: 'object',
        properties: {
          role: { type: 'string', example: 'blue_role' },
          users: {
            type: 'array',
            items: { type: 'string' },
            example: ['alice', 'bob'],
          },
        },
      },
      AccessRequest: {
        type: 'object',
        properties: {
          id:          { type: 'string', format: 'uuid' },
          username:    { type: 'string', example: 'alice' },
          role:        { type: 'string', nullable: true, example: 'blue_role' },
          service:     { type: 'string', nullable: true, example: 'llm' },
          note:        { type: 'string', example: 'need LLM access for a demo' },
          status:      { type: 'string', enum: ['pending', 'approved', 'rejected'] },
          requestedAt: { type: 'string', format: 'date-time' },
          resolvedAt:  { type: 'string', format: 'date-time', nullable: true },
          resolvedBy:  { type: 'string', nullable: true, example: 'admin' },
          grantedRole: { type: 'string', nullable: true, example: 'blue_role' },
        },
      },
    },
  },

  // ─── PATHS ────────────────────────────────────────────────────────────────
  // Key format must exactly match what the test checks with paths['/auth/signup']
  paths: {

    // ── Auth ────────────────────────────────────────────────────────────────
    '/auth/signup': {
      post: {
        tags: ['Auth'],
        summary: 'Register a new user',
        description:
          'Creates a user account with the default `user` role. Usernames are 2-64 characters: ' +
          'letters, digits, `.`, `_`, `-`, `+` or `@`. Passwords are 8-128 characters. Signups ' +
          'are rate-limited per client address (429 with `Retry-After`).',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/Credentials' },
              examples: {
                example1: {
                  summary: 'New user',
                  value: { username: 'alice', password: 'SecurePass123!' },
                },
              },
            },
          },
        },
        responses: {
          201: {
            description: 'User created successfully',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: 'User registered successfully' },
                  },
                },
              },
            },
          },
          400: {
            description: 'Missing username or password, or a username outside the allowed characters',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
          409: {
            description: 'Username already taken',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
        },
      },
    },

    '/auth/login': {
      post: {
        tags: ['Auth'],
        summary: 'Login and receive a JWT',
        description:
          'Returns a signed JWT valid for 24 hours. ' +
          'Use it as `Authorization: Bearer <token>` on all protected routes.\n\n' +
          'The token carries the account\'s id (`sub`), its security version and a token id — no ' +
          'username and no role. Whether the account still exists, is active, and is an admin is ' +
          'read from the store on every request, so a token never outlives a suspension, a ' +
          'deletion, or any loss of access.\n\n' +
          'A failed login always answers `401 Invalid username or password`, whether or not the ' +
          'username exists, and takes the same time either way. Attempts are limited per address ' +
          'and per username (existing or not); the limit is taken before the password is checked, ' +
          'so parallel guesses cannot exceed it.\n\n' +
          'There is no built-in account password. The initial `admin` account is created once, ' +
          'the first time the gateway boots against an empty store, with a random one-time password ' +
          'written to a file on the gateway host; logging in with it returns `mustChangePassword: true`.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/Credentials' },
              examples: {
                regularUser: {
                  summary: 'Regular user',
                  value: { username: 'alice', password: 'SecurePass123!' },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Login successful — returns JWT',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/LoginResponse' },
              },
            },
          },
          400: {
            description: 'Missing or malformed username or password',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
          401: {
            description: 'Invalid username or password — the same answer for an unknown user and a wrong password',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
          403: {
            description: 'The password was correct but the account is suspended (`code: "ACCOUNT_SUSPENDED"`)',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
          429: {
            description: 'Too many attempts from this address or for this username; see `Retry-After`',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
        },
      },
    },

    '/auth/logout': {
      post: {
        tags: ['Auth'],
        summary: 'Revoke the current token',
        description:
          'Adds the token\'s unique id (jti) to a Redis denylist for the ' +
          'remainder of its natural lifetime, so it can no longer be used ' +
          'even though JWTs are otherwise stateless.',
        security: [{ BearerAuth: [] }],
        responses: {
          200: { description: 'Logged out; token revoked' },
          401: { description: 'Missing or invalid token' },
        },
      },
    },

    '/auth/logout-all': {
      post: {
        tags: ['Auth'],
        summary: 'Sign out everywhere',
        description:
          'Ends every session of the calling account, on every device, by moving its security ' +
          'version. The token used for this call stops working too.',
        security: [{ BearerAuth: [] }],
        responses: {
          200: { description: 'Every session ended' },
          401: { description: 'Missing or invalid token' },
        },
      },
    },

    '/auth/password-recovery': {
      post: {
        tags: ['Auth'],
        summary: 'Ask to recover a forgotten password',
        description:
          'Always answers 202 with the same message, immediately, whether or not the account exists. ' +
          'For a real, active account a single-use link valid for 30 minutes is handed to the ' +
          'configured notification service (PASSWORD_RECOVERY_WEBHOOK_URL). With none configured ' +
          'nothing is sent, and a platform admin issues the link instead. Limited per address and per account.',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', required: ['username'], properties: { username: { type: 'string' } } } } },
        },
        responses: {
          202: { description: 'Accepted — says nothing about whether the account exists' },
          400: { description: 'Malformed request' },
          429: { description: 'Too many requests from this address' },
        },
      },
    },

    '/auth/password-recovery/complete': {
      post: {
        tags: ['Auth'],
        summary: 'Set a new password with a recovery token',
        description:
          'The token is the part of the recovery link after `#recover=`. It works once. Setting the ' +
          'password ends every session of the account.',
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object', required: ['token', 'newPassword'],
            properties: { token: { type: 'string' }, newPassword: { type: 'string', minLength: 8, maxLength: 128 } },
          } } },
        },
        responses: {
          200: { description: 'Password changed; sign in with it' },
          400: { description: 'The token is invalid, expired or already used — or the password is not acceptable' },
          429: { description: 'Too many attempts from this address' },
        },
      },
    },

    '/.well-known/openid-configuration': {
      get: {
        tags: ['OpenID Connect'],
        summary: 'Discovery document',
        description: 'What an OIDC client library needs: the issuer, the endpoints below, and what is supported (code flow, PKCE S256, RS256, public clients).',
        responses: { 200: { description: 'OpenID Provider metadata' } },
      },
    },

    '/oauth/jwks': {
      get: {
        tags: ['OpenID Connect'],
        summary: 'Public keys ID tokens are signed with',
        responses: { 200: { description: 'JSON Web Key Set' } },
      },
    },

    '/oauth/authorize': {
      get: {
        tags: ['OpenID Connect'],
        summary: 'Start a sign-in (the browser is sent here)',
        description:
          'Shows the gateway\'s sign-in page. After the user signs in, the browser is redirected to ' +
          '`redirect_uri` with `code` and `state`. An unknown `client_id` or a `redirect_uri` that is ' +
          'not registered exactly gets an error page, never a redirect; every other error is returned ' +
          'to the redirect URI as `error` / `error_description`.',
        parameters: [
          { name: 'response_type', in: 'query', required: true, schema: { type: 'string', enum: ['code'] } },
          { name: 'client_id', in: 'query', required: true, schema: { type: 'string' } },
          { name: 'redirect_uri', in: 'query', required: true, schema: { type: 'string' } },
          { name: 'scope', in: 'query', required: true, schema: { type: 'string', example: 'openid profile' }, description: 'Must include `openid`' },
          { name: 'state', in: 'query', schema: { type: 'string' }, description: 'Returned unchanged; the client checks it' },
          { name: 'nonce', in: 'query', schema: { type: 'string' }, description: 'Returned in the ID token' },
          { name: 'code_challenge', in: 'query', required: true, schema: { type: 'string' }, description: 'BASE64URL(SHA-256(code_verifier))' },
          { name: 'code_challenge_method', in: 'query', required: true, schema: { type: 'string', enum: ['S256'] } },
        ],
        responses: {
          200: { description: 'The sign-in page (HTML)' },
          303: { description: 'Redirect back to the client with an error' },
          400: { description: 'Unknown client or unregistered redirect URI (HTML error page)' },
        },
      },
      post: {
        tags: ['OpenID Connect'],
        summary: 'Submit the sign-in form',
        description:
          'Posted by the sign-in page itself, not by clients. Draws on the same attempt limits as ' +
          '/auth/login and gives the same single failure message. An account holding a temporary ' +
          'password is asked to replace it before a code is issued.',
        requestBody: { content: { 'application/x-www-form-urlencoded': { schema: { type: 'object' } } } },
        responses: {
          200: { description: 'The page again — asking for a new password' },
          303: { description: 'Signed in: redirect to the client with `code` and `state`' },
          400: { description: 'The form was altered or has expired' },
          401: { description: 'Invalid username or password (the page, with that message)' },
          403: { description: 'The account is suspended' },
          429: { description: 'Too many attempts' },
        },
      },
    },

    '/oauth/token': {
      post: {
        tags: ['OpenID Connect'],
        summary: 'Exchange an authorization code for tokens',
        description:
          'A code works once, within 60 seconds, for the client and redirect URI it was issued to, ' +
          'and only with the verifier matching its challenge. Presenting a code a second time is ' +
          'refused and revokes the token issued the first time. Browser clients may call this from ' +
          'the origin of a registered redirect URI.',
        requestBody: {
          required: true,
          content: { 'application/x-www-form-urlencoded': { schema: {
            type: 'object', required: ['grant_type', 'code', 'redirect_uri', 'client_id', 'code_verifier'],
            properties: {
              grant_type: { type: 'string', enum: ['authorization_code'] },
              code: { type: 'string' }, redirect_uri: { type: 'string' },
              client_id: { type: 'string' }, code_verifier: { type: 'string' },
            },
          } } },
        },
        responses: {
          200: {
            description: 'Tokens',
            content: { 'application/json': { schema: { type: 'object', properties: {
              access_token: { type: 'string', description: 'A gateway session token — use it as the Bearer token for this API' },
              token_type: { type: 'string', example: 'Bearer' },
              expires_in: { type: 'integer' },
              id_token: { type: 'string', description: 'RS256 JWT: sub, preferred_username, nonce, at_hash' },
              scope: { type: 'string' },
            } } } },
          },
          400: { description: '`invalid_grant`, `invalid_request` or `unsupported_grant_type`' },
        },
      },
    },

    '/oauth/userinfo': {
      get: {
        tags: ['OpenID Connect'],
        summary: 'Who the access token belongs to',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: '`sub` and `preferred_username`' }, 401: { description: 'Missing or invalid token' } },
      },
    },

    '/admin/oidc/clients': {
      get: {
        tags: ['Admin'],
        summary: 'List the applications that may sign people in',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Registered clients, including the built-in console' }, 403: { description: 'Admin privileges required' } },
      },
      post: {
        tags: ['Admin'],
        summary: 'Register an application',
        description:
          'Clients are public (no secret; PKCE protects the exchange). Redirect URIs are matched ' +
          'exactly and must be https, or http on loopback; no fragments.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object', required: ['name', 'redirectUris'],
            properties: {
              name: { type: 'string', example: 'Reports portal' },
              redirectUris: { type: 'array', items: { type: 'string' }, example: ['https://reports.example.org/callback'] },
            },
          } } },
        },
        responses: {
          201: { description: 'Registered; the response carries the new `clientId`' },
          400: { description: 'A redirect URI is not acceptable' },
          403: { description: 'Admin privileges required' },
        },
      },
    },

    '/admin/oidc/clients/{clientId}': {
      delete: {
        tags: ['Admin'],
        summary: 'Remove an application',
        security: [{ BearerAuth: [] }],
        parameters: [{ name: 'clientId', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Removed — sign-ins to it stop' },
          403: { description: 'Admin privileges required' },
          404: { description: 'No such client' },
          409: { description: 'The console is built in and cannot be removed' },
        },
      },
    },

    '/metrics': {
      get: {
        tags: ['Operations'],
        summary: 'Metrics, in Prometheus text format',
        description:
          'Error rates by area and status, policy synchronisation latency, Redis status, backup age ' +
          'and log-forwarding health. Off (404) unless the gateway was started with METRICS_TOKEN; ' +
          'answers only that token — an account\'s session, even an admin\'s, is not accepted.',
        security: [{ BearerAuth: [] }],
        responses: {
          200: { description: 'text/plain; version=0.0.4' },
          401: { description: 'The scrape token is missing or wrong' },
          404: { description: 'Metrics are not enabled' },
        },
      },
    },

    '/auth/change-password': {
      post: {
        tags: ['Auth'],
        summary: 'Change your own password',
        description:
          'Verifies the current password, stores the new one (Argon2), and ' +
          'bumps the account\'s tokenVersion — invalidating every ' +
          'outstanding JWT for this user, including the one used on this call.\n\n' +
          'This is also how a temporary password is replaced: it is one of the two routes an ' +
          'account with `mustChangePassword` can reach.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['currentPassword', 'newPassword'],
                properties: {
                  currentPassword: { type: 'string', example: 'SecurePass123!' },
                  newPassword: { type: 'string', example: 'EvenMoreSecure456!' },
                },
              },
            },
          },
        },
        responses: {
          200: { description: 'Password changed; all sessions invalidated' },
          400: { description: 'Missing currentPassword or newPassword, or the new password is the same as the current one' },
          401: { description: 'Missing/invalid token, or current password incorrect' },
        },
      },
    },

    // ── Self-Service (any authenticated user) ─────────────────────────────────
    '/me': {
      get: {
        tags: ['Self-Service'],
        summary: 'Get your own username, primary role, and Casbin roles',
        security: [{ BearerAuth: [] }],
        responses: {
          200: { description: 'Your identity', content: { 'application/json': { schema: { $ref: '#/components/schemas/UserEntry' } } } },
          401: { description: 'Missing or invalid token' },
        },
      },
    },

    '/catalog/services': {
      get: {
        tags: ['Self-Service'],
        summary: 'Browse active services (no baseUrl — that stays internal)',
        description: 'Each entry includes `rolesWithAccess` so a user knows which role to request.',
        security: [{ BearerAuth: [] }],
        responses: {
          200: { description: 'Service catalog' },
          401: { description: 'Missing or invalid token' },
        },
      },
    },

    '/catalog/roles': {
      get: {
        tags: ['Self-Service'],
        summary: 'List all defined role names',
        security: [{ BearerAuth: [] }],
        responses: {
          200: { description: 'Role names' },
          401: { description: 'Missing or invalid token' },
        },
      },
    },

    '/requests': {
      post: {
        tags: ['Self-Service'],
        summary: 'Request a role and/or access to a service',
        description:
          'At least one of `tenant`/`role`/`service` is required.\n\n' +
          'Naming a `tenant` routes the request to **that tenant\'s own administrators**, who ' +
          'approve it from their console — the platform admin is not in the loop. Omitting ' +
          '`tenant` falls back to a platform-level role request resolved by the platform admin. ' +
          'If `role` is omitted, whoever approves picks the role.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                properties: {
                  tenant:  { type: 'string', example: 'payments', description: "Send this to that tenant's admins instead of the platform admin" },
                  role:    { type: 'string', example: 'blue_role' },
                  service: { type: 'string', example: 'llm' },
                  note:    { type: 'string', example: 'need LLM access for a demo' },
                },
              },
            },
          },
        },
        responses: {
          201: { description: 'Request submitted', content: { 'application/json': { schema: { $ref: '#/components/schemas/AccessRequest' } } } },
          400: { description: 'None of tenant, role or service provided' },
          404: { description: 'Requested tenant or role does not exist' },
          409: { description: 'Already has the role, or a pending request for it already exists' },
        },
      },
    },

    '/requests/me': {
      get: {
        tags: ['Self-Service'],
        summary: 'List your own requests and their status',
        security: [{ BearerAuth: [] }],
        responses: {
          200: {
            description: 'Your requests',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    count: { type: 'integer' },
                    requests: { type: 'array', items: { $ref: '#/components/schemas/AccessRequest' } },
                  },
                },
              },
            },
          },
          401: { description: 'Missing or invalid token' },
        },
      },
    },

    // ── Admin ────────────────────────────────────────────────────────────────
    '/admin/users': {
      get: {
        tags: ['Admin'],
        summary: 'List all users with their roles',
        security: [{ BearerAuth: [] }],
        responses: {
          200: {
            description: 'All known users',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    count: { type: 'integer', example: 3 },
                    users: { type: 'array', items: { $ref: '#/components/schemas/UserEntry' } },
                  },
                },
              },
            },
          },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
        },
      },
    },

    '/admin/users/{username}': {
      get: {
        tags: ['Admin'],
        summary: 'Get a single user',
        security: [{ BearerAuth: [] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: {
            description: 'User details',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/UserEntry' } } },
          },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
          404: { description: 'User not found' },
        },
      },
      delete: {
        tags: ['Admin'],
        summary: 'Delete a user and all of their role assignments',
        security: [{ BearerAuth: [] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'User deleted' },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
          404: { description: 'User not found' },
        },
      },
    },

    '/admin/users/{username}/suspend': {
      post: {
        tags: ['Admin'],
        summary: 'Suspend an account',
        description:
          'Switches the account off without destroying it. It can no longer sign in, and every ' +
          'session it has is ended at once (its security version is moved, so every token issued ' +
          'before this call stops authenticating). Roles, tenant memberships and requests are ' +
          'kept, so reactivating restores it whole. An admin cannot suspend their own account.',
        security: [{ BearerAuth: [] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Suspended; sessions ended' },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
          404: { description: 'User not found' },
          409: { description: 'You cannot suspend your own account' },
        },
      },
    },

    '/admin/users/{username}/reactivate': {
      post: {
        tags: ['Admin'],
        summary: 'Reactivate a suspended account',
        security: [{ BearerAuth: [] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Reactivated — the account can sign in again' },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
          404: { description: 'User not found' },
        },
      },
    },

    '/admin/users/{username}/revoke-sessions': {
      post: {
        tags: ['Admin'],
        summary: 'End every session of an account',
        description: 'The account stays active and can sign in again; every token it holds now stops working.',
        security: [{ BearerAuth: [] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: 'Sessions ended' },
          403: { description: 'Admin privileges required' },
          404: { description: 'User not found' },
        },
      },
    },

    '/admin/users/{username}/recovery-link': {
      post: {
        tags: ['Admin'],
        summary: 'Issue a one-time password recovery link',
        description:
          'For handing to the account\'s owner out of band. Unlike reset-password, the admin never ' +
          'learns the password. The link works once, for 30 minutes, and cancels any earlier one. ' +
          'It is returned in this response only; it is not logged.',
        security: [{ BearerAuth: [] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        responses: {
          200: { description: '`link`, `token` and `expiresAt`' },
          403: { description: 'Admin privileges required' },
          404: { description: 'User not found' },
        },
      },
    },

    '/admin/users/{username}/attributes': {
      put: {
        tags: ['Admin'],
        summary: 'Set the attributes policy conditions are evaluated against',
        description:
          'Replaces the account\'s attributes (`subject.*` in a condition). Only a platform admin can: ' +
          'an account that could describe itself could satisfy any condition. Ends the account\'s sessions.',
        security: [{ BearerAuth: [] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object', required: ['attributes'],
            properties: { attributes: { type: 'object', example: { department: 'radiology', clearance: 2 } } },
          } } },
        },
        responses: {
          200: { description: 'Attributes replaced' },
          400: { description: 'Not a flat object of strings, numbers and booleans' },
          403: { description: 'Admin privileges required' },
          404: { description: 'User not found' },
        },
      },
    },

    '/admin/users/{username}/reset-password': {
      post: {
        tags: ['Admin'],
        summary: "Force-reset a user's password",
        description:
          'Sets a TEMPORARY password on the target account — its holder must replace it at next ' +
          'sign-in — and bumps its tokenVersion, invalidating every JWT that account currently holds. ' +
          'Prefer a recovery link, which does not put the account\'s password in an admin\'s hands.',
        security: [{ BearerAuth: [] }],
        parameters: [{ name: 'username', in: 'path', required: true, schema: { type: 'string' } }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['newPassword'],
                properties: { newPassword: { type: 'string', example: 'TempPass789!' } },
              },
            },
          },
        },
        responses: {
          200: { description: 'Password reset; all of the user\'s sessions invalidated' },
          400: { description: 'Missing newPassword' },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
          404: { description: 'User not found' },
        },
      },
    },

    '/admin/roles': {
      get: {
        tags: ['Admin'],
        summary: 'List all defined role names and their members',
        security: [{ BearerAuth: [] }],
        responses: {
          200: {
            description: 'All defined roles',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    count: { type: 'integer', example: 5 },
                    roles: { type: 'array', items: { $ref: '#/components/schemas/RoleEntry' } },
                  },
                },
              },
            },
          },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
        },
      },
      post: {
        tags: ['Admin'],
        summary: 'Assign a Casbin role to a user',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/RoleAssignment' },
              examples: {
                grantBlue: { summary: 'Grant blue_role', value: { username: 'alice', role: 'blue_role' } },
                grantRed:  { summary: 'Grant red_role',  value: { username: 'bob',   role: 'red_role' } },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Role assigned',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: { type: 'string', example: "Role 'blue_role' assigned to 'alice'" },
                  },
                },
              },
            },
          },
          400: { description: 'Missing username or role' },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
          404: { description: 'User not found' },
        },
      },
      delete: {
        tags: ['Admin'],
        summary: 'Remove a role from a user',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': { schema: { $ref: '#/components/schemas/RoleAssignment' } },
          },
        },
        responses: {
          200: { description: 'Role removed' },
          400: { description: 'Missing username or role' },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
          404: { description: 'User or role assignment not found' },
        },
      },
    },

    '/admin/roles/define': {
      post: {
        tags: ['Admin'],
        summary: 'Register a new role name without assigning it to anyone',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['role'],
                properties: { role: { type: 'string', example: 'purple_role' } },
              },
            },
          },
        },
        responses: {
          201: { description: 'Role defined' },
          400: { description: 'Missing role' },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
          409: { description: 'Role already exists' },
        },
      },
    },

    '/admin/policies': {
      get: {
        tags: ['Admin'],
        summary: 'List all Casbin policy rules',
        security: [{ BearerAuth: [] }],
        responses: {
          200: {
            description: 'All policy rules',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    count: { type: 'integer', example: 4 },
                    version: {
                      type: 'integer',
                      description:
                        'The policy version this gateway instance is enforcing. Every change, made through ' +
                        'any instance, increments it; instances that have seen the same changes report the same number.',
                    },
                    policies: { type: 'array', items: { $ref: '#/components/schemas/PolicyEntry' } },
                  },
                },
              },
            },
          },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
        },
      },
      post: {
        tags: ['Admin'],
        summary: 'Add a Casbin access-control policy rule',
        description:
          'Adds a `(subject, resource, action)` rule. ' +
          'Subject is a role name, a tenant role (`t:{tenant}:{role}`), or one account written ' +
          'explicitly as `user:{username}`. Resource supports `keyMatch` wildcards. ' +
          'An optional `condition` (see the Condition schema) makes the rule grant only while it holds.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/PolicyRule' },
              examples: {
                claudeAccess: {
                  summary: 'blue_role → GET /llm/claude',
                  value: { subject: 'blue_role', resource: '/llm/claude', action: 'get' },
                },
                visionAccess: {
                  summary: 'red_role → GET /vision/service3',
                  value: { subject: 'red_role', resource: '/vision/service3', action: 'get' },
                },
              },
            },
          },
        },
        responses: {
          200: {
            description: 'Policy added',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message: {
                      type: 'string',
                      example: 'Policy added: blue_role can get on /llm/claude',
                    },
                  },
                },
              },
            },
          },
          400: { description: 'Missing subject, resource or action' },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
        },
      },
      delete: {
        tags: ['Admin'],
        summary: 'Remove a Casbin access-control policy rule',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { $ref: '#/components/schemas/PolicyRule' } } },
        },
        responses: {
          200: { description: 'Policy removed' },
          400: { description: 'Missing subject, resource or action' },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
          404: { description: 'Policy rule not found' },
        },
      },
    },

    '/admin/services': {
      get: {
        tags: ['Admin'],
        summary: 'Force-refresh the gateway service cache and return it',
        security: [{ BearerAuth: [] }],
        responses: {
          200: {
            description: 'Current gateway service cache after fresh sync',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    lastSyncTime: { type: 'string', format: 'date-time' },
                    registryUrl:  { type: 'string', example: 'http://localhost:3001' },
                    count:        { type: 'integer', example: 2 },
                    services: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/ServiceEntry' },
                    },
                  },
                },
              },
            },
          },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
        },
      },
    },

    '/admin/requests': {
      get: {
        tags: ['Admin'],
        summary: 'List access requests (optionally filtered by status)',
        security: [{ BearerAuth: [] }],
        parameters: [
          { in: 'query', name: 'status', schema: { type: 'string', enum: ['pending', 'approved', 'rejected'] } },
        ],
        responses: {
          200: {
            description: 'Requests',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    count: { type: 'integer' },
                    requests: { type: 'array', items: { $ref: '#/components/schemas/AccessRequest' } },
                  },
                },
              },
            },
          },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
        },
      },
    },

    '/admin/requests/{id}/approve': {
      post: {
        tags: ['Admin'],
        summary: 'Approve a pending request — grants the role to the requesting user',
        description: 'If the request has no `role` attached (a pure service request), pass one in the body.',
        security: [{ BearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
        requestBody: {
          content: {
            'application/json': {
              schema: { type: 'object', properties: { role: { type: 'string', example: 'blue_role' } } },
            },
          },
        },
        responses: {
          200: { description: 'Approved and role granted', content: { 'application/json': { schema: { $ref: '#/components/schemas/AccessRequest' } } } },
          400: { description: 'No role attached and none provided' },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
          404: { description: 'Request, user, or role not found' },
          409: { description: 'Request already resolved' },
        },
      },
    },

    '/admin/requests/{id}/reject': {
      post: {
        tags: ['Admin'],
        summary: 'Reject a pending request',
        security: [{ BearerAuth: [] }],
        parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string', format: 'uuid' } }],
        responses: {
          200: { description: 'Rejected', content: { 'application/json': { schema: { $ref: '#/components/schemas/AccessRequest' } } } },
          401: { description: 'Missing or invalid token' },
          403: { description: 'Admin privileges required' },
          404: { description: 'Request not found' },
          409: { description: 'Request already resolved' },
        },
      },
    },

    // ── Gateway (proxied routes) ──────────────────────────────────────────────
    '/gateway/{serviceName}/{subpath}': {
      get: {
        tags: ['Gateway'],
        summary: 'Proxy a request to a downstream service (any method)',
        description:
          'Checks JWT validity → evaluates Casbin policy for `/{serviceName}/{subpath}` → ' +
          'proxies to the registered service.\n\n' +
          '**What is forwarded.** The path after `/gateway` exactly as sent (percent-encoding and ' +
          '`//` preserved, not re-normalised), the query string exactly as sent (never parsed; it ' +
          'plays no part in authorization), and the body untouched — the gateway does not read ' +
          'proxied bodies, so POST / PUT / PATCH payloads of any content type and size reach the ' +
          'service byte for byte. A path containing `.` or `..` segments (plain or `%2e`) is ' +
          'refused with 400 rather than forwarded.\n\n' +
          '**Budget.** Every authenticated request is counted against its account (by account id): ' +
          'proxied calls against `GATEWAY_REQUESTS_PER_MINUTE`, calls to the gateway\'s own API ' +
          'against `API_REQUESTS_PER_MINUTE` (1200 each by default). Responses carry ' +
          '`RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`; over budget is ' +
          '`429` with `code: "RATE_LIMITED"` and `Retry-After`.\n\n' +
          '**What the service receives.** Not the caller\'s token: the `Authorization` header is ' +
          'removed before the request is forwarded, because a bearer token is a credential for ' +
          'the whole platform and a service needs none of that to answer one call. The service is ' +
          'told who is calling instead — `X-Gateway-User-Id` (the account\'s immutable id) and ' +
          '`X-Gateway-User` (its username, URI-encoded). Both are set by the gateway on every ' +
          'request, overwriting anything the caller sent. A service receives the original token ' +
          'only if the platform operator has listed it in `FORWARD_AUTHORIZATION_TO`.\n\n' +
          '**Where it may be sent.** Only to an address inside `UPSTREAM_ALLOWED_CIDRS`. The ' +
          'service\'s hostname is resolved by the gateway, every resolved address is checked, and ' +
          'the connection is made to that address — a name that starts resolving somewhere else ' +
          'is answered with 502, not followed.\n\n' +
          '**Seeded policies (ready to test):**\n' +
          '| Role | Resource | Action |\n' +
          '|---|---|---|\n' +
          '| `blue_role` | `/llm/claude` | GET |\n' +
          '| `blue_role` | `/vision/service1` | GET |\n' +
          '| `red_role` | `/vision/service3` | GET |\n' +
          '| `green_role` | `/llm/gemini` | GET |\n' +
          '| `admin` | everything | all |',
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'serviceName',
            required: true,
            schema: { type: 'string', enum: ['llm', 'vision'] },
            description: 'Registered service name (must be active in registry)',
            example: 'llm',
          },
          {
            in: 'path',
            name: 'subpath',
            required: true,
            schema: { type: 'string' },
            description: 'Path on the downstream service',
            example: 'claude',
          },
        ],
        responses: {
          200: {
            description: 'Successful proxied response from downstream',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  description: 'Shape depends on the downstream service',
                  example: {
                    source: 'LLM 3 - Claude',
                    status: 'operational',
                    response: 'This is from Claude: What can I help you with?',
                  },
                },
              },
            },
          },
          401: { description: 'Missing or invalid JWT' },
          403: {
            description: 'Casbin policy denies this user/role for this resource',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    error: {
                      type: 'string',
                      example: 'Forbidden: You lack clearance for /llm/claude',
                    },
                  },
                },
              },
            },
          },
          404: {
            description: 'Service not found in registry or marked inactive',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    error: { type: 'string' },
                    hint:  { type: 'string' },
                  },
                },
              },
            },
          },
          502: {
            description: 'Gateway reached the service but the upstream returned an error',
          },
        },
      },
      post: {
        tags: ['Gateway'],
        summary: 'Proxy POST to a downstream service',
        security: [{ BearerAuth: [] }],
        parameters: [
          {
            in: 'path',
            name: 'serviceName',
            required: true,
            schema: { type: 'string', enum: ['llm', 'vision'] },
          },
          {
            in: 'path',
            name: 'subpath',
            required: true,
            schema: { type: 'string' },
          },
        ],
        requestBody: {
          content: {
            'application/json': {
              schema: { type: 'object', description: 'Forwarded body — shape depends on service' },
            },
          },
        },
        responses: {
          200: { description: 'Successful proxied response' },
          401: { description: 'Missing or invalid JWT' },
          403: { description: 'Policy denied' },
          404: { description: 'Service not found' },
          502: { description: 'Upstream error' },
        },
      },
    },

    // ── Registry (port 3001 — shown here for completeness) ─────────────────
    '/register': {
      post: {
        tags: ['Registry'],
        summary: 'Register a service with the Registry',
        description:
          'Called automatically by each microservice on startup, and by hand (or through '
          + '`POST /tenants/register`) to onboard a new one.\n\n'
          + '**`catalogUrl` is optional.** If it is absent or unreachable the service is still '
          + 'registered, from the metadata in this request, and the response carries a `warnings` '
          + 'array explaining what could not be verified. The periodic health check then records '
          + 'whether the service answers, but does not read its configuration from it — send '
          + '`PATCH /services/{name}` with `syncFromCatalog: true` to adopt what the catalog says. (Registration used to fail outright with 502 '
          + 'whenever the catalog could not be reached, which made a not-yet-running service '
          + 'impossible to onboard.)\n\n'
          + '**The registered `name` is authoritative.** A remote catalog reporting a different '
          + 'name cannot rename the entry — it only produces a warning.\n\n'
          + '**Creating needs an authenticated caller.** A name that is not yet registered can be '
          + 'created by the gateway acting for a signed-in user (`POST /tenants/register`, '
          + '`POST /admin/tenants`), or by a service presenting the operator-issued enrollment token '
          + 'as `X-Enrollment-Token`. Anything else is a 401. With no `REGISTRY_ENROLLMENT_TOKEN` '
          + 'configured, direct self-registration is off and the gateway is the only way in.\n\n'
          + '`createOnly: true` makes the call refuse (409) if the name already exists, whoever is '
          + 'asking; the gateway sets it when it vouches for a user who may add a service but has '
          + 'no claim on an existing one.\n\n'
          + '**Name ownership.** The first registration of a name returns a one-time '
          + '`serviceToken`. From then on, anything that changes or removes the record needs that '
          + 'token (`X-Service-Token` header or `serviceToken` body field): registering over the '
          + 'name again, `PATCH`, `DELETE`. That includes re-registering at the *same* `baseUrl` — '
          + 'a name and its address are both public, so matching them proves nothing. A service '
          + 'that is only restarting does not register again; it calls '
          + '`POST /services/{name}/heartbeat`.\n\n'
          + '**Destinations.** `baseUrl` and `catalogUrl` must be http(s) URLs without credentials '
          + 'whose host resolves inside `UPSTREAM_ALLOWED_CIDRS` (and matches '
          + '`UPSTREAM_ALLOWED_HOSTS` / `_PORTS` if those are set). Anything else is a 400.\n\n'
          + '**Duplicates.** A *different* name at the same `baseUrl` is allowed — one process '
          + 'routinely hosts many logical services — and the response warns which other services '
          + 'share that host. What is refused (409, with `duplicateOf`) is pointing a new name at '
          + "the catalog of a service that is **already registered**, since that only ever "
          + 'produces a second copy of it; pass `allowAlias: true` if a deliberate second name is '
          + 'intended. Endpoints reported by a catalog are dropped unless they sit under the '
          + "registering service's own `/{name}/` prefix, so an alias cannot inherit the "
          + "original's paths and be reported as sharing its access.",
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['name', 'baseUrl'],
                properties: {
                  name:         { type: 'string', example: 'llm', description: 'Lowercase slug, 2-63 chars. Also becomes the tenant id and the /gateway/{name} route.' },
                  baseUrl:      { type: 'string', example: 'http://localhost:8080' },
                  catalogUrl:   { type: 'string', example: 'http://localhost:8080/catalog', description: 'Optional. Unreachable is a warning, not an error.' },
                  endpoints:    { type: 'array', items: { type: 'string' }, example: ['/llm/claude'], description: 'Optional manual declaration; each must start with /{name}/.' },
                  version:      { type: 'string', example: 'v2.0' },
                  owner:        { type: 'string', example: 'ai_team' },
                  displayName:  { type: 'string', example: 'LLM Gateway' },
                  description:  { type: 'string' },
                  serviceToken: { type: 'string', description: 'Required only to repoint an existing name at a different baseUrl.' },
                allowAlias:   { type: 'boolean', description: 'Register even though the catalog identifies an already-registered service — i.e. deliberately create a second name for it.' },
                },
              },
            },
          },
        },
        responses: {
          201: {
            description: 'Registered. `warnings` lists anything that could not be verified; `serviceToken` is present only on the first registration of this name.',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    message:      { type: 'string' },
                    service:      { type: 'object' },
                    warnings:     { type: 'array', items: { type: 'string' } },
                    serviceToken: { type: 'string' },
                  },
                },
              },
            },
          },
          400: { description: 'Missing baseUrl, invalid or reserved name, or an endpoint outside the service namespace' },
          409: { description: 'Name already registered at a different baseUrl and no valid serviceToken was supplied' },
        },
      },
    },

    '/services': {
      get: {
        tags: ['Registry'],
        summary: 'List all registered services',
        parameters: [
          {
            in: 'query',
            name: 'status',
            schema: { type: 'string', enum: ['active', 'inactive'] },
          },
        ],
        responses: {
          200: {
            description: 'Service list',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    count: { type: 'integer' },
                    services: {
                      type: 'array',
                      items: { $ref: '#/components/schemas/ServiceEntry' },
                    },
                  },
                },
              },
            },
          },
        },
      },
    },

    '/services/{name}': {
      patch: {
        tags: ['Registry'],
        summary: "Change a registered service's configuration",
        description:
          'Requires the service token issued at first registration — pass it as the '
          + '`X-Service-Token` header or a `serviceToken` body field. Tenant admins normally go '
          + 'through `PATCH /tenants/{tenantId}/service` instead, which replays the stored token '
          + 'for them.\n\n'
          + 'This is the only way configuration changes. The health check records liveness '
          + '(`health`, `lastSeen`) and nothing else; it no longer copies endpoints, version or '
          + 'owner from the catalog, and never changes `status`. Pass `syncFromCatalog: true` to '
          + 're-read those from the service\'s `catalogUrl` as part of this (authenticated) call.',
        parameters: [{ name: 'X-Service-Token', in: 'header', schema: { type: 'string' } }],
        requestBody: {
          content: { 'application/json': { schema: { type: 'object', properties: {
            endpoints: { type: 'array', items: { type: 'string' } },
            baseUrl: { type: 'string' }, catalogUrl: { type: 'string' },
            version: { type: 'string' }, owner: { type: 'string' },
            displayName: { type: 'string' }, description: { type: 'string' },
            status: { type: 'string', enum: ['active', 'inactive'] },
            syncFromCatalog: { type: 'boolean', description: 'Re-read endpoints, version and owner from catalogUrl' },
            serviceToken: { type: 'string' },
          } } } },
        },
        responses: {
          200: { description: 'Service updated' },
          400: { description: 'Invalid field', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          403: { description: 'Missing or wrong service token', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          404: { description: 'No such service', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
      get: {
        tags: ['Registry'],
        summary: 'Get a single service by name',
        parameters: [
          {
            in: 'path',
            name: 'name',
            required: true,
            schema: { type: 'string' },
            example: 'llm',
          },
        ],
        responses: {
          200: {
            description: 'Service entry',
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/ServiceEntry' },
              },
            },
          },
          404: {
            description: 'Service not found',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
        },
      },
      delete: {
        tags: ['Registry'],
        summary: 'Deregister a service',
        description:
          'Requires the service token (`X-Service-Token` header or `serviceToken` body field). '
          + 'Removing a record takes the service off the gateway for everyone and frees its name, '
          + 'so only its owner — or a platform admin, through '
          + '`DELETE /admin/tenants/{tenantId}?deregister=true` — may do it.',
        parameters: [
          {
            in: 'path',
            name: 'name',
            required: true,
            schema: { type: 'string' },
          },
          { name: 'X-Service-Token', in: 'header', schema: { type: 'string' } },
        ],
        responses: {
          200: { description: 'Removed from registry' },
          403: { description: 'Missing or wrong service token' },
          404: { description: 'Not found' },
        },
      },
    },

    '/services/{name}/heartbeat': {
      post: {
        tags: ['Registry'],
        summary: 'Renew a service registration',
        description:
          'Lifecycle renewal — "this service is up". Requires the service token. It takes no '
          + 'configuration and changes none: only `health` and `lastSeen` are written, and any '
          + 'other field in the body is ignored. This is what a service calls when it starts '
          + 'again; registration is for creating the record, `PATCH` for changing it. The current '
          + 'record is returned so the service can see whether it still matches what it serves.',
        parameters: [
          { in: 'path', name: 'name', required: true, schema: { type: 'string' } },
          { name: 'X-Service-Token', in: 'header', schema: { type: 'string' } },
        ],
        responses: {
          200: { description: 'Renewed; returns the current record' },
          403: { description: 'Missing or wrong service token' },
          404: { description: 'No such service — register it' },
        },
      },
    },

    // ── Tenants ─────────────────────────────────────────────────────────────
    // Every registered service is a tenant that governs its own roles,
    // policies and users. `platform admin` endpoints live under /admin;
    // everything below is what a service owner uses for their own tenant.

    '/tenants/register': {
      post: {
        tags: ['Tenants'],
        summary: 'Register a service and become its tenant administrator',
        description:
          'The front door for onboarding a service. Registers it with the Service Registry, '
          + 'provisions a tenant named after it, and makes the caller its first administrator.\n\n'
          + '`catalogUrl` is optional, and an unreachable one is **not** an error: the service is '
          + 'registered from the metadata in this request, and the registry starts reporting it '
          + 'healthy once it answers. Its endpoints stay as given here until changed through '
          + '`PATCH /tenants/{tenantId}/service` (`syncFromCatalog: true` re-reads them from the '
          + 'catalog). Warnings are reported in the response.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: {
                type: 'object',
                required: ['name', 'baseUrl'],
                properties: {
                  name:        { type: 'string', example: 'payments', description: 'Lowercase slug; becomes the tenant id and the /gateway/{name} path' },
                  baseUrl:     { type: 'string', example: 'http://localhost:9090' },
                  catalogUrl:  { type: 'string', example: 'http://localhost:9090/catalog', description: 'Optional' },
                  endpoints:   { type: 'array', items: { type: 'string' }, example: ['/payments/charge'], description: 'Optional; each must start with /{name}/' },
                  version:     { type: 'string', example: 'v1' },
                  displayName: { type: 'string', example: 'Payments API' },
                  description: { type: 'string' },
                },
              },
            },
          },
        },
        responses: {
          201: { description: 'Service registered; caller is now its tenant admin' },
          400: { description: 'Invalid name or missing baseUrl', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          409: { description: 'The tenant or service name is already owned by someone else', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
        },
      },
    },

    '/tenants': {
      get: {
        tags: ['Tenants'],
        summary: 'List active tenants you could request access to',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Tenant catalogue (no baseUrl — that is internal routing)' } },
      },
    },

    '/tenants/mine': {
      get: {
        tags: ['Tenants'],
        summary: 'Tenants you belong to, and your standing in each',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Your tenants, with your roles and whether you administer them' } },
      },
    },

    '/tenants/{tenantId}': {
      parameters: [{ name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } }],
      get: {
        tags: ['Tenants'],
        summary: 'Tenant detail (members and platform admins only)',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Tenant, its roles, admins and backing service' }, 403: { description: 'Not a member' }, 404: { description: 'No such tenant' } },
      },
      patch: {
        tags: ['Tenants'],
        summary: 'Update the tenant (tenant admin)',
        description: 'Setting `status: suspended` is a kill switch — the gateway stops routing to the service immediately, without touching any policy.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          content: { 'application/json': { schema: { type: 'object', properties: {
            displayName: { type: 'string' }, description: { type: 'string' },
            status: { type: 'string', enum: ['active', 'suspended'] },
            attributes: { type: 'object', description: 'What conditions see as `resource.*` for this tenant\'s service', example: { department: 'radiology' } },
          } } } },
        },
        responses: { 200: { description: 'Updated' }, 403: { description: 'Not a tenant admin' } },
      },
    },

    '/tenants/{tenantId}/service': {
      parameters: [{ name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } }],
      patch: {
        tags: ['Tenants'],
        summary: "Create or update the tenant's backing service (tenant admin)",
        description:
          'Create-or-update: if the tenant has no service yet, supplying `baseUrl` registers one. '
          + 'The gateway replays the registry service token it holds for this tenant, and where it '
          + 'holds none — anything that self-registered — it vouches for the caller instead, who '
          + 'has already been authorised as an administrator of this tenant. Tenant admins never '
          + 'handle a registry credential themselves.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          content: { 'application/json': { schema: { type: 'object', properties: {
            endpoints: { type: 'array', items: { type: 'string' } },
            baseUrl: { type: 'string' }, catalogUrl: { type: 'string' }, version: { type: 'string' },
            displayName: { type: 'string' }, description: { type: 'string' },
            status: { type: 'string', enum: ['active', 'inactive'] },
          } } } },
        },
        responses: { 200: { description: 'Service updated' }, 409: { description: 'No service token held for this tenant' } },
      },
    },

    '/tenants/{tenantId}/users': {
      parameters: [{ name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } }],
      get: {
        tags: ['Tenants'],
        summary: 'Users of this tenant and their roles here (tenant admin)',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Tenant membership' }, 403: { description: 'Not a tenant admin' } },
      },
      post: {
        tags: ['Tenants'],
        summary: 'Add an existing platform account to this tenant (tenant admin)',
        description: 'Not a signup endpoint: identity is platform-wide, so a tenant grants access to an account rather than creating one.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', required: ['username'], properties: {
            username: { type: 'string', example: 'alice' },
            role: { type: 'string', example: 'engineer', description: 'Optional role to grant at the same time' },
          } } } },
        },
        responses: { 201: { description: 'Added' }, 404: { description: 'No such platform account, or no such role in this tenant' } },
      },
    },

    '/tenants/{tenantId}/users/{username}': {
      parameters: [
        { name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } },
        { name: 'username', in: 'path', required: true, schema: { type: 'string' } },
      ],
      delete: {
        tags: ['Tenants'],
        summary: 'Remove a member; every role they hold here is revoked (tenant admin)',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Removed' }, 409: { description: 'They own this tenant' } },
      },
    },

    '/tenants/{tenantId}/users/{username}/roles': {
      parameters: [
        { name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } },
        { name: 'username', in: 'path', required: true, schema: { type: 'string' } },
      ],
      post: {
        tags: ['Tenants'],
        summary: 'Grant a tenant role (tenant admin)',
        security: [{ BearerAuth: [] }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['role'], properties: { role: { type: 'string', example: 'engineer' } } } } } },
        responses: { 200: { description: 'Granted' }, 404: { description: 'No such role in this tenant' }, 409: { description: 'Already held' } },
      },
    },

    '/tenants/{tenantId}/users/{username}/roles/{role}': {
      parameters: [
        { name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } },
        { name: 'username', in: 'path', required: true, schema: { type: 'string' } },
        { name: 'role', in: 'path', required: true, schema: { type: 'string' } },
      ],
      delete: {
        tags: ['Tenants'],
        summary: 'Revoke a tenant role (tenant admin)',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Revoked' }, 404: { description: 'They do not hold it' } },
      },
    },

    '/tenants/{tenantId}/users/{username}/admin': {
      parameters: [
        { name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } },
        { name: 'username', in: 'path', required: true, schema: { type: 'string' } },
      ],
      post: {
        tags: ['Tenants'],
        summary: 'Make this user a tenant administrator',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Promoted' } },
      },
      delete: {
        tags: ['Tenants'],
        summary: 'Remove tenant administrator rights',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Demoted' }, 409: { description: 'They own the tenant, or are its last administrator' } },
      },
    },

    '/tenants/{tenantId}/users/{username}/permissions': {
      parameters: [
        { name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } },
        { name: 'username', in: 'path', required: true, schema: { type: 'string' } },
      ],
      put: {
        tags: ['Tenants'],
        summary: 'Delegate parts of administering the tenant to a member (full tenant admin)',
        description:
          'Administration is four separate permissions: `members` (add and remove members), `roles` ' +
          '(define, grant and revoke roles; decide requests), `policies` (what a role may reach) and ' +
          '`destinations` (where the service lives). The body is the complete set the member should ' +
          'hold; anything left out is taken away, which ends their sessions. A full tenant admin ' +
          'holds all four and is the only one who can call this.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: {
            type: 'object', required: ['permissions'],
            properties: { permissions: { type: 'array', items: { type: 'string', enum: ['members', 'roles', 'policies', 'destinations'] }, example: ['members', 'roles'] } },
          } } },
        },
        responses: {
          200: { description: 'Permissions replaced' },
          403: { description: 'Not a full administrator of this tenant' },
          404: { description: 'No such account (an account that is not yet a member becomes one)' },
        },
      },
    },

    '/tenants/{tenantId}/users/{username}/test-access': {
      parameters: [
        { name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } },
        { name: 'username', in: 'path', required: true, schema: { type: 'string' } },
      ],
      post: {
        tags: ['Tenants'],
        summary: "Would the gateway let that user reach this tenant's endpoints?",
        description:
          'Evaluated in-process by the same authorization function the proxy route uses, so the '
          + 'answer is the live path\'s own decision. **No token is issued for the user and no request '
          + 'is sent to the service**: an administrator of one tenant never holds, even briefly, a '
          + 'credential for an account that may belong to other tenants. Audited.\n\n'
          + 'Only this tenant\'s own `/{tenantId}/...` endpoints are evaluated. Each one reports '
          + '`decision` (`allowed`, `denied`, or `error` when the service is not routable), '
          + '`grantedBy` (the policy row, or the bypass role, that allows it) or `stoppedBy` plus an '
          + '`explanation`, and `status` — what the gateway itself would answer, `null` when it would '
          + 'forward the call. What the service would then reply is not part of this result; the '
          + 'account can see that for itself with `POST /me/test-access`.\n\n'
          + '`POST /admin/users/{username}/test-access` is the same evaluation across every service, '
          + 'for a platform admin.',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: '`mode: "policy-evaluation"` and, per endpoint, the decision and what granted or stopped it' } },
      },
    },

    '/me/test-access': {
      post: {
        tags: ['Self-Service'],
        summary: 'Test your own access and see exactly what you get',
        description:
          'The counterpart to the admin and tenant-admin access tests, for the person whose access '
          + 'it is. Calls every endpoint on the gateway **with your own bearer token**, so the result '
          + 'is literally what your current session gets — including, if your token is stale or '
          + 'revoked, the 401 you would really see.\n\n'
          + 'Each endpoint reports the request that was sent and the status, headers and body that '
          + 'came back (`mode: "live-call"`). This is the only access test that makes real calls: '
          + 'the admin-facing ones evaluate policy without any token, because there the account '
          + 'belongs to somebody else.',
        security: [{ BearerAuth: [] }],
        responses: {
          200: {
            description: 'Your token, your roles per tenant, and the full exchange for every endpoint',
            content: { 'application/json': { schema: { type: 'object', properties: {
              username: { type: 'string' },
              roles: { type: 'array', items: { type: 'string' } },
              tenants: { type: 'array', items: { type: 'object' } },
              token: {
                type: 'object',
                properties: {
                  value: { type: 'string' },
                  masked: { type: 'boolean' },
                  header: { type: 'object' },
                  claims: { type: 'object' },
                  expiresInSeconds: { type: 'integer' },
                  note: { type: 'string' },
                },
              },
              services: { type: 'array', items: { type: 'object', properties: {
                service: { type: 'string' },
                allowedCount: { type: 'integer' },
                totalCount: { type: 'integer' },
                endpoints: { type: 'array', items: { type: 'object', properties: {
                  endpoint: { type: 'string' },
                  status: { type: 'integer', nullable: true },
                  decision: {
                    type: 'string',
                    enum: ['allowed', 'denied', 'error'],
                    description: "Three-valued on purpose: `denied` means authorization refused it, `error` means authorization PASSED and something further along failed. Collapsing the two sends you to the wrong end of the system.",
                  },
                  stoppedBy: {
                    type: 'string', nullable: true,
                    enum: ['gateway-policy', 'gateway-authentication', 'gateway-tenant-suspended', 'upstream', 'upstream-missing-endpoint', 'upstream-error', 'upstream-unreachable', 'service-registry', 'timeout', 'network'],
                  },
                  explanation: { type: 'string', nullable: true, description: 'Plain-language reason, matched to stoppedBy' },
                  deniedBy: { type: 'string', nullable: true, deprecated: true, description: 'Former name for stoppedBy; kept for existing clients' },
                  latencyMs: { type: 'integer' },
                  request: { type: 'object', properties: { method: { type: 'string' }, url: { type: 'string' }, headers: { type: 'object' } } },
                  response: { type: 'object', nullable: true, properties: {
                    status: { type: 'integer' }, statusText: { type: 'string' },
                    headers: { type: 'object' }, json: {}, text: { type: 'string', nullable: true },
                    truncated: { type: 'boolean' },
                  } },
                } } },
              } } },
            } } } },
          },
          401: { description: 'Missing, expired or revoked token' },
        },
      },
    },

    '/tenants/{tenantId}/roles': {
      parameters: [{ name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } }],
      get: {
        tags: ['Tenants'],
        summary: 'Roles defined in this tenant, with members and policies',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Tenant roles' } },
      },
      post: {
        tags: ['Tenants'],
        summary: 'Define a role inside this tenant (tenant admin)',
        description: 'Stored in Casbin as `t:{tenantId}:{role}`, so two tenants can use the same role name without ever meeting.',
        security: [{ BearerAuth: [] }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['role'], properties: { role: { type: 'string', example: 'engineer' } } } } } },
        responses: { 201: { description: 'Defined' }, 409: { description: 'Already exists here' } },
      },
    },

    '/tenants/{tenantId}/roles/{role}': {
      parameters: [
        { name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } },
        { name: 'role', in: 'path', required: true, schema: { type: 'string' } },
      ],
      delete: {
        tags: ['Tenants'],
        summary: 'Delete a tenant role along with its policies and grants',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Deleted' }, 404: { description: 'No such role here' } },
      },
    },

    '/tenants/{tenantId}/policies': {
      parameters: [{ name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } }],
      get: {
        tags: ['Tenants'],
        summary: 'Policies belonging to this tenant',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Tenant policies' } },
      },
      post: {
        tags: ['Tenants'],
        summary: 'Attach a policy to one of this tenant\'s roles (tenant admin)',
        description: 'The subject is derived from the URL\'s tenantId, never the body, and `resource` must sit under `/{tenantId}/`. A tenant therefore cannot write a rule affecting another tenant.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', required: ['role', 'resource', 'action'], properties: {
            role:     { type: 'string', example: 'engineer' },
            resource: { type: 'string', example: '/payments/charge' },
            action:   { type: 'string', enum: ['get', 'post', 'put', 'patch', 'delete'], example: 'get' },
            condition: { $ref: '#/components/schemas/Condition' },
          } } } },
        },
        responses: { 201: { description: 'Policy added' }, 400: { description: 'The condition is not valid' }, 403: { description: 'Resource is outside this tenant\'s namespace, or the `policies` permission is missing' }, 409: { description: 'Policy already exists' } },
      },
      delete: {
        tags: ['Tenants'],
        summary: 'Remove one of this tenant\'s policies (tenant admin)',
        security: [{ BearerAuth: [] }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['role', 'resource', 'action'], properties: {
          role: { type: 'string' }, resource: { type: 'string' }, action: { type: 'string' },
        } } } } },
        responses: { 200: { description: 'Removed' }, 404: { description: 'No such policy in this tenant' } },
      },
    },

    '/tenants/{tenantId}/requests': {
      parameters: [{ name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } }],
      get: {
        tags: ['Tenants'],
        summary: "This tenant's own access-request queue (tenant admin)",
        security: [{ BearerAuth: [] }],
        parameters: [{ name: 'status', in: 'query', schema: { type: 'string', enum: ['pending', 'approved', 'rejected'] } }],
        responses: { 200: { description: 'Requests addressed to this tenant' } },
      },
    },

    '/tenants/{tenantId}/requests/{id}/approve': {
      parameters: [
        { name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } },
        { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
      ],
      post: {
        tags: ['Tenants'],
        summary: 'Approve a request and grant the role — no platform admin needed',
        security: [{ BearerAuth: [] }],
        requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { role: { type: 'string' } } } } } },
        responses: { 200: { description: 'Approved and granted' }, 409: { description: 'Already resolved' } },
      },
    },

    '/tenants/{tenantId}/requests/{id}/reject': {
      parameters: [
        { name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } },
        { name: 'id', in: 'path', required: true, schema: { type: 'string' } },
      ],
      post: {
        tags: ['Tenants'],
        summary: 'Reject a request',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Rejected' }, 409: { description: 'Already resolved' } },
      },
    },

    // ── Platform admin: tenant lifecycle ────────────────────────────────────

    '/admin/tenants': {
      get: {
        tags: ['Admin'],
        summary: 'Every tenant on the platform',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'All tenants with owners, admins, roles and service health' }, 403: { description: 'Platform admin required' } },
      },
      post: {
        tags: ['Admin'],
        summary: 'Create a tenant and register its service in one call',
        description:
          'A tenant and the service behind it are the same object seen from two sides, so this '
          + 'creates both. Supplying `baseUrl` registers the service with the Registry and stores '
          + "its service token on the tenant, so the tenant's own admins can edit it later without "
          + 'ever handling a credential. Omitting `baseUrl` creates a tenant whose service can be '
          + 'filled in later with `PATCH /tenants/{id}/service`.\n\n'
          + 'If the service registration fails the tenant is **not** created — a tenant without the '
          + 'service it exists to govern is a shell whose failure is only discovered later.',
        security: [{ BearerAuth: [] }],
        requestBody: {
          required: true,
          content: { 'application/json': { schema: { type: 'object', required: ['id'], properties: {
            id: { type: 'string', example: 'payments' }, displayName: { type: 'string' },
            description: { type: 'string' },
            baseUrl: { type: 'string', example: 'http://localhost:9090', description: 'Registers the service when present' },
            catalogUrl: { type: 'string', description: 'Optional; may be unreachable' },
            endpoints: { type: 'array', items: { type: 'string' }, example: ['/payments/charge'] },
            version: { type: 'string' },
            owner: { type: 'string', description: 'Existing username; becomes its first admin' },
          } } } },
        },
        responses: {
          201: { description: 'Created, with the registered service and any registry warnings' },
          400: { description: 'Invalid id, endpoints or baseUrl' },
          409: { description: 'Tenant already exists, or the service name is taken' },
        },
      },
    },

    '/admin/tenants/{tenantId}': {
      parameters: [{ name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } }],
      delete: {
        tags: ['Admin'],
        summary: 'Delete a tenant and every Casbin row carrying its prefix',
        description:
          'Without `?deregister=true` the backing service stays in the registry — and since a '
          + 'registered service *is* a tenant, the next sync tick provisions a blank one back '
          + 'under the same id. That is a reset, not a deletion; the response reports which '
          + 'happened via `willBeReprovisioned`.',
        security: [{ BearerAuth: [] }],
        parameters: [{ name: 'deregister', in: 'query', schema: { type: 'boolean' }, description: 'Also remove the backing service from the registry' }],
        responses: { 200: { description: 'Deleted, or reset if the service is still registered', content: { 'application/json': { schema: { type: 'object', properties: {
          message: { type: 'string' }, deregisteredService: { type: 'boolean' }, willBeReprovisioned: { type: 'boolean' },
        } } } } } },
      },
    },

    '/admin/tenants/{tenantId}/owner': {
      parameters: [{ name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } }],
      post: {
        tags: ['Admin'],
        summary: 'Assign an owner to a tenant (they also become an admin of it)',
        description: 'Tenants auto-provisioned from a self-registering service start unowned, because a machine has no user identity to hand ownership to.',
        security: [{ BearerAuth: [] }],
        requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['username'], properties: { username: { type: 'string' } } } } } },
        responses: { 200: { description: 'Owner assigned' }, 404: { description: 'No such user or tenant' } },
      },
    },

    '/health': {
      get: {
        tags: ['Registry'],
        summary: 'Registry health check',
        responses: {
          200: {
            description: 'Health status',
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    status:             { type: 'string', enum: ['ok', 'degraded'] },
                    redis:              { type: 'string', enum: ['ok', 'error'] },
                    registeredServices: { type: 'integer' },
                    uptime:             { type: 'number' },
                  },
                },
              },
            },
          },
        },
      },
    },
  },
};

module.exports = { spec };
