
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
      'Authenticate at /auth/login and pass the JWT as `Authorization: Bearer <token>`.\n\n' +
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
    { name: 'Self-Service', description: 'Any authenticated user — browse the catalog and request roles/services' },
    { name: 'Admin',    description: 'Platform-wide administration and tenant lifecycle — platform admin JWT required' },
    { name: 'Tenants',  description: 'Multi-tenancy — every registered service is a tenant that governs its own roles, policies and users' },
    { name: 'Gateway',  description: 'Proxied downstream calls — JWT + Casbin policy required' },
    { name: 'Registry', description: 'Service Registry API (port 3001)' },
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
          subject:  { type: 'string', description: 'Role or username', example: 'blue_role' },
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
        description: 'Creates a user account with the default `user` role.',
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
            description: 'Missing username or password',
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
          'Use it as `Authorization: Bearer <token>` on all protected routes.',
        requestBody: {
          required: true,
          content: {
            'application/json': {
              schema: { $ref: '#/components/schemas/Credentials' },
              examples: {
                admin: {
                  summary: 'Admin user (pre-seeded)',
                  value: { username: 'admin', password: 'adminpass' },
                },
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
            description: 'Missing username or password',
            content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } },
          },
          401: {
            description: 'Wrong username or password',
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

    '/auth/change-password': {
      post: {
        tags: ['Auth'],
        summary: 'Change your own password',
        description:
          'Verifies the current password, stores the new one (Argon2), and ' +
          'bumps the account\'s tokenVersion — invalidating every ' +
          'outstanding JWT for this user, including the one used on this call.',
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
          400: { description: 'Missing currentPassword or newPassword' },
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

    '/admin/users/{username}/reset-password': {
      post: {
        tags: ['Admin'],
        summary: "Force-reset a user's password",
        description:
          'Sets a new password on the target account and bumps its ' +
          'tokenVersion, invalidating every JWT that account currently holds.',
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
          'Subject is a role. Resource supports `keyMatch` wildcards.',
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
        summary: 'Proxy GET to a downstream service',
        description:
          'Checks JWT validity → evaluates Casbin policy for `/{serviceName}/{subpath}` → ' +
          'proxies to the registered service.\n\n' +
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
          + 'array explaining what could not be verified; the periodic health check fills in live '
          + 'metadata as soon as the service answers. (Registration used to fail outright with 502 '
          + 'whenever the catalog could not be reached, which made a not-yet-running service '
          + 'impossible to onboard.)\n\n'
          + '**The registered `name` is authoritative.** A remote catalog reporting a different '
          + 'name cannot rename the entry — it only produces a warning.\n\n'
          + '**Name ownership.** The first registration of a name returns a one-time '
          + '`serviceToken`. Re-registering the same name at the same `baseUrl` stays open (so a '
          + 'restarting service needs no state of its own), but repointing it at a different host '
          + 'requires that token.\n\n'
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
        summary: "Update a registered service's metadata",
        description:
          'Requires the service token issued at first registration — pass it as the '
          + '`X-Service-Token` header or a `serviceToken` body field. Tenant admins normally go '
          + 'through `PATCH /tenants/{tenantId}/service` instead, which replays the stored token '
          + 'for them.',
        parameters: [{ name: 'X-Service-Token', in: 'header', schema: { type: 'string' } }],
        requestBody: {
          content: { 'application/json': { schema: { type: 'object', properties: {
            endpoints: { type: 'array', items: { type: 'string' } },
            baseUrl: { type: 'string' }, catalogUrl: { type: 'string' },
            version: { type: 'string' }, owner: { type: 'string' },
            displayName: { type: 'string' }, description: { type: 'string' },
            status: { type: 'string', enum: ['active', 'inactive'] },
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
        parameters: [
          {
            in: 'path',
            name: 'name',
            required: true,
            schema: { type: 'string' },
          },
        ],
        responses: {
          200: { description: 'Removed from registry' },
          404: { description: 'Not found' },
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
          + 'registered from the metadata in this request and the registry fills in live metadata '
          + 'once the service answers. Warnings are reported in the response.',
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

    '/tenants/{tenantId}/users/{username}/test-access': {
      parameters: [
        { name: 'tenantId', in: 'path', required: true, schema: { type: 'string' } },
        { name: 'username', in: 'path', required: true, schema: { type: 'string' } },
      ],
      post: {
        tags: ['Tenants'],
        summary: "Probe every endpoint of this tenant's service as that user",
        description:
          'Mints a short-lived (60s) impersonation token and calls the gateway over loopback, so '
          + 'the result reflects the real authenticate → enforce → proxy path rather than a '
          + 're-reading of the policy table. Audited.\n\n'
          + 'The response records the **whole exchange** for each endpoint: the request as it was '
          + 'sent (method, URL, headers), and the response status, headers and body — so a role '
          + 'grant can be verified by what the caller actually receives, not just by a status '
          + 'code. `deniedBy` separates a gateway policy denial from an upstream one.\n\n'
          + "The token's decoded header and claims are returned in full; its raw value is masked. "
          + 'A complete token would be a working credential for that account across every tenant '
          + 'they belong to — not only this one — which would make an access test a means of '
          + 'impersonation.',
        security: [{ BearerAuth: [] }],
        responses: { 200: { description: 'Token claims plus, per endpoint, the request sent and the response received' } },
      },
    },

    '/me/test-access': {
      post: {
        tags: ['Self-Service'],
        summary: 'Test your own access and see exactly what you get',
        description:
          'The counterpart to the admin and tenant-admin access tests, for the person whose access '
          + 'it is. Calls every endpoint on the gateway **with your own bearer token** rather than '
          + 'a minted one, so the result is literally what your current session gets — including, '
          + 'if your token is stale or revoked, the 401 you would really see.\n\n'
          + 'Each endpoint reports the request that was sent and the status, headers and body that '
          + 'came back. Because the token is your own and already in your browser, it is returned '
          + 'unmasked here; the admin-facing tests mask it, since there it belongs to somebody else.',
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
          } } } },
        },
        responses: { 201: { description: 'Policy added' }, 403: { description: 'Resource is outside this tenant\'s namespace' }, 409: { description: 'Policy already exists' } },
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
