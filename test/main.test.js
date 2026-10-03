/**
 * End-to-End Test Suite for IAM API Gateway
 * Requires Node.js v18+ (for native fetch)
 * * INSTRUCTIONS:
 * 1. Ensure your API Gateway (src/main.js) is currently RUNNING in another terminal.
 * 2. Run this test suite using the native Node test runner:
 * node --test tests/e2e.test.js
 */

const test = require('node:test');
const assert = require('node:assert');

const BASE_URL = 'http://localhost:3000';

// --- HELPER FUNCTIONS ---
async function postJSON(endpoint, payload, token = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  const res = await fetch(`${BASE_URL}${endpoint}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });

  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

async function getAuth(endpoint, token) {
  const headers = { Authorization: `Bearer ${token}` };
  const res = await fetch(`${BASE_URL}${endpoint}`, { headers });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

// --- TEST SCENARIOS ---
test('IAM API Gateway - Full Scenario Coverage', async (t) => {
  let adminToken;
  let userToken;
  const testUser = `user_${Date.now()}`; // Unique user for this run

  await t.test('1. Admin Login', async () => {
    // There is no built-in admin password: say which platform admin to run as.
    assert.ok(process.env.ADMIN_PASSWORD, 'set ADMIN_PASSWORD to a platform admin password');
    const { status, data } = await postJSON('/auth/login', {
      username: process.env.ADMIN_USERNAME || 'admin',
      password: process.env.ADMIN_PASSWORD,
    });
    assert.strictEqual(status, 200, 'Admin should be able to login');
    assert.ok(data.token, 'Should receive a JWT token');
    adminToken = data.token;
  });

  await t.test('2. Register a new user', async () => {
    const { status, data } = await postJSON('/auth/signup', {
      username: testUser,
      password: 'password123',
    });
    assert.strictEqual(status, 201, 'User should be successfully registered');
  });

  await t.test('3. Login as the new user', async () => {
    const { status, data } = await postJSON('/auth/login', {
      username: testUser,
      password: 'password123',
    });
    assert.strictEqual(status, 200, 'User should be able to login');
    assert.ok(data.token, 'User should receive a JWT token');
    userToken = data.token;
  });

  await t.test(
    '4. Attempt unpermitted access to a service (Should be Blocked)',
    async () => {
      // User tries to access Gemini without having any roles assigned yet
      const { status, data } = await getAuth('/gateway/llm/gemini', userToken);
      assert.strictEqual(status, 403, 'Casbin should block the request');
      assert.strictEqual(
        data.error,
        'Forbidden: You lack clearance for /llm/gemini',
      );
    },
  );

  await t.test(
    '5. Admin grants access to user via role assignment',
    async () => {
      // Admin assigns 'green_role' to the user (which has access to /llm/gemini)
      const { status, data } = await postJSON(
        '/admin/roles',
        {
          username: testUser,
          role: 'green_role',
        },
        adminToken,
      );
      assert.strictEqual(status, 200, 'Admin should successfully assign role');
    },
  );

  await t.test('6. Attempt permitted access (Should Succeed)', async () => {
    // User tries again, Casbin should now allow it and proxy to the mock LLM machine
    const { status, data } = await getAuth('/gateway/llm/gemini', userToken);
    assert.strictEqual(
      status,
      200,
      'Gateway should proxy the request successfully',
    );
    assert.strictEqual(
      data.source,
      'LLM 1 - Gemini',
      'Should receive response from the target microservice',
    );
  });

  await t.test(
    '7. Admin registers a completely NEW service dynamically',
    async () => {
      const { status, data } = await postJSON(
        '/admin/services',
        {
          name: 'analytics',
          baseUrl: 'http://localhost:8080', // Re-using LLM machine port to simulate active host
          version: 'v1',
          owner: 'data_team',
          status: 'active',
        },
        adminToken,
      );
      assert.strictEqual(
        status,
        200,
        'Admin should successfully register new service into Redis',
      );
    },
  );

  await t.test(
    '8. Admin dynamically adds a policy for the new service',
    async () => {
      const { status, data } = await postJSON(
        '/admin/policies',
        {
          subject: `user:${testUser}`, // Granting directly to the user — a bare name is always a role
          resource: '/analytics/metrics',
          action: 'get',
        },
        adminToken,
      );
      assert.strictEqual(
        status,
        200,
        'Admin should successfully add Casbin policy',
      );
    },
  );

  await t.test(
    '9. User accesses the newly registered and permitted service',
    async () => {
      // Test the newly mapped dynamic proxy
      const { status } = await getAuth('/gateway/analytics/metrics', userToken);

      // As long as the status is NOT 403, it means Casbin authorized it and the API Gateway successfully attempted to proxy it.
      // (It might be 404 because the mock machine on 8080 doesn't actually have a /analytics/metrics route, but the Gateway did its job!)
      assert.notStrictEqual(
        status,
        403,
        'Casbin should allow access to the dynamically added service',
      );
    },
  );
});
