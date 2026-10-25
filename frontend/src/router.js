import { createRouter, createWebHistory } from 'vue-router'
import AccessView from '@/views/AccessView.vue'
import ApplicationsView from '@/views/ApplicationsView.vue'
import ClientsView from '@/views/ClientsView.vue'
import DashboardView from '@/views/DashboardView.vue'
import ForbiddenView from '@/views/ForbiddenView.vue'
import GroupsView from '@/views/GroupsView.vue'
import PlatformView from '@/views/PlatformView.vue'
import SessionsView from '@/views/SessionsView.vue'
import UsersView from '@/views/UsersView.vue'

/**
 * `requires` mirrors the BFF's route guards for navigation purposes only.
 * The server is the authority (IAM-0203); this just avoids showing a user a
 * screen that would only ever return 403.
 */
export const routes = [
  { path: '/', name: 'dashboard', component: DashboardView },
  {
    path: '/applications/mapdashboard',
    name: 'mapdashboard-access',
    component: ApplicationsView,
    meta: { requires: 'tenantAdmin' },
  },
  {
    // Roles and Permissions are tabs of the application access screen; each gets
    // its own entry so the menu can name them directly.
    path: '/roles',
    name: 'roles',
    component: ApplicationsView,
    meta: { requires: 'tenantAdmin', tab: 'roles' },
  },
  {
    path: '/permissions',
    name: 'permissions',
    component: ApplicationsView,
    meta: { requires: 'tenantAdmin', tab: 'permissions' },
  },
  {
    // Out of the menu: groups are only used by the POC fixtures. Kept routable.
    path: '/groups',
    name: 'groups',
    component: GroupsView,
    meta: { requires: 'tenantAdmin' },
  },
  {
    path: '/sessions',
    name: 'sessions',
    component: SessionsView,
    meta: { requires: 'tenantAdmin' },
  },
  {
    path: '/users',
    name: 'users',
    component: UsersView,
    meta: { requires: 'tenantAdmin' },
  },
  { path: '/users/:id', name: 'user-detail', component: UsersView,
    props: route => ({ detailUserId: route.params.id, detailTenant: route.query.tenant }),
    meta: { requires: 'tenantAdmin' } },
  {
    // Nested under the user because effective access is never asked in the
    // abstract - it is always "this person's". The tenant travels in the query
    // rather than being inferred, so a copied link resolves to the same subject
    // for a cross-tenant operator; the server's predicate (IAM-0204) still
    // decides whether they may see it.
    path: '/users/:id/access',
    name: 'user-access',
    component: AccessView,
    meta: { requires: 'tenantAdmin' },
  },
  {
    // IAM-0217. Not nested under a tenant in the path: the registry is always
    // read for the session's tenant, exactly as the user list is, and the server's
    // predicate (IAM-0204) decides which that may be.
    path: '/clients',
    name: 'clients',
    component: ClientsView,
    meta: { requires: 'tenantAdmin' },
  },
  {
    path: '/platform',
    name: 'platform',
    component: PlatformView,
    meta: { requires: 'platformAdmin' },
  },
  { path: '/forbidden', name: 'forbidden', component: ForbiddenView },
  { path: '/:pathMatch(.*)*', redirect: '/' },
]

/**
 * The mount path is a parameter, not a constant, because this app is intended to
 * become a microfrontend: a host would own the URL and pass its own base (or a
 * memory history for embedded mode). Keeping it injectable now costs nothing and
 * avoids a rewrite later. See server-docs/02-microfrontend-readiness.md.
 */
export const DEFAULT_BASE = '/ui/'

export function createAppRouter(getSession, { history } = {}) {
  const router = createRouter({ history: history ?? createWebHistory(DEFAULT_BASE), routes })

  router.beforeEach((to) => {
    const session = getSession()
    const needed = to.meta?.requires
    if (needed && session && !session.permissions?.[needed]) {
      return { name: 'forbidden' }
    }
    return true
  })

  return router
}
