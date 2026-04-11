# HashiCorp-Style Vault UI — End-to-End Implementation Plan

## 1) Current state (what you already have)

Based on the current Django project, you already have the essential backend capabilities needed for a modern Vault-like UI:

- **Core vault lifecycle + session model** in `vault` app (`initialize`, `unseal`, `seal`, login/session gating).
- **Secrets hierarchy** in `vault_dashboard` app: Environment → Folder → Secret.
- **Policy model** with user/group policy controls and machine auth (AppRole/JWT).
- **Deletion approvals**, **audit logs**, **notifications**, and **analysis/incidents** endpoints.
- A large single-template dashboard at `vault_dashboard/templates/vault_dashboard/dashboard.html` that currently mixes layout + styles + interactions in one file.

So this is not a greenfield product. You are in a **refactor + UX architecture** stage, not a backend feature-gap stage.

---

## 2) Target UX benchmark (HashiCorp Vault-inspired)

A UI similar to HashiCorp Vault should feel:

- **Navigation-first**: persistent left sidebar, clear section hierarchy.
- **Task-driven**: quick actions (create secret, reveal, rotate, copy path, policy test).
- **Stateful**: clear sealed/unsealed/authenticated state at all times.
- **Operationally safe**: explicit destructive actions, approvals, and audit context.
- **Multi-tenant aware**: environment/project scoping visible in header and breadcrumbs.

---

## 3) Recommended UI information architecture

Build these top-level sections in the sidebar:

1. **Overview**
   - Vault health, sealed state, recent activity, expiring secrets summary.
2. **Secrets**
   - Environment/folder tree, secret table, reveal/copy/version actions.
3. **Policies**
   - Human access policies (user/group), policy docs, policy simulator.
4. **Machine Auth**
   - AppRole, JWT/OIDC workload identity, issued session tokens.
5. **Approvals**
   - Pending delete approvals, owner/admin workflow.
6. **Audit & Insights**
   - Audit logs, incident feed, saved analysis queries.
7. **Settings**
   - Secret naming/regex rules, feature flags, notification controls.

---

## 4) Frontend architecture (recommended)

### Option A (best medium/long-term): Componentized Django templates + vanilla JS

- Keep Django server-rendered pages.
- Break monolithic template into:
  - `templates/base_app_shell.html`
  - `templates/components/sidebar.html`
  - `templates/components/topbar.html`
  - `templates/components/secret_table.html`
  - section templates per feature.
- Move inline CSS to static assets:
  - `static/css/app-shell.css`
  - `static/css/secrets.css`
  - `static/css/policy.css`
- Move script blocks into:
  - `static/js/secrets.js`
  - `static/js/policy.js`
  - `static/js/analysis.js`

### Option B: React/Vue SPA

Useful for very dynamic UX, but higher migration and auth/session complexity. I would **not** start here given your current codebase maturity and delivery speed.

---

## 5) Backend-to-UI contract map (already available)

You can wire these existing routes directly into a polished UI flow:

- Secrets CRUD and reveal/copy/search:
  - `add-environment`, `add-folder`, `add-secret`, `reveal-secret`, `copy-secret`, `search-secret-paths`.
- Policy engine:
  - `policy-engine/save-ui`, `policy-engine/save-document`, group membership/policy attach/detach.
- Machine auth:
  - AppRole/JWT save + JWT login.
- Governance:
  - delete approval approve/reject + env-level approval toggle.
- Analysis:
  - run/query incidents + saved queries.

This means most UI work is **composition and workflow**, not new API design.

---

## 6) End-to-end implementation phases

## Phase 0 — Foundation hardening (1–2 days)

- Set visual design tokens (color, spacing, typography).
- Define common page layout (sidebar + top header + content panels).
- Introduce reusable Django template partials.
- Add route-level breadcrumbs and active nav state.

**Definition of done:** all pages share one shell and component system.

## Phase 1 — Secrets experience (3–5 days)

- Build tree explorer (Environment/Folder).
- Build secrets list table with:
  - key name, expiry, owner, last accessed (if available), access toggle.
- Add row actions: reveal (masked by default), copy value/path, delete/request-delete.
- Add “create secret” drawer/modal and folder creation inline.
- Add advanced filters: expiring soon, environment, owner.

**Definition of done:** secrets management UX is faster and clearer than current dashboard.

## Phase 2 — Policy UX (3–4 days)

- Split into two tabs: **Visual Policy Builder** and **Policy Document Editor**.
- Add subject selector (user/group), scope selector (global/env/folder/secret), permissions matrix.
- Build policy simulation panel (“Can user X read secret Y?”).

**Definition of done:** administrators can reason about access without reading raw DB records.

## Phase 3 — Machine auth + approvals (2–3 days)

- AppRole management screen (role, secret id rotation controls, bound scopes).
- JWT workload identity setup screen (issuer, audience, subject claim mapping).
- Approval queue UI with timeline and decision notes.

**Definition of done:** service-to-service and governance flows are first-class, not hidden.

## Phase 4 — Audit + analysis cockpit (2–3 days)

- Unified feed: audit events + incidents.
- Saved query library with one-click rerun.
- Alert routing status cards.

**Definition of done:** security/operations users can investigate activity from one pane.

## Phase 5 — Production readiness (2 days)

- Add loading/empty/error states for all async actions.
- Add toast notifications and optimistic updates where safe.
- Add accessibility pass (keyboard nav, focus states, contrast, aria labels).
- Add responsive behavior for 1280+, tablet, and narrow laptop widths.

**Definition of done:** stable, supportable operator UI.

---

## 7) Suggested folder/file refactor blueprint

```text
templates/
  base_app_shell.html
  components/
    sidebar.html
    topbar.html
    stats_cards.html
    table_toolbar.html
  vault_dashboard/
    pages/
      overview.html
      secrets.html
      policies.html
      machine_auth.html
      approvals.html
      audit_insights.html
      settings.html

static/
  css/
    tokens.css
    app-shell.css
    secrets.css
    policies.css
    auth.css
  js/
    api-client.js
    sections/
      secrets.js
      policies.js
      machine-auth.js
      approvals.js
      analysis.js
```

---

## 8) Security UX requirements (must-have)

- Mask all secret values by default.
- Add “click-and-hold to reveal” (or timed reveal) for sensitive contexts.
- Require confirmation + reason for destructive actions.
- Show approval status inline before deletion.
- Never expose encrypted payloads or key material in DOM attributes.
- Ensure CSRF token handling in all POST actions.

---

## 9) Recommended acceptance criteria

- New user can create environment → folder → secret in under 2 minutes.
- Admin can grant scoped read-only access via visual policy builder in under 90 seconds.
- Service owner can configure machine auth (AppRole or JWT) without terminal commands.
- All delete actions either complete with confirmation or move to approval queue.
- Audit trail is visible from every critical workflow.

---

## 10) Delivery strategy for your team

- **Sprint 1:** Foundation + Secrets.
- **Sprint 2:** Policies + Machine auth.
- **Sprint 3:** Approvals + Audit/Insights + hardening.

If you want, next I can generate the **actual first implementation patch** for Sprint 1:

1. base shell template,
2. extracted sidebar/topbar components,
3. secrets page split from monolithic dashboard,
4. CSS/JS asset extraction,
5. incremental URL/view wiring (backward compatible).
