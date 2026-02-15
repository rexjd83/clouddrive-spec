// worker_7.js — Spec-aligned skeleton (Phases 0–6) + /api/collection routing layer placeholder
// Base: worker_2.js (Phase 2: Cards owner)
// Generated: 2026-01-20 (Asia/Taipei)

const BUILD_ID = 'worker_8_phase8_search_owner_plus_collection_20260120';



const CONTRACT_VERSION = 'v7.33'; // pinned by spec freeze
const DEFAULT_RATE_LIMIT = 300; // placeholder; Phase 1 requires headers, Phase 5 adds real enforcement

// -----------------------------
// ULID (Crockford base32, 26 chars) — v7.33
// -----------------------------
const ULID_CHARS = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function ulidEncodeTime(timeMs) {
  let t = Math.max(0, Number(timeMs) | 0);
  // time is 48 bits; JS bit ops are 32-bit, so use division
  let out = '';
  let time = Number(timeMs);
  for (let i = 0; i < 10; i++) {
    const mod = time % 32;
    out = ULID_CHARS.charAt(mod) + out;
    time = Math.floor(time / 32);
  }
  return out;
}

function ulidEncodeRandom() {
  const a = new Uint8Array(16);
  crypto.getRandomValues(a);
  // 80 bits => 16 chars base32 (we take 10 bytes = 80 bits)
  // We'll encode 16 bytes anyway; truncate to 16 chars for simplicity (stable).
  // Deterministic length: 16 chars
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < a.length; i++) {
    value = (value << 8) | a[i];
    bits += 8;
    while (bits >= 5) {
      out += ULID_CHARS.charAt((value >>> (bits - 5)) & 31);
      bits -= 5;
    }
  }
  if (bits > 0) out += ULID_CHARS.charAt((value << (5 - bits)) & 31);
  return out.slice(0, 16);
}

function makeUlid(nowMs = Date.now()) {
  return ulidEncodeTime(nowMs) + ulidEncodeRandom();
}

function isUlid(s) {
  return typeof s === 'string' && /^[0-9A-HJKMNP-TV-Z]{26}$/.test(s);
}

// -----------------------------
// Contract enforcement + response headers (Phase 0 deliverables)
// -----------------------------
function getRequestId(request) {
  const rid = request.headers.get('X-Request-Id');
  if (rid && isUlid(rid)) return rid;
  return makeUlid();
}

function rateLimitHeaders(nowMs = Date.now()) {
  // Placeholder (Phase 5 upgrades to KV/DO backed counters)
  const reset = Math.floor((nowMs + 60_000) / 1000);
  return {
    'X-RateLimit-Limit': String(DEFAULT_RATE_LIMIT),
    'X-RateLimit-Remaining': String(DEFAULT_RATE_LIMIT - 1),
    'X-RateLimit-Reset': String(reset),
  };
}

function withStandardHeaders(resp, request_id) {
  const h = new Headers(resp.headers);
  h.set('X-Contract-Version', CONTRACT_VERSION);
  h.set('X-Request-Id', request_id);
  const rl = rateLimitHeaders();
  for (const [k, v] of Object.entries(rl)) h.set(k, v);
  return new Response(resp.body, { status: resp.status, headers: h });
}

async function requireContractVersion(request) {
  const v = request.headers.get('X-Contract-Version');
  if (v !== CONTRACT_VERSION) {
    throw new HttpError('UPGRADE_REQUIRED', 'contract version mismatch', 426, {
      expected: CONTRACT_VERSION,
      got: v,
    });
  }
}

// -----------------------------
// Envelope helpers (Frozen v1.3.2)
// -----------------------------
function okJson(data, status = 200, extraHeaders = {}) {
  return jsonResponse({ ok: true, data }, status, extraHeaders);
}

function errJson({ code, message, request_id }, status, extraHeaders = {}) {
  // v7.33 error envelope (ALL 4xx/5xx)
  return jsonResponse(
    {
      error_code: String(code || 'INTERNAL'),
      error_message: String(message || 'internal error'),
      contract_version: CONTRACT_VERSION,
      request_id: String(request_id || makeUlid()),
    },
    status,
    extraHeaders
  );
}

function jsonResponse(obj, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...extraHeaders,
  });
  return new Response(JSON.stringify(obj), { status, headers });
}

function htmlResponse(html, status = 200, extraHeaders = {}) {
  const headers = new Headers({
    'content-type': 'text/html; charset=utf-8',
    'cache-control': 'no-store',
    ...extraHeaders,
  });
  return new Response(html, { status, headers });
}

// -----------------------------
// Request ID / logging
// -----------------------------
function makeRequestId() {
  // v7.33: request_id is ULID (26 chars)
  return makeUlid();
}

function logEvent(event, fields) {
  const payload = {
    ts_ms: Date.now(),
    event,
    ...fields,
  };
  console.log(JSON.stringify(payload));
}

// -----------------------------
// Errors (Frozen set)
// -----------------------------
class HttpError extends Error {
  constructor(code, message, status, details) {
    super(message);
    this.name = 'HttpError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

function notFound(request_id, details) {
  return new HttpError('NOT_FOUND', 'not found', 404, details);
}

function forbidden(message = 'forbidden', details) {
  return new HttpError('FORBIDDEN', message, 403, details);
}

function validation(message = 'validation error', details) {
  return new HttpError('VALIDATION', message, 400, details);
}

function conflict(message = 'conflict', details) {
  return new HttpError('CONFLICT', message, 409, details);
}

// -----------------------------
// JWT (HS256) verification
// -----------------------------
function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const pad = b64.length % 4 ? '='.repeat(4 - (b64.length % 4)) : '';
  const str = atob(b64 + pad);
  const bytes = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) bytes[i] = str.charCodeAt(i);
  return bytes;
}

function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

async function hmacSha256Verify(secret, data, signatureBytes) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  return crypto.subtle.verify('HMAC', key, signatureBytes, new TextEncoder().encode(data));
}

async function verifySessionToken(jwt, jwtSecret) {
  if (!jwtSecret) throw new HttpError('INTERNAL', 'JWT secret not configured', 500);
  const parts = String(jwt || '').split('.');
  if (parts.length !== 3) throw new HttpError('AUTH_INVALID', 'invalid token format', 401);

  const [hB64, pB64, sB64] = parts;
  let header, payload;
  try {
    header = JSON.parse(bytesToUtf8(base64UrlToBytes(hB64)));
    payload = JSON.parse(bytesToUtf8(base64UrlToBytes(pB64)));
  } catch {
    throw new HttpError('AUTH_INVALID', 'invalid token encoding', 401);
  }

  if (!header || header.alg !== 'HS256' || header.typ !== 'JWT') {
    throw new HttpError('AUTH_INVALID', 'unsupported token header', 401);
  }

  const ok = await hmacSha256Verify(jwtSecret, `${hB64}.${pB64}`, base64UrlToBytes(sB64));
  if (!ok) throw new HttpError('AUTH_INVALID', 'invalid token signature', 401);

  const nowSec = Math.floor(Date.now() / 1000);
  const { viewer_id, iat, exp, jti } = payload || {};

  if (typeof viewer_id !== 'string' || !viewer_id) {
    throw new HttpError('AUTH_INVALID', 'missing viewer_id', 401);
  }
  if (typeof iat !== 'number' || typeof exp !== 'number' || typeof jti !== 'string') {
    throw new HttpError('AUTH_INVALID', 'missing claims', 401);
  }
  if (exp <= nowSec) {
    throw new HttpError('AUTH_INVALID', 'token expired', 401);
  }

  return payload;
}

async function parseViewerContext(request, env) {
  const auth = request.headers.get('authorization') || request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) throw new HttpError('AUTH_REQUIRED', 'authorization required', 401);
  const token = m[1].trim();
  const claims = await verifySessionToken(token, env.JWT_SECRET);

  // Phase 1: Owner-only endpoints. owner_id == viewer_id.
  return {
    viewer_id: claims.viewer_id,
    owner_id: claims.viewer_id,
    roles: {},
    claims,
  };
}

// Collection-viewer context placeholder (Phase 0): viewer_id may differ from owner_id.
// NOTE: Phase 7 mount-aware permissions are NOT implemented in this file; this is a routing/context layer only.
async function parseCollectionViewerContext(request, env) {
  const auth = request.headers.get('authorization') || request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) throw new HttpError('AUTH_REQUIRED', 'authorization required', 401);
  const token = m[1].trim();
  const claims = await verifySessionToken(token, env.JWT_SECRET);

  return {
    viewer_id: claims.viewer_id,
    owner_id: null,
    roles: {},
    claims,
  };
}

// -----------------------------
// Transaction wrapper (standardized)
// -----------------------------
async function withTx(db, fn) {
  await db.prepare('BEGIN').run();
  await db.prepare('PRAGMA foreign_keys = ON').run();
  try {
    const out = await fn(db);
    await db.prepare('COMMIT').run();
    return out;
  } catch (e) {
    try {
      await db.prepare('ROLLBACK').run();
    } catch {
      // ignore rollback errors
    }
    throw e;
  }
}

// -----------------------------
// Phase 9: Quota / Usage / used_bytes helpers
// -----------------------------
function getDefaultQuotaBytes(env) {
  const v = Number(env && env.DEFAULT_QUOTA_BYTES);
  if (Number.isFinite(v) && v > 0) return Math.floor(v);
  // Fallback default: 1 GiB
  return 1024 * 1024 * 1024;
}

function planRowToDto(row) {
  if (!row) return null;
  return {
    owner_id: String(row.owner_id),
    plan: String(row.plan),
    quota_bytes: Number(row.quota_bytes),
    created_at: Number(row.created_at),
    updated_at: Number(row.updated_at),
  };
}

async function getOrCreateUserPlan({ db, owner_id, default_quota_bytes }) {
  const row = await db
    .prepare('SELECT owner_id, plan, quota_bytes, created_at, updated_at FROM user_plans WHERE owner_id=? LIMIT 1')
    .bind(String(owner_id))
    .first();
  if (row) return planRowToDto(row);

  const now = Date.now();
  const plan = 'free';
  const quota_bytes = Number(default_quota_bytes);

  await db
    .prepare('INSERT INTO user_plans(owner_id, plan, quota_bytes, created_at, updated_at) VALUES(?,?,?,?,?)')
    .bind(String(owner_id), String(plan), Number(quota_bytes), now, now)
    .run();

  const created = await db
    .prepare('SELECT owner_id, plan, quota_bytes, created_at, updated_at FROM user_plans WHERE owner_id=? LIMIT 1')
    .bind(String(owner_id))
    .first();
  return planRowToDto(created);
}

async function computeOwnerUsedBytesTotal({ db, owner_id }) {
  const row = await db
    .prepare(
      `SELECT IFNULL(SUM(a.size_bytes), 0) AS used_bytes
       FROM assets a
       JOIN cards c ON c.owner_id=a.owner_id AND c.card_id=a.card_id
       JOIN folders f ON f.owner_id=c.owner_id AND f.folder_id=c.folder_id
       WHERE a.owner_id=?
         AND a.deleted_at IS NULL`
    )
    .bind(String(owner_id))
    .first();
  return Number(row?.used_bytes || 0);
}

async function computeFolderUsedBytes({ db, owner_id, folder_id }) {
  const row = await db
    .prepare(
      `SELECT IFNULL(SUM(a.size_bytes), 0) AS used_bytes
       FROM assets a
       JOIN cards c ON c.owner_id=a.owner_id AND c.card_id=a.card_id
       WHERE c.owner_id=?
         AND c.folder_id=?
         AND a.deleted_at IS NULL`
    )
    .bind(String(owner_id), String(folder_id))
    .first();
  return Number(row?.used_bytes || 0);
}

async function reconcileFolderUsedBytes({ db, owner_id, folder_id }) {
  const used_bytes = await computeFolderUsedBytes({ db, owner_id, folder_id });
  await db
    .prepare('UPDATE folders SET used_bytes=? WHERE owner_id=? AND folder_id=?')
    .bind(Number(used_bytes), String(owner_id), String(folder_id))
    .run();
  return used_bytes;
}

async function reconcileOwnerUsedBytes({ db, owner_id }) {
  const folders = await db
    .prepare('SELECT folder_id FROM folders WHERE owner_id=?')
    .bind(String(owner_id))
    .all();
  for (const r of (folders.results || [])) {
    await reconcileFolderUsedBytes({ db, owner_id, folder_id: String(r.folder_id) });
  }
}

function quotaExceeded({ quota_bytes, used_bytes, add_bytes }) {
  const remaining_bytes = Math.max(0, Number(quota_bytes) - Number(used_bytes));
  return new HttpError(
    'QUOTA_EXCEEDED',
    'quota exceeded',
    409,
    {
      quota_bytes: Number(quota_bytes),
      used_bytes: Number(used_bytes),
      add_bytes: Number(add_bytes),
      remaining_bytes,
    }
  );
}

async function assertQuotaCanAddBytes({ db, owner_id, folder_id, add_bytes, default_quota_bytes }) {
  const plan = await getOrCreateUserPlan({ db, owner_id, default_quota_bytes });
  const folder = await db
    .prepare('SELECT used_bytes, deleted_at FROM folders WHERE owner_id=? AND folder_id=? LIMIT 1')
    .bind(String(owner_id), String(folder_id))
    .first();
  if (!folder) throw notFound(null, { entity: 'folder', folder_id });
  if (folder.deleted_at != null) throw conflict('folder is in trash');

  const used = Number(folder.used_bytes || 0);
  const add = Number(add_bytes || 0);
  if (used + add > Number(plan.quota_bytes)) {
    throw quotaExceeded({ quota_bytes: plan.quota_bytes, used_bytes: used, add_bytes: add });
  }
}

// -----------------------------
// Utilities
// -----------------------------
function isLiffAppPath(pathname) {
  return pathname === '/liff' || pathname === '/liff/app' || pathname.startsWith('/liff/app/');
}

function liffShellHtml() {
  // Phase 1: still a placeholder shell (Drive UI can be wired later).
  return `<!doctype html>
<html lang="zh-Hant">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Cloud Drive (LIFF) - Phase 1</title>
  <style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;line-height:1.4;padding:24px}code{background:#f5f5f5;padding:2px 6px;border-radius:6px}</style>
</head>
<body>
  <h1>Cloud Drive (LIFF) — Phase 1</h1>
  <p>此頁為 SPA Shell 佔位。Phase 1 已完成 Owner Folders API 最小閉環。</p>
  <p><code>BUILD_ID</code>: ${BUILD_ID}</p>
</body>
</html>`;
}

function getClientIp(request) {
  return (
    request.headers.get('cf-connecting-ip') ||
    request.headers.get('x-forwarded-for') ||
    request.headers.get('x-real-ip') ||
    null
  );
}

function getUserAgent(request) {
  return request.headers.get('user-agent') || null;
}

async function readJson(request) {
  const ct = request.headers.get('content-type') || '';
  if (!ct.toLowerCase().includes('application/json')) {
    throw validation('content-type must be application/json');
  }
  let obj;
  try {
    obj = await request.json();
  } catch {
    throw validation('invalid json');
  }
  if (obj == null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw validation('json body must be an object');
  }
  return obj;
}

// Phase 1 (Roadmap): Idempotency + Optimistic Lock helpers
const IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60; // 24h (Roadmap/Whitepaper)

// Read JSON but also return raw string so we can hash for idempotency.
async function readJsonWithRaw(request) {
  const ct = request.headers.get('content-type') || '';
  if (!ct.toLowerCase().includes('application/json')) {
    throw validation('content-type must be application/json');
  }
  const raw = await request.text();
  let obj;
  try {
    obj = JSON.parse(raw);
  } catch {
    throw validation('invalid json');
  }
  if (obj == null || typeof obj !== 'object' || Array.isArray(obj)) {
    throw validation('json body must be an object');
  }
  return { obj, raw };
}

function requireIdempotencyKey(request) {
  const key = (request.headers.get('X-Idempotency-Key') || request.headers.get('x-idempotency-key') || '').trim();
  if (!key) throw new HttpError('IDEMPOTENCY_KEY_REQUIRED', 'missing X-Idempotency-Key', 400);
  // v7.33 requires ULID for idempotency keys
  if (!isUlid(key)) throw validation('X-Idempotency-Key must be a ULID (26 chars)');
  return key;
}

async function sha256Base64Url(input) {
  const enc = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', enc);
  const bytes = new Uint8Array(digest);
  // base64url
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}


function canonicalizeJsonString(raw) {
  // Stable JSON normalization: parse then stringify with sorted keys.
  // If raw is empty/null, treat as empty object.
  if (raw == null || raw === '') return '{}';
  let obj;
  try { obj = JSON.parse(raw); } catch { return raw; }
  return JSON.stringify(sortKeysDeep(obj));
}

function sortKeysDeep(v) {
  if (Array.isArray(v)) return v.map(sortKeysDeep);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortKeysDeep(v[k]);
    return out;
  }
  return v;
}
function etagFromUpdatedAt(updated_at) {
  // Weak ETag based on updated_at (ms). Stable enough for optimistic locking.
  return `W/\"u:${Number(updated_at)}\"`;
}

function requireIfMatch(request, currentEtag) {
  const ifMatch = request.headers.get('if-match');
  if (!ifMatch) return; // backward compatible; client can opt-in
  if (ifMatch !== currentEtag) throw new HttpError('VERSION_MISMATCH', 'resource version mismatch', 409);
}

function requireOwnerWrite(ctx) {
  // Phase 1 ACL (owner-only): writes must be performed by the owner themselves
  if (!ctx || ctx.viewer_id !== ctx.owner_id) throw forbidden('write requires owner');
}


/* ============================================================
 * Phase 2 — Collections & Sharing (Roadmap v7.33)
 * Goal: Controlled collaboration.
 * Includes: collections, collection_members, role model (viewer/editor/admin),
 * ACL enforcement through shared context, mount placeholder model.
 * ============================================================ */

const ROLE_ABILITIES = {
  owner:  { read: true, write: true, manage_members: true, manage_mounts: true },
  admin:  { read: true, write: true, manage_members: true, manage_mounts: true },
  editor: { read: true, write: true, manage_members: false, manage_mounts: false },
  viewer: { read: true, write: false, manage_members: false, manage_mounts: false },
};

function normalizeRole(role) {
  const r = String(role || '').toLowerCase();
  if (r === 'admin' || r === 'editor' || r === 'viewer') return r;
  return null;
}

async function getCollectionRole({ db, owner_id, collection_id, viewer_id }) {
  if (!owner_id || !collection_id || !viewer_id) return null;
  if (viewer_id === owner_id) return 'owner';

  // collection_members schema is frozen in v7.33 (role model: viewer/editor/admin).
  // We treat deleted_at != NULL as removed membership.
  const row = await db.prepare(
    `SELECT role FROM collection_members
      WHERE owner_id = ?1 AND collection_id = ?2 AND member_id = ?3 AND deleted_at IS NULL
      LIMIT 1`
  ).bind(owner_id, collection_id, viewer_id).first();

  const role = normalizeRole(row?.role);
  return role; // null means not a member
}

async function resolveCollectionPerms({ db, owner_id, collection_id, viewer_id }) {
  const role = await getCollectionRole({ db, owner_id, collection_id, viewer_id });
  if (!role) {
    return { role: null, can_read: false, can_write: false, can_manage_members: false, can_manage_mounts: false };
  }
  const ab = ROLE_ABILITIES[role] || ROLE_ABILITIES.viewer;
  return {
    role,
    can_read: !!ab.read,
    can_write: !!ab.write,
    can_manage_members: !!ab.manage_members,
    can_manage_mounts: !!ab.manage_mounts,
  };
}

function requireCollectionRead(perms) {
  if (!perms?.can_read) throw forbidden('collection read forbidden');
}

function requireCollectionWrite(perms) {
  if (!perms?.can_write) throw forbidden('collection write forbidden');
}

function requireCollectionManageMembers(perms) {
  if (!perms?.can_manage_members) throw forbidden('collection member management forbidden');
}

function requireCollectionManageMounts(perms) {
  if (!perms?.can_manage_mounts) throw forbidden('collection mount management forbidden');
}

async function withIdempotency({ env, ctx, request, bodyRaw, handler }) {
  const db = env.DB;
  const kv = env.IDEMPOTENCY_KV;
  if (!db) throw new HttpError('CONFIG_MISSING', 'DB binding missing', 501);
  if (!kv) throw new HttpError('CONFIG_MISSING', 'IDEMPOTENCY_KV binding missing', 501);

  const idemKey = requireIdempotencyKey(request);
  const method = request.method.toUpperCase();
  const path = new URL(request.url).pathname;

  // Canonical request hash: hash(canonical_json_body + method + path + owner_user_id)
  const canonicalBody = canonicalizeJsonString(bodyRaw || '{}');
  const owner_user_id = ctx.viewer_id; // auth middleware sets viewer_id; treat as owner_user_id for 1.0
  const requestHash = await sha256Base64Url(`${canonicalBody}\n${method}\n${path}\n${owner_user_id}`);

  const kvKey = `idem:v7.33:${owner_user_id}:${idemKey}`;
  const cached = await kv.get(kvKey);
  if (cached) {
    const rec = JSON.parse(cached);
    if (rec.request_hash !== requestHash) throw new HttpError('IDEMPOTENCY_CONFLICT', 'idempotency key reused with different request hash', 409);
    return new Response(rec.body, { status: rec.status, headers: rec.headers });
  }

  // D1 source-of-truth
  const nowIso = nowISO();
  const expiresIso = new Date(Date.now() + IDEMPOTENCY_TTL_SECONDS * 1000).toISOString();

  // 1) Fast path: try insert PENDING. If exists, fetch & replay/validate.
  // Note: table is required by v7.33 implementation plan.
  try {
    await db.prepare(
      `INSERT INTO idempotency_requests
        (owner_user_id, idem_key, method, path, request_hash, response_status, response_body, created_at, expires_at)
       VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, ?6, ?7)`
    ).bind(owner_user_id, idemKey, method, path, requestHash, nowIso, expiresIso).run();
  } catch (e) {
    // likely UNIQUE(owner_user_id, idem_key)
    const row = await db.prepare(
      `SELECT request_hash, response_status, response_body
         FROM idempotency_requests
        WHERE owner_user_id = ?1 AND idem_key = ?2`
    ).bind(owner_user_id, idemKey).first();

    if (!row) throw e;

    if (row.request_hash !== requestHash) throw new HttpError('IDEMPOTENCY_CONFLICT', 'idempotency key reused with different request hash', 409);

    if (row.response_status != null) {
      const status = Number(row.response_status);
      const body = row.response_body || '';
      const headersObj = {
        'content-type': 'application/json; charset=utf-8',
        'x-contract-version': CONTRACT_VERSION,
      };
      // cache replay for speed
      await kv.put(kvKey, JSON.stringify({ request_hash: requestHash, status, headers: headersObj, body }), { expirationTtl: IDEMPOTENCY_TTL_SECONDS });
      return new Response(body, { status, headers: headersObj });
    }

    // Pending/in-progress
    throw new HttpError('IDEMPOTENCY_PENDING', 'idempotency request is pending; retry later', 409);
  }

  // 2) Execute handler
  const res = await handler();

  // 3) Persist response (ALL statuses) to D1, then cache in KV
  const body = await res.clone().text();
  await db.prepare(
    `UPDATE idempotency_requests
        SET response_status = ?1, response_body = ?2
      WHERE owner_user_id = ?3 AND idem_key = ?4`
  ).bind(res.status, body, owner_user_id, idemKey).run();

  const headersObj = {};
  res.headers.forEach((v, k) => (headersObj[k] = v));
  await kv.put(kvKey, JSON.stringify({ request_hash: requestHash, status: res.status, headers: headersObj, body }), { expirationTtl: IDEMPOTENCY_TTL_SECONDS });

  return new Response(body, { status: res.status, headers: headersObj });
}


function requireNonEmptyString(v, field, maxLen = 120) {
  const s = String(v ?? '').trim();
  if (!s) throw validation(`${field} is required`);
  if (s.length > maxLen) throw validation(`${field} is too long`, { field, maxLen });
  return s;
}

function clampLimit(raw, def = 30, max = 50) {
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) return def;
  return Math.min(Math.floor(n), max);
}

function bytesToBase64Url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function utf8ToBase64Url(str) {
  return bytesToBase64Url(new TextEncoder().encode(str));
}

function base64UrlToUtf8(b64url) {
  return bytesToUtf8(base64UrlToBytes(b64url));
}

function encodeCursor(obj) {
  return utf8ToBase64Url(JSON.stringify(obj));
}

function decodeCursor(cursor) {
  try {
    const raw = base64UrlToUtf8(String(cursor || ''));
    return JSON.parse(raw);
  } catch {
    throw validation('invalid cursor');
  }
}

// -----------------------------
// Search helpers (Frozen v1.3.2)
// -----------------------------
function escapeLikeTerm(term) {
  // Escape for LIKE ... ESCAPE '\'
  return String(term || '').replace(/[\\%_]/g, '\\$&');
}

function encodeSearchCursor(obj) {
  return utf8ToBase64Url(JSON.stringify(obj));
}

function decodeSearchCursor(cursor) {
  try {
    const raw = base64UrlToUtf8(String(cursor || ''));
    const obj = JSON.parse(raw);
    if (!obj || typeof obj !== 'object') throw new Error('bad');
    return obj;
  } catch {
    throw validation('invalid cursor');
  }
}

function truncateSnippet(s, maxLen = 120) {
  const t = String(s || '');
  if (t.length <= maxLen) return t;
  return t.slice(0, maxLen);
}

function chooseSearchSnippet(q, title, text, location, match_filename) {
  const qq = String(q || '').trim();
  if (!qq) return '';
  const needle = qq.toLowerCase();

  const tTitle = String(title || '');
  const tText = String(text || '');
  const tLoc = String(location || '');
  const tFile = String(match_filename || '');

  if (tTitle && tTitle.toLowerCase().includes(needle)) return truncateSnippet(tTitle);
  if (tText && tText.toLowerCase().includes(needle)) return truncateSnippet(tText);
  if (tLoc && tLoc.toLowerCase().includes(needle)) return truncateSnippet(tLoc);
  if (tFile && tFile.toLowerCase().includes(needle)) return truncateSnippet(tFile);
  // Fallback: prefer title/text/location
  return truncateSnippet(tTitle || tText || tLoc || tFile || '');
}

function newId(prefix) {
  try {
    return `${prefix}_${crypto.randomUUID().replace(/-/g, '')}`;
  } catch {
    const a = new Uint8Array(16);
    crypto.getRandomValues(a);
    const hex = Array.from(a)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    return `${prefix}_${hex}`;
  }
}

const DAY_MS = 24 * 60 * 60 * 1000;
const TRASH_RETENTION_DAYS = 30; // Phase 4 may adjust; Phase 1 uses a safe default.

function computePurgeAt(nowMs) {
  return nowMs + TRASH_RETENTION_DAYS * DAY_MS;
}

function folderRowToDto(r) {
  return {
    owner_id: String(r.owner_id),
    folder_id: String(r.folder_id),
    name: String(r.name),
    used_bytes: Number(r.used_bytes || 0),
    created_at: Number(r.created_at || 0),
    updated_at: Number(r.updated_at || 0),
    deleted_at: r.deleted_at == null ? null : Number(r.deleted_at),
  };
}

async function writeAudit(db, { owner_id, actor_id, action, entity_type, entity_id, at, ip, user_agent, before, after }) {
  const log_id = newId('log');
  const before_json = before == null ? null : JSON.stringify(before);
  const after_json = after == null ? null : JSON.stringify(after);
  await db
    .prepare(
      `INSERT INTO audit_log(
         owner_id, log_id, actor_id, action, entity_type, entity_id, at, ip, user_agent, before_json, after_json
       ) VALUES(?,?,?,?,?,?,?,?,?,?,?)`
    )
    .bind(
      String(owner_id),
      String(log_id),
      String(actor_id),
      String(action),
      String(entity_type),
      String(entity_id),
      Number(at),
      ip == null ? null : String(ip),
      user_agent == null ? null : String(user_agent),
      before_json,
      after_json
    )
    .run();
}

// -----------------------------
// Phase 2: Cards helpers + DB ops
// -----------------------------

function requireStringAllowEmpty(v, field, maxLen = 500) {
  if (v === undefined) return '';
  if (v === null) throw validation(`${field} must be a string`);
  if (typeof v !== 'string') throw validation(`${field} must be a string`);
  const s = v.trim();
  if (s.length > maxLen) throw validation(`${field} is too long`, { field, maxLen });
  return s;
}

function canonicalizeCardContentForWrite(raw) {
  // 12.7.1 Frozen v1.3.2 MUST
  // 1) missing content -> {text:"",location:""}
  // 2) content is string -> {text:<string>,location:""}
  // 3) content is object -> fill missing with ""; non-string values rejected
  if (raw === undefined) return { text: '', location: '' };
  if (raw === null) throw validation('content must be object|string');

  if (typeof raw === 'string') {
    return { text: raw, location: '' };
  }

  if (typeof raw === 'object' && !Array.isArray(raw)) {
    const hasText = Object.prototype.hasOwnProperty.call(raw, 'text');
    const hasLoc = Object.prototype.hasOwnProperty.call(raw, 'location');

    const text = hasText ? raw.text : '';
    const location = hasLoc ? raw.location : '';

    if (text !== undefined && text !== null && typeof text !== 'string') {
      throw validation('content.text must be a string');
    }
    if (location !== undefined && location !== null && typeof location !== 'string') {
      throw validation('content.location must be a string');
    }

    return { text: String(text ?? ''), location: String(location ?? '') };
  }

  throw validation('content must be object|string');
}

function parseCardContentForRead(raw) {
  // read-repair: if DB string is not valid JSON, return {text:<raw>, location:""}
  const s = String(raw ?? '');
  try {
    const obj = JSON.parse(s);
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) {
      const t = obj.text;
      const l = obj.location;
      return {
        text: typeof t === 'string' ? t : '',
        location: typeof l === 'string' ? l : '',
      };
    }
  } catch {
    // ignore
  }
  return { text: s, location: '' };
}

function makeSnippetFromText(text, maxLen = 80) {
  const s = String(text ?? '')
    .replace(/\s+/g, ' ')
    .trim();
  if (!s) return '';
  if (s.length <= maxLen) return s;
  return s.slice(0, Math.max(0, maxLen - 3)) + '...';
}

function cardRowToDto(r) {
  const content = parseCardContentForRead(r.content);
  return {
    owner_id: String(r.owner_id),
    card_id: String(r.card_id),
    folder_id: String(r.folder_id),
    title: String(r.title ?? ''),
    content,
    created_at: Number(r.created_at || 0),
    updated_at: Number(r.updated_at || 0),
    deleted_at: r.deleted_at == null ? null : Number(r.deleted_at),
    file_count: Number(r.file_count || 0),
  };
}

function cardListItemDto(r) {
  const content = parseCardContentForRead(r.content);
  return {
    card_id: String(r.card_id),
    title: String(r.title ?? ''),
    snippet: makeSnippetFromText(content.text, 80),
    location: String(content.location ?? ''),
    file_count: Number(r.file_count || 0),
    updated_at: Number(r.updated_at || 0),
    ...(r.deleted_at == null ? {} : { deleted_at: Number(r.deleted_at) }),
  };
}

async function assertFolderExists(db, owner_id, folder_id, { requireActive = false } = {}) {
  const row = await db
    .prepare('SELECT owner_id, folder_id, name, used_bytes, created_at, updated_at, deleted_at FROM folders WHERE owner_id=? AND folder_id=?')
    .bind(String(owner_id), String(folder_id))
    .first();
  if (!row) throw notFound(null, { owner_id, folder_id });
  if (requireActive && row.deleted_at != null) {
    throw conflict('folder is in trash', { owner_id, folder_id });
  }
  return row;
}

async function createOwnerCard({ db, owner_id, actor_id, folder_id, title, content, ip, user_agent }) {
  const now = Date.now();

  // folder existence / active check
  await assertFolderExists(db, owner_id, folder_id, { requireActive: true });

  const t = requireStringAllowEmpty(title, 'title', 500);
  const c = canonicalizeCardContentForWrite(content);

  // Validation (four-of-one; Phase 2 has no upload pipeline, so file_count=0)
  const hasAny = Boolean(t) || Boolean(c.text) || Boolean(c.location);
  if (!hasAny) throw validation('card is empty');

  const card_id = newId('c');
  const content_json = JSON.stringify({ text: c.text, location: c.location });

  await db
    .prepare(
      `INSERT INTO cards(
         owner_id, card_id, folder_id, title, content,
         created_at, updated_at, deleted_at, purge_at, deleted_by
       ) VALUES(?,?,?,?,?,?,?,?,?,?)`
    )
    .bind(
      String(owner_id),
      String(card_id),
      String(folder_id),
      String(t),
      String(content_json),
      Number(now),
      Number(now),
      null,
      null,
      null,
    )
    .run();

  // Read back (with file_count subquery for future-proofing)
  const row = await db
    .prepare(
      `SELECT c.owner_id, c.card_id, c.folder_id, c.title, c.content,
              c.created_at, c.updated_at, c.deleted_at,
              (SELECT COUNT(1) FROM assets a
                 WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL) AS file_count
       FROM cards c
       WHERE c.owner_id=? AND c.card_id=?`
    )
    .bind(String(owner_id), String(card_id))
    .first();

  const dto = cardRowToDto(row);

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'CREATE_CARD',
    entity_type: 'card',
    entity_id: card_id,
    at: now,
    ip,
    user_agent,
    before: null,
    after: dto,
  });

  return dto;
}

function _cardsWhereClause(state, include_deleted) {
  // state: 'active'|'trash'|'all'
  if (state === 'active') return 'c.deleted_at IS NULL';
  if (state === 'trash') return 'c.deleted_at IS NOT NULL';
  if (include_deleted) return '1=1';
  return 'c.deleted_at IS NULL';
}

async function listOwnerFolderCards({ db, owner_id, folder_id, state, include_deleted, sort, limit, cursor }) {
  // For Phase 2, allow listing cards even if folder is in trash.
  await assertFolderExists(db, owner_id, folder_id, { requireActive: false });

  const whereDeleted = _cardsWhereClause(state, include_deleted);

  // Cursor
  let cursorKey = null;
  if (cursor) {
    const c = decodeCursor(cursor);
    if (!c || c.sort !== sort || !c.last_key) throw validation('cursor mismatch');

    if (sort === 'updated_desc') {
      cursorKey = { updated_at: Number(c.last_key.updated_at), id: String(c.last_key.id) };
      if (!Number.isFinite(cursorKey.updated_at) || !cursorKey.id) throw validation('invalid cursor');
    } else if (sort === 'created_desc') {
      cursorKey = { created_at: Number(c.last_key.created_at), id: String(c.last_key.id) };
      if (!Number.isFinite(cursorKey.created_at) || !cursorKey.id) throw validation('invalid cursor');
    } else if (sort === 'title_asc') {
      cursorKey = { title: String(c.last_key.title ?? ''), id: String(c.last_key.id) };
      if (!cursorKey.id) throw validation('invalid cursor');
    } else {
      throw validation('invalid sort');
    }
  }

  const baseSelect = `
    SELECT
      c.owner_id, c.card_id, c.folder_id, c.title, c.content, c.created_at, c.updated_at, c.deleted_at,
      (SELECT COUNT(1) FROM assets a WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL) AS file_count
    FROM cards c
    WHERE c.owner_id = ? AND c.folder_id = ? AND ${whereDeleted}
  `;

  const binds = [String(owner_id), String(folder_id)];
  let orderBy = '';

  if (sort === 'updated_desc') {
    orderBy = 'ORDER BY c.updated_at DESC, c.card_id DESC';
    if (cursorKey) {
      binds.push(cursorKey.updated_at, cursorKey.updated_at, cursorKey.id);
      orderBy = `AND (c.updated_at < ? OR (c.updated_at = ? AND c.card_id < ?))\n` + orderBy;
    }
  } else if (sort === 'created_desc') {
    orderBy = 'ORDER BY c.created_at DESC, c.card_id DESC';
    if (cursorKey) {
      binds.push(cursorKey.created_at, cursorKey.created_at, cursorKey.id);
      orderBy = `AND (c.created_at < ? OR (c.created_at = ? AND c.card_id < ?))\n` + orderBy;
    }
  } else if (sort === 'title_asc') {
    // Note: DB collation freeze is external to this phase; we use SQLite default.
    orderBy = 'ORDER BY c.title ASC, c.card_id ASC';
    if (cursorKey) {
      binds.push(cursorKey.title, cursorKey.title, cursorKey.id);
      orderBy = `AND (c.title > ? OR (c.title = ? AND c.card_id > ?))\n` + orderBy;
    }
  } else {
    throw validation('invalid sort');
  }

  const sql = `${baseSelect}\n${orderBy}\nLIMIT ?`;
  binds.push(Number(limit));

  const rows = (await db.prepare(sql).bind(...binds).all()).results || [];

  const items = rows.map(cardListItemDto);
  let next_cursor = null;
  if (rows.length === Number(limit)) {
    const last = rows[rows.length - 1];
    if (sort === 'updated_desc') {
      next_cursor = encodeCursor({ sort, last_key: { updated_at: Number(last.updated_at), id: String(last.card_id) } });
    } else if (sort === 'created_desc') {
      next_cursor = encodeCursor({ sort, last_key: { created_at: Number(last.created_at), id: String(last.card_id) } });
    } else if (sort === 'title_asc') {
      next_cursor = encodeCursor({ sort, last_key: { title: String(last.title || ''), id: String(last.card_id) } });
    }
  }

  return {
    items,
    next_cursor,
    meta: {
      limit: Number(limit),
      sort: String(sort),
      scope: `folder:${folder_id}:${state || (include_deleted ? 'all' : 'active')}`,
    },
  };
}

async function getOwnerCardDetail({ db, owner_id, card_id }) {
  const row = (
    await db
      .prepare(
        `SELECT c.owner_id, c.card_id, c.folder_id, c.title, c.content, c.created_at, c.updated_at, c.deleted_at,
                (SELECT COUNT(1) FROM assets a WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL) AS file_count
         FROM cards c
         WHERE c.owner_id=? AND c.card_id=?`
      )
      .bind(String(owner_id), String(card_id))
      .first()
  );

  if (!row) throw notFound(null, { owner_id, card_id });
  return cardRowToDto(row);
}

async function updateOwnerCard({ db, owner_id, actor_id, card_id, patch, if_match, ip, user_agent }) {
  const now = Date.now();

  const before = (
    await db
      .prepare(
        `SELECT c.owner_id, c.card_id, c.folder_id, c.title, c.content, c.created_at, c.updated_at, c.deleted_at,
                (SELECT COUNT(1) FROM assets a WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL) AS file_count
         FROM cards c
         WHERE c.owner_id=? AND c.card_id=?`
      )
      .bind(String(owner_id), String(card_id))
      .first()
  );

  // Optimistic lock (Phase 1): enforce If-Match when provided
  if (before && if_match) {
    const current = etagFromUpdatedAt(before.updated_at);
    if (if_match !== current) throw new HttpError('VERSION_MISMATCH', 'resource version mismatch', 409);
  }

  if (!before) throw notFound(null, { owner_id, card_id });
  if (before.deleted_at != null) throw conflict('card is in trash', { owner_id, card_id });

  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) throw validation('json body must be an object');

  const hasTitle = Object.prototype.hasOwnProperty.call(patch, 'title');
  const hasContent = Object.prototype.hasOwnProperty.call(patch, 'content');
  if (!hasTitle && !hasContent) throw validation('at least one field is required', { fields: ['title', 'content'] });

  const title = hasTitle ? requireStringAllowEmpty(patch.title, 'title', 500) : String(before.title || '');

  let contentObj;
  if (hasContent) {
    contentObj = canonicalizeCardContentForWrite(patch.content);
  } else {
    contentObj = parseCardContentForRead(before.content);
  }

  const file_count = Number(before.file_count || 0);
  if (!title && !contentObj.text && !contentObj.location && file_count <= 0) {
    throw validation('card is empty', { rule: 'title|content.text|content.location|file_count', file_count });
  }

  const contentJson = JSON.stringify({ text: contentObj.text, location: contentObj.location });

  await db
    .prepare(`UPDATE cards SET title=?, content=?, updated_at=? WHERE owner_id=? AND card_id=? AND deleted_at IS NULL`)
    .bind(String(title), String(contentJson), Number(now), String(owner_id), String(card_id))
    .run();

  const afterRow = (
    await db
      .prepare(
        `SELECT c.owner_id, c.card_id, c.folder_id, c.title, c.content, c.created_at, c.updated_at, c.deleted_at,
                (SELECT COUNT(1) FROM assets a WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL) AS file_count
         FROM cards c
         WHERE c.owner_id=? AND c.card_id=?`
      )
      .bind(String(owner_id), String(card_id))
      .first()
  );

  const after = cardRowToDto(afterRow);

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'UPDATE_CARD',
    entity_type: 'card',
    entity_id: card_id,
    at: now,
    ip,
    user_agent,
    before: cardRowToDto(before),
    after,
  });

  return after;
}

async function moveCardToTrash({ db, owner_id, actor_id, card_id, ip, user_agent }) {
  const now = Date.now();

  const before = (
    await db
      .prepare(
        `SELECT c.owner_id, c.card_id, c.folder_id, c.title, c.content, c.created_at, c.updated_at, c.deleted_at,
                (SELECT COUNT(1) FROM assets a WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL) AS file_count
         FROM cards c
         WHERE c.owner_id=? AND c.card_id=?`
      )
      .bind(String(owner_id), String(card_id))
      .first()
  );

  if (!before) throw notFound(null, { owner_id, card_id });

  if (before.deleted_at == null) {
    await db
      .prepare(
        `UPDATE cards
         SET deleted_at=?, purge_at=?, deleted_by=?, updated_at=?
         WHERE owner_id=? AND card_id=? AND deleted_at IS NULL`
      )
      .bind(Number(now), Number(computePurgeAt(now)), String(actor_id), Number(now), String(owner_id), String(card_id))
      .run();

// Cascade: soft delete active assets under this card
await db
  .prepare(
    `UPDATE assets
     SET deleted_at=?, purge_at=?, deleted_by=?, updated_at=?
     WHERE owner_id=? AND card_id=? AND deleted_at IS NULL`
  )
  .bind(now, purge_at, String(actor_id), now, String(owner_id), String(card_id))
  .run();

await reconcileFolderUsedBytes({ db, owner_id, folder_id: String(before.folder_id) });

    const afterRow = (
      await db
        .prepare(
          `SELECT c.owner_id, c.card_id, c.folder_id, c.title, c.content, c.created_at, c.updated_at, c.deleted_at,
                  (SELECT COUNT(1) FROM assets a WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL) AS file_count
           FROM cards c
           WHERE c.owner_id=? AND c.card_id=?`
        )
        .bind(String(owner_id), String(card_id))
        .first()
    );

    const after = cardRowToDto(afterRow);

    await writeAudit(db, {
      owner_id,
      actor_id,
      action: 'DELETE_CARD',
      entity_type: 'card',
      entity_id: card_id,
      at: now,
      ip,
      user_agent,
      before: cardRowToDto(before),
      after,
    });

    return after;
  }

  // idempotent: already in trash
  return cardRowToDto(before);
}

// -----------------------------
// Phase 1: Owner folders API
// -----------------------------
async function listOwnerFolders({ db, owner_id, state, sort, limit, cursor }) {
  const whereDeleted = state === 'trash' ? 'deleted_at IS NOT NULL' : 'deleted_at IS NULL';

  let cursorKey = null;
  if (cursor) {
    const c = decodeCursor(cursor);
    if (!c || c.sort !== sort || !c.last_key) {
      throw validation('cursor mismatch');
    }
    cursorKey = {
      updated_at: Number(c.last_key.updated_at),
      folder_id: String(c.last_key.id),
    };
    if (!Number.isFinite(cursorKey.updated_at) || !cursorKey.folder_id) throw validation('invalid cursor');
  }

  // Sorting: updated_at DESC, folder_id DESC
  const parts = [
    `SELECT owner_id, folder_id, name, used_bytes, created_at, updated_at, deleted_at`,
    `FROM folders`,
    `WHERE owner_id = ? AND ${whereDeleted}`,
  ];

  const binds = [String(owner_id)];

  if (cursorKey) {
    parts.push(`AND (updated_at < ? OR (updated_at = ? AND folder_id < ?))`);
    binds.push(cursorKey.updated_at, cursorKey.updated_at, cursorKey.folder_id);
  }

  parts.push(`ORDER BY updated_at DESC, folder_id DESC`);
  parts.push(`LIMIT ?`);
  binds.push(limit);

  const sql = parts.join('\n');
  const res = await db.prepare(sql).bind(...binds).all();
  const rows = Array.isArray(res.results) ? res.results : [];
  const items = rows.map(folderRowToDto);

  let next_cursor = null;
  if (items.length === limit) {
    const last = items[items.length - 1];
    next_cursor = encodeCursor({
      sort,
      last_key: { updated_at: last.updated_at, id: last.folder_id },
    });
  }

  return {
    items,
    next_cursor,
    meta: {
      state,
      sort,
      limit,
    },
  };
}

async function createOwnerFolder({ db, owner_id, actor_id, name, ip, user_agent }) {
  const now = Date.now();
  const folder_id = newId('f');

  const row = {
    owner_id: String(owner_id),
    folder_id,
    name: String(name),
    used_bytes: 0,
    created_at: now,
    updated_at: now,
    deleted_at: null,
  };

  await db
    .prepare(
      `INSERT INTO folders(owner_id, folder_id, name, used_bytes, created_at, updated_at, deleted_at, purge_at, deleted_by)
       VALUES(?,?,?,?,?,?,?,?,?)`
    )
    .bind(row.owner_id, row.folder_id, row.name, 0, now, now, null, null, null)
    .run();

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'CREATE_FOLDER',
    entity_type: 'folder',
    entity_id: folder_id,
    at: now,
    ip,
    user_agent,
    before: null,
    after: { folder_id, name: row.name, deleted_at: null },
  });

  return row;
}

async function renameOwnerFolder({ db, owner_id, actor_id, folder_id, name, if_match, ip, user_agent }) {
  const now = Date.now();

  const before = await db
    .prepare(
      `SELECT owner_id, folder_id, name, used_bytes, created_at, updated_at, deleted_at
       FROM folders WHERE owner_id = ? AND folder_id = ? LIMIT 1`
    )
    .bind(String(owner_id), String(folder_id))
    .first();

  // Optimistic lock (Phase 1): enforce If-Match when provided
  if (before && if_match) {
    const current = etagFromUpdatedAt(before.updated_at);
    if (if_match !== current) throw new HttpError('VERSION_MISMATCH', 'resource version mismatch', 409);
  }

  if (!before) throw notFound(null, { entity: 'folder', folder_id });
  if (before.deleted_at != null) throw conflict('folder is in trash');

  await db
    .prepare(`UPDATE folders SET name = ?, updated_at = ? WHERE owner_id = ? AND folder_id = ?`)
    .bind(String(name), now, String(owner_id), String(folder_id))
    .run();

  const after = {
    folder_id: String(folder_id),
    name: String(name),
    deleted_at: null,
  };

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'UPDATE_FOLDER',
    entity_type: 'folder',
    entity_id: folder_id,
    at: now,
    ip,
    user_agent,
    before: { folder_id: String(folder_id), name: String(before.name), deleted_at: before.deleted_at },
    after,
  });

  // Return current row
  const row = await db
    .prepare(
      `SELECT owner_id, folder_id, name, used_bytes, created_at, updated_at, deleted_at
       FROM folders WHERE owner_id = ? AND folder_id = ? LIMIT 1`
    )
    .bind(String(owner_id), String(folder_id))
    .first();

  return folderRowToDto(row);
}

async function moveFolderToTrash({ db, owner_id, actor_id, folder_id, ip, user_agent }) {
  const now = Date.now();
  const purge_at = computePurgeAt(now);

  const before = await db
    .prepare(
      `SELECT owner_id, folder_id, name, used_bytes, created_at, updated_at, deleted_at
       FROM folders WHERE owner_id = ? AND folder_id = ? LIMIT 1`
    )
    .bind(String(owner_id), String(folder_id))
    .first();

  if (!before) throw notFound(null, { entity: 'folder', folder_id });

  // Idempotent: if already in trash, return as-is.
  if (before.deleted_at == null) {
    await db
      .prepare(
        `UPDATE folders
         SET deleted_at = ?, purge_at = ?, deleted_by = ?, updated_at = ?
         WHERE owner_id = ? AND folder_id = ? AND deleted_at IS NULL`
      )
      .bind(now, purge_at, String(actor_id), now, String(owner_id), String(folder_id))
      .run();

    // Sync mounts (spec: avoid ghost folders)
    await db
      .prepare(
        `UPDATE mounts
         SET deleted_at = ?, purge_at = ?, deleted_by = ?, updated_at = ?
         WHERE owner_id = ? AND folder_id = ? AND deleted_at IS NULL`
      )
      .bind(now, purge_at, String(actor_id), now, String(owner_id), String(folder_id))
      .run();

// Cascade: soft delete active cards and assets under this folder
await db
  .prepare(
    `UPDATE cards
     SET deleted_at=?, purge_at=?, deleted_by=?, updated_at=?
     WHERE owner_id=? AND folder_id=? AND deleted_at IS NULL`
  )
  .bind(now, purge_at, String(actor_id), now, String(owner_id), String(folder_id))
  .run();

await db
  .prepare(
    `UPDATE assets
     SET deleted_at=?, purge_at=?, deleted_by=?, updated_at=?
     WHERE owner_id=? AND deleted_at IS NULL
       AND card_id IN (SELECT card_id FROM cards WHERE owner_id=? AND folder_id=?)`
  )
  .bind(now, purge_at, String(actor_id), now, String(owner_id), String(owner_id), String(folder_id))
  .run();

await reconcileFolderUsedBytes({ db, owner_id, folder_id: String(folder_id) });

    await writeAudit(db, {
      owner_id,
      actor_id,
      action: 'DELETE_FOLDER',
      entity_type: 'folder',
      entity_id: folder_id,
      at: now,
      ip,
      user_agent,
      before: { folder_id: String(folder_id), name: String(before.name), deleted_at: null },
      after: { folder_id: String(folder_id), name: String(before.name), deleted_at: now, purge_at },
    });
  }

  const row = await db
    .prepare(
      `SELECT owner_id, folder_id, name, used_bytes, created_at, updated_at, deleted_at
       FROM folders WHERE owner_id = ? AND folder_id = ? LIMIT 1`
    )
    .bind(String(owner_id), String(folder_id))
    .first();

  return folderRowToDto(row);
}

// -----------------------------
// Phase 4: Trash / Restore / Purge helpers
// -----------------------------

function normalizeTrashType(type) {
  const t = String(type || '').toLowerCase();
  if (t === 'folder' || t === 'folders') return 'folder';
  if (t === 'card' || t === 'cards') return 'card';
  if (t === 'asset' || t === 'assets' || t === 'file' || t === 'files') return 'asset';
  if (t === 'all') return 'all';
  throw validation('invalid type', { type });
}

async function listOwnerTrash({ db, owner_id, type, limit, cursors }) {
  const t = normalizeTrashType(type || 'all');
  const c = cursors || {};

  if (t === 'folder') {
    return { folders: await listTrashFolders({ db, owner_id, limit, cursor: c.folders_cursor || null }) };
  }
  if (t === 'card') {
    return { cards: await listTrashCards({ db, owner_id, limit, cursor: c.cards_cursor || null }) };
  }
  if (t === 'asset') {
    return { assets: await listTrashAssets({ db, owner_id, limit, cursor: c.assets_cursor || null }) };
  }

  return {
    folders: await listTrashFolders({ db, owner_id, limit, cursor: c.folders_cursor || null }),
    cards: await listTrashCards({ db, owner_id, limit, cursor: c.cards_cursor || null }),
    assets: await listTrashAssets({ db, owner_id, limit, cursor: c.assets_cursor || null }),
  };
}

async function listTrashFolders({ db, owner_id, limit, cursor }) {
  let last_deleted_at = null;
  let last_id = null;

  if (cursor) {
    const c = decodeCursor(cursor);
    if (!c || c.sort !== 'deleted_desc' || !c.last_key) throw validation('cursor mismatch');
    last_deleted_at = Number(c.last_key.deleted_at);
    last_id = String(c.last_key.id);
    if (!Number.isFinite(last_deleted_at) || !last_id) throw validation('invalid cursor');
  }

  const binds = [String(owner_id)];
  let where = 'owner_id=? AND deleted_at IS NOT NULL';

  if (last_deleted_at != null) {
    where += ' AND (deleted_at < ? OR (deleted_at = ? AND folder_id < ?))';
    binds.push(last_deleted_at, last_deleted_at, String(last_id));
  }

  const rows = await db
    .prepare(
      `SELECT owner_id, folder_id, name, used_bytes, created_at, updated_at, deleted_at
       FROM folders
       WHERE ${where}
       ORDER BY deleted_at DESC, folder_id DESC
       LIMIT ?`
    )
    .bind(...binds, Number(limit))
    .all();

  const items = (rows.results || []).map(folderRowToDto);
  let next_cursor = null;
  if (items.length === Number(limit) && items.length > 0) {
    const last = items[items.length - 1];
    next_cursor = encodeCursor({ sort: 'deleted_desc', last_key: { deleted_at: last.deleted_at, id: last.folder_id } });
  }

  return { items, next_cursor };
}

async function listTrashCards({ db, owner_id, limit, cursor }) {
  let last_deleted_at = null;
  let last_id = null;

  if (cursor) {
    const c = decodeCursor(cursor);
    if (!c || c.sort !== 'deleted_desc' || !c.last_key) throw validation('cursor mismatch');
    last_deleted_at = Number(c.last_key.deleted_at);
    last_id = String(c.last_key.id);
    if (!Number.isFinite(last_deleted_at) || !last_id) throw validation('invalid cursor');
  }

  const binds = [String(owner_id)];
  let where = 'c.owner_id=? AND c.deleted_at IS NOT NULL';

  if (last_deleted_at != null) {
    where += ' AND (c.deleted_at < ? OR (c.deleted_at = ? AND c.card_id < ?))';
    binds.push(last_deleted_at, last_deleted_at, String(last_id));
  }

  const rows = await db
    .prepare(
      `SELECT c.owner_id, c.card_id, c.folder_id, c.title, c.content, c.created_at, c.updated_at, c.deleted_at,
              (SELECT COUNT(1) FROM assets a WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL) AS file_count
       FROM cards c
       WHERE ${where}
       ORDER BY c.deleted_at DESC, c.card_id DESC
       LIMIT ?`
    )
    .bind(...binds, Number(limit))
    .all();

  const items = (rows.results || []).map(cardRowToDto);
  let next_cursor = null;
  if (items.length === Number(limit) && items.length > 0) {
    const last = items[items.length - 1];
    next_cursor = encodeCursor({ sort: 'deleted_desc', last_key: { deleted_at: last.deleted_at, id: last.card_id } });
  }

  return { items, next_cursor };
}

async function listTrashAssets({ db, owner_id, limit, cursor }) {
  let last_deleted_at = null;
  let last_id = null;

  if (cursor) {
    const c = decodeCursor(cursor);
    if (!c || c.sort !== 'deleted_desc' || !c.last_key) throw validation('cursor mismatch');
    last_deleted_at = Number(c.last_key.deleted_at);
    last_id = String(c.last_key.id);
    if (!Number.isFinite(last_deleted_at) || !last_id) throw validation('invalid cursor');
  }

  const binds = [String(owner_id)];
  let where = 'owner_id=? AND deleted_at IS NOT NULL';

  if (last_deleted_at != null) {
    where += ' AND (deleted_at < ? OR (deleted_at = ? AND asset_id < ?))';
    binds.push(last_deleted_at, last_deleted_at, String(last_id));
  }

  const rows = await db
    .prepare(
      `SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at
       FROM assets
       WHERE ${where}
       ORDER BY deleted_at DESC, asset_id DESC
       LIMIT ?`
    )
    .bind(...binds, Number(limit))
    .all();

  const items = (rows.results || []).map(assetRowToDto);
  let next_cursor = null;
  if (items.length === Number(limit) && items.length > 0) {
    const last = items[items.length - 1];
    next_cursor = encodeCursor({ sort: 'deleted_desc', last_key: { deleted_at: last.deleted_at, id: last.asset_id } });
  }

  return { items, next_cursor };
}

async function restoreOwnerTrash({ db, owner_id, actor_id, type, id, ip, user_agent }) {
  const t = normalizeTrashType(type);
  const entity_id = String(id);

  if (t === 'folder') {
    return { type: t, entity: await restoreFolderFromTrash({ db, owner_id, actor_id, folder_id: entity_id, ip, user_agent }) };
  }
  if (t === 'card') {
    return { type: t, entity: await restoreCardFromTrash({ db, owner_id, actor_id, card_id: entity_id, ip, user_agent }) };
  }
  if (t === 'asset') {
    return { type: t, entity: await restoreAssetFromTrash({ db, owner_id, actor_id, asset_id: entity_id, ip, user_agent }) };
  }

  throw validation('invalid type', { type });
}

async function restoreFolderFromTrash({ db, owner_id, actor_id, folder_id, ip, user_agent }) {
  const now = Date.now();

  const before = await db
    .prepare(
      `SELECT owner_id, folder_id, name, used_bytes, created_at, updated_at, deleted_at
       FROM folders WHERE owner_id=? AND folder_id=? LIMIT 1`
    )
    .bind(String(owner_id), String(folder_id))
    .first();

  if (!before) throw notFound(null, { entity: 'folder', folder_id });
  if (before.deleted_at == null) return folderRowToDto(before);

  await db
    .prepare(
      `UPDATE folders
       SET deleted_at=NULL, purge_at=NULL, deleted_by=NULL, updated_at=?
       WHERE owner_id=? AND folder_id=? AND deleted_at IS NOT NULL`
    )
    .bind(now, String(owner_id), String(folder_id))
    .run();

  // Sync mounts: if folder is restored, restore mounts too.
  await db
    .prepare(
      `UPDATE mounts
       SET deleted_at=NULL, purge_at=NULL, deleted_by=NULL, updated_at=?
       WHERE owner_id=? AND folder_id=? AND deleted_at IS NOT NULL`
    )
    .bind(now, String(owner_id), String(folder_id))
    .run();

// Cascade: restore cards and assets under this folder
await db
  .prepare(
    `UPDATE cards
     SET deleted_at=NULL, purge_at=NULL, deleted_by=NULL, updated_at=?
     WHERE owner_id=? AND folder_id=? AND deleted_at IS NOT NULL`
  )
  .bind(now, String(owner_id), String(folder_id))
  .run();

await db
  .prepare(
    `UPDATE assets
     SET deleted_at=NULL, purge_at=NULL, deleted_by=NULL, updated_at=?
     WHERE owner_id=? AND deleted_at IS NOT NULL
       AND card_id IN (SELECT card_id FROM cards WHERE owner_id=? AND folder_id=?)`
  )
  .bind(now, String(owner_id), String(owner_id), String(folder_id))
  .run();

await reconcileFolderUsedBytes({ db, owner_id, folder_id: String(folder_id) });

  const after = await db
    .prepare(
      `SELECT owner_id, folder_id, name, used_bytes, created_at, updated_at, deleted_at
       FROM folders WHERE owner_id=? AND folder_id=? LIMIT 1`
    )
    .bind(String(owner_id), String(folder_id))
    .first();

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'RESTORE_FOLDER',
    entity_type: 'folder',
    entity_id: String(folder_id),
    at: now,
    ip,
    user_agent,
    before: folderRowToDto(before),
    after: folderRowToDto(after),
  });

  return folderRowToDto(after);
}

async function restoreCardFromTrash({ db, owner_id, actor_id, card_id, ip, user_agent }) {
  const now = Date.now();

  const before = (
    await db
      .prepare(
        `SELECT c.owner_id, c.card_id, c.folder_id, c.title, c.content, c.created_at, c.updated_at, c.deleted_at,
                (SELECT COUNT(1) FROM assets a WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL) AS file_count
         FROM cards c
         WHERE c.owner_id=? AND c.card_id=?`
      )
      .bind(String(owner_id), String(card_id))
      .first()
  );

  if (!before) throw notFound(null, { entity: 'card', card_id });
  if (before.deleted_at == null) return cardRowToDto(before);

  const folder = await db
    .prepare('SELECT folder_id, deleted_at FROM folders WHERE owner_id=? AND folder_id=? LIMIT 1')
    .bind(String(owner_id), String(before.folder_id))
    .first();
  if (!folder) throw conflict('parent folder missing');
  if (folder.deleted_at != null) throw conflict('parent folder is in trash');

  await db
    .prepare(
      `UPDATE cards
       SET deleted_at=NULL, purge_at=NULL, deleted_by=NULL, updated_at=?
       WHERE owner_id=? AND card_id=? AND deleted_at IS NOT NULL`
    )
    .bind(now, String(owner_id), String(card_id))
    .run();

// Cascade: restore all assets under this card
await db
  .prepare(
    `UPDATE assets
     SET deleted_at=NULL, purge_at=NULL, deleted_by=NULL, updated_at=?
     WHERE owner_id=? AND card_id=? AND deleted_at IS NOT NULL`
  )
  .bind(now, String(owner_id), String(card_id))
  .run();

await reconcileFolderUsedBytes({ db, owner_id, folder_id: String(before.folder_id) });

  const after = (
    await db
      .prepare(
        `SELECT c.owner_id, c.card_id, c.folder_id, c.title, c.content, c.created_at, c.updated_at, c.deleted_at,
                (SELECT COUNT(1) FROM assets a WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL) AS file_count
         FROM cards c
         WHERE c.owner_id=? AND c.card_id=?`
      )
      .bind(String(owner_id), String(card_id))
      .first()
  );

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'RESTORE_CARD',
    entity_type: 'card',
    entity_id: String(card_id),
    at: now,
    ip,
    user_agent,
    before: cardRowToDto(before),
    after: cardRowToDto(after),
  });

  return cardRowToDto(after);
}

async function restoreAssetFromTrash({ db, owner_id, actor_id, asset_id, ip, user_agent }) {
  const now = Date.now();

  const before = await db
    .prepare(
      `SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at
       FROM assets WHERE owner_id=? AND asset_id=? LIMIT 1`
    )
    .bind(String(owner_id), String(asset_id))
    .first();

  if (!before) throw notFound(null, { entity: 'asset', asset_id });
  if (before.deleted_at == null) return assetRowToDto(before);

  const card = await db
    .prepare('SELECT card_id, folder_id, deleted_at FROM cards WHERE owner_id=? AND card_id=? LIMIT 1')
    .bind(String(owner_id), String(before.card_id))
    .first();
  if (!card) throw conflict('parent card missing');
  if (card.deleted_at != null) throw conflict('parent card is in trash');

  await db
    .prepare(
      `UPDATE assets
       SET deleted_at=NULL, purge_at=NULL, deleted_by=NULL, updated_at=?
       WHERE owner_id=? AND asset_id=? AND deleted_at IS NOT NULL`
    )
    .bind(now, String(owner_id), String(asset_id))
    .run();

  await db
    .prepare('UPDATE cards SET updated_at=? WHERE owner_id=? AND card_id=?')
    .bind(now, String(owner_id), String(before.card_id))
    .run();

const cardRow2 = await db
  .prepare('SELECT folder_id FROM cards WHERE owner_id=? AND card_id=? LIMIT 1')
  .bind(String(owner_id), String(before.card_id))
  .first();
if (cardRow2 && cardRow2.folder_id) {
  await reconcileFolderUsedBytes({ db, owner_id, folder_id: String(cardRow2.folder_id) });
}

const cardRow = await db
  .prepare('SELECT folder_id FROM cards WHERE owner_id=? AND card_id=? LIMIT 1')
  .bind(String(owner_id), String(before.card_id))
  .first();
if (cardRow && cardRow.folder_id) {
  await reconcileFolderUsedBytes({ db, owner_id, folder_id: String(cardRow.folder_id) });
}

  const after = await db
    .prepare(
      `SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at
       FROM assets WHERE owner_id=? AND asset_id=? LIMIT 1`
    )
    .bind(String(owner_id), String(asset_id))
    .first();

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'RESTORE_ASSET',
    entity_type: 'asset',
    entity_id: String(asset_id),
    at: now,
    ip,
    user_agent,
    before: assetRowToDto(before),
    after: assetRowToDto(after),
  });

  return assetRowToDto(after);
}

async function purgeOwnerTrash({ db, owner_id, actor_id, type, id, ip, user_agent }) {
  const t = normalizeTrashType(type);
  const entity_id = String(id);

  if (t === 'asset') {
    return { type: t, purged: await purgeAssetPermanently({ db, owner_id, actor_id, asset_id: entity_id, ip, user_agent }) };
  }
  if (t === 'card') {
    return { type: t, purged: await purgeCardPermanently({ db, owner_id, actor_id, card_id: entity_id, ip, user_agent }) };
  }
  if (t === 'folder') {
    return { type: t, purged: await purgeFolderPermanently({ db, owner_id, actor_id, folder_id: entity_id, ip, user_agent }) };
  }

  throw validation('invalid type', { type });
}

async function purgeAssetPermanently({ db, owner_id, actor_id, asset_id, ip, user_agent }) {
  const now = Date.now();

  const before = await db
    .prepare(
      `SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at
       FROM assets WHERE owner_id=? AND asset_id=? LIMIT 1`
    )
    .bind(String(owner_id), String(asset_id))
    .first();

  if (!before) throw notFound(null, { entity: 'asset', asset_id });
  if (before.deleted_at == null) throw conflict('asset is active; move to trash first');

  await db
    .prepare('DELETE FROM assets WHERE owner_id=? AND asset_id=?')
    .bind(String(owner_id), String(asset_id))
    .run();

  // Keep card freshness for UI.
  await db
    .prepare('UPDATE cards SET updated_at=? WHERE owner_id=? AND card_id=?')
    .bind(now, String(owner_id), String(before.card_id))
    .run();

const cardRow = await db
  .prepare('SELECT folder_id FROM cards WHERE owner_id=? AND card_id=? LIMIT 1')
  .bind(String(owner_id), String(before.card_id))
  .first();
if (cardRow && cardRow.folder_id) {
  await reconcileFolderUsedBytes({ db, owner_id, folder_id: String(cardRow.folder_id) });
}

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'PURGE_ASSET',
    entity_type: 'asset',
    entity_id: String(asset_id),
    at: now,
    ip,
    user_agent,
    before: assetRowToDto(before),
    after: null,
  });

  // TODO: R2 object deletion by before.r2_key
  return { asset_id: String(asset_id), r2_key: String(before.r2_key) };
}

async function purgeCardPermanently({ db, owner_id, actor_id, card_id, ip, user_agent }) {
  const now = Date.now();

  const before = (
    await db
      .prepare(
        `SELECT c.owner_id, c.card_id, c.folder_id, c.title, c.content, c.created_at, c.updated_at, c.deleted_at,
                (SELECT COUNT(1) FROM assets a WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL) AS file_count
         FROM cards c
         WHERE c.owner_id=? AND c.card_id=? LIMIT 1`
      )
      .bind(String(owner_id), String(card_id))
      .first()
  );

  if (!before) throw notFound(null, { entity: 'card', card_id });
  if (before.deleted_at == null) throw conflict('card is active; move to trash first');

  // Purge assets metadata first (avoid FK).
  const assetRows = await db
    .prepare('SELECT asset_id, r2_key FROM assets WHERE owner_id=? AND card_id=?')
    .bind(String(owner_id), String(card_id))
    .all();

  const purged_assets = (assetRows.results || []).map((r) => ({ asset_id: String(r.asset_id), r2_key: String(r.r2_key) }));

  await db
    .prepare('DELETE FROM assets WHERE owner_id=? AND card_id=?')
    .bind(String(owner_id), String(card_id))
    .run();

  await db
    .prepare('DELETE FROM cards WHERE owner_id=? AND card_id=?')
    .bind(String(owner_id), String(card_id))
    .run();

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'PURGE_CARD',
    entity_type: 'card',
    entity_id: String(card_id),
    at: now,
    ip,
    user_agent,
    before: cardRowToDto(before),
    after: null,
  });

await reconcileFolderUsedBytes({ db, owner_id, folder_id: String(before.folder_id) });

  // TODO: R2 object deletion by purged_assets[*].r2_key
  return { card_id: String(card_id), purged_assets };
}

async function purgeFolderPermanently({ db, owner_id, actor_id, folder_id, ip, user_agent }) {
  const now = Date.now();

  const before = await db
    .prepare(
      `SELECT owner_id, folder_id, name, used_bytes, created_at, updated_at, deleted_at
       FROM folders WHERE owner_id=? AND folder_id=? LIMIT 1`
    )
    .bind(String(owner_id), String(folder_id))
    .first();

  if (!before) throw notFound(null, { entity: 'folder', folder_id });
  if (before.deleted_at == null) throw conflict('folder is active; move to trash first');

  // Collect cards under folder.
  const cardRows = await db
    .prepare('SELECT card_id FROM cards WHERE owner_id=? AND folder_id=?')
    .bind(String(owner_id), String(folder_id))
    .all();

  const card_ids = (cardRows.results || []).map((r) => String(r.card_id));

  // Purge assets -> cards -> mounts -> folder.
  const purged_assets = []
  for (const cid of card_ids) {
    const assetRows = await db
      .prepare('SELECT asset_id, r2_key FROM assets WHERE owner_id=? AND card_id=?')
      .bind(String(owner_id), String(cid))
      .all();

    for (const r of (assetRows.results || [])) {
      purged_assets.push({ asset_id: String(r.asset_id), r2_key: String(r.r2_key), card_id: String(cid) })
    }

    await db
      .prepare('DELETE FROM assets WHERE owner_id=? AND card_id=?')
      .bind(String(owner_id), String(cid))
      .run();
  }

  await db
    .prepare('DELETE FROM cards WHERE owner_id=? AND folder_id=?')
    .bind(String(owner_id), String(folder_id))
    .run();

  await db
    .prepare('DELETE FROM mounts WHERE owner_id=? AND folder_id=?')
    .bind(String(owner_id), String(folder_id))
    .run();

  await db
    .prepare('DELETE FROM folders WHERE owner_id=? AND folder_id=?')
    .bind(String(owner_id), String(folder_id))
    .run();

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'PURGE_FOLDER',
    entity_type: 'folder',
    entity_id: String(folder_id),
    at: now,
    ip,
    user_agent,
    before: { folder_id: String(folder_id), name: String(before.name), deleted_at: Number(before.deleted_at) },
    after: null,
  });

  // TODO: R2 object deletion by purged_assets[*].r2_key
  return { folder_id: String(folder_id), purged_cards: card_ids, purged_assets };
}

// -----------------------------
// Phase 3: Assets Metadata helpers (no upload session)
// -----------------------------

function requireNonNegativeInt(v, field) {
  if (v === undefined || v === null || v === '') return 0;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) throw validation(`${field} must be a non-negative integer`, { field });
  return Math.floor(n);
}

function assetRowToDto(r) {
  return {
    owner_id: String(r.owner_id),
    asset_id: String(r.asset_id),
    card_id: String(r.card_id),
    r2_key: String(r.r2_key),
    filename: String(r.filename ?? ''),
    mime: String(r.mime ?? ''),
    size_bytes: Number(r.size_bytes ?? 0),
    created_at: Number(r.created_at ?? 0),
    updated_at: Number(r.updated_at ?? 0),
    deleted_at: r.deleted_at == null ? null : Number(r.deleted_at),
  };
}

// -----------------------------
// Phase 6: Collections + Members (ACL; no mounts)
// -----------------------------

function parsePolicyJsonForRead(raw) {
  const s = String(raw ?? '{}');
  try {
    const obj = JSON.parse(s);
    if (obj && typeof obj === 'object' && !Array.isArray(obj)) return obj;
  } catch {
    // ignore
  }
  return {};
}

function canonicalizePolicyJsonForWrite(raw) {
  let obj;

  if (raw === undefined || raw === null) {
    obj = {};
  } else if (typeof raw === 'string') {
    try {
      obj = JSON.parse(raw);
    } catch {
      throw validation('policy_json must be valid JSON');
    }
  } else if (typeof raw === 'object' && !Array.isArray(raw)) {
    obj = raw;
  } else {
    throw validation('policy_json must be object|string');
  }

  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    throw validation('policy_json must be an object');
  }

  if (!Object.prototype.hasOwnProperty.call(obj, 'allow_download')) {
    obj.allow_download = true;
  } else if (typeof obj.allow_download !== 'boolean') {
    throw validation('policy_json.allow_download must be boolean');
  }

  return JSON.stringify(obj);
}

function collectionRowToDto(r) {
  return {
    owner_id: String(r.owner_id),
    collection_id: String(r.collection_id),
    name: String(r.name),
    policy_json: parsePolicyJsonForRead(r.policy_json),
    created_at: Number(r.created_at ?? 0),
    updated_at: Number(r.updated_at ?? 0),
    deleted_at: r.deleted_at == null ? null : Number(r.deleted_at),
  };
}

function memberRowToDto(r) {
  return {
    owner_id: String(r.owner_id),
    collection_id: String(r.collection_id),
    member_id: String(r.member_id),
    role: String(r.role),
    added_at: Number(r.added_at ?? 0),
    updated_at: Number(r.updated_at ?? 0),
  };
}

function requireMemberRole(v, field = 'role') {
  const role = requireNonEmptyString(v, field, 20).toLowerCase();
  if (!['owner', 'admin', 'editor', 'viewer'].includes(role)) throw validation('invalid role', { field, role });
  return role;
}

async function assertCollectionOwnerRole({ db, owner_id, collection_id, actor_id }) {
  const row = await db
    .prepare(
      `SELECT role
       FROM collection_members
       WHERE owner_id=? AND collection_id=? AND member_id=?
       LIMIT 1`
    )
    .bind(String(owner_id), String(collection_id), String(actor_id))
    .first();

  if (!row || String(row.role) !== 'owner') throw forbidden('owner only');
}

async function getCollectionRow({ db, owner_id, collection_id }) {
  const row = await db
    .prepare('SELECT owner_id, collection_id, name, policy_json, created_at, updated_at, deleted_at FROM collections WHERE owner_id=? AND collection_id=? LIMIT 1')
    .bind(String(owner_id), String(collection_id))
    .first();
  return row || null;
}

async function listOwnerCollections({ db, owner_id, state, sort, limit, cursor }) {
  const whereDeleted = state === 'trash' ? 'deleted_at IS NOT NULL' : 'deleted_at IS NULL';

  let cursorKey = null;
  if (cursor) {
    const c = decodeCursor(cursor);
    if (!c || c.sort !== sort || !c.last_key) throw validation('cursor mismatch');

    cursorKey = {
      updated_at: Number(c.last_key.updated_at),
      collection_id: String(c.last_key.id),
    };

    if (!Number.isFinite(cursorKey.updated_at) || !cursorKey.collection_id) throw validation('invalid cursor');
  }

  const parts = [
    `SELECT owner_id, collection_id, name, policy_json, created_at, updated_at, deleted_at`,
    `FROM collections`,
    `WHERE owner_id=? AND ${whereDeleted}`,
  ];

  const binds = [String(owner_id)];

  if (cursorKey) {
    parts.push(`AND (updated_at < ? OR (updated_at = ? AND collection_id < ?))`);
    binds.push(Number(cursorKey.updated_at), Number(cursorKey.updated_at), String(cursorKey.collection_id));
  }

  parts.push(`ORDER BY updated_at DESC, collection_id DESC`);
  parts.push(`LIMIT ?`);
  binds.push(Number(limit));

  const rows = await db.prepare(parts.join('\n')).bind(...binds).all();
  const items = (rows.results || []).map(collectionRowToDto);

  let next_cursor = null;
  if (items.length === limit) {
    const last = items[items.length - 1];
    next_cursor = encodeCursor({ sort, last_key: { updated_at: last.updated_at, id: last.collection_id } });
  }

  return { items, next_cursor };
}

async function createOwnerCollection({ db, owner_id, actor_id, name, policy_json, request_id, ip, user_agent }) {
  const now = Date.now();
  const collection_id = newId('col');
  const policyStr = canonicalizePolicyJsonForWrite(policy_json);

  await db
    .prepare(
      `INSERT INTO collections(owner_id, collection_id, name, policy_json, created_at, updated_at, deleted_at, purge_at, deleted_by)
       VALUES(?,?,?,?,?,?,?,?,?)`
    )
    .bind(String(owner_id), String(collection_id), String(name), String(policyStr), now, now, null, null, null)
    .run();

  // Bootstrap owner membership
  await db
    .prepare(
      `INSERT INTO collection_members(owner_id, collection_id, member_id, role, added_at, updated_at)
       VALUES(?,?,?,?,?,?)`
    )
    .bind(String(owner_id), String(collection_id), String(owner_id), 'owner', now, now)
    .run();

  const row = await getCollectionRow({ db, owner_id, collection_id });
  const dto = collectionRowToDto(row);

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'CREATE_COLLECTION',
    entity_type: 'collection',
    entity_id: String(collection_id),
    at: now,
    ip,
    user_agent,
    before: null,
    after: dto,
  });

  return dto;
}

async function updateOwnerCollection({ db, owner_id, collection_id, actor_id, patch, request_id, ip, user_agent }) {
  const now = Date.now();
  const beforeRow = await getCollectionRow({ db, owner_id, collection_id });
  if (!beforeRow) throw notFound(request_id, { entity: 'collection', collection_id });
  if (beforeRow.deleted_at != null) throw conflict('collection is in trash');

  const updates = [];
  const binds = [];

  if (patch.name !== undefined) {
    const nm = requireNonEmptyString(patch.name, 'name', 200);
    updates.push('name=?');
    binds.push(nm);
  }

  if (patch.policy_json !== undefined) {
    const pol = canonicalizePolicyJsonForWrite(patch.policy_json);
    updates.push('policy_json=?');
    binds.push(String(pol));
  }

  if (updates.length === 0) throw validation('no updatable fields');

  updates.push('updated_at=?');
  binds.push(now);

  binds.push(String(owner_id), String(collection_id));

  await db
    .prepare(`UPDATE collections SET ${updates.join(', ')} WHERE owner_id=? AND collection_id=? AND deleted_at IS NULL`)
    .bind(...binds)
    .run();

  const afterRow = await getCollectionRow({ db, owner_id, collection_id });
  const beforeDto = collectionRowToDto(beforeRow);
  const afterDto = collectionRowToDto(afterRow);

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'UPDATE_COLLECTION',
    entity_type: 'collection',
    entity_id: String(collection_id),
    at: now,
    ip,
    user_agent,
    before: beforeDto,
    after: afterDto,
  });

  return afterDto;
}

async function moveCollectionToTrash({ db, owner_id, collection_id, actor_id, request_id, ip, user_agent }) {
  const now = Date.now();
  const beforeRow = await getCollectionRow({ db, owner_id, collection_id });
  if (!beforeRow) throw notFound(request_id, { entity: 'collection', collection_id });
  if (beforeRow.deleted_at != null) {
    // idempotent
    return collectionRowToDto(beforeRow);
  }

  const purge_at = computePurgeAt(now);

  await db
    .prepare(
      `UPDATE collections
       SET deleted_at=?, purge_at=?, deleted_by=?, updated_at=?
       WHERE owner_id=? AND collection_id=? AND deleted_at IS NULL`
    )
    .bind(now, purge_at, String(actor_id), now, String(owner_id), String(collection_id))
    .run();

  const afterRow = await getCollectionRow({ db, owner_id, collection_id });
  const beforeDto = collectionRowToDto(beforeRow);
  const afterDto = collectionRowToDto(afterRow);

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'DELETE_COLLECTION',
    entity_type: 'collection',
    entity_id: String(collection_id),
    at: now,
    ip,
    user_agent,
    before: beforeDto,
    after: afterDto,
  });

  return afterDto;
}

async function listCollectionMembers({ db, owner_id, collection_id }) {
  const rows = await db
    .prepare(
      `SELECT owner_id, collection_id, member_id, role, added_at, updated_at
       FROM collection_members
       WHERE owner_id=? AND collection_id=?
       ORDER BY role ASC, member_id ASC`
    )
    .bind(String(owner_id), String(collection_id))
    .all();

  return (rows.results || []).map(memberRowToDto);
}

async function addCollectionMember({ db, owner_id, collection_id, actor_id, member_id, role, request_id, ip, user_agent }) {
  const now = Date.now();

  const col = await getCollectionRow({ db, owner_id, collection_id });
  if (!col) throw notFound(request_id, { entity: 'collection', collection_id });
  if (col.deleted_at != null) throw conflict('collection is in trash');

  await assertCollectionOwnerRole({ db, owner_id, collection_id, actor_id });

  const mid = requireNonEmptyString(member_id, 'member_id', 128);
  const r = requireMemberRole(role, 'role');
  if (r === 'owner') throw validation('role "owner" is reserved');

  if (String(mid) == String(owner_id)) throw validation('owner is implicit member');

  const existing = await db
    .prepare(
      `SELECT owner_id, collection_id, member_id, role, added_at, updated_at
       FROM collection_members
       WHERE owner_id=? AND collection_id=? AND member_id=?
       LIMIT 1`
    )
    .bind(String(owner_id), String(collection_id), String(mid))
    .first();

  if (existing) throw conflict('member already exists');

  await db
    .prepare(
      `INSERT INTO collection_members(owner_id, collection_id, member_id, role, added_at, updated_at)
       VALUES(?,?,?,?,?,?)`
    )
    .bind(String(owner_id), String(collection_id), String(mid), String(r), now, now)
    .run();

  const after = await db
    .prepare(
      `SELECT owner_id, collection_id, member_id, role, added_at, updated_at
       FROM collection_members
       WHERE owner_id=? AND collection_id=? AND member_id=?
       LIMIT 1`
    )
    .bind(String(owner_id), String(collection_id), String(mid))
    .first();

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'ADD_MEMBER',
    entity_type: 'member',
    entity_id: String(mid),
    at: now,
    ip,
    user_agent,
    before: null,
    after: memberRowToDto(after),
  });

  return memberRowToDto(after);
}

async function updateCollectionMemberRole({ db, owner_id, collection_id, actor_id, member_id, role, request_id, ip, user_agent }) {
  const now = Date.now();

  const col = await getCollectionRow({ db, owner_id, collection_id });
  if (!col) throw notFound(request_id, { entity: 'collection', collection_id });
  if (col.deleted_at != null) throw conflict('collection is in trash');

  await assertCollectionOwnerRole({ db, owner_id, collection_id, actor_id });

  const mid = requireNonEmptyString(member_id, 'member_id', 128);
  const r = requireMemberRole(role, 'role');
  if (r === 'owner') throw validation('role "owner" is reserved');

  const before = await db
    .prepare(
      `SELECT owner_id, collection_id, member_id, role, added_at, updated_at
       FROM collection_members
       WHERE owner_id=? AND collection_id=? AND member_id=?
       LIMIT 1`
    )
    .bind(String(owner_id), String(collection_id), String(mid))
    .first();

  if (!before) throw notFound(request_id, { entity: 'member', member_id: mid });

  await db
    .prepare(
      `UPDATE collection_members
       SET role=?, updated_at=?
       WHERE owner_id=? AND collection_id=? AND member_id=?`
    )
    .bind(String(r), now, String(owner_id), String(collection_id), String(mid))
    .run();

  const after = await db
    .prepare(
      `SELECT owner_id, collection_id, member_id, role, added_at, updated_at
       FROM collection_members
       WHERE owner_id=? AND collection_id=? AND member_id=?
       LIMIT 1`
    )
    .bind(String(owner_id), String(collection_id), String(mid))
    .first();

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'UPDATE_MEMBER',
    entity_type: 'member',
    entity_id: String(mid),
    at: now,
    ip,
    user_agent,
    before: memberRowToDto(before),
    after: memberRowToDto(after),
  });

  return memberRowToDto(after);
}

async function revokeCollectionMember({ db, owner_id, collection_id, actor_id, member_id, request_id, ip, user_agent }) {
  const now = Date.now();

  const col = await getCollectionRow({ db, owner_id, collection_id });
  if (!col) throw notFound(request_id, { entity: 'collection', collection_id });
  if (col.deleted_at != null) throw conflict('collection is in trash');

  await assertCollectionOwnerRole({ db, owner_id, collection_id, actor_id });

  const mid = requireNonEmptyString(member_id, 'member_id', 128);
  if (String(mid) == String(owner_id)) throw validation('cannot revoke owner');

  const before = await db
    .prepare(
      `SELECT owner_id, collection_id, member_id, role, added_at, updated_at
       FROM collection_members
       WHERE owner_id=? AND collection_id=? AND member_id=?
       LIMIT 1`
    )
    .bind(String(owner_id), String(collection_id), String(mid))
    .first();

  if (!before) {
    // idempotent
    return { revoked: false };
  }

  await db
    .prepare('DELETE FROM collection_members WHERE owner_id=? AND collection_id=? AND member_id=?')
    .bind(String(owner_id), String(collection_id), String(mid))
    .run();

  await writeAudit(db, {
    owner_id,
    actor_id,
    action: 'REMOVE_MEMBER',
    entity_type: 'member',
    entity_id: String(mid),
    at: now,
    ip,
    user_agent,
    before: memberRowToDto(before),
    after: null,
  });

  return { revoked: true };
}

// -----------------------------
// Phase 8: Search (Owner + Collection views; mount-aware)
// -----------------------------

async function resolveCollectionByPublicId({ db, collection_id }) {
  // collection_id is treated as globally unique. If not unique, fail closed.
  const out = await db
    .prepare(
      'SELECT owner_id, collection_id, name, policy_json, created_at, updated_at, deleted_at FROM collections WHERE collection_id=? LIMIT 2'
    )
    .bind(String(collection_id))
    .all();

  const rows = (out && out.results) || [];
  if (rows.length === 0) return null;
  if (rows.length > 1) throw conflict('ambiguous collection_id');
  return rows[0];
}

async function getCollectionMemberRole({ db, owner_id, collection_id, member_id }) {
  const row = await db
    .prepare('SELECT role FROM collection_members WHERE owner_id=? AND collection_id=? AND member_id=? LIMIT 1')
    .bind(String(owner_id), String(collection_id), String(member_id))
    .first();
  return row ? String(row.role) : null;
}

function assertReadableRoleOrNotFound(role, request_id, details) {
  if (!role) throw notFound(request_id, details);
  const r = String(role);
  if (!['owner', 'editor', 'viewer'].includes(r)) throw notFound(request_id, details);
  return r;
}

function searchRowToItem(r, q) {
  const content = parseCardContentForRead(r.content);
  const title = String(r.title || '');
  const location = String(content.location || '');
  const text = String(content.text || '');

  return {
    card_owner_id: String(r.card_owner_id),
    card_id: String(r.card_id),
    folder_owner_id: String(r.folder_owner_id),
    folder_id: String(r.folder_id),
    collection_id: r.collection_id == null ? null : String(r.collection_id),
    title,
    snippet: chooseSearchSnippet(q, title, text, location, r.match_filename),
    location,
    file_count: Number(r.file_count || 0),
    updated_at: Number(r.updated_at || 0),
  };
}

async function searchOwnerCards({ db, owner_id, q, limit, cursor }) {
  const qq = String(q || '').trim();
  const pattern = qq ? `%${escapeLikeTerm(qq)}%` : null;

  let last_updated_at = null;
  let last_card_id = null;
  if (cursor) {
    const c = decodeSearchCursor(cursor);
    last_updated_at = Number(c.updated_at);
    last_card_id = String(c.card_id);
    if (!Number.isFinite(last_updated_at) || !last_card_id) throw validation('invalid cursor');
  }

  const where = ['c.owner_id=?', 'c.deleted_at IS NULL'];
  const binds = [String(owner_id)];

  if (last_updated_at != null) {
    where.push('(c.updated_at < ? OR (c.updated_at = ? AND c.card_id < ?))');
    binds.push(last_updated_at, last_updated_at, last_card_id);
  }

  if (qq) {
    where.push(
      `(
        c.title LIKE ? ESCAPE '\\'
        OR (CASE WHEN json_valid(c.content) THEN json_extract(c.content,'$.text') ELSE c.content END) LIKE ? ESCAPE '\\'
        OR (CASE WHEN json_valid(c.content) THEN json_extract(c.content,'$.location') ELSE '' END) LIKE ? ESCAPE '\\'
        OR EXISTS (
          SELECT 1 FROM assets a
          WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL
            AND a.filename LIKE ? ESCAPE '\\'
        )
      )`
    );
    binds.push(pattern, pattern, pattern, pattern);
  }

  const matchFilenameExpr = qq
    ? `(SELECT a3.filename FROM assets a3
        WHERE a3.owner_id=c.owner_id AND a3.card_id=c.card_id AND a3.deleted_at IS NULL
          AND a3.filename LIKE ? ESCAPE '\\'
        ORDER BY a3.created_at ASC, a3.asset_id ASC
        LIMIT 1)`
    : 'NULL';

  const sql = `
    SELECT
      c.owner_id AS card_owner_id,
      c.card_id AS card_id,
      c.owner_id AS folder_owner_id,
      c.folder_id AS folder_id,
      NULL AS collection_id,
      c.title AS title,
      c.content AS content,
      c.updated_at AS updated_at,
      (SELECT COUNT(1) FROM assets a2 WHERE a2.owner_id=c.owner_id AND a2.card_id=c.card_id AND a2.deleted_at IS NULL) AS file_count,
      ${matchFilenameExpr} AS match_filename
    FROM cards c
    WHERE ${where.join(' AND ')}
    ORDER BY c.updated_at DESC, c.card_id DESC
    LIMIT ?
  `;

  const finalBinds = binds.slice();
  if (qq) finalBinds.push(pattern); // for matchFilenameExpr
  finalBinds.push(Number(limit));

  const out = await db.prepare(sql).bind(...finalBinds).all();
  const rows = (out && out.results) || [];

  const items = rows.map((r) => searchRowToItem(r, qq));

  let next_cursor = null;
  if (rows.length === Number(limit) && rows.length > 0) {
    const last = rows[rows.length - 1];
    next_cursor = encodeSearchCursor({ updated_at: Number(last.updated_at), card_id: String(last.card_id) });
  }

  return {
    items,
    next_cursor,
    meta: { limit: Number(limit), sort: 'updated_desc', scope: 'owner' },
  };
}

async function searchCollectionCards({ db, owner_id, collection_id, viewer_id, q, limit, cursor, request_id }) {
  const qq = String(q || '').trim();
  const pattern = qq ? `%${escapeLikeTerm(qq)}%` : null;

  const col = await getCollectionRow({ db, owner_id, collection_id });
  if (!col || col.deleted_at != null) throw notFound(request_id, { entity: 'collection', collection_id });

  const role = await getCollectionMemberRole({ db, owner_id, collection_id, member_id: viewer_id });
  assertReadableRoleOrNotFound(role, request_id, { entity: 'collection', collection_id });

  let last_updated_at = null;
  let last_card_id = null;
  if (cursor) {
    const c = decodeSearchCursor(cursor);
    last_updated_at = Number(c.updated_at);
    last_card_id = String(c.card_id);
    if (!Number.isFinite(last_updated_at) || !last_card_id) throw validation('invalid cursor');
  }

  const where = [
    'c.owner_id=?',
    'c.deleted_at IS NULL',
    `EXISTS (
      SELECT 1
      FROM mounts m
      JOIN folders f ON f.owner_id=m.owner_id AND f.folder_id=m.folder_id
      WHERE m.owner_id=c.owner_id
        AND m.collection_id=?
        AND m.folder_id=c.folder_id
        AND m.deleted_at IS NULL
        AND f.deleted_at IS NULL
    )`,
  ];

  const binds = [String(owner_id), String(collection_id)];

  if (last_updated_at != null) {
    where.push('(c.updated_at < ? OR (c.updated_at = ? AND c.card_id < ?))');
    binds.push(last_updated_at, last_updated_at, last_card_id);
  }

  if (qq) {
    where.push(
      `(
        c.title LIKE ? ESCAPE '\\'
        OR (CASE WHEN json_valid(c.content) THEN json_extract(c.content,'$.text') ELSE c.content END) LIKE ? ESCAPE '\\'
        OR (CASE WHEN json_valid(c.content) THEN json_extract(c.content,'$.location') ELSE '' END) LIKE ? ESCAPE '\\'
        OR EXISTS (
          SELECT 1 FROM assets a
          WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL
            AND a.filename LIKE ? ESCAPE '\\'
        )
      )`
    );
    binds.push(pattern, pattern, pattern, pattern);
  }

  const matchFilenameExpr = qq
    ? `(SELECT a3.filename FROM assets a3
        WHERE a3.owner_id=c.owner_id AND a3.card_id=c.card_id AND a3.deleted_at IS NULL
          AND a3.filename LIKE ? ESCAPE '\\'
        ORDER BY a3.created_at ASC, a3.asset_id ASC
        LIMIT 1)`
    : 'NULL';

  const sql = `
    SELECT
      c.owner_id AS card_owner_id,
      c.card_id AS card_id,
      c.owner_id AS folder_owner_id,
      c.folder_id AS folder_id,
      ? AS collection_id,
      c.title AS title,
      c.content AS content,
      c.updated_at AS updated_at,
      (SELECT COUNT(1) FROM assets a2 WHERE a2.owner_id=c.owner_id AND a2.card_id=c.card_id AND a2.deleted_at IS NULL) AS file_count,
      ${matchFilenameExpr} AS match_filename
    FROM cards c
    WHERE ${where.join(' AND ')}
    ORDER BY c.updated_at DESC, c.card_id DESC
    LIMIT ?
  `;

  const finalBinds = [String(collection_id), ...binds];
  if (qq) finalBinds.push(pattern);
  finalBinds.push(Number(limit));

  const out = await db.prepare(sql).bind(...finalBinds).all();
  const rows = (out && out.results) || [];

  const items = rows.map((r) => searchRowToItem(r, qq));

  let next_cursor = null;
  if (rows.length === Number(limit) && rows.length > 0) {
    const last = rows[rows.length - 1];
    next_cursor = encodeSearchCursor({ updated_at: Number(last.updated_at), card_id: String(last.card_id) });
  }

  return {
    items,
    next_cursor,
    meta: { limit: Number(limit), sort: 'updated_desc', scope: 'collection' },
  };
}

async function searchAllReadableCards({ db, viewer_id, q, limit, cursor }) {
  const qq = String(q || '').trim();
  const pattern = qq ? `%${escapeLikeTerm(qq)}%` : null;

  let last_updated_at = null;
  let last_card_id = null;
  if (cursor) {
    const c = decodeSearchCursor(cursor);
    last_updated_at = Number(c.updated_at);
    last_card_id = String(c.card_id);
    if (!Number.isFinite(last_updated_at) || !last_card_id) throw validation('invalid cursor');
  }

  const readableExists = `EXISTS (
    SELECT 1
    FROM mounts m
    JOIN collections col ON col.owner_id=m.owner_id AND col.collection_id=m.collection_id
    JOIN collection_members cm ON cm.owner_id=m.owner_id AND cm.collection_id=m.collection_id
    JOIN folders f ON f.owner_id=m.owner_id AND f.folder_id=m.folder_id
    WHERE m.owner_id=c.owner_id
      AND m.folder_id=c.folder_id
      AND m.deleted_at IS NULL
      AND col.deleted_at IS NULL
      AND cm.member_id=?
      AND cm.role IN ('owner','editor','viewer')
      AND f.deleted_at IS NULL
  )`;

  const where = [
    'c.deleted_at IS NULL',
    `(c.owner_id=? OR ${readableExists})`,
  ];

  const binds = [String(viewer_id), String(viewer_id)];

  if (last_updated_at != null) {
    where.push('(c.updated_at < ? OR (c.updated_at = ? AND c.card_id < ?))');
    binds.push(last_updated_at, last_updated_at, last_card_id);
  }

  if (qq) {
    where.push(
      `(
        c.title LIKE ? ESCAPE '\\'
        OR (CASE WHEN json_valid(c.content) THEN json_extract(c.content,'$.text') ELSE c.content END) LIKE ? ESCAPE '\\'
        OR (CASE WHEN json_valid(c.content) THEN json_extract(c.content,'$.location') ELSE '' END) LIKE ? ESCAPE '\\'
        OR EXISTS (
          SELECT 1 FROM assets a
          WHERE a.owner_id=c.owner_id AND a.card_id=c.card_id AND a.deleted_at IS NULL
            AND a.filename LIKE ? ESCAPE '\\'
        )
      )`
    );
    binds.push(pattern, pattern, pattern, pattern);
  }

  const representativeCollectionExpr = `CASE
    WHEN c.owner_id=? THEN NULL
    ELSE (
      SELECT m2.collection_id
      FROM mounts m2
      JOIN collections col2 ON col2.owner_id=m2.owner_id AND col2.collection_id=m2.collection_id
      JOIN collection_members cm2 ON cm2.owner_id=m2.owner_id AND cm2.collection_id=m2.collection_id
      JOIN folders f2 ON f2.owner_id=m2.owner_id AND f2.folder_id=m2.folder_id
      WHERE m2.owner_id=c.owner_id
        AND m2.folder_id=c.folder_id
        AND m2.deleted_at IS NULL
        AND col2.deleted_at IS NULL
        AND cm2.member_id=?
        AND cm2.role IN ('owner','editor','viewer')
        AND f2.deleted_at IS NULL
      ORDER BY m2.updated_at DESC, m2.collection_id DESC
      LIMIT 1
    )
  END`;

  const matchFilenameExpr = qq
    ? `(SELECT a3.filename FROM assets a3
        WHERE a3.owner_id=c.owner_id AND a3.card_id=c.card_id AND a3.deleted_at IS NULL
          AND a3.filename LIKE ? ESCAPE '\\'
        ORDER BY a3.created_at ASC, a3.asset_id ASC
        LIMIT 1)`
    : 'NULL';

  const sql = `
    SELECT
      c.owner_id AS card_owner_id,
      c.card_id AS card_id,
      c.owner_id AS folder_owner_id,
      c.folder_id AS folder_id,
      ${representativeCollectionExpr} AS collection_id,
      c.title AS title,
      c.content AS content,
      c.updated_at AS updated_at,
      (SELECT COUNT(1) FROM assets a2 WHERE a2.owner_id=c.owner_id AND a2.card_id=c.card_id AND a2.deleted_at IS NULL) AS file_count,
      ${matchFilenameExpr} AS match_filename
    FROM cards c
    WHERE ${where.join(' AND ')}
    ORDER BY c.updated_at DESC, c.card_id DESC
    LIMIT ?
  `;

  const finalBinds = binds.slice();
  // representativeCollectionExpr binds:
  finalBinds.push(String(viewer_id), String(viewer_id));
  if (qq) finalBinds.push(pattern);
  finalBinds.push(Number(limit));

  const out = await db.prepare(sql).bind(...finalBinds).all();
  const rows = (out && out.results) || [];

  const items = rows.map((r) => searchRowToItem(r, qq));

  let next_cursor = null;
  if (rows.length === Number(limit) && rows.length > 0) {
    const last = rows[rows.length - 1];
    next_cursor = encodeSearchCursor({ updated_at: Number(last.updated_at), card_id: String(last.card_id) });
  }

  return {
    items,
    next_cursor,
    meta: { limit: Number(limit), sort: 'updated_desc', scope: 'all' },
  };
}

async function apiSearchV1({ db, viewer_id, q, scope, owner_id, collection_id, limit, cursor, request_id }) {
  const sc = String(scope || 'all').toLowerCase();
  if (!['all', 'collection', 'folder'].includes(sc)) throw validation('invalid scope', { scope });

  const lim = clampLimit(limit, 30, 50);

  if (sc === 'all') {
    return await searchAllReadableCards({ db, viewer_id, q, limit: lim, cursor });
  }

  if (sc === 'collection') {
    const oid = requireNonEmptyString(owner_id, 'owner_id', 128);
    const cid = requireNonEmptyString(collection_id, 'collection_id', 128);
    return await searchCollectionCards({ db, owner_id: oid, collection_id: cid, viewer_id, q, limit: lim, cursor, request_id });
  }

  // sc === 'folder'
  throw new HttpError('NOT_IMPLEMENTED', 'scope=folder not implemented yet', 501);
}

// -----------------------------
// Routing: /api/v1 + /api/owner aliases (Phase 1)
// -----------------------------
async function handleApiV1(request, env, request_id) {
  const url = new URL(request.url);
  const { pathname } = url;

  // Healthcheck
  if (request.method === 'GET' && pathname === '/api/v1/health') {
    return apiHealth(request, env, request_id);
  }

  // Auth: LIFF id_token -> session_token exchange (no Bearer required)
  if (pathname === '/api/v1/auth/liff/exchange' && request.method === 'POST') {
    return await apiAuthLiffExchange(request, env, request_id);
  }

  if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);

  // All other /api/v1 endpoints require session_token (Bearer)
  const ctx = await parseViewerContext(request, env);
    requireOwnerWrite(ctx);

  // Upload Session FSM (Spec: /api/v1/assets/upload/*)
  if (pathname.startsWith('/api/v1/assets/upload/')) {
    return await apiAssetsUpload(request, env, request_id, ctx);
  }

  // Assets content proxy (Range-enabled)
  // GET /api/v1/assets/:owner_id/:asset_id/content
  const mAssetContent = pathname.match(/^\/api\/v1\/assets\/([^\/]+)\/([^\/]+)\/content$/);
  if (mAssetContent && request.method === 'GET') {
    const owner_id = decodeURIComponent(mAssetContent[1]);
    const asset_id = decodeURIComponent(mAssetContent[2]);
    return await apiAssetContentProxy({ request, env, request_id, ctx, owner_id, asset_id });
  }

  // Trash (canonical)
  // GET  /api/v1/trash?type=all|folder|card|asset&limit=30&folders_cursor=...&cards_cursor=...&assets_cursor=...
  // POST /api/v1/trash/restore { targets:[{type,id},...] }  (also accepts {type,id})
  // POST /api/v1/trash/purge   { targets:[{type,id},...] }  (also accepts {type,id})
  if (pathname === '/api/v1/trash' && request.method === 'GET') {
    const type = url.searchParams.get('type') || 'all';
    const limit = clampLimit(url.searchParams.get('limit'), 30, 100);
    const cursors = {
      folders_cursor: url.searchParams.get('folders_cursor') || null,
      cards_cursor: url.searchParams.get('cards_cursor') || null,
      assets_cursor: url.searchParams.get('assets_cursor') || null,
    };
    const data = await withTx(env.DB, async (db) => {
      return await listOwnerTrash({ db, owner_id: ctx.owner_id, type, limit, cursors });
    });
    return okJson(data);
  }

  if (pathname === '/api/v1/trash/restore' && request.method === 'POST') {
    const body = await readJson(request);
    const targets = Array.isArray(body?.targets) ? body.targets : [{ type: body?.type, id: body?.id }];
    if (!targets || targets.length === 0) throw validation('targets required');
    const ip = getClientIp(request);
    const user_agent = getUserAgent(request);

    const data = await withTx(env.DB, async (db) => {
      const out = [];
      for (const t of targets) {
        const type = requireNonEmptyString(t?.type, 'type', 20);
        const id = requireNonEmptyString(t?.id, 'id', 128);
        out.push(await restoreOwnerTrash({ db, owner_id: ctx.owner_id, actor_id: ctx.viewer_id, type, id, ip, user_agent }));
      }
      return { restored: out };
    });
    return okJson(data);
  }

  if (pathname === '/api/v1/trash/purge' && request.method === 'POST') {
    const body = await readJson(request);
    const targets = Array.isArray(body?.targets) ? body.targets : [{ type: body?.type, id: body?.id }];
    if (!targets || targets.length === 0) throw validation('targets required');
    const ip = getClientIp(request);
    const user_agent = getUserAgent(request);

    const data = await withTx(env.DB, async (db) => {
      const out = [];
      for (const t of targets) {
        const type = requireNonEmptyString(t?.type, 'type', 20);
        const id = requireNonEmptyString(t?.id, 'id', 128);
        out.push(await purgeOwnerTrash({ db, owner_id: ctx.owner_id, actor_id: ctx.viewer_id, type, id, ip, user_agent }));
      }
      return { purged: out };
    });
    return okJson(data);
  }

  // Convenience wrappers (frozen in spec)
  // POST /api/v1/trash/cards/:owner_id/:card_id/restore
  const mTrashCardRestore = pathname.match(/^\/api\/v1\/trash\/cards\/([^\/]+)\/([^\/]+)\/restore$/);
  if (mTrashCardRestore && request.method === 'POST') {
    const owner_id = decodeURIComponent(mTrashCardRestore[1]);
    const card_id = decodeURIComponent(mTrashCardRestore[2]);
    if (owner_id !== ctx.owner_id) throw forbidden('owner mismatch');
    const ip = getClientIp(request);
    const user_agent = getUserAgent(request);
    const data = await withTx(env.DB, async (db) => {
      return await restoreOwnerTrash({ db, owner_id, actor_id: ctx.viewer_id, type: 'card', id: card_id, ip, user_agent });
    });
    return okJson(data);
  }

  // POST /api/v1/trash/cards/:owner_id/:card_id/purge
  const mTrashCardPurge = pathname.match(/^\/api\/v1\/trash\/cards\/([^\/]+)\/([^\/]+)\/purge$/);
  if (mTrashCardPurge && request.method === 'POST') {
    const owner_id = decodeURIComponent(mTrashCardPurge[1]);
    const card_id = decodeURIComponent(mTrashCardPurge[2]);
    if (owner_id !== ctx.owner_id) throw forbidden('owner mismatch');
    const ip = getClientIp(request);
    const user_agent = getUserAgent(request);
    const data = await withTx(env.DB, async (db) => {
      return await purgeOwnerTrash({ db, owner_id, actor_id: ctx.viewer_id, type: 'card', id: card_id, ip, user_agent });
    });
    return okJson(data);
  }


// ==========================================================
// Phase 2 — Collections & Sharing (canonical /api/v1)
// ==========================================================

// GET  /api/v1/collections
// POST /api/v1/collections { title }
if (pathname === '/api/v1/collections') {
  if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
  if (request.method === 'GET') {
    const limit = clampInt(url.searchParams.get('limit') ?? '50', 1, 200);
    const rows = await env.DB.prepare(
      `SELECT owner_id, collection_id, name, policy_json, created_at, updated_at
       FROM collections
       WHERE owner_id = ?1 AND deleted_at IS NULL
       ORDER BY updated_at DESC, collection_id DESC
       LIMIT ?2`
    ).bind(ctx.viewer_id, limit).all();
    return okJson({ items: rows.results || [], next_cursor: null, meta: { limit, scope: 'owner' } });
  }

  if (request.method === 'POST') {
    const body = await request.json().catch(() => null);
    const name = String(body?.name || body?.title || '').trim();
    if (!name) throw badRequest('name is required');

    const data = await withIdempotency({
      env,
      ctx,
      request,
      bodyRaw: JSON.stringify(body ?? {}),
      handler: async () => {
        const now = nowUnix();
        const owner_id = ctx.viewer_id;
        const collection_id = makeUlid(Date.now());

        await withTx(env.DB, async (db) => {
          await db.prepare(
            `INSERT INTO collections (owner_id, collection_id, name, policy_json, created_at, updated_at, deleted_at, deleted_by, purge_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL, NULL, NULL)`
          ).bind(owner_id, collection_id, name, '{"allow_download":true}', now).run();

          // Owner is implicit admin; still store explicit owner row to simplify ACL queries.
          await db.prepare(
            `INSERT INTO collection_members (owner_id, collection_id, member_id, role, created_at, updated_at, deleted_at)
             VALUES (?1, ?2, ?3, 'admin', ?4, ?4, NULL)`
          ).bind(owner_id, collection_id, owner_id, now).run();
        });

        return { owner_id, collection_id, name, policy_json: { allow_download: true }, created_at: now, updated_at: now };
      },
    });

    return okJson(data, 201);
  }

  throw methodNotAllowed();
}

// Collection resource: GET/PATCH/DELETE /api/v1/collections/:owner_id/:collection_id
const mCollection = pathname.match(/^\/api\/v1\/collections\/([^\/]+)\/([^\/]+)$/);
if (mCollection) {
  if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
  const owner_id = decodeURIComponent(mCollection[1]);
  const collection_id = decodeURIComponent(mCollection[2]);

  const perms = await resolveCollectionPerms({ db: env.DB, owner_id, collection_id, viewer_id: ctx.viewer_id });

  if (request.method === 'GET') {
    requireCollectionRead(perms);
    const row = await env.DB.prepare(
      `SELECT owner_id, collection_id, name, policy_json, created_at, updated_at
       FROM collections
       WHERE owner_id = ?1 AND collection_id = ?2 AND deleted_at IS NULL
       LIMIT 1`
    ).bind(owner_id, collection_id).first();
    if (!row) throw notFound('collection not found');
    return okJson({ ...row, role: perms.role });
  }

  if (request.method === 'PATCH') {
    requireCollectionWrite(perms);
    const body = await request.json().catch(() => null);
    const name = String(body?.name || body?.title || '').trim();
    if (!name) throw badRequest('name is required');

    const data = await withIdempotency({
      env,
      ctx,
      request,
      bodyRaw: JSON.stringify(body ?? {}),
      handler: async () => {
        const now = nowUnix();
        await withTx(env.DB, async (db) => {
          const res = await db.prepare(
            `UPDATE collections
             SET name = ?3, updated_at = ?4
             WHERE owner_id = ?1 AND collection_id = ?2 AND deleted_at IS NULL`
          ).bind(owner_id, collection_id, name, '{"allow_download":true}', now).run();
          if ((res.meta?.changes ?? 0) === 0) throw notFound('collection not found');
        });
        return { owner_id, collection_id, name, updated_at: now };
      },
    });

    return okJson(data);
  }

  if (request.method === 'DELETE') {
    // Only owner/admin can delete (member management privilege)
    requireCollectionManageMembers(perms);

    const data = await withIdempotency({
      env,
      ctx,
      request,
      bodyRaw: '',
      handler: async () => {
        const now = nowUnix();
        await withTx(env.DB, async (db) => {
          const res = await db.prepare(
            `UPDATE collections SET deleted_at = ?3, updated_at = ?3
             WHERE owner_id = ?1 AND collection_id = ?2 AND deleted_at IS NULL`
          ).bind(owner_id, collection_id, now).run();
          if ((res.meta?.changes ?? 0) === 0) throw notFound('collection not found');
        });
        return { ok: true, deleted_at: now };
      },
    });

    return okJson(data);
  }

  throw methodNotAllowed();
}

// Members: /api/v1/collections/:owner_id/:collection_id/members
const mMembers = pathname.match(/^\/api\/v1\/collections\/([^\/]+)\/([^\/]+)\/members$/);
if (mMembers) {
  if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
  const owner_id = decodeURIComponent(mMembers[1]);
  const collection_id = decodeURIComponent(mMembers[2]);

  const perms = await resolveCollectionPerms({ db: env.DB, owner_id, collection_id, viewer_id: ctx.viewer_id });

  if (request.method === 'GET') {
    requireCollectionRead(perms);
    const rows = await env.DB.prepare(
      `SELECT member_id, role, created_at, updated_at
       FROM collection_members
       WHERE owner_id = ?1 AND collection_id = ?2 AND deleted_at IS NULL
       ORDER BY role DESC, member_id ASC`
    ).bind(owner_id, collection_id).all();
    return okJson({ items: rows.results || [], role: perms.role });
  }

  if (request.method === 'POST') {
    requireCollectionManageMembers(perms);
    const body = await request.json().catch(() => null);
    const member_id = String(body?.member_id || '').trim();
    const role = normalizeRole(body?.role);
    if (!member_id) throw badRequest('member_id is required');
    if (!role) throw badRequest('role must be viewer|editor|admin');

    const data = await withIdempotency({
      env, ctx, request,
      bodyRaw: JSON.stringify(body ?? {}),
      handler: async () => {
        const now = nowUnix();
        await withTx(env.DB, async (db) => {
          // Upsert semantics: if exists and deleted, revive; if exists active, update role.
          await db.prepare(
            `INSERT INTO collection_members (owner_id, collection_id, member_id, role, created_at, updated_at, deleted_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)
             ON CONFLICT(owner_id, collection_id, member_id)
             DO UPDATE SET role = excluded.role, updated_at = excluded.updated_at, deleted_at = NULL`
          ).bind(owner_id, collection_id, member_id, role, now).run();
        });
        return { ok: true, member_id, role, updated_at: now };
      },
    });

    return okJson(data, 201);
  }

  throw methodNotAllowed();
}

// Member: PATCH/DELETE /api/v1/collections/:owner_id/:collection_id/members/:member_id
const mMember = pathname.match(/^\/api\/v1\/collections\/([^\/]+)\/([^\/]+)\/members\/([^\/]+)$/);
if (mMember) {
  if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
  const owner_id = decodeURIComponent(mMember[1]);
  const collection_id = decodeURIComponent(mMember[2]);
  const member_id = decodeURIComponent(mMember[3]);

  const perms = await resolveCollectionPerms({ db: env.DB, owner_id, collection_id, viewer_id: ctx.viewer_id });

  if (request.method === 'PATCH') {
    requireCollectionManageMembers(perms);
    const body = await request.json().catch(() => null);
    const role = normalizeRole(body?.role);
    if (!role) throw badRequest('role must be viewer|editor|admin');

    const data = await withIdempotency({
      env, ctx, request,
      bodyRaw: JSON.stringify(body ?? {}),
      handler: async () => {
        const now = nowUnix();
        await withTx(env.DB, async (db) => {
          const res = await db.prepare(
            `UPDATE collection_members
             SET role = ?4, updated_at = ?5
             WHERE owner_id = ?1 AND collection_id = ?2 AND member_id = ?3 AND deleted_at IS NULL`
          ).bind(owner_id, collection_id, member_id, role, now).run();
          if ((res.meta?.changes ?? 0) === 0) throw notFound('member not found');
        });
        return { ok: true, member_id, role, updated_at: now };
      },
    });

    return okJson(data);
  }

  if (request.method === 'DELETE') {
    // Admin/owner can remove anyone; non-admin can only remove themselves (leave).
    if (!(perms?.can_manage_members || ctx.viewer_id === member_id)) throw forbidden('member removal forbidden');

    const data = await withIdempotency({
      env, ctx, request,
      bodyRaw: '',
      handler: async () => {
        const now = nowUnix();
        await withTx(env.DB, async (db) => {
          const res = await db.prepare(
            `UPDATE collection_members
             SET deleted_at = ?4, updated_at = ?4
             WHERE owner_id = ?1 AND collection_id = ?2 AND member_id = ?3 AND deleted_at IS NULL`
          ).bind(owner_id, collection_id, member_id, now).run();
          if ((res.meta?.changes ?? 0) === 0) throw notFound('member not found');
        });
        return { ok: true, deleted_at: now };
      },
    });

    return okJson(data);
  }

  throw methodNotAllowed();
}

  // Mounts (canonical)
  // GET  /api/v1/collections/:owner_id/:collection_id/mounts
  // POST /api/v1/collections/:owner_id/:collection_id/mounts { folder_id, access }
  // PATCH/DELETE /api/v1/collections/:owner_id/:collection_id/mounts/:folder_id
  const mMounts = pathname.match(/^\/api\/v1\/collections\/([^\/]+)\/([^\/]+)\/mounts$/);
  if (mMounts) {
    const owner_id = decodeURIComponent(mMounts[1]);
    const collection_id = decodeURIComponent(mMounts[2]);
    return await apiCollectionMounts({ request, env, request_id, ctx, owner_id, collection_id });
  }
  const mMount = pathname.match(/^\/api\/v1\/collections\/([^\/]+)\/([^\/]+)\/mounts\/([^\/]+)$/);
  if (mMount) {
    const owner_id = decodeURIComponent(mMount[1]);
    const collection_id = decodeURIComponent(mMount[2]);
    const folder_id = decodeURIComponent(mMount[3]);
    return await apiCollectionMount({ request, env, request_id, ctx, owner_id, collection_id, folder_id });
  }

  // Search (canonical)
  // GET /api/v1/search?q=...&scope=all|collection|folder&owner_id=...&collection_id=...&sort=updated_desc&limit=..&cursor=..
  if (request.method === 'GET' && pathname === '/api/v1/search') {
    if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
    const ctx = await parseViewerContext(request, env);

const q = url.searchParams.get('q') || '';
    const scope = url.searchParams.get('scope') || 'all';
    const owner_id = url.searchParams.get('owner_id') || null;
    const collection_id = url.searchParams.get('collection_id') || null;

    const sort = (url.searchParams.get('sort') || 'updated_desc').toLowerCase();
    if (sort !== 'updated_desc') throw validation('invalid sort', { sort });

    const limit = clampLimit(url.searchParams.get('limit'), 30, 50);
    const cursor = url.searchParams.get('cursor');

    const data = await withTx(env.DB, async (db) => {
      return await apiSearchV1({
        db,
        viewer_id: ctx.viewer_id,
        q,
        scope,
        owner_id,
        collection_id,
        limit,
        cursor,
        request_id,
      });
    });

    return okJson(data);
  }

  // Owner folders list (canonical)
  // GET /api/v1/folders/owned?state=active|trash&sort=updated_desc&limit=..&cursor=..
  if (request.method === 'GET' && pathname === '/api/v1/folders/owned') {
    if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
    const ctx = await parseViewerContext(request, env);

    const state = (url.searchParams.get('state') || 'active').toLowerCase();
    if (state !== 'active' && state !== 'trash') throw validation('invalid state', { state });

    const sort = (url.searchParams.get('sort') || 'updated_desc').toLowerCase();
    if (sort !== 'updated_desc') throw validation('invalid sort', { sort });

    const limit = clampLimit(url.searchParams.get('limit'), 30, 50);
    const cursor = url.searchParams.get('cursor');

    const data = await withTx(env.DB, async (db) =>
      listOwnerFolders({ db, owner_id: ctx.owner_id, state, sort, limit, cursor })
    );

    return okJson(data);
  }

  // Owner folder create (canonical)
  // POST /api/v1/folders  { name }
  if (request.method === 'POST' && pathname === '/api/v1/folders') {
    if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
    const ctx = await parseViewerContext(request, env);
    const { obj: body, raw } = await readJsonWithRaw(request.clone());
    const name = requireNonEmptyString(body.name, 'name', 120);
    const ip = getClientIp(request);
    const user_agent = getUserAgent(request);

    return withIdempotency({
      env,
      ctx,
      request,
      bodyRaw: raw,
      handler: async () => {
        const folder = await withTx(env.DB, async (db) =>
          createOwnerFolder({ db, owner_id: ctx.owner_id, actor_id: ctx.viewer_id, name, ip, user_agent })
        );
        const etag = etagFromUpdatedAt(folder.updated_at || Date.now());
        return okJson({ folder }, 201, { ETag: etag });
      },
    });
  }

  // Owner folder rename (canonical)
  // PATCH /api/v1/folders/:owner_id/:folder_id { name }
  const mRename = pathname.match(/^\/api\/v1\/folders\/([^\/]+)\/([^\/]+)$/);
  if (mRename && request.method === 'PATCH') {
    if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
    const ctx = await parseViewerContext(request, env);
    requireOwnerWrite(ctx);
    const owner_id = decodeURIComponent(mRename[1]);
    const folder_id = decodeURIComponent(mRename[2]);

    if (owner_id !== ctx.owner_id) throw forbidden('owner mismatch');

    const { obj: body, raw } = await readJsonWithRaw(request.clone());
    const name = requireNonEmptyString(body.name, 'name', 120);
    const ip = getClientIp(request);
    const user_agent = getUserAgent(request);
    const if_match = request.headers.get('if-match') || null;

    return withIdempotency({
      env,
      ctx,
      request,
      bodyRaw: raw,
      handler: async () => {
        const folder = await withTx(env.DB, async (db) =>
          renameOwnerFolder({
            db,
            owner_id,
            actor_id: ctx.viewer_id,
            folder_id,
            name,
            if_match,
            ip,
            user_agent,
          })
        );
        const etag = etagFromUpdatedAt(folder.updated_at || Date.now());
        return okJson({ folder }, 200, { ETag: etag });
      },
    });
  }

// Owner folder soft delete (canonical)
  // POST /api/v1/folders/:owner_id/:folder_id/delete
  const mDel = pathname.match(/^\/api\/v1\/folders\/([^\/]+)\/([^\/]+)\/delete$/);
  if (mDel && request.method === 'POST') {
    if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
    const ctx = await parseViewerContext(request, env);
    requireOwnerWrite(ctx);
    const owner_id = decodeURIComponent(mDel[1]);
    const folder_id = decodeURIComponent(mDel[2]);
    if (owner_id !== ctx.owner_id) throw forbidden('owner mismatch');

    const ip = getClientIp(request);
    const user_agent = getUserAgent(request);

    return withIdempotency({
      env,
      ctx,
      request,
      bodyRaw: '',
      handler: async () => {
        const folder = await withTx(env.DB, async (db) =>
          moveFolderToTrash({ db, owner_id, actor_id: ctx.viewer_id, folder_id, ip, user_agent })
        );
        const etag = etagFromUpdatedAt(folder.updated_at || Date.now());
        return okJson({ folder }, 200, { ETag: etag });
      },
    });
  }

  // -----------------------------
  // Phase 2: Cards (Owner) — canonical v1 endpoints
  // -----------------------------

  // GET/POST /api/v1/folders/:owner_id/:folder_id/cards
  const mCardsByFolder = pathname.match(/^\/api\/v1\/folders\/([^\/]+)\/([^\/]+)\/cards$/);
  if (mCardsByFolder) {
    if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
    const ctx = await parseViewerContext(request, env);
    requireOwnerWrite(ctx);

    const owner_id = decodeURIComponent(mCardsByFolder[1]);
    const folder_id = decodeURIComponent(mCardsByFolder[2]);
    if (owner_id !== ctx.owner_id) throw forbidden('owner mismatch');

    if (request.method === 'GET') {
      const stateRaw = (url.searchParams.get('state') || 'active').toLowerCase();
      const state = stateRaw === 'trash' ? 'trash' : stateRaw === 'all' ? 'all' : 'active';
      const include_deleted = state === 'all' || url.searchParams.get('include_deleted') === '1';

      const sort = (url.searchParams.get('sort') || 'updated_desc').toLowerCase();
      if (sort !== 'updated_desc' && sort !== 'created_desc' && sort !== 'title_asc') {
        throw validation('invalid sort', { sort });
      }

      const limit = clampLimit(url.searchParams.get('limit'), 30, 50);
      const cursor = url.searchParams.get('cursor');

      const data = await withTx(env.DB, async (db) =>
        listOwnerFolderCards({
          db,
          owner_id,
          folder_id,
          state,
          include_deleted,
          sort,
          limit,
          cursor,
        })
      );

      return okJson(data);
    }

    if (request.method === 'POST') {
      const { obj: body, raw } = await readJsonWithRaw(request.clone());
      const ip = getClientIp(request);
      const user_agent = getUserAgent(request);

      return withIdempotency({
        env,
        ctx,
        request,
        bodyRaw: raw,
        handler: async () => {
          const card = await withTx(env.DB, async (db) =>
            createOwnerCard({
              db,
              owner_id,
              actor_id: ctx.viewer_id,
              folder_id,
              title: body.title,
              content: body.content,
              ip,
              user_agent,
            })
          );
          const etag = etagFromUpdatedAt(card.updated_at || Date.now());
          return okJson({ card }, 201, { ETag: etag });
        },
      });
    }

    throw notFound(request_id, { path: pathname, method: request.method });
  }

  // GET/PATCH /api/v1/cards/:owner_id/:card_id
  const mCard = pathname.match(/^\/api\/v1\/cards\/([^\/]+)\/([^\/]+)$/);
  if (mCard) {
    if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
    const ctx = await parseViewerContext(request, env);
    requireOwnerWrite(ctx);

    const owner_id = decodeURIComponent(mCard[1]);
    const card_id = decodeURIComponent(mCard[2]);
    if (owner_id !== ctx.owner_id) throw forbidden('owner mismatch');

    if (request.method === 'GET') {
      const card = await withTx(env.DB, async (db) => getOwnerCardDetail({ db, owner_id, card_id }));
      const etag = etagFromUpdatedAt(card.updated_at || Date.now());
      return okJson({ card }, 200, { ETag: etag });
    }

    if (request.method === 'PATCH') {
      const { obj: body, raw } = await readJsonWithRaw(request.clone());
      const ip = getClientIp(request);
      const user_agent = getUserAgent(request);
      const if_match = request.headers.get('if-match') || null;

      return withIdempotency({
        env,
        ctx,
        request,
        bodyRaw: raw,
        handler: async () => {
          const card = await withTx(env.DB, async (db) =>
            updateOwnerCard({
              db,
              owner_id,
              actor_id: ctx.viewer_id,
              card_id,
              patch: body,
              if_match,
              ip,
              user_agent,
            })
          );
          const etag = etagFromUpdatedAt(card.updated_at || Date.now());
          return okJson({ card }, 200, { ETag: etag });
        },
      });
    }

    throw notFound(request_id, { path: pathname, method: request.method });
  }

  // POST /api/v1/cards/:owner_id/:card_id/delete
  const mCardDelete = pathname.match(/^\/api\/v1\/cards\/([^\/]+)\/([^\/]+)\/delete$/);
  if (mCardDelete) {
    if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
    const ctx = await parseViewerContext(request, env);
    requireOwnerWrite(ctx);

    const owner_id = decodeURIComponent(mCardDelete[1]);
    const card_id = decodeURIComponent(mCardDelete[2]);
    if (owner_id !== ctx.owner_id) throw forbidden('owner mismatch');

    if (request.method === 'POST') {
      const ip = getClientIp(request);
      const user_agent = getUserAgent(request);

      return withIdempotency({
        env,
        ctx,
        request,
        bodyRaw: '',
        handler: async () => {
          const card = await withTx(env.DB, async (db) =>
            moveCardToTrash({
              db,
              owner_id,
              actor_id: ctx.viewer_id,
              card_id,
              ip,
              user_agent,
            })
          );
          const etag = etagFromUpdatedAt(card.updated_at || Date.now());
          return okJson({ card }, 200, { ETag: etag });
        },
      });
    }

    throw notFound(request_id, { path: pathname, method: request.method });
  }

  

  // -----------------------------
  // Phase 3: Assets Metadata — canonical v1 endpoints
  // -----------------------------
// GET/POST /api/owner/cards/:card_id/assets
  const mOwnerCardAssets = pathname.match(/^\/api\/owner\/cards\/([^\/]+)\/assets$/);
  if (mOwnerCardAssets) {
    const card_id = decodeURIComponent(mOwnerCardAssets[1]);

    if (request.method === 'GET') {
      const limit = clampLimit(url.searchParams.get('limit'), 50, 200);
      const cursor = url.searchParams.get('cursor');

      const data = await withTx(env.DB, async (db) => {
        const card = await db
          .prepare('SELECT card_id FROM cards WHERE owner_id=? AND card_id=? LIMIT 1')
          .bind(String(ctx.owner_id), String(card_id))
          .first();
        if (!card) throw notFound(request_id, { entity: 'card', card_id });

        let last_created_at = null;
        let last_asset_id = null;
        if (cursor) {
          const c = decodeCursor(cursor);
          if (!c || c.sort !== 'created_asc' || !c.last_key) throw validation('cursor mismatch');
          last_created_at = Number(c.last_key.created_at);
          last_asset_id = String(c.last_key.asset_id);
        }

        let stmt;
        if (last_created_at == null) {
          stmt = db
            .prepare(
              `SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at
               FROM assets
               WHERE owner_id=? AND card_id=? AND deleted_at IS NULL
               ORDER BY created_at ASC, asset_id ASC
               LIMIT ?`
            )
            .bind(String(ctx.owner_id), String(card_id), Number(limit));
        } else {
          stmt = db
            .prepare(
              `SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at
               FROM assets
               WHERE owner_id=? AND card_id=? AND deleted_at IS NULL
                 AND (created_at > ? OR (created_at = ? AND asset_id > ?))
               ORDER BY created_at ASC, asset_id ASC
               LIMIT ?`
            )
            .bind(String(ctx.owner_id), String(card_id), last_created_at, last_created_at, String(last_asset_id), Number(limit));
        }

        const rows = await stmt.all();
        const items = (rows.results || []).map(assetRowToDto);
        let next_cursor = null;
        if (items.length === Number(limit) && items.length > 0) {
          const last = items[items.length - 1];
          next_cursor = encodeCursor({ sort: 'created_asc', last_key: { created_at: last.created_at, asset_id: last.asset_id } });
        }
        return { items, next_cursor };
      });

      return okJson(data);
    }

    if (request.method === 'POST') {
      const body = await readJson(request);
      const ip = getClientIp(request);
      const user_agent = getUserAgent(request);

      const r2_key = requireNonEmptyString(body.r2_key, 'r2_key', 1024);
      const filename = requireStringAllowEmpty(body.filename, 'filename', 500);
      const mime = requireStringAllowEmpty(body.mime, 'mime', 200);
      const size_bytes = requireNonNegativeInt(body.size_bytes, 'size_bytes');

      const default_quota_bytes = getDefaultQuotaBytes(env);

      const asset = await withTx(env.DB, async (db) => {
        const now = Date.now();

        const card = await db
          .prepare('SELECT card_id, folder_id, deleted_at FROM cards WHERE owner_id=? AND card_id=? LIMIT 1')
          .bind(String(ctx.owner_id), String(card_id))
          .first();
        if (!card) throw notFound(request_id, { entity: 'card', card_id });
        if (card.deleted_at != null) throw conflict('card is in trash');

        const existing = await db
          .prepare(
            'SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at FROM assets WHERE r2_key=? LIMIT 1'
          )
          .bind(String(r2_key))
          .first();

        if (existing) {
          if (String(existing.owner_id) !== String(ctx.owner_id)) throw conflict('r2_key already used');
          if (String(existing.card_id) !== String(card_id)) throw conflict('r2_key already attached to another card');

          if (existing.deleted_at != null) {
            await assertQuotaCanAddBytes({ db, owner_id: ctx.owner_id, folder_id: card.folder_id, add_bytes: Number(size_bytes), default_quota_bytes });

            await db
              .prepare(
                `UPDATE assets
                 SET deleted_at=NULL, purge_at=NULL, deleted_by=NULL,
                     filename=?, mime=?, size_bytes=?, created_at=?, updated_at=?
                 WHERE owner_id=? AND asset_id=?`
              )
              .bind(filename, mime, Number(size_bytes), now, now, String(ctx.owner_id), String(existing.asset_id))
              .run();

            await db
              .prepare('UPDATE cards SET updated_at=? WHERE owner_id=? AND card_id=?')
              .bind(now, String(ctx.owner_id), String(card_id))
              .run();

            await reconcileFolderUsedBytes({ db, owner_id: ctx.owner_id, folder_id: card.folder_id });

            const row = await db
              .prepare(
                'SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at FROM assets WHERE owner_id=? AND asset_id=? LIMIT 1'
              )
              .bind(String(ctx.owner_id), String(existing.asset_id))
              .first();

            await writeAudit(db, {
              owner_id: ctx.owner_id,
              actor_id: ctx.viewer_id,
              action: 'RESTORE_ASSET',
              entity_type: 'asset',
              entity_id: String(existing.asset_id),
              at: now,
              ip,
              user_agent,
              before: assetRowToDto(existing),
              after: assetRowToDto(row),
            });

            return assetRowToDto(row);
          }

          return assetRowToDto(existing);
        }

        const asset_id = newId('a');
        await db
          .prepare(
            `INSERT INTO assets(owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at, purge_at, deleted_by)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`
          )
          .bind(
            String(ctx.owner_id),
            String(asset_id),
            String(card_id),
            String(r2_key),
            filename,
            mime,
            Number(size_bytes),
            now,
            now,
            null,
            null,
            null
          )
          .run();

        await db
          .prepare('UPDATE cards SET updated_at=? WHERE owner_id=? AND card_id=?')
          .bind(now, String(ctx.owner_id), String(card_id))
          .run();

        const row = await db
          .prepare(
            'SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at FROM assets WHERE owner_id=? AND asset_id=? LIMIT 1'
          )
          .bind(String(ctx.owner_id), String(asset_id))
          .first();

        await writeAudit(db, {
          owner_id: ctx.owner_id,
          actor_id: ctx.viewer_id,
          action: 'UPLOAD_ASSET',
          entity_type: 'asset',
          entity_id: String(asset_id),
          at: now,
          ip,
          user_agent,
          before: null,
          after: assetRowToDto(row),
        });

        return assetRowToDto(row);
      });

      return okJson({ asset }, 201);
    }

    throw notFound(request_id, { path: pathname, method: request.method });
  }

  // PATCH /api/owner/cards/:card_id/assets/order
  const mOwnerCardAssetsOrder = pathname.match(/^\/api\/owner\/cards\/([^\/]+)\/assets\/order$/);
  if (mOwnerCardAssetsOrder && request.method === 'PATCH') {
    const card_id = decodeURIComponent(mOwnerCardAssetsOrder[1]);

    const body = await readJson(request);
    if (!body || !Array.isArray(body.asset_ids)) throw validation('asset_ids must be an array');
    const asset_ids = body.asset_ids.map((x) => String(x));
    const set_ids = new Set(asset_ids);
    if (asset_ids.length === 0 || set_ids.size !== asset_ids.length) throw validation('asset_ids must be unique and non-empty');

    const data = await withTx(env.DB, async (db) => {
      const now = Date.now();

      const card = await db
        .prepare('SELECT card_id, folder_id, deleted_at FROM cards WHERE owner_id=? AND card_id=? LIMIT 1')
        .bind(String(ctx.owner_id), String(card_id))
        .first();
      if (!card) throw notFound(request_id, { entity: 'card', card_id });
      if (card.deleted_at != null) throw conflict('card is in trash');

      const rows = await db
        .prepare(
          `SELECT asset_id
           FROM assets WHERE owner_id=? AND card_id=? AND deleted_at IS NULL
           ORDER BY created_at ASC, asset_id ASC`
        )
        .bind(String(ctx.owner_id), String(card_id))
        .all();

      const existing = (rows.results || []).map((r) => String(r.asset_id));
      const existing_set = new Set(existing);
      if (existing.length !== asset_ids.length) throw validation('asset_ids must match current active assets on the card');
      for (const id of asset_ids) if (!existing_set.has(id)) throw validation('asset_ids must match current active assets on the card');

      const base = now - asset_ids.length;
      for (let i = 0; i < asset_ids.length; i++) {
        const aid = asset_ids[i];
        await db
          .prepare('UPDATE assets SET created_at=?, updated_at=? WHERE owner_id=? AND asset_id=? AND deleted_at IS NULL')
          .bind(base + i, now, String(ctx.owner_id), String(aid))
          .run();
      }

      await db
        .prepare('UPDATE cards SET updated_at=? WHERE owner_id=? AND card_id=?')
        .bind(now, String(ctx.owner_id), String(card_id))
        .run();

      const out = await db
        .prepare(
          `SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at
           FROM assets WHERE owner_id=? AND card_id=? AND deleted_at IS NULL
           ORDER BY created_at ASC, asset_id ASC`
        )
        .bind(String(ctx.owner_id), String(card_id))
        .all();

      return { items: (out.results || []).map(assetRowToDto) };
    });

    return okJson(data);
  }

  // DELETE /api/owner/assets/:asset_id
  const mOwnerAsset = pathname.match(/^\/api\/owner\/assets\/([^\/]+)$/);
  if (mOwnerAsset && request.method === 'DELETE') {
    const asset_id = decodeURIComponent(mOwnerAsset[1]);

    const ip = getClientIp(request);
    const user_agent = getUserAgent(request);

    const asset = await withTx(env.DB, async (db) => {
      const now = Date.now();
      const purge_at = computePurgeAt(now);

      const before = await db
        .prepare(
          'SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at FROM assets WHERE owner_id=? AND asset_id=? LIMIT 1'
        )
        .bind(String(ctx.owner_id), String(asset_id))
        .first();
      if (!before) throw notFound(request_id, { entity: 'asset', asset_id });

      if (before.deleted_at == null) {
        await db
          .prepare(
            `UPDATE assets
             SET deleted_at=?, purge_at=?, deleted_by=?, updated_at=?
             WHERE owner_id=? AND asset_id=? AND deleted_at IS NULL`
          )
          .bind(now, purge_at, String(ctx.viewer_id), now, String(ctx.owner_id), String(asset_id))
          .run();

        await db
          .prepare('UPDATE cards SET updated_at=? WHERE owner_id=? AND card_id=?')
          .bind(now, String(ctx.owner_id), String(before.card_id))
          .run();

const cardRow = await db
  .prepare('SELECT folder_id FROM cards WHERE owner_id=? AND card_id=? LIMIT 1')
  .bind(String(ctx.owner_id), String(before.card_id))
  .first();
if (cardRow && cardRow.folder_id) {
  await reconcileFolderUsedBytes({ db, owner_id: ctx.owner_id, folder_id: String(cardRow.folder_id) });
}

        const after = await db
          .prepare(
            'SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at FROM assets WHERE owner_id=? AND asset_id=? LIMIT 1'
          )
          .bind(String(ctx.owner_id), String(asset_id))
          .first();

        await writeAudit(db, {
          owner_id: ctx.owner_id,
          actor_id: ctx.viewer_id,
          action: 'DELETE_ASSET',
          entity_type: 'asset',
          entity_id: asset_id,
          at: now,
          ip,
          user_agent,
          before: assetRowToDto(before),
          after: assetRowToDto(after),
        });

        return assetRowToDto(after);
      }

      return assetRowToDto(before);
    });

    return okJson({ asset });
  }

  // -----------------------------
  // Phase 6: Collections + Members (owner aliases)
  // -----------------------------

  if (pathname === '/api/owner/collections') {
    if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
    const ctx = await parseViewerContext(request, env);

    if (request.method === 'GET') {
      const q = url.searchParams;
      const state = (q.get('state') || 'active').toLowerCase();
      if (!['active', 'trash'].includes(state)) throw validation('invalid state');

      const sort = 'updated_desc';
      const limit = clampLimit(q.get('limit'));
      const cursor = q.get('cursor');

      const data = await listOwnerCollections({
        db: env.DB,
        owner_id: ctx.owner_id,
        state,
        sort,
        limit,
        cursor,
      });

      return okJson(data);
    }

    if (request.method === 'POST') {
      const body = await readJson(request);
      const name = requireNonEmptyString(body.name, 'name', 200);
      const policy_json = body.policy_json;

      const ip = getClientIp(request);
      const user_agent = getUserAgent(request);

      const collection = await withTx(env.DB, async (db) => {
        return await createOwnerCollection({
          db,
          owner_id: ctx.owner_id,
          actor_id: ctx.viewer_id,
          name,
          policy_json,
          request_id,
          ip,
          user_agent,
        });
      });

      return okJson({ collection }, 201);
    }

    throw notFound(request_id, { path: pathname, method: request.method });
  }

  const mOwnerCollection = pathname.match(/^\/api\/owner\/collections\/([^\/]+)$/);
  if (mOwnerCollection) {
    if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
    const ctx = await parseViewerContext(request, env);

    const collection_id = decodeURIComponent(mOwnerCollection[1]);
    const owner_id = ctx.owner_id;

    if (request.method === 'GET') {
      const row = await env.DB
        .prepare('SELECT owner_id, collection_id, name, policy_json, created_at, updated_at, deleted_at FROM collections WHERE owner_id=? AND collection_id=? LIMIT 1')
        .bind(String(owner_id), String(collection_id))
        .first();
      if (!row) throw notFound(request_id, { entity: 'collection', collection_id });
      return okJson({ collection: collectionRowToDto(row) });
    }

    if (request.method === 'PATCH') {
      const body = await readJson(request);
      const ip = getClientIp(request);
      const user_agent = getUserAgent(request);

      const collection = await withTx(env.DB, async (db) => {
        await assertCollectionOwnerRole({ db, owner_id, collection_id, actor_id: ctx.viewer_id });
        return await updateOwnerCollection({
          db,
          owner_id,
          collection_id,
          actor_id: ctx.viewer_id,
          patch: body,
          request_id,
          ip,
          user_agent,
        });
      });

      return okJson({ collection });
    }

    if (request.method === 'DELETE') {
      const ip = getClientIp(request);
      const user_agent = getUserAgent(request);

      const collection = await withTx(env.DB, async (db) => {
        await assertCollectionOwnerRole({ db, owner_id, collection_id, actor_id: ctx.viewer_id });
        return await moveCollectionToTrash({ db, owner_id, collection_id, actor_id: ctx.viewer_id, request_id, ip, user_agent });
      });

      return okJson({ collection });
    }

    throw notFound(request_id, { path: pathname, method: request.method });
  }

  const mOwnerMembers = pathname.match(/^\/api\/owner\/collections\/([^\/]+)\/members$/);
  if (mOwnerMembers) {
    if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
    const ctx = await parseViewerContext(request, env);

    const collection_id = decodeURIComponent(mOwnerMembers[1]);
    const owner_id = ctx.owner_id;

    if (request.method === 'GET') {
      await assertCollectionOwnerRole({ db: env.DB, owner_id, collection_id, actor_id: ctx.viewer_id });
      const members = await listCollectionMembers({ db: env.DB, owner_id, collection_id });
      return okJson({ members });
    }

    if (request.method === 'POST') {
      const body = await readJson(request);
      const ip = getClientIp(request);
      const user_agent = getUserAgent(request);

      const member = await withTx(env.DB, async (db) => {
        return await addCollectionMember({
          db,
          owner_id,
          collection_id,
          actor_id: ctx.viewer_id,
          member_id: body.member_id,
          role: body.role,
          request_id,
          ip,
          user_agent,
        });
      });

      return okJson({ member }, 201);
    }

    throw notFound(request_id, { path: pathname, method: request.method });
  }

  const mOwnerMember = pathname.match(/^\/api\/owner\/collections\/([^\/]+)\/members\/([^\/]+)$/);
  if (mOwnerMember) {
    if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
    const ctx = await parseViewerContext(request, env);

    const collection_id = decodeURIComponent(mOwnerMember[1]);
    const member_id = decodeURIComponent(mOwnerMember[2]);
    const owner_id = ctx.owner_id;

    if (request.method === 'PATCH') {
      const body = await readJson(request);
      const ip = getClientIp(request);
      const user_agent = getUserAgent(request);

      const member = await withTx(env.DB, async (db) => {
        return await updateCollectionMemberRole({
          db,
          owner_id,
          collection_id,
          actor_id: ctx.viewer_id,
          member_id,
          role: body.role,
          request_id,
          ip,
          user_agent,
        });
      });

      return okJson({ member });
    }

    if (request.method === 'DELETE') {
      const ip = getClientIp(request);
      const user_agent = getUserAgent(request);

      const result = await withTx(env.DB, async (db) => {
        return await revokeCollectionMember({
          db,
          owner_id,
          collection_id,
          actor_id: ctx.viewer_id,
          member_id,
          request_id,
          ip,
          user_agent,
        });
      });

      return okJson(result);
    }

    throw notFound(request_id, { path: pathname, method: request.method });
  }
  throw notFound(request_id, { path: pathname, method: request.method });
}

// -----------------------------
// Phase 8: /api/collection mount-aware search (viewer context)
// -----------------------------
async function handleApiCollection(request, env, request_id) {
  const url = new URL(request.url);
  const pathname = url.pathname;

  if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
  const ctx = await parseCollectionViewerContext(request, env);

  // GET /api/collection/{collection_id}/search?q=...&limit=..&cursor=..
  const mSearch = pathname.match(/^\/api\/collection\/([^\/]+)\/search$/);
  if (mSearch && request.method === 'GET') {
    const public_collection_id = decodeURIComponent(mSearch[1]);

    const q = url.searchParams.get('q') || '';
    const limit = clampLimit(url.searchParams.get('limit'), 30, 50);
    const cursor = url.searchParams.get('cursor');

    const data = await withTx(env.DB, async (db) => {
      const col = await resolveCollectionByPublicId({ db, collection_id: public_collection_id });
      if (!col || col.deleted_at != null) throw notFound(request_id, { entity: 'collection', collection_id: public_collection_id });

      return await searchCollectionCards({
        db,
        owner_id: String(col.owner_id),
        collection_id: String(col.collection_id),
        viewer_id: ctx.viewer_id,
        q,
        limit,
        cursor,
        request_id,
      });
    });

    return okJson(data);
  }

  throw notFound(request_id, { path: pathname, method: request.method });
}

async function apiHealth(request, env, request_id) {
  const start = Date.now();
  try {
    if (!env.DB) throw new HttpError('INTERNAL', 'DB binding missing', 500);
    const row = await env.DB.prepare('SELECT 1 AS ok').first();

    const data = {
      now_ms: Date.now(),
      db: row && row.ok === 1,
      build_id: BUILD_ID,
    };

    logEvent('api.health', {
      request_id,
      route: '/api/v1/health',
      method: 'GET',
      status: 200,
      latency_ms: Date.now() - start,
      db: data.db,
    });

    return okJson(data, 200);
  } catch (e) {
    const err = normalizeError(e, request_id);
    logEvent('api.health.error', {
      request_id,
      route: '/api/v1/health',
      method: 'GET',
      status: err.status,
      latency_ms: Date.now() - start,
      err_code: err.code,
      err_message: err.message,
    });
    return errJson({ code: err.code, message: err.message, details: err.details, request_id }, err.status);
  }
}

function normalizeError(e, request_id) {
  if (e && e.name === 'HttpError') {
    return {
      code: e.code || 'INTERNAL',
      message: e.message || 'internal error',
      status: e.status || 500,
      details: e.details,
    };
  }
  return {
    code: 'INTERNAL',
    message: 'internal error',
    status: 500,
    details: { request_id },
  };
}

// -----------------------------
// Added in worker_10: Spec compliance fixes (auth exchange, upload FSM, mounts, asset content, canonical trash)
// -----------------------------

const PURGE_RETENTION_DAYS = 30;
const PURGE_RETENTION_MS = PURGE_RETENTION_DAYS * 24 * 60 * 60 * 1000;

async function hmacSha256Sign(secret, data) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(String(secret)),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(String(data)));
  return new Uint8Array(sig);
}

async function signSessionTokenHS256({ viewer_id, jwt_secret, ttl_sec = 7 * 24 * 60 * 60 }) {
  if (!jwt_secret) throw new HttpError('INTERNAL', 'JWT secret not configured', 500);

  const nowSec = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = {
    viewer_id: String(viewer_id),
    iat: nowSec,
    exp: nowSec + Number(ttl_sec),
    jti: (crypto.randomUUID ? crypto.randomUUID() : newId('j')),
  };

  const h = utf8ToBase64Url(JSON.stringify(header));
  const p = utf8ToBase64Url(JSON.stringify(payload));
  const signingInput = `${h}.${p}`;

  const sigBytes = await hmacSha256Sign(jwt_secret, signingInput);
  const s = bytesToBase64Url(sigBytes);

  return `${signingInput}.${s}`;
}


// -----------------------------
// LINE ID Token verification helpers (local signature verification)
// -----------------------------
function parseJwt(jwt) {
  const parts = String(jwt).split('.');
  if (parts.length !== 3) throw new HttpError('AUTH_INVALID', 'invalid JWT format', 401);
  const [hB64, pB64, sB64] = parts;

  let header, payload;
  try {
    header = JSON.parse(bytesToUtf8(base64UrlToBytes(hB64)));
  } catch {
    throw new HttpError('AUTH_INVALID', 'invalid JWT header', 401);
  }
  try {
    payload = JSON.parse(bytesToUtf8(base64UrlToBytes(pB64)));
  } catch {
    throw new HttpError('AUTH_INVALID', 'invalid JWT payload', 401);
  }

  const signingInput = `${hB64}.${pB64}`;
  const signatureBytes = base64UrlToBytes(sB64);

  return { header, payload, signingInput, signatureBytes };
}

async function hmacSha256Verify(secret, signingInput, signatureBytes) {
  const expected = await hmacSha256Sign(secret, signingInput);
  return constantTimeEqual(expected, signatureBytes);
}

function constantTimeEqual(a, b) {
  if (!(a instanceof Uint8Array)) a = new Uint8Array(a);
  if (!(b instanceof Uint8Array)) b = new Uint8Array(b);
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// JWT ES256 signatures are JOSE (raw R||S). WebCrypto expects DER.
// Convert 64-byte JOSE signature to DER encoded ECDSA signature.
function joseToDerEcdsa(sig) {
  if (!(sig instanceof Uint8Array)) sig = new Uint8Array(sig);
  if (sig.length !== 64) throw new HttpError('AUTH_INVALID', 'invalid ES256 signature length', 401, { len: sig.length });

  const r = sig.slice(0, 32);
  const s = sig.slice(32);

  const rDer = toDerInt(r);
  const sDer = toDerInt(s);

  const totalLen = 2 + rDer.length + 2 + sDer.length;
  const out = new Uint8Array(2 + totalLen);
  let o = 0;
  out[o++] = 0x30; // SEQUENCE
  out[o++] = totalLen;
  out[o++] = 0x02; // INTEGER
  out[o++] = rDer.length;
  out.set(rDer, o);
  o += rDer.length;
  out[o++] = 0x02; // INTEGER
  out[o++] = sDer.length;
  out.set(sDer, o);
  return out;
}

function toDerInt(bytes) {
  // strip leading zeros
  let i = 0;
  while (i < bytes.length - 1 && bytes[i] === 0x00) i++;
  let v = bytes.slice(i);

  // if high bit set, prepend 0x00
  if (v[0] & 0x80) {
    const tmp = new Uint8Array(v.length + 1);
    tmp[0] = 0x00;
    tmp.set(v, 1);
    v = tmp;
  }
  return v;
}

let __lineJwksCache = { ts: 0, jwks: null };
async function fetchLineJwks() {
  const now = Date.now();
  if (__lineJwksCache.jwks && now - __lineJwksCache.ts < 10 * 60 * 1000) return __lineJwksCache.jwks;

  const res = await fetch('https://api.line.me/oauth2/v2.1/certs');
  if (!res.ok) throw new HttpError('INTERNAL', 'failed to fetch LINE JWKS', 500, { status: res.status });
  const jwks = await res.json().catch(() => null);
  if (!jwks || !Array.isArray(jwks.keys)) throw new HttpError('INTERNAL', 'invalid LINE JWKS response', 500);

  __lineJwksCache = { ts: now, jwks };
  return jwks;
}

function pickJwkByKid(jwks, kid) {
  const keys = Array.isArray(jwks?.keys) ? jwks.keys : [];
  if (!kid) return keys[0] || null;
  return keys.find((k) => String(k.kid) === String(kid)) || null;
}

async function verifyLineIdToken({ id_token, client_id, channel_secret }) {
  if (!id_token) throw new HttpError('AUTH_INVALID', 'missing id_token', 401);
  if (!client_id) throw new HttpError('INTERNAL', 'LINE client_id not configured', 500);

  // Prefer local signature verification (spec). Support HS256 (channel secret) and ES256 (JWKS).
  const { header, payload, signingInput, signatureBytes } = parseJwt(id_token);

  const alg = String(header?.alg || '');
  const kid = header?.kid ? String(header.kid) : null;

  if (alg === 'HS256') {
    if (!channel_secret) throw new HttpError('INTERNAL', 'LINE channel secret not configured for HS256', 500);
    const ok = await hmacSha256Verify(channel_secret, signingInput, signatureBytes);
    if (!ok) throw new HttpError('AUTH_INVALID', 'invalid id_token signature', 401);
  } else if (alg === 'ES256') {
    const jwks = await fetchLineJwks();
    const jwk = pickJwkByKid(jwks, kid);
    if (!jwk) throw new HttpError('AUTH_INVALID', 'no matching JWK for id_token kid', 401, { kid });

    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );

    const derSig = joseToDerEcdsa(signatureBytes);
    const ok = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      derSig,
      new TextEncoder().encode(signingInput)
    );
    if (!ok) throw new HttpError('AUTH_INVALID', 'invalid id_token signature', 401);
  } else {
    throw new HttpError('AUTH_INVALID', 'unsupported id_token alg', 401, { alg });
  }

  // Claims validation (OIDC basics + LINE docs)
  const nowSec = Math.floor(Date.now() / 1000);

  const iss = String(payload?.iss || '');
  if (iss !== 'https://access.line.me') {
    throw new HttpError('AUTH_INVALID', 'invalid id_token issuer', 401, { iss });
  }

  const aud = payload?.aud;
  const audOk =
    (typeof aud === 'string' && aud === String(client_id)) ||
    (Array.isArray(aud) && aud.map(String).includes(String(client_id)));
  if (!audOk) {
    throw new HttpError('AUTH_INVALID', 'invalid id_token audience', 401, { aud, client_id });
  }

  const exp = Number(payload?.exp);
  const iat = Number(payload?.iat);
  if (!Number.isFinite(exp) || !Number.isFinite(iat)) {
    throw new HttpError('AUTH_INVALID', 'invalid id_token time claims', 401, { exp: payload?.exp, iat: payload?.iat });
  }
  if (exp <= nowSec) throw new HttpError('AUTH_INVALID', 'id_token expired', 401, { exp, nowSec });

  const sub = payload?.sub;
  if (typeof sub !== 'string' || !sub) throw new HttpError('AUTH_INVALID', 'id_token missing sub', 401);

  return payload;
}

function pickEnvFirst(env, keys) {
  for (const k of keys) {
    if (env && env[k]) return env[k];
  }
  return null;
}

function detectKvBinding(env) {
  if (!env || typeof env !== 'object') return null;
  // Prefer explicit
  const preferred = pickEnvFirst(env, ['SESSIONS', 'SESSION_KV', 'UPLOAD_SESSIONS', 'KV']);
  if (preferred && typeof preferred.get === 'function' && typeof preferred.put === 'function') return preferred;

  for (const [k, v] of Object.entries(env)) {
    if (v && typeof v.get === 'function' && typeof v.put === 'function') return v;
  }
  return null;
}

function detectR2Bucket(env) {
  if (!env || typeof env !== 'object') return null;
  const preferred = pickEnvFirst(env, ['R2', 'BUCKET', 'ASSETS', 'ASSETS_BUCKET', 'R2_BUCKET']);
  if (preferred && typeof preferred.get === 'function' && typeof preferred.put === 'function') return preferred;

  for (const [k, v] of Object.entries(env)) {
    if (v && typeof v.get === 'function' && typeof v.put === 'function') return v;
  }
  return null;
}

async function apiAuthLiffExchange(request, env, request_id) {
  const body = await readJson(request);
  const id_token = requireNonEmptyString(body?.id_token, 'id_token', 4096);

  const client_id =
    pickEnvFirst(env, ['LINE_CHANNEL_ID', 'LINE_CLIENT_ID', 'LIFF_CHANNEL_ID', 'LIFF_CLIENT_ID']) || '';
  const channel_secret = pickEnvFirst(env, ['LIFF_CHANNEL_SECRET','LINE_CHANNEL_SECRET','LINE_CLIENT_SECRET']) || '';
  const verify = await verifyLineIdToken({ id_token, client_id, channel_secret });

  const viewer_id = String(verify.sub);
  const session_token = await signSessionTokenHS256({ viewer_id, jwt_secret: env.JWT_SECRET });

  // Bootstrap (DB-first, idempotent)
  const bootstrap = await withTx(env.DB, async (db) => bootstrapOwnerIfNeeded({ db, owner_id: viewer_id }));

  return okJson({ viewer_id, session_token, bootstrap }, 200);
}

async function bootstrapOwnerIfNeeded({ db, owner_id }) {
  const now = Date.now();
  const default_quota_bytes = 3 * 1024 * 1024 * 1024; // 3GB default; adjust via env if needed in future

  // user_plans
  const plan = await db
    .prepare('SELECT owner_id, plan, quota_bytes, created_at, updated_at FROM user_plans WHERE owner_id=? LIMIT 1')
    .bind(String(owner_id))
    .first();

  if (!plan) {
    await db
      .prepare(
        'INSERT INTO user_plans(owner_id, plan, quota_bytes, created_at, updated_at) VALUES(?,?,?,?,?)'
      )
      .bind(String(owner_id), 'free', Number(default_quota_bytes), now, now)
      .run();
  }

  // Ensure at least one collection
  let col = await db
    .prepare(
      'SELECT owner_id, collection_id, name FROM collections WHERE owner_id=? AND deleted_at IS NULL ORDER BY created_at ASC LIMIT 1'
    )
    .bind(String(owner_id))
    .first();

  if (!col) {
    const collection_id = newId('col');
    await db
      .prepare(
        'INSERT INTO collections(owner_id, collection_id, name, policy_json, created_at, updated_at, deleted_at, purge_at, deleted_by) VALUES(?,?,?,?,?,?,?,?,?)'
      )
      .bind(String(owner_id), String(collection_id), 'My Collection', '{}', now, now, null, null, null)
      .run();
    col = { owner_id: String(owner_id), collection_id: String(collection_id), name: 'My Collection' };
  }

  // Ensure collection_members owner
  const mem = await db
    .prepare('SELECT role FROM collection_members WHERE owner_id=? AND collection_id=? AND member_id=? LIMIT 1')
    .bind(String(owner_id), String(col.collection_id), String(owner_id))
    .first();
  if (!mem) {
    await db
      .prepare(
        'INSERT INTO collection_members(owner_id, collection_id, member_id, role, added_at, updated_at) VALUES(?,?,?,?,?,?)'
      )
      .bind(String(owner_id), String(col.collection_id), String(owner_id), 'owner', now, now)
      .run();
  }

  // Ensure a root folder
  let folder = await db
    .prepare(
      'SELECT owner_id, folder_id, name FROM folders WHERE owner_id=? AND deleted_at IS NULL ORDER BY created_at ASC LIMIT 1'
    )
    .bind(String(owner_id))
    .first();
  if (!folder) {
    const folder_id = newId('f');
    await db
      .prepare(
        'INSERT INTO folders(owner_id, folder_id, name, used_bytes, created_at, updated_at, deleted_at, purge_at, deleted_by) VALUES(?,?,?,?,?,?,?,?,?)'
      )
      .bind(String(owner_id), String(folder_id), 'My Drive', 0, now, now, null, null, null)
      .run();
    folder = { owner_id: String(owner_id), folder_id: String(folder_id), name: 'My Drive' };
  }

  // Ensure mount (collection -> folder)
  const mount = await db
    .prepare(
      'SELECT owner_id, collection_id, folder_id, access, deleted_at FROM mounts WHERE owner_id=? AND collection_id=? AND folder_id=? LIMIT 1'
    )
    .bind(String(owner_id), String(col.collection_id), String(folder.folder_id))
    .first();
  if (!mount) {
    await db
      .prepare(
        'INSERT INTO mounts(owner_id, collection_id, folder_id, access, created_at, updated_at, deleted_at, purge_at, deleted_by) VALUES(?,?,?,?,?,?,?,?,?)'
      )
      .bind(String(owner_id), String(col.collection_id), String(folder.folder_id), 'write', now, now, null, null, null)
      .run();
  } else if (mount.deleted_at != null) {
    await db
      .prepare('UPDATE mounts SET access=?, updated_at=?, deleted_at=NULL, purge_at=NULL, deleted_by=NULL WHERE owner_id=? AND collection_id=? AND folder_id=?')
      .bind('write', now, String(owner_id), String(col.collection_id), String(folder.folder_id))
      .run();
  }

  return {
    collection_id: String(col.collection_id),
    folder_id: String(folder.folder_id),
  };
}

function parseRangeHeader(rangeHeader, totalSize) {
  const h = String(rangeHeader || '').trim();
  if (!h) return null;
  const m = h.match(/^bytes=(\d*)-(\d*)$/);
  if (!m) return null;

  let start = m[1] === '' ? null : Number(m[1]);
  let end = m[2] === '' ? null : Number(m[2]);

  if (Number.isNaN(start)) start = null;
  if (Number.isNaN(end)) end = null;

  if (start == null && end == null) return null;

  // suffix: bytes=-N
  if (start == null && end != null) {
    const n = end;
    if (n <= 0) return null;
    start = Math.max(0, totalSize - n);
    end = totalSize - 1;
    return { start, end };
  }

  // open-ended: bytes=N-
  if (start != null && end == null) {
    if (start < 0 || start >= totalSize) return null;
    end = totalSize - 1;
    return { start, end };
  }

  // bounded: bytes=N-M
  if (start != null && end != null) {
    if (start < 0 || end < start) return null;
    if (start >= totalSize) return null;
    end = Math.min(end, totalSize - 1);
    return { start, end };
  }

  return null;
}

async function apiAssetContentProxy({ request, env, request_id, ctx, owner_id, asset_id }) {
  if (owner_id !== ctx.owner_id) throw forbidden('owner mismatch');

  const row = await env.DB
    .prepare(
      'SELECT owner_id, asset_id, r2_key, mime, size_bytes, deleted_at FROM assets WHERE owner_id=? AND asset_id=? LIMIT 1'
    )
    .bind(String(owner_id), String(asset_id))
    .first();

  if (!row) throw notFound(request_id, { entity: 'asset', asset_id });
  if (row.deleted_at != null) throw notFound(request_id, { entity: 'asset', asset_id });

  const bucket = detectR2Bucket(env);
  if (!bucket) throw new HttpError('INTERNAL', 'R2 bucket binding missing', 500);

  const size = Number(row.size_bytes || 0);
  const range = parseRangeHeader(request.headers.get('Range'), size);

  let obj;
  if (range) {
    obj = await bucket.get(String(row.r2_key), { range: { offset: range.start, length: range.end - range.start + 1 } });
    if (!obj) throw notFound(request_id, { entity: 'asset', asset_id });
    const headers = new Headers();
    headers.set('accept-ranges', 'bytes');
    headers.set('content-type', String(row.mime || 'application/octet-stream'));
    headers.set('content-length', String(range.end - range.start + 1));
    headers.set('content-range', `bytes ${range.start}-${range.end}/${size}`);
    return new Response(obj.body, { status: 206, headers });
  }

  obj = await bucket.get(String(row.r2_key));
  if (!obj) throw notFound(request_id, { entity: 'asset', asset_id });

  const headers = new Headers();
  headers.set('accept-ranges', 'bytes');
  headers.set('content-type', String(row.mime || 'application/octet-stream'));
  if (size) headers.set('content-length', String(size));
  return new Response(obj.body, { status: 200, headers });
}

async function apiAssetsUpload(request, env, request_id, ctx) {
  const url = new URL(request.url);
  const { pathname } = url;

  // Phase 3 (Roadmap): upload_sessions FSM + upload_session_files + R2 integration + write-order invariant + allow_download control + cleanup job
  // v7.33 upload_sessions FSM (Implementation Plan): CREATED | UPLOADING | FINALIZING | ACTIVE | FAILED | ABANDONED
  const db = env.DB;
  const bucket = detectR2Bucket(env);
  if (!bucket) throw new HttpError('INTERNAL', 'R2 bucket binding missing', 500);

  const now = Date.now();
  const ip = getClientIp(request);
  const user_agent = getUserAgent(request);

  function validateR2Key(r2_key) {
    if (typeof r2_key !== 'string') throw validation('r2_key must be a string');
    const s = r2_key.trim();
    if (!s) throw validation('r2_key is required');
    if (s.length > 1024) throw validation('r2_key too long');
    if (/[ \n\r\t]/.test(s)) throw validation('r2_key must not contain whitespace');
    return s;
  }

  async function getActiveCardOrThrow(owner_id, card_id) {
    const card = await db
      .prepare('SELECT owner_id, card_id, folder_id, deleted_at FROM cards WHERE owner_id=? AND card_id=? LIMIT 1')
      .bind(String(owner_id), String(card_id))
      .first();
    if (!card) throw notFound(request_id, { entity: 'card', card_id });
    if (card.deleted_at != null) throw conflict('card is in trash');
    return card;
  }

  async function getSessionOrThrow(owner_id, upload_session_id) {
    const row = await db
      .prepare(
        'SELECT owner_id, upload_session_id, status, folder_id, replace_mode, total_bytes, created_at, updated_at, expires_at, committed_at, canceled_at FROM upload_sessions WHERE owner_id=? AND upload_session_id=? LIMIT 1'
      )
      .bind(String(owner_id), String(upload_session_id))
      .first();
    if (!row) throw notFound(request_id, { entity: 'upload_session', upload_session_id });
    return row;
  }

  async function listSessionFiles(owner_id, upload_session_id) {
    const rows = await db
      .prepare(
        'SELECT file_id, r2_key, filename, mime, size_bytes, sha256, created_at FROM upload_session_files WHERE owner_id=? AND upload_session_id=? ORDER BY created_at ASC'
      )
      .bind(String(owner_id), String(upload_session_id))
      .all();
    return rows.results || [];
  }

  // -----------------------------
  // POST /api/v1/assets/upload/init
  // { card_id, mode: "append"|"replace", items:[{ filename, mime, size_bytes, sha256? }] }
  // Returns: { upload_session_id, items:[{file_id,r2_key,put_url,put_headers}] }
  // -----------------------------
  if ((pathname === '/api/v1/assets/upload/init' || pathname === '/upload-sessions') && request.method === 'POST') {
    const { obj: body, raw } = await readJsonWithRaw(request);

    const handler = async () => {
      const card_id = requireNonEmptyString(body?.card_id, 'card_id', 64);
      const mode = String(body?.mode || 'append');
      if (!['append', 'replace'].includes(mode)) throw validation('mode must be append|replace');

      if (!Array.isArray(body?.items) || body.items.length === 0) throw validation('items must be a non-empty array');
      if (body.items.length > 50) throw validation('too many items');

      // Phase 3: keep strict — only owner can init upload
      requireOwnerWrite(ctx);

      // validate card exists
      const card = await getActiveCardOrThrow(ctx.owner_id, card_id);

      const upload_session_id = makeUlid(now);
      const replace_mode = mode === 'replace' ? 1 : 0;

      const items = body.items.map((it) => {
        const filename = requireStringAllowEmpty(it?.filename, 'filename', 512);
        const mime = requireStringAllowEmpty(it?.mime, 'mime', 200) || 'application/octet-stream';
        const size_bytes = requireNonNegativeInt(it?.size_bytes, 'size_bytes');
        const sha256 = it?.sha256 == null ? null : String(it.sha256);
        if (sha256 != null && !/^[0-9a-f]{64}$/.test(sha256)) throw validation('sha256 must be 64 hex lowercase', { field: 'sha256' });

        const file_id = makeUlid(now + Math.floor(Math.random() * 10));
        // r2_key immutable at creation time
        const r2_key = validateR2Key(`mb/v7.33/o/${ctx.owner_id}/u/${upload_session_id}/f/${file_id}`);
        return { file_id, r2_key, filename, mime, size_bytes, sha256 };
      });

      const total_bytes = items.reduce((a, b) => a + Number(b.size_bytes || 0), 0);
      // Phase 3 quota gate (roadmap): used_bytes + delta <= quota_bytes
      // For replace mode, only the net growth counts toward quota (shrinking replacement does not require extra quota).
      let net_add_bytes = Number(total_bytes || 0);
      if (replace_mode === 1) {
        const existing = await db
          .prepare('SELECT COALESCE(SUM(size_bytes),0) AS bytes FROM assets WHERE owner_id=? AND card_id=? AND deleted_at IS NULL')
          .bind(String(ctx.owner_id), String(card_id))
          .first();
        const existing_bytes = Number(existing?.bytes || 0);
        net_add_bytes = Math.max(0, Number(total_bytes || 0) - existing_bytes);
      }
      await assertQuotaCanAddBytes({
        db,
        owner_id: ctx.owner_id,
        folder_id: card.folder_id,
        add_bytes: net_add_bytes,
        default_quota_bytes: getDefaultQuotaBytes(env),
      });

      const expires_at = now + 24 * 60 * 60 * 1000;

      const resp = await withTx(db, async (tx) => {
        await tx
          .prepare(
            'INSERT INTO upload_sessions(owner_id, upload_session_id, status, folder_id, replace_mode, total_bytes, created_at, updated_at, expires_at) VALUES(?,?,?,?,?,?,?,?,?)'
          )
          .bind(
            String(ctx.owner_id),
            String(upload_session_id),
            'CREATED',
            String(card.folder_id),
            Number(replace_mode),
            Number(total_bytes),
            Number(now),
            Number(now),
            Number(expires_at)
          )
          .run();

        for (const it of items) {
          await tx
            .prepare(
              'INSERT INTO upload_session_files(owner_id, upload_session_id, file_id, r2_key, filename, mime, size_bytes, sha256, created_at) VALUES(?,?,?,?,?,?,?,?,?)'
            )
            .bind(
              String(ctx.owner_id),
              String(upload_session_id),
              String(it.file_id),
              String(it.r2_key),
              String(it.filename),
              String(it.mime),
              Number(it.size_bytes),
              it.sha256 == null ? null : String(it.sha256),
              Number(now)
            )
            .run();
        }

        await writeAudit(tx, {
          owner_id: ctx.owner_id,
          actor_id: ctx.viewer_id,
          action: 'CREATE',
          entity_type: 'UPLOAD_SESSION',
          entity_id: String(upload_session_id),
          at: now,
          ip,
          user_agent,
          before: null,
          after: { upload_session_id, card_id: String(card_id), mode, total_bytes, expires_at, items: items.map((x) => ({ file_id: x.file_id, r2_key: x.r2_key, size_bytes: x.size_bytes })) },
        });

        const put_base = `/api/v1/assets/upload/put/${encodeURIComponent(upload_session_id)}`;
        return okJson(
          {
            upload_session_id,
            mode,
            total_bytes,
            expires_at,
            items: items.map((it) => ({
              file_id: it.file_id,
              r2_key: it.r2_key,
              put_url: `${put_base}/${encodeURIComponent(it.file_id)}`,
              put_headers: { 'content-type': it.mime },
            })),
          },
          201
        );
      });

      return resp;
    };

    return withIdempotency({ env, ctx, request, bodyRaw: raw, handler });
  }

  // -----------------------------
  // PUT /api/v1/assets/upload/put/:upload_session_id/:file_id  (binary body)
  // Stores bytes to R2 at immutable r2_key recorded in upload_session_files.
  // -----------------------------
  const mPut = pathname.match(/^\/api\/v1\/assets\/upload\/put\/([^\/]+)\/([^\/]+)$/);
  if (mPut && request.method === 'PUT') {
    const upload_session_id = decodeURIComponent(mPut[1]);
    const file_id = decodeURIComponent(mPut[2]);

    if (!isUlid(upload_session_id)) throw validation('upload_session_id must be ULID');
    if (!isUlid(file_id)) throw validation('file_id must be ULID');

    requireOwnerWrite(ctx);

    const session = await getSessionOrThrow(ctx.owner_id, upload_session_id);
    if (session.status !== 'CREATED') throw conflict(`session not writable: ${session.status}`);
    if (Number(session.expires_at || 0) <= now) throw conflict('session expired (pending job)');

    const file = await db
      .prepare('SELECT r2_key, mime, size_bytes FROM upload_session_files WHERE owner_id=? AND upload_session_id=? AND file_id=? LIMIT 1')
      .bind(String(ctx.owner_id), String(upload_session_id), String(file_id))
      .first();
    if (!file) throw notFound(request_id, { entity: 'upload_session_file', upload_session_id, file_id });

    const contentType = request.headers.get('content-type') || String(file.mime || 'application/octet-stream');

    await bucket.put(String(file.r2_key), request.body, {
      httpMetadata: { contentType },
      customMetadata: { owner_id: String(ctx.owner_id), upload_session_id: String(upload_session_id), file_id: String(file_id) },
    });

    await db
      .prepare('UPDATE upload_sessions SET updated_at=? WHERE owner_id=? AND upload_session_id=?')
      .bind(Number(now), String(ctx.owner_id), String(upload_session_id))
      .run();

    return okJson({ upload_session_id, file_id, uploaded: true, r2_key: String(file.r2_key) }, 200);
  }

  // -----------------------------
  // POST /api/v1/assets/upload/commit  { upload_session_id, card_id }
  // Commit == finalize: verify R2 objects exist; then create asset rows and mark session COMMITTED.
  // -----------------------------
  if ((pathname === '/api/v1/assets/upload/commit' || /^\/upload-sessions\/[0-9A-HJKMNP-TV-Z]{26}\/finalize$/.test(pathname)) && request.method === 'POST') {
    const { obj: body, raw } = await readJsonWithRaw(request);

    const handler = async () => {
      const upload_session_id = requireNonEmptyString(body?.upload_session_id, 'upload_session_id', 64);
      if (!isUlid(upload_session_id)) throw validation('upload_session_id must be ULID');
      const card_id = requireNonEmptyString(body?.card_id, 'card_id', 64);

      requireOwnerWrite(ctx);

      const session = await getSessionOrThrow(ctx.owner_id, upload_session_id);

      if (session.status === 'ACTIVE') {
        const rows = await db
          .prepare('SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at, deleted_at FROM assets WHERE owner_id=? AND card_id=? AND deleted_at IS NULL ORDER BY created_at ASC')
          .bind(String(ctx.owner_id), String(card_id))
          .all();
        return okJson({ committed: true, assets: (rows.results || []).map(assetRowToDto) }, 200);
      }

      if (session.status !== 'CREATED') throw conflict(`session not committable: ${session.status}`);
      if (Number(session.expires_at || 0) <= now) throw conflict('session expired (pending job)');

      const card = await getActiveCardOrThrow(ctx.owner_id, card_id);

      const files = await listSessionFiles(ctx.owner_id, upload_session_id);
      if (files.length === 0) throw validation('upload_session has no files');

      // Write-order invariant: verify R2 first, then write DB assets.
      const missing = [];
      for (const f of files) {
        const head = await bucket.head(String(f.r2_key));
        if (!head) missing.push({ file_id: String(f.file_id), r2_key: String(f.r2_key) });
        else {
          const declared = Number(f.size_bytes || 0);
          const actual = Number(head.size || 0);
          if (declared > 0 && actual > 0 && declared !== actual) {
            missing.push({ file_id: String(f.file_id), r2_key: String(f.r2_key), reason: 'SIZE_MISMATCH', declared, actual });
          }
        }
      }

      if (missing.length > 0) {
        // Explicit failure => mark CANCELED (no ACTIVE assets will be created)
        await db
          .prepare('UPDATE upload_sessions SET status=?, updated_at=?, canceled_at=? WHERE owner_id=? AND upload_session_id=? AND status=?')
          .bind('ABANDONED', Number(now), Number(now), Number(now), String(ctx.owner_id), String(upload_session_id), 'CREATED')
          .run();

        await writeAudit(db, {
          owner_id: ctx.owner_id,
          actor_id: ctx.viewer_id,
          action: 'DELETE',
          entity_type: 'UPLOAD_SESSION',
          entity_id: String(upload_session_id),
          at: now,
          ip,
          user_agent,
          before: { upload_session_id, status: 'CREATED' },
          after: { upload_session_id, status: 'ABANDONED', missing },
        });

        throw new HttpError('UPLOAD_BLOB_MISSING', 'one or more upload blobs are missing or invalid', 409, { missing });
      }

      return withTx(db, async (tx) => {
        if (Number(session.replace_mode || 0) === 1) {
          const existing = await tx
            .prepare('SELECT size_bytes FROM assets WHERE owner_id=? AND card_id=? AND deleted_at IS NULL')
            .bind(String(ctx.owner_id), String(card_id))
            .all();
          const ex = existing.results || [];
          const dec = ex.reduce((a, r) => a + Number(r.size_bytes || 0), 0);
          const delAt = now;
          const purgeAt = computePurgeAt(delAt);

          await tx
            .prepare('UPDATE assets SET deleted_at=?, purge_at=?, deleted_by=? WHERE owner_id=? AND card_id=? AND deleted_at IS NULL')
            .bind(Number(delAt), Number(purgeAt), String(ctx.viewer_id), String(ctx.owner_id), String(card_id))
            .run();

          if (dec > 0) {
            await tx
              .prepare('UPDATE folders SET used_bytes = CASE WHEN used_bytes >= ? THEN used_bytes - ? ELSE 0 END, updated_at=? WHERE owner_id=? AND folder_id=? AND deleted_at IS NULL')
              .bind(Number(dec), Number(dec), Number(now), String(ctx.owner_id), String(card.folder_id))
              .run();
          }
        }

        const created_assets = [];
        const inc = (files || []).reduce((a, f) => a + Number(f?.size_bytes || 0), 0);

        // Phase 3 quota gate (roadmap): used_bytes + delta <= quota_bytes
        // Note: in replace_mode we already subtracted existing bytes above, so we only need to check the add_bytes here.
        await assertQuotaCanAddBytes({
          db: tx,
          owner_id: ctx.owner_id,
          folder_id: card.folder_id,
          add_bytes: inc,
          default_quota_bytes: getDefaultQuotaBytes(env),
        });

        for (const f of files) {
          const asset_id = makeUlid(now + Math.floor(Math.random() * 10));
          const size = Number(f.size_bytes || 0);

          await tx
            .prepare('INSERT INTO assets(owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)')
            .bind(
              String(ctx.owner_id),
              String(asset_id),
              String(card_id),
              String(f.r2_key),
              String(f.filename || ''),
              String(f.mime || 'application/octet-stream'),
              Number(size),
              Number(now),
              Number(now)
            )
            .run();

          created_assets.push({
            owner_id: String(ctx.owner_id),
            asset_id,
            card_id: String(card_id),
            r2_key: String(f.r2_key),
            filename: String(f.filename || ''),
            mime: String(f.mime || 'application/octet-stream'),
            size_bytes: size,
            created_at: now,
            updated_at: now,
            deleted_at: null,
          });
        }

        if (inc > 0) {
          await tx
            .prepare('UPDATE folders SET used_bytes = used_bytes + ?, updated_at=? WHERE owner_id=? AND folder_id=? AND deleted_at IS NULL')
            .bind(Number(inc), Number(now), String(ctx.owner_id), String(card.folder_id))
            .run();
        }

        await tx
          .prepare('UPDATE upload_sessions SET status=?, updated_at=?, committed_at=? WHERE owner_id=? AND upload_session_id=? AND status=?')
          .bind('ACTIVE', Number(now), Number(now), String(ctx.owner_id), String(upload_session_id), 'CREATED')
          .run();

        await writeAudit(tx, {
          owner_id: ctx.owner_id,
          actor_id: ctx.viewer_id,
          action: 'UPDATE',
          entity_type: 'UPLOAD_SESSION',
          entity_id: String(upload_session_id),
          at: now,
          ip,
          user_agent,
          before: { upload_session_id, status: 'CREATED' },
          after: { upload_session_id, status: 'ACTIVE', created_assets: created_assets.map((a) => ({ asset_id: a.asset_id, r2_key: a.r2_key, size_bytes: a.size_bytes })) },
        });

        return okJson({ committed: true, upload_session_id, assets: created_assets }, 200);
      });
    };

    return withIdempotency({ env, ctx, request, bodyRaw: raw, handler });
  }

  // -----------------------------
  // POST /api/v1/assets/upload/cancel { upload_session_id }
  // -----------------------------
  if (pathname === '/api/v1/assets/upload/cancel' && request.method === 'POST') {
    const { obj: body, raw } = await readJsonWithRaw(request);

    const handler = async () => {
      const upload_session_id = requireNonEmptyString(body?.upload_session_id, 'upload_session_id', 64);
      if (!isUlid(upload_session_id)) throw validation('upload_session_id must be ULID');

      requireOwnerWrite(ctx);

      const session = await getSessionOrThrow(ctx.owner_id, upload_session_id);
      if (session.status === 'ACTIVE') throw conflict('cannot cancel committed session');
      if (session.status === 'ABANDONED') return okJson({ canceled: true, upload_session_id }, 200);

      await db
        .prepare('UPDATE upload_sessions SET status=?, updated_at=?, canceled_at=? WHERE owner_id=? AND upload_session_id=? AND status=?')
        .bind('ABANDONED', Number(now), Number(now), Number(now), String(ctx.owner_id), String(upload_session_id), 'CREATED')
        .run();

      await writeAudit(db, {
        owner_id: ctx.owner_id,
        actor_id: ctx.viewer_id,
        action: 'DELETE',
        entity_type: 'UPLOAD_SESSION',
        entity_id: String(upload_session_id),
        at: now,
        ip,
        user_agent,
        before: { upload_session_id, status: String(session.status) },
        after: { upload_session_id, status: 'ABANDONED' },
      });

      return okJson({ canceled: true, upload_session_id }, 200);
    };

    return withIdempotency({ env, ctx, request, bodyRaw: raw, handler });
  }

  // -----------------------------
  // GET /api/v1/assets/:owner_id/:asset_id/content
  // Streams R2 object if permitted. Enforces collection policy_json.allow_download when accessed via share.
  // -----------------------------
  const mContent = pathname.match(/^\/api\/v1\/assets\/([^\/]+)\/([^\/]+)\/content$/);
  if (mContent && request.method === 'GET') {
    const owner_id = decodeURIComponent(mContent[1]);
    const asset_id = decodeURIComponent(mContent[2]);
    if (!isUlid(asset_id)) throw validation('asset_id must be ULID');

    const asset = await db
      .prepare('SELECT owner_id, asset_id, card_id, r2_key, filename, mime, size_bytes, deleted_at FROM assets WHERE owner_id=? AND asset_id=? LIMIT 1')
      .bind(String(owner_id), String(asset_id))
      .first();
    if (!asset) throw notFound(request_id, { entity: 'asset', asset_id });
    if (asset.deleted_at != null) throw notFound(request_id, { entity: 'asset', asset_id });

    if (String(ctx.viewer_id) !== String(owner_id)) {
      const row = await db
        .prepare(
          `SELECT c.policy_json AS policy_json
             FROM cards k
             JOIN mounts m ON m.owner_id = k.owner_id AND m.folder_id = k.folder_id AND m.deleted_at IS NULL
             JOIN collection_members cm ON cm.owner_id = m.owner_id AND cm.collection_id = m.collection_id AND cm.member_id = ? AND cm.deleted_at IS NULL
             JOIN collections c ON c.owner_id = m.owner_id AND c.collection_id = m.collection_id AND c.deleted_at IS NULL
            WHERE k.owner_id = ? AND k.card_id = ? AND k.deleted_at IS NULL
            LIMIT 1`
        )
        .bind(String(ctx.viewer_id), String(owner_id), String(asset.card_id))
        .first();
      if (!row) throw forbidden('download not permitted');
      const policy = parsePolicyJsonForRead(row.policy_json);
      if (policy.allow_download !== true) throw forbidden('downloads disabled by collection policy');
    }

    const obj = await bucket.get(String(asset.r2_key));
    if (!obj) throw notFound(request_id, { entity: 'r2_object', r2_key: String(asset.r2_key) });

    const headers = new Headers();
    headers.set('cache-control', 'no-store');
    headers.set('content-type', String(asset.mime || 'application/octet-stream'));
    if (asset.size_bytes != null) headers.set('content-length', String(asset.size_bytes));
    headers.set('content-disposition', `inline; filename="${String(asset.filename || 'file').replace(/"/g, '')}"`);
    return new Response(obj.body, { status: 200, headers });
  }

  throw notFound(request_id, { entity: 'route', pathname, method: request.method });
}

async function requireCollectionAdmin({ db, owner_id, collection_id, viewer_id, request_id }) {
  const role = await getCollectionMemberRole({ db, owner_id, collection_id, member_id: viewer_id });
  if (!role) throw notFound(request_id, { entity: 'collection', collection_id });
  if (!['owner', 'admin'].includes(String(role))) throw forbidden('collection admin required');
  return String(role);
}

async function apiCollectionMounts({ request, env, request_id, ctx, owner_id, collection_id }) {
  const perms = await resolveCollectionPerms({ db: env.DB, owner_id, collection_id, viewer_id: ctx.viewer_id });
  const url = new URL(request.url);

  const ip = getClientIp(request);
  const user_agent = getUserAgent(request);

  if (request.method === 'GET') {
    const data = await withTx(env.DB, async (db) => {
      requireCollectionManageMounts(perms);
      const rows = await db
        .prepare(
          `SELECT m.owner_id, m.collection_id, m.folder_id, m.access, m.created_at, m.updated_at,
                  f.name as folder_name
           FROM mounts m
           LEFT JOIN folders f ON f.owner_id=m.owner_id AND f.folder_id=m.folder_id
           WHERE m.owner_id=? AND m.collection_id=? AND m.deleted_at IS NULL
           ORDER BY m.created_at ASC, m.folder_id ASC`
        )
        .bind(String(owner_id), String(collection_id))
        .all();

      const items = (rows.results || []).map((r) => ({
        owner_id: String(r.owner_id),
        collection_id: String(r.collection_id),
        folder_id: String(r.folder_id),
        access: String(r.access),
        folder_name: String(r.folder_name || ''),
        created_at: Number(r.created_at || 0),
        updated_at: Number(r.updated_at || 0),
      }));

      return { items, next_cursor: null };
    });

    return okJson(data);
  }

  if (request.method === 'POST') {
    const body = await readJson(request);
    const folder_id = requireNonEmptyString(body?.folder_id, 'folder_id', 64);
    const access = String(body?.access || 'read');
    if (!['read', 'write'].includes(access)) throw validation('access must be read|write');

    const out = await withTx(env.DB, async (db) => {
      requireCollectionManageMounts(perms);

      const folder = await db
        .prepare('SELECT folder_id, deleted_at FROM folders WHERE owner_id=? AND folder_id=? LIMIT 1')
        .bind(String(owner_id), String(folder_id))
        .first();
      if (!folder) throw notFound(request_id, { entity: 'folder', folder_id });
      if (folder.deleted_at != null) throw conflict('folder is in trash');

      const now2 = Date.now();
      const existing = await db
        .prepare('SELECT owner_id, collection_id, folder_id, access, deleted_at FROM mounts WHERE owner_id=? AND collection_id=? AND folder_id=? LIMIT 1')
        .bind(String(owner_id), String(collection_id), String(folder_id))
        .first();

      if (existing && existing.deleted_at == null) throw conflict('mount already exists');

      if (existing && existing.deleted_at != null) {
        await db
          .prepare('UPDATE mounts SET access=?, updated_at=?, deleted_at=NULL, purge_at=NULL, deleted_by=NULL WHERE owner_id=? AND collection_id=? AND folder_id=?')
          .bind(access, now2, String(owner_id), String(collection_id), String(folder_id))
          .run();
      } else {
        await db
          .prepare(
            'INSERT INTO mounts(owner_id, collection_id, folder_id, access, created_at, updated_at, deleted_at, purge_at, deleted_by) VALUES(?,?,?,?,?,?,?,?,?)'
          )
          .bind(String(owner_id), String(collection_id), String(folder_id), access, now2, now2, null, null, null)
          .run();
      }

      await writeAudit(db, {
        owner_id,
        actor_id: ctx.viewer_id,
        action: 'CREATE_MOUNT',
        entity_type: 'mount',
        entity_id: `${collection_id}:${folder_id}`,
        at: now2,
        ip,
        user_agent,
        before: existing ? { ...existing } : null,
        after: { owner_id, collection_id, folder_id, access },
      });

      return { owner_id, collection_id, folder_id, access };
    });

    return okJson({ mount: out }, 201);
  }

  throw notFound(request_id, { path: url.pathname });
}

async function apiCollectionMount({ request, env, request_id, ctx, owner_id, collection_id, folder_id }) {
  const perms = await resolveCollectionPerms({ db: env.DB, owner_id, collection_id, viewer_id: ctx.viewer_id });

  const ip = getClientIp(request);
  const user_agent = getUserAgent(request);

  if (request.method === 'PATCH') {
    const body = await readJson(request);
    const access = String(body?.access || '');
    if (!['read', 'write'].includes(access)) throw validation('access must be read|write');

    const out = await withTx(env.DB, async (db) => {
      requireCollectionManageMounts(perms);
      const now = Date.now();

      const existing = await db
        .prepare('SELECT owner_id, collection_id, folder_id, access, deleted_at FROM mounts WHERE owner_id=? AND collection_id=? AND folder_id=? LIMIT 1')
        .bind(String(owner_id), String(collection_id), String(folder_id))
        .first();
      if (!existing || existing.deleted_at != null) throw notFound(request_id, { entity: 'mount', folder_id });

      await db
        .prepare('UPDATE mounts SET access=?, updated_at=? WHERE owner_id=? AND collection_id=? AND folder_id=?')
        .bind(access, now, String(owner_id), String(collection_id), String(folder_id))
        .run();

      await writeAudit(db, {
        owner_id,
        actor_id: ctx.viewer_id,
        action: 'UPDATE_MOUNT',
        entity_type: 'mount',
        entity_id: `${collection_id}:${folder_id}`,
        at: now,
        ip,
        user_agent,
        before: { ...existing },
        after: { ...existing, access },
      });

      return { owner_id, collection_id, folder_id, access };
    });

    return okJson({ mount: out });
  }

  if (request.method === 'DELETE') {
    const out = await withTx(env.DB, async (db) => {
      requireCollectionManageMounts(perms);
      const now = Date.now();

      const existing = await db
        .prepare('SELECT owner_id, collection_id, folder_id, access, deleted_at FROM mounts WHERE owner_id=? AND collection_id=? AND folder_id=? LIMIT 1')
        .bind(String(owner_id), String(collection_id), String(folder_id))
        .first();
      if (!existing || existing.deleted_at != null) throw notFound(request_id, { entity: 'mount', folder_id });

      await db
        .prepare('UPDATE mounts SET deleted_at=?, purge_at=?, deleted_by=? WHERE owner_id=? AND collection_id=? AND folder_id=?')
        .bind(now, now + PURGE_RETENTION_MS, String(ctx.viewer_id), String(owner_id), String(collection_id), String(folder_id))
        .run();

      await writeAudit(db, {
        owner_id,
        actor_id: ctx.viewer_id,
        action: 'DELETE_MOUNT',
        entity_type: 'mount',
        entity_id: `${collection_id}:${folder_id}`,
        at: now,
        ip,
        user_agent,
        before: { ...existing },
        after: null,
      });

      return { owner_id, collection_id, folder_id, deleted: true };
    });

    return okJson({ mount: out });
  }

  throw notFound(request_id, { path: new URL(request.url).pathname });
}

// LIFF session: retained as compatibility shim; canonical is /api/v1/assets/upload/*
async function handleLiffSession(request, env, request_id) {
  const url = new URL(request.url);
  return errJson(
    { code: 'DEPRECATED', message: 'Use /api/v1/assets/upload/* (Bearer session_token) instead of /liff/session', status: 410, details: { path: url.pathname } },
    410
  );
}



async function rewriteUploadRoutes(request, url) {
  const pathname = url.pathname;
  const method = request.method.toUpperCase();

  if (method !== 'POST') return { request, url };

  // POST /upload-sessions -> legacy init
  if (pathname === '/upload-sessions') {
    const newUrl = new URL(url.toString());
    newUrl.pathname = '/api/v1/assets/upload/init';
    return { request: new Request(newUrl.toString(), request), url: newUrl };
  }

  const mFiles = pathname.match(/^\/upload-sessions\/([0-9A-HJKMNP-TV-Z]{26})\/files$/);
  if (mFiles) {
    const upload_session_id = mFiles[1];
    const bodyText = await request.text();
    let obj = {};
    try { obj = bodyText ? JSON.parse(bodyText) : {}; } catch { obj = {}; }
    obj.upload_session_id = upload_session_id;
    const newUrl = new URL(url.toString());
    newUrl.pathname = '/api/v1/assets/upload/put';
    const newReq = new Request(newUrl.toString(), {
      method: 'POST',
      headers: request.headers,
      body: JSON.stringify(obj),
    });
    return { request: newReq, url: newUrl };
  }

  const mFinalize = pathname.match(/^\/upload-sessions\/([0-9A-HJKMNP-TV-Z]{26})\/finalize$/);
  if (mFinalize) {
    const upload_session_id = mFinalize[1];
    const bodyText = await request.text();
    let obj = {};
    try { obj = bodyText ? JSON.parse(bodyText) : {}; } catch { obj = {}; }
    obj.upload_session_id = upload_session_id;
    const newUrl = new URL(url.toString());
    newUrl.pathname = '/api/v1/assets/upload/commit';
    const newReq = new Request(newUrl.toString(), {
      method: 'POST',
      headers: request.headers,
      body: JSON.stringify(obj),
    });
    return { request: newReq, url: newUrl };
  }

  return { request, url };
}


// -----------------------------
// Main handler
// -----------------------------
export default {
  async fetch(request, env, ctx) {
    const start = Date.now();
    let url = new URL(request.url);
    const request_id = getRequestId(request);

    // Route normalization (Implementation Plan v7.33):
    // Support new minimal route map by rewriting to legacy internal handlers.
    // - POST /upload-sessions                     -> POST /api/v1/assets/upload/init
    // - POST /upload-sessions/:id/files           -> POST /api/v1/assets/upload/put   (inject upload_session_id)
    // - POST /upload-sessions/:id/finalize        -> POST /api/v1/assets/upload/commit (inject upload_session_id)
    // This keeps the worker backwards-compatible while meeting the production route map.
    ({ request, url } = await rewriteUploadRoutes(request, url));

    logEvent('request.start', {
      request_id,
      method: request.method,
      path: url.pathname,
      query: url.search ? url.search.slice(1) : '',
    });

    const wrap = (r) => withStandardHeaders(r, request_id);

    try {
      await requireContractVersion(request);
      // LIFF SPA shell
      if (request.method === 'GET' && isLiffAppPath(url.pathname)) {
        const res = htmlResponse(liffShellHtml(), 200);
        logEvent('request.end', {
          request_id,
          method: request.method,
          path: url.pathname,
          status: 200,
          latency_ms: Date.now() - start,
        });
        return wrap(res);
      }

      // LIFF Upload Session FSM
      if (url.pathname === '/liff/session' || url.pathname.startsWith('/liff/session/')) {
        const res = await handleLiffSession(request, env, request_id);
        logEvent('request.end', {
          request_id,
          method: request.method,
          path: url.pathname,
          status: res.status,
          latency_ms: Date.now() - start,
        });
        return wrap(res);
      }

      // API v1
      if (url.pathname === '/api/v1' || url.pathname.startsWith('/api/v1/')) {
        const res = await handleApiV1(request, env, request_id);
        logEvent('request.end', {
          request_id,
          method: request.method,
          path: url.pathname,
          status: res.status,
          latency_ms: Date.now() - start,
        });
        return wrap(res);
      }

      // Phase 1 aliases (requested wording)
      if (url.pathname === '/api/owner' || url.pathname.startsWith('/api/owner/')) {
        const res = await handleApiOwner(request, env, request_id);
        logEvent('request.end', {
          request_id,
          method: request.method,
          path: url.pathname,
          status: res.status,
          latency_ms: Date.now() - start,
        });
        return wrap(res);
      }

      // /api/collection/* deprecated: use /api/v1/* only.


      const out = errJson(
        { code: 'NOT_FOUND', message: 'not found', details: { path: url.pathname, method: request.method }, request_id },
        404
      );

      logEvent('request.end', {
        request_id,
        method: request.method,
        path: url.pathname,
        status: out.status,
        latency_ms: Date.now() - start,
      });

      return wrap(out);
    } catch (e) {
      const err = normalizeError(e, request_id);
      const out = errJson({ code: err.code, message: err.message, details: err.details, request_id }, err.status);

      logEvent('request.error', {
        request_id,
        method: request.method,
        path: url.pathname,
        status: out.status,
        latency_ms: Date.now() - start,
        err_code: err.code,
        err_message: err.message,
      });

      return wrap(out);
    }

  },

  // Phase 3 (Roadmap): cleanup job for upload_sessions
  // - Mark INITIATED sessions past expires_at as EXPIRED (FSM: EXPIRED only by job)
  // - Purge R2 objects + hard-delete session rows for CANCELED/EXPIRED beyond retention window
  async scheduled(event, env, ctx) {
    const db = env.DB;
    const bucket = detectR2Bucket(env);
    const now = Date.now();
    const retention_ms = 48 * 60 * 60 * 1000; // 48h retention for canceled/expired sessions (Phase 3 pragmatic default)

    try {
      // 1) Expire sessions (limit to avoid long runs)
      const toExpire = await db
        .prepare(
          "SELECT owner_id, upload_session_id FROM upload_sessions WHERE status='CREATED' AND expires_at <= ? ORDER BY expires_at ASC LIMIT 50"
        )
        .bind(Number(now))
        .all();

      for (const s of (toExpire.results || [])) {
        await db
          .prepare("UPDATE upload_sessions SET status='ABANDONED', updated_at=? WHERE owner_id=? AND upload_session_id=? AND status='CREATED'")
          .bind(Number(now), String(s.owner_id), String(s.upload_session_id))
          .run();

        await writeAudit(db, {
          owner_id: String(s.owner_id),
          actor_id: 'system',
          action: 'UPDATE',
          entity_type: 'UPLOAD_SESSION',
          entity_id: String(s.upload_session_id),
          at: now,
          ip: null,
          user_agent: 'scheduled',
          before: { upload_session_id: String(s.upload_session_id), status: 'CREATED' },
          after: { upload_session_id: String(s.upload_session_id), status: 'ABANDONED' },
        });
      }

      // 2) Purge old canceled/expired sessions (hard-delete) + delete R2 blobs
      const cutoff = now - retention_ms;
      const toPurge = await db
        .prepare(
          "SELECT owner_id, upload_session_id FROM upload_sessions WHERE status IN ('ABANDONED','ABANDONED') AND updated_at <= ? ORDER BY updated_at ASC LIMIT 50"
        )
        .bind(Number(cutoff))
        .all();

      for (const s of (toPurge.results || [])) {
        if (bucket) {
          const files = await db
            .prepare('SELECT r2_key FROM upload_session_files WHERE owner_id=? AND upload_session_id=?')
            .bind(String(s.owner_id), String(s.upload_session_id))
            .all();
          for (const f of (files.results || [])) {
            try {
              await bucket.delete(String(f.r2_key));
            } catch (e) {
              // ignore per-object errors to keep cleanup progressing
              console.log(JSON.stringify({ event: 'cleanup.r2.delete_failed', r2_key: String(f.r2_key), err: String(e) }));
            }
          }
        }

        // Hard delete session row (CASCADE removes upload_session_files)
        await db
          .prepare('DELETE FROM upload_sessions WHERE owner_id=? AND upload_session_id=?')
          .bind(String(s.owner_id), String(s.upload_session_id))
          .run();

        await writeAudit(db, {
          owner_id: String(s.owner_id),
          actor_id: 'system',
          action: 'DELETE',
          entity_type: 'UPLOAD_SESSION',
          entity_id: String(s.upload_session_id),
          at: now,
          ip: null,
          user_agent: 'scheduled',
          before: { upload_session_id: String(s.upload_session_id), status: 'CANCELED|EXPIRED' },
          after: null,
        });
      }
    } catch (e) {
      console.log(JSON.stringify({ event: 'scheduled.error', err: String(e) }));
      throw e;
    }
  }
};
