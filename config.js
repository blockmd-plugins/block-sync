/**
 * Configuration defaults, multi-notebook normalization, legacy field migration,
 * host.storage.* persistence, and host.secrets.* credential lifecycle + cleanup
 * compensation for block-sync. Pure ES2023, QuickJS-NG compatible.
 */

import { tr, normalizeLog } from './i18n.js';
import {
  resolveCallHost,
  sha256Text,
  textToBytes,
  normAbsPath,
  posixBasename,
  isSafeRelPath,
  isSafeRelMd,
  syncDirKey,
  sanitizeUrlForDisplay,
  DEFAULT_MAX_FILE_SIZE_MB,
  normalizeMaxFileSizeMb,
} from './utils.js';

export const VALID_PROTOCOLS = Object.freeze(['local_mirror', 'webdav', 'git']);
export const PROTOCOL_ENABLED_KEYS = Object.freeze({
  local_mirror: 'local_mirror_enabled',
  webdav: 'webdav_enabled',
  git: 'git_enabled',
});
export const VALID_CONFLICT_POLICIES = Object.freeze(['keep_both', 'remote_first', 'local_first']);
export const VALID_GIT_AUTHS = Object.freeze(['ssh', 'token']);
export const VALID_SYNC_INTERVALS = Object.freeze(['5', '30', '60']);
export const SYNC_INTERVAL_EVENT = 'plugin.sync_interval';
export const DELETE_GUARD_THRESHOLD = 5;
export const MAX_LOG_ENTRIES = 100;
export const MAX_HOST_LOG_QUEUE = 500;
export const WEBDAV_TRASH_DIR = '.block-sync-trash';
export const LAYOUTS_META_KEY = 'notebook_layouts';
export const INITIALIZED_META_KEY = 'initialized_targets';
export const TOMBSTONES_META_KEY = '__tombstones__';
export const MAX_TOMBSTONES_PER_NB = 4000;
export const MAX_STORED_CONFIRM_SAMPLES = 30;
export const MAX_WEBDAV_DIRS = 2000;
export const CREDENTIAL_FIELDS = Object.freeze(['git_token', 'webdav_pass']);
export const CREDENTIAL_MAX_BYTES = 1536;
export const CREDENTIAL_REF_RE = /^sync\.(git_token|webdav_pass)\.[0-9a-f]{32}$/;

export const DEFAULT_CONFIG = Object.freeze({
  selected_notebooks: [],
  protocol: 'local_mirror',
  local_mirror_enabled: false,
  webdav_enabled: false,
  git_enabled: false,
  mirror_dir: '',
  sync_scope: 'all',
  webdav_url: '',
  webdav_dir: '/BlockNotes',
  webdav_user: '',
  webdav_pass: '',
  git_remote: '',
  git_branch: 'main',
  git_auth: 'ssh',
  git_token: '',
  auto_sync: true,
  sync_interval: '5',
  system_notifications: true,
  sync_assets: true,
  max_file_size_mb: DEFAULT_MAX_FILE_SIZE_MB,
  ignore_patterns: '',
  conflict_policy: 'keep_both',
  delete_guard: true,
});

export function cloneDefaultConfig() {
  return {
    ...DEFAULT_CONFIG,
    selected_notebooks: [],
  };
}

// ============================================================================
// Storage RPC Wrappers (host.storage.*)
// ============================================================================

export function storageGet(callHost, key = '') {
  const rpc = resolveCallHost(callHost);
  const res = rpc('host.storage.get', key ? { key: String(key) } : {});
  return res && typeof res === 'object' ? res : { found: false, value: null };
}

export function storageSet(callHost, key, value) {
  const rpc = resolveCallHost(callHost);
  return rpc('host.storage.set', { key: String(key), value });
}

export function storageSetMany(callHost, values) {
  const rpc = resolveCallHost(callHost);
  const entries = Object.entries(values || {});
  if (entries.length === 0) {
    return { ok: true };
  }
  const CHUNK_SIZE = 64;
  for (let i = 0; i < entries.length; i += CHUNK_SIZE) {
    const chunk = Object.fromEntries(entries.slice(i, i + CHUNK_SIZE));
    rpc('host.storage.set_many', { values: chunk });
  }
  return { ok: true };
}

// ============================================================================
// Secrets RPC Wrappers (host.secrets.*)
// ============================================================================

let refCounter = 0;

export function generateCredentialRef(field) {
  if (!CREDENTIAL_FIELDS.includes(field)) {
    throw new Error(`Unsupported credential field: ${field}`);
  }
  const bytes = new Uint8Array(16);
  if (typeof globalThis.crypto !== 'undefined' && typeof globalThis.crypto.getRandomValues === 'function') {
    globalThis.crypto.getRandomValues(bytes);
  } else {
    refCounter = (refCounter + 1) >>> 0;
    let seed = (Date.now() ^ (refCounter * 0x9e3779b9)) >>> 0;
    for (let i = 0; i < 16; i += 1) {
      const r = Math.floor(Math.random() * 256);
      seed = (seed * 1664525 + 1013904223) >>> 0;
      bytes[i] = (r ^ (seed >>> 24)) & 0xff;
    }
  }
  let hex = '';
  for (let i = 0; i < bytes.length; i += 1) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return `sync.${field}.${hex}`;
}

export function credentialFits(value) {
  if (typeof value !== 'string') return false;
  if (value.includes('\x00')) return false;
  return textToBytes(value).length <= CREDENTIAL_MAX_BYTES;
}

export function credentialTarget(config, field) {
  const cfg = config || {};
  if (field === 'webdav_pass') {
    return `${String(cfg.webdav_url || '').replace(/\/+$/, '')}\u0000${String(cfg.webdav_user || '')}`;
  }
  return String(cfg.git_remote || '').replace(/\/+$/, '');
}

export function secretGet(callHost, key) {
  const rpc = resolveCallHost(callHost);
  const res = rpc('host.secrets.get', { key: String(key) });
  return res && typeof res === 'object' ? res : { ok: false, found: false };
}

export function secretSet(callHost, key, value) {
  const rpc = resolveCallHost(callHost);
  rpc('host.secrets.set', { key: String(key), value: String(value) });
  const check = secretGet(rpc, key);
  if (!check.found || check.value !== value) {
    throw new Error('system credential verification failed');
  }
  return { ok: true };
}

export function secretDelete(callHost, key) {
  const rpc = resolveCallHost(callHost);
  return rpc('host.secrets.delete', { key: String(key) });
}

export function resolveCredentials(callHost, config, locale = 'zh') {
  const cfg = config || {};
  let field = null;
  if (cfg.protocol === 'webdav') {
    field = 'webdav_pass';
  } else if (cfg.protocol === 'git' && cfg.git_auth === 'token') {
    field = 'git_token';
  }
  if (!field) {
    return cfg;
  }
  const refs = cfg.credential_refs && typeof cfg.credential_refs === 'object' ? cfg.credential_refs : {};
  const ref = refs[field];
  if (!ref || cfg[field]) {
    return cfg;
  }
  let value = null;
  try {
    const stored = secretGet(callHost, ref);
    value = stored && stored.found ? stored.value : null;
  } catch (_err) {
    value = null;
  }
  if (typeof value !== 'string' || !value) {
    throw new Error(
      tr(
        locale,
        '无法读取系统凭据，请解锁或重新填写同步凭据',
        'Could not read the system credential. Unlock the credential store or enter it again.'
      )
    );
  }
  return { ...cfg, [field]: value };
}

// ============================================================================
// Path & Target Resolution Helpers
// ============================================================================

export function downloadsRoot(downloadsDir = '', homeDir = '') {
  const raw = String(downloadsDir || '').trim() || '~/Downloads';
  return normAbsPath(raw, homeDir);
}

export function resolveMirrorDir(cfg, downloadsDir = '', homeDir = '') {
  const raw = String((cfg && cfg.mirror_dir) || '');
  if (!raw) return '';
  const expanded = raw.startsWith('~') ? normAbsPath(raw, homeDir) : raw.replace(/\\/g, '/');
  if (expanded.startsWith('/') || /^[a-zA-Z]:\//.test(expanded)) {
    return normAbsPath(expanded, homeDir);
  }
  const dl = downloadsRoot(downloadsDir, homeDir);
  const combined = dl ? `${dl.replace(/\/+$/, '')}/${expanded}` : expanded;
  return normAbsPath(combined, homeDir);
}

export function resolveWebdavDir(cfg) {
  return String((cfg && cfg.webdav_dir) || '').trim() || '/BlockNotes';
}

export function cfgForProtocol(cfg, protocol) {
  return { ...(cfg || cloneDefaultConfig()), protocol };
}

export function protocolHasInput(cfg, protocol, downloadsDir = '', homeDir = '') {
  const c = cfg || {};
  if (protocol === 'local_mirror') {
    return Boolean(resolveMirrorDir(c, downloadsDir, homeDir));
  }
  if (protocol === 'webdav') {
    return Boolean(String(c.webdav_url || '').trim());
  }
  if (protocol === 'git') {
    return Boolean(String(c.git_remote || '').trim());
  }
  return false;
}

export function protocolEnabled(cfg, protocol) {
  const key = PROTOCOL_ENABLED_KEYS[protocol];
  return key ? Boolean(cfg && cfg[key]) : false;
}

export function configMatchesSaved(a, b) {
  if (a == null || b == null) return a === b;
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  keys.delete('protocol');
  for (const k of keys) {
    const va = a[k];
    const vb = b[k];
    if (va === vb) continue;
    if (typeof va === 'object' && typeof vb === 'object' && JSON.stringify(va) === JSON.stringify(vb)) {
      continue;
    }
    return false;
  }
  return true;
}

export function changedProtocols(oldCfg, newCfg) {
  const oldC = oldCfg || {};
  const newC = newCfg || {};
  const sharedKeys = ['selected_notebooks', 'conflict_policy', 'sync_scope', 'sync_assets', 'max_file_size_mb', 'ignore_patterns', 'delete_guard'];
  if (sharedKeys.some((k) => JSON.stringify(oldC[k]) !== JSON.stringify(newC[k]))) {
    return new Set(VALID_PROTOCOLS);
  }
  const changed = new Set();
  if (oldC.mirror_dir !== newC.mirror_dir || oldC.local_mirror_enabled !== newC.local_mirror_enabled) {
    changed.add('local_mirror');
  }
  const oldRefs = oldC.credential_refs || {};
  const newRefs = newC.credential_refs || {};
  if (
    ['webdav_url', 'webdav_dir', 'webdav_user', 'webdav_pass', 'webdav_enabled'].some((k) => oldC[k] !== newC[k]) ||
    oldRefs.webdav_pass !== newRefs.webdav_pass
  ) {
    changed.add('webdav');
  }
  if (
    ['git_remote', 'git_branch', 'git_auth', 'git_token', 'git_enabled'].some((k) => oldC[k] !== newC[k]) ||
    oldRefs.git_token !== newRefs.git_token
  ) {
    changed.add('git');
  }
  return changed;
}

// ============================================================================
// Configuration Normalization & Legacy Migration
// ============================================================================

export function normalizeConfig(
  raw,
  {
    base = null,
    supportsSystem = true,
    downloadsDir = '',
    homeDir = '',
  } = {}
) {
  const srcBase = base || cloneDefaultConfig();
  const merged = {
    ...cloneDefaultConfig(),
    ...srcBase,
  };
  if (Array.isArray(srcBase.selected_notebooks)) {
    merged.selected_notebooks = srcBase.selected_notebooks
      .map((p) => normAbsPath(p, homeDir))
      .filter(Boolean);
  }

  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return merged;
  }

  if (Array.isArray(raw.selected_notebooks)) {
    const dedup = [];
    const seen = new Set();
    for (const item of raw.selected_notebooks) {
      const norm = normAbsPath(item, homeDir);
      if (norm && !seen.has(norm)) {
        seen.add(norm);
        dedup.push(norm);
      }
    }
    merged.selected_notebooks = dedup;
  }

  const protocol = raw.protocol ?? merged.protocol;
  if (VALID_PROTOCOLS.includes(protocol)) {
    merged.protocol = protocol;
  }

  const strFields = [
    'mirror_dir',
    'sync_scope',
    'webdav_url',
    'webdav_dir',
    'webdav_user',
    'webdav_pass',
    'git_remote',
    'git_branch',
    'git_token',
  ];
  for (const key of strFields) {
    if (Object.hasOwn(raw, key) && raw[key] !== null && raw[key] !== undefined) {
      const val = String(raw[key]);
      if (supportsSystem && CREDENTIAL_FIELDS.includes(key) && !val) {
        continue;
      }
      merged[key] = ['mirror_dir', 'webdav_pass', 'git_token'].includes(key) ? val : val.trim();
    }
  }

  // Migrate legacy presets once.
  const mirrorPreset = raw.mirror_preset;
  const dlRoot = downloadsRoot(downloadsDir, homeDir);
  if (mirrorPreset === 'downloads') {
    merged.mirror_dir = normAbsPath(`${dlRoot}/Block-Sync`, homeDir);
  } else if (mirrorPreset === 'documents') {
    merged.mirror_dir = normAbsPath('~/Documents/Block-Sync', homeDir);
  } else if (mirrorPreset === 'custom' && !merged.mirror_dir) {
    merged.mirror_dir = normAbsPath(`${dlRoot}/Block-Sync`, homeDir);
  }

  const webdavDirPreset = raw.webdav_dir_preset;
  if (['/BlockNotes', '/Notes', '/Markdown'].includes(webdavDirPreset)) {
    merged.webdav_dir = webdavDirPreset;
  }
  const gitBranchPreset = raw.git_branch_preset;
  if (['main', 'master'].includes(gitBranchPreset)) {
    merged.git_branch = gitBranchPreset;
  }

  if (!merged.sync_scope) {
    merged.sync_scope = 'all';
  }

  // Backward compatibility with legacy target_path / endpoint_url / secret_token keys.
  const legacyTarget = String(raw.target_path || raw.endpoint_url || '').trim();
  if (legacyTarget) {
    if (merged.protocol === 'local_mirror' && !merged.mirror_dir) {
      merged.mirror_dir = legacyTarget;
    } else if (merged.protocol === 'webdav' && !merged.webdav_url) {
      merged.webdav_url = legacyTarget;
    } else if (merged.protocol === 'git' && !merged.git_remote) {
      merged.git_remote = legacyTarget;
    }
  }

  const legacySecret = raw.secret_token !== undefined && raw.secret_token !== null ? String(raw.secret_token) : '';
  if (legacySecret) {
    if (merged.protocol === 'webdav' && !merged.webdav_pass) {
      const colonIdx = legacySecret.indexOf(':');
      if (colonIdx >= 0 && !merged.webdav_user) {
        merged.webdav_user = legacySecret.slice(0, colonIdx).trim();
        merged.webdav_pass = legacySecret.slice(colonIdx + 1);
      } else {
        merged.webdav_pass = legacySecret;
      }
    } else if (merged.protocol === 'git' && !merged.git_token) {
      merged.git_token = legacySecret;
    }
  }

  if (!merged.webdav_dir) {
    merged.webdav_dir = '/BlockNotes';
  }
  if (!merged.git_branch) {
    merged.git_branch = 'main';
  }

  const gitAuth = raw.git_auth ?? merged.git_auth;
  if (VALID_GIT_AUTHS.includes(gitAuth)) {
    merged.git_auth = gitAuth;
  }

  const interval = String(raw.sync_interval ?? merged.sync_interval ?? '').trim();
  merged.sync_interval = VALID_SYNC_INTERVALS.includes(interval) ? interval : DEFAULT_CONFIG.sync_interval;
  merged.max_file_size_mb = normalizeMaxFileSizeMb(Object.hasOwn(raw, 'max_file_size_mb') ? raw.max_file_size_mb : merged.max_file_size_mb);
  const ignorePatterns = Object.hasOwn(raw, 'ignore_patterns') ? raw.ignore_patterns : merged.ignore_patterns;
  merged.ignore_patterns = typeof ignorePatterns === 'string' ? ignorePatterns.replace(/\r\n|\\n/g, '\n') : '';

  for (const boolKey of [
    'auto_sync',
    'sync_assets',
    'delete_guard',
    'system_notifications',
    'local_mirror_enabled',
    'webdav_enabled',
    'git_enabled',
  ]) {
    if (Object.hasOwn(raw, boolKey)) {
      merged[boolKey] = Boolean(raw[boolKey]);
    }
  }

  const policy = raw.conflict_policy ?? merged.conflict_policy;
  if (VALID_CONFLICT_POLICIES.includes(policy)) {
    merged.conflict_policy = policy;
  }

  merged.mirror_dir = resolveMirrorDir(merged, downloadsDir, homeDir);

  if (base === null || base === DEFAULT_CONFIG) {
    for (const [proto, enabledKey] of Object.entries(PROTOCOL_ENABLED_KEYS)) {
      if (!Object.hasOwn(raw, enabledKey)) {
        merged[enabledKey] = protocolHasInput(merged, proto, downloadsDir, homeDir);
      }
    }
  }

  if (supportsSystem && base !== null && base !== DEFAULT_CONFIG) {
    const refs = { ...(merged.credential_refs || {}) };
    for (const field of CREDENTIAL_FIELDS) {
      if (credentialTarget(merged, field) !== credentialTarget(srcBase, field)) {
        delete refs[field];
        const suppliedViaLegacy =
          Boolean(legacySecret) &&
          ((field === 'webdav_pass' && merged.protocol === 'webdav') ||
            (field === 'git_token' && merged.protocol === 'git'));
        if (!raw[field] && !suppliedViaLegacy) {
          merged[field] = '';
        }
      }
    }
    if (Object.hasOwn(merged, 'credential_refs')) {
      merged.credential_refs = refs;
    }
  }

  return merged;
}

export function loadConfigRecord(raw, opts = {}) {
  const config = normalizeConfig(raw, { ...opts, base: DEFAULT_CONFIG });
  const refs = raw && typeof raw === 'object' ? raw.credential_refs : null;
  if (refs && typeof refs === 'object' && !Array.isArray(refs)) {
    const cleanRefs = {};
    for (const [key, ref] of Object.entries(refs)) {
      if (
        CREDENTIAL_FIELDS.includes(key) &&
        typeof ref === 'string' &&
        CREDENTIAL_REF_RE.test(ref) &&
        ref.startsWith(`sync.${key}.`)
      ) {
        cleanRefs[key] = ref;
      }
    }
    config.credential_refs = cleanRefs;
  }
  return config;
}

export function configValuesForUI(config, supportsSystem = true) {
  const values = {};
  for (const [k, v] of Object.entries(config || {})) {
    if (!supportsSystem || (!CREDENTIAL_FIELDS.includes(k) && k !== 'credential_refs')) {
      values[k] = k === 'ignore_patterns' ? String(v ?? '').replace(/\n/g, '\\n') : v;
    }
  }
  if (supportsSystem) {
    for (const field of CREDENTIAL_FIELDS) values[field] = '';
  }
  return values;
}

export function credentialPlaceholder(config, field, defaultText, { supportsSystem = true, locale = 'zh' } = {}) {
  if (supportsSystem) {
    const val = config && config[field];
    if (val && !credentialFits(val)) {
      return tr(
        locale,
        '旧凭据仍为明文，请重新录入或清除',
        'Legacy credential is still stored in plain text. Replace or clear it.'
      );
    }
    const refs = (config && config.credential_refs) || {};
    if (val || refs[field]) {
      return tr(locale, '已保存，留空保留', 'Saved. Leave blank to keep it.');
    }
  }
  return defaultText;
}

export function configRefs(notebooks, shared, current) {
  const out = new Set();
  const records = [...Object.values(notebooks || {}), shared, current];
  for (const cfg of records) {
    if (!cfg || typeof cfg !== 'object') continue;
    const refs = cfg.credential_refs;
    if (refs && typeof refs === 'object') {
      for (const ref of Object.values(refs)) {
        if (typeof ref === 'string' && ref) {
          out.add(ref);
        }
      }
    }
  }
  return out;
}

// ============================================================================
// Pending Confirmation Normalization
// ============================================================================

export function normalizePendingConfirm(raw, homeDir = '') {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return null;
  }
  const scopeKey = String(raw.scope_key || '').trim();
  const fingerprint = String(raw.fingerprint || '').trim();
  const protocol = String(raw.protocol || '').trim();
  const reasons = (Array.isArray(raw.reasons) ? raw.reasons : [])
    .map((r) => String(r || '').trim())
    .filter(Boolean);
  const reasonItems = (Array.isArray(raw.reason_items) ? raw.reason_items : [])
    .filter((r) => r && typeof r === 'object' && r.kind);

  if (reasonItems.some((item) => item.kind === 'git_worktree_update')) {
    return null;
  }
  if (!scopeKey || !fingerprint || !VALID_PROTOCOLS.includes(protocol) || (reasons.length === 0 && reasonItems.length === 0)) {
    return null;
  }

  const sampleItems = (Array.isArray(raw.sample_items) ? raw.sample_items : [])
    .filter((s) => s && typeof s === 'object' && s.kind && s.path)
    .slice(0, MAX_STORED_CONFIRM_SAMPLES);
  const sampleLines = (Array.isArray(raw.sample_lines) ? raw.sample_lines : [])
    .map((s) => String(s || '').trim())
    .filter(Boolean)
    .slice(0, MAX_STORED_CONFIRM_SAMPLES);
  const totalSamples = Number.parseInt(raw.total_samples || sampleItems.length || sampleLines.length || 0, 10) || 0;

  const pending = {
    scope_key: scopeKey,
    fingerprint,
    protocol,
    target_display: sanitizeUrlForDisplay(raw.target_display || ''),
    reasons: reasons.slice(0, 30),
    reason_items: reasonItems.slice(0, 30),
    badge: String(raw.badge || '').trim(),
    sample_items: sampleItems,
    sample_lines: sampleLines,
    total_samples: totalSamples,
  };

  const onlyPath = raw.only_path;
  const onlyNbRoot = raw.only_nb_root;
  if (typeof onlyPath === 'string' && isSafeRelMd(onlyPath) && typeof onlyNbRoot === 'string' && onlyNbRoot) {
    pending.only_path = onlyPath;
    pending.only_nb_root = normAbsPath(onlyNbRoot, homeDir);
  }
  return pending;
}

// ============================================================================
// Notebook Layout & Subdir Mapping
// ============================================================================

export function validSyncSubdir(subdir) {
  return isSafeRelPath(subdir) && !subdir.includes('/') && !subdir.includes('\\');
}

export function notebookKey(nbRoot, fallbackRoot = '', homeDir = '') {
  const raw = nbRoot !== undefined && nbRoot !== null ? nbRoot : fallbackRoot;
  const norm = normAbsPath(raw, homeDir);
  return norm || 'default';
}

export function notebookLabel(nbRoot, locale = 'zh', fallbackRoot = '', homeDir = '') {
  const key = notebookKey(nbRoot, fallbackRoot, homeDir);
  if (key === 'default') {
    return tr(locale, '默认笔记本', 'Default notebook');
  }
  return posixBasename(key) || key;
}

export function notebookSlug(nbRoot, callHost, fallbackRoot = '', homeDir = '') {
  const key = notebookKey(nbRoot, fallbackRoot, homeDir);
  if (key === 'default') return 'default';
  const base = posixBasename(key) || 'notebook';
  const safe = base
    .split('')
    .map((ch) => (/[\p{L}\p{N}_-]/u.test(ch) ? ch : '-'))
    .join('')
    .replace(/^-+|-+$/g, '') || 'notebook';
  const hash = sha256Text(key, callHost);
  return `${safe.slice(0, 24)}-${hash.slice(0, 8)}`;
}

export function computeNotebookSubdirMap({
  notebooks,
  protocol,
  targetBases,
  syncMeta = {},
  notebookConfigs = {},
  knownNotebooks = [],
  callHost,
  locale = 'zh',
  syncTargetBaseFn = null,
}) {
  const layoutKey = `${protocol}:${targetBases[0]}`;
  const layouts = syncMeta[LAYOUTS_META_KEY];
  const stored = layouts && typeof layouts === 'object' ? layouts[layoutKey] : null;
  const bindings = stored && typeof stored === 'object' ? { ...stored } : {};

  for (const subdir of Object.values(bindings)) {
    if (typeof subdir !== 'string' || (subdir && !validSyncSubdir(subdir))) {
      throw new Error(tr(locale, '保存的笔记本同步目录无效', 'The saved notebook sync folder is invalid'));
    }
  }

  const historical = new Map();
  let legacyRoot = false;
  const marker = `|${protocol}:`;
  const legacyKeys = new Set(targetBases.map((base) => `${protocol}:${base}`));

  for (const [key, entry] of Object.entries(syncMeta)) {
    if (key === LAYOUTS_META_KEY || key === INITIALIZED_META_KEY || key === TOMBSTONES_META_KEY) {
      continue;
    }
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      continue;
    }
    if (legacyKeys.has(key)) {
      legacyRoot = true;
      continue;
    }
    if (!key.startsWith('nb:') || !key.includes(marker)) {
      continue;
    }
    const markerIdx = key.lastIndexOf(marker);
    const nb = key.slice(3, markerIdx);
    const location = key.slice(markerIdx + marker.length);
    for (const base of targetBases) {
      if (location === base) {
        if (!historical.has(nb)) historical.set(nb, new Set());
        historical.get(nb).add('');
        break;
      }
      if (location.startsWith(`${base}::`)) {
        const subdir = location.slice(base.length + 2);
        if (validSyncSubdir(subdir)) {
          if (!historical.has(nb)) historical.set(nb, new Set());
          historical.get(nb).add(subdir);
        }
        break;
      }
    }
  }

  if (
    legacyRoot &&
    ![...historical.values()].some((dirs) => dirs.has('')) &&
    !Object.values(bindings).includes('')
  ) {
    const candidates = [];
    for (const [nb, cfg] of Object.entries(notebookConfigs)) {
      if (nb === 'default' || !cfg || cfg.protocol !== protocol) continue;
      const sel = cfg.selected_notebooks;
      if (Array.isArray(sel) && sel.length > 0 && (sel.length !== 1 || sel[0] !== nb)) {
        continue;
      }
      const tb = typeof syncTargetBaseFn === 'function' ? syncTargetBaseFn(cfg) : '';
      if (tb && targetBases.includes(tb)) {
        candidates.push(nb);
      }
    }
    let owner = '';
    if (candidates.length === 1) {
      owner = candidates[0];
    } else if (candidates.length === 0 && knownNotebooks.length === 1 && knownNotebooks[0]?.path) {
      owner = knownNotebooks[0].path;
    } else {
      throw new Error(
        tr(
          locale,
          '旧同步根目录缺少唯一的笔记本归属，无法安全继续同步',
          'The legacy sync root cannot be attributed to one notebook. Sync cannot safely continue.'
        )
      );
    }
    if (!historical.has(owner)) historical.set(owner, new Set());
    historical.get(owner).add('');
  }

  const owners = new Map();
  const nbSet = new Set([...Object.keys(bindings), ...historical.keys()]);
  for (const nb of nbSet) {
    const dirs = new Set(historical.get(nb) || []);
    if (Object.hasOwn(bindings, nb)) {
      dirs.add(bindings[nb]);
    }
    for (const subdir of dirs) {
      const folded = syncDirKey(subdir);
      if (owners.has(folded) && owners.get(folded) !== nb) {
        throw new Error(
          tr(
            locale,
            '同步目标的旧路径被多个笔记本共用，无法安全继续同步',
            'Multiple notebooks share the legacy sync path. Sync cannot safely continue.'
          )
        );
      }
      owners.set(folded, nb);
    }
    if (!Object.hasOwn(bindings, nb)) {
      if (dirs.has('')) {
        bindings[nb] = '';
      } else if (dirs.size === 1) {
        bindings[nb] = [...dirs][0];
      } else if (notebooks.includes(nb)) {
        const lbl = notebookLabel(nb, locale);
        throw new Error(
          tr(
            locale,
            `笔记本「${lbl}」有多个旧同步目录，无法安全选择`,
            `Notebook ${lbl} has multiple legacy sync folders. A folder cannot be chosen safely.`
          )
        );
      }
    }
  }

  if (owners.size === 0 && notebooks.length === 1) {
    bindings[notebooks[0]] = '';
    return { layoutKey, bindings, reservedSubdirs: new Set() };
  }

  const names = new Map();
  const nameCounts = new Map();
  for (const nb of notebooks) {
    if (Object.hasOwn(bindings, nb)) continue;
    let name = posixBasename(nb).trim().replace(/^\.+|\.+$/g, '') || 'notebook';
    name = name.replace(/\\/g, '-');
    names.set(nb, name);
    const folded = syncDirKey(name);
    nameCounts.set(folded, (nameCounts.get(folded) || 0) + 1);
  }

  const sortedEntries = [...names.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  for (const [nb, rawName] of sortedEntries) {
    let name = rawName;
    let folded = syncDirKey(name);
    if (
      owners.has('') ||
      owners.has(folded) ||
      folded === 'assets' ||
      (nameCounts.get(folded) || 0) > 1
    ) {
      const digest = sha256Text(nb, callHost);
      name = `${name}-${digest.slice(0, 8)}`;
      folded = syncDirKey(name);
    }
    let suffix = 2;
    let subdir = name;
    while (owners.has(folded)) {
      subdir = `${name}-${suffix}`;
      folded = syncDirKey(subdir);
      suffix += 1;
    }
    bindings[nb] = subdir;
    owners.set(folded, nb);
  }

  const reservedSubdirs = new Set([...owners.keys()].filter((k) => k !== ''));
  return { layoutKey, bindings, reservedSubdirs };
}

// ============================================================================
// Stateful Config & Credential Store
// ============================================================================

export function createConfigStore({
  callHost = null,
  locale = 'zh',
  supportsSystem = true,
  supportsMultiNotebook = true,
  notebookRoot = '',
  downloadsDir = '',
  homeDir = '',
} = {}) {
  const getRpc = () => resolveCallHost(callHost);

  const state = {
    locale,
    supportsSystem,
    supportsMultiNotebook,
    notebookRoot: normAbsPath(notebookRoot, homeDir),
    downloadsDir: downloadsDir || '',
    homeDir: homeDir || '',
    knownNotebooks: [],
    config: cloneDefaultConfig(),
    savedConfig: cloneDefaultConfig(),
    storedGlobal: null,
    notebookConfigs: {},
    notebookResults: {},
    stats: { total_synced: 0, last_sync: '' },
    logs: [],
    syncMeta: {},
    pendingConfirms: {},
    savedPendingConfirms: {},
    pendingConfirm: null,
    pendingNotices: {},
    credentialCleanup: new Set(),
  };

  const normOpts = () => ({
    supportsSystem: state.supportsSystem,
    downloadsDir: state.downloadsDir,
    homeDir: state.homeDir,
  });

  const nbKey = (root = null) => notebookKey(root, state.notebookRoot, state.homeDir);

  const resultKey = () => {
    if (
      state.supportsMultiNotebook &&
      ((state.storedGlobal && Object.hasOwn(state.storedGlobal, 'selected_notebooks')) ||
        Object.keys(state.pendingConfirms).some((k) => k === '__multi__' || k.startsWith('__multi__:')))
    ) {
      return '__multi__';
    }
    return nbKey();
  };

  const getPendingConfirm = (protocol = null) => {
    const scope = resultKey();
    if (protocol) {
      const specific = state.pendingConfirms[`${scope}:${protocol}`];
      if (specific) return specific;
      const legacy = state.pendingConfirms[scope];
      if (legacy && legacy.protocol === protocol) return legacy;
      return null;
    }
    if (state.pendingConfirms[scope]) {
      return state.pendingConfirms[scope];
    }
    for (const proto of VALID_PROTOCOLS) {
      const pc = state.pendingConfirms[`${scope}:${proto}`];
      if (pc) return pc;
    }
    return null;
  };

  const setPendingConfirm = (pending) => {
    if (!pending) return;
    const key = `${resultKey()}:${pending.protocol}`;
    state.pendingConfirms[key] = pending;
    state.pendingConfirm = getPendingConfirm();
  };

  const clearPendingConfirm = (protocol = null) => {
    const scope = resultKey();
    if (protocol) {
      delete state.pendingConfirms[`${scope}:${protocol}`];
      const legacy = state.pendingConfirms[scope];
      if (legacy && legacy.protocol === protocol) {
        delete state.pendingConfirms[scope];
      }
    } else {
      delete state.pendingConfirms[scope];
      for (const proto of VALID_PROTOCOLS) {
        delete state.pendingConfirms[`${scope}:${proto}`];
      }
    }
    state.pendingConfirm = getPendingConfirm();
  };

  const writeCredentialCleanup = (refs) => {
    const sorted = [...refs].sort();
    const raw = JSON.stringify(sorted);
    if (raw.length > 262144) {
      throw new Error('credential cleanup journal is full');
    }
    storageSet(getRpc(), 'credential_cleanup', sorted);
    state.credentialCleanup = new Set(sorted);
  };

  const cleanupCredentials = () => {
    const active = configRefs(state.notebookConfigs, state.storedGlobal, state.config);
    const complete = new Set([...state.credentialCleanup].filter((r) => active.has(r)));
    const toDelete = [...state.credentialCleanup].filter((r) => !active.has(r)).sort().slice(0, 4);
    for (const ref of toDelete) {
      try {
        secretDelete(getRpc(), ref);
        complete.add(ref);
      } catch (_err) {
        break;
      }
    }
    if (complete.size > 0) {
      const remaining = new Set([...state.credentialCleanup].filter((r) => !complete.has(r)));
      writeCredentialCleanup(remaining);
    }
  };

  const refreshKnownNotebooks = () => {
    const entries = [];
    const seen = new Set();
    const activeNorm = normAbsPath(state.notebookRoot, state.homeDir);

    const addEntry = (pathRaw, nameRaw = '', active = false) => {
      const norm = normAbsPath(pathRaw, state.homeDir);
      if (!norm || seen.has(norm)) return;
      seen.add(norm);
      const label = String(nameRaw || '').trim() || posixBasename(norm) || norm;
      entries.push({ path: norm, name: label, active: Boolean(active) });
    };

    let hostListed = false;
    if (state.supportsMultiNotebook) {
      try {
        const res = getRpc()('host.notebooks.list', {});
        if (res && Array.isArray(res.notebooks)) {
          hostListed = true;
          for (const item of res.notebooks) {
            if (item && typeof item === 'object') {
              const p = item.path;
              addEntry(p, item.name, Boolean(item.active) || (Boolean(activeNorm) && normAbsPath(p, state.homeDir) === activeNorm));
            }
          }
        }
      } catch (_err) {
        // Fallback to cached notebooks.
      }
    }

    if (!hostListed) {
      for (const existing of state.knownNotebooks) {
        if (existing && typeof existing === 'object') {
          addEntry(existing.path, existing.name, Boolean(activeNorm) && normAbsPath(existing.path, state.homeDir) === activeNorm);
        } else if (typeof existing === 'string') {
          addEntry(existing, '', Boolean(activeNorm) && normAbsPath(existing, state.homeDir) === activeNorm);
        }
      }
    }

    if (activeNorm) {
      addEntry(activeNorm, posixBasename(activeNorm) || activeNorm, true);
    }
    state.knownNotebooks = entries;
    return entries;
  };

  const selectedNotebooks = (cfg = null) => {
    const c = cfg || state.config;
    const raw = c.selected_notebooks;
    const knownSet = new Set(state.knownNotebooks.map((e) => e.path));
    const out = [];
    const seen = new Set();
    if (Array.isArray(raw)) {
      for (const item of raw) {
        const norm = normAbsPath(item, state.homeDir);
        if (!norm || seen.has(norm)) continue;
        if (knownSet.size > 0 && !knownSet.has(norm)) continue;
        seen.add(norm);
        out.push(norm);
      }
    }
    if (!state.supportsMultiNotebook) {
      const activeNorm = normAbsPath(state.notebookRoot, state.homeDir);
      return activeNorm ? [activeNorm] : [];
    }
    return out;
  };

  const loadState = () => {
    const rpc = getRpc();
    refreshKnownNotebooks();
    const key = nbKey();
    const opts = normOpts();

    const nbCfgsRes = storageGet(rpc, 'notebook_configs');
    if (nbCfgsRes.found && nbCfgsRes.value && typeof nbCfgsRes.value === 'object' && !Array.isArray(nbCfgsRes.value)) {
      state.notebookConfigs = {};
      for (const [k, v] of Object.entries(nbCfgsRes.value)) {
        if (v && typeof v === 'object' && !Array.isArray(v)) {
          state.notebookConfigs[String(k)] = loadConfigRecord(v, opts);
        }
      }
    } else {
      state.notebookConfigs = {};
    }

    const cfgRes = storageGet(rpc, 'config');
    const rawCfg = cfgRes.found && cfgRes.value && typeof cfgRes.value === 'object' && !Array.isArray(cfgRes.value)
      ? cfgRes.value
      : null;
    state.storedGlobal = rawCfg !== null ? loadConfigRecord(rawCfg, opts) : null;
    if (state.storedGlobal && !Object.hasOwn(rawCfg, 'selected_notebooks')) {
      delete state.storedGlobal.selected_notebooks;
    }

    if (!state.supportsMultiNotebook) {
      if (Object.hasOwn(state.notebookConfigs, key)) {
        state.config = { ...state.notebookConfigs[key] };
      } else if (rawCfg !== null && (!Array.isArray(rawCfg.selected_notebooks) || rawCfg.selected_notebooks.length === 0)) {
        state.config = { ...state.storedGlobal };
      } else {
        state.config = cloneDefaultConfig();
      }
      if (state.notebookRoot) {
        state.config.selected_notebooks = [normAbsPath(state.notebookRoot, state.homeDir)];
      }
    } else if (rawCfg !== null && Object.hasOwn(rawCfg, 'selected_notebooks')) {
      state.config = { ...state.storedGlobal };
    } else if (Object.hasOwn(state.notebookConfigs, key)) {
      state.config = { ...state.notebookConfigs[key] };
      if (state.notebookRoot) {
        state.config.selected_notebooks = [normAbsPath(state.notebookRoot, state.homeDir)];
      }
    } else if (rawCfg !== null) {
      state.config = { ...state.storedGlobal };
      state.config.selected_notebooks = state.notebookRoot ? [normAbsPath(state.notebookRoot, state.homeDir)] : [];
    } else {
      state.config = cloneDefaultConfig();
      if (state.notebookRoot) {
        state.config.selected_notebooks = [normAbsPath(state.notebookRoot, state.homeDir)];
      }
    }

    const nbRes = storageGet(rpc, 'notebook_results');
    state.notebookResults = nbRes.found && nbRes.value && typeof nbRes.value === 'object' && !Array.isArray(nbRes.value)
      ? { ...nbRes.value }
      : {};

    const statsRes = storageGet(rpc, 'stats');
    if (statsRes.found && statsRes.value && typeof statsRes.value === 'object') {
      state.stats = {
        total_synced: Number.parseInt(statsRes.value.total_synced || 0, 10) || 0,
        last_sync: String(statsRes.value.last_sync || ''),
      };
    }

    const logsRes = storageGet(rpc, 'logs');
    if (logsRes.found && Array.isArray(logsRes.value)) {
      state.logs = logsRes.value
        .filter((e) => e && typeof e === 'object')
        .slice(0, MAX_LOG_ENTRIES)
        .map((e) => normalizeLog(e));
    }

    const metaRes = storageGet(rpc, 'sync_meta');
    state.syncMeta = metaRes.found && metaRes.value && typeof metaRes.value === 'object' && !Array.isArray(metaRes.value)
      ? { ...metaRes.value }
      : {};

    state.pendingConfirms = {};
    const pcsRes = storageGet(rpc, 'pending_confirms');
    if (pcsRes.found && pcsRes.value && typeof pcsRes.value === 'object' && !Array.isArray(pcsRes.value)) {
      for (const [k, v] of Object.entries(pcsRes.value)) {
        const norm = normalizePendingConfirm(v, state.homeDir);
        if (norm) state.pendingConfirms[String(k)] = norm;
      }
    }
    const pcRes = storageGet(rpc, 'pending_confirm');
    if (pcRes.found) {
      const legacyPc = normalizePendingConfirm(pcRes.value, state.homeDir);
      if (legacyPc && !Object.hasOwn(state.pendingConfirms, legacyPc.scope_key)) {
        state.pendingConfirms[legacyPc.scope_key] = legacyPc;
      }
    }
    state.pendingConfirm = getPendingConfirm();
    state.savedPendingConfirms = { ...state.pendingConfirms };
    state.savedConfig = { ...state.config };

    if (state.supportsSystem) {
      const noticesRes = storageGet(rpc, 'pending_notices');
      state.pendingNotices = noticesRes.found && noticesRes.value && typeof noticesRes.value === 'object' && !Array.isArray(noticesRes.value)
        ? { ...noticesRes.value }
        : {};
      const journalRes = storageGet(rpc, 'credential_cleanup');
      if (journalRes.found && Array.isArray(journalRes.value)) {
        state.credentialCleanup = new Set(
          journalRes.value.filter((ref) => typeof ref === 'string' && CREDENTIAL_REF_RE.test(ref))
        );
      } else {
        state.credentialCleanup = new Set();
      }
    }
    return state;
  };

  const commitSystemConfig = (notebooks, shared, current, { migrate = null, clearPending = false } = {}) => {
    const rpc = getRpc();
    const staged = new Map();
    const refsByValue = new Map();

    const prepare = (cfg) => {
      if (!cfg) return null;
      const disk = { ...cfg };
      const refs = { ...(cfg.credential_refs || {}) };
      for (const field of CREDENTIAL_FIELDS) {
        const value = cfg[field] || '';
        const replace = migrate !== null
          ? migrate[0] === field && migrate[1] === value
          : Boolean(
              value &&
                (value !== state.savedConfig[field] ||
                  credentialTarget(cfg, field) !== credentialTarget(state.savedConfig, field))
            );
        if (replace) {
          const valKey = `${field}\u0000${value}`;
          let ref = refsByValue.get(valKey);
          if (!ref) {
            ref = generateCredentialRef(field);
            refsByValue.set(valKey, ref);
            staged.set(ref, value);
          }
          refs[field] = ref;
          disk[field] = '';
        }
      }
      disk.credential_refs = refs;
      return disk;
    };

    const actualNotebooks = {};
    for (const [k, v] of Object.entries(notebooks || {})) {
      actualNotebooks[k] = migrate ? prepare(v) : v;
    }
    const actualShared = migrate || shared === current ? prepare(shared) : shared;
    const actualCurrent = prepare(current);
    if (!migrate) {
      actualNotebooks[nbKey()] = actualCurrent;
    }

    const oldRefs = configRefs(state.notebookConfigs, state.storedGlobal, state.config);
    const newRefs = configRefs(actualNotebooks, actualShared, actualCurrent);
    const pendingRefs = new Set([
      ...state.credentialCleanup,
      ...staged.keys(),
      ...[...oldRefs].filter((r) => !newRefs.has(r)),
    ]);
    const sameCleanup =
      pendingRefs.size === state.credentialCleanup.size &&
      [...pendingRefs].every((r) => state.credentialCleanup.has(r));
    if (!sameCleanup) {
      writeCredentialCleanup(pendingRefs);
    }

    for (const [ref, secret] of staged.entries()) {
      secretSet(rpc, ref, secret);
    }

    const updates = {
      notebook_configs: actualNotebooks,
      config: actualShared,
    };

    let nextPending = state.pendingConfirms;
    let nextNotices = state.pendingNotices;
    if (clearPending) {
      nextPending = { ...state.pendingConfirms };
      const scope = resultKey();
      const clearProtos = clearPending === true ? new Set(VALID_PROTOCOLS) : new Set(clearPending);
      if (clearProtos.size >= VALID_PROTOCOLS.length && VALID_PROTOCOLS.every((p) => clearProtos.has(p))) {
        delete nextPending[scope];
      } else {
        const legacy = nextPending[scope];
        if (legacy && clearProtos.has(legacy.protocol)) {
          delete nextPending[scope];
        }
      }
      for (const proto of clearProtos) {
        delete nextPending[`${scope}:${proto}`];
      }
      const clearedScopes = new Set([scope]);
      if (shared === current) {
        for (const root of current.selected_notebooks || []) {
          clearedScopes.add(nbKey(root));
        }
        clearedScopes.add('__multi__');
      }
      nextNotices = { ...state.pendingNotices };
      for (const [nKey, notice] of Object.entries(state.pendingNotices)) {
        if (!notice || typeof notice !== 'object') continue;
        const isPause = notice.status === '待确认' || Boolean(notice.fingerprint);
        if (notice.status === '失败' || isPause) {
          const nScope = notice.scope || nKey;
          if (typeof nScope === 'string' && clearedScopes.has(nScope)) {
            if (clearProtos.size >= VALID_PROTOCOLS.length || !notice.protocol || clearProtos.has(notice.protocol)) {
              delete nextNotices[nKey];
            }
          }
        }
      }
      updates.pending_confirms = nextPending;
      updates.pending_confirm = null;
      updates.pending_notices = nextNotices;
    }

    storageSetMany(rpc, updates);
    state.notebookConfigs = actualNotebooks;
    state.storedGlobal = actualShared;
    state.config = actualCurrent;
    state.savedConfig = { ...state.config };
    if (clearPending) {
      state.pendingConfirms = nextPending;
      state.savedPendingConfirms = { ...nextPending };
      state.pendingConfirm = getPendingConfirm();
      state.pendingNotices = nextNotices;
    }
  };

  const saveConfig = (config = null, { forget = null, clearPending = false } = {}) => {
    const rpc = getRpc();
    let candidate = config || state.config;
    const sharedScope =
      state.supportsMultiNotebook &&
      (Boolean(state.storedGlobal && Object.hasOwn(state.storedGlobal, 'selected_notebooks')) ||
        JSON.stringify(candidate.selected_notebooks) !== JSON.stringify(state.config.selected_notebooks));

    if (state.supportsSystem) {
      for (const field of CREDENTIAL_FIELDS) {
        const value = candidate[field];
        if (
          value &&
          !credentialFits(value) &&
          (value !== state.savedConfig[field] ||
            credentialTarget(candidate, field) !== credentialTarget(state.savedConfig, field))
        ) {
          throw new Error(
            tr(
              state.locale,
              '请输入不超过 1536 字节且不含空字符的凭据',
              'Enter a credential of at most 1536 bytes with no NUL characters.'
            )
          );
        }
      }

      let shared = sharedScope ? candidate : state.storedGlobal;
      let notebooks = { ...state.notebookConfigs };
      if (forget) {
        const target = credentialTarget(candidate, forget);
        const removeCredential = (record) => {
          if (!record || credentialTarget(record, forget) !== target) return record;
          const refs = { ...(record.credential_refs || {}) };
          delete refs[forget];
          return { ...record, credential_refs: refs, [forget]: '' };
        };
        const updatedNotebooks = {};
        for (const [k, v] of Object.entries(notebooks)) {
          updatedNotebooks[k] = removeCredential(v);
        }
        notebooks = updatedNotebooks;
        candidate = removeCredential(candidate);
        shared = sharedScope ? candidate : removeCredential(shared);
      }

      commitSystemConfig(notebooks, shared, candidate, { clearPending });
      cleanupCredentials();
      return state.config;
    }

    state.config = candidate;
    state.notebookConfigs[nbKey()] = { ...candidate };
    if (sharedScope) {
      state.storedGlobal = { ...candidate };
      storageSet(rpc, 'config', candidate);
    }
    storageSet(rpc, 'notebook_configs', state.notebookConfigs);
    state.savedConfig = { ...state.config };
    return state.config;
  };

  const migrateCredentials = () => {
    if (!state.supportsSystem) return 'skipped';
    try {
      cleanupCredentials();
      const stored = [...Object.values(state.notebookConfigs), state.storedGlobal, state.config];
      const pending = [];
      const seen = new Set();
      for (const cfg of stored) {
        if (!cfg) continue;
        for (const field of CREDENTIAL_FIELDS) {
          const val = cfg[field];
          if (val && credentialFits(val)) {
            const k = `${field}\u0000${val}`;
            if (!seen.has(k)) {
              seen.add(k);
              pending.push([field, val]);
            }
          }
        }
      }
      if (pending.length > 0) {
        commitSystemConfig(state.notebookConfigs, state.storedGlobal, state.config, { migrate: pending[0] });
      }
      if (pending.length > 1) return 'migration_pending';
    } catch (_err) {
      return 'migration_retry';
    }
    return state.credentialCleanup.size > 0 ? 'migration_retry' : 'skipped';
  };

  const saveRuntime = () => {
    const rpc = getRpc();
    const values = {
      stats: state.stats,
      logs: state.logs.slice(0, MAX_LOG_ENTRIES),
      sync_meta: state.syncMeta,
      notebook_results: state.notebookResults,
      pending_confirms: state.pendingConfirms,
      pending_confirm: null,
    };
    if (state.supportsSystem) {
      storageSetMany(rpc, values);
    } else {
      for (const [k, v] of Object.entries(values)) {
        storageSet(rpc, k, v);
      }
    }
    state.savedPendingConfirms = { ...state.pendingConfirms };
  };

  const metaKey = (protocol, targetId, customNbKey = null) => {
    const nb = customNbKey || nbKey();
    return `nb:${nb}|${protocol}:${targetId}`;
  };

  const getBaseMap = (...keys) => {
    for (const key of keys) {
      if (!key || key === LAYOUTS_META_KEY || key === INITIALIZED_META_KEY || key === TOMBSTONES_META_KEY) {
        continue;
      }
      const val = state.syncMeta[key];
      if (val && typeof val === 'object' && !Array.isArray(val)) {
        return { ...val };
      }
    }
    return {};
  };

  const recordTombstone = (targetNbKey, itemKey, itemHash, ts = null) => {
    if (!targetNbKey || !itemKey || !itemHash) return false;
    let allTombs = state.syncMeta[TOMBSTONES_META_KEY];
    if (!allTombs || typeof allTombs !== 'object' || Array.isArray(allTombs)) {
      allTombs = {};
    }
    let nbTombs = allTombs[targetNbKey];
    if (!nbTombs || typeof nbTombs !== 'object' || Array.isArray(nbTombs)) {
      nbTombs = {};
    }
    nbTombs[itemKey] = {
      hash: String(itemHash),
      ts: ts !== null && ts !== undefined ? Number(ts) : Math.floor(Date.now() / 1000),
    };
    const entries = Object.entries(nbTombs);
    if (entries.length > MAX_TOMBSTONES_PER_NB) {
      entries.sort((a, b) => Number((b[1] && b[1].ts) || 0) - Number((a[1] && a[1].ts) || 0));
      nbTombs = Object.fromEntries(entries.slice(0, MAX_TOMBSTONES_PER_NB));
    }
    allTombs[targetNbKey] = nbTombs;
    state.syncMeta[TOMBSTONES_META_KEY] = allTombs;
    return true;
  };

  const clearTombstone = (targetNbKey, itemKey) => {
    const allTombs = state.syncMeta[TOMBSTONES_META_KEY];
    if (!allTombs || typeof allTombs !== 'object') return;
    const nbTombs = allTombs[targetNbKey];
    if (!nbTombs || typeof nbTombs !== 'object') return;
    delete nbTombs[itemKey];
  };

  const lookupTombstoneHash = (targetNbKey, itemKey) => {
    const allTombs = state.syncMeta[TOMBSTONES_META_KEY];
    if (!allTombs || typeof allTombs !== 'object') return null;
    const nbTombs = allTombs[targetNbKey];
    if (!nbTombs || typeof nbTombs !== 'object') return null;
    const entry = nbTombs[itemKey];
    if (entry && typeof entry === 'object' && typeof entry.hash === 'string' && entry.hash) {
      return entry.hash;
    }
    return null;
  };

  const lookupOtherProtocolHash = (targetNbKey, itemKey, targetHash, excludeMetaKey = null) => {
    if (!targetNbKey || !itemKey || !targetHash) return null;
    const nbPrefix = `nb:${targetNbKey}|`;
    const isDefaultNb = targetNbKey === normAbsPath(state.notebookRoot, state.homeDir) || targetNbKey === 'default';
    for (const [mk, entry] of Object.entries(state.syncMeta)) {
      if (mk === LAYOUTS_META_KEY || mk === INITIALIZED_META_KEY || mk === TOMBSTONES_META_KEY || mk === excludeMetaKey) {
        continue;
      }
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
      if (!(mk.startsWith(nbPrefix) || (!mk.startsWith('nb:') && isDefaultNb))) continue;
      const val = entry[itemKey];
      if (typeof val === 'string' && val === targetHash) {
        return val;
      }
    }
    return null;
  };

  return {
    state,
    normalizeConfig: (raw, base = null) =>
      normalizeConfig(raw, { ...normOpts(), base: base !== null && base !== undefined ? base : state.config }),
    loadConfigRecord: (raw) => loadConfigRecord(raw, normOpts()),
    refreshKnownNotebooks,
    selectedNotebooks,
    notebookKey: nbKey,
    notebookLabel: (root = null) => notebookLabel(root, state.locale, state.notebookRoot, state.homeDir),
    notebookSlug: (root = null) => notebookSlug(root, getRpc(), state.notebookRoot, state.homeDir),
    resultKey,
    getPendingConfirm,
    setPendingConfirm,
    clearPendingConfirm,
    loadState,
    saveConfig,
    saveRuntime,
    commitSystemConfig,
    cleanupCredentials,
    migrateCredentials,
    resolveCredentials: (cfg) => resolveCredentials(getRpc(), cfg || state.config, state.locale),
    metaKey,
    getBaseMap,
    recordTombstone,
    clearTombstone,
    lookupTombstoneHash,
    lookupOtherProtocolHash,
  };
}
