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
  DEFAULT_IGNORE_PATTERNS,
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
export const VALID_SYNC_INTERVALS = Object.freeze(['10', '30', '60']);
export const SYNC_INTERVAL_EVENT = 'plugin.sync_interval';
export const DELETE_GUARD_THRESHOLD = 5;
export const MAX_LOG_ENTRIES = 100;
export const MAX_HOST_LOG_QUEUE = 500;
export const WEBDAV_TRASH_DIR = '.block-sync-trash';
export const LAYOUTS_META_KEY = 'notebook_layouts';
export const INITIALIZED_META_KEY = 'initialized_targets';
export const TOMBSTONES_META_KEY = '__tombstones__';
export const ROOT_IDENTITIES_META_KEY = '__nb_identities__';
export const BASELINE_FINGERPRINTS_META_KEY = '__baseline_fingerprints__';
export const BASE_TIMESTAMPS_META_KEY = '__base_ts__';
export const LEGACY_PATH_MIGRATED_KEY = '__legacy_path_migrated__';
export const NOTEBOOK_ID_MAP_KEY = 'notebook_id_map';
export const MAX_TOMBSTONES_PER_NB = 4000;
export const MAX_STORED_CONFIRM_SAMPLES = 30;
export const MAX_WEBDAV_DIRS = 2000;
export const CREDENTIAL_FIELDS = Object.freeze(['git_token', 'webdav_pass']);
export const CREDENTIAL_MAX_BYTES = 1536;
export const CREDENTIAL_REF_RE = /^sync\.(git_token|webdav_pass)\.[0-9a-f]{32}$/;

export function isReservedSyncMetaKey(key) {
  return (
    !key ||
    key === LAYOUTS_META_KEY ||
    key === INITIALIZED_META_KEY ||
    key === TOMBSTONES_META_KEY ||
    key === ROOT_IDENTITIES_META_KEY ||
    key === BASELINE_FINGERPRINTS_META_KEY ||
    key === BASE_TIMESTAMPS_META_KEY ||
    key === LEGACY_PATH_MIGRATED_KEY
  );
}

function isLegacyPathNotebookKey(rawNb) {
  const s = String(rawNb || '').trim();
  if (!s || s === 'default') return false;
  return s.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(s) || s === '~' || s.startsWith('~/') || s.startsWith('~\\');
}

function isUnsupportedHostMethod(exc) {
  if (!exc) return false;
  if (typeof exc === 'object' && exc.code === -32601) return true;
  const low = String(exc?.message || exc || '').toLowerCase();
  return (
    low.includes('unknown host method') ||
    low.includes('method not found') ||
    low.includes('-32601') ||
    low.includes('unexpected host request')
  );
}

export function queryLiveNotebookIdentity(callHost, nbRoot, homeDir = '') {
  const empty = { verified: false, rootIdentity: '', id: '', previousPaths: [] };
  const cleanRoot = normAbsPath(nbRoot, homeDir);
  if (!cleanRoot) return empty;
  const rpc = resolveCallHost(callHost);

  const normalizePrev = (raw) => {
    if (!Array.isArray(raw)) return [];
    const out = [];
    const seen = new Set();
    for (const p of raw) {
      const np = normAbsPath(p, homeDir);
      if (np && np !== cleanRoot && !seen.has(np)) {
        seen.add(np);
        out.push(np);
      }
    }
    return out;
  };

  try {
    const res = rpc('host.notebooks.data_dir', { path: cleanRoot });
    if (res && typeof res === 'object') {
      const rootIdentity = String(res.root_identity || '').trim();
      const verified = res.identity_verified === true && Boolean(rootIdentity);
      return {
        verified,
        rootIdentity,
        id: String(res.id || '').trim(),
        previousPaths: normalizePrev(res.previous_paths),
      };
    }
    return empty;
  } catch (exc) {
    if (!isUnsupportedHostMethod(exc)) {
      return empty;
    }
  }

  try {
    const listRes = rpc('host.notebooks.list', {});
    if (listRes && Array.isArray(listRes.notebooks)) {
      const match = listRes.notebooks.find(
        (item) => item && typeof item === 'object' && normAbsPath(item.path, homeDir) === cleanRoot
      );
      if (match) {
        const rootIdentity = String(match.root_identity || '').trim();
        const verified = match.identity_verified === true && Boolean(rootIdentity);
        return {
          verified,
          rootIdentity,
          id: String(match.id || '').trim(),
          previousPaths: normalizePrev(match.previous_paths),
        };
      }
    }
  } catch (_listErr) {
    // Unverified if host list is unavailable.
  }
  return empty;
}

/**
 * Evaluate whether a baseline's stored state fingerprint matches the current
 * notebook root identity (dev:ino) and target identity (mirror dev:ino or
 * Git local commit oid). When missing or mismatched, forces full merge-only
 * sync with no deletions propagated to either side.
 */
export function evaluateBaselineState(
  configStore,
  {
    protocol = 'local_mirror',
    nbRoot = '',
    metaKey = '',
    aliases = [],
    legacyKeys = [],
    nbKeyVal = '',
    currentTargetIdentity = '',
    hasUnpushedCommits = false,
    callHost = null,
    homeDir = '',
  } = {}
) {
  const candidateLegacyKeys = (legacyKeys || []).filter(Boolean);
  const allowLegacy =
    candidateLegacyKeys.length > 0 &&
    !(
      configStore &&
      configStore.state &&
      (configStore.state.hostSupportsNotebookIds ||
        (configStore.state.notebookIdMap &&
          configStore.state.notebookIdMap.by_id &&
          Object.hasOwn(configStore.state.notebookIdMap.by_id, nbKeyVal)))
    );
  const effectiveLegacyKeys = allowLegacy ? candidateLegacyKeys : [];
  const syncMeta = (configStore && configStore.state && configStore.state.syncMeta) || {};
  const primaryAndAliases = [metaKey, ...(aliases || [])].filter(Boolean);
  const candidateKeys = [...primaryAndAliases, ...effectiveLegacyKeys];

  const originalBaseMap =
    configStore && typeof configStore.getBaseMap === 'function'
      ? configStore.getBaseMap(...candidateKeys)
      : {};
  const initializedMap = syncMeta[INITIALIZED_META_KEY];
  const hasExistingMeta = Boolean(
    (initializedMap &&
      typeof initializedMap === 'object' &&
      candidateKeys.some((k) => Boolean(initializedMap[k]))) ||
      Object.keys(originalBaseMap).length > 0
  );

  const effectiveHome = (configStore && configStore.state && configStore.state.homeDir) || homeDir || '';
  const idCheck =
    configStore && typeof configStore.verifyNotebookIdentity === 'function'
      ? configStore.verifyNotebookIdentity(nbRoot, {
          metaKey,
          aliases,
          legacyKeys: effectiveLegacyKeys,
          nbKeyVal,
          hasExistingBaseline: hasExistingMeta,
        })
      : (() => {
          const live = queryLiveNotebookIdentity(callHost, nbRoot, effectiveHome);
          return {
            identity_ok: Boolean(live.verified && live.rootIdentity),
            verified: Boolean(live.verified),
            root_identity: live.rootIdentity || '',
            recorded_root_identity: '',
            live_id: live.id || '',
            reason: live.verified ? '' : 'host_unverified',
          };
        })();

  const liveVerified = Boolean(idCheck && idCheck.verified === true && idCheck.root_identity);
  const idOk = Boolean(idCheck && idCheck.identity_ok === true);

  let matchedBaseKey = '';
  for (const k of candidateKeys) {
    if (isReservedSyncMetaKey(k)) continue;
    const val = syncMeta[k];
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      matchedBaseKey = k;
      break;
    }
  }
  if (!matchedBaseKey && initializedMap && typeof initializedMap === 'object') {
    for (const k of candidateKeys) {
      if (initializedMap[k]) {
        matchedBaseKey = k;
        break;
      }
    }
  }

  const fpMap =
    syncMeta[BASELINE_FINGERPRINTS_META_KEY] &&
    typeof syncMeta[BASELINE_FINGERPRINTS_META_KEY] === 'object' &&
    !Array.isArray(syncMeta[BASELINE_FINGERPRINTS_META_KEY])
      ? syncMeta[BASELINE_FINGERPRINTS_META_KEY]
      : null;
  const storedFp =
    matchedBaseKey && fpMap && fpMap[matchedBaseKey] && typeof fpMap[matchedBaseKey] === 'object'
      ? fpMap[matchedBaseKey]
      : null;

  const fpNbId = storedFp ? String(storedFp.nb_root_identity || '').trim() : '';
  const fpTargetId = storedFp ? String(storedFp.target_identity || '').trim() : '';
  const curTargetId = String(currentTargetIdentity || '').trim();
  const needsTargetId = protocol === 'local_mirror' || protocol === 'git';

  const nbMatches = Boolean(idOk && fpNbId && fpNbId === idCheck.root_identity);
  const targetMatches = !needsTargetId || Boolean(fpTargetId && curTargetId && fpTargetId === curTargetId);
  const fingerprintMatch = Boolean(hasExistingMeta && storedFp && nbMatches && targetMatches);

  let reason = '';
  if (!hasExistingMeta) {
    reason = 'first_sync';
  } else if (!liveVerified) {
    reason = (idCheck && idCheck.reason) || 'host_unverified';
  } else if (!idOk) {
    reason = (idCheck && idCheck.reason) || 'notebook_identity_mismatch';
  } else if (!storedFp || !fpNbId || (needsTargetId && !fpTargetId)) {
    reason = 'missing_fingerprint';
  } else if (fpNbId !== idCheck.root_identity) {
    reason = 'notebook_fingerprint_mismatch';
  } else if (needsTargetId && fpTargetId !== curTargetId) {
    reason = 'target_fingerprint_mismatch';
  }

  const mergeOnly = !fingerprintMatch;
  const mergeOnlyRule = Boolean(hasExistingMeta && liveVerified && mergeOnly);
  const forceFullSync = mergeOnly || Boolean(hasUnpushedCommits);
  const identityVerified = Boolean(idOk && (!hasExistingMeta || fingerprintMatch));
  const identityDegraded = Boolean(hasExistingMeta && !liveVerified);

  return {
    effectiveLegacyKeys,
    originalBaseMap,
    hasExistingMeta,
    idCheck,
    liveVerified,
    identityVerified,
    identityDegraded,
    baseMap: mergeOnly ? {} : { ...originalBaseMap },
    isFirstSync: mergeOnly,
    mergeOnly,
    mergeOnlyRule,
    forceFullSync,
    fingerprintMatch,
    reason,
    storedFingerprint: storedFp,
  };
}

// Bump when defaults change in a way existing configs should adopt once.
export const CONFIG_DEFAULTS_REV = 2;

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
  sync_interval: '10',
  system_notifications: true,
  sync_assets: true,
  max_file_size_mb: DEFAULT_MAX_FILE_SIZE_MB,
  ignore_patterns: DEFAULT_IGNORE_PATTERNS,
  conflict_policy: 'keep_both',
  delete_guard: true,
  defaults_rev: CONFIG_DEFAULTS_REV,
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

export function connConfigSignature(cfg, protocol, downloadsDir = '', homeDir = '') {
  const c = cfg || {};
  const refs = c.credential_refs && typeof c.credential_refs === 'object' ? c.credential_refs : {};
  if (protocol === 'local_mirror') {
    return JSON.stringify(['local_mirror', resolveMirrorDir(c, downloadsDir, homeDir)]);
  }
  if (protocol === 'webdav') {
    return JSON.stringify([
      'webdav',
      String(c.webdav_url || '').trim(),
      resolveWebdavDir(c),
      String(c.webdav_user || '').trim(),
      Boolean(c.webdav_pass || refs.webdav_pass),
    ]);
  }
  if (protocol === 'git') {
    return JSON.stringify([
      'git',
      String(c.git_remote || '').trim(),
      String(c.git_branch || 'main').trim() || 'main',
      String(c.git_auth || 'ssh'),
      Boolean(c.git_token || refs.git_token),
    ]);
  }
  return JSON.stringify([protocol || '']);
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
  if (raw && typeof raw === 'object' && (Number(raw.defaults_rev) || 0) < CONFIG_DEFAULTS_REV) {
    // One-time migration: adopt GitHub-sized limit and default media ignore rules.
    if (String(raw.max_file_size_mb ?? '50') === '50') config.max_file_size_mb = DEFAULT_MAX_FILE_SIZE_MB;
    if (!String(raw.ignore_patterns ?? '').trim()) config.ignore_patterns = DEFAULT_IGNORE_PATTERNS;
  }
  config.defaults_rev = CONFIG_DEFAULTS_REV;
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

export function parseNbMetaKey(mk) {
  const s = String(mk || '');
  if (!s.startsWith('nb:')) return null;
  let bestIdx = -1;
  let bestProto = '';
  for (const proto of VALID_PROTOCOLS) {
    const marker = `|${proto}:`;
    const idx = s.indexOf(marker, 3);
    if (idx > 3 && (bestIdx < 0 || idx < bestIdx)) {
      bestIdx = idx;
      bestProto = proto;
    }
  }
  if (bestIdx > 3) {
    return {
      nb: s.slice(3, bestIdx),
      protocol: bestProto,
      target: s.slice(bestIdx + bestProto.length + 2),
      rest: s.slice(bestIdx),
    };
  }
  const lastPipe = s.lastIndexOf('|');
  if (lastPipe > 3) {
    return {
      nb: s.slice(3, lastPipe),
      protocol: '',
      target: '',
      rest: s.slice(lastPipe),
    };
  }
  return null;
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
  const idToPath = new Map();
  for (const kn of knownNotebooks || []) {
    if (kn && typeof kn === 'object' && kn.id && kn.path) {
      idToPath.set(String(kn.id), String(kn.path));
    }
  }
  const resolveNbPath = (rawKey) => idToPath.get(String(rawKey)) || String(rawKey);

  const layoutKey = `${protocol}:${targetBases[0]}`;
  const layouts = syncMeta[LAYOUTS_META_KEY];
  const stored = layouts && typeof layouts === 'object' ? layouts[layoutKey] : null;
  const bindings = {};
  if (stored && typeof stored === 'object') {
    for (const [k, subdir] of Object.entries(stored)) {
      bindings[resolveNbPath(k)] = subdir;
    }
  }

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
    if (isReservedSyncMetaKey(key)) {
      continue;
    }
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      continue;
    }
    if (legacyKeys.has(key)) {
      legacyRoot = true;
      continue;
    }
    const parsed = parseNbMetaKey(key);
    if (!parsed || parsed.protocol !== protocol) {
      continue;
    }
    const nb = resolveNbPath(parsed.nb);
    const location = parsed.target;
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
    for (const [rawNb, cfg] of Object.entries(notebookConfigs)) {
      if (rawNb === 'default' || !cfg || cfg.protocol !== protocol) continue;
      const nb = resolveNbPath(rawNb);
      const sel = Array.isArray(cfg.selected_notebooks)
        ? cfg.selected_notebooks.map((item) => resolveNbPath(item))
        : cfg.selected_notebooks;
      if (Array.isArray(sel) && sel.length > 0 && (sel.length !== 1 || (sel[0] !== nb && sel[0] !== rawNb))) {
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
    connStates: {},
    credentialCleanup: new Set(),
    notebookIdMap: { by_id: {}, by_path: {} },
    hostSupportsNotebookIds: false,
    _stateLoaded: false,
  };

  const normOpts = () => ({
    supportsSystem: state.supportsSystem,
    downloadsDir: state.downloadsDir,
    homeDir: state.homeDir,
  });

  const idForPath = (rawPath) => {
    const norm = normAbsPath(rawPath, state.homeDir);
    if (!norm) return '';
    const hit = state.knownNotebooks.find((kn) => kn && kn.path === norm && kn.id);
    return hit ? String(hit.id) : '';
  };

  const pathForKeyOrPath = (raw) => {
    const val = String(raw || '').trim();
    if (!val) return '';
    const byId = state.knownNotebooks.find((kn) => kn && kn.id === val);
    if (byId && byId.path) return byId.path;
    return normAbsPath(val, state.homeDir) || val;
  };

  const nbKey = (root = null) => {
    const target = root !== undefined && root !== null ? root : state.notebookRoot;
    const norm = normAbsPath(target, state.homeDir);
    if (!norm) return 'default';
    return idForPath(norm) || norm;
  };

  const decodeSelectedNotebooks = (arr) => {
    if (!Array.isArray(arr)) return [];
    const out = [];
    const seen = new Set();
    for (const item of arr) {
      const resolved = normAbsPath(pathForKeyOrPath(item), state.homeDir);
      if (resolved && !seen.has(resolved)) {
        seen.add(resolved);
        out.push(resolved);
      }
    }
    return out;
  };

  const encodeSelectedNotebooks = (arr) => {
    if (!Array.isArray(arr)) return [];
    const out = [];
    const seen = new Set();
    for (const item of arr) {
      const resolvedPath = normAbsPath(pathForKeyOrPath(item), state.homeDir);
      if (!resolvedPath) continue;
      const encoded = idForPath(resolvedPath) || resolvedPath;
      if (!seen.has(encoded)) {
        seen.add(encoded);
        out.push(encoded);
      }
    }
    return out;
  };

  const decodeConfigSelected = (rawCfg) => {
    if (!rawCfg || typeof rawCfg !== 'object' || Array.isArray(rawCfg)) return rawCfg;
    if (!Object.hasOwn(rawCfg, 'selected_notebooks')) return rawCfg;
    return { ...rawCfg, selected_notebooks: decodeSelectedNotebooks(rawCfg.selected_notebooks) };
  };

  const encodeConfigSelected = (cfg) => {
    if (!cfg || typeof cfg !== 'object' || Array.isArray(cfg)) return cfg;
    if (!Object.hasOwn(cfg, 'selected_notebooks')) return cfg;
    return { ...cfg, selected_notebooks: encodeSelectedNotebooks(cfg.selected_notebooks) };
  };

  const encodeLayoutsForStorage = (layouts) => {
    if (!layouts || typeof layouts !== 'object' || Array.isArray(layouts)) return layouts;
    const out = {};
    for (const [lk, bindings] of Object.entries(layouts)) {
      if (!bindings || typeof bindings !== 'object' || Array.isArray(bindings)) {
        out[lk] = bindings;
        continue;
      }
      const mapped = {};
      for (const [nbK, subdir] of Object.entries(bindings)) {
        const norm = normAbsPath(pathForKeyOrPath(nbK), state.homeDir);
        const storedKey = (norm && idForPath(norm)) || String(nbK);
        if (!Object.hasOwn(mapped, storedKey)) { // preserve existing mapped ID over raw path fallback
          mapped[storedKey] = subdir;
        }
      }
      out[lk] = mapped;
    }
    return out;
  };

  const rewriteScopedAliasMap = (
    obj,
    aliasMap,
    { isConfirm = false, isNotice = false, isResult = false, isConn = false, oldPath = '', newPath = '' } = {}
  ) => {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj) || !aliasMap || aliasMap.size === 0) {
      return [obj, false];
    }
    let changed = false;
    const rewriteScope = (s) => aliasMap.get(s) || s;
    const next = {};
    const pendingAliased = [];

    const resolveTargetAndVal = (k, v) => {
      let targetKey = k;
      if (aliasMap.has(k)) {
        targetKey = aliasMap.get(k);
      } else {
        for (const proto of VALID_PROTOCOLS) {
          const suffix = `:${proto}`;
          if (k.endsWith(suffix)) {
            const base = k.slice(0, k.length - suffix.length);
            if (aliasMap.has(base)) {
              targetKey = `${aliasMap.get(base)}${suffix}`;
            }
            break;
          }
        }
      }
      if (targetKey !== k) changed = true;
      let nextVal = v;
      if (isConfirm && v && typeof v === 'object') {
        const updatedScope = v.scope_key ? rewriteScope(v.scope_key) : v.scope_key;
        let targets = v.targets;
        let targetsChanged = false;
        if (oldPath && newPath && Array.isArray(v.targets)) {
          targets = v.targets.map((t) => {
            if (t && typeof t === 'object' && normAbsPath(t.notebook_root || '', state.homeDir) === oldPath) {
              targetsChanged = true;
              return { ...t, notebook_root: newPath };
            }
            return t;
          });
        }
        const onlyNb = oldPath && newPath && v.only_nb_root && normAbsPath(v.only_nb_root, state.homeDir) === oldPath
          ? newPath
          : v.only_nb_root;
        if (updatedScope !== v.scope_key || targetsChanged || onlyNb !== v.only_nb_root) {
          nextVal = { ...v, scope_key: updatedScope, targets, only_nb_root: onlyNb };
          changed = true;
        }
      } else if (isNotice && v && typeof v === 'object') {
        const updatedScope = typeof v.scope === 'string' ? rewriteScope(v.scope) : v.scope;
        let nextParams = v.params;
        if (oldPath && newPath && v.params && typeof v.params === 'object' && v.params.notebook_root && normAbsPath(v.params.notebook_root, state.homeDir) === oldPath) {
          nextParams = { ...v.params, notebook_root: newPath };
        }
        if (updatedScope !== v.scope || nextParams !== v.params) {
          nextVal = { ...v, scope: updatedScope, params: nextParams };
          changed = true;
        }
      }
      return [targetKey, nextVal];
    };

    // Pass 1: keep all non-aliased / target keys in place.
    for (const [k, v] of Object.entries(obj)) {
      const [targetKey, nextVal] = resolveTargetAndVal(k, v);
      if (targetKey === k) {
        next[targetKey] = nextVal;
      } else {
        pendingAliased.push([targetKey, nextVal]);
      }
    }

    // Pass 2: merge aliased keys without clobbering existing target-key entries.
    for (const [targetKey, nextVal] of pendingAliased) {
      if (!Object.hasOwn(next, targetKey)) {
        next[targetKey] = nextVal;
        continue;
      }
      if (isResult && nextVal && typeof nextVal === 'object' && next[targetKey] && typeof next[targetKey] === 'object') {
        const curEntry = next[targetKey];
        if (nextVal.protocols && typeof nextVal.protocols === 'object') {
          const curProtos = curEntry.protocols && typeof curEntry.protocols === 'object' ? { ...curEntry.protocols } : {};
          let protoMerged = false;
          for (const [pKey, pVal] of Object.entries(nextVal.protocols)) {
            if (!Object.hasOwn(curProtos, pKey)) {
              curProtos[pKey] = pVal;
              protoMerged = true;
            }
          }
          if (protoMerged) {
            next[targetKey] = { ...curEntry, protocols: curProtos };
          }
        }
      } else if (isConn && nextVal && typeof nextVal === 'object' && next[targetKey] && typeof next[targetKey] === 'object') {
        const curTime = String(next[targetKey].time || '');
        const incTime = String(nextVal.time || '');
        if (!curTime && incTime) {
          next[targetKey] = nextVal;
        }
      }
    }
    return [next, changed];
  };

  const mergeTombstoneBuckets = (existingBucket, incomingBucket) => {
    const out = {};
    for (const bucket of [existingBucket, incomingBucket]) {
      if (!bucket || typeof bucket !== 'object' || Array.isArray(bucket)) continue;
      for (const [itemKey, rawEntry] of Object.entries(bucket)) {
        if (!rawEntry || typeof rawEntry !== 'object') continue;
        const hash = typeof rawEntry.hash === 'string' ? rawEntry.hash : '';
        if (!hash) continue;
        const tsNum = Number(rawEntry.ts);
        const ts = Number.isFinite(tsNum) ? tsNum : 0;
        const prev = out[itemKey];
        if (!prev || ts >= prev.ts) {
          out[itemKey] = { hash, ts };
        }
      }
    }
    const entries = Object.entries(out);
    if (entries.length > MAX_TOMBSTONES_PER_NB) {
      entries.sort((a, b) => Number((b[1] && b[1].ts) || 0) - Number((a[1] && a[1].ts) || 0));
      return Object.fromEntries(entries.slice(0, MAX_TOMBSTONES_PER_NB));
    }
    return out;
  };

  const mergeBaselineMaps = (existingMap, incomingMap, existingTs = null, incomingTs = null) => {
    const merged = existingMap && typeof existingMap === 'object' && !Array.isArray(existingMap) ? { ...existingMap } : {};
    const mergedTs = existingTs && typeof existingTs === 'object' && !Array.isArray(existingTs) ? { ...existingTs } : {};
    if (!incomingMap || typeof incomingMap !== 'object' || Array.isArray(incomingMap)) {
      return { merged, mergedTs };
    }
    const incTsObj = incomingTs && typeof incomingTs === 'object' && !Array.isArray(incomingTs) ? incomingTs : {};
    for (const [itemKey, rawHash] of Object.entries(incomingMap)) {
      if (typeof rawHash !== 'string' || !rawHash) continue;
      const incT = Number(incTsObj[itemKey]) || 0;
      const hasCur = Object.hasOwn(merged, itemKey) && typeof merged[itemKey] === 'string' && Boolean(merged[itemKey]);
      if (!hasCur) {
        merged[itemKey] = rawHash;
        if (incT > 0) mergedTs[itemKey] = incT;
        continue;
      }
      const curHash = merged[itemKey];
      const curT = Number(mergedTs[itemKey]) || 0;
      if (curHash === rawHash) {
        const bestT = Math.max(curT, incT);
        if (bestT > 0) mergedTs[itemKey] = bestT;
        continue;
      }
      if (curT > 0 && incT > 0 && curT !== incT) {
        merged[itemKey] = incT > curT ? rawHash : curHash;
        mergedTs[itemKey] = Math.max(curT, incT);
      } else {
        // Conflicting baseline hashes without clear ordering: drop the item from baseline so
        // the next 3-way sync preserves both local and remote copies safely.
        delete merged[itemKey];
        delete mergedTs[itemKey];
      }
    }
    return { merged, mergedTs };
  };

  const buildUpdatedIdMap = (baseMapObj, pairs = [], { oldPath = '' } = {}) => {
    const next = {
      by_id: { ...((baseMapObj && baseMapObj.by_id) || {}) },
      by_path: { ...((baseMapObj && baseMapObj.by_path) || {}) },
    };
    const normOld = oldPath ? normAbsPath(oldPath, state.homeDir) : '';
    for (const [rawId, rawPath] of pairs) {
      const id = String(rawId || '').trim();
      const np = normAbsPath(rawPath, state.homeDir);
      if (!id || !np || id === np) continue;
      const prevPath = next.by_id[id];
      if (prevPath && prevPath !== np && next.by_path[prevPath] === id) {
        delete next.by_path[prevPath];
      }
      if (normOld && normOld !== np && next.by_path[normOld] === id) {
        delete next.by_path[normOld];
      }
      const prevOwner = next.by_path[np];
      if (prevOwner && prevOwner !== id && next.by_id[prevOwner] === np) {
        delete next.by_id[prevOwner];
      }
      next.by_id[id] = np;
      next.by_path[np] = id;
    }
    const prevStr = JSON.stringify({
      by_id: (baseMapObj && baseMapObj.by_id) || {},
      by_path: (baseMapObj && baseMapObj.by_path) || {},
    });
    return { next, changed: JSON.stringify(next) !== prevStr };
  };

  const applyUiScopeAliases = (
    uiAlias,
    {
      oldPath = '',
      newPath = '',
      persist = false,
      preMigratedNbConfigs = false,
      preMigratedGlobal = false,
      extraDirty = null,
    } = {}
  ) => {
    const rpc = getRpc();
    const aliasMap = uiAlias instanceof Map ? uiAlias : new Map();
    const dirty = extraDirty && typeof extraDirty === 'object' ? { ...extraDirty } : {};
    const idToCurrentPath = new Map();
    for (const kn of state.knownNotebooks) {
      if (kn && kn.id && kn.path) idToCurrentPath.set(String(kn.id), kn.path);
    }

    const ensureSelectedPathReplaced = (cfg) => {
      if (!cfg || typeof cfg !== 'object' || !Array.isArray(cfg.selected_notebooks)) return [cfg, false];
      let mod = false;
      const nextSel = [];
      const seen = new Set();
      for (const item of cfg.selected_notebooks) {
        let mapped = item;
        if (oldPath && newPath && mapped === oldPath) {
          mapped = newPath;
        } else if (aliasMap.has(mapped)) {
          const targetId = aliasMap.get(mapped);
          mapped = idToCurrentPath.get(targetId) || newPath || mapped;
        }
        if (mapped !== item) mod = true;
        if (mapped && !seen.has(mapped)) {
          seen.add(mapped);
          nextSel.push(mapped);
        } else if (seen.has(mapped)) {
          mod = true;
        }
      }
      if (!mod) return [cfg, false];
      return [{ ...cfg, selected_notebooks: nextSel }, true];
    };

    const [migratedNbCfgsRaw, nbCfgsKeyChanged] = rewriteScopedAliasMap(state.notebookConfigs, aliasMap);
    const candNotebookConfigs = {};
    let nbCfgsSelChanged = false;
    if (migratedNbCfgsRaw && typeof migratedNbCfgsRaw === 'object') {
      for (const [k, cfg] of Object.entries(migratedNbCfgsRaw)) {
        const [nextCfg, selChanged] = ensureSelectedPathReplaced(cfg);
        if (selChanged) nbCfgsSelChanged = true;
        candNotebookConfigs[k] = nextCfg;
      }
    }
    if (nbCfgsKeyChanged || nbCfgsSelChanged || preMigratedNbConfigs) {
      const toStore = {};
      for (const [k, v] of Object.entries(candNotebookConfigs)) {
        toStore[k] = encodeConfigSelected(v);
      }
      dirty.notebook_configs = toStore;
    }

    const [candStoredGlobal, sharedSelChanged] = ensureSelectedPathReplaced(state.storedGlobal);
    const [candConfig] = ensureSelectedPathReplaced(state.config);
    const [candSavedConfig] = ensureSelectedPathReplaced(state.savedConfig);
    if ((sharedSelChanged || preMigratedGlobal) && candStoredGlobal) {
      dirty.config = encodeConfigSelected(candStoredGlobal);
    }

    const [migratedRes, resChanged] = rewriteScopedAliasMap(state.notebookResults, aliasMap, { isResult: true });
    if (resChanged) {
      dirty.notebook_results = migratedRes;
    }

    const [migratedConfs, confsChanged] = rewriteScopedAliasMap(state.pendingConfirms, aliasMap, {
      isConfirm: true,
      oldPath,
      newPath,
    });
    if (confsChanged) {
      dirty.pending_confirms = migratedConfs;
    }

    const [migratedConn, connChanged] = rewriteScopedAliasMap(state.connStates, aliasMap, { isConn: true });
    if (connChanged) {
      dirty.conn_states = migratedConn;
    }

    let migratedNotices = state.pendingNotices;
    let noticesChanged = false;
    if (state.supportsSystem) {
      [migratedNotices, noticesChanged] = rewriteScopedAliasMap(state.pendingNotices, aliasMap, {
        isNotice: true,
        oldPath,
        newPath,
      });
      if (noticesChanged) {
        dirty.pending_notices = migratedNotices;
      }
    }

    const commitInMemory = (persistedKeys = null) => {
      const has = (k) => !persistedKeys || persistedKeys.has(k);
      if ((nbCfgsKeyChanged || nbCfgsSelChanged || preMigratedNbConfigs) && has('notebook_configs')) {
        state.notebookConfigs = candNotebookConfigs;
      }
      if ((sharedSelChanged || preMigratedGlobal) && has('config')) {
        state.storedGlobal = candStoredGlobal;
        state.config = candConfig;
        state.savedConfig = candSavedConfig;
      }
      if (resChanged && has('notebook_results')) {
        state.notebookResults = migratedRes;
      }
      if (confsChanged && has('pending_confirms')) {
        state.pendingConfirms = migratedConfs;
        state.savedPendingConfirms = { ...migratedConfs };
        state.pendingConfirm = getPendingConfirm();
      }
      if (connChanged && has('conn_states')) {
        state.connStates = migratedConn;
      }
      if (noticesChanged && has('pending_notices')) {
        state.pendingNotices = migratedNotices;
      }
      if (Object.hasOwn(dirty, 'sync_meta') && has('sync_meta')) {
        state.syncMeta = dirty.sync_meta;
      }
      if (Object.hasOwn(dirty, NOTEBOOK_ID_MAP_KEY) && has(NOTEBOOK_ID_MAP_KEY)) {
        const payload = dirty[NOTEBOOK_ID_MAP_KEY];
        state.notebookIdMap = {
          by_id: { ...(payload.by_id || {}) },
          by_path: { ...(payload.by_path || {}) },
        };
      }
    };

    if (persist && Object.keys(dirty).length > 0) {
      if (state.supportsSystem) {
        try {
          storageSetMany(rpc, dirty);
          commitInMemory();
        } catch (_err) {
          return false;
        }
      } else {
        const order = [
          'sync_meta',
          NOTEBOOK_ID_MAP_KEY,
          'notebook_configs',
          'config',
          'notebook_results',
          'pending_confirms',
          'conn_states',
          'pending_notices',
        ];
        const written = new Set();
        try {
          for (const k of order) {
            if (Object.hasOwn(dirty, k)) {
              storageSet(rpc, k, dirty[k]);
              written.add(k);
            }
          }
          commitInMemory(written);
        } catch (_err) {
          commitInMemory(written);
          return false;
        }
      }
    } else if (!persist) {
      commitInMemory();
    }
    return true;
  };

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

  const refreshKnownNotebooks = ({ claimLegacy = true } = {}) => {
    const entries = [];
    const seen = new Set();
    const activeNorm = normAbsPath(state.notebookRoot, state.homeDir);
    const byPathMap = (state.notebookIdMap && state.notebookIdMap.by_path) || {};

    const addEntry = (
      pathRaw,
      nameRaw = '',
      active = false,
      idRaw = '',
      prevRaw = [],
      allowReverseLookup = false,
      identityVerifiedRaw = undefined,
      rootIdentityRaw = ''
    ) => {
      const norm = normAbsPath(pathRaw, state.homeDir);
      if (!norm || seen.has(norm)) return;
      seen.add(norm);
      const label = String(nameRaw || '').trim() || posixBasename(norm) || norm;
      let id = String(idRaw || '').trim();
      if (!id && allowReverseLookup && typeof byPathMap[norm] === 'string' && byPathMap[norm]) {
        id = String(byPathMap[norm]).trim();
      }
      const prevPaths = [];
      const seenPrev = new Set();
      if (Array.isArray(prevRaw)) {
        for (const p of prevRaw) {
          const np = normAbsPath(p, state.homeDir);
          if (np && np !== norm && !seenPrev.has(np)) {
            seenPrev.add(np);
            prevPaths.push(np);
          }
        }
      }
      const entry = { path: norm, name: label, active: Boolean(active), previous_paths: prevPaths };
      if (id) entry.id = id;
      if (typeof identityVerifiedRaw === 'boolean') entry.identity_verified = identityVerifiedRaw;
      const rootIdent = String(rootIdentityRaw || '').trim();
      if (rootIdent) entry.root_identity = rootIdent;
      entries.push(entry);
    };

    let hostListed = false;
    let hostProvidedIDs = false;
    let hostProvidedLiveIDs = false;
    try {
      const res = getRpc()('host.notebooks.list', {});
      if (res && Array.isArray(res.notebooks)) {
        hostListed = true;
        hostProvidedIDs = res.notebooks.some((item) => item && typeof item === 'object' && String(item.id || '').trim() !== '');
        if (hostProvidedIDs) hostProvidedLiveIDs = true;
        for (const item of res.notebooks) {
          if (item && typeof item === 'object') {
            const p = item.path;
            addEntry(
              p,
              item.name,
              Boolean(item.active) || (Boolean(activeNorm) && normAbsPath(p, state.homeDir) === activeNorm),
              item.id,
              item.previous_paths,
              !hostProvidedIDs,
              typeof item.identity_verified === 'boolean' ? item.identity_verified : undefined,
              item.root_identity
            );
          }
        }
      }
    } catch (_err) {
      // Fallback to cached notebooks or live data_dir verification.
    }

    if (!hostListed) {
      for (const existing of state.knownNotebooks) {
        if (existing && typeof existing === 'object') {
          addEntry(
            existing.path,
            existing.name,
            Boolean(activeNorm) && normAbsPath(existing.path, state.homeDir) === activeNorm,
            existing.id,
            existing.previous_paths,
            true,
            undefined,
            ''
          );
        } else if (typeof existing === 'string') {
          addEntry(existing, '', Boolean(activeNorm) && normAbsPath(existing, state.homeDir) === activeNorm, '', [], true, undefined, '');
        }
      }
    }

    if (activeNorm) {
      addEntry(activeNorm, posixBasename(activeNorm) || activeNorm, true, '', [], !hostProvidedIDs, undefined, '');
    }

    for (const entry of entries) {
      if (!entry || !entry.path) continue;
      const needsLive =
        !entry.id ||
        typeof entry.identity_verified !== 'boolean' ||
        (entry.identity_verified === true && !entry.root_identity);
      if (!needsLive) continue;
      const live = queryLiveNotebookIdentity(getRpc(), entry.path, state.homeDir);
      if (!entry.id && live.id) {
        entry.id = live.id;
        hostProvidedLiveIDs = true;
      } else if (live.id) {
        hostProvidedLiveIDs = true;
      }
      if ((!Array.isArray(entry.previous_paths) || entry.previous_paths.length === 0) && live.previousPaths.length > 0) {
        entry.previous_paths = live.previousPaths;
      }
      if (live.verified && live.rootIdentity) {
        entry.identity_verified = true;
        entry.root_identity = live.rootIdentity;
      } else if (typeof entry.identity_verified !== 'boolean') {
        entry.identity_verified = false;
        if (live.rootIdentity && !entry.root_identity) {
          entry.root_identity = live.rootIdentity;
        }
      }
    }

    state.hostSupportsNotebookIds = hostProvidedLiveIDs;
    state.knownNotebooks = entries;
    if (claimLegacy && state._stateLoaded && state.hostSupportsNotebookIds) {
      claimLegacyPathBaselines({ persist: true });
    }
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

  const hasVerifiedBaseline = (
    nbRoot,
    { metaKey: targetMetaKey = '', aliases = [], legacyKeys = [], nbKeyVal = '' } = {}
  ) => {
    const cleanRoot = normAbsPath(nbRoot, state.homeDir);
    const effectiveNbKey = String(nbKeyVal || (cleanRoot ? nbKey(cleanRoot) : '') || '').trim();
    const allowLegacy =
      !state.hostSupportsNotebookIds &&
      (!effectiveNbKey || effectiveNbKey === 'default' || effectiveNbKey === cleanRoot);
    const candLegacy = allowLegacy && Array.isArray(legacyKeys) ? legacyKeys.filter(Boolean) : [];
    const rawBase = getBaseMap(targetMetaKey, ...(Array.isArray(aliases) ? aliases : []), ...candLegacy);
    const initMap = state.syncMeta && state.syncMeta[INITIALIZED_META_KEY];
    const primaryKeys = [targetMetaKey, ...(Array.isArray(aliases) ? aliases : []), ...candLegacy]
      .map((k) => String(k || '').trim())
      .filter(Boolean);
    const hasMeta = Boolean(
      (initMap && typeof initMap === 'object' && primaryKeys.some((k) => Boolean(initMap[k]))) ||
        Object.keys(rawBase).length > 0
    );
    if (!hasMeta) return false;
    const chk = verifyNotebookIdentity(cleanRoot || nbRoot, {
      metaKey: targetMetaKey,
      aliases,
      legacyKeys: candLegacy,
      nbKeyVal: effectiveNbKey,
      hasExistingBaseline: true,
    });
    return Boolean(chk && chk.identity_ok === true);
  };

  const claimLegacyPathBaselines = ({ persist = true, extraIdMap = null, rawCfg = null } = {}) => {
    if (!state.hostSupportsNotebookIds) {
      if (extraIdMap) {
        applyUiScopeAliases(new Map(), {
          persist,
          extraDirty: { [NOTEBOOK_ID_MAP_KEY]: extraIdMap },
        });
      }
      return false;
    }

    const rawMeta = state.syncMeta || {};
    const rawRootIds =
      rawMeta[ROOT_IDENTITIES_META_KEY] &&
      typeof rawMeta[ROOT_IDENTITIES_META_KEY] === 'object' &&
      !Array.isArray(rawMeta[ROOT_IDENTITIES_META_KEY])
        ? rawMeta[ROOT_IDENTITIES_META_KEY]
        : {};
    const rawFpMap =
      rawMeta[BASELINE_FINGERPRINTS_META_KEY] &&
      typeof rawMeta[BASELINE_FINGERPRINTS_META_KEY] === 'object' &&
      !Array.isArray(rawMeta[BASELINE_FINGERPRINTS_META_KEY])
        ? rawMeta[BASELINE_FINGERPRINTS_META_KEY]
        : {};

    const hasIdentityConflict = (keyOrPath, expectedRootId) => {
      if (rawRootIds[keyOrPath] && String(rawRootIds[keyOrPath]).trim() !== expectedRootId) {
        return true;
      }
      for (const [rk, rv] of Object.entries(rawRootIds)) {
        const parsed = parseNbMetaKey(rk);
        if (parsed && parsed.nb === keyOrPath && rv && String(rv).trim() !== expectedRootId) {
          return true;
        }
      }
      for (const [fk, fv] of Object.entries(rawFpMap)) {
        const parsed = parseNbMetaKey(fk);
        const nbId = fv && typeof fv === 'object' ? String(fv.nb_root_identity || '').trim() : '';
        if (parsed && parsed.nb === keyOrPath && nbId && nbId !== expectedRootId) {
          return true;
        }
      }
      return false;
    };

    const knownCurrentPaths = new Set();
    for (const kn of state.knownNotebooks) {
      if (kn && kn.path) knownCurrentPaths.add(kn.path);
    }

    const pathAlias = new Map();
    for (const kn of state.knownNotebooks) {
      if (!kn || !kn.id || !kn.path || kn.path === kn.id) continue;
      if (kn.identity_verified !== true || !kn.root_identity) continue;
      if (hasIdentityConflict(kn.id, kn.root_identity)) continue;
      if (!hasIdentityConflict(kn.path, kn.root_identity)) {
        pathAlias.set(kn.path, kn.id);
      }
    }
    for (const kn of state.knownNotebooks) {
      if (!kn || !kn.id || !kn.path || kn.path === kn.id) continue;
      if (kn.identity_verified !== true || !kn.root_identity) continue;
      if (hasIdentityConflict(kn.id, kn.root_identity)) continue;
      const prevList = Array.isArray(kn.previous_paths) ? kn.previous_paths : [];
      for (const rawPrev of prevList) {
        const prevPath = normAbsPath(rawPrev, state.homeDir);
        if (!prevPath || prevPath === kn.id || knownCurrentPaths.has(prevPath) || pathAlias.has(prevPath)) {
          continue;
        }
        if (!hasIdentityConflict(prevPath, kn.root_identity)) {
          pathAlias.set(prevPath, kn.id);
        }
      }
    }

    const hasGlobalMigrationFlag = Object.hasOwn(rawMeta, LEGACY_PATH_MIGRATED_KEY);
    if (pathAlias.size === 0 && !hasGlobalMigrationFlag) {
      if (extraIdMap) {
        applyUiScopeAliases(new Map(), {
          persist,
          extraDirty: { [NOTEBOOK_ID_MAP_KEY]: extraIdMap },
        });
      }
      return false;
    }

    const rawTsAll =
      rawMeta[BASE_TIMESTAMPS_META_KEY] &&
      typeof rawMeta[BASE_TIMESTAMPS_META_KEY] === 'object' &&
      !Array.isArray(rawMeta[BASE_TIMESTAMPS_META_KEY])
        ? rawMeta[BASE_TIMESTAMPS_META_KEY]
        : {};
    const nextMeta = {};
    const nextTsAll = {};
    const claimedTargetKeys = new Set();
    let metaChanged = hasGlobalMigrationFlag;

    const aliasedEntries = [];
    for (const [mk, mv] of Object.entries(rawMeta)) {
      if (isReservedSyncMetaKey(mk)) continue;
      if (!mv || typeof mv !== 'object' || Array.isArray(mv)) {
        nextMeta[mk] = mv;
        continue;
      }
      const parsed = parseNbMetaKey(mk);
      const newNb = parsed ? pathAlias.get(parsed.nb) : '';
      if (newNb && newNb !== parsed.nb) {
        const newMk = `nb:${newNb}${parsed.rest}`;
        aliasedEntries.push([mk, newMk, mv]);
        metaChanged = true;
      } else {
        nextMeta[mk] = { ...mv };
        if (rawTsAll[mk] && typeof rawTsAll[mk] === 'object' && !Array.isArray(rawTsAll[mk])) {
          nextTsAll[mk] = { ...rawTsAll[mk] };
        }
      }
    }
    for (const [mk, newMk, mv] of aliasedEntries) {
      claimedTargetKeys.add(newMk);
      const incTs = rawTsAll[mk] && typeof rawTsAll[mk] === 'object' && !Array.isArray(rawTsAll[mk]) ? rawTsAll[mk] : null;
      if (!Object.hasOwn(nextMeta, newMk)) {
        nextMeta[newMk] = { ...mv };
        if (incTs) nextTsAll[newMk] = { ...incTs };
      } else {
        const { merged, mergedTs } = mergeBaselineMaps(nextMeta[newMk], mv, nextTsAll[newMk], incTs);
        nextMeta[newMk] = merged;
        if (Object.keys(mergedTs).length > 0) nextTsAll[newMk] = mergedTs;
        else delete nextTsAll[newMk];
      }
    }
    if (Object.keys(nextTsAll).length > 0) {
      nextMeta[BASE_TIMESTAMPS_META_KEY] = nextTsAll;
    }

    if (rawMeta[INITIALIZED_META_KEY] && typeof rawMeta[INITIALIZED_META_KEY] === 'object' && !Array.isArray(rawMeta[INITIALIZED_META_KEY])) {
      const initOut = {};
      const pendingInit = [];
      for (const [ik, iv] of Object.entries(rawMeta[INITIALIZED_META_KEY])) {
        const parsed = parseNbMetaKey(ik);
        const newNb = parsed ? pathAlias.get(parsed.nb) : '';
        if (newNb && newNb !== parsed.nb) {
          pendingInit.push([ik, `nb:${newNb}${parsed.rest}`, iv]);
          metaChanged = true;
        } else {
          initOut[ik] = iv;
        }
      }
      for (const [, newIk, iv] of pendingInit) {
        claimedTargetKeys.add(newIk);
        if (initOut[newIk] || iv) initOut[newIk] = Boolean(initOut[newIk] || iv);
      }
      nextMeta[INITIALIZED_META_KEY] = initOut;
    }

    if (rawMeta[TOMBSTONES_META_KEY] && typeof rawMeta[TOMBSTONES_META_KEY] === 'object' && !Array.isArray(rawMeta[TOMBSTONES_META_KEY])) {
      const tombsOut = {};
      const pendingTombs = [];
      for (const [tk, tv] of Object.entries(rawMeta[TOMBSTONES_META_KEY])) {
        const newTk = pathAlias.get(tk);
        if (newTk && newTk !== tk) {
          pendingTombs.push([newTk, tv]);
          metaChanged = true;
        } else {
          tombsOut[tk] = mergeTombstoneBuckets(tombsOut[tk], tv);
        }
      }
      for (const [newTk, tv] of pendingTombs) {
        tombsOut[newTk] = mergeTombstoneBuckets(tombsOut[newTk], tv);
      }
      nextMeta[TOMBSTONES_META_KEY] = tombsOut;
    }

    if (rawMeta[LAYOUTS_META_KEY] && typeof rawMeta[LAYOUTS_META_KEY] === 'object' && !Array.isArray(rawMeta[LAYOUTS_META_KEY])) {
      const layoutsOut = {};
      for (const [lk, lv] of Object.entries(rawMeta[LAYOUTS_META_KEY])) {
        if (!lv || typeof lv !== 'object' || Array.isArray(lv)) {
          layoutsOut[lk] = lv;
          continue;
        }
        const bOut = {};
        const pendingBindings = [];
        for (const [bk, bVal] of Object.entries(lv)) {
          const newBk = pathAlias.get(bk);
          if (newBk && newBk !== bk) {
            pendingBindings.push([newBk, bVal]);
            metaChanged = true;
          } else {
            bOut[bk] = bVal;
          }
        }
        for (const [newBk, bVal] of pendingBindings) {
          if (!Object.hasOwn(bOut, newBk)) bOut[newBk] = bVal;
        }
        layoutsOut[lk] = bOut;
      }
      nextMeta[LAYOUTS_META_KEY] = layoutsOut;
    }

    const idOut = {};
    for (const [rk, rv] of Object.entries(rawRootIds)) {
      const parsed = parseNbMetaKey(rk);
      const matchedAlias = parsed ? pathAlias.get(parsed.nb) : pathAlias.get(rk);
      if (matchedAlias && matchedAlias !== (parsed ? parsed.nb : rk)) {
        metaChanged = true;
        continue;
      }
      if (claimedTargetKeys.has(rk)) {
        metaChanged = true;
        continue;
      }
      idOut[rk] = rv;
    }
    if (Object.keys(idOut).length > 0) {
      nextMeta[ROOT_IDENTITIES_META_KEY] = idOut;
    }

    const fpOut = {};
    for (const [fk, fv] of Object.entries(rawFpMap)) {
      const parsed = parseNbMetaKey(fk);
      const matchedAlias = parsed ? pathAlias.get(parsed.nb) : '';
      if ((matchedAlias && matchedAlias !== parsed.nb) || claimedTargetKeys.has(fk)) {
        metaChanged = true;
        continue;
      }
      fpOut[fk] = fv && typeof fv === 'object' && !Array.isArray(fv) ? { ...fv } : fv;
    }
    if (Object.keys(fpOut).length > 0) {
      nextMeta[BASELINE_FINGERPRINTS_META_KEY] = fpOut;
    }

    let preNb = false;
    for (const [k, v] of Object.entries(state.notebookConfigs)) {
      if (pathAlias.has(k) || (v && Array.isArray(v.selected_notebooks) && v.selected_notebooks.some((x) => pathAlias.has(normAbsPath(x, state.homeDir))))) {
        preNb = true;
        break;
      }
    }
    const selSrc = rawCfg || state.storedGlobal;
    const preGl = Boolean(
      selSrc && Array.isArray(selSrc.selected_notebooks) && selSrc.selected_notebooks.some((x) => pathAlias.has(normAbsPath(x, state.homeDir)))
    );
    const extraDirty = {};
    if (metaChanged) extraDirty.sync_meta = nextMeta;
    if (extraIdMap) extraDirty[NOTEBOOK_ID_MAP_KEY] = extraIdMap;
    applyUiScopeAliases(pathAlias, {
      persist,
      preMigratedNbConfigs: preNb,
      preMigratedGlobal: preGl,
      extraDirty: Object.keys(extraDirty).length > 0 ? extraDirty : null,
    });
    return metaChanged;
  };

  const loadState = () => {
    state._stateLoaded = false;
    const rpc = getRpc();
    const idMapRes = storageGet(rpc, NOTEBOOK_ID_MAP_KEY);
    const rawMap = idMapRes.found && idMapRes.value && typeof idMapRes.value === 'object' && !Array.isArray(idMapRes.value)
      ? idMapRes.value
      : null;
    state.notebookIdMap = {
      by_id: rawMap && rawMap.by_id && typeof rawMap.by_id === 'object' ? { ...rawMap.by_id } : {},
      by_path: rawMap && rawMap.by_path && typeof rawMap.by_path === 'object' ? { ...rawMap.by_path } : {},
    };

    refreshKnownNotebooks();

    const opts = normOpts();

    const nbCfgsRes = storageGet(rpc, 'notebook_configs');
    if (nbCfgsRes.found && nbCfgsRes.value && typeof nbCfgsRes.value === 'object' && !Array.isArray(nbCfgsRes.value)) {
      state.notebookConfigs = {};
      for (const [k, v] of Object.entries(nbCfgsRes.value)) {
        if (v && typeof v === 'object' && !Array.isArray(v)) {
          state.notebookConfigs[String(k)] = loadConfigRecord(decodeConfigSelected(v), opts);
        }
      }
    } else {
      state.notebookConfigs = {};
    }

    const cfgRes = storageGet(rpc, 'config');
    const rawCfg = cfgRes.found && cfgRes.value && typeof cfgRes.value === 'object' && !Array.isArray(cfgRes.value)
      ? cfgRes.value
      : null;
    state.storedGlobal = rawCfg !== null ? loadConfigRecord(decodeConfigSelected(rawCfg), opts) : null;
    if (state.storedGlobal && !Object.hasOwn(rawCfg, 'selected_notebooks')) {
      delete state.storedGlobal.selected_notebooks;
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

    const connRes = storageGet(rpc, 'conn_states');
    state.connStates = connRes.found && connRes.value && typeof connRes.value === 'object' && !Array.isArray(connRes.value)
      ? { ...connRes.value }
      : {};

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

    const idPairs = [];
    if (state.hostSupportsNotebookIds) {
      for (const kn of state.knownNotebooks) {
        if (kn && kn.id && kn.path && kn.path !== kn.id) {
          idPairs.push([kn.id, kn.path]);
        }
      }
    }
    const { next: nextIdMap, changed: idMapChanged } = buildUpdatedIdMap(state.notebookIdMap, idPairs);
    state._stateLoaded = true;
    claimLegacyPathBaselines({
      persist: true,
      extraIdMap: idMapChanged ? nextIdMap : null,
      rawCfg,
    });

    const key = nbKey();
    const activeNorm = normAbsPath(state.notebookRoot, state.homeDir);
    const activeNbRecord =
      (Object.hasOwn(state.notebookConfigs, key) && state.notebookConfigs[key]) ||
      (!state.hostSupportsNotebookIds &&
        key === activeNorm &&
        activeNorm &&
        Object.hasOwn(state.notebookConfigs, activeNorm) &&
        state.notebookConfigs[activeNorm]) ||
      null;

    if (!state.supportsMultiNotebook) {
      if (activeNbRecord) {
        state.config = { ...activeNbRecord };
      } else if (rawCfg !== null && (!Array.isArray(rawCfg.selected_notebooks) || rawCfg.selected_notebooks.length === 0)) {
        state.config = { ...state.storedGlobal };
      } else {
        state.config = cloneDefaultConfig();
      }
      if (state.notebookRoot) {
        state.config.selected_notebooks = [activeNorm];
      }
    } else if (rawCfg !== null && Object.hasOwn(rawCfg, 'selected_notebooks')) {
      state.config = { ...state.storedGlobal };
    } else if (activeNbRecord) {
      state.config = { ...activeNbRecord };
      if (state.notebookRoot) {
        state.config.selected_notebooks = [activeNorm];
      }
    } else if (rawCfg !== null) {
      state.config = { ...state.storedGlobal };
      state.config.selected_notebooks = state.notebookRoot ? [activeNorm] : [];
    } else {
      state.config = cloneDefaultConfig();
      if (state.notebookRoot) {
        state.config.selected_notebooks = [activeNorm];
      }
    }

    state.pendingConfirm = getPendingConfirm();
    state.savedPendingConfirms = { ...state.pendingConfirms };
    state.savedConfig = { ...state.config };
    return state;
  };

  const verifyNotebookIdentity = (
    nbRoot,
    {
      metaKey: targetMetaKey = '',
      aliases = [],
      legacyKeys = [],
      nbKeyVal = '',
      expectedRootIdentity = '',
      hasExistingBaseline = false,
    } = {}
  ) => {
    const cleanRoot = normAbsPath(nbRoot, state.homeDir);
    if (!cleanRoot) {
      return {
        identity_ok: false,
        verified: false,
        root_identity: '',
        recorded_root_identity: '',
        live_id: '',
        reason: 'missing_root',
      };
    }
    const live = queryLiveNotebookIdentity(getRpc(), cleanRoot, state.homeDir);
    if (!live.verified || !live.rootIdentity) {
      return {
        identity_ok: false,
        verified: false,
        root_identity: live.rootIdentity || '',
        recorded_root_identity: '',
        live_id: live.id || '',
        reason: 'host_unverified',
      };
    }
    const nb = String(nbKeyVal || nbKey(cleanRoot) || '').trim();
    if (nb && nb !== cleanRoot && nb !== 'default' && live.id && live.id !== nb) {
      return {
        identity_ok: false,
        verified: true,
        root_identity: live.rootIdentity,
        recorded_root_identity: '',
        live_id: live.id,
        reason: 'id_mismatch',
      };
    }
    const expRoot = String(expectedRootIdentity || '').trim();
    if (expRoot && live.rootIdentity !== expRoot) {
      return {
        identity_ok: false,
        verified: true,
        root_identity: live.rootIdentity,
        recorded_root_identity: expRoot,
        live_id: live.id,
        reason: 'root_changed',
      };
    }

    const rawRootIds =
      state.syncMeta &&
      state.syncMeta[ROOT_IDENTITIES_META_KEY] &&
      typeof state.syncMeta[ROOT_IDENTITIES_META_KEY] === 'object' &&
      !Array.isArray(state.syncMeta[ROOT_IDENTITIES_META_KEY])
        ? state.syncMeta[ROOT_IDENTITIES_META_KEY]
        : {};
    const primaryKeys = [targetMetaKey, ...(Array.isArray(aliases) ? aliases : []), ...(Array.isArray(legacyKeys) ? legacyKeys : [])]
      .map((k) => String(k || '').trim())
      .filter(Boolean);
    const recordedPrimary = [];
    for (const pk of primaryKeys) {
      const val = String(rawRootIds[pk] || '').trim();
      if (val && !recordedPrimary.includes(val)) recordedPrimary.push(val);
    }
    if (recordedPrimary.some((val) => val !== live.rootIdentity)) {
      return {
        identity_ok: false,
        verified: true,
        root_identity: live.rootIdentity,
        recorded_root_identity: recordedPrimary[0] || '',
        live_id: live.id,
        reason: 'baseline_identity_mismatch',
      };
    }
    if (hasExistingBaseline && primaryKeys.length > 0 && recordedPrimary.length === 0) {
      return {
        identity_ok: false,
        verified: true,
        root_identity: live.rootIdentity,
        recorded_root_identity: '',
        live_id: live.id,
        reason: 'missing_baseline_identity',
      };
    }

    const secondaryVals = [];
    const addSec = (v) => {
      const s = String(v || '').trim();
      if (s && !secondaryVals.includes(s)) secondaryVals.push(s);
    };
    if (nb) {
      addSec(rawRootIds[nb]);
    }
    if (live.id) {
      addSec(rawRootIds[live.id]);
    }
    if (!nb || nb === cleanRoot) {
      addSec(rawRootIds[cleanRoot]);
    }
    if (secondaryVals.some((val) => val !== live.rootIdentity)) {
      return {
        identity_ok: false,
        verified: true,
        root_identity: live.rootIdentity,
        recorded_root_identity: secondaryVals.find((val) => val !== live.rootIdentity) || '',
        live_id: live.id,
        reason: 'map_identity_mismatch',
      };
    }

    return {
      identity_ok: true,
      verified: true,
      root_identity: live.rootIdentity,
      recorded_root_identity: recordedPrimary[0] || expRoot || live.rootIdentity,
      live_id: live.id,
      reason: '',
    };
  };

  const commitNotebookBaseline = (
    targetMetaKey,
    nextBaseMap,
    {
      rootIdentity = '',
      verified = false,
      nbKeyVal = '',
      nbRoot = '',
      tsNow = Date.now(),
      markInitialized = true,
      partial = false,
      deletedKeys = [],
      targetIdentity = '',
      updateTargetIdentity = false,
      protocol = '',
      staleKeys = [],
    } = {}
  ) => {
    const mk = String(targetMetaKey || '').trim();
    const rootIdent = String(rootIdentity || '').trim();
    if (!mk) return false;
    const prevBase =
      state.syncMeta[mk] && typeof state.syncMeta[mk] === 'object' && !Array.isArray(state.syncMeta[mk])
        ? state.syncMeta[mk]
        : {};
    if (partial) {
      if (verified !== true) return false;
      const merged = { ...prevBase };
      const patch = nextBaseMap && typeof nextBaseMap === 'object' && !Array.isArray(nextBaseMap) ? nextBaseMap : {};
      for (const [k, v] of Object.entries(patch)) {
        if (typeof v === 'string' && v) {
          merged[k] = v;
        }
      }
      for (const dk of Array.isArray(deletedKeys) ? deletedKeys : []) {
        delete merged[dk];
      }
      state.syncMeta[mk] = merged;

      const allTs =
        state.syncMeta[BASE_TIMESTAMPS_META_KEY] &&
        typeof state.syncMeta[BASE_TIMESTAMPS_META_KEY] === 'object' &&
        !Array.isArray(state.syncMeta[BASE_TIMESTAMPS_META_KEY])
          ? { ...state.syncMeta[BASE_TIMESTAMPS_META_KEY] }
          : {};
      const prevKeyTs = allTs[mk] && typeof allTs[mk] === 'object' && !Array.isArray(allTs[mk]) ? allTs[mk] : {};
      const nextKeyTs = {};
      const nowVal = Number.isFinite(Number(tsNow)) && Number(tsNow) > 0 ? Number(tsNow) : Date.now();
      for (const [itemK, itemH] of Object.entries(merged)) {
        if (typeof itemH !== 'string' || !itemH) continue;
        if (prevBase[itemK] === itemH && Number.isFinite(Number(prevKeyTs[itemK])) && Number(prevKeyTs[itemK]) > 0) {
          nextKeyTs[itemK] = Number(prevKeyTs[itemK]);
        } else {
          nextKeyTs[itemK] = nowVal;
        }
      }
      allTs[mk] = nextKeyTs;
      state.syncMeta[BASE_TIMESTAMPS_META_KEY] = allTs;
      const cleanTargetIdent = String(targetIdentity || '').trim();
      if (updateTargetIdentity && cleanTargetIdent) {
        const fpAll =
          state.syncMeta[BASELINE_FINGERPRINTS_META_KEY] &&
          typeof state.syncMeta[BASELINE_FINGERPRINTS_META_KEY] === 'object' &&
          !Array.isArray(state.syncMeta[BASELINE_FINGERPRINTS_META_KEY])
            ? { ...state.syncMeta[BASELINE_FINGERPRINTS_META_KEY] }
            : {};
        const curFp = fpAll[mk] && typeof fpAll[mk] === 'object' && !Array.isArray(fpAll[mk]) ? fpAll[mk] : null;
        if (curFp && (!rootIdent || !curFp.nb_root_identity || curFp.nb_root_identity === rootIdent)) {
          fpAll[mk] = {
            nb_root_identity: curFp.nb_root_identity || rootIdent,
            target_identity: cleanTargetIdent,
          };
          state.syncMeta[BASELINE_FINGERPRINTS_META_KEY] = fpAll;
        }
      }
      // Preserve any older rootless baseline untouched until a full sync verifies everything.
      return true;
    }

    if (verified !== true || !rootIdent) return false;
    const cleanBase = nextBaseMap && typeof nextBaseMap === 'object' && !Array.isArray(nextBaseMap) ? { ...nextBaseMap } : {};
    state.syncMeta[mk] = cleanBase;

    const allTs =
      state.syncMeta[BASE_TIMESTAMPS_META_KEY] &&
      typeof state.syncMeta[BASE_TIMESTAMPS_META_KEY] === 'object' &&
      !Array.isArray(state.syncMeta[BASE_TIMESTAMPS_META_KEY])
        ? { ...state.syncMeta[BASE_TIMESTAMPS_META_KEY] }
        : {};
    const prevKeyTs = allTs[mk] && typeof allTs[mk] === 'object' && !Array.isArray(allTs[mk]) ? allTs[mk] : {};
    const nextKeyTs = {};
    for (const [itemK, itemH] of Object.entries(cleanBase)) {
      if (typeof itemH !== 'string' || !itemH) continue;
      if (prevBase[itemK] === itemH && Number.isFinite(Number(prevKeyTs[itemK])) && Number(prevKeyTs[itemK]) > 0) {
        nextKeyTs[itemK] = Number(prevKeyTs[itemK]);
      } else {
        nextKeyTs[itemK] = Number.isFinite(Number(tsNow)) && Number(tsNow) > 0 ? Number(tsNow) : Date.now();
      }
    }
    allTs[mk] = nextKeyTs;
    state.syncMeta[BASE_TIMESTAMPS_META_KEY] = allTs;

    const idMapMeta =
      state.syncMeta[ROOT_IDENTITIES_META_KEY] &&
      typeof state.syncMeta[ROOT_IDENTITIES_META_KEY] === 'object' &&
      !Array.isArray(state.syncMeta[ROOT_IDENTITIES_META_KEY])
        ? { ...state.syncMeta[ROOT_IDENTITIES_META_KEY] }
        : {};
    idMapMeta[mk] = rootIdent;
    const nb = String(nbKeyVal || '').trim();
    const cleanRoot = normAbsPath(nbRoot, state.homeDir);
    if (nb && nb !== 'default') idMapMeta[nb] = rootIdent;
    if (cleanRoot) idMapMeta[cleanRoot] = rootIdent;
    state.syncMeta[ROOT_IDENTITIES_META_KEY] = idMapMeta;

    const fpAll =
      state.syncMeta[BASELINE_FINGERPRINTS_META_KEY] &&
      typeof state.syncMeta[BASELINE_FINGERPRINTS_META_KEY] === 'object' &&
      !Array.isArray(state.syncMeta[BASELINE_FINGERPRINTS_META_KEY])
        ? { ...state.syncMeta[BASELINE_FINGERPRINTS_META_KEY] }
        : {};
    const fpEntry = { nb_root_identity: rootIdent };
    const cleanTargetIdent = String(targetIdentity || '').trim();
    if (cleanTargetIdent) {
      fpEntry.target_identity = cleanTargetIdent;
    }
    fpAll[mk] = fpEntry;
    if (Array.isArray(staleKeys)) {
      for (const rawAlias of staleKeys) {
        const ak = String(rawAlias || '').trim();
        if (ak && ak !== mk) {
          delete fpAll[ak];
        }
      }
    }
    state.syncMeta[BASELINE_FINGERPRINTS_META_KEY] = fpAll;

    if (markInitialized) {
      const initMap = { ...(state.syncMeta[INITIALIZED_META_KEY] || {}) };
      initMap[mk] = true;
      state.syncMeta[INITIALIZED_META_KEY] = initMap;
    }

    if (!state.notebookIdMap || typeof state.notebookIdMap !== 'object') {
      state.notebookIdMap = { by_id: {}, by_path: {} };
    }
    if (!state.notebookIdMap.by_id) state.notebookIdMap.by_id = {};
    if (!state.notebookIdMap.by_path) state.notebookIdMap.by_path = {};
    if (cleanRoot && nb && nb !== cleanRoot && nb !== 'default') {
      const prevPath = state.notebookIdMap.by_id[nb];
      if (prevPath && prevPath !== cleanRoot && state.notebookIdMap.by_path[prevPath] === nb) {
        delete state.notebookIdMap.by_path[prevPath];
      }
      state.notebookIdMap.by_id[nb] = cleanRoot;
      state.notebookIdMap.by_path[cleanRoot] = nb;
    }
    return true;
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
    const storageNotebooks = {};
    for (const [k, v] of Object.entries(notebooks || {})) {
      const rec = migrate ? prepare(v) : v;
      actualNotebooks[k] = rec;
      storageNotebooks[k] = encodeConfigSelected(rec);
    }
    const actualShared = migrate || shared === current ? prepare(shared) : shared;
    const actualCurrent = prepare(current);
    if (!migrate) {
      actualNotebooks[nbKey()] = actualCurrent;
      storageNotebooks[nbKey()] = encodeConfigSelected(actualCurrent);
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
      notebook_configs: storageNotebooks,
      config: encodeConfigSelected(actualShared),
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
      storageSet(rpc, 'config', encodeConfigSelected(candidate));
    }
    const storageNotebooks = {};
    for (const [k, v] of Object.entries(state.notebookConfigs)) {
      storageNotebooks[k] = encodeConfigSelected(v);
    }
    storageSet(rpc, 'notebook_configs', storageNotebooks);
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

  const getConnState = (protocol) => {
    if (!protocol) return null;
    const key = `${resultKey()}:${protocol}`;
    const entry = state.connStates[key];
    return entry && typeof entry === 'object' ? entry : null;
  };

  const setConnState = (protocol, entry) => {
    if (!protocol) return;
    const key = `${resultKey()}:${protocol}`;
    if (entry && typeof entry === 'object') {
      state.connStates[key] = { ...entry };
    } else {
      delete state.connStates[key];
    }
  };

  const clearConnState = (protocol = null) => {
    const scope = resultKey();
    if (protocol) {
      delete state.connStates[`${scope}:${protocol}`];
    } else {
      for (const proto of VALID_PROTOCOLS) {
        delete state.connStates[`${scope}:${proto}`];
      }
    }
  };

  const saveRuntime = () => {
    const rpc = getRpc();
    const storedSyncMeta = { ...state.syncMeta };
    if (storedSyncMeta[LAYOUTS_META_KEY] && typeof storedSyncMeta[LAYOUTS_META_KEY] === 'object') {
      storedSyncMeta[LAYOUTS_META_KEY] = encodeLayoutsForStorage(storedSyncMeta[LAYOUTS_META_KEY]);
    }
    const values = {
      stats: state.stats,
      logs: state.logs.slice(0, MAX_LOG_ENTRIES),
      sync_meta: storedSyncMeta,
      notebook_results: state.notebookResults,
      pending_confirms: state.pendingConfirms,
      pending_confirm: null,
      conn_states: state.connStates,
    };
    const idMapData = state.notebookIdMap || {};
    if (
      state.hostSupportsNotebookIds ||
      Object.keys(idMapData.by_id || {}).length > 0 ||
      Object.keys(idMapData.by_path || {}).length > 0
    ) {
      values[NOTEBOOK_ID_MAP_KEY] = {
        by_id: { ...(idMapData.by_id || {}) },
        by_path: { ...(idMapData.by_path || {}) },
      };
    }
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
      if (isReservedSyncMetaKey(key)) {
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
    const cleanActive = normAbsPath(state.notebookRoot, state.homeDir);
    const allowUnnamespacedDefault =
      !state.hostSupportsNotebookIds &&
      (targetNbKey === 'default' || targetNbKey === cleanActive);
    for (const [mk, entry] of Object.entries(state.syncMeta)) {
      if (isReservedSyncMetaKey(mk) || mk === excludeMetaKey) {
        continue;
      }
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
      const parsed = parseNbMetaKey(mk);
      if (parsed) {
        if (parsed.nb !== targetNbKey) continue;
      } else if (!allowUnnamespacedDefault) {
        continue;
      }
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
    notebookLabel: (root = null) => notebookLabel(pathForKeyOrPath(root !== undefined && root !== null ? root : state.notebookRoot), state.locale, state.notebookRoot, state.homeDir),
    notebookSlug: (root = null) => notebookSlug(pathForKeyOrPath(root !== undefined && root !== null ? root : state.notebookRoot), getRpc(), state.notebookRoot, state.homeDir),
    verifyNotebookIdentity,
    hasVerifiedBaseline,
    commitNotebookBaseline,
    onNotebookRenamed: (params = {}) => {
      const id = String((params && params.id) || '').trim();
      const oldPath = normAbsPath((params && params.old_path) || '', state.homeDir);
      const newPath = normAbsPath((params && params.new_path) || '', state.homeDir);
      const activeRenamed = Boolean(oldPath && state.notebookRoot === oldPath);
      if (activeRenamed && newPath) {
        state.notebookRoot = newPath;
      }
      const live = newPath ? queryLiveNotebookIdentity(getRpc(), newPath, state.homeDir) : { verified: false, rootIdentity: '', id: '' };
      const resolvedId = id || live.id || '';
      const liveVerified = Boolean(live.verified && live.rootIdentity && (!resolvedId || !live.id || live.id === resolvedId));

      refreshKnownNotebooks({ claimLegacy: false });

      if (newPath && !state.knownNotebooks.some((kn) => kn && kn.path === newPath)) {
        const nextList = state.knownNotebooks.filter((kn) => !(kn && ((resolvedId && kn.id === resolvedId) || (oldPath && kn.path === oldPath))));
        const prev = oldPath && oldPath !== newPath ? [oldPath] : [];
        const entry = {
          path: newPath,
          name: posixBasename(newPath) || newPath,
          active: state.notebookRoot === newPath,
          previous_paths: prev,
          identity_verified: liveVerified,
        };
        if (resolvedId) entry.id = resolvedId;
        if (live.rootIdentity) entry.root_identity = live.rootIdentity;
        nextList.push(entry);
        state.knownNotebooks = nextList;
      }

      const idPairs = resolvedId && newPath && resolvedId !== newPath ? [[resolvedId, newPath]] : [];
      const { next: nextIdMap, changed: idMapChanged } = buildUpdatedIdMap(state.notebookIdMap, idPairs, { oldPath });
      const extraDirty = idMapChanged ? { [NOTEBOOK_ID_MAP_KEY]: nextIdMap } : {};

      const uiAlias = new Map();
      const targetKey = resolvedId || newPath;
      if (oldPath && targetKey && oldPath !== targetKey) {
        uiAlias.set(oldPath, targetKey);
      }
      if (uiAlias.size > 0 || (oldPath && newPath) || idMapChanged) {
        applyUiScopeAliases(uiAlias, {
          oldPath,
          newPath,
          persist: true,
          extraDirty,
        });
      }
      return { id: resolvedId, oldPath, newPath, activeRenamed, verified: liveVerified };
    },
    onNotebookRemoved: () => {
      refreshKnownNotebooks({ claimLegacy: false });
    },
    resultKey,
    getPendingConfirm,
    setPendingConfirm,
    clearPendingConfirm,
    getConnState,
    setConnState,
    clearConnState,
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
