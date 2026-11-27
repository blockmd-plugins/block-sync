/**
 * Local directory mirror sync engine & shared target-filesystem primitives
 * for block-sync. All target directory I/O goes through host.fs.*; local
 * notebook I/O goes through host.notes.* / host.fs.*; hashing goes through
 * host.crypto.hash. Pure ES2023, QuickJS-NG compatible.
 */

import {
  tr,
  errorDetail,
  protocolLabel,
  formatReasonItem,
  formatSkippedCount,
} from './i18n.js';
import {
  resolveCallHost,
  sha256Text,
  sha256Bytes,
  sha256File,
  textToBytes,
  bytesToText,
  decodeNoteBytes,
  bytesToBase64,
  base64ToBytes,
  nowHms,
  conflictStamp,
  sleepMs,
  splitExt,
  posixDirname,
  posixBasename,
  posixJoin,
  normAbsPath,
  isSafeRelPath,
  isSafeRelMd,
  isSafeRelAsset,
  syncDirKey,
  foldSyncPath,
  inSyncSubdir,
  matchesScope,
  pathsOverlap,
  noteAssetPaths,
  rewriteNoteAssetLinks,
  makeUniqueConflictPath,
  MAX_SYNC_FILE_BYTES,
  assertCompleteListing,
  createSyncSkips,
  classifySyncError,
  checkSyncFileSize,
  checkSyncFilename,
  isSyncAssetCandidate,
  checkSyncBufferSize,
  restoreSkippedBase,
  isMissingSyncFile,
  checkMissingSyncPath,
  hashSyncFile,
  readPlannedAsset,
  collectSkippedItems,
} from './utils.js';
import {
  DELETE_GUARD_THRESHOLD,
  MAX_STORED_CONFIRM_SAMPLES,
  MAX_LOG_ENTRIES,
  INITIALIZED_META_KEY,
  LAYOUTS_META_KEY,
  resolveMirrorDir,
  computeNotebookSubdirMap,
  notebookKey,
  notebookLabel,
} from './config.js';
import { createHostLocalAdapter } from './webdav.js';

const DEFAULT_LOCK_TTL_MS = 120000;
const MAX_STASH_ENTRIES = 64;
const STASH_PROTECT_WINDOW_MS = 60000;
const RECOVERY_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const TEXT_DIRECT_READ_MAX_BYTES = 256 * 1024;
const HOST_BUFFER_READ_MAX_BYTES = 2 * 1024 * 1024;

function trimTrailingSlash(p) {
  const s = String(p ?? '').replace(/\\/g, '/');
  return s.length > 1 ? s.replace(/\/+$/, '') : s;
}

function isNotFoundError(exc) {
  return isMissingSyncFile(exc);
}

function isAlreadyExistsError(exc) {
  const low = String(exc?.message || exc || '').toLowerCase();
  return ['already exists', 'file exists', 'eexist', 'exist'].some((tok) => low.includes(tok));
}

// ============================================================================
// Host FS RPC Primitives (host.fs.*)
// ============================================================================

/** Stat a filesystem path through host.fs.stat; returns { exists: false } when missing. */
export function fsStat(callHost, path) {
  const rpc = resolveCallHost(callHost);
  const res = rpc('host.fs.stat', { path: String(path ?? '') });
  return res && typeof res === 'object' ? res : { exists: false, path: String(path ?? '') };
}

/** List directory entries through host.fs.list. */
export function fsList(callHost, path, recursive = false, locale = 'zh') {
  const rpc = resolveCallHost(callHost);
  const res = rpc('host.fs.list', {
    path: String(path ?? ''),
    recursive: Boolean(recursive),
  });
  assertCompleteListing(res, path, locale);
  return Array.isArray(res?.entries) ? res.entries : Array.isArray(res?.files) ? res.files : [];
}

/** Read raw file bytes via host.fs.read (encoding: base64); returns null if missing. */
export function fsReadBytes(callHost, path) {
  const rpc = resolveCallHost(callHost);
  try {
    const maxBytes = globalThis.BlockSDK ? HOST_BUFFER_READ_MAX_BYTES : MAX_SYNC_FILE_BYTES;
    if (globalThis.BlockSDK) checkSyncBufferSize(fsStat(rpc, path).size);
    const res = rpc('host.fs.read', {
      path: String(path ?? ''),
      encoding: 'base64',
      max_bytes: maxBytes,
    });
    if (!res || res.found === false) return null;
    if (typeof res.content_base64 === 'string') return base64ToBytes(res.content_base64);
    if (typeof res.base64 === 'string') return base64ToBytes(res.base64);
    if (res.content instanceof Uint8Array) return res.content;
    if (typeof res.content === 'string') return textToBytes(res.content);
    return null;
  } catch (exc) {
    if (isNotFoundError(exc)) return null;
    throw exc;
  }
}

/** Read UTF-8 note text via host.fs.read (bounded utf8 direct read, bounded base64 fallback); returns null if missing. */
export function fsReadNoteText(callHost, path, relPath = '', entry = null) {
  const rpc = resolveCallHost(callHost);
  const cleanPath = String(path ?? '');
  const isSizeLimitErr = (exc) => {
    const low = String(exc?.message || exc || '').toLowerCase();
    return low.includes('exceeds size limit') || low.includes('exceeds the size limit') || low.includes('exceeds maximum');
  };
  const decodeReadRes = (res) => {
    if (!res || res.found === false) return null;
    if (typeof res.content === 'string') return res.content;
    if (typeof res.content_base64 === 'string') return decodeNoteBytes(base64ToBytes(res.content_base64), relPath);
    if (typeof res.base64 === 'string') return decodeNoteBytes(base64ToBytes(res.base64), relPath);
    if (res.content instanceof Uint8Array) return decodeNoteBytes(res.content, relPath);
    return null;
  };
  try {
    let knownSize = typeof entry?.size === 'number' && Number.isFinite(entry.size) ? entry.size : null;
    if (globalThis.BlockSDK) {
      if (knownSize === null) {
        const st = fsStat(rpc, cleanPath);
        if (typeof st?.size === 'number' && Number.isFinite(st.size)) {
          knownSize = st.size;
        }
      }
      if (knownSize !== null) checkSyncBufferSize(knownSize);
    }
    if (knownSize !== null && knownSize >= 0 && knownSize <= TEXT_DIRECT_READ_MAX_BYTES) {
      try {
        const res = rpc('host.fs.read', {
          path: cleanPath,
          encoding: 'utf8',
          max_bytes: TEXT_DIRECT_READ_MAX_BYTES,
        });
        return decodeReadRes(res);
      } catch (directExc) {
        if (!isSizeLimitErr(directExc)) throw directExc;
        // File grew past direct-read cap after stat/list; fall through to bounded base64 path.
      }
    }
    const fallbackMax = globalThis.BlockSDK ? HOST_BUFFER_READ_MAX_BYTES : MAX_SYNC_FILE_BYTES;
    if (globalThis.BlockSDK) {
      const st = fsStat(rpc, cleanPath);
      checkSyncBufferSize(st.size);
    }
    const res = rpc('host.fs.read', {
      path: cleanPath,
      encoding: 'base64',
      max_bytes: fallbackMax,
    });
    return decodeReadRes(res);
  } catch (exc) {
    if (isNotFoundError(exc)) return null;
    const low = String(exc?.message || exc || '').toLowerCase();
    if (low.includes('not valid utf-8') || low.includes('invalid utf-8')) {
      const label = relPath || 'note';
      throw new Error(`Note is not valid UTF-8 (${label}): ${exc?.message || exc}`);
    }
    if (isSizeLimitErr(exc) && globalThis.BlockSDK) {
      const err = new Error('File exceeds the current host’s 2 MiB in-memory transfer limit');
      err.code = 'file_limit';
      throw err;
    }
    throw exc;
  }
}

/** Read UTF-8 text via host.fs.read; returns null if missing. */
export function fsReadText(callHost, path) {
  const rpc = resolveCallHost(callHost);
  try {
    const res = rpc('host.fs.read', {
      path: String(path ?? ''),
      encoding: 'utf8',
    });
    if (!res || res.found === false) return null;
    if (typeof res.content === 'string') return res.content;
    if (typeof res.content_base64 === 'string') return bytesToText(base64ToBytes(res.content_base64));
    return null;
  } catch (exc) {
    if (isNotFoundError(exc)) return null;
    throw exc;
  }
}

/** Write raw bytes via host.fs.write. */
export function fsWriteBytes(callHost, path, data, { atomic = false, mkdirParents = false } = {}) {
  const rpc = resolveCallHost(callHost);
  const view = data instanceof Uint8Array ? data : new Uint8Array(data || 0);
  return rpc('host.fs.write', {
    path: String(path ?? ''),
    content_base64: bytesToBase64(view),
    atomic: Boolean(atomic),
    mkdir_parents: Boolean(mkdirParents),
  });
}

/** Write UTF-8 text via host.fs.write. */
export function fsWriteText(callHost, path, content, { atomic = false, mkdirParents = false } = {}) {
  const rpc = resolveCallHost(callHost);
  return rpc('host.fs.write', {
    path: String(path ?? ''),
    content: String(content ?? ''),
    atomic: Boolean(atomic),
    mkdir_parents: Boolean(mkdirParents),
  });
}

/** Create a directory via host.fs.mkdir. */
export function fsMkdir(callHost, path, recursive = true) {
  const rpc = resolveCallHost(callHost);
  return rpc('host.fs.mkdir', {
    path: String(path ?? ''),
    recursive: Boolean(recursive),
    parents: Boolean(recursive),
  });
}

/** Delete a file or directory via host.fs.delete. */
export function fsDelete(callHost, path, recursive = false) {
  const rpc = resolveCallHost(callHost);
  return rpc('host.fs.delete', {
    path: String(path ?? ''),
    recursive: Boolean(recursive),
  });
}

/** Rename/move a path via host.fs.rename. */
export function fsRename(callHost, from, to, { overwrite = false, mkdirParents = false } = {}) {
  const rpc = resolveCallHost(callHost);
  return rpc('host.fs.rename', {
    from: String(from ?? ''),
    to: String(to ?? ''),
    overwrite: Boolean(overwrite),
    mkdir_parents: Boolean(mkdirParents),
  });
}

/** Stream-copy a regular file on the host via host.fs.copy (avoids Wasm memory). */
export function fsCopy(callHost, from, to, { overwrite = false, mkdirParents = false } = {}) {
  const rpc = resolveCallHost(callHost);
  return rpc('host.fs.copy', {
    from: String(from ?? ''),
    to: String(to ?? ''),
    overwrite: Boolean(overwrite),
    mkdir_parents: Boolean(mkdirParents),
  });
}

function isHostMethodUnsupported(exc) {
  if (!exc) return false;
  if (typeof exc === 'object' && exc.code === -32601) return true;
  const low = String(exc?.message || exc || '').toLowerCase();
  return low.includes('unknown host method') || low.includes('-32601');
}

/** Atomically swap two files in the same directory via host.fs.atomic_swap. */
export function fsAtomicSwap(callHost, pathA, pathB) {
  const rpc = resolveCallHost(callHost);
  return rpc('host.fs.atomic_swap', {
    path_a: String(pathA ?? ''),
    path_b: String(pathB ?? ''),
  });
}

// ============================================================================
// iCloud Placeholder, Path Validation & Case/Normalization Helpers
// ============================================================================

/** Return true when a file is an evicted iCloud placeholder (.name.icloud or host flag). */
export function isCloudPlaceholder(callHost, rootDir, relPath) {
  if (!rootDir || !relPath) return false;
  const cleanRoot = trimTrailingSlash(rootDir);
  const norm = String(relPath).replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  if (!norm) return false;
  const full = posixJoin(cleanRoot, norm);
  try {
    const st = fsStat(callHost, full);
    if (st.exists && st.is_icloud_placeholder) return true;
  } catch (_err) {
    // Ignore stat errors for missing paths or restricted roots.
  }
  const dirPart = posixDirname(norm);
  const baseName = posixBasename(norm);
  if (!baseName) return false;
  const icloudName = `.${baseName}.icloud`;
  const icloudPath = dirPart ? posixJoin(cleanRoot, dirPart, icloudName) : posixJoin(cleanRoot, icloudName);
  try {
    const st = fsStat(callHost, icloudPath);
    return Boolean(st.exists);
  } catch (_err) {
    return false;
  }
}

/** Re-verify that rootDir is an existing directory and neither relPath nor its .icloud stub exists. */
export function isConfirmedAbsentOnRoot(callHost, rootDir, relPath) {
  if (!rootDir || !relPath) return false;
  const cleanRoot = trimTrailingSlash(rootDir);
  const norm = normalizeRelPath(relPath);
  if (!norm) return false;
  try {
    const rootSt = fsStat(callHost, cleanRoot);
    if (!rootSt.exists || !rootSt.is_dir) return false;
    const st = fsStat(callHost, posixJoin(cleanRoot, norm));
    if (st.exists || st.is_icloud_placeholder) return false;
    const dirPart = posixDirname(norm);
    const baseName = posixBasename(norm);
    if (!baseName) return false;
    const icloudName = `.${baseName}.icloud`;
    const icloudPath = dirPart ? posixJoin(cleanRoot, dirPart, icloudName) : posixJoin(cleanRoot, icloudName);
    const icloudSt = fsStat(callHost, icloudPath);
    if (icloudSt.exists) return false;
    return true;
  } catch (_err) {
    // Any stat I/O failure is treated conservatively as "cannot confirm absent" so deletion is aborted.
    return false;
  }
}

/** Validate and resolve a safe markdown destination path inside mirrorDir. */
export function safeMirrorDest(mirrorDir, relPath, excludedSubdirs = new Set(), locale = 'zh') {
  if (!isSafeRelMd(relPath) || inSyncSubdir(relPath, excludedSubdirs)) {
    throw new Error(tr(locale, `拒绝访问不安全路径: ${relPath}`, `Refused unsafe path: ${relPath}`));
  }
  const cleanRoot = trimTrailingSlash(mirrorDir);
  return posixJoin(cleanRoot, relPath);
}

/** Validate and resolve a safe attachment destination path inside mirrorDir. */
export function safeAssetDest(mirrorDir, relPath, excludedSubdirs = new Set(), locale = 'zh') {
  if (!isSafeRelAsset(relPath) || inSyncSubdir(relPath, excludedSubdirs)) {
    throw new Error(tr(locale, `拒绝访问不安全附件路径: ${relPath}`, `Refused unsafe attachment path: ${relPath}`));
  }
  const cleanRoot = trimTrailingSlash(mirrorDir);
  return posixJoin(cleanRoot, relPath);
}

/** Resolve actual on-disk casing of relPath under baseDir using host.fs.list. */
export function resolveActualRelCasing(callHost, baseDir, relPath, locale = 'zh') {
  const parts = String(relPath ?? '').replace(/\\/g, '/').split('/').filter(Boolean);
  if (parts.length === 0) return relPath;
  let curDir = trimTrailingSlash(baseDir);
  const resolved = [];
  for (const part of parts) {
    let entries;
    try {
      entries = fsList(callHost, curDir, false, locale);
    } catch (exc) {
      if (isNotFoundError(exc)) return relPath;
      throw exc;
    }
    const names = entries.map((e) => String(e?.name || '')).filter(Boolean);
    if (names.includes(part)) {
      resolved.push(part);
      curDir = posixJoin(curDir, part);
      continue;
    }
    const targetKey = foldSyncPath(part, { caseInsensitive: true, normalize: true });
    let chosen = null;
    for (const name of names) {
      if (foldSyncPath(name, { caseInsensitive: true, normalize: true }) === targetKey) {
        const candSt = fsStat(callHost, posixJoin(curDir, part));
        const entrySt = fsStat(callHost, posixJoin(curDir, name));
        if (candSt.exists && entrySt.exists) {
          chosen = name;
          break;
        }
      }
    }
    if (!chosen) return relPath;
    resolved.push(chosen);
    curDir = posixJoin(curDir, chosen);
  }
  return resolved.join('/');
}

function swapCase(str) {
  let out = '';
  for (let i = 0; i < str.length; i += 1) {
    const ch = str[i];
    const low = ch.toLowerCase();
    const up = ch.toUpperCase();
    out += ch === low ? up : low;
  }
  return out;
}

/** Return true if p1 and p2 collide on baseDir (same file on disk). */
export function pathsCaseCollideOnDir(callHost, baseDir, p1, p2) {
  if (!baseDir) return false;
  const cleanBase = trimTrailingSlash(baseDir);
  try {
    const stBase = fsStat(callHost, cleanBase);
    if (!stBase.exists || !stBase.is_dir) return false;
    const f1 = posixJoin(cleanBase, p1);
    const f2 = posixJoin(cleanBase, p2);
    const s1 = fsStat(callHost, f1);
    const s2 = fsStat(callHost, f2);
    if (!s1.exists || !s2.exists) return false;
    if (s1.path && s2.path && s1.path === s2.path) return true;
    return (
      s1.size === s2.size &&
      s1.mod_time_ms === s2.mod_time_ms &&
      foldSyncPath(p1, { caseInsensitive: true, normalize: true }) ===
        foldSyncPath(p2, { caseInsensitive: true, normalize: true })
    );
  } catch (_err) {
    return false;
  }
}

/** Detect whether baseDir is case-insensitive. */
export function dirIsCaseInsensitive(callHost, baseDir, candidatePaths = []) {
  if (!baseDir) return false;
  const cleanBase = trimTrailingSlash(baseDir);
  try {
    const st = fsStat(callHost, cleanBase);
    if (!st.exists || !st.is_dir) return false;
  } catch (_err) {
    return false;
  }
  for (const rel of candidatePaths) {
    const swapped = swapCase(rel);
    if (swapped !== rel && pathsCaseCollideOnDir(callHost, cleanBase, rel, swapped)) {
      return true;
    }
  }
  try {
    for (const entry of fsList(callHost, cleanBase, false)) {
      const name = String(entry?.name || '');
      if (!name) continue;
      const swapped = swapCase(name);
      if (swapped !== name) {
        return pathsCaseCollideOnDir(callHost, cleanBase, name, swapped);
      }
    }
  } catch (_err) {
    // Ignore listing errors.
  }
  return false;
}

/** Detect whether baseDir folds NFC/NFD Unicode normalization. */
export function dirIsNormalizationInsensitive(callHost, baseDir, { pid = 1, nowMsFn = () => Date.now() } = {}) {
  if (!baseDir) return false;
  const cleanBase = trimTrailingSlash(baseDir);
  try {
    const st = fsStat(callHost, cleanBase);
    if (!st.exists || !st.is_dir) return false;
    const token = `.bsnorm-${pid}-${nowMsFn()}-caf\u00e9`;
    const nfc = token.normalize('NFC');
    const nfd = token.normalize('NFD');
    const probePath = posixJoin(cleanBase, nfc);
    let created = false;
    try {
      fsWriteText(callHost, probePath, '', { atomic: false });
      created = true;
      const otherSt = fsStat(callHost, posixJoin(cleanBase, nfd));
      return Boolean(otherSt.exists);
    } catch (_err) {
      return false;
    } finally {
      if (created) {
        try {
          fsDelete(callHost, probePath);
        } catch (_delErr) {
          // Ignore probe cleanup errors.
        }
      }
    }
  } catch (_err) {
    return false;
  }
}

/** Return true if pathA and pathB collapse onto the same directory entry on baseDir. */
export function pathsCollapse(callHost, baseDir, pathA, pathB, opts = {}) {
  if (pathA === pathB) return true;
  if (foldSyncPath(pathA, { caseInsensitive: true, normalize: true }) !==
      foldSyncPath(pathB, { caseInsensitive: true, normalize: true })) {
    return false;
  }
  if (!baseDir) return false;
  const cleanBase = trimTrailingSlash(baseDir);
  const st = fsStat(callHost, cleanBase);
  if (!st.exists || !st.is_dir) return false;
  if (foldSyncPath(pathA, { caseInsensitive: true }) === foldSyncPath(pathB, { caseInsensitive: true })) {
    if (foldSyncPath(pathA, { normalize: true }) !== foldSyncPath(pathB, { normalize: true })) {
      return dirIsCaseInsensitive(callHost, cleanBase, [pathA, pathB]);
    }
    return dirIsNormalizationInsensitive(callHost, cleanBase, opts);
  }
  return dirIsCaseInsensitive(callHost, cleanBase, [pathA, pathB]);
}

/** Return true if any pair of distinct paths in group collapses on baseDir. */
export function groupCollapses(callHost, group, baseDir, opts = {}) {
  if (!group || group.length < 2 || !baseDir) return false;
  for (let i = 0; i < group.length; i += 1) {
    for (let j = i + 1; j < group.length; j += 1) {
      if (pathsCollapse(callHost, baseDir, group[i], group[j], opts)) {
        return true;
      }
    }
  }
  return false;
}

/** Return bilingual error message for collapsed/case-colliding filenames. */
export function collapsedNameError(locale, pair) {
  return tr(
    locale,
    `检测到仅大小写或字符编码不同的同名文件（${pair}），当前磁盘会相互覆盖，已中止同步`,
    `Found files whose names differ only by case or Unicode form (${pair}), which would overwrite each other on this disk; sync aborted`
  );
}

// ============================================================================
// Scanning Mirror Notes & Assets via host.fs.*
// ============================================================================

export function entryRelPath(entry, cleanRoot) {
  if (typeof entry?.rel_path === 'string' && entry.rel_path) return entry.rel_path;
  const raw = typeof entry === 'string' ? entry : String(entry?.path || '');
  const path = /^[a-z]:\//i.test(cleanRoot) ? raw.replace(/\\/g, '/') : raw;
  const prefix = String(cleanRoot || '').replace(/\/$/, '') + '/';
  if (path.startsWith(prefix)) return path.slice(prefix.length);
  return path.startsWith('/') || /^[a-z]:\//i.test(path) ? String(entry?.name || '') : path;
}

function hasDotSegment(rel) {
  return String(rel || '').split('/').some((seg) => seg.startsWith('.'));
}

function hasAssetSegment(rel) {
  return String(rel || '').split('/').slice(0, -1).includes('assets');
}

function listEntriesSkippingDotDirs(callHost, cleanRoot, excludedSubdirs = new Set(), locale = 'zh') {
  const topEntries = fsList(callHost, cleanRoot, false, locale);
  if (topEntries.some((e) => entryRelPath(e, cleanRoot).includes('/'))) {
    return topEntries;
  }
  const topFiles = [];
  const walkDirs = [];
  let skippedRootDir = false;
  for (const e of topEntries) {
    if (!e) continue;
    const rawName = String(e.name ?? '') || posixBasename(entryRelPath(e, cleanRoot));
    if (!rawName) continue;
    if (e.is_dir) {
      if (rawName.startsWith('.') || inSyncSubdir(rawName, excludedSubdirs)) {
        skippedRootDir = true;
      } else {
        walkDirs.push(rawName);
      }
    } else {
      topFiles.push(e);
    }
  }
  if (walkDirs.length === 0) {
    return topFiles;
  }
  if (skippedRootDir && walkDirs.length <= 32) {
    const out = [...topFiles];
    for (const dirName of walkDirs) {
      const subEntries = fsList(callHost, posixJoin(cleanRoot, dirName), true, locale);
      for (const se of subEntries) {
        if (!se) continue;
        let relFromRoot = '';
        if (typeof se.rel_path === 'string' && se.rel_path) {
          relFromRoot = `${dirName}/${se.rel_path}`;
        } else {
          relFromRoot = entryRelPath(se, cleanRoot);
          if (!relFromRoot || relFromRoot === String(se.name || '')) {
            relFromRoot = `${dirName}/${String(se.name || '')}`;
          }
        }
        out.push({ ...se, rel_path: relFromRoot });
      }
    }
    return out;
  }
  return fsList(callHost, cleanRoot, true, locale);
}

/** Scan a directory once, partitioning notes, attachments, iCloud placeholders, and stale tmp files. */
export function scanDirSnapshot(
  callHost,
  rootDir,
  {
    excludedSubdirs = new Set(),
    locale = 'zh',
  } = {}
) {
  if (!rootDir) return null;
  const cleanRoot = trimTrailingSlash(rootDir);
  const rootSt = fsStat(callHost, cleanRoot);
  if (!rootSt.exists || !rootSt.is_dir) return null;

  const entries = listEntriesSkippingDotDirs(callHost, cleanRoot, excludedSubdirs, locale);
  const noteEntries = new Map();
  const assetEntries = new Map();
  const icloudPaths = new Set();
  const icloudFoldedPaths = new Map();
  const staleTmpPaths = [];
  const addIcloudPath = (p) => {
    icloudPaths.add(p);
    const fk = foldSyncPath(p, { caseInsensitive: true, normalize: true });
    if (!icloudFoldedPaths.has(fk)) icloudFoldedPaths.set(fk, []);
    const list = icloudFoldedPaths.get(fk);
    if (!list.includes(p)) list.push(p);
  };

  for (const entry of entries) {
    if (!entry || entry.is_dir) continue;
    const rel = entryRelPath(entry, cleanRoot);
    if (!rel) continue;

    if (entry.is_icloud_placeholder) {
      addIcloudPath(rel);
    }
    const base = posixBasename(rel);
    const icMatch = /^\.(.+)\.icloud$/i.exec(base);
    if (icMatch) {
      const dir = posixDirname(rel);
      addIcloudPath(dir ? `${dir}/${icMatch[1]}` : icMatch[1]);
      addIcloudPath(rel);
    }
    if (base.startsWith('.block-sync-') && base.endsWith('.tmp') && !rel.split('/').some((seg) => seg === '.git')) {
      staleTmpPaths.push(rel);
    }

    if (inSyncSubdir(rel, excludedSubdirs)) continue;
    if (isSyncAssetCandidate(rel)) {
      assetEntries.set(rel, entry);
    } else if (!hasDotSegment(rel) && !hasAssetSegment(rel) && isSafeRelMd(rel)) {
      noteEntries.set(rel, entry);
    }
  }

  return {
    cleanRoot,
    noteEntries,
    assetEntries,
    icloudPaths,
    icloudFoldedPaths,
    staleTmpPaths,
  };
}

/** Check iCloud placeholder via pre-scanned snapshot set (case/norm aware), falling back to host stat on miss. */
export function snapshotHasCloudPlaceholder(callHost, snapshot, rootDir, relPath) {
  if (!relPath) return false;
  const norm = String(relPath).replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
  if (!norm) return false;
  const effectiveRoot = rootDir || snapshot?.cleanRoot || '';
  if (snapshot && snapshot.icloudPaths) {
    if (snapshot.icloudPaths.has(norm)) return true;
    if (snapshot.icloudFoldedPaths && effectiveRoot) {
      const fk = foldSyncPath(norm, { caseInsensitive: true, normalize: true });
      const cands = snapshot.icloudFoldedPaths.get(fk);
      if (cands && cands.length > 0) {
        if (snapshot._ci === undefined) {
          snapshot._ci = dirIsCaseInsensitive(callHost, effectiveRoot);
        }
        const ci = snapshot._ci;
        for (const cand of cands) {
          if (foldSyncPath(cand, { caseInsensitive: ci }) === foldSyncPath(norm, { caseInsensitive: ci })) {
            return true;
          }
          if (
            foldSyncPath(cand, { caseInsensitive: ci, normalize: true }) ===
            foldSyncPath(norm, { caseInsensitive: ci, normalize: true })
          ) {
            if (snapshot._norm === undefined) {
              snapshot._norm = dirIsNormalizationInsensitive(callHost, effectiveRoot);
            }
            if (snapshot._norm) return true;
          }
        }
      }
    }
  }
  return effectiveRoot ? isCloudPlaceholder(callHost, effectiveRoot, norm) : false;
}

/** Scan markdown notes in mirrorDir (or Git worktree) via host.fs.list + host.fs.read. */
export function scanMirrorFiles(
  callHost,
  mirrorDir,
  {
    onlyPath = null,
    scope = 'all',
    excludedSubdirs = new Set(),
    locale = 'zh',
    cfg = null,
    skips = createSyncSkips(cfg, locale),
  } = {}
) {
  const remoteFiles = Object.create(null);
  if (!mirrorDir) return remoteFiles;
  const cleanRoot = trimTrailingSlash(mirrorDir);
  const rootSt = fsStat(callHost, cleanRoot);
  if (!rootSt.exists || !rootSt.is_dir) return remoteFiles;

  if (onlyPath !== null && onlyPath !== undefined) {
    if (isSafeRelAsset(onlyPath) || inSyncSubdir(onlyPath, excludedSubdirs)) {
      return remoteFiles;
    }
    let candidate;
    try {
      candidate = safeMirrorDest(cleanRoot, onlyPath, excludedSubdirs, locale);
    } catch (_err) {
      return remoteFiles;
    }
    if (!skips.check(onlyPath)) return remoteFiles;
    skips.run(onlyPath, () => {
      if (isCloudPlaceholder(callHost, cleanRoot, onlyPath)) return;
      const entry = fsStat(callHost, candidate);
      if (!entry.exists || !skips.check(onlyPath, entry)) return;
      const actualRel = resolveActualRelCasing(callHost, cleanRoot, onlyPath, locale);
      if (!skips.check(actualRel)) return;
      const text = fsReadNoteText(callHost, posixJoin(cleanRoot, actualRel), actualRel, entry);
      if (text !== null) remoteFiles[actualRel] = text;
      else throw new Error('Note changed while opening');
    });
    return remoteFiles;
  }

  const mirrorCi = dirIsCaseInsensitive(callHost, cleanRoot);
  const mirrorNorm = dirIsNormalizationInsensitive(callHost, cleanRoot);
  const entries = listEntriesSkippingDotDirs(callHost, cleanRoot, excludedSubdirs, locale);
  for (const entry of entries) {
    if (!entry || entry.is_dir) continue;
    const rel = entryRelPath(entry, cleanRoot);
    if (!rel || hasDotSegment(rel) || hasAssetSegment(rel)) continue;
    if (!isSafeRelMd(rel) || inSyncSubdir(rel, excludedSubdirs)) continue;
    if (!matchesScope(rel, scope, { caseInsensitive: mirrorCi, normalize: mirrorNorm }) || !skips.check(rel, entry)) continue;
    skips.run(rel, () => {
      const text = fsReadNoteText(callHost, posixJoin(cleanRoot, rel), rel, entry);
      if (text === null) throw new Error('Note changed while opening');
      remoteFiles[rel] = text;
    });
  }
  return remoteFiles;
}

/** List attachments while preserving the Set of relative paths used by existing callers. */
export function listDirAssets(callHost, rootDir, excludedSubdirs = new Set(), {
  cfg = null, locale = 'zh', skips = createSyncSkips(cfg, locale), metadata = new Map(),
} = {}) {
  const names = new Set();
  if (!rootDir) return names;
  const cleanRoot = trimTrailingSlash(rootDir);
  const rootSt = fsStat(callHost, cleanRoot);
  if (!rootSt.exists || !rootSt.is_dir) return names;

  for (const entry of fsList(callHost, cleanRoot, true, locale)) {
    if (!entry || entry.is_dir) continue;
    const rel = entryRelPath(entry, cleanRoot);
    if (!isSyncAssetCandidate(rel) || inSyncSubdir(rel, excludedSubdirs)) continue;
    if (!skips.check(rel, entry)) continue;
    names.add(rel);
    metadata.set(rel, entry);
  }
  return names;
}

/** Read attachment bytes from rootDir via host.fs.read; returns null if missing or iCloud stub. */
export function readAssetFile(callHost, rootDir, relPath, excludedSubdirs = new Set()) {
  if (!rootDir || !isSafeRelAsset(relPath) || inSyncSubdir(relPath, excludedSubdirs)) {
    return null;
  }
  const cleanRoot = trimTrailingSlash(rootDir);
  if (isCloudPlaceholder(callHost, cleanRoot, relPath)) {
    return null;
  }
  const full = posixJoin(cleanRoot, relPath);
  const st = fsStat(callHost, full);
  if (!st.exists || st.is_dir || st.is_icloud_placeholder) {
    return null;
  }
  return fsReadBytes(callHost, full);
}

/** Return true if mirror/git target directory contains any non-empty note or attachment. */
export function remoteHasAnyContent(callHost, cfg, targetDir, excludedSubdirs = new Set(), locale = 'zh') {
  if (!targetDir) return false;
  const cleanDir = trimTrailingSlash(targetDir);
  const st = fsStat(callHost, cleanDir);
  if (!st.exists || !st.is_dir) return false;
  const notes = scanMirrorFiles(callHost, cleanDir, { excludedSubdirs, locale, cfg });
  if (Object.keys(notes).length > 0) return true;
  if (cfg?.sync_assets !== false && listDirAssets(callHost, cleanDir, excludedSubdirs, { cfg, locale }).size > 0) {
    return true;
  }
  return false;
}

// ============================================================================
// Sync Lock, Recovery Stash, Atomic Swap & Recoverable Deletion
// ============================================================================

/** Resolve plugin private data_dir from explicit parameter or host.fs.list_grants(). */
export function resolvePluginDataDir(callHost, dataDir = '') {
  const raw = typeof dataDir === 'string' ? dataDir.trim() : '';
  if (raw) return trimTrailingSlash(raw);
  try {
    const grants = resolveCallHost(callHost)('host.fs.list_grants', {});
    if (grants && typeof grants.data_dir === 'string' && grants.data_dir.trim()) {
      return trimTrailingSlash(grants.data_dir.trim());
    }
  } catch (_err) {
    // Optional if host mock does not implement list_grants.
  }
  return '';
}

const hostDataDirCacheByRpc = new WeakMap();

function isRecoveryMethodUnsupportedError(err) {
  if (!err) return false;
  if (typeof err === 'object' && err.code === -32601) return true;
  const msg = String(err && err.message ? err.message : err).toLowerCase();
  return (
    msg.includes('unknown host method') ||
    msg.includes('method not found') ||
    msg.includes('-32601')
  );
}

export function clearRecoveryDirCache(callHost, rootDir = '') {
  const rpc = typeof callHost === 'function' ? callHost : null;
  if (!rpc) return;
  const st = hostDataDirCacheByRpc.get(rpc);
  if (!st) return;
  const cleanRoot = trimTrailingSlash(rootDir);
  if (cleanRoot) {
    st.dirs.delete(cleanRoot);
  } else {
    st.dirs.clear();
  }
}

function resolveNotebookRecoveryDir(rpc, cleanRoot) {
  if (typeof rpc !== 'function' || !cleanRoot) return '';
  let cache = hostDataDirCacheByRpc.get(rpc);
  if (!cache) {
    cache = { unsupported: false, dirs: new Map() };
    hostDataDirCacheByRpc.set(rpc, cache);
  }
  if (cache.unsupported) return '';
  if (cache.dirs.has(cleanRoot)) return cache.dirs.get(cleanRoot) || '';
  try {
    const res = rpc('host.notebooks.data_dir', { path: cleanRoot });
    const nbDataPath = trimTrailingSlash(res && res.path ? res.path : '');
    if (nbDataPath) {
      const recDir = posixJoin(nbDataPath, 'recovery');
      cache.dirs.set(cleanRoot, recDir);
      return recDir;
    }
  } catch (exc) {
    if (isRecoveryMethodUnsupportedError(exc)) {
      cache.unsupported = true;
      return '';
    }
    cache.dirs.set(cleanRoot, '');
    return '';
  }
  cache.dirs.set(cleanRoot, '');
  return '';
}

/**
 * Return the plugin-private recovery stash directory for rootDir.
 * Prefers host.notebooks.data_dir (<dataDir>/notebooks/<id>/recovery) for
 * registered notebooks, falling back to <dataDir>/recovery/<hash16>/ on
 * unregistered external directories or older hosts.
 */
export function recoveryDirForRoot(callHost, rootDir, dataDir = '') {
  const rpc = resolveCallHost(callHost);
  const cleanRoot = trimTrailingSlash(rootDir);
  if (!cleanRoot) return '';
  const nbRecoveryDir = resolveNotebookRecoveryDir(rpc, cleanRoot);
  if (nbRecoveryDir) return nbRecoveryDir;
  const pluginDataDir = resolvePluginDataDir(rpc, dataDir);
  if (!pluginDataDir) return '';
  const rootHash = sha256Text(cleanRoot, rpc).slice(0, 16);
  return posixJoin(pluginDataDir, 'recovery', rootHash);
}

/** Execute fn under an exclusive filesystem lock file in <dataDir>/locks/. */
export function withTargetLock(
  callHost,
  targetDir,
  fn,
  {
    dataDir = '',
    pid = 1,
    nowMsFn = () => Date.now(),
    sleepFn = null,
    ttlMs = DEFAULT_LOCK_TTL_MS,
    waitTimeoutMs = 5000,
  } = {}
) {
  if (!targetDir) return fn();
  const rpc = resolveCallHost(callHost);
  const lockBase = resolvePluginDataDir(rpc, dataDir);
  if (!lockBase) {
    return fn();
  }

  const lockRoot = posixJoin(lockBase, 'locks');
  fsMkdir(rpc, lockRoot, true);
  const cleanTarget = trimTrailingSlash(targetDir);
  const key = sha256Text(cleanTarget, rpc).slice(0, 16);
  const lockPath = posixJoin(lockRoot, `${key}.lock`);
  const token = `${pid}-${nowMsFn()}-${Math.floor(Math.random() * 1e9)}`;
  const tmpPath = posixJoin(lockRoot, `.lock-${token}.tmp`);

  let acquired = false;
  const deadline = nowMsFn() + waitTimeoutMs;
  try {
    fsWriteText(rpc, tmpPath, JSON.stringify({ pid, ts: nowMsFn(), token }), { atomic: false });
    while (true) {
      try {
        fsRename(rpc, tmpPath, lockPath, { overwrite: false });
        acquired = true;
        break;
      } catch (exc) {
        if (!isAlreadyExistsError(exc)) {
          throw exc;
        }
        // Break stale lock if older than ttlMs.
        try {
          const st = fsStat(rpc, lockPath);
          if (st.exists && st.mod_time_ms && nowMsFn() - st.mod_time_ms > ttlMs) {
            fsDelete(rpc, lockPath);
            continue;
          }
        } catch (_staleErr) {
          // Ignore inspection errors.
        }
        if (nowMsFn() >= deadline) {
          throw new Error(`Sync target lock busy: ${cleanTarget}`);
        }
        sleepMs(50, sleepFn);
      }
    }
    return fn();
  } finally {
    if (!acquired) {
      try {
        fsDelete(rpc, tmpPath);
      } catch (_err) {
        // Ignore temp cleanup.
      }
    } else {
      try {
        const cur = fsReadText(rpc, lockPath);
        if (cur === null || cur.includes(token)) {
          fsDelete(rpc, lockPath);
        }
      } catch (_err) {
        // Ignore lock cleanup errors.
      }
    }
  }
}

function findGitWorktreeAndDir(callHost, startDir) {
  let cur = trimTrailingSlash(startDir);
  while (cur) {
    const gitEntry = posixJoin(cur, '.git');
    try {
      const st = fsStat(callHost, gitEntry);
      if (st.exists) {
        if (st.is_dir) {
          return [cur, gitEntry];
        }
        const raw = fsReadText(callHost, gitEntry);
        if (raw) {
          const firstLine = raw.split(/\r?\n/, 1)[0].trim();
          if (firstLine.toLowerCase().startsWith('gitdir:')) {
            const rawGd = firstLine.slice(7).trim();
            if (rawGd) {
              const gd = rawGd.startsWith('/') ? trimTrailingSlash(rawGd) : posixJoin(cur, rawGd);
              const gdSt = fsStat(callHost, gd);
              if (gdSt.exists && gdSt.is_dir) {
                return [cur, gd];
              }
            }
          }
        }
      }
    } catch (_err) {
      // Stop climbing if outside authorized scope.
      break;
    }
    const parent = posixDirname(cur);
    if (!parent || parent === cur) break;
    cur = parent;
  }
  return ['', ''];
}

function ensureGitInfoExclude(callHost, gitDir, pattern) {
  if (!gitDir || !pattern) return;
  try {
    const infoDir = posixJoin(gitDir, 'info');
    const excludePath = posixJoin(infoDir, 'exclude');
    fsMkdir(callHost, infoDir, true);
    const existing = fsReadText(callHost, excludePath) || '';
    const lines = existing.split(/\r?\n/).map((ln) => ln.trim());
    if (!lines.includes(pattern)) {
      const prefix = existing && !existing.endsWith('\n') ? `${existing}\n` : existing;
      fsWriteText(callHost, excludePath, `${prefix}${pattern}\n`, { atomic: false });
    }
  } catch (_err) {
    // Non-fatal if git info/exclude cannot be updated.
  }
}

function stashCandidatesForRoot(callHost, rootDir, relPath, nowMsFn = () => Date.now(), dataDir = '') {
  const cleanRoot = trimTrailingSlash(rootDir);
  const nowMs = nowMsFn();
  const baseName = (posixBasename(relPath).replace(/[^A-Za-z0-9._-]+/g, '_') || 'file').slice(0, 48);
  const tag = `${String(nowMs).padStart(15, '0')}-${sha256Text(relPath, callHost).slice(0, 8)}-${baseName}`;
  const recoveryDir = recoveryDirForRoot(callHost, cleanRoot, dataDir);
  if (recoveryDir) {
    return {
      nowMs,
      tag,
      gitDir: '',
      candidates: [[recoveryDir, false, '']],
    };
  }
  const [wtRoot, gitDir] = findGitWorktreeAndDir(callHost, cleanRoot);
  const candidates = [];
  if (gitDir) {
    candidates.push([posixJoin(gitDir, 'block-sync-replaced'), false, '']);
    const wt = wtRoot || cleanRoot;
    candidates.push([posixJoin(wt, '.block-sync-replaced'), true, '/.block-sync-replaced/']);
    candidates.push([posixJoin(wt, '.block-sync-recovery'), true, '/.block-sync-recovery/']);
  } else {
    candidates.push([posixJoin(cleanRoot, '.block-sync-replaced'), false, '']);
    candidates.push([posixJoin(cleanRoot, '.block-sync-recovery'), false, '']);
  }
  return { nowMs, tag, gitDir, candidates };
}

function stashEntryTimestampMs(entry, name) {
  const tsPart = String(name || '').split('-', 1)[0];
  if (/^\d+$/.test(tsPart)) {
    const parsed = Number.parseInt(tsPart, 10);
    if (Number.isFinite(parsed) && parsed >= 1_000_000_000_000) {
      return parsed;
    }
  }
  const mtimeMs = Number(entry && entry.mod_time_ms);
  if (Number.isFinite(mtimeMs) && mtimeMs > 0) {
    return mtimeMs;
  }
  return 0;
}

function pruneStashDir(callHost, stashDir, keepName, nowMs) {
  try {
    const expireBeforeMs = nowMs - RECOVERY_RETENTION_MS;
    const protectAfterMs = nowMs - STASH_PROTECT_WINDOW_MS;
    const entries = fsList(callHost, stashDir, false);
    const surviving = [];
    for (const entry of entries) {
      if (!entry || entry.is_dir) continue;
      const name = String(entry.name || posixBasename(entry.path || ''));
      if (!name) continue;
      const tsMs = stashEntryTimestampMs(entry, name);
      if (name !== keepName && tsMs > 0 && tsMs < expireBeforeMs) {
        try {
          fsDelete(callHost, posixJoin(stashDir, name));
        } catch (_err) {
          // Ignore prune errors.
        }
        continue;
      }
      surviving.push({ name, tsMs });
    }
    if (surviving.length > MAX_STASH_ENTRIES) {
      surviving.sort((a, b) => (a.tsMs !== b.tsMs ? a.tsMs - b.tsMs : a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      for (const item of surviving.slice(0, surviving.length - MAX_STASH_ENTRIES)) {
        if (item.name === keepName) continue;
        if (keepName && item.tsMs >= protectAfterMs) continue;
        try {
          fsDelete(callHost, posixJoin(stashDir, item.name));
        } catch (_err) {
          // Ignore prune errors.
        }
      }
    }
    if (!keepName) {
      try {
        if (fsList(callHost, stashDir, false).length === 0) {
          fsDelete(callHost, stashDir, false);
        }
      } catch (_err) {
        // Ignore empty dir cleanup errors.
      }
    }
  } catch (_err) {
    // Ignore listing errors.
  }
}

function moveFileIntoRecovery(callHost, srcPath, stashDir, baseName, nowMs) {
  const baseDest = posixJoin(stashDir, baseName);
  for (let idx = 0; idx < 50; idx += 1) {
    const cand = idx === 0 ? baseDest : `${baseDest}-${idx}`;
    try {
      fsRename(callHost, srcPath, cand, { overwrite: false });
      pruneStashDir(callHost, stashDir, posixBasename(cand), nowMs);
      return cand;
    } catch (exc) {
      if (isAlreadyExistsError(exc)) continue;

      // Cross-device (e.g. EXDEV) or non-collision rename failure: copy -> verify -> delete.
      const bytes = fsReadBytes(callHost, srcPath);
      if (bytes === null) {
        throw new Error(`Source file missing during recovery move: ${srcPath}`);
      }
      let tmpPath = '';
      for (let tIdx = 0; tIdx < 100; tIdx += 1) {
        const tCand = posixJoin(stashDir, `.block-sync-stash-${nowMs}-${tIdx}.tmp`);
        const tSt = fsStat(callHost, tCand);
        if (!tSt.exists) {
          tmpPath = tCand;
          break;
        }
      }
      if (!tmpPath) {
        throw new Error('Cannot allocate recovery temporary file');
      }

      let tmpAlive = true;
      try {
        fsWriteBytes(callHost, tmpPath, bytes, { atomic: false, mkdirParents: false });
        for (let cIdx = idx; cIdx < 50; cIdx += 1) {
          const copyCand = cIdx === 0 ? baseDest : `${baseDest}-${cIdx}`;
          try {
            fsRename(callHost, tmpPath, copyCand, { overwrite: false });
          } catch (copyExc) {
            if (isAlreadyExistsError(copyExc)) continue;
            throw copyExc;
          }
          tmpAlive = false;
          const dstSt = fsStat(callHost, copyCand);
          if (
            !dstSt.exists ||
            dstSt.is_dir ||
            dstSt.size === undefined ||
            dstSt.size === null ||
            Number(dstSt.size) !== bytes.byteLength
          ) {
            try {
              fsDelete(callHost, copyCand);
            } catch (_cleanupErr) {
              // Best-effort cleanup of unverified destination.
            }
            throw new Error(`Recovery copy verification failed: ${copyCand}`);
          }
          try {
            fsDelete(callHost, srcPath);
          } catch (delSrcErr) {
            if (!isNotFoundError(delSrcErr)) throw delSrcErr;
          }
          pruneStashDir(callHost, stashDir, posixBasename(copyCand), nowMs);
          return copyCand;
        }
        throw new Error('Exhausted recovery destination candidates');
      } finally {
        if (tmpAlive) {
          try {
            fsDelete(callHost, tmpPath);
          } catch (_delErr) {
            // Ignore temp cleanup errors.
          }
        }
      }
    }
  }
  return '';
}

function moveToRecoveryStash(callHost, srcPath, rootDir, relPath, nowMsFn = () => Date.now(), dataDir = '') {
  const { nowMs, tag, gitDir, candidates } = stashCandidatesForRoot(callHost, rootDir, relPath, nowMsFn, dataDir);
  for (const [stashDir, needsExclude, exclPattern] of candidates) {
    try {
      const st = fsStat(callHost, stashDir);
      if (st.exists && !st.is_dir) continue;
      fsMkdir(callHost, stashDir, true);
      if (needsExclude && gitDir && exclPattern) {
        ensureGitInfoExclude(callHost, gitDir, exclPattern);
      }
      const moved = moveFileIntoRecovery(callHost, srcPath, stashDir, tag, nowMs);
      if (moved) return moved;
    } catch (_err) {
      // Try next candidate directory.
    }
  }
  return '';
}

function moveDirFilesToRecovery(rpc, srcDir, recoveryDir, nowMs) {
  let dirSt;
  try {
    dirSt = fsStat(rpc, srcDir);
  } catch (_statErr) {
    return;
  }
  if (!dirSt.exists || !dirSt.is_dir) return;
  let entries = [];
  try {
    entries = fsList(rpc, srcDir, false);
  } catch (_listErr) {
    return;
  }
  let ensuredRecoveryDir = false;
  for (const entry of entries) {
    if (!entry || entry.is_dir || entry.is_regular === false || entry.is_file === false) continue;
    const name = String(entry.name || posixBasename(entry.path || '')).trim();
    if (!name) continue;
    const srcPath = entry.path ? String(entry.path) : posixJoin(srcDir, name);
    try {
      if (!ensuredRecoveryDir) {
        const recSt = fsStat(rpc, recoveryDir);
        if (recSt.exists && !recSt.is_dir) return;
        fsMkdir(rpc, recoveryDir, true);
        ensuredRecoveryDir = true;
      }
      moveFileIntoRecovery(rpc, srcPath, recoveryDir, name, nowMs);
    } catch (_moveErr) {
      // Best-effort per entry; never block sync.
    }
  }
  try {
    const remaining = fsList(rpc, srcDir, false);
    if (remaining.length === 0) {
      fsDelete(rpc, srcDir, false);
    }
  } catch (_delErr) {
    // Best-effort empty directory cleanup.
  }
}

/**
 * Best-effort migration of legacy workspace .block-sync-replaced / .block-sync-recovery
 * and path-hash recovery directories into recoveryDirForRoot(rootDir).
 */
export function migrateLegacyRecoveryDirs(
  callHost,
  rootDir,
  { dataDir = '', nowMsFn = () => Date.now(), extraHashRoots = [] } = {}
) {
  try {
    const rpc = resolveCallHost(callHost);
    const cleanRoot = trimTrailingSlash(rootDir);
    if (!cleanRoot) return;
    const recoveryDir = recoveryDirForRoot(rpc, cleanRoot, dataDir);
    if (!recoveryDir) return;
    const nowMs = nowMsFn();

    const pluginDataDir = resolvePluginDataDir(rpc, dataDir);
    if (pluginDataDir) {
      const hashRoots = [cleanRoot];
      for (const extra of extraHashRoots || []) {
        const cleanExtra = trimTrailingSlash(extra);
        if (cleanExtra && !hashRoots.includes(cleanExtra)) hashRoots.push(cleanExtra);
      }
      for (const hr of hashRoots) {
        const legacyHashDir = posixJoin(pluginDataDir, 'recovery', sha256Text(hr, rpc).slice(0, 16));
        if (legacyHashDir && legacyHashDir !== recoveryDir) {
          moveDirFilesToRecovery(rpc, legacyHashDir, recoveryDir, nowMs);
        }
      }
    }

    for (const legacyName of ['.block-sync-replaced', '.block-sync-recovery']) {
      const legacyDir = posixJoin(cleanRoot, legacyName);
      let dirSt;
      try {
        dirSt = fsStat(rpc, legacyDir);
      } catch (_statErr) {
        continue;
      }
      if (!dirSt.exists || !dirSt.is_dir) continue;

      let entries = [];
      try {
        entries = fsList(rpc, legacyDir, false);
      } catch (_listErr) {
        continue;
      }

      let ensuredRecoveryDir = false;
      for (const entry of entries) {
        if (!entry || entry.is_dir || entry.is_regular === false || entry.is_file === false) continue;
        const name = String(entry.name ?? '') || posixBasename(entry.path || '');
        if (!name) continue;
        const srcPath = entry.path ? String(entry.path) : posixJoin(legacyDir, name);
        try {
          if (!ensuredRecoveryDir) {
            const recSt = fsStat(rpc, recoveryDir);
            if (recSt.exists && !recSt.is_dir) break;
            fsMkdir(rpc, recoveryDir, true);
            ensuredRecoveryDir = true;
          }
          moveFileIntoRecovery(rpc, srcPath, recoveryDir, name, nowMs);
        } catch (_moveErr) {
          // Best-effort per entry; never block sync.
        }
      }

      try {
        const remaining = fsList(rpc, legacyDir, false);
        if (remaining.length === 0) {
          fsDelete(rpc, legacyDir, false);
        }
      } catch (_delErr) {
        // Best-effort empty directory cleanup.
      }
    }
    if (pluginDataDir) {
      try {
        const legacyRecoveryBase = posixJoin(pluginDataDir, 'recovery');
        const st = fsStat(rpc, legacyRecoveryBase);
        if (st.exists && st.is_dir && fsList(rpc, legacyRecoveryBase, false).length === 0) {
          fsDelete(rpc, legacyRecoveryBase, false);
        }
      } catch (_cleanErr) {
        // Ignore cleanup errors.
      }
    }
  } catch (_err) {
    // Best-effort migration; never block sync.
  }
}

/** Enforce 7-day retention and 64-entry cap across notebook and legacy recovery dirs. */
export function cleanupRecoveryDirs(
  callHost,
  { dataDir = '', notebooks = [], nowMsFn = () => Date.now() } = {}
) {
  try {
    const rpc = resolveCallHost(callHost);
    const nowMs = nowMsFn();
    const seenDirs = new Set();
    for (const nb of notebooks || []) {
      const cleanNb = trimTrailingSlash(nb);
      if (!cleanNb) continue;
      const recDir = recoveryDirForRoot(rpc, cleanNb, dataDir);
      if (recDir && !seenDirs.has(recDir)) {
        seenDirs.add(recDir);
        pruneStashDir(rpc, recDir, '', nowMs);
      }
    }
    const pluginDataDir = resolvePluginDataDir(rpc, dataDir);
    if (pluginDataDir) {
      const base = posixJoin(pluginDataDir, 'recovery');
      const st = fsStat(rpc, base);
      if (st.exists && st.is_dir) {
        for (const ent of fsList(rpc, base, false)) {
          if (!ent || !ent.is_dir) continue;
          const p = ent.path ? String(ent.path) : posixJoin(base, String(ent.name || ''));
          if (p && !seenDirs.has(p)) {
            seenDirs.add(p);
            pruneStashDir(rpc, p, '', nowMs);
          }
        }
        try {
          if (fsList(rpc, base, false).length === 0) {
            fsDelete(rpc, base, false);
          }
        } catch (_delErr) {
          // Ignore empty dir cleanup.
        }
      }
    }
  } catch (_err) {
    // Best-effort maintenance; never block plugin startup.
  }
}

function preserveExternalConflictCopy(
  callHost,
  srcPath,
  destPath,
  hashHex,
  defaultExt = ''
) {
  const parent = posixDirname(destPath);
  const baseName = posixBasename(destPath);
  const [stem, ext] = splitExt(baseName);
  const useExt = ext || defaultExt;
  const tag = String(hashHex || 'ext').slice(0, 8);
  for (let idx = 1; idx < 50; idx += 1) {
    const suffix = idx === 1 ? '' : `-${idx}`;
    const cand = posixJoin(parent, `${stem}.conflict-${tag}${suffix}${useExt}`);
    try {
      fsRename(callHost, srcPath, cand, { overwrite: false });
      return cand;
    } catch (exc) {
      if (isAlreadyExistsError(exc)) continue;
      return '';
    }
  }
  return '';
}

/** Clean up stale .block-sync-*.tmp files in rootDir (excluding Git-tracked files). */
export function cleanupStaleTempFiles(
  callHost,
  rootDir,
  { trackedPaths = new Set(), locale = 'zh' } = {}
) {
  if (!rootDir) return;
  const cleanRoot = trimTrailingSlash(rootDir);
  const st = fsStat(callHost, cleanRoot);
  if (!st.exists || !st.is_dir) return;
  const entries = fsList(callHost, cleanRoot, true);
  for (const entry of entries) {
    if (!entry || entry.is_dir) continue;
    const rel = entryRelPath(entry, cleanRoot);
    const name = posixBasename(rel);
    if (!name.startsWith('.block-sync-') || !name.endsWith('.tmp')) continue;
    if (rel.split('/').some((seg) => seg === '.git')) continue;
    if (trackedPaths && trackedPaths.has(rel)) continue;
    try {
      fsDelete(callHost, posixJoin(cleanRoot, rel));
    } catch (exc) {
      if (!isNotFoundError(exc)) {
        throw new Error(
          tr(
            locale,
            `无法清理残留临时文件，已中止提交：${rel} (${errorDetail(locale, exc)})`,
            `Could not clean up stale temporary files; aborted commit: ${rel} (${errorDetail(locale, exc)})`
          )
        );
      }
    }
  }
}

/**
 * Atomically write a mirror/worktree file via temp file + host.fs.rename (create-only)
 * or host.fs.atomic_swap (CAS overwrite) + recovery stash.
 */
export function writeMirrorPayload(
  callHost,
  mirrorDir,
  relPath,
  rawBytes,
  {
    isText = false,
    sourcePath = '',
    copyFromPath = '',
    sourceHash = '',
    readFallback = null,
    expectedHash = null,
    createOnly = false,
    excludedSubdirs = new Set(),
    verifyTarget = null,
    changeErr = '',
    locale = 'zh',
    dataDir = '',
    pid = 1,
    nowMsFn = () => Date.now(),
  } = {}
) {
  const rpc = resolveCallHost(callHost);
  if (typeof verifyTarget === 'function') verifyTarget();
  const cleanMirror = trimTrailingSlash(mirrorDir);
  const dest = isText
    ? safeMirrorDest(cleanMirror, relPath, excludedSubdirs, locale)
    : safeAssetDest(cleanMirror, relPath, excludedSubdirs, locale);
  const isRawString = isText && typeof rawBytes === 'string' && !sourcePath && !copyFromPath;
  const bytes = sourcePath || copyFromPath || isRawString
    ? null
    : (rawBytes instanceof Uint8Array ? rawBytes : textToBytes(String(rawBytes ?? '')));
  const contentHash = sourcePath || copyFromPath
    ? sourceHash
    : isRawString
      ? sha256Text(rawBytes, rpc)
      : sha256Bytes(bytes, rpc);
  const hashAt = (path) => hashSyncFile(path, rpc, () => fsReadBytes(rpc, path));
  const errMsg =
    changeErr ||
    tr(
      locale,
      `目标文件已变更，已中止覆盖以避免数据丢失：${relPath}`,
      `Destination file changed during sync; aborted overwrite to protect data: ${relPath}`
    );

  const parentDir = posixDirname(dest);
  if (parentDir) {
    fsMkdir(rpc, parentDir, true);
  }

  let tmpPath = '';
  for (let idx = 0; idx < 100; idx += 1) {
    const cand = posixJoin(parentDir || cleanMirror, `.block-sync-${pid}-${nowMsFn()}-${idx}.tmp`);
    const st = fsStat(rpc, cand);
    if (!st.exists) {
      tmpPath = cand;
      break;
    }
  }
  if (!tmpPath) {
    throw new Error(tr(locale, '无法创建临时文件', 'Cannot allocate temporary file'));
  }

  let tmpAlive = false;
  try {
    if (sourcePath) {
      fsRename(rpc, sourcePath, tmpPath, { overwrite: false });
      tmpAlive = true;
    } else if (copyFromPath) {
      let copied = false;
      try {
        fsCopy(rpc, copyFromPath, tmpPath, { overwrite: false, mkdirParents: false });
        copied = true;
      } catch (exc) {
        if (!isHostMethodUnsupported(exc) || typeof readFallback !== 'function') throw exc;
      }
      if (copied) {
        tmpAlive = true;
        if (contentHash && hashAt(tmpPath) !== contentHash) {
          const err = new Error(tr(locale, '附件在扫描后发生变化', 'Attachment changed after scanning'));
          err.code = 'fs_error';
          throw err;
        }
      } else {
        const fallbackBytes = readFallback();
        fsWriteBytes(rpc, tmpPath, fallbackBytes, { atomic: false, mkdirParents: false });
        tmpAlive = true;
      }
    } else if (isRawString) {
      fsWriteText(rpc, tmpPath, rawBytes, { atomic: false, mkdirParents: false });
      tmpAlive = true;
    } else {
      fsWriteBytes(rpc, tmpPath, bytes, { atomic: false, mkdirParents: false });
      tmpAlive = true;
    }

    if (createOnly) {
      const existingHash = hashAt(dest);
      if (existingHash !== null) {
        if (existingHash === contentHash) return;
        throw new Error(errMsg);
      }
      try {
        fsRename(rpc, tmpPath, dest, { overwrite: false });
        tmpAlive = false;
        return;
      } catch (exc) {
        if (isAlreadyExistsError(exc)) {
          if (hashAt(dest) === contentHash) return;
          throw new Error(errMsg);
        }
        throw exc;
      }
    }

    if (expectedHash !== null && expectedHash !== undefined) {
      const curHash = hashAt(dest);
      if (curHash !== expectedHash && curHash !== contentHash) throw new Error(errMsg);

      fsAtomicSwap(rpc, tmpPath, dest);
      // The temporary path now owns the old contents. It must survive a failed verification or recovery.
      tmpAlive = false;
      let swappedHash;
      try {
        swappedHash = hashAt(tmpPath);
        if (swappedHash !== expectedHash && swappedHash !== contentHash) throw new Error(errMsg);
      } catch (exc) {
        try {
          fsAtomicSwap(rpc, tmpPath, dest);
          tmpAlive = !preserveExternalConflictCopy(rpc, tmpPath, dest, contentHash, isText ? '.md' : '');
        } catch (_rollbackErr) {
          const moved = moveToRecoveryStash(rpc, tmpPath, cleanMirror, relPath, nowMsFn, dataDir);
          if (!moved) fsRename(rpc, tmpPath, `${tmpPath}.recovery`, { overwrite: false });
        }
        throw exc;
      }

      const stashed = moveToRecoveryStash(rpc, tmpPath, cleanMirror, relPath, nowMsFn, dataDir);
      if (stashed) {
        tmpAlive = false;
      } else {
        // Keep a dot-prefixed non-.tmp fallback so stale temp cleanup never removes it.
        const recoveryDir = recoveryDirForRoot(rpc, cleanMirror, dataDir);
        const keepName = `.block-sync-keep-${nowMsFn()}-${sha256Text(relPath, rpc).slice(0, 8)}`;
        if (recoveryDir) {
          try {
            fsMkdir(rpc, recoveryDir, true);
            const moved = moveFileIntoRecovery(rpc, tmpPath, recoveryDir, keepName, nowMsFn());
            if (moved) tmpAlive = false;
          } catch (_fbErr) {
            // Keep workspace clean; finally will clean up tmpPath if move failed.
          }
        } else {
          const fallback = posixJoin(parentDir || cleanMirror, keepName);
          try {
            fsRename(rpc, tmpPath, fallback, { overwrite: false });
            tmpAlive = false;
          } catch (_fbErr) {
            // Will be cleaned up in finally if move failed.
          }
        }
      }
      return;
    }

    fsRename(rpc, tmpPath, dest, { overwrite: true });
    tmpAlive = false;
  } finally {
    if (tmpAlive) {
      try {
        fsDelete(rpc, tmpPath);
      } catch (_delErr) {
        // Ignore cleanup errors.
      }
    }
  }
}

/** Write a markdown note atomically to mirrorDir. */
export function writeMirrorFile(callHost, mirrorDir, relPath, content, opts = {}) {
  const locale = opts.locale || 'zh';
  return writeMirrorPayload(callHost, mirrorDir, relPath, String(content ?? ''), {
    ...opts,
    isText: true,
    changeErr: tr(
      locale,
      `目标文件已变更，已中止覆盖以避免数据丢失：${relPath}`,
      `Destination file changed during sync; aborted overwrite to protect data: ${relPath}`
    ),
  });
}

/** Write binary attachment bytes atomically to mirrorDir. */
export function writeMirrorBytes(callHost, mirrorDir, relPath, data, opts = {}) {
  const locale = opts.locale || 'zh';
  return writeMirrorPayload(callHost, mirrorDir, relPath, data, {
    ...opts,
    isText: false,
    changeErr: tr(
      locale,
      `附件在同步期间已变更，已中止覆盖以避免数据丢失：${relPath}`,
      `Attachment changed during sync; aborted overwrite to protect data: ${relPath}`
    ),
  });
}

/**
 * Move a mirror or Git worktree file into the recovery stash once its bytes still match.
 * Returns 'deleted', 'missing', or 'changed'.
 */
export function deleteMirrorEntry(
  callHost,
  targetDir,
  relPath,
  matchesFn,
  {
    excludedSubdirs = new Set(),
    locale = 'zh',
    dataDir = '',
    nowMsFn = () => Date.now(),
    expectedAssetHash = null,
    cfg = null,
  } = {}
) {
  const rpc = resolveCallHost(callHost);
  if (!isSafeRelPath(relPath) || inSyncSubdir(relPath, excludedSubdirs)) {
    throw new Error(tr(locale, `拒绝删除不安全路径：${relPath}`, `Refused to delete unsafe path: ${relPath}`));
  }
  const cleanTarget = trimTrailingSlash(targetDir);
  const full = posixJoin(cleanTarget, relPath);
  const st = fsStat(rpc, full);
  if (!st.exists) return 'missing';
  if (st.is_dir || st.is_regular === false) throw new Error('Must be a regular file');
  checkSyncFileSize(st.size, cfg, locale);
  if (expectedAssetHash !== null) {
    const hash = hashSyncFile(full, rpc, () => fsReadBytes(rpc, full));
    if (hash === null) return 'missing';
    if (hash !== expectedAssetHash) return 'changed';
  } else {
    const raw = fsReadBytes(rpc, full);
    if (raw === null) return 'missing';
    if (!matchesFn(raw)) return 'changed';
  }

  const stashed = moveToRecoveryStash(rpc, full, cleanTarget, relPath, nowMsFn, dataDir);
  if (!stashed) {
    throw new Error(tr(locale, `无法移入恢复区：${relPath}`, `Could not move into the recovery folder: ${relPath}`));
  }
  return 'deleted';
}

// ============================================================================
// Physical Target Validation & Shared 3-Way Planning / Risk Helpers
// ============================================================================

/** Validate physical sync target directories across notebook bindings and pin stat identities. */
export function validatePhysicalTargets(
  callHost,
  protocol,
  bindings,
  baseRoot,
  {
    expectedIdentities = null,
    locale = 'zh',
    homeDir = '',
  } = {}
) {
  if (!['local_mirror', 'git'].includes(protocol) || !baseRoot) {
    return { identities: {}, error: '' };
  }
  const cleanBase = trimTrailingSlash(baseRoot);
  const identities = {};
  const resolvedTargets = [];

  for (const [nb, sub] of Object.entries(bindings || {})) {
    const lbl = notebookLabel(nb, locale, '', homeDir);
    const tdir = sub ? posixJoin(cleanBase, sub) : cleanBase;
    if (sub) {
      const normSub = normAbsPath(tdir, homeDir);
      if (normSub === cleanBase || !normSub.startsWith(`${cleanBase}/`)) {
        return {
          identities: {},
          error: tr(
            locale,
            `笔记本「${lbl}」的同步子目录超出同步根目录，已中止同步`,
            `Sync subfolder for notebook ${lbl} resolves outside the sync root; sync aborted`
          ),
        };
      }
    }
    for (const [prevNb, prevSub, prevDir] of resolvedTargets) {
      const sameOrNested = tdir === prevDir || (Boolean(sub) && Boolean(prevSub) && pathsOverlap(tdir, prevDir));
      if (sameOrNested) {
        const prevLbl = notebookLabel(prevNb, locale, '', homeDir);
        return {
          identities: {},
          error: tr(
            locale,
            `笔记本「${prevLbl}」与「${lbl}」的同步目标目录指向同一或嵌套物理目录，已中止同步`,
            `Sync folders for ${prevLbl} and ${lbl} resolve to the same or nested directory; sync aborted`
          ),
        };
      }
    }

    const st = fsStat(callHost, tdir);
    const exists = Boolean(st.exists);
    if (expectedIdentities && Object.hasOwn(expectedIdentities, nb)) {
      const exp = expectedIdentities[nb];
      if (exp.path && st.path && st.path !== exp.path) {
        return {
          identities: {},
          error: tr(
            locale,
            `笔记本「${lbl}」的同步目标目录在执行期间已变更，已中止同步`,
            `Sync target folder for ${lbl} changed during execution; sync aborted`
          ),
        };
      }
      if (exp.exists && !exists) {
        return {
          identities: {},
          error: tr(
            locale,
            `笔记本「${lbl}」的同步目标目录已被移除，已中止同步`,
            `Sync target folder for ${lbl} was removed during execution; sync aborted`
          ),
        };
      }
      if (exp.exists && exists && exp.is_dir !== st.is_dir) {
        return {
          identities: {},
          error: tr(
            locale,
            `笔记本「${lbl}」的同步目标实体目录已被替换，已中止同步`,
            `Physical sync target directory for ${lbl} was replaced during execution; sync aborted`
          ),
        };
      }
    }

    identities[nb] = {
      sub,
      tdir,
      exists,
      is_dir: Boolean(st.is_dir),
      path: st.path || tdir,
    };
    resolvedTargets.push([nb, sub, tdir]);
  }
  return { identities, error: '' };
}

/** Pair 1-to-1 single-side paths missing from baseMap with orphan baseMap keys that collapse on disk. */
export function pairOrphanBaseKeys(
  callHost,
  sidePaths,
  orphanBasePaths,
  baseMap,
  prefix,
  localDir,
  targetDir,
  protocol,
  aliasesOut
) {
  if (!sidePaths.length || !orphanBasePaths.length) return;
  const sideFolded = new Map();
  for (const p of [...sidePaths].sort()) {
    const fk = foldSyncPath(p, { caseInsensitive: true, normalize: true });
    if (!sideFolded.has(fk)) sideFolded.set(fk, []);
    sideFolded.get(fk).push(p);
  }
  const orphanFolded = new Map();
  for (const bp of [...orphanBasePaths].sort()) {
    const fk = foldSyncPath(bp, { caseInsensitive: true, normalize: true });
    if (!orphanFolded.has(fk)) orphanFolded.set(fk, []);
    orphanFolded.get(fk).push(bp);
  }
  for (const [fk, sList] of sideFolded.entries()) {
    const bList = orphanFolded.get(fk);
    if (!bList || sList.length !== 1 || bList.length !== 1) continue;
    const sp = sList[0];
    const bp = bList[0];
    const sKey = `${prefix}${sp}`;
    const bKey = `${prefix}${bp}`;
    if (Object.hasOwn(baseMap, sKey) || !Object.hasOwn(baseMap, bKey)) continue;
    const collides =
      (Boolean(localDir) && pathsCollapse(callHost, localDir, sp, bp)) ||
      (['local_mirror', 'git'].includes(protocol) && Boolean(targetDir) && pathsCollapse(callHost, targetDir, sp, bp));
    if (collides) {
      baseMap[sKey] = baseMap[bKey];
      if (!Object.hasOwn(aliasesOut, sKey)) aliasesOut[sKey] = [];
      if (!aliasesOut[sKey].includes(bKey)) aliasesOut[sKey].push(bKey);
    }
  }
}

/** Resolve a 3-way conflict pair for a single note. */
export function resolveConflictPair(callHost, relPath, localText, remoteText, baseHash, policy = 'keep_both') {
  const localHash = sha256Text(localText, callHost);
  const remoteHash = sha256Text(remoteText, callHost);
  if (localHash === remoteHash) return ['skip', localText, null, localHash];
  if (baseHash && baseHash === localHash) return ['pull', remoteText, null, remoteHash];
  if (baseHash && baseHash === remoteHash) return ['push', localText, null, localHash];
  if (policy === 'local_first') return ['push', localText, null, localHash];
  if (policy === 'remote_first') return ['pull', remoteText, null, remoteHash];
  const conflictRel = makeUniqueConflictPath(relPath, remoteText, { callHost });
  return ['keep_both', localText, [conflictRel, remoteText], localHash];
}

/** Plan attachment sync operations for local_mirror or git. */
export function planNotebookAssets({
  callHost,
  configStore = null,
  localAdapter,
  protocol,
  cfg,
  nbRoot,
  targetDir,
  baseMap,
  policy,
  scope,
  localNotes = {},
  remoteNotes = {},
  localSnapshot = null,
  remoteSnapshot = null,
  localNoteEntries = null,
  remoteNoteEntries = null,
  readLocalNote = null,
  readRemoteNote = null,
  onlyPath = null,
  excludedSubdirs = new Set(),
  trackedRemotePaths = null,
  gitTreePaths = null,
  isFirstSync = false,
  nbKey = 'default',
  locale = 'zh',
  skips = createSyncSkips(cfg, locale),
} = {}) {
  const rpc = resolveCallHost(callHost);
  const empty = {
    skipped_items: skips.items,
    local_asset_hashes: {},
    remote_asset_hashes: {},
    remote_asset_etags: {},
    remote_asset_path_map: {},
    assets_to_push_new: [],
    assets_to_push_overwrite: [],
    assets_to_pull_new: [],
    assets_to_pull_overwrite: [],
    asset_conflicts: [],
    assets_synced: [],
    assets_to_delete_remote: [],
    assets_to_delete_local: [],
    delete_expected_hashes: {},
    asset_base_aliases: {},
  };
  if (cfg?.sync_assets === false || !nbRoot) {
    return empty;
  }

  let explicitPaths = null;
  if (onlyPath !== null && onlyPath !== undefined) {
    const lOnly = Object.hasOwn(localNotes, onlyPath)
      ? localNotes[onlyPath]
      : (typeof readLocalNote === 'function' ? readLocalNote(onlyPath) : '') || '';
    const rOnly = Object.hasOwn(remoteNotes, onlyPath)
      ? remoteNotes[onlyPath]
      : (typeof readRemoteNote === 'function' ? readRemoteNote(onlyPath) : '') || '';
    explicitPaths = new Set([
      ...noteAssetPaths(onlyPath, lOnly),
      ...noteAssetPaths(onlyPath, rOnly),
    ]);
    if (isSafeRelAsset(onlyPath)) explicitPaths.add(onlyPath);
    if (explicitPaths.size === 0) return empty;
  }

  const localMetadata = new Map();
  const remoteMetadata = new Map();
  let localCandidates;
  if (explicitPaths !== null) {
    localCandidates = new Set(explicitPaths);
  } else if (localSnapshot && localSnapshot.assetEntries) {
    localCandidates = new Set();
    for (const [rel, entry] of localSnapshot.assetEntries.entries()) {
      if (inSyncSubdir(rel, excludedSubdirs)) continue;
      if (!skips.check(rel, entry)) continue;
      localCandidates.add(rel);
      localMetadata.set(rel, entry);
    }
  } else {
    localCandidates = localAdapter.listAssets(nbRoot, excludedSubdirs, { cfg, locale, skips, metadata: localMetadata });
  }
  for (const rel of localCandidates) {
    if (inSyncSubdir(rel, excludedSubdirs)) {
      throw new Error(
        tr(
          locale,
          `附件路径与其他笔记本的同步目录重叠：${rel}`,
          `Attachment path overlaps with another notebook's sync folder: ${rel}`
        )
      );
    }
  }

  let remoteCandidates = new Set();
  if (explicitPaths !== null) {
    remoteCandidates = new Set(explicitPaths);
  } else if (targetDir) {
    let listed;
    if (remoteSnapshot && remoteSnapshot.assetEntries) {
      listed = new Set();
      for (const [rel, entry] of remoteSnapshot.assetEntries.entries()) {
        if (inSyncSubdir(rel, excludedSubdirs)) continue;
        if (!skips.check(rel, entry)) continue;
        listed.add(rel);
        remoteMetadata.set(rel, entry);
      }
    } else {
      listed = listDirAssets(rpc, targetDir, excludedSubdirs, { cfg, locale, skips, metadata: remoteMetadata });
    }
    remoteCandidates = trackedRemotePaths !== null && trackedRemotePaths !== undefined
      ? new Set([...listed].filter((p) => trackedRemotePaths.has(p)))
      : listed;
  }

  const referenced = new Set();
  let candidates = new Set([...localCandidates, ...remoteCandidates]);
  if (explicitPaths === null && scope && scope !== 'all') {
    const localKeys = (localNoteEntries ? [...localNoteEntries.keys()] : Object.keys(localNotes))
      .filter((np) => !skips.has(np));
    const remoteKeys = (remoteNoteEntries ? [...remoteNoteEntries.keys()] : Object.keys(remoteNotes))
      .filter((np) => !skips.has(np));
    for (const np of localKeys) {
      if (skips.has(np)) continue;
      const txt = Object.hasOwn(localNotes, np)
        ? localNotes[np]
        : (typeof readLocalNote === 'function'
          ? skips.run(np, () => readLocalNote(np, localNoteEntries?.get(np)))
          : undefined);
      if (!skips.has(np) && typeof txt === 'string') {
        for (const a of noteAssetPaths(np, txt)) referenced.add(a);
      }
    }
    for (const np of remoteKeys) {
      if (skips.has(np)) continue;
      const txt = Object.hasOwn(remoteNotes, np)
        ? remoteNotes[np]
        : (typeof readRemoteNote === 'function'
          ? skips.run(np, () => readRemoteNote(np, remoteNoteEntries?.get(np)))
          : undefined);
      if (!skips.has(np) && typeof txt === 'string') {
        for (const a of noteAssetPaths(np, txt)) referenced.add(a);
      }
    }
    const locCi = dirIsCaseInsensitive(rpc, nbRoot, localKeys);
    const remCi = dirIsCaseInsensitive(rpc, targetDir, remoteKeys);
    candidates = new Set([
      ...[...candidates].filter((p) => matchesScope(p, scope, { caseInsensitive: locCi || remCi })),
      ...referenced,
    ]);
  }
  if (excludedSubdirs.size > 0) {
    candidates = new Set([...candidates].filter((p) => !inSyncSubdir(p, excludedSubdirs)));
  }

  const localAssets = Object.create(null);
  const remoteAssets = Object.create(null);
  const remoteAssetPathMap = Object.create(null);
  const hashLocalAsset = (rel) => {
    const options = { cfg, locale, skips, entry: localMetadata.get(rel), snapshot: localSnapshot };
    if (typeof localAdapter.hashAsset === 'function') return localAdapter.hashAsset(nbRoot, rel, options);
    const bytes = localAdapter.readAsset(nbRoot, rel);
    if (bytes === null) return null;
    checkSyncFileSize(bytes.length, cfg, locale);
    return sha256Bytes(bytes, rpc);
  };
  const hashRemoteAsset = (rel) => {
    if (!targetDir || snapshotHasCloudPlaceholder(rpc, remoteSnapshot, targetDir, rel)) return null;
    const full = safeAssetDest(targetDir, rel, excludedSubdirs, locale);
    const entry = remoteMetadata.get(rel) || fsStat(rpc, full);
    if (entry.exists === false || entry.is_icloud_placeholder || !skips.check(rel, entry)) return null;
    const hash = hashSyncFile(full, rpc, () => {
      const bytes = fsReadBytes(rpc, full);
      if (bytes !== null) checkSyncFileSize(bytes.length, cfg, locale);
      return bytes;
    });
    if (hash === null) throw new Error('Attachment changed while opening');
    return hash;
  };

  const gitTrackedAssetsFolded = new Map();
  if (gitTreePaths) {
    for (const tp of [...gitTreePaths].sort()) {
      if (isSafeRelAsset(tp) && !inSyncSubdir(tp, excludedSubdirs)) {
        const fk = foldSyncPath(tp, { caseInsensitive: true, normalize: true });
        if (!gitTrackedAssetsFolded.has(fk)) gitTrackedAssetsFolded.set(fk, []);
        gitTrackedAssetsFolded.get(fk).push(tp);
      }
    }
  }

  for (const rel of [...candidates].sort()) {
    if (excludedSubdirs.size > 0 && inSyncSubdir(rel, excludedSubdirs)) continue;
    skips.run(rel, () => {
      const hash = hashLocalAsset(rel);
      if (hash !== null) {
        const actualRel = localMetadata.has(rel) ? rel : resolveActualRelCasing(rpc, nbRoot, rel, locale);
        if (skips.check(actualRel)) localAssets[actualRel] = hash;
      }
      if (!targetDir || skips.has(rel)) return;
      let actualRel = rel;
      if (gitTreePaths && !gitTreePaths.has(rel)) {
        const fk = foldSyncPath(rel, { caseInsensitive: true, normalize: true });
        const foldedHits = (gitTrackedAssetsFolded.get(fk) || []).filter((cand) =>
          pathsCollapse(rpc, targetDir, rel, cand)
        );
        if (foldedHits.length > 1) {
          throw new Error(collapsedNameError(locale, foldedHits.slice(0, 2).join(' / ')));
        }
        if (foldedHits.length === 1) actualRel = foldedHits[0];
      }
      if (trackedRemotePaths != null && !trackedRemotePaths.has(actualRel)) return;
      const rhash = hashRemoteAsset(actualRel);
      if (rhash !== null) {
        const resolvedRel = remoteMetadata.has(actualRel) || actualRel !== rel
          ? actualRel : resolveActualRelCasing(rpc, targetDir, rel, locale);
        if (skips.check(resolvedRel)) remoteAssets[resolvedRel] = rhash;
      }
    });
  }
  for (const paths of [localAssets, remoteAssets]) {
    for (const rel of Object.keys(paths)) if (skips.has(rel)) delete paths[rel];
  }

  const localFolded = new Map();
  for (const lp of Object.keys(localAssets).sort()) {
    const fk = foldSyncPath(lp, { caseInsensitive: true, normalize: true });
    if (!localFolded.has(fk)) localFolded.set(fk, []);
    localFolded.get(fk).push(lp);
  }
  const remoteFolded = new Map();
  for (const rp of Object.keys(remoteAssets).sort()) {
    const fk = foldSyncPath(rp, { caseInsensitive: true, normalize: true });
    if (!remoteFolded.has(fk)) remoteFolded.set(fk, []);
    remoteFolded.get(fk).push(rp);
  }

  for (const grp of remoteFolded.values()) {
    if (groupCollapses(rpc, grp, nbRoot)) {
      throw new Error(collapsedNameError(locale, grp.slice(0, 2).join(' / ')));
    }
  }
  for (const grp of localFolded.values()) {
    if (groupCollapses(rpc, grp, targetDir)) {
      throw new Error(collapsedNameError(locale, grp.slice(0, 2).join(' / ')));
    }
  }

  for (const [fk, lList] of localFolded.entries()) {
    const rList = remoteFolded.get(fk);
    if (!rList || lList.length !== 1 || rList.length !== 1) continue;
    const lp = lList[0];
    const rp = rList[0];
    if (lp === rp || Object.hasOwn(remoteAssets, lp) || Object.hasOwn(localAssets, rp)) continue;
    const collides = pathsCollapse(rpc, nbRoot, lp, rp) || pathsCollapse(rpc, targetDir, lp, rp);
    if (collides) {
      remoteAssetPathMap[lp] = rp;
      remoteAssets[lp] = remoteAssets[rp];
      delete remoteAssets[rp];
      if (!Object.hasOwn(baseMap, `asset:${lp}`) && Object.hasOwn(baseMap, `asset:${rp}`)) {
        baseMap[`asset:${lp}`] = baseMap[`asset:${rp}`];
      }
    }
  }

  const assetBaseAliases = {};
  const orphanBaseAssets = Object.keys(baseMap)
    .filter((k) => k.startsWith('asset:') && !skips.has(k.slice(6)) && !Object.hasOwn(localAssets, k.slice(6)) && !Object.hasOwn(remoteAssets, k.slice(6)))
    .map((k) => k.slice(6));
  const onlyLocalAssets = Object.keys(localAssets).filter(
    (lp) => !Object.hasOwn(remoteAssets, lp) && !Object.hasOwn(baseMap, `asset:${lp}`)
  );
  const onlyRemoteAssets = Object.keys(remoteAssets).filter(
    (rp) => !Object.hasOwn(localAssets, rp) && !Object.hasOwn(baseMap, `asset:${rp}`)
  );
  pairOrphanBaseKeys(rpc, onlyLocalAssets, orphanBaseAssets, baseMap, 'asset:', nbRoot, targetDir, protocol, assetBaseAliases);
  pairOrphanBaseKeys(rpc, onlyRemoteAssets, orphanBaseAssets, baseMap, 'asset:', nbRoot, targetDir, protocol, assetBaseAliases);

  const pushNew = [];
  const pushOw = [];
  const pullNew = [];
  const pullOw = [];
  const conflicts = [];
  const synced = [];
  const deleteRemote = [];
  const deleteLocal = [];
  const assetDeleteExpectedHashes = {};
  const reservedCopies = new Set();

  const nbSnapshotOk = Boolean(localSnapshot);
  const remoteSnapshotOk = Boolean(remoteSnapshot);
  const nbExists = nbSnapshotOk || Boolean(nbRoot && fsStat(rpc, trimTrailingSlash(nbRoot)).is_dir);
  const targetExists = remoteSnapshotOk || Boolean(targetDir && fsStat(rpc, trimTrailingSlash(targetDir)).is_dir);
  const allowDeleteRemote = !isFirstSync && nbExists;
  const hasRemoteNotes = remoteNoteEntries ? remoteNoteEntries.size > 0 : Object.keys(remoteNotes).length > 0;
  const allowDeleteLocal =
    !isFirstSync &&
    explicitPaths === null &&
    (hasRemoteNotes || Object.keys(remoteAssets).length > 0) &&
    targetExists;

  const allAssetPaths = [...new Set([...Object.keys(localAssets), ...Object.keys(remoteAssets)])].sort();
  for (const rel of allAssetPaths) {
    const lhash = localAssets[rel] ?? null;
    const rhash = remoteAssets[rel] ?? null;
    if (skips.has(rel)) continue;
    if (lhash === rhash) {
      synced.push(rel);
      continue;
    }
    if (lhash === null) {
      if (snapshotHasCloudPlaceholder(rpc, localSnapshot, nbRoot, rel)) continue;
      const assetKey = `asset:${rel}`;
      let matchedDelHash = null;
      if (allowDeleteRemote) {
        const bhash = baseMap[assetKey];
        if (bhash !== undefined) {
          if (rhash === bhash) matchedDelHash = bhash;
        } else if (configStore) {
          const thash = configStore.lookupTombstoneHash(nbKey, assetKey);
          if (thash !== null && rhash === thash) {
            matchedDelHash = thash;
          } else {
            matchedDelHash = configStore.lookupOtherProtocolHash(nbKey, assetKey, rhash);
          }
        }
      }
      if (matchedDelHash !== null) {
        if (!checkMissingSyncPath(nbRoot, rel, (path) => fsStat(rpc, path), skips)) continue;
        deleteRemote.push(rel);
        assetDeleteExpectedHashes[assetKey] = matchedDelHash;
      } else {
        pullNew.push(rel);
      }
      continue;
    }
    if (rhash === null) {
      const targetRel = remoteAssetPathMap[rel] || rel;
      if (targetDir && snapshotHasCloudPlaceholder(rpc, remoteSnapshot, targetDir, targetRel)) continue;
      const baseDel = allowDeleteLocal ? baseMap[`asset:${rel}`] : undefined;
      if (baseDel !== undefined && lhash === baseDel) {
        if (!checkMissingSyncPath(targetDir, targetRel, (path) => fsStat(rpc, path), skips)) continue;
        deleteLocal.push(rel);
        assetDeleteExpectedHashes[`asset:${rel}`] = baseDel;
      } else {
        pushNew.push(rel);
      }
      continue;
    }

    const baseKey = `asset:${rel}`;
    const baseHash = baseMap[baseKey];
    if (baseHash !== undefined && lhash === baseHash && rhash !== baseHash) {
      pullOw.push([rel, false]);
    } else if (baseHash !== undefined && rhash === baseHash && lhash !== baseHash) {
      pushOw.push([rel, false]);
    } else if (policy === 'remote_first') {
      pullOw.push([rel, true]);
    } else if (policy === 'local_first') {
      pushOw.push([rel, true]);
    } else {
      skips.run(rel, () => {
        const [stem, ext] = splitExt(rel);
        const fingerprint = rhash.slice(0, 16);
        for (let attempt = 1; ; attempt += 1) {
          const suffix = attempt === 1 ? '' : `-${attempt}`;
          const copyRel = `${stem}.conflict-${fingerprint}${suffix}${ext}`;
          if (checkSyncFilename(copyRel, locale)) throw new Error('Conflict copy file name too long');
          if (reservedCopies.has(copyRel) || skips.has(copyRel)) continue;
          if (!skips.check(copyRel)) {
            skips.add(rel, 'conflict_copy', tr(locale, `无法同步冲突副本：${copyRel}`, `Cannot sync conflict copy: ${copyRel}`));
            return;
          }
          const lcopy = localAssets[copyRel] ?? hashLocalAsset(copyRel);
          const rcopy = remoteAssets[copyRel] ?? hashRemoteAsset(copyRel);
          if (!skips.has(copyRel) && (lcopy === null || lcopy === rhash) && (rcopy === null || rcopy === rhash)) {
            reservedCopies.add(copyRel);
            conflicts.push([rel, copyRel]);
            break;
          }
        }
      });
    }
  }

  return {
    skipped_items: skips.items,
    local_asset_hashes: localAssets,
    remote_asset_hashes: remoteAssets,
    remote_asset_etags: {},
    remote_asset_path_map: remoteAssetPathMap,
    assets_to_push_new: pushNew,
    assets_to_push_overwrite: pushOw,
    assets_to_pull_new: pullNew,
    assets_to_pull_overwrite: pullOw,
    asset_conflicts: conflicts,
    assets_synced: synced,
    assets_to_delete_remote: deleteRemote,
    assets_to_delete_local: deleteLocal,
    delete_expected_hashes: assetDeleteExpectedHashes,
    asset_base_aliases: assetBaseAliases,
  };
}

/** Shared 3-way note + asset planner for local_mirror and git. */
export function computeThreeWaySyncPlan({
  callHost,
  configStore = null,
  localAdapter,
  protocol,
  cfg,
  nbRoot,
  nbKeyVal,
  nbLabelVal,
  subdir = '',
  excludedSubdirs = new Set(),
  targetDisplay,
  targetDir,
  repoRoot = '',
  metaKey,
  legacyKey = null,
  aliases = [],
  legacyAliases = [],
  localNotes = {},
  remoteNotes = {},
  localSnapshot = null,
  remoteSnapshot = null,
  localNoteEntries = null,
  remoteNoteEntries = null,
  readLocalNote = null,
  readRemoteNote = null,
  remoteInspected,
  remoteError,
  trackedRemotePaths = null,
  gitTreePaths = null,
  onlyPath = null,
  locale = 'zh',
  skips = createSyncSkips(cfg, locale),
} = {}) {
  const rpc = resolveCallHost(callHost);
  const scope = cfg.sync_scope || 'all';
  const policy = cfg.conflict_policy || 'keep_both';
  const originalBaseMap = configStore ? configStore.getBaseMap(metaKey, ...aliases, legacyKey, ...legacyAliases) : {};
  const baseMap = { ...originalBaseMap };
  const initializedMap = configStore ? configStore.state.syncMeta[INITIALIZED_META_KEY] : null;
  const isInitialized = Boolean(
    (initializedMap && typeof initializedMap === 'object' && [metaKey, ...aliases].some((k) => Boolean(initializedMap[k]))) ||
      Object.keys(baseMap).length > 0
  );
  const isFirstSync = !isInitialized;

  let inspected = remoteInspected;
  let errText = remoteError;
  let remoteNonemptyOnFirstSync = false;
  if (remoteInspected && !remoteError && isFirstSync && onlyPath !== null && onlyPath !== undefined) {
    try {
      remoteNonemptyOnFirstSync = remoteHasAnyContent(rpc, cfg, targetDir, excludedSubdirs, locale);
    } catch (exc) {
      inspected = false;
      errText = errorDetail(locale, exc);
    }
  }

  const toPushNew = [];
  const toPushOverwrite = [];
  const toPullNew = [];
  const toPullOverwrite = [];
  const conflicts = [];
  const synced = [];
  const reservedConflictPaths = new Set();
  const remotePathMap = {};
  const baseKeyAliases = {};

  const lazyMode = Boolean(localNoteEntries || remoteNoteEntries);
  const validLocalEntries = new Map();
  const validRemoteEntries = new Map();
  let localKeysSet = new Set();
  let remoteKeysSet = new Set();

  if (inspected && !errText) {
    if (localNoteEntries) {
      for (const [lp, entry] of localNoteEntries.entries()) {
        if (skips.check(lp, entry)) {
          validLocalEntries.set(lp, entry);
          localKeysSet.add(lp);
        }
      }
    } else {
      localNotes = Object.fromEntries(Object.entries(localNotes).filter(([path]) => skips.check(path)));
      localKeysSet = new Set(Object.keys(localNotes));
    }

    if (remoteNoteEntries) {
      for (const [rp, entry] of remoteNoteEntries.entries()) {
        if (skips.check(rp, entry)) {
          validRemoteEntries.set(rp, entry);
          remoteKeysSet.add(rp);
        }
      }
    } else {
      remoteNotes = Object.fromEntries(Object.entries(remoteNotes).filter(([path]) => skips.check(path)));
      remoteKeysSet = new Set(Object.keys(remoteNotes));
    }

    const localFolded = new Map();
    for (const lp of [...localKeysSet].sort()) {
      const fk = foldSyncPath(lp, { caseInsensitive: true, normalize: true });
      if (!localFolded.has(fk)) localFolded.set(fk, []);
      localFolded.get(fk).push(lp);
    }
    const remoteFolded = new Map();
    for (const rp of [...remoteKeysSet].sort()) {
      const fk = foldSyncPath(rp, { caseInsensitive: true, normalize: true });
      if (!remoteFolded.has(fk)) remoteFolded.set(fk, []);
      remoteFolded.get(fk).push(rp);
    }

    for (const grp of remoteFolded.values()) {
      if (groupCollapses(rpc, grp, nbRoot)) {
        inspected = false;
        errText = collapsedNameError(locale, grp.slice(0, 2).join(' / '));
        break;
      }
    }
    if (inspected) {
      for (const grp of localFolded.values()) {
        if (groupCollapses(rpc, grp, targetDir)) {
          inspected = false;
          errText = collapsedNameError(locale, grp.slice(0, 2).join(' / '));
          break;
        }
      }
    }

    if (inspected && !errText) {
      for (const [fk, lList] of localFolded.entries()) {
        const rList = remoteFolded.get(fk);
        if (!rList || lList.length !== 1 || rList.length !== 1) continue;
        const lp = lList[0];
        const rp = rList[0];
        if (lp === rp || remoteKeysSet.has(lp) || localKeysSet.has(rp)) continue;
        if (pathsCollapse(rpc, nbRoot, lp, rp) || pathsCollapse(rpc, targetDir, lp, rp)) {
          remotePathMap[lp] = rp;
          remoteKeysSet.delete(rp);
          remoteKeysSet.add(lp);
          if (validRemoteEntries.has(rp)) {
            validRemoteEntries.set(lp, validRemoteEntries.get(rp));
            validRemoteEntries.delete(rp);
          }
          if (Object.hasOwn(remoteNotes, rp)) {
            remoteNotes[lp] = remoteNotes[rp];
            delete remoteNotes[rp];
          }
          if (!Object.hasOwn(baseMap, lp) && Object.hasOwn(baseMap, rp)) {
            baseMap[lp] = baseMap[rp];
          }
        }
      }

      const orphanBaseNotes = Object.keys(baseMap).filter(
        (bp) => isSafeRelMd(bp) && !skips.has(bp) && !localKeysSet.has(bp) && !remoteKeysSet.has(bp)
      );
      const onlyLocalNotes = [...localKeysSet].filter(
        (lp) => !remoteKeysSet.has(lp) && !Object.hasOwn(baseMap, lp)
      );
      const onlyRemoteNotes = [...remoteKeysSet].filter(
        (rp) => !localKeysSet.has(rp) && !Object.hasOwn(baseMap, rp)
      );
      pairOrphanBaseKeys(rpc, onlyLocalNotes, orphanBaseNotes, baseMap, '', nbRoot, targetDir, protocol, baseKeyAliases);
      pairOrphanBaseKeys(rpc, onlyRemoteNotes, orphanBaseNotes, baseMap, '', nbRoot, targetDir, protocol, baseKeyAliases);
    }
  }

  const localHashes = Object.create(null);
  const remoteHashes = Object.create(null);

  const readSingleLocal = (relPath) => {
    if (Object.hasOwn(localNotes, relPath)) return localNotes[relPath];
    if (typeof readLocalNote !== 'function') return undefined;
    const entry = validLocalEntries.get(relPath);
    const txt = readLocalNote(relPath, entry);
    if (txt === null || txt === undefined) throw new Error('Note changed while opening');
    return txt;
  };

  const readSingleRemote = (relPath) => {
    if (Object.hasOwn(remoteNotes, relPath)) return remoteNotes[relPath];
    if (typeof readRemoteNote !== 'function') return undefined;
    const actualRel = remotePathMap[relPath] || relPath;
    const entry = validRemoteEntries.get(relPath);
    const txt = readRemoteNote(actualRel, entry);
    if (txt === null || txt === undefined) throw new Error('Note changed while opening');
    return txt;
  };

  const hashSingleNote = ({ relPath, side, knownValidHash = '' }) => {
    const hashMap = side === 'local' ? localHashes : remoteHashes;
    if (Object.hasOwn(hashMap, relPath)) return hashMap[relPath];
    const eagerMap = side === 'local' ? localNotes : remoteNotes;
    const entriesMap = side === 'local' ? validLocalEntries : validRemoteEntries;
    const rootDir = side === 'local' ? nbRoot : targetDir;
    const actualRel = side === 'local' ? relPath : (remotePathMap[relPath] || relPath);
    const entry = entriesMap.get(relPath) || null;
    const full = rootDir && actualRel ? posixJoin(trimTrailingSlash(rootDir), actualRel) : '';

    if (Object.hasOwn(eagerMap, relPath)) {
      const h = sha256Text(eagerMap[relPath], rpc);
      hashMap[relPath] = h;
      return h;
    }

    const trustedExpected = (Object.hasOwn(baseMap, relPath) ? baseMap[relPath] : '') || knownValidHash || '';
    if (trustedExpected && full && entry) {
      try {
        const fhash = sha256File(full, rpc);
        if (fhash && fhash === trustedExpected) {
          hashMap[relPath] = fhash;
          return fhash;
        }
      } catch (exc) {
        if (isNotFoundError(exc)) throw new Error('Note changed while opening');
      }
    }

    const txt = side === 'local' ? readSingleLocal(relPath) : readSingleRemote(relPath);
    const h = sha256Text(txt, rpc);
    hashMap[relPath] = h;
    return { hash: h, text: txt };
  };

  const resolveHashValue = (relPath, side, knownValidHash = '') => {
    const res = hashSingleNote({ relPath, side, knownValidHash });
    return typeof res === 'string' ? { hash: res, text: undefined } : res;
  };

  let checkLocalNote = null;
  let checkRemoteNote = null;
  if (inspected && !errText) {
    if (onlyPath !== null && onlyPath !== undefined) {
      checkLocalNote = (cand) => {
        const found = localAdapter.readNotes({ onlyPath: cand, scope, nbRoot, cfg, locale, skips })[cand];
        return skips.has(cand) ? false : found;
      };
      checkRemoteNote = (cand) => {
        if (!targetDir) return null;
        const foundMap = scanMirrorFiles(rpc, targetDir, { onlyPath: cand, scope, excludedSubdirs, locale, cfg, skips });
        if (skips.has(cand)) return false;
        if (Object.hasOwn(foundMap, cand)) return foundMap[cand];
        const firstVal = Object.values(foundMap)[0];
        return firstVal !== undefined ? firstVal : null;
      };
    } else if (lazyMode) {
      checkLocalNote = (cand) => (localKeysSet.has(cand) ? readSingleLocal(cand) : undefined);
      checkRemoteNote = (cand) => (remoteKeysSet.has(cand) ? readSingleRemote(cand) : undefined);
    }

    const allPaths = [...new Set([...localKeysSet, ...remoteKeysSet])].sort();
    for (const relPath of allPaths) {
      if (skips.has(relPath)) continue;
      const inLocal = localKeysSet.has(relPath);
      const inRemote = remoteKeysSet.has(relPath);
      if (inLocal && !inRemote) {
        skips.run(relPath, () => {
          resolveHashValue(relPath, 'local');
          toPushNew.push(relPath);
        });
      } else if (inRemote && !inLocal) {
        skips.run(relPath, () => {
          resolveHashValue(relPath, 'remote');
          toPullNew.push(relPath);
        });
      } else {
        skips.run(relPath, () => {
          const lInfo = resolveHashValue(relPath, 'local');
          const rInfo = resolveHashValue(relPath, 'remote', lInfo.hash);
          const lhash = lInfo.hash;
          const rhash = rInfo.hash;
          const baseHash = baseMap[relPath];
          let action = 'skip';
          if (lhash !== rhash) {
            if (baseHash && baseHash === lhash) action = 'pull';
            else if (baseHash && baseHash === rhash) action = 'push';
            else if (policy === 'local_first') action = 'push';
            else if (policy === 'remote_first') action = 'pull';
            else action = 'keep_both';
          }
          if (action === 'push') {
            toPushOverwrite.push(relPath);
          } else if (action === 'pull') {
            toPullOverwrite.push(relPath);
          } else if (action === 'keep_both') {
            const rtext = rInfo.text !== undefined ? rInfo.text : readSingleRemote(relPath);
            const conflictRel = makeUniqueConflictPath(relPath, rtext, {
              existingLocal: localNotes,
              existingRemote: remoteNotes,
              reserved: reservedConflictPaths,
              checkLocal: checkLocalNote,
              checkRemote: checkRemoteNote,
              checkPath: skips.check,
              callHost: rpc,
            });
            conflicts.push([relPath, conflictRel, rtext]);
          } else {
            synced.push(relPath);
          }
        });
      }
      if (skips.has(relPath)) {
        localKeysSet.delete(relPath);
        remoteKeysSet.delete(relPath);
        validLocalEntries.delete(relPath);
        validRemoteEntries.delete(relPath);
        delete localNotes[relPath];
        delete remoteNotes[relPath];
        delete localHashes[relPath];
        delete remoteHashes[relPath];
      }
    }
  }

  const toDeleteRemote = [];
  const toDeleteLocal = [];
  const deleteExpectedHashes = {};
  const deletionHeld = new Set();

  if (inspected && !errText && !isFirstSync) {
    const localDirOk = Boolean(localSnapshot) || Boolean(nbRoot && fsStat(rpc, trimTrailingSlash(nbRoot)).is_dir);
    const remoteDirOk = Boolean(remoteSnapshot) || Boolean(targetDir && fsStat(rpc, trimTrailingSlash(targetDir)).is_dir);
    for (const relPath of [...toPullNew]) {
      const rhash = remoteHashes[relPath] || sha256Text(readSingleRemote(relPath), rpc);
      const bhash = baseMap[relPath];
      let matchedDelHash = null;
      if (bhash !== undefined) {
        if (rhash === bhash) matchedDelHash = bhash;
      } else if (configStore) {
        const thash = configStore.lookupTombstoneHash(nbKeyVal, relPath);
        if (thash !== null && rhash === thash) {
          matchedDelHash = thash;
        } else {
          matchedDelHash = configStore.lookupOtherProtocolHash(nbKeyVal, relPath, rhash, metaKey);
        }
      }
      if (matchedDelHash === null) continue;
      if (snapshotHasCloudPlaceholder(rpc, localSnapshot, nbRoot, relPath)) {
        const idx = toPullNew.indexOf(relPath);
        if (idx >= 0) toPullNew.splice(idx, 1);
        deletionHeld.add(relPath);
      } else if (localDirOk && matchedDelHash) {
        const idx = toPullNew.indexOf(relPath);
        if (idx >= 0) toPullNew.splice(idx, 1);
        if (!checkMissingSyncPath(nbRoot, relPath, (path) => fsStat(rpc, path), skips)) continue;
        toDeleteRemote.push(relPath);
        deleteExpectedHashes[relPath] = matchedDelHash;
      }
    }

    for (const relPath of [...toPushNew]) {
      const bhash = baseMap[relPath];
      if (bhash === undefined) continue;
      const targetRel = remotePathMap[relPath] || relPath;
      if (snapshotHasCloudPlaceholder(rpc, remoteSnapshot, targetDir, targetRel)) {
        const idx = toPushNew.indexOf(relPath);
        if (idx >= 0) toPushNew.splice(idx, 1);
        deletionHeld.add(relPath);
      } else if (
        onlyPath === null &&
        remoteKeysSet.size > 0 &&
        remoteDirOk &&
        (localHashes[relPath] || sha256Text(readSingleLocal(relPath), rpc)) === bhash
      ) {
        const idx = toPushNew.indexOf(relPath);
        if (idx >= 0) toPushNew.splice(idx, 1);
        if (!checkMissingSyncPath(targetDir, targetRel, (path) => fsStat(rpc, path), skips)) continue;
        toDeleteLocal.push(relPath);
        deleteExpectedHashes[relPath] = bhash;
      }
    }
  }

  let assetPlan = {
    local_asset_hashes: {},
    remote_asset_hashes: {},
    remote_asset_etags: {},
    remote_asset_path_map: {},
    assets_to_push_new: [],
    assets_to_push_overwrite: [],
    assets_to_pull_new: [],
    assets_to_pull_overwrite: [],
    asset_conflicts: [],
    assets_synced: [],
    assets_to_delete_remote: [],
    assets_to_delete_local: [],
    delete_expected_hashes: {},
    asset_base_aliases: {},
  };

  if (inspected && !errText) {
    try {
      assetPlan = planNotebookAssets({
        callHost: rpc,
        configStore,
        localAdapter,
        protocol,
        cfg,
        nbRoot,
        targetDir,
        baseMap,
        policy,
        scope,
        localNotes,
        remoteNotes,
        localSnapshot,
        remoteSnapshot,
        localNoteEntries: localNoteEntries ? validLocalEntries : null,
        remoteNoteEntries: remoteNoteEntries ? validRemoteEntries : null,
        readLocalNote: typeof readLocalNote === 'function' ? readSingleLocal : null,
        readRemoteNote: typeof readRemoteNote === 'function' ? readSingleRemote : null,
        onlyPath,
        excludedSubdirs,
        trackedRemotePaths: protocol === 'git' ? trackedRemotePaths : null,
        gitTreePaths: protocol === 'git' ? gitTreePaths : null,
        isFirstSync,
        nbKey: nbKeyVal,
        locale,
        skips,
      });
    } catch (exc) {
      inspected = false;
      errText = tr(
        locale,
        `附件扫描失败: ${errorDetail(locale, exc)}`,
        `Attachment scan failed: ${errorDetail(locale, exc)}`
      );
    }
  }

  Object.assign(deleteExpectedHashes, assetPlan.delete_expected_hashes || {});
  for (const [ak, aAliases] of Object.entries(assetPlan.asset_base_aliases || {})) {
    if (!Object.hasOwn(baseKeyAliases, ak)) baseKeyAliases[ak] = [];
    for (const oldKey of aAliases) {
      if (!baseKeyAliases[ak].includes(oldKey)) baseKeyAliases[ak].push(oldKey);
    }
  }

  const assetViewCopies = [];
  if (inspected && !errText && policy === 'keep_both' && assetPlan.asset_conflicts.length > 0) {
    const plannedAssetCopyMap = Object.fromEntries(assetPlan.asset_conflicts);
    for (const relPath of synced) {
      if (skips.has(relPath)) continue;
      let rtext;
      if (Object.hasOwn(remoteNotes, relPath)) {
        rtext = remoteNotes[relPath];
      } else if (typeof readRemoteNote === 'function') {
        rtext = skips.run(relPath, () => {
          const txt = readSingleRemote(relPath);
          if (txt !== undefined && Object.hasOwn(remoteHashes, relPath) && sha256Text(txt, rpc) !== remoteHashes[relPath]) {
            const err = new Error(tr(locale, `笔记在扫描后发生变化，已跳过等待重试：${relPath}`, `Note changed after scanning; skipped for retry: ${relPath}`));
            err.code = 'fs_error';
            throw err;
          }
          return txt;
        });
      }
      if (rtext === undefined || skips.has(relPath)) continue;
      const rewritten = rewriteNoteAssetLinks(relPath, rtext, plannedAssetCopyMap);
      if (rewritten !== rtext) {
        const conflictRel = makeUniqueConflictPath(relPath, rewritten, {
          existingLocal: localNotes,
          existingRemote: remoteNotes,
          reserved: reservedConflictPaths,
          checkLocal: checkLocalNote,
          checkRemote: checkRemoteNote,
          checkPath: skips.check,
          callHost: rpc,
        });
        assetViewCopies.push([relPath, conflictRel, rtext]);
      }
    }
  }

  const missingScopeCi = dirIsCaseInsensitive(rpc, nbRoot, [...localKeysSet]);
  let remoteMissing = [];
  let localMissing = [];
  if (inspected) {
    if (onlyPath === null || onlyPath === undefined) {
      for (const p of Object.keys(baseMap)) {
        if (!isSafeRelMd(p) || !matchesScope(p, scope, { caseInsensitive: missingScopeCi })) continue;
        if (localKeysSet.has(p) && !remoteKeysSet.has(p)) remoteMissing.push(p);
        if (remoteKeysSet.has(p) && !localKeysSet.has(p)) localMissing.push(p);
      }
    } else if (Object.hasOwn(baseMap, onlyPath)) {
      if (localKeysSet.has(onlyPath) && !remoteKeysSet.has(onlyPath)) remoteMissing.push(onlyPath);
      if (remoteKeysSet.has(onlyPath) && !localKeysSet.has(onlyPath)) localMissing.push(onlyPath);
    }
  }

  remoteMissing = remoteMissing.filter((p) => !skips.has(p));
  localMissing = localMissing.filter((p) => !skips.has(p));
  if (deletionHeld.size > 0) {
    remoteMissing = remoteMissing.filter((p) => !deletionHeld.has(p));
    localMissing = localMissing.filter((p) => !deletionHeld.has(p));
  }
  for (const p of toDeleteRemote) {
    if (!deletionHeld.has(p) && !localMissing.includes(p)) {
      localMissing.push(p);
    }
  }

  const sortedLocalHashes = Object.fromEntries(
    Object.keys(localHashes).sort().map((p) => [p, localHashes[p]])
  );
  const sortedRemoteHashes = Object.fromEntries(
    Object.keys(remoteHashes).sort().map((p) => [p, remoteHashes[p]])
  );
  const localAssetHashes = Object.fromEntries(Object.entries(assetPlan.local_asset_hashes).sort());
  const remoteAssetHashes = Object.fromEntries(Object.entries(assetPlan.remote_asset_hashes).sort());
  const baseHashes = Object.fromEntries(
    Object.keys(baseMap)
      .sort()
      .filter(
        (p) =>
          localKeysSet.has(p) ||
          remoteKeysSet.has(p) ||
          (p.startsWith('asset:') &&
            (Object.hasOwn(localAssetHashes, p.slice(6)) || Object.hasOwn(remoteAssetHashes, p.slice(6))))
      )
      .map((p) => [p, baseMap[p]])
  );

  const fpPayload = JSON.stringify({
    nb: nbKeyVal,
    subdir,
    excluded_subdirs: [...excludedSubdirs].sort(),
    protocol,
    target: targetDisplay,
    scope,
    policy,
    push_new: toPushNew,
    push_ow: toPushOverwrite,
    pull_new: toPullNew,
    pull_ow: toPullOverwrite,
    conflicts: conflicts.map((c) => [c[0], c[1]]),
    asset_view_copies: assetViewCopies.map((c) => [c[0], c[1]]),
    assets_push_new: assetPlan.assets_to_push_new,
    assets_push_ow: assetPlan.assets_to_push_overwrite.map((a) => a[0]),
    assets_pull_new: assetPlan.assets_to_pull_new,
    assets_pull_ow: assetPlan.assets_to_pull_overwrite.map((a) => a[0]),
    asset_conflicts: assetPlan.asset_conflicts.map((a) => [a[0], a[1]]),
    remote_missing: remoteMissing,
    local_missing: localMissing,
    delete_remote: toDeleteRemote,
    delete_local: toDeleteLocal,
    assets_delete_remote: assetPlan.assets_to_delete_remote,
    assets_delete_local: assetPlan.assets_to_delete_local,
    local_hashes: sortedLocalHashes,
    remote_hashes: sortedRemoteHashes,
    local_asset_hashes: localAssetHashes,
    remote_asset_hashes: remoteAssetHashes,
    base_hashes: baseHashes,
    remote_path_map: remotePathMap,
    remote_asset_path_map: assetPlan.remote_asset_path_map,
  });

  const exposedReadLocal = typeof readLocalNote === 'function' ? readSingleLocal : null;
  const exposedReadRemote = typeof readRemoteNote === 'function' ? readSingleRemote : null;

  return {
    cfg: { ...cfg },
    nb_root: nbRoot,
    nb_key: nbKeyVal,
    nb_label: nbLabelVal,
    subdir,
    excluded_subdirs: excludedSubdirs,
    protocol,
    target_display: targetDisplay,
    target_dir: targetDir,
    repo_root: repoRoot,
    base_url: '',
    meta_key: metaKey,
    base_map: baseMap,
    original_base_map: originalBaseMap,
    skipped_items: skips.items,
    skips,
    is_first_sync: isFirstSync,
    remote_nonempty_on_first_sync: remoteNonemptyOnFirstSync,
    local_notes: localNotes,
    remote_notes: remoteNotes,
    local_hashes: sortedLocalHashes,
    remote_hashes: sortedRemoteHashes,
    local_note_keys: [...localKeysSet],
    remote_note_keys: [...remoteKeysSet],
    read_local_note: exposedReadLocal,
    read_remote_note: exposedReadRemote,
    remote_etags: {},
    remote_path_map: remotePathMap,
    remote_inspected: inspected,
    remote_error: errText,
    to_push_new: toPushNew,
    to_push_overwrite: toPushOverwrite,
    to_pull_new: toPullNew,
    to_pull_overwrite: toPullOverwrite,
    conflicts,
    asset_view_copies: assetViewCopies,
    synced,
    ...assetPlan,
    remote_missing: remoteMissing,
    local_missing: localMissing,
    to_delete_remote: toDeleteRemote,
    to_delete_local: toDeleteLocal,
    delete_expected_hashes: deleteExpectedHashes,
    base_key_aliases: baseKeyAliases,
    policy,
    scope,
    fingerprint: sha256Text(fpPayload, rpc),
  };
}

/** Compute numerical risk counts for a sync plan. */
export function planRiskMetrics(callHost, plan) {
  const baseMap = plan.base_map || {};
  const localNotes = plan.local_notes || {};
  const remoteNotes = plan.remote_notes || {};
  const localHashes = plan.local_hashes || {};
  const remoteHashes = plan.remote_hashes || {};
  const getLocalHash = (p) =>
    localHashes[p] || (Object.hasOwn(localNotes, p) ? sha256Text(localNotes[p], callHost) : '');
  const getRemoteHash = (p) =>
    remoteHashes[p] || (Object.hasOwn(remoteNotes, p) ? sha256Text(remoteNotes[p], callHost) : '');
  const nPullNew = plan.to_pull_new.length + (plan.assets_to_pull_new || []).length;
  const nPullTotal = plan.to_pull_overwrite.length + (plan.assets_to_pull_overwrite || []).length;
  const nPullConflict =
    plan.to_pull_overwrite.filter((p) => baseMap[p] !== getLocalHash(p)).length +
    (plan.assets_to_pull_overwrite || []).filter(([, isConf]) => Boolean(isConf)).length;
  const nPushConflict =
    plan.to_push_overwrite.filter((p) => baseMap[p] !== getRemoteHash(p)).length +
    (plan.assets_to_push_overwrite || []).filter(([, isConf]) => Boolean(isConf)).length;
  const nConf =
    plan.conflicts.length +
    (plan.asset_view_copies || []).length +
    (plan.asset_conflicts || []).length;
  const nRmMiss = plan.remote_missing.length + (plan.assets_to_delete_local || []).length;
  const locMissNotes = new Set([...(plan.local_missing || []), ...(plan.to_delete_remote || [])]);
  const nLocMiss = locMissNotes.size + (plan.assets_to_delete_remote || []).length;
  return {
    pull_new: nPullNew,
    pull_total: nPullTotal,
    pull_conflict: nPullConflict,
    push_conflict: nPushConflict,
    conflicts: nConf,
    remote_missing: nRmMiss,
    local_missing: nLocMiss,
  };
}

/** Assess dangerous change reason items for a single notebook plan. */
export function assessDangerousChanges(callHost, plan, cfg, nbLabelVal = '') {
  if (!plan.remote_inspected) return [];
  const items = [];
  const policy = plan.policy || cfg.conflict_policy || 'keep_both';
  const m = planRiskMetrics(callHost, plan);

  if (plan.is_first_sync) {
    if (m.pull_new > 0 || m.pull_conflict > 0 || m.push_conflict > 0 || m.conflicts > 0) {
      items.push({
        kind: 'first_sync',
        nb_label: nbLabelVal,
        pull_new: m.pull_new,
        pull_ow: m.pull_conflict,
        push_ow: m.push_conflict,
        conflicts: m.conflicts,
      });
    } else if (plan.remote_nonempty_on_first_sync) {
      items.push({ kind: 'first_sync_nonempty', nb_label: nbLabelVal });
    }
  } else {
    if (m.pull_conflict > 0 && (policy !== 'remote_first' || m.pull_conflict > DELETE_GUARD_THRESHOLD)) {
      items.push({ kind: 'pull_conflict', nb_label: nbLabelVal, count: m.pull_conflict });
    }
    if (m.push_conflict > 0 && (policy !== 'local_first' || m.push_conflict > DELETE_GUARD_THRESHOLD)) {
      items.push({ kind: 'push_conflict', nb_label: nbLabelVal, count: m.push_conflict });
    }
    if (cfg.delete_guard !== false && m.remote_missing > 0 && m.remote_missing <= DELETE_GUARD_THRESHOLD) {
      const autoDeleted = new Set(plan.to_delete_local || []);
      for (const p of plan.remote_missing) {
        if (!autoDeleted.has(p)) {
          items.push({ kind: 'remote_missing_single', nb_label: nbLabelVal, path: p });
        }
      }
    }
  }

  if (cfg.delete_guard !== false && (m.remote_missing > DELETE_GUARD_THRESHOLD || m.local_missing > DELETE_GUARD_THRESHOLD)) {
    items.push({
      kind: 'delete_guard',
      nb_label: nbLabelVal,
      remote_missing: m.remote_missing,
      local_missing: m.local_missing,
    });
  } else if (m.pull_new + m.pull_total > DELETE_GUARD_THRESHOLD) {
    items.push({ kind: 'bulk_pull', nb_label: nbLabelVal, count: m.pull_new + m.pull_total });
  }
  return items;
}

/** Assess aggregated dangerous changes across a batch of notebook plans. */
export function assessBatchDangerousChanges(callHost, batch, cfg) {
  const reasonItems = [];
  const multi = batch.plans.length > 1;
  const policy = cfg.conflict_policy || 'keep_both';
  let totalRmMiss = 0;
  let totalLocMiss = 0;
  let totalPullWrites = 0;
  let totalPullConflicts = 0;
  let totalPushConflicts = 0;
  let hasDeleteGuard = false;
  let hasBulkPull = false;
  let hasPullConflict = false;
  let hasPushConflict = false;

  for (const plan of batch.plans) {
    const nbLbl = multi ? plan.nb_label : '';
    const nbItems = assessDangerousChanges(callHost, plan, cfg, nbLbl);
    for (const it of nbItems) {
      if (it.kind === 'delete_guard') hasDeleteGuard = true;
      else if (it.kind === 'bulk_pull') hasBulkPull = true;
      else if (it.kind === 'pull_conflict') hasPullConflict = true;
      else if (it.kind === 'push_conflict') hasPushConflict = true;
      reasonItems.push(it);
    }
    if (plan.remote_inspected) {
      const m = planRiskMetrics(callHost, plan);
      totalRmMiss += m.remote_missing;
      totalLocMiss += m.local_missing;
      totalPullWrites += m.pull_new + m.pull_total;
      if (!plan.is_first_sync) {
        totalPullConflicts += m.pull_conflict;
        totalPushConflicts += m.push_conflict;
      }
    }
  }

  if (multi) {
    if (
      !hasDeleteGuard &&
      cfg.delete_guard !== false &&
      (totalRmMiss > DELETE_GUARD_THRESHOLD || totalLocMiss > DELETE_GUARD_THRESHOLD)
    ) {
      reasonItems.push({
        kind: 'delete_guard',
        nb_label: '',
        remote_missing: totalRmMiss,
        local_missing: totalLocMiss,
      });
    }
    if (!hasBulkPull && totalPullWrites > DELETE_GUARD_THRESHOLD) {
      reasonItems.push({ kind: 'bulk_pull', nb_label: '', count: totalPullWrites });
    }
    if (!hasPullConflict && policy === 'remote_first' && totalPullConflicts > DELETE_GUARD_THRESHOLD) {
      reasonItems.push({ kind: 'pull_conflict', nb_label: '', count: totalPullConflicts });
    }
    if (!hasPushConflict && policy === 'local_first' && totalPushConflicts > DELETE_GUARD_THRESHOLD) {
      reasonItems.push({ kind: 'push_conflict', nb_label: '', count: totalPushConflicts });
    }
  }
  return reasonItems;
}

/** Build a pending confirmation payload matching main.py's structure. */
export function buildPendingConfirm(
  callHost,
  batch,
  reasonItems,
  {
    configStore = null,
    locale = 'zh',
    onlyPath = null,
    onlyNbRoot = null,
  } = {}
) {
  const sampleItems = [];
  let totalSamples = 0;

  const addSample = (kind, p, extra = '') => {
    totalSamples += 1;
    if (sampleItems.length < MAX_STORED_CONFIRM_SAMPLES) {
      const item = { kind, path: p };
      if (extra) item.extra = extra;
      sampleItems.push(item);
    }
  };

  const multi = batch.plans.length > 1;
  for (const plan of batch.plans) {
    const prefix = multi ? `${plan.nb_label}/` : '';
    const baseMap = plan.base_map || {};
    const localNotes = plan.local_notes || {};
    const remoteNotes = plan.remote_notes || {};
    const localHashes = plan.local_hashes || {};
    const remoteHashes = plan.remote_hashes || {};
    const getLocalHash = (p) =>
      localHashes[p] || (Object.hasOwn(localNotes, p) ? sha256Text(localNotes[p], callHost) : '');
    const getRemoteHash = (p) =>
      remoteHashes[p] || (Object.hasOwn(remoteNotes, p) ? sha256Text(remoteNotes[p], callHost) : '');
    for (const p of plan.to_pull_overwrite) {
      addSample(baseMap[p] !== getLocalHash(p) ? 'pull_ow' : 'pull_upd', `${prefix}${p}`);
    }
    for (const p of plan.to_push_overwrite) {
      addSample(baseMap[p] !== getRemoteHash(p) ? 'push_ow' : 'push_upd', `${prefix}${p}`);
    }
    for (const [p, cr] of plan.conflicts) {
      addSample('conflict', `${prefix}${p}`, cr);
    }
    for (const [p, isConf] of plan.assets_to_pull_overwrite || []) {
      addSample(isConf ? 'pull_ow' : 'pull_upd', `${prefix}${p}`);
    }
    for (const [p, isConf] of plan.assets_to_push_overwrite || []) {
      addSample(isConf ? 'push_ow' : 'push_upd', `${prefix}${p}`);
    }
    for (const [p, cr] of plan.asset_conflicts || []) {
      addSample('conflict', `${prefix}${p}`, cr);
    }
    for (const p of plan.to_pull_new) addSample('pull_new', `${prefix}${p}`);
    for (const p of plan.assets_to_pull_new || []) addSample('pull_new', `${prefix}${p}`);
    for (const p of plan.to_push_new) addSample('push_new', `${prefix}${p}`);
    for (const p of plan.assets_to_push_new || []) addSample('push_new', `${prefix}${p}`);
    for (const p of plan.remote_missing) addSample('rm_miss', `${prefix}${p}`);
    for (const p of plan.local_missing) addSample('loc_miss', `${prefix}${p}`);
  }

  return {
    scope_key: configStore ? configStore.resultKey() : 'default',
    fingerprint: batch.fingerprint,
    protocol: batch.protocol,
    target_display: batch.target_display,
    reason_items: reasonItems.slice(0, 30),
    reasons: reasonItems.slice(0, 30).map((r) => formatReasonItem(locale, r, DELETE_GUARD_THRESHOLD)),
    sample_items: sampleItems,
    total_samples: totalSamples,
    only_path: onlyPath,
    only_nb_root: onlyNbRoot,
  };
}

/** Shared notebook plan applicator used by both local_mirror and git engines. */
export function applyMirrorOrGitNotebookPlan(
  plan,
  {
    callHost,
    notifyHost = null,
    configStore = null,
    localAdapter,
    locale = 'zh',
    dataDir = '',
    pid = 1,
    nowMsFn = () => Date.now(),
    sleepFn = null,
    progressState = null,
    beforeRemoteWrite = null,
    afterRemoteDelete = null,
    skipLock = false,
  } = {}
) {
  const rpc = resolveCallHost(callHost);
  const protocol = plan.protocol || 'local_mirror';
  const protoLbl = protocolLabel(locale, protocol);
  const state = configStore ? configStore.state : { logs: [], syncMeta: {} };
  const cfg = plan.cfg;
  const nbRoot = plan.nb_root;
  const nbKeyVal = plan.nb_key;
  const subdir = plan.subdir || '';
  const targetDir = plan.target_dir;
  const excludedSubdirs = plan.excluded_subdirs || new Set();
  const baseMap = { ...(plan.base_map || {}) };
  const originalBaseMap = plan.original_base_map || plan.base_map || {};
  const skips = plan.skips || createSyncSkips(cfg, locale);
  plan.skipped_items = skips.items;
  const restoreBase = () => restoreSkippedBase(baseMap, originalBaseMap, skips);
  const localNotes = plan.local_notes || {};
  const remoteNotes = plan.remote_notes || {};
  const localHashes = plan.local_hashes || {};
  const remoteHashes = plan.remote_hashes || {};
  const localNoteSet = plan.local_note_keys instanceof Set
    ? plan.local_note_keys
    : Array.isArray(plan.local_note_keys)
      ? new Set(plan.local_note_keys)
      : null;
  const hasLocalNote = (relPath) =>
    localNoteSet ? localNoteSet.has(relPath) : Object.hasOwn(localNotes, relPath);
  const getLocalText = (relPath) => {
    if (Object.hasOwn(localNotes, relPath)) return localNotes[relPath];
    if (typeof plan.read_local_note === 'function') {
      const txt = plan.read_local_note(relPath);
      if (txt !== null && txt !== undefined) return txt;
    }
    return undefined;
  };
  const getRemoteText = (relPath) => {
    if (Object.hasOwn(remoteNotes, relPath)) return remoteNotes[relPath];
    if (typeof plan.read_remote_note === 'function') {
      const txt = plan.read_remote_note(relPath);
      if (txt !== null && txt !== undefined) return txt;
    }
    return undefined;
  };
  const getLocalHash = (relPath) => {
    if (Object.hasOwn(localHashes, relPath)) return localHashes[relPath];
    const txt = getLocalText(relPath);
    return txt !== undefined ? sha256Text(txt, rpc) : null;
  };
  const getRemoteHash = (relPath) => {
    if (Object.hasOwn(remoteHashes, relPath)) return remoteHashes[relPath];
    const txt = getRemoteText(relPath);
    return txt !== undefined ? sha256Text(txt, rpc) : null;
  };
  const verifyPlannedText = (relPath, txt, expectedHashes) => {
    if (txt === undefined || txt === null) {
      const err = new Error(tr(locale, `笔记在扫描后消失或变化：${relPath}`, `Note changed during sync: ${relPath}`));
      err.code = 'fs_error';
      throw err;
    }
    const expected = Object.hasOwn(expectedHashes, relPath) ? expectedHashes[relPath] : null;
    if (expected && sha256Text(txt, rpc) !== expected) {
      const err = new Error(tr(locale, `笔记在扫描后发生变化，已跳过等待重试：${relPath}`, `Note changed after scanning; skipped for retry: ${relPath}`));
      err.code = 'fs_error';
      throw err;
    }
    return txt;
  };
  const getVerifiedLocalText = (relPath) => {
    if (Object.hasOwn(localNotes, relPath)) return localNotes[relPath];
    return verifyPlannedText(relPath, getLocalText(relPath), localHashes);
  };
  const getVerifiedRemoteText = (relPath) => {
    if (Object.hasOwn(remoteNotes, relPath)) return remoteNotes[relPath];
    return verifyPlannedText(relPath, getRemoteText(relPath), remoteHashes);
  };
  const localAssets = plan.local_asset_hashes || {};
  const remoteAssets = plan.remote_asset_hashes || {};
  const remotePathMap = plan.remote_path_map || {};
  const remoteAssetPathMap = plan.remote_asset_path_map || {};
  const readLocalAsset = (rel) => readPlannedAsset(
    () => localAdapter.readAsset(nbRoot, rel), localAssets[rel], cfg, rpc, locale
  );
  const readRemoteAsset = (rel) => readPlannedAsset(
    () => readAssetFile(rpc, targetDir, remoteAssetPathMap[rel] || rel, excludedSubdirs),
    remoteAssets[rel], cfg, rpc, locale
  );
  const batchBaseRoot = plan.batch_base_root || (protocol === 'local_mirror' ? resolveMirrorDir(cfg) : plan.repo_root || '');
  const batchBindings = plan.batch_bindings || {};
  const targetIdentities = { ...(plan.target_identities || {}) };
  const writtenRemotePaths = [];
  const deletedGitPaths = [];
  const plannedGitBlobs = {};

  const emitProgress = (params) => {
    try {
      const notifyFn = typeof notifyHost === 'function'
        ? notifyHost
        : typeof globalThis.notifyHost === 'function'
          ? globalThis.notifyHost
          : null;
      if (notifyFn) notifyFn('host.action.progress', params);
      else rpc('host.action.progress', params);
    } catch (_err) {
      // Progress notifications are best-effort.
    }
  };

  const appendLog = (title, status, { tone = '', tooltip = '', logKey = null, logArgs = null } = {}) => {
    const raw = {
      title: String(title || tr(locale, '同步任务', 'Sync task')).trim() || tr(locale, '同步任务', 'Sync task'),
      status: String(status || '成功').trim() || '成功',
      time: nowHms(),
      tone,
      tooltip,
      protocol_id: protocol,
    };
    if (logKey) {
      raw.log_key = logKey;
      raw.log_args = { ...(logArgs || {}), protocol };
    }
    if (locale === 'en') raw.locale = 'en';
    state.logs.unshift(raw);
    if (state.logs.length > MAX_LOG_ENTRIES) state.logs.length = MAX_LOG_ENTRIES;
  };

  const verifyTarget = () => {
    if (!batchBaseRoot) return;
    if (Object.keys(batchBindings).length > 0) {
      const { identities, error } = validatePhysicalTargets(rpc, protocol, batchBindings, batchBaseRoot, {
        expectedIdentities: targetIdentities,
        locale,
        homeDir: configStore ? configStore.state.homeDir : '',
      });
      if (error) throw new Error(error);
      for (const [kNb, info] of Object.entries(identities)) {
        if (Object.hasOwn(targetIdentities, kNb)) {
          const cur = { ...targetIdentities[kNb] };
          if (!cur.exists && info.exists) {
            cur.exists = info.exists;
            cur.is_dir = info.is_dir;
            cur.path = info.path;
          }
          targetIdentities[kNb] = cur;
        }
      }
    }
  };

  const recordRemotePath = (rel, blob) => {
    const subTrim = subdir.replace(/^\/+|\/+$/g, '');
    const repoRel = subTrim ? `${subTrim}/${rel}` : rel;
    writtenRemotePaths.push(repoRel);
    if (protocol === 'git') plannedGitBlobs[repoRel] = blob;
  };

  const writeRemoteNote = (rel, text, { expectedHash = null, createOnly = false } = {}) => {
    const targetRel = remotePathMap[rel] || rel;
    writeMirrorFile(rpc, targetDir, targetRel, text, {
      expectedHash,
      createOnly,
      excludedSubdirs,
      verifyTarget,
      locale,
      dataDir,
      pid,
      nowMsFn,
    });
    recordRemotePath(targetRel, textToBytes(text));
  };

  const writeRemoteAsset = (
    rel,
    data,
    hash,
    { expectedHash = null, createOnly = false, copyFromPath = '', readFallback = null } = {}
  ) => {
    const targetRel = remoteAssetPathMap[rel] || rel;
    writeMirrorBytes(rpc, targetDir, targetRel, data, {
      expectedHash,
      createOnly,
      copyFromPath,
      sourceHash: hash,
      readFallback,
      excludedSubdirs,
      verifyTarget,
      locale,
      dataDir,
      pid,
      nowMsFn,
    });
    recordRemotePath(targetRel, { file_path: posixJoin(targetDir, targetRel), hash });
  };

  let pushed = 0;
  let pulled = 0;
  let conflictCount = 0;
  let assetCount = 0;
  const prefix = subdir ? `${plan.nb_label}/` : '';
  const assetCopyMap = {};

  const stepProgress = () => {
    if (progressState && progressState.total > 0) {
      progressState.done += 1;
      emitProgress({
        channel: protocol,
        done: progressState.done,
        total: progressState.total,
        label: tr(locale, '同步中', 'Syncing'),
        tone: 'accent',
        running: true,
      });
    }
  };

  const runInsideLock = () => {
    verifyTarget();
    fsMkdir(rpc, targetDir, true);
    verifyTarget();
    if (typeof beforeRemoteWrite === 'function') {
      beforeRemoteWrite();
    }

    // 1. Sync attachments first.
    skips.each(plan.assets_synced, (rel) => {
      baseMap[`asset:${rel}`] = localAssets[rel];
      if (configStore) configStore.clearTombstone(nbKeyVal, `asset:${rel}`);
    });

    const localAssetPath = (rel) => posixJoin(trimTrailingSlash(nbRoot), rel);
    const remoteAssetPath = (rel) => posixJoin(trimTrailingSlash(targetDir), remoteAssetPathMap[rel] || rel);

    skips.each(plan.assets_to_push_new, (rel) => {
      writeRemoteAsset(rel, null, localAssets[rel], {
        createOnly: true,
        copyFromPath: localAssetPath(rel),
        readFallback: () => readLocalAsset(rel),
      });
      baseMap[`asset:${rel}`] = localAssets[rel];
      if (configStore) configStore.clearTombstone(nbKeyVal, `asset:${rel}`);
      assetCount += 1;
      stepProgress();
    });

    skips.each(plan.assets_to_push_overwrite, ([rel]) => {
      writeRemoteAsset(rel, null, localAssets[rel], {
        expectedHash: remoteAssets[rel],
        copyFromPath: localAssetPath(rel),
        readFallback: () => readLocalAsset(rel),
      });
      baseMap[`asset:${rel}`] = localAssets[rel];
      if (configStore) configStore.clearTombstone(nbKeyVal, `asset:${rel}`);
      assetCount += 1;
      stepProgress();
    });

    skips.each(plan.assets_to_pull_new, (rel) => {
      const rhash = remoteAssets[rel];
      if (!plan.is_first_sync && configStore && configStore.lookupTombstoneHash(nbKeyVal, `asset:${rel}`) === rhash) {
        stepProgress();
        return;
      }
      localAdapter.writeAsset(nbRoot, rel, null, {
        createOnly: true,
        copyFromPath: remoteAssetPath(rel),
        sourceHash: rhash,
        readFallback: () => readRemoteAsset(rel),
      });
      baseMap[`asset:${rel}`] = rhash;
      if (configStore) configStore.clearTombstone(nbKeyVal, `asset:${rel}`);
      assetCount += 1;
      stepProgress();
    });

    skips.each(plan.assets_to_pull_overwrite, ([rel]) => {
      localAdapter.writeAsset(nbRoot, rel, null, {
        expectedHash: localAssets[rel],
        copyFromPath: remoteAssetPath(rel),
        sourceHash: remoteAssets[rel],
        readFallback: () => readRemoteAsset(rel),
      });
      baseMap[`asset:${rel}`] = remoteAssets[rel];
      if (configStore) configStore.clearTombstone(nbKeyVal, `asset:${rel}`);
      assetCount += 1;
      stepProgress();
    });

    const deferredAssetOverwrites = [];
    skips.each(plan.asset_conflicts, ([rel, copyRel]) => {
      const rhash = remoteAssets[rel];
      const srcPath = remoteAssetPath(rel);
      const readRdata = () => readRemoteAsset(rel);
      localAdapter.writeAsset(nbRoot, copyRel, null, {
        createOnly: true,
        copyFromPath: srcPath,
        sourceHash: rhash,
        readFallback: readRdata,
      });
      writeRemoteAsset(copyRel, null, rhash, {
        createOnly: true,
        copyFromPath: srcPath,
        readFallback: readRdata,
      });
      baseMap[`asset:${copyRel}`] = rhash;
      if (configStore) configStore.clearTombstone(nbKeyVal, `asset:${copyRel}`);
      assetCopyMap[rel] = copyRel;
      deferredAssetOverwrites.push(rel);
      assetCount += 1;
      stepProgress();
    }, (paths) => paths);

    if (assetCount > 0) {
      appendLog(tr(locale, `${prefix}同步 ${assetCount} 个附件`, `${prefix}Synced attachments: ${assetCount}`), '成功', {
        tone: 'success',
        logKey: 'assets_synced',
        logArgs: { prefix, count: assetCount },
      });
    }

    // 2. Sync notes.
    skips.each(plan.synced, (relPath) => {
      baseMap[relPath] = getLocalHash(relPath);
      if (configStore) configStore.clearTombstone(nbKeyVal, relPath);
    });

    skips.each(plan.to_push_new, (relPath) => {
      const text = getVerifiedLocalText(relPath);
      writeRemoteNote(relPath, text, { createOnly: true });
      baseMap[relPath] = getLocalHash(relPath) || sha256Text(text, rpc);
      if (configStore) configStore.clearTombstone(nbKeyVal, relPath);
      pushed += 1;
      appendLog(tr(locale, `推送 ${prefix}${relPath}`, `Push ${prefix}${relPath}`), '成功', {
        tone: 'success',
        tooltip: tr(locale, `已推送到${protoLbl}`, `Pushed to ${protoLbl}`),
        logKey: 'push_new',
        logArgs: { path: `${prefix}${relPath}` },
      });
      stepProgress();
    });

    skips.each(plan.to_push_overwrite, (relPath) => {
      const text = getVerifiedLocalText(relPath);
      const remoteHash = getRemoteHash(relPath);
      const isConflict = baseMap[relPath] !== remoteHash;
      writeRemoteNote(relPath, text, { expectedHash: remoteHash });
      baseMap[relPath] = getLocalHash(relPath) || sha256Text(text, rpc);
      if (configStore) configStore.clearTombstone(nbKeyVal, relPath);
      pushed += 1;
      appendLog(
        isConflict
          ? tr(locale, `本地覆盖 ${prefix}${relPath}`, `Overwrite remote: ${prefix}${relPath}`)
          : tr(locale, `更新 ${prefix}${relPath}`, `Update ${prefix}${relPath}`),
        '成功',
        {
          tone: 'success',
          tooltip: isConflict
            ? tr(locale, `本地优先覆盖${protoLbl}`, `Local version took precedence on ${protoLbl}`)
            : tr(locale, `已同步修改到${protoLbl}`, `Synced changes to ${protoLbl}`),
          logKey: isConflict ? 'push_overwrite' : 'push_update',
          logArgs: { path: `${prefix}${relPath}` },
        }
      );
      stepProgress();
    });

    skips.each(plan.to_pull_new, (relPath) => {
      const origText = getVerifiedRemoteText(relPath);
      const origHash = getRemoteHash(relPath) || sha256Text(origText, rpc);
      if (!plan.is_first_sync && configStore && configStore.lookupTombstoneHash(nbKeyVal, relPath) === origHash) {
        stepProgress();
        return;
      }
      const text = rewriteNoteAssetLinks(relPath, origText, assetCopyMap);
      localAdapter.writeNote(relPath, text, { nbRoot });
      if (text !== origText) {
        writeRemoteNote(relPath, text, { expectedHash: origHash });
      }
      baseMap[relPath] = text === origText ? origHash : sha256Text(text, rpc);
      if (configStore) configStore.clearTombstone(nbKeyVal, relPath);
      pulled += 1;
      appendLog(tr(locale, `拉取 ${prefix}${relPath}`, `Pull ${prefix}${relPath}`), '成功', {
        tone: 'success',
        tooltip: tr(locale, `已从${protoLbl}拉取`, `Pulled from ${protoLbl}`),
        logKey: 'pull_new',
        logArgs: { path: `${prefix}${relPath}` },
      });
      stepProgress();
    });

    skips.each(plan.to_pull_overwrite, (relPath) => {
      const origText = getVerifiedRemoteText(relPath);
      const origHash = getRemoteHash(relPath) || sha256Text(origText, rpc);
      const text = rewriteNoteAssetLinks(relPath, origText, assetCopyMap);
      const localHash = getLocalHash(relPath);
      const isConflict = baseMap[relPath] !== localHash;
      localAdapter.writeNote(relPath, text, { nbRoot, expectedRevision: localHash });
      if (text !== origText) {
        writeRemoteNote(relPath, text, { expectedHash: origHash });
      }
      baseMap[relPath] = text === origText ? origHash : sha256Text(text, rpc);
      if (configStore) configStore.clearTombstone(nbKeyVal, relPath);
      pulled += 1;
      appendLog(
        isConflict
          ? tr(locale, `远端覆盖 ${prefix}${relPath}`, `Overwrite local: ${prefix}${relPath}`)
          : tr(locale, `拉取更新 ${prefix}${relPath}`, `Pull update: ${prefix}${relPath}`),
        '成功',
        {
          tone: 'success',
          tooltip: isConflict
            ? tr(locale, `${protoLbl}优先更新本地`, `Version from ${protoLbl} replaced the local copy`)
            : tr(locale, `已从${protoLbl}拉取更新`, `Pulled update from ${protoLbl}`),
          logKey: isConflict ? 'pull_overwrite' : 'pull_update',
          logArgs: { path: `${prefix}${relPath}` },
        }
      );
      stepProgress();
    });

    const conflictPaths = ([relPath, conflictRel]) => [relPath, conflictRel];
    skips.each(plan.conflicts, ([relPath, conflictRel, remoteText]) => {
      verifyPlannedText(relPath, remoteText, remoteHashes);
      const localText = getVerifiedLocalText(relPath);
      const savedConflictText = rewriteNoteAssetLinks(conflictRel, remoteText, assetCopyMap);
      localAdapter.writeNote(conflictRel, savedConflictText, { nbRoot });
      writeRemoteNote(conflictRel, savedConflictText, { createOnly: true });
      writeRemoteNote(relPath, localText, { expectedHash: getRemoteHash(relPath) || sha256Text(remoteText, rpc) });
      baseMap[relPath] = getLocalHash(relPath) || sha256Text(localText, rpc);
      baseMap[conflictRel] = sha256Text(savedConflictText, rpc);
      if (configStore) {
        configStore.clearTombstone(nbKeyVal, relPath);
        configStore.clearTombstone(nbKeyVal, conflictRel);
      }
      conflictCount += 1;
      appendLog(tr(locale, `冲突保留 ${prefix}${relPath}`, `Keep conflict copy: ${prefix}${relPath}`), '冲突副本', {
        tone: 'warning',
        tooltip: tr(locale, `已保留副本 ${conflictRel}`, `Saved a copy at ${conflictRel}`),
        logKey: 'conflict_copy',
        logArgs: { path: `${prefix}${relPath}`, copy: conflictRel },
      });
      stepProgress();
    }, conflictPaths);

    skips.each(plan.asset_view_copies, ([relPath, conflictRel, remoteText]) => {
      verifyPlannedText(relPath, remoteText, remoteHashes);
      const savedConflictText = rewriteNoteAssetLinks(conflictRel, remoteText, assetCopyMap);
      if (savedConflictText === remoteText) {
        stepProgress();
        return;
      }
      localAdapter.writeNote(conflictRel, savedConflictText, { nbRoot });
      writeRemoteNote(conflictRel, savedConflictText, { createOnly: true });
      baseMap[conflictRel] = sha256Text(savedConflictText, rpc);
      if (configStore) configStore.clearTombstone(nbKeyVal, conflictRel);
      conflictCount += 1;
      appendLog(tr(locale, `冲突保留 ${prefix}${relPath}`, `Keep conflict copy: ${prefix}${relPath}`), '冲突副本', {
        tone: 'warning',
        tooltip: tr(locale, `已保留副本 ${conflictRel}`, `Saved a copy at ${conflictRel}`),
        logKey: 'conflict_copy',
        logArgs: { path: `${prefix}${relPath}`, copy: conflictRel },
      });
      stepProgress();
    }, conflictPaths);

    // 3. Complete deferred remote original-asset overwrites.
    skips.each(deferredAssetOverwrites, (rel) => {
      writeRemoteAsset(rel, null, localAssets[rel], {
        expectedHash: remoteAssets[rel],
        copyFromPath: localAssetPath(rel),
        readFallback: () => readLocalAsset(rel),
      });
      baseMap[`asset:${rel}`] = localAssets[rel];
    });

    // 4. Propagate recoverable deletions.
    let deletedCount = 0;
    const deletions = [
      ...(plan.to_delete_remote || []).map((rel) => ['remote', rel, false]),
      ...(plan.assets_to_delete_remote || []).map((rel) => ['remote', rel, true]),
      ...(plan.to_delete_local || []).map((rel) => ['local', rel, false]),
      ...(plan.assets_to_delete_local || []).map((rel) => ['local', rel, true]),
    ];
    const deleteExpectedHashes = plan.delete_expected_hashes || {};
    const baseKeyAliases = plan.base_key_aliases || {};

    skips.each(deletions, ([side, rel, isAsset]) => {
      const key = isAsset ? `asset:${rel}` : rel;
      const expect =
        deleteExpectedHashes[key] ||
        baseMap[key] ||
        (configStore ? configStore.lookupTombstoneHash(nbKeyVal, key) : null);
      let outcome = 'failed';
      let errText = '';
      try {
        if (side === 'remote') {
          const targetRel = (isAsset ? remoteAssetPathMap : remotePathMap)[rel] || rel;
          verifyTarget();
          if (!isConfirmedAbsentOnRoot(rpc, nbRoot, rel)) {
            outcome = 'changed';
          } else {
            const matchesFn = isAsset
              ? (raw) => sha256Bytes(raw, rpc) === expect
              : (raw) => sha256Text(decodeNoteBytes(raw, rel), rpc) === expect;
            outcome = deleteMirrorEntry(rpc, targetDir, targetRel, matchesFn, {
              excludedSubdirs,
              locale,
              dataDir,
              nowMsFn,
              cfg,
              expectedAssetHash: isAsset ? expect : null,
            });
            if (outcome === 'deleted' && protocol === 'git') {
              const subTrim = subdir.replace(/^\/+|\/+$/g, '');
              const gitRel = subTrim ? `${subTrim}/${targetRel}` : targetRel;
              deletedGitPaths.push(gitRel);
              if (typeof afterRemoteDelete === 'function') afterRemoteDelete(gitRel);
            }
          }
        } else {
          const targetRel = (isAsset ? remoteAssetPathMap : remotePathMap)[rel] || rel;
          if (!isConfirmedAbsentOnRoot(rpc, targetDir, targetRel)) {
            outcome = 'changed';
          } else {
            const revision = isAsset
              ? localAssets[rel] || expect || ''
              : (getLocalHash(rel) || expect || '');
            outcome = localAdapter.trashFile(rel, revision, { nbRoot });
          }
        }
      } catch (exc) {
        if (['file_limit', 'fs_error', 'quota_full'].includes(classifySyncError(exc))) throw exc;
        outcome = 'failed';
        errText = errorDetail(locale, exc);
      }

      const shown = `${prefix}${rel}`;
      const where = side === 'remote' ? protoLbl : tr(locale, '本地', 'local');
      if (outcome === 'deleted' || outcome === 'missing') {
        delete baseMap[key];
        for (const aliasKey of baseKeyAliases[key] || []) {
          if (!skips.has(isAsset ? aliasKey.slice(6) : aliasKey)) delete baseMap[aliasKey];
        }
        if (expect && configStore) {
          configStore.recordTombstone(nbKeyVal, key, expect);
        }
      }
      if (outcome === 'deleted') {
        deletedCount += 1;
        appendLog(tr(locale, `删除 ${shown}`, `Delete ${shown}`), '成功', {
          tone: 'success',
          tooltip: tr(locale, `已在${where}删除（可找回）`, `Deleted from ${where} (recoverable)`),
          logKey: `delete_${side}`,
          logArgs: { path: shown },
        });
      } else if (outcome === 'changed') {
        appendLog(tr(locale, `保留 ${shown}`, `Keep ${shown}`), '无变更', {
          tone: 'warning',
          tooltip: tr(locale, `${where}内容已变化，未删除`, `Changed on ${where}; not deleted`),
          logKey: 'delete_skipped',
          logArgs: { path: shown, side },
        });
      } else if (outcome === 'unsupported') {
        appendLog(
          tr(locale, '远端删除未同步到本地', 'Remote deletions not applied locally'),
          '待确认',
          {
            tone: 'warning',
            tooltip: tr(locale, '请升级 Block 后重试', 'Update Block and sync again'),
            logKey: 'delete_unsupported',
          }
        );
      } else if (outcome === 'failed') {
        appendLog(tr(locale, `删除失败 ${shown}`, `Delete failed: ${shown}`), '失败', {
          tone: 'danger',
          tooltip: errText,
          logKey: 'delete_failed',
          logArgs: { path: shown, error: errText },
        });
      }
      stepProgress();
    }, ([, rel, isAsset]) => {
      const actual = (isAsset ? remoteAssetPathMap : remotePathMap)[rel];
      return actual && actual !== rel ? [rel, actual] : [rel];
    });
    plan._deleted_count = deletedCount;
    plan._deleted_git_paths = deletedGitPaths;
  };

  try {
    const lockDir = protocol === 'local_mirror' ? batchBaseRoot : plan.repo_root || targetDir;
    if (skipLock) {
      runInsideLock();
    } else {
      withTargetLock(rpc, lockDir, runInsideLock, { dataDir, pid, nowMsFn, sleepFn });
    }
  } catch (exc) {
    restoreBase();
    if (protocol !== 'git' && configStore) {
      configStore.state.syncMeta[plan.meta_key] = baseMap;
    }
    throw exc;
  }

  for (const [lp, rp] of Object.entries(remotePathMap)) {
    if (rp !== lp && !skips.has(lp) && !skips.has(rp) && Object.hasOwn(baseMap, lp) && !hasLocalNote(rp)) {
      delete baseMap[rp];
    }
  }
  for (const [lp, rp] of Object.entries(remoteAssetPathMap)) {
    if (rp !== lp && !skips.has(lp) && !skips.has(rp) && Object.hasOwn(baseMap, `asset:${lp}`) && !Object.hasOwn(localAssets, rp)) {
      delete baseMap[`asset:${rp}`];
    }
  }
  const relativeKey = (key) => key.startsWith('asset:') ? key.slice(6) : key;
  for (const [key, aliases] of Object.entries(plan.base_key_aliases || {})) {
    if (!skips.has(relativeKey(key)) && Object.hasOwn(baseMap, key)) {
      for (const aliasKey of aliases) {
        if (aliasKey !== key && !skips.has(relativeKey(aliasKey))) delete baseMap[aliasKey];
      }
    }
  }
  restoreBase();

  const syncedRepoPaths = [];
  if (protocol === 'git') {
    const subTrim = subdir.replace(/^\/+|\/+$/g, '');
    const subPrefix = subTrim ? `${subTrim}/` : '';
    for (const relPath of plan.synced || []) {
      if (skips.has(relPath)) continue;
      const remoteRel = remotePathMap[relPath] || relPath;
      const repoRel = `${subPrefix}${remoteRel}`;
      syncedRepoPaths.push(repoRel);
      if (!Object.hasOwn(plannedGitBlobs, repoRel)) {
        const syncedHash = getLocalHash(relPath) || getRemoteHash(relPath) || '';
        if (targetDir && syncedHash) {
          plannedGitBlobs[repoRel] = { file_path: posixJoin(targetDir, remoteRel), hash: syncedHash };
        } else if (Object.hasOwn(localNotes, relPath)) {
          plannedGitBlobs[repoRel] = textToBytes(localNotes[relPath]);
        } else if (syncedHash && nbRoot) {
          plannedGitBlobs[repoRel] = { file_path: posixJoin(nbRoot, relPath), hash: syncedHash };
        }
      }
    }
    for (const relPath of plan.assets_synced || []) {
      if (skips.has(relPath)) continue;
      const remoteRel = remoteAssetPathMap[relPath] || relPath;
      const repoRel = `${subPrefix}${remoteRel}`;
      syncedRepoPaths.push(repoRel);
      if (!Object.hasOwn(plannedGitBlobs, repoRel)) {
        plannedGitBlobs[repoRel] = { file_path: posixJoin(targetDir, remoteRel), hash: remoteAssets[relPath] };
      }
    }
  }

  return {
    pushed,
    pulled,
    conflictCount,
    assetCount,
    baseMap,
    writtenRemotePaths,
    syncedRepoPaths,
    plannedGitBlobs,
  };
}

// ============================================================================
// Local Mirror Sync Engine
// ============================================================================

/**
 * Create a local directory mirror sync engine wired to host.fs.*, host.notes.*,
 * and host.crypto.hash via callHost.
 */
export function createLocalMirrorSyncEngine({
  callHost = null,
  notifyHost = null,
  configStore = null,
  localAdapter = null,
  locale = 'zh',
  sleepFn = null,
  nowMsFn = () => Date.now(),
  dataDir = '',
  pid = 1,
} = {}) {
  const getRpc = () => resolveCallHost(callHost);
  const local =
    localAdapter ||
    createHostLocalAdapter({
      callHost,
      supportsMultiNotebook: configStore ? configStore.state.supportsMultiNotebook : true,
      configStore,
      nowMsFn,
    });
  const getLocale = () => (configStore ? configStore.state.locale : locale);
  const getDownloadsDir = () => (configStore ? configStore.state.downloadsDir : '');
  const getHomeDir = () => (configStore ? configStore.state.homeDir : '');
  const resolveDataDir = () => resolvePluginDataDir(getRpc(), dataDir);

  const testConnection = (cfg) => {
    const rpc = getRpc();
    const loc = getLocale();
    const mirrorDir = resolveMirrorDir(cfg, getDownloadsDir(), getHomeDir());
    if (!mirrorDir) {
      return [false, tr(loc, '请先填写本地镜像目录', 'Enter a local mirror folder first')];
    }
    let probePath = '';
    try {
      fsMkdir(rpc, mirrorDir, true);
      probePath = posixJoin(mirrorDir, `.block-sync-probe-${pid}-${nowMsFn()}.tmp`);
      fsWriteText(rpc, probePath, 'ok', { atomic: false });
      return [true, tr(loc, `目录镜像可用: ${mirrorDir}`, `Local mirror is available: ${mirrorDir}`)];
    } catch (exc) {
      return [
        false,
        tr(loc, `目录镜像不可写: ${errorDetail(loc, exc)}`, `Local mirror is not writable: ${errorDetail(loc, exc)}`),
      ];
    } finally {
      if (probePath) {
        try {
          fsDelete(rpc, probePath);
        } catch (_delErr) {
          // Ignore probe cleanup errors.
        }
      }
    }
  };

  const computeSyncPlan = ({
    cfg,
    onlyPath = null,
    nbRoot = null,
    subdir = '',
    excludedSubdirs = new Set(),
    skipRound,
  } = {}) => {
    const rpc = getRpc();
    const loc = getLocale();
    const homeDir = getHomeDir();
    const effectiveNbRoot = nbRoot || (configStore ? configStore.state.notebookRoot : '');
    const nbKeyVal = configStore
      ? configStore.notebookKey(effectiveNbRoot)
      : notebookKey(effectiveNbRoot, '', homeDir);
    const nbLabelVal = configStore
      ? configStore.notebookLabel(effectiveNbRoot)
      : notebookLabel(effectiveNbRoot, loc, '', homeDir);
    const scope = cfg.sync_scope || 'all';
    const skips = createSyncSkips(cfg, loc, skipRound);

    const baseDir = resolveMirrorDir(cfg, getDownloadsDir(), homeDir);
    const targetDir = subdir ? posixJoin(baseDir, subdir) : baseDir;
    const metaTarget = subdir ? `${baseDir}::${subdir}` : baseDir;
    const metaKey = configStore
      ? configStore.metaKey('local_mirror', metaTarget, nbKeyVal)
      : `nb:${nbKeyVal}|local_mirror:${metaTarget}`;
    const legacyKey = !subdir ? `local_mirror:${baseDir}` : null;

    const canLazyLocal = onlyPath === null && typeof local.readNote === 'function';
    let localNotes = {};
    let remoteNotes = {};
    let localSnapshot = null;
    let remoteSnapshot = null;
    let localNoteEntries = null;
    let remoteNoteEntries = null;
    let readLocalNote = null;
    let readRemoteNote = null;
    let remoteInspected = true;
    let remoteError = null;

    if (onlyPath === null) {
      // Scan remote mirror directory first so out-of-scope errors fail fast before scanning the notebook.
      try {
        remoteSnapshot = scanDirSnapshot(rpc, targetDir, { excludedSubdirs, locale: loc });
        remoteNoteEntries = new Map();
        if (remoteSnapshot) {
          const mirrorCi = scope && scope !== 'all' ? dirIsCaseInsensitive(rpc, remoteSnapshot.cleanRoot) : false;
          const mirrorNorm = scope && scope !== 'all' ? dirIsNormalizationInsensitive(rpc, remoteSnapshot.cleanRoot) : false;
          for (const [rel, entry] of remoteSnapshot.noteEntries.entries()) {
            if (!scope || scope === 'all' || matchesScope(rel, scope, { caseInsensitive: mirrorCi, normalize: mirrorNorm })) {
              remoteNoteEntries.set(rel, entry);
            }
          }
          readRemoteNote = (relPath, entry = null) => fsReadNoteText(rpc, posixJoin(remoteSnapshot.cleanRoot, relPath), relPath, entry);
        }
      } catch (exc) {
        remoteInspected = false;
        remoteError = errorDetail(loc, exc);
      }
    } else {
      try {
        remoteNotes = scanMirrorFiles(rpc, targetDir, {
          onlyPath,
          scope,
          excludedSubdirs,
          locale: loc,
          cfg,
          skips,
        });
      } catch (exc) {
        remoteInspected = false;
        remoteError = errorDetail(loc, exc);
      }
    }

    if (remoteInspected && !remoteError) {
      if (canLazyLocal) {
        try {
          localSnapshot = scanDirSnapshot(rpc, effectiveNbRoot, { excludedSubdirs: new Set(), locale: loc });
        } catch (exc) {
          if (!String(exc?.message || exc).includes('unknown host method')) throw exc;
        }
      }
      if (localSnapshot) {
        localNoteEntries = new Map();
        for (const [relPath, entry] of localSnapshot.noteEntries.entries()) {
          if (inSyncSubdir(relPath, excludedSubdirs)) {
            throw new Error(
              tr(
                loc,
                `笔记路径与其他笔记本的同步目录重叠：${relPath}`,
                `Note path overlaps with another notebook's sync folder: ${relPath}`
              )
            );
          }
          if (!scope || scope === 'all' || matchesScope(relPath, scope)) {
            localNoteEntries.set(relPath, entry);
          }
        }
        readLocalNote = (relPath, entry = null) => local.readNote(relPath, { nbRoot: effectiveNbRoot, cfg, locale: loc, skips, entry });
      } else {
        localNotes = local.readNotes({ onlyPath, scope, nbRoot: effectiveNbRoot, cfg, locale: loc, skips });
        for (const relPath of Object.keys(localNotes)) {
          if (inSyncSubdir(relPath, excludedSubdirs)) {
            throw new Error(
              tr(
                loc,
                `笔记路径与其他笔记本的同步目录重叠：${relPath}`,
                `Note path overlaps with another notebook's sync folder: ${relPath}`
              )
            );
          }
        }
      }
    }

    return computeThreeWaySyncPlan({
      callHost: rpc,
      configStore,
      localAdapter: local,
      protocol: 'local_mirror',
      cfg,
      nbRoot: effectiveNbRoot,
      nbKeyVal,
      nbLabelVal,
      subdir,
      excludedSubdirs,
      targetDisplay: baseDir,
      targetDir,
      metaKey,
      legacyKey,
      localNotes,
      remoteNotes,
      localSnapshot,
      remoteSnapshot,
      localNoteEntries,
      remoteNoteEntries,
      readLocalNote,
      readRemoteNote,
      remoteInspected,
      remoteError,
      onlyPath,
      locale: loc,
      skips,
    });
  };

  const computeBatchPlan = ({ cfg, notebooks = [], onlyPath = null } = {}) => {
    const rpc = getRpc();
    const loc = getLocale();
    const homeDir = getHomeDir();
    const baseDir = resolveMirrorDir(cfg, getDownloadsDir(), homeDir);
    const targetBases = [baseDir];
    const effectiveNotebooks = Array.isArray(notebooks) ? notebooks : [];

    const { layoutKey, bindings, reservedSubdirs } = computeNotebookSubdirMap({
      notebooks: (configStore && configStore.selectedNotebooks(cfg).length > 0
        ? configStore.selectedNotebooks(cfg)
        : effectiveNotebooks),
      protocol: 'local_mirror',
      targetBases,
      syncMeta: configStore ? configStore.state.syncMeta : {},
      notebookConfigs: configStore ? configStore.state.notebookConfigs : {},
      knownNotebooks: configStore ? configStore.state.knownNotebooks : [],
      callHost: rpc,
      locale: loc,
      syncTargetBaseFn: (c) => resolveMirrorDir(c, getDownloadsDir(), homeDir),
    });

    for (let i = 0; i < effectiveNotebooks.length; i += 1) {
      for (let j = 0; j < i; j += 1) {
        if (pathsOverlap(effectiveNotebooks[j], effectiveNotebooks[i])) {
          const prevLbl = notebookLabel(effectiveNotebooks[j], loc, '', homeDir);
          const curLbl = notebookLabel(effectiveNotebooks[i], loc, '', homeDir);
          return {
            cfg: { ...cfg },
            protocol: 'local_mirror',
            target_display: baseDir,
            plans: [],
            remote_error: tr(
              loc,
              `笔记本「${prevLbl}」与「${curLbl}」的本地目录重叠，已中止同步`,
              `Local folders for ${prevLbl} and ${curLbl} overlap; sync aborted`
            ),
            fingerprint: '',
          };
        }
      }
    }

    const { identities: targetIdentities, error: physErr } = validatePhysicalTargets(
      rpc,
      'local_mirror',
      bindings,
      baseDir,
      { locale: loc, homeDir }
    );
    if (physErr) {
      return {
        cfg: { ...cfg },
        protocol: 'local_mirror',
        target_display: baseDir,
        plans: [],
        remote_error: physErr,
        fingerprint: '',
      };
    }

    const plans = [];
    const skipRound = { consecutive: 0 };
    for (const nb of effectiveNotebooks) {
      const sub = bindings[nb] || '';
      const plan = computeSyncPlan({
        cfg,
        onlyPath,
        nbRoot: nb,
        subdir: sub,
        excludedSubdirs: sub ? new Set() : reservedSubdirs,
        skipRound,
      });
      plan.batch_base_root = baseDir;
      plan.batch_bindings = bindings;
      plan.target_identities = targetIdentities;
      if (plan.remote_error) {
        return {
          cfg: { ...cfg },
          protocol: 'local_mirror',
          target_display: baseDir,
          plans,
          remote_error: plan.remote_error,
          fingerprint: '',
        };
      }
      plans.push(plan);
    }

    const physFp = Object.keys(targetIdentities)
      .sort()
      .map((nb) => [
        nb,
        targetIdentities[nb].path,
        targetIdentities[nb].exists,
        targetIdentities[nb].is_dir,
      ]);
    const fp = sha256Text(
      JSON.stringify({ plans: plans.map((p) => p.fingerprint), targets: physFp }),
      rpc
    );

    return {
      cfg: { ...cfg },
      protocol: 'local_mirror',
      target_display: baseDir,
      layout_key: layoutKey,
      bindings,
      plans,
      remote_error: null,
      fingerprint: fp,
    };
  };

  const applyNotebookPlan = (plan, { progressState = null } = {}) =>
    applyMirrorOrGitNotebookPlan(plan, {
      callHost: getRpc(),
      notifyHost,
      configStore,
      localAdapter: local,
      locale: getLocale(),
      dataDir: resolveDataDir(),
      pid,
      nowMsFn,
      sleepFn,
      progressState,
    });

  const executeBatchPlan = (batch, { reportProgress = false } = {}) => {
    const rpc = getRpc();
    const loc = getLocale();
    const dDir = resolveDataDir();
    const legacyRoots = new Set();
    for (const plan of batch.plans) {
      if (plan.batch_base_root) legacyRoots.add(plan.batch_base_root);
      if (plan.target_dir) legacyRoots.add(plan.target_dir);
    }
    for (const rootDir of legacyRoots) {
      migrateLegacyRecoveryDirs(rpc, rootDir, { dataDir: dDir, nowMsFn });
    }
    let totalPushed = 0;
    let totalPulled = 0;
    let totalConflicts = 0;
    let reportedConflicts = 0;
    let totalAssets = 0;
    let totalDeleted = 0;

    let totalItems = 0;
    for (const plan of batch.plans) {
      totalItems +=
        plan.to_push_new.length +
        plan.to_push_overwrite.length +
        plan.to_pull_new.length +
        plan.to_pull_overwrite.length +
        plan.conflicts.length +
        (plan.asset_view_copies || []).length +
        (plan.assets_to_push_new || []).length +
        (plan.assets_to_push_overwrite || []).length +
        (plan.assets_to_pull_new || []).length +
        (plan.assets_to_pull_overwrite || []).length +
        (plan.asset_conflicts || []).length +
        (plan.to_delete_remote || []).length +
        (plan.to_delete_local || []).length +
        (plan.assets_to_delete_remote || []).length +
        (plan.assets_to_delete_local || []).length;
    }

    const progressState = reportProgress ? { done: 0, total: totalItems } : null;

    if (configStore && batch.layout_key && batch.bindings) {
      const layouts = { ...(configStore.state.syncMeta[LAYOUTS_META_KEY] || {}) };
      layouts[batch.layout_key] = { ...batch.bindings };
      configStore.state.syncMeta[LAYOUTS_META_KEY] = layouts;
    }

    for (const plan of batch.plans) {
      const res = applyNotebookPlan(plan, { progressState });
      totalPushed += res.pushed;
      totalPulled += res.pulled;
      totalConflicts += res.conflictCount;
      totalAssets += res.assetCount;
      totalDeleted += Number(plan._deleted_count || 0);
      const risks = planRiskMetrics(rpc, plan);
      reportedConflicts += risks.conflicts + risks.pull_conflict + risks.push_conflict;
      if (configStore) {
        configStore.state.syncMeta[plan.meta_key] = res.baseMap;
      }
    }

    if (configStore) {
      const initMap = { ...(configStore.state.syncMeta[INITIALIZED_META_KEY] || {}) };
      for (const plan of batch.plans) initMap[plan.meta_key] = true;
      configStore.state.syncMeta[INITIALIZED_META_KEY] = initMap;
      configStore.state.stats.total_synced += totalPushed + totalPulled + totalConflicts;
      configStore.state.stats.last_sync = nowHms();
    }

    const skippedItems = collectSkippedItems(batch.plans);
    const skippedSummary = skippedItems.length ? formatSkippedCount(loc, skippedItems.length) : '';
    const totalNotes = totalPushed + totalPulled + totalConflicts;
    if (totalNotes === 0 && totalAssets === 0 && totalDeleted === 0) {
      return {
        status: '无变更',
        summary: skippedSummary || tr(loc, '已是最新', 'Up to date'),
        skipped_items: skippedItems,
        pushed: 0,
        pulled: 0,
        conflicts: 0,
        assets: 0,
        deleted: 0,
      };
    }

    let summary = tr(
      loc,
      `推送 ${totalPushed} 篇 · 拉取 ${totalPulled} 篇 · 冲突 ${reportedConflicts} 处`,
      `Pushed: ${totalPushed} · Pulled: ${totalPulled} · Conflicts: ${reportedConflicts}`
    );
    if (totalAssets > 0) {
      summary += tr(loc, ` · 附件 ${totalAssets} 个`, ` · Attachments: ${totalAssets}`);
    }
    if (totalDeleted > 0) {
      summary += tr(loc, ` · 删除 ${totalDeleted} 项`, ` · Deleted: ${totalDeleted}`);
    }
    if (skippedSummary) summary += ` · ${skippedSummary}`;
    return {
      status: '成功',
      summary,
      skipped_items: skippedItems,
      pushed: totalPushed,
      pulled: totalPulled,
      conflicts: reportedConflicts,
      assets: totalAssets,
      deleted: totalDeleted,
    };
  };

  const validateTarget = (cfg, notebooks) => {
    const loc = getLocale();
    if (!notebooks || notebooks.length === 0) {
      return tr(loc, '请至少选择一个笔记本', 'Select at least one notebook');
    }
    const mirrorDir = resolveMirrorDir(cfg, getDownloadsDir(), getHomeDir());
    if (!mirrorDir) {
      return tr(loc, '请先填写本地镜像目录', 'Enter a local mirror folder first');
    }
    for (const nb of notebooks) {
      if (pathsOverlap(nb, mirrorDir)) {
        const lbl = notebookLabel(nb, loc, '', getHomeDir());
        return tr(
          loc,
          `本地镜像目录不能与笔记本「${lbl}」重合或互为父子目录`,
          `Local mirror folder cannot match or nest inside notebook ${lbl}`
        );
      }
    }
    return '';
  };

  const syncLocalMirror = ({
    cfg = null,
    notebooks = null,
    onlyPath = null,
    onlyNbRoot = null,
    confirmed = false,
    approvedBatch = null,
    reportProgress = false,
  } = {}) => {
    const rpc = getRpc();
    const loc = getLocale();
    const effectiveCfg = cfg || (configStore ? configStore.state.config : {});
    let targetNotebooks = notebooks;
    if (!targetNotebooks && configStore) {
      targetNotebooks = configStore.selectedNotebooks(effectiveCfg);
    }
    if (onlyNbRoot && targetNotebooks) {
      const normOnly = notebookKey(onlyNbRoot, '', getHomeDir());
      targetNotebooks = targetNotebooks.filter((nb) => nb === normOnly);
    }

    const targetErr = validateTarget(effectiveCfg, targetNotebooks);
    if (targetErr) {
      return { outcome: 'error', error: targetErr };
    }

    const baseDir = resolveMirrorDir(effectiveCfg, getDownloadsDir(), getHomeDir());
    migrateLegacyRecoveryDirs(rpc, baseDir, { dataDir: resolveDataDir(), nowMsFn });

    const batch =
      approvedBatch ||
      computeBatchPlan({
        cfg: effectiveCfg,
        notebooks: targetNotebooks,
        onlyPath,
      });

    if (batch.remote_error) {
      return { outcome: 'error', error: batch.remote_error };
    }

    if (!confirmed) {
      const reasonItems = assessBatchDangerousChanges(rpc, batch, effectiveCfg);
      if (reasonItems.length > 0) {
        const pending = buildPendingConfirm(rpc, batch, reasonItems, {
          configStore,
          locale: loc,
          onlyPath,
          onlyNbRoot: onlyNbRoot || (configStore ? configStore.state.notebookRoot : null),
        });
        if (configStore) {
          configStore.setPendingConfirm(pending);
        }
        return {
          outcome: 'pending_confirm',
          pendingConfirm: pending,
          batch,
        };
      }
    }

    const result = executeBatchPlan(batch, { reportProgress });
    if (configStore && confirmed) {
      configStore.clearPendingConfirm('local_mirror');
    }
    return {
      outcome: 'synced',
      ...result,
      batch,
    };
  };

  return {
    localAdapter: local,
    testConnection,
    computeSyncPlan,
    computeBatchPlan,
    planRiskMetrics: (plan) => planRiskMetrics(getRpc(), plan),
    assessDangerousChanges: (plan, cfg, nbLbl = '') => assessDangerousChanges(getRpc(), plan, cfg, nbLbl),
    assessBatchDangerousChanges: (batch, cfg) => assessBatchDangerousChanges(getRpc(), batch, cfg),
    buildPendingConfirm: (batch, reasons, opts = {}) =>
      buildPendingConfirm(getRpc(), batch, reasons, { configStore, locale: getLocale(), ...opts }),
    applyNotebookPlan,
    executeBatchPlan,
    syncLocalMirror,
  };
}
