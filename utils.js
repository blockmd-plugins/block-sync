/**
 * Pure ES2023 utilities for block-sync (QuickJS-NG & Node compatible).
 * Path normalization, pure-JS UTF-8/base64, URL parsing/sanitization,
 * time/backoff helpers, CommonMark asset link scanner/rewriter,
 * deterministic conflict copy naming, and host.crypto.hash wrappers.
 */

export const NOTE_EXTENSIONS = new Set([
  '.md',
  '.markdown',
  '.mdown',
  '.mkd',
  '.mkdn',
  '.mdwn',
  '.mdtxt',
  '.mdtext',
  '.mdx',
]);

// ============================================================================
// Host RPC Resolution & Crypto Hashing
// ============================================================================

export function resolveCallHost(callHost) {
  const fn = typeof callHost === 'function' ? callHost : globalThis.callHost;
  if (typeof fn !== 'function') {
    throw new Error('Host RPC bridge (callHost) is unavailable');
  }
  return fn;
}

export function extractHashHex(res) {
  if (typeof res === 'string') {
    return res.trim().toLowerCase();
  }
  if (res && typeof res === 'object') {
    const raw = res.hex ?? res.hash ?? res.digest ?? res.sha256 ?? '';
    if (typeof raw === 'string') {
      return raw.trim().toLowerCase();
    }
  }
  return '';
}

export function sha256Text(text, callHost) {
  const rpc = resolveCallHost(callHost);
  const res = rpc('host.crypto.hash', {
    algorithm: 'sha256',
    text: String(text ?? ''),
  });
  const hex = extractHashHex(res);
  if (!hex) {
    throw new Error('host.crypto.hash returned an empty digest');
  }
  return hex;
}

export function sha256Bytes(bytes, callHost) {
  const rpc = resolveCallHost(callHost);
  const view = bytes instanceof Uint8Array
    ? bytes
    : bytes instanceof ArrayBuffer
      ? new Uint8Array(bytes)
      : textToBytes(String(bytes ?? ''));
  const res = rpc('host.crypto.hash', {
    algorithm: 'sha256',
    base64: bytesToBase64(view),
  });
  const hex = extractHashHex(res);
  if (!hex) {
    throw new Error('host.crypto.hash returned an empty digest');
  }
  return hex;
}

export function sha256File(filePath, callHost) {
  const rpc = resolveCallHost(callHost);
  const res = rpc('host.crypto.hash', {
    algorithm: 'sha256',
    file_path: String(filePath ?? ''),
  });
  const hex = extractHashHex(res);
  if (!hex) {
    throw new Error('host.crypto.hash returned an empty digest');
  }
  return hex;
}

// ============================================================================
// Pure-JS UTF-8 & Base64 Encoding / Decoding
// ============================================================================

export function textToBytes(text) {
  const str = String(text ?? '');
  const out = [];
  for (let i = 0; i < str.length; i += 1) {
    let cp = str.charCodeAt(i);
    if (cp < 0x80) {
      out.push(cp);
    } else if (cp < 0x800) {
      out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
    } else if (cp >= 0xd800 && cp <= 0xdbff) {
      const next = i + 1 < str.length ? str.charCodeAt(i + 1) : 0;
      if (next >= 0xdc00 && next <= 0xdfff) {
        cp = 0x10000 + (((cp - 0xd800) << 10) | (next - 0xdc00));
        i += 1;
        out.push(
          0xf0 | (cp >> 18),
          0x80 | ((cp >> 12) & 0x3f),
          0x80 | ((cp >> 6) & 0x3f),
          0x80 | (cp & 0x3f)
        );
      } else {
        // Lone high surrogate -> U+FFFD
        out.push(0xef, 0xbf, 0xbd);
      }
    } else if (cp >= 0xdc00 && cp <= 0xdfff) {
      // Lone low surrogate -> U+FFFD
      out.push(0xef, 0xbf, 0xbd);
    } else {
      out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    }
  }
  return new Uint8Array(out);
}

export function bytesToText(bytes, { fatal = false } = {}) {
  const arr = bytes instanceof Uint8Array
    ? bytes
    : bytes instanceof ArrayBuffer
      ? new Uint8Array(bytes)
      : new Uint8Array(0);
  const chunks = [];
  let i = 0;
  const failOrReplace = () => {
    if (fatal) {
      throw new Error('Invalid UTF-8 byte sequence');
    }
    chunks.push('\ufffd');
  };

  while (i < arr.length) {
    const b0 = arr[i];
    if (b0 < 0x80) {
      chunks.push(String.fromCharCode(b0));
      i += 1;
      continue;
    }
    if (b0 >= 0xc2 && b0 <= 0xdf) {
      if (i + 1 >= arr.length) {
        failOrReplace();
        i += 1;
        continue;
      }
      const b1 = arr[i + 1];
      if ((b1 & 0xc0) !== 0x80) {
        failOrReplace();
        i += 1;
        continue;
      }
      const cp = ((b0 & 0x1f) << 6) | (b1 & 0x3f);
      chunks.push(String.fromCharCode(cp));
      i += 2;
      continue;
    }
    if (b0 >= 0xe0 && b0 <= 0xef) {
      if (i + 2 >= arr.length) {
        failOrReplace();
        i += 1;
        continue;
      }
      const b1 = arr[i + 1];
      const b2 = arr[i + 2];
      const validLead =
        (b1 & 0xc0) === 0x80 &&
        (b2 & 0xc0) === 0x80 &&
        !(b0 === 0xe0 && b1 < 0xa0) &&
        !(b0 === 0xed && b1 >= 0xa0);
      if (!validLead) {
        failOrReplace();
        i += 1;
        continue;
      }
      const cp = ((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f);
      chunks.push(String.fromCharCode(cp));
      i += 3;
      continue;
    }
    if (b0 >= 0xf0 && b0 <= 0xf4) {
      if (i + 3 >= arr.length) {
        failOrReplace();
        i += 1;
        continue;
      }
      const b1 = arr[i + 1];
      const b2 = arr[i + 2];
      const b3 = arr[i + 3];
      const validLead =
        (b1 & 0xc0) === 0x80 &&
        (b2 & 0xc0) === 0x80 &&
        (b3 & 0xc0) === 0x80 &&
        !(b0 === 0xf0 && b1 < 0x90) &&
        !(b0 === 0xf4 && b1 > 0x8f);
      if (!validLead) {
        failOrReplace();
        i += 1;
        continue;
      }
      const cp = ((b0 & 0x07) << 18) | ((b1 & 0x3f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f);
      const u = cp - 0x10000;
      chunks.push(String.fromCharCode(0xd800 + (u >> 10), 0xdc00 + (u & 0x3ff)));
      i += 4;
      continue;
    }
    failOrReplace();
    i += 1;
  }
  return chunks.join('');
}

export function decodeNoteBytes(rawBytes, relPath = '') {
  try {
    return bytesToText(rawBytes, { fatal: true });
  } catch (err) {
    const label = relPath || 'note';
    throw new Error(`Note is not valid UTF-8 (${label}): ${err.message}`);
  }
}

export function bytesToEqualCheck(a, b) {
  if (a === b) return true;
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array)) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export const bytesEqual = bytesToEqualCheck;

const B64_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const B64_REV = new Int16Array(128).fill(-1);
for (let i = 0; i < B64_ALPHA.length; i += 1) {
  B64_REV[B64_ALPHA.charCodeAt(i)] = i;
}

export function bytesToBase64(bytes) {
  const arr = bytes instanceof Uint8Array
    ? bytes
    : bytes instanceof ArrayBuffer
      ? new Uint8Array(bytes)
      : textToBytes(String(bytes ?? ''));
  if (arr.length === 0) return '';
  const parts = [];
  for (let i = 0; i < arr.length; i += 3) {
    const b0 = arr[i];
    const has1 = i + 1 < arr.length;
    const has2 = i + 2 < arr.length;
    const b1 = has1 ? arr[i + 1] : 0;
    const b2 = has2 ? arr[i + 2] : 0;
    const triplet = (b0 << 16) | (b1 << 8) | b2;
    parts.push(
      B64_ALPHA[(triplet >> 18) & 0x3f],
      B64_ALPHA[(triplet >> 12) & 0x3f],
      has1 ? B64_ALPHA[(triplet >> 6) & 0x3f] : '=',
      has2 ? B64_ALPHA[triplet & 0x3f] : '='
    );
  }
  return parts.join('');
}

export function base64ToBytes(b64) {
  const clean = String(b64 ?? '').replace(/[\r\n\t ]+/g, '');
  if (clean.length === 0) return new Uint8Array(0);
  if (clean.length % 4 !== 0) {
    throw new Error('Invalid base64 string length');
  }
  let pad = 0;
  if (clean.endsWith('==')) pad = 2;
  else if (clean.endsWith('=')) pad = 1;

  const outLen = (clean.length / 4) * 3 - pad;
  const out = new Uint8Array(outLen);
  let outIdx = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const c0 = clean.charCodeAt(i);
    const c1 = clean.charCodeAt(i + 1);
    const c2 = clean.charCodeAt(i + 2);
    const c3 = clean.charCodeAt(i + 3);
    const v0 = c0 < 128 ? B64_REV[c0] : -1;
    const v1 = c1 < 128 ? B64_REV[c1] : -1;
    const v2 = c2 === 61 ? 0 : (c2 < 128 ? B64_REV[c2] : -1);
    const v3 = c3 === 61 ? 0 : (c3 < 128 ? B64_REV[c3] : -1);
    if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0) {
      throw new Error('Invalid base64 character');
    }
    const triplet = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
    if (outIdx < outLen) out[outIdx++] = (triplet >> 16) & 0xff;
    if (outIdx < outLen) out[outIdx++] = (triplet >> 8) & 0xff;
    if (outIdx < outLen) out[outIdx++] = triplet & 0xff;
  }
  return out;
}

export function textToBase64(text) {
  return bytesToBase64(textToBytes(text));
}

export function base64ToText(b64, opts = {}) {
  return bytesToText(base64ToBytes(b64), opts);
}

// ============================================================================
// HTML / XML Entity Escaping
// ============================================================================

const NAMED_ENTITIES = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: '\u00a0',
};

export function htmlUnescape(text) {
  return String(text ?? '').replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]+);/g, (full, body) => {
    if (body.startsWith('#x') || body.startsWith('#X')) {
      const cp = Number.parseInt(body.slice(2), 16);
      if (Number.isFinite(cp) && cp >= 0 && cp <= 0x10ffff) {
        return String.fromCodePoint(cp);
      }
      return full;
    }
    if (body.startsWith('#')) {
      const cp = Number.parseInt(body.slice(1), 10);
      if (Number.isFinite(cp) && cp >= 0 && cp <= 0x10ffff) {
        return String.fromCodePoint(cp);
      }
      return full;
    }
    const lower = body.toLowerCase();
    return Object.hasOwn(NAMED_ENTITIES, lower) ? NAMED_ENTITIES[lower] : full;
  });
}

export function htmlEscape(text, quote = true) {
  let out = String(text ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  if (quote) {
    out = out.replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
  }
  return out;
}

// ============================================================================
// Time & Retry Backoff Helpers
// ============================================================================

function pad2(n) {
  return String(n).padStart(2, '0');
}

export function nowHms(date = new Date()) {
  return `${pad2(date.getHours())}:${pad2(date.getMinutes())}:${pad2(date.getSeconds())}`;
}

export function formatHm(timeStr) {
  const raw = String(timeStr ?? '').trim();
  const m = raw.match(/^(\d{1,2}:\d{2})(?::\d{2})?$/);
  return m ? m[1] : raw;
}

export function conflictStamp(date = new Date()) {
  return (
    `${date.getFullYear()}${pad2(date.getMonth() + 1)}${pad2(date.getDate())}-` +
    `${pad2(date.getHours())}${pad2(date.getMinutes())}${pad2(date.getSeconds())}`
  );
}

export function computeBackoffMs(attempt, baseMs = 400, maxMs = 1500) {
  const step = Math.max(0, Number(attempt) || 0) + 1;
  return Math.min(baseMs * step, maxMs);
}

export function sleepMs(ms, sleepFn = null) {
  const duration = Math.max(0, Number(ms) || 0);
  if (duration === 0) return;
  if (typeof sleepFn === 'function') {
    sleepFn(duration);
    return;
  }
  if (typeof Atomics !== 'undefined' && typeof SharedArrayBuffer !== 'undefined') {
    try {
      const buf = new SharedArrayBuffer(4);
      const arr = new Int32Array(buf);
      Atomics.wait(arr, 0, 0, duration);
      return;
    } catch (_err) {
      // SharedArrayBuffer may be unavailable in restricted sandboxes.
    }
  }
  const end = Date.now() + duration;
  while (Date.now() < end) {
    // Synchronous fallback for environments without Atomics.wait.
  }
}

// ============================================================================
// Path Normalization & Validation
// ============================================================================

export function splitExt(relPath) {
  const p = String(relPath ?? '');
  const slashIdx = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  const base = slashIdx >= 0 ? p.slice(slashIdx + 1) : p;
  const dotIdx = base.lastIndexOf('.');
  if (dotIdx <= 0) {
    return [p, ''];
  }
  const fullDotIdx = slashIdx + 1 + dotIdx;
  return [p.slice(0, fullDotIdx), p.slice(fullDotIdx)];
}

export function posixDirname(p) {
  const s = String(p ?? '').replace(/\\/g, '/');
  const idx = s.lastIndexOf('/');
  if (idx < 0) return '';
  if (idx === 0) return '/';
  return s.slice(0, idx).replace(/\/+$/, '') || '/';
}

export function posixBasename(p) {
  const s = String(p ?? '').replace(/\\/g, '/').replace(/\/+$/, '');
  if (!s) return '';
  const idx = s.lastIndexOf('/');
  return idx >= 0 ? s.slice(idx + 1) : s;
}

export function posixNormpath(p) {
  const raw = String(p ?? '').replace(/\\/g, '/');
  if (!raw) return '.';
  const isAbs = raw.startsWith('/');
  const doubleSlash = raw.startsWith('//') && !raw.startsWith('///');
  const parts = raw.split('/');
  const stack = [];
  for (const seg of parts) {
    if (!seg || seg === '.') continue;
    if (seg === '..') {
      if (stack.length > 0 && stack[stack.length - 1] !== '..') {
        stack.pop();
      } else if (!isAbs) {
        stack.push('..');
      }
    } else {
      stack.push(seg);
    }
  }
  let res = (isAbs ? (doubleSlash ? '//' : '/') : '') + stack.join('/');
  return res || (isAbs ? '/' : '.');
}

export function posixJoin(...segments) {
  let out = '';
  for (const seg of segments) {
    const s = String(seg ?? '');
    if (!s) continue;
    if (s.startsWith('/')) {
      out = s;
    } else if (!out || out.endsWith('/')) {
      out += s;
    } else {
      out += '/' + s;
    }
  }
  return out;
}

export function posixRelpath(targetPath, startDir = '.') {
  const target = posixNormpath(targetPath);
  const start = posixNormpath(startDir);
  if (!start || start === '.') {
    return target;
  }
  const tParts = target === '/' ? [] : target.split('/').filter(Boolean);
  const sParts = start === '/' ? [] : start.split('/').filter(Boolean);
  let common = 0;
  while (common < tParts.length && common < sParts.length && tParts[common] === sParts[common]) {
    common += 1;
  }
  const ups = new Array(sParts.length - common).fill('..');
  const rest = tParts.slice(common);
  const combined = [...ups, ...rest];
  return combined.length > 0 ? combined.join('/') : '.';
}

export function normAbsPath(raw, homeDir = '') {
  let text = String(raw ?? '').trim();
  if (!text) return '';
  if (homeDir && (text === '~' || text.startsWith('~/') || text.startsWith('~\\'))) {
    const cleanHome = String(homeDir).replace(/\\/g, '/').replace(/\/+$/, '');
    text = text.length === 1 ? cleanHome : `${cleanHome}/${text.slice(2)}`;
  }
  const slash = text.replace(/\\/g, '/');
  const norm = posixNormpath(slash);
  if (norm.length > 1 && norm.endsWith('/')) {
    return norm.slice(0, -1);
  }
  return norm;
}

export function displayPath(raw, homeDir = '') {
  const norm = normAbsPath(raw, homeDir);
  if (!norm) return '';
  const home = homeDir ? normAbsPath(homeDir) : '';
  if (home) {
    if (norm === home) return '~';
    if (norm.startsWith(`${home}/`)) {
      return `~${norm.slice(home.length)}`;
    }
  }
  return norm;
}

export function isSafeRelPath(relPath) {
  if (!relPath || typeof relPath !== 'string') return false;
  if (relPath.includes('\x00') || relPath.startsWith('/') || relPath.startsWith('\\')) {
    return false;
  }
  const norm = relPath.replace(/\\/g, '/');
  const parts = norm.split('/');
  return !parts.some((part) => part === '' || part === '.' || part === '..' || part.startsWith('.'));
}

export function isSafeRelMd(relPath) {
  if (!isSafeRelPath(relPath)) return false;
  const [, ext] = splitExt(relPath);
  return NOTE_EXTENSIONS.has(ext.toLowerCase());
}

export function isSafeRelAsset(relPath) {
  if (!relPath || typeof relPath !== 'string') return false;
  if (relPath.includes('\\') || !isSafeRelPath(relPath)) return false;
  const parts = relPath.split('/');
  return parts.slice(0, -1).includes('assets');
}

export function syncDirKey(name) {
  return String(name ?? '').normalize('NFC').toLowerCase();
}

export function foldSyncPath(relPath, { caseInsensitive = false, normalize = false } = {}) {
  let text = String(relPath ?? '').replace(/\\/g, '/');
  if (normalize) {
    text = text.normalize('NFC');
  }
  if (caseInsensitive) {
    text = text.toLowerCase();
  }
  return text;
}

export function inSyncSubdir(relPath, subdirs) {
  if (!subdirs) return false;
  const first = syncDirKey(String(relPath ?? '').split('/', 1)[0]);
  if (subdirs instanceof Set) {
    return subdirs.has(first);
  }
  if (Array.isArray(subdirs)) {
    return subdirs.includes(first);
  }
  return false;
}

export function matchesScope(relPath, scope = 'all', { caseInsensitive = false, normalize = false } = {}) {
  const sc = scope || 'all';
  if (sc === 'all') return true;
  if (caseInsensitive || normalize) {
    const folded = foldSyncPath(relPath, { caseInsensitive, normalize });
    const prefix = foldSyncPath(sc, { caseInsensitive, normalize });
    return folded.startsWith(`${prefix}/`);
  }
  return String(relPath ?? '').startsWith(`${sc}/`);
}

export function pathsOverlap(pathA, pathB, { caseInsensitive = false, normalize = true } = {}) {
  if (!pathA || !pathB) return false;
  const a = normAbsPath(pathA);
  const b = normAbsPath(pathB);
  if (!a || !b) return false;
  const fa = foldSyncPath(a, { caseInsensitive, normalize });
  const fb = foldSyncPath(b, { caseInsensitive, normalize });
  if (fa === fb) return true;
  if (fa === '/' || fb === '/') return a.startsWith('/') && b.startsWith('/');
  return fa.startsWith(`${fb}/`) || fb.startsWith(`${fa}/`);
}

// ============================================================================
// Pure-JS URL Parsing, Encoding, Sanitization & Normalization
// ============================================================================

const UNRESERVED_AND_SUBDELIMS = new Set(
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:@!$&'()*+,;=".split('')
);
const UNRESERVED_ONLY = new Set(
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~'.split('')
);

export function percentEncode(str, safeChars = '') {
  const safeSet = safeChars === 'path-segment'
    ? UNRESERVED_ONLY
    : new Set([...UNRESERVED_ONLY, ...String(safeChars).split('')]);
  const bytes = textToBytes(str);
  const out = [];
  for (let i = 0; i < bytes.length; i += 1) {
    const b = bytes[i];
    const ch = String.fromCharCode(b);
    if (b < 0x80 && safeSet.has(ch)) {
      out.push(ch);
    } else {
      out.push('%' + b.toString(16).toUpperCase().padStart(2, '0'));
    }
  }
  return out.join('');
}

export function percentEncodeSegment(seg) {
  return percentEncode(String(seg ?? ''), '');
}

export function percentDecode(str) {
  const raw = String(str ?? '');
  if (!raw.includes('%')) return raw;
  const bytes = [];
  let i = 0;
  while (i < raw.length) {
    if (raw[i] === '%' && i + 2 < raw.length && /^[0-9a-fA-F]{2}$/.test(raw.slice(i + 1, i + 3))) {
      bytes.push(Number.parseInt(raw.slice(i + 1, i + 3), 16));
      i += 3;
    } else {
      const chBytes = textToBytes(raw[i]);
      for (let j = 0; j < chBytes.length; j += 1) {
        bytes.push(chBytes[j]);
      }
      i += 1;
    }
  }
  return bytesToText(new Uint8Array(bytes));
}

export function parseUrl(raw) {
  const text = String(raw ?? '').trim();
  if (!text || /[\x00-\x1f\x7f\s]/.test(text)) {
    return null;
  }
  const schemeMatch = text.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/);
  if (!schemeMatch) {
    return null;
  }
  const scheme = schemeMatch[1].toLowerCase();
  let rest = schemeMatch[2];

  let fragment = '';
  const hashIdx = rest.indexOf('#');
  if (hashIdx >= 0) {
    fragment = rest.slice(hashIdx + 1);
    rest = rest.slice(0, hashIdx);
  }

  let query = '';
  const qIdx = rest.indexOf('?');
  if (qIdx >= 0) {
    query = rest.slice(qIdx + 1);
    rest = rest.slice(0, qIdx);
  }

  let authority = '';
  let path = rest;
  if (rest.startsWith('//')) {
    const afterSlashes = rest.slice(2);
    const slashIdx = afterSlashes.indexOf('/');
    if (slashIdx >= 0) {
      authority = afterSlashes.slice(0, slashIdx);
      path = afterSlashes.slice(slashIdx);
    } else {
      authority = afterSlashes;
      path = '';
    }
  }

  let username = null;
  let password = null;
  let hostPort = authority;
  const atIdx = authority.lastIndexOf('@');
  if (atIdx >= 0) {
    const userInfo = authority.slice(0, atIdx);
    hostPort = authority.slice(atIdx + 1);
    const colonIdx = userInfo.indexOf(':');
    if (colonIdx >= 0) {
      username = userInfo.slice(0, colonIdx);
      password = userInfo.slice(colonIdx + 1);
    } else {
      username = userInfo;
    }
  }

  let hostname = '';
  let port = null;
  if (hostPort.startsWith('[')) {
    const closeIdx = hostPort.indexOf(']');
    if (closeIdx < 0) return null;
    hostname = hostPort.slice(1, closeIdx);
    const tail = hostPort.slice(closeIdx + 1);
    if (tail) {
      if (!tail.startsWith(':')) return null;
      const portStr = tail.slice(1);
      if (!/^\d+$/.test(portStr)) return null;
      const portNum = Number.parseInt(portStr, 10);
      if (portNum < 1 || portNum > 65535) return null;
      port = portNum;
    }
  } else {
    const colonIdx = hostPort.indexOf(':');
    if (colonIdx >= 0) {
      hostname = hostPort.slice(0, colonIdx);
      const portStr = hostPort.slice(colonIdx + 1);
      if (portStr) {
        if (!/^\d+$/.test(portStr)) return null;
        const portNum = Number.parseInt(portStr, 10);
        if (portNum < 1 || portNum > 65535) return null;
        port = portNum;
      }
    } else {
      hostname = hostPort;
    }
  }

  return {
    scheme,
    username,
    password,
    hostname: hostname.toLowerCase(),
    port,
    path,
    query,
    fragment,
  };
}

export function formatUrl(parsed) {
  if (!parsed || !parsed.scheme) return '';
  let host = parsed.hostname || '';
  if (host.includes(':') && !host.startsWith('[')) {
    host = `[${host}]`;
  }
  let authority = parsed.port ? `${host}:${parsed.port}` : host;
  if (parsed.username !== null && parsed.username !== undefined) {
    const userInfo = parsed.password !== null && parsed.password !== undefined
      ? `${parsed.username}:${parsed.password}`
      : parsed.username;
    authority = `${userInfo}@${authority}`;
  }
  const hasAuth = Boolean(authority);
  let out = `${parsed.scheme}:${hasAuth ? '//' + authority : ''}${parsed.path || ''}`;
  if (parsed.query) out += `?${parsed.query}`;
  if (parsed.fragment) out += `#${parsed.fragment}`;
  return out;
}

export function resolveUrl(baseUrl, href) {
  const rawHref = String(href ?? '').trim();
  if (!rawHref) return baseUrl;
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(rawHref)) {
    return rawHref;
  }
  const base = parseUrl(baseUrl);
  if (!base) return rawHref;

  if (rawHref.startsWith('//')) {
    return `${base.scheme}:${rawHref}`;
  }

  const hostPart = base.hostname.includes(':') ? `[${base.hostname}]` : base.hostname;
  const authority = base.port ? `${hostPart}:${base.port}` : hostPart;
  const origin = `${base.scheme}://${authority}`;

  if (rawHref.startsWith('#')) {
    return `${origin}${base.path || '/'}${base.query ? '?' + base.query : ''}${rawHref}`;
  }
  if (rawHref.startsWith('?')) {
    const qAndF = rawHref.split('#');
    return `${origin}${base.path || '/'}${qAndF[0]}${qAndF.length > 1 ? '#' + qAndF.slice(1).join('#') : ''}`;
  }

  let hrefPath = rawHref;
  let hrefQuery = '';
  let hrefFrag = '';
  const fIdx = hrefPath.indexOf('#');
  if (fIdx >= 0) {
    hrefFrag = hrefPath.slice(fIdx);
    hrefPath = hrefPath.slice(0, fIdx);
  }
  const qIdx = hrefPath.indexOf('?');
  if (qIdx >= 0) {
    hrefQuery = hrefPath.slice(qIdx);
    hrefPath = hrefPath.slice(0, qIdx);
  }

  let mergedPath;
  if (hrefPath.startsWith('/')) {
    mergedPath = posixNormpath(hrefPath);
    if (hrefPath.endsWith('/') && !mergedPath.endsWith('/')) {
      mergedPath += '/';
    }
  } else {
    const baseDir = (base.path || '/').replace(/\/[^/]*$/, '/');
    mergedPath = posixNormpath(baseDir + hrefPath);
    if (hrefPath.endsWith('/') && !mergedPath.endsWith('/')) {
      mergedPath += '/';
    }
  }
  return `${origin}${mergedPath}${hrefQuery}${hrefFrag}`;
}

export function safeParseUrl(raw) {
  return parseUrl(raw);
}

export function hasEmbeddedUrlCredentials(raw, allowSshUsername = true) {
  const parsed = safeParseUrl(raw);
  if (!parsed || !parsed.scheme) return false;
  if (parsed.scheme === 'http' || parsed.scheme === 'https') {
    return parsed.username !== null || parsed.password !== null;
  }
  if (parsed.scheme === 'ssh') {
    if (parsed.password !== null) return true;
    if (!allowSshUsername && parsed.username !== null) return true;
  }
  return false;
}

export function sanitizeUrlForDisplay(raw) {
  const text = String(raw ?? '').trim();
  if (!text) return '';
  const parsed = safeParseUrl(text);
  if (!parsed || !['http', 'https', 'ssh'].includes(parsed.scheme)) {
    return text;
  }
  if (parsed.username === null && parsed.password === null) {
    return text;
  }
  const clean = {
    ...parsed,
    username: parsed.scheme === 'ssh' && parsed.username && parsed.password === null ? parsed.username : null,
    password: null,
  };
  return formatUrl(clean);
}

export function normalizeHttpUrl(raw) {
  const parsed = safeParseUrl(raw);
  if (!parsed || !['http', 'https'].includes(parsed.scheme) || !parsed.hostname) {
    return '';
  }
  if (parsed.username !== null || parsed.password !== null) {
    return '';
  }
  const rawPath = parsed.path || '/';
  const encodedSegments = rawPath.split('/').map((seg) => {
    if (!seg) return '';
    const decoded = percentDecode(seg);
    const bytes = textToBytes(decoded);
    const out = [];
    for (let i = 0; i < bytes.length; i += 1) {
      const b = bytes[i];
      const ch = String.fromCharCode(b);
      if (b < 0x80 && UNRESERVED_AND_SUBDELIMS.has(ch)) {
        out.push(ch);
      } else {
        out.push('%' + b.toString(16).toUpperCase().padStart(2, '0'));
      }
    }
    return out.join('');
  });
  let normPath = encodedSegments.join('/');
  if (!normPath.startsWith('/')) {
    normPath = '/' + normPath;
  }
  normPath = normPath.replace(/\/+$/, '') + '/';
  return formatUrl({
    scheme: parsed.scheme,
    username: null,
    password: null,
    hostname: parsed.hostname,
    port: parsed.port,
    path: normPath,
    query: '',
    fragment: '',
  });
}

export function urlOriginTuple(raw) {
  const parsed = safeParseUrl(raw);
  if (!parsed || !['http', 'https'].includes(parsed.scheme) || !parsed.hostname) {
    return null;
  }
  if (parsed.username !== null || parsed.password !== null) {
    return null;
  }
  const effPort = parsed.port !== null ? parsed.port : (parsed.scheme === 'https' ? 443 : 80);
  return `${parsed.scheme}://${parsed.hostname}:${effPort}`;
}

export function sanitizeErrorText(exc) {
  const raw = exc && typeof exc === 'object' && 'message' in exc ? exc.message : exc;
  let msg = String(raw ?? '').trim().replace(/[\r\n]+/g, ' ');
  msg = msg.replace(/((?:https?|ssh):\/\/)([^/\s@]+)@/gi, '$1***@');
  if (msg.length > 120) {
    msg = `${msg.slice(0, 117)}...`;
  }
  if (msg) return msg;
  if (exc && typeof exc === 'object' && exc.constructor && exc.constructor.name) {
    return exc.constructor.name;
  }
  return 'Error';
}

// ============================================================================
// CommonMark Code-Segment Scanner & Asset Link Extractor / Rewriter
// ============================================================================

function splitLinesKeepEnds(text) {
  if (!text) return [];
  const matches = String(text).match(/[^\r\n]*(?:\r\n|\r|\n|$)/g) || [];
  if (matches.length > 0 && matches[matches.length - 1] === '') {
    matches.pop();
  }
  return matches;
}

export function splitMarkdownCodeSegments(text) {
  if (!text) return [];

  const expandIndentCols = (s) => {
    let cols = 0;
    for (let i = 0; i < s.length; i += 1) {
      if (s[i] === ' ') cols += 1;
      else if (s[i] === '\t') cols += 4 - (cols % 4);
      else break;
    }
    return cols;
  };

  const splitInlineCodeSpans = (chunk) => {
    const out = [];
    const n = chunk.length;
    let i = 0;
    let plainStart = 0;
    const paraSepRe = /\r?\n[ \t]*\r?\n/g;
    while (i < n) {
      if (chunk[i] === '`') {
        let bs = 0;
        let p = i - 1;
        while (p >= 0 && chunk[p] === '\\') {
          bs += 1;
          p -= 1;
        }
        if (bs % 2 === 1) {
          i += 1;
          continue;
        }
        let j = i;
        while (j < n && chunk[j] === '`') j += 1;
        const ticks = j - i;
        paraSepRe.lastIndex = j;
        const sepM = paraSepRe.exec(chunk);
        const limit = sepM ? sepM.index : n;
        let k = j;
        let matchedEnd = -1;
        while (k < limit) {
          if (chunk[k] === '`') {
            let m = k;
            while (m < limit && chunk[m] === '`') m += 1;
            if (m - k === ticks) {
              matchedEnd = m;
              break;
            }
            k = m;
          } else {
            k += 1;
          }
        }
        if (matchedEnd !== -1) {
          if (i > plainStart) out.push([false, chunk.slice(plainStart, i)]);
          out.push([true, chunk.slice(i, matchedEnd)]);
          i = matchedEnd;
          plainStart = matchedEnd;
          continue;
        }
        i = j;
      } else {
        i += 1;
      }
    }
    if (plainStart < n) {
      out.push([false, chunk.slice(plainStart)]);
    }
    return out;
  };

  const bqOneRe = /^ {0,3}>[ \t]?(.*)$/;
  const listOneRe = /^( {0,3}(?:[*+-]|\d{1,9}[.)])(?:[ \t]+|$))(.*)$/;
  const fenceRe = /^([ \t]*)(`{3,}|~{3,})(.*)$/;
  const atxHeadingRe = /^ {0,3}#{1,6}(?:[ \t]|$)/;
  const thematicBreakRe = /^ {0,3}(?:(?:\*[ \t]*){3,}|(?:-[ \t]*){3,}|(?:_[ \t]*){3,})$/;

  const stripContainers = (lineBody, activeIndent = 0) => {
    let rest = lineBody;
    let bqCount = 0;
    let totalIndent = 0;
    let openedList = false;
    while (true) {
      const bm = rest.match(bqOneRe);
      if (bm) {
        bqCount += 1;
        rest = bm[1];
        continue;
      }
      const lm = rest.match(listOneRe);
      if (lm) {
        const markerStr = lm[1];
        let step = expandIndentCols(markerStr);
        if (!markerStr.endsWith(' ') && !markerStr.endsWith('\t')) {
          step += 1;
        }
        totalIndent += step;
        rest = lm[2];
        openedList = true;
        continue;
      }
      if (activeIndent > totalIndent && expandIndentCols(rest) >= activeIndent - totalIndent) {
        const needed = activeIndent - totalIndent;
        let cols = 0;
        let idx = 0;
        while (idx < rest.length && cols < needed) {
          if (rest[idx] === ' ') cols += 1;
          else if (rest[idx] === '\t') cols += 4 - (cols % 4);
          else break;
          idx += 1;
        }
        const candidate = rest.slice(idx);
        const bm2 = candidate.match(bqOneRe);
        if (bm2) {
          totalIndent = activeIndent;
          bqCount += 1;
          rest = bm2[1];
          continue;
        }
      }
      break;
    }
    return [rest, bqCount, totalIndent, openedList];
  };

  const blockSegments = [];
  let buf = [];
  let fenceChar = '';
  let fenceLen = 0;
  let fenceBqDepth = 0;
  let fenceMinIndent = 0;
  let inIndentedCode = false;
  let indentedBqDepth = 0;
  let indentedMinCols = 4;
  let prevLineBlank = true;
  let activeListIndent = 0;
  let activeListBqDepth = 0;
  let lastPlainSig = null;

  const flushPlain = () => {
    if (buf.length > 0) {
      blockSegments.push([false, buf.join('')]);
      buf = [];
    }
  };

  for (const rawLine of splitLinesKeepEnds(text)) {
    const body = rawLine.replace(/[\r\n]+$/, '');

    if (fenceChar) {
      const [fRest, fBq, fListInd] = stripContainers(body, fenceMinIndent);
      const fBlank = fRest.trim() === '';
      const fLead = expandIndentCols(fRest);
      const effectiveIndent = fListInd + fLead;
      const droppedContainer =
        fBq < fenceBqDepth || (!fBlank && fenceMinIndent > 0 && effectiveIndent < fenceMinIndent);
      if (droppedContainer) {
        blockSegments.push([true, buf.join('')]);
        buf = [];
        fenceChar = '';
        fenceLen = 0;
        fenceBqDepth = 0;
        fenceMinIndent = 0;
        prevLineBlank = false;
        lastPlainSig = null;
      } else {
        const closeM = fRest.match(/^([ \t]*)(`{3,}|~{3,})[ \t]*$/);
        buf.push(rawLine);
        if (
          fBq === fenceBqDepth &&
          closeM &&
          fListInd + expandIndentCols(closeM[1]) <= fenceMinIndent + 3 &&
          closeM[2][0] === fenceChar &&
          closeM[2].length >= fenceLen
        ) {
          blockSegments.push([true, buf.join('')]);
          buf = [];
          fenceChar = '';
          fenceLen = 0;
          fenceBqDepth = 0;
          fenceMinIndent = 0;
          prevLineBlank = false;
          lastPlainSig = null;
        }
        continue;
      }
    }

    const [rest, curDepth, lineListIndent, openedListOnLine] = stripContainers(body, activeListIndent);
    const isBlank = rest.trim() === '';
    const indentCols = expandIndentCols(rest);
    const effIndent = lineListIndent + indentCols;

    if (inIndentedCode) {
      if (curDepth === indentedBqDepth && (isBlank || effIndent >= indentedMinCols)) {
        buf.push(rawLine);
        prevLineBlank = isBlank;
        continue;
      }
      blockSegments.push([true, buf.join('')]);
      buf = [];
      inIndentedCode = false;
      lastPlainSig = null;
    }

    if (
      !isBlank &&
      !openedListOnLine &&
      (curDepth !== activeListBqDepth || effIndent < activeListIndent)
    ) {
      activeListIndent = 0;
      activeListBqDepth = 0;
    }

    if (openedListOnLine) {
      activeListIndent = lineListIndent;
      activeListBqDepth = curDepth;
    }

    const fenceBaseIndent = openedListOnLine
      ? lineListIndent
      : curDepth === activeListBqDepth
        ? activeListIndent
        : 0;
    const maxFenceLead =
      openedListOnLine || lineListIndent >= fenceBaseIndent ? 3 : fenceBaseIndent + 3;
    const fm = rest.match(fenceRe);
    if (fm && expandIndentCols(fm[1]) <= maxFenceLead) {
      const ch = fm[2][0];
      const info = fm[3];
      if (ch !== '`' || !info.includes('`')) {
        flushPlain();
        fenceChar = ch;
        fenceLen = fm[2].length;
        fenceBqDepth = curDepth;
        fenceMinIndent = fenceBaseIndent;
        buf.push(rawLine);
        prevLineBlank = false;
        lastPlainSig = null;
        continue;
      }
    }

    const minIndentedCols =
      curDepth === activeListBqDepth && activeListIndent > 0 ? activeListIndent + 4 : 4;
    if (prevLineBlank && !isBlank && !openedListOnLine && effIndent >= minIndentedCols) {
      flushPlain();
      inIndentedCode = true;
      indentedBqDepth = curDepth;
      indentedMinCols = minIndentedCols;
      buf.push(rawLine);
      prevLineBlank = false;
      lastPlainSig = null;
      continue;
    }

    const isLeafBoundary = atxHeadingRe.test(rest) || thematicBreakRe.test(rest);
    const curSig = `${curDepth}:${curDepth === activeListBqDepth ? activeListIndent : 0}`;
    if (isBlank || isLeafBoundary || openedListOnLine || (lastPlainSig !== null && curSig !== lastPlainSig)) {
      flushPlain();
    }
    buf.push(rawLine);
    if (isBlank || isLeafBoundary) {
      flushPlain();
      lastPlainSig = null;
    } else {
      lastPlainSig = curSig;
    }
    prevLineBlank = isBlank;
  }

  if (buf.length > 0) {
    blockSegments.push([Boolean(fenceChar || inIndentedCode), buf.join('')]);
  }

  const finalSegments = [];
  for (const [isCode, seg] of blockSegments) {
    if (isCode) {
      finalSegments.push([true, seg]);
    } else {
      finalSegments.push(...splitInlineCodeSpans(seg));
    }
  }
  return finalSegments;
}

const BARE_DEST_SRC = '(?:\\\\.|[^\\s()<>\\\\]|\\((?:\\\\.|[^\\s()<>\\\\])*\\))+';

export function noteAssetPaths(notePath, text) {
  const visibleParts = [];
  for (const [isCode, seg] of splitMarkdownCodeSegments(text)) {
    if (isCode) {
      visibleParts.push(seg.replace(/[^\r\n]/g, ' '));
    } else {
      visibleParts.push(seg);
    }
  }
  const visibleText = visibleParts.join('');
  const linkDestSrc = `<([^>\\n]+)>|(${BARE_DEST_SRC})`;
  const linkRe = new RegExp(`\\]\\(\\s*(?:${linkDestSrc})(?=[\\s)])`, 'g');
  const refRe = new RegExp(
    `^(?: {0,3}>[ \\t]?)* {0,3}\\[(?:\\\\.|[^\\]\\\\\\n])+\\]:[ \\t]*(?:\\r?\\n(?: {0,3}>[ \\t]?)*[ \\t]*)?(?:${linkDestSrc})(?=[ \\t\\r]|$)`,
    'gm'
  );
  const attrRe = /\b(?:src|href)\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s>]+))/gi;

  const rawDests = [];
  for (const m of visibleText.matchAll(linkRe)) {
    rawDests.push(m[1] || m[2]);
  }
  for (const m of visibleText.matchAll(refRe)) {
    rawDests.push(m[1] || m[2]);
  }
  for (const m of visibleText.matchAll(attrRe)) {
    rawDests.push(m[1] || m[2] || m[3]);
  }

  const noteDir = posixDirname(notePath);
  const paths = new Set();
  for (const raw of rawDests) {
    if (!raw) continue;
    let value = htmlUnescape(raw);
    value = value.replace(/\\([()<>\\])/g, '$1');
    const basePart = value.split('#', 1)[0].split('?', 1)[0];
    const decoded = percentDecode(basePart);
    for (const candidate of new Set([value, decoded])) {
      if (
        !candidate ||
        candidate.startsWith('/') ||
        candidate.startsWith('\\') ||
        /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(candidate)
      ) {
        continue;
      }
      const joined = noteDir && noteDir !== '/' ? posixJoin(noteDir, candidate) : candidate;
      const relPath = posixNormpath(joined);
      if (isSafeRelAsset(relPath)) {
        paths.add(relPath);
      }
    }
  }
  return paths;
}

export function rewriteNoteAssetLinks(notePath, text, assetCopyMap) {
  if (!assetCopyMap || !text) return text;
  const copyLookup = assetCopyMap instanceof Map
    ? (k) => assetCopyMap.get(k)
    : (k) => (Object.hasOwn(assetCopyMap, k) ? assetCopyMap[k] : undefined);
  const hasAny = assetCopyMap instanceof Map ? assetCopyMap.size > 0 : Object.keys(assetCopyMap).length > 0;
  if (!hasAny) return text;

  const noteDir = posixDirname(String(notePath).replace(/\\/g, '/'));

  const resolveReplacement = (rawDest) => {
    if (!rawDest) return null;
    let unesc = htmlUnescape(rawDest);
    unesc = unesc.replace(/\\([()<>\\])/g, '$1');
    const qIdx = unesc.indexOf('?');
    const baseAndHash = qIdx >= 0 ? unesc.slice(0, qIdx) : unesc;
    const restQ = qIdx >= 0 ? unesc.slice(qIdx) : '';
    const hIdx = baseAndHash.indexOf('#');
    const basePart = hIdx >= 0 ? baseAndHash.slice(0, hIdx) : baseAndHash;
    const restH = hIdx >= 0 ? baseAndHash.slice(hIdx) : '';
    const tail = restH + restQ;
    const decoded = percentDecode(basePart);

    for (const cand of [basePart, decoded]) {
      if (
        !cand ||
        cand.startsWith('/') ||
        cand.startsWith('\\') ||
        /^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(cand)
      ) {
        continue;
      }
      const joined = noteDir && noteDir !== '/' ? posixJoin(noteDir, cand) : cand;
      const rel = posixNormpath(joined);
      const targetRel = copyLookup(rel);
      if (targetRel) {
        let relFromNote = noteDir ? posixRelpath(targetRel, noteDir) : targetRel;
        if (basePart.startsWith('./') && !relFromNote.startsWith('.')) {
          relFromNote = `./${relFromNote}`;
        }
        if (basePart !== decoded && basePart.includes('%')) {
          relFromNote = relFromNote.split('/').map((seg) => percentEncodeSegment(seg)).join('/');
        }
        return relFromNote + tail;
      }
    }
    return null;
  };

  const encodeMdBareDest = (destStr) => {
    const out = destStr
      .replace(/\\/g, '\\\\')
      .replace(/\(/g, '\\(')
      .replace(/\)/g, '\\)')
      .replace(/</g, '\\<')
      .replace(/>/g, '\\>');
    if (/\s/.test(out)) {
      return `<${destStr.replace(/</g, '%3C').replace(/>/g, '%3E')}>`;
    }
    return out;
  };

  const encodeMdAngleDest = (destStr) =>
    destStr.replace(/\\/g, '\\\\').replace(/</g, '\\<').replace(/>/g, '\\>');

  const mdLinkRe = new RegExp(`(\\]\\(\\s*)(?:<([^>\\n]+)>|(${BARE_DEST_SRC}))(?=[\\s)])`, 'g');
  const mdRefRe = new RegExp(
    `^((?:(?: {0,3}>[ \\t]?)* {0,3})\\[(?:\\\\.|[^\\]\\\\\\n])+\\]:[ \\t]*(?:\\r?\\n(?: {0,3}>[ \\t]?)*[ \\t]*)?)(?:<([^>\\n]+)>|(${BARE_DEST_SRC}))(?=[ \\t\\r]|$)`,
    'gm'
  );
  const attrRe = /(\b(?:src|href)\s*=\s*)(?:"([^"]+)"|'([^']+)'|([^\s>]+))/gi;

  const replMd = (match, prefix, angle, bare) => {
    const raw = angle !== undefined ? angle : bare;
    const updated = resolveReplacement(raw);
    if (!updated) return match;
    if (angle !== undefined) {
      return `${prefix}<${encodeMdAngleDest(updated)}>`;
    }
    return `${prefix}${encodeMdBareDest(updated)}`;
  };

  const replAttr = (match, prefix, q1, q2, bare) => {
    const raw = q1 !== undefined ? q1 : q2 !== undefined ? q2 : bare;
    const updated = resolveReplacement(raw);
    if (!updated) return match;
    if (q1 !== undefined) return `${prefix}"${htmlEscape(updated, true)}"`;
    if (q2 !== undefined) return `${prefix}'${htmlEscape(updated, true)}'`;
    return `${prefix}${updated}`;
  };

  const rewritePlainSegment = (segment) => {
    let out = segment.replace(mdLinkRe, replMd);
    out = out.replace(mdRefRe, replMd);
    out = out.replace(attrRe, replAttr);
    return out;
  };

  const outParts = [];
  for (const [isCode, seg] of splitMarkdownCodeSegments(text)) {
    outParts.push(isCode ? seg : rewritePlainSegment(seg));
  }
  return outParts.join('');
}

// ============================================================================
// Conflict Copy Naming
// ============================================================================

export function makeConflictPath(relPath, tag) {
  const norm = String(relPath ?? '').replace(/\\/g, '/');
  const [stem, ext] = splitExt(norm);
  return `${stem}.conflict-${tag}${ext || '.md'}`;
}

export function makeUniqueConflictPath(
  relPath,
  remoteText,
  {
    existingLocal = null,
    existingRemote = null,
    reserved = null,
    checkLocal = null,
    checkRemote = null,
    callHost = null,
    hashFn = null,
  } = {}
) {
  const norm = String(relPath ?? '').replace(/\\/g, '/');
  const [stem, ext] = splitExt(norm);
  const finalExt = ext || '.md';
  const digest = typeof hashFn === 'function' ? hashFn(remoteText) : sha256Text(remoteText, callHost);
  const fingerprint = digest.slice(0, 8);
  const localMap = existingLocal || {};
  const remoteMap = existingRemote || {};
  const used = reserved instanceof Set ? reserved : new Set();

  let attempt = 1;
  while (true) {
    const suffix = attempt === 1 ? '' : `-${attempt}`;
    const candidate = `${stem}.conflict-${fingerprint}${suffix}${finalExt}`;
    if (!used.has(candidate)) {
      let locCur = Object.hasOwn(localMap, candidate) ? localMap[candidate] : undefined;
      if (locCur === undefined && typeof checkLocal === 'function') {
        locCur = checkLocal(candidate);
      }
      let remCur = Object.hasOwn(remoteMap, candidate) ? remoteMap[candidate] : undefined;
      if (remCur === undefined && typeof checkRemote === 'function') {
        remCur = checkRemote(candidate);
      }
      const locOk = locCur === undefined || locCur === null || locCur === remoteText;
      const remOk = remCur === undefined || remCur === null || remCur === remoteText;
      if (locOk && remOk) {
        used.add(candidate);
        return candidate;
      }
    }
    attempt += 1;
  }
}

// ============================================================================
// Sync Error Classification
// ============================================================================

const AUTH_ERROR_TOKENS = [
  'permission denied (publickey)',
  'authentication failed',
  'invalid username or token',
  'invalid username or password',
  'http basic: access denied',
  'could not read username',
  'terminal prompts disabled',
  'returned error: 401',
  'returned error: 403',
  'http 401',
  'http 403',
  '(401)',
  '(403)',
  'status 401',
  'status 403',
  'unauthorized',
  'forbidden',
  '认证失败',
  '公钥认证',
  '访问令牌',
  '用户名或密码',
  'access token',
  'ssh key',
];

const CONFLICT_ERROR_TOKENS = [
  'non-fast-forward',
  'could not apply',
  'merge conflict',
  'conflict',
  '冲突',
  'git 分支已更新',
  'branch advanced',
];

const CONFIG_ERROR_TOKENS = [
  'repository not found',
  'returned error: 404',
  'http 404',
  '(404)',
  'status 404',
  '未找到远端仓库',
  '请填写',
  '请先填写',
  '请先选择',
  '请至少选择',
  'enter a ',
  'select at least',
  'address is missing',
  '未安装 git',
  'git is not installed',
  '不是有效的 git 仓库',
  'not a valid git repository',
  '目录不存在',
  'does not exist',
  '不安全',
  'unsafe',
  '重叠',
  'overlap',
  '内嵌',
  'do not embed',
  '不可写',
  'not writable',
  'invalid url',
  '无效的',
];

const TRANSIENT_NETWORK_TOKENS = [
  // Git / SSH / TLS transient errors (mirrors git_sync.js isTransientGitError)
  'connection closed',
  'connection reset',
  'broken pipe',
  'timed out',
  'timeout',
  'could not resolve host',
  'temporary failure in name resolution',
  'failed to connect',
  "couldn't connect to server",
  'network is unreachable',
  'no route to host',
  'connection refused',
  'unexpected disconnect',
  'early eof',
  'the remote end hung up unexpectedly',
  'kex_exchange_identification',
  'banner exchange',
  'recv failure',
  'empty reply from server',
  'ssl_connect',
  'gnutls_handshake',
  'curl 7',
  'curl 28',
  'curl 35',
  'curl 56',
  // WebDAV / Node / HTTP transient network errors
  'http 502',
  'http 503',
  'http 504',
  '(502)',
  '(503)',
  '(504)',
  'status 502',
  'status 503',
  'status 504',
  'returned error: 502',
  'returned error: 503',
  'returned error: 504',
  '502 bad gateway',
  '503 service unavailable',
  '504 gateway timeout',
  'etimedout',
  'econnreset',
  'enotfound',
  'eai_again',
  'econnrefused',
  'ehostunreach',
  'enetunreach',
  'epipe',
  'socket hang up',
  // Localized network error messages from gitErrorMessage / webdav.js
  '连接超时',
  '网络连接中断',
  '无法连接远端服务器',
  '连接不可达',
  '远端不可达',
  'server is unreachable',
  'remote is unreachable',
  'could not reach the remote server',
  'network connection was closed',
  'connection timed out',
  '到达后台执行时限',
  'reached the background deadline',
];

/** Classify a sync error message into 'network' | 'auth' | 'conflict' | 'config' | 'other'. */
export function classifySyncError(msg) {
  const raw = msg && typeof msg === 'object' && 'message' in msg ? msg.message : msg;
  const lower = String(raw ?? '').toLowerCase();
  if (!lower) return 'other';
  if (AUTH_ERROR_TOKENS.some((tok) => lower.includes(tok))) return 'auth';
  if (CONFLICT_ERROR_TOKENS.some((tok) => lower.includes(tok))) return 'conflict';
  if (CONFIG_ERROR_TOKENS.some((tok) => lower.includes(tok))) return 'config';
  if (TRANSIENT_NETWORK_TOKENS.some((tok) => lower.includes(tok))) return 'network';
  return 'other';
}

