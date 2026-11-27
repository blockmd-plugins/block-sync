/**
 * WebDAV protocol client, pure-JS lightweight XML parser, and 3-way sync engine
 * for block-sync. All HTTP calls go through host.http.request; local note/asset
 * I/O goes through host.notes.* / host.fs.*; hashing goes through host.crypto.hash.
 * Pure ES2023, QuickJS-NG compatible.
 */

import {
  tr,
  errorDetail,
  protocolLabel,
  formatReasonItem,
} from './i18n.js';
import {
  resolveCallHost,
  sha256Text,
  sha256Bytes,
  textToBytes,
  bytesToText,
  decodeNoteBytes,
  bytesEqual,
  bytesToBase64,
  base64ToBytes,
  textToBase64,
  htmlUnescape,
  nowHms,
  conflictStamp,
  computeBackoffMs,
  sleepMs,
  splitExt,
  posixDirname,
  posixBasename,
  posixJoin,
  isSafeRelMd,
  isSafeRelAsset,
  syncDirKey,
  foldSyncPath,
  inSyncSubdir,
  matchesScope,
  pathsOverlap,
  percentEncodeSegment,
  percentDecode,
  parseUrl,
  formatUrl,
  resolveUrl,
  hasEmbeddedUrlCredentials,
  sanitizeUrlForDisplay,
  normalizeHttpUrl,
  urlOriginTuple,
  noteAssetPaths,
  rewriteNoteAssetLinks,
  makeUniqueConflictPath,
} from './utils.js';
import {
  DELETE_GUARD_THRESHOLD,
  MAX_WEBDAV_DIRS,
  MAX_STORED_CONFIRM_SAMPLES,
  MAX_LOG_ENTRIES,
  WEBDAV_TRASH_DIR,
  INITIALIZED_META_KEY,
  LAYOUTS_META_KEY,
  resolveWebdavDir,
  resolveCredentials,
  computeNotebookSubdirMap,
  notebookKey,
  notebookLabel,
} from './config.js';

// ============================================================================
// Pure-JS Lightweight XML Parser (WebDAV multistatus & LOCK responses)
// ============================================================================

function parseXmlAttributes(attrStr) {
  const attrs = {};
  const re = /([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;
  for (const m of attrStr.matchAll(re)) {
    const val = m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4] || '';
    attrs[m[1]] = htmlUnescape(val);
  }
  return attrs;
}

function splitQName(qName) {
  const idx = qName.indexOf(':');
  if (idx < 0) return ['', qName];
  return [qName.slice(0, idx), qName.slice(idx + 1)];
}

export function parseXml(xmlInput) {
  let src = typeof xmlInput === 'string' ? xmlInput : bytesToText(xmlInput);
  if (src.charCodeAt(0) === 0xfeff) {
    src = src.slice(1);
  }

  const root = {
    name: '#document',
    localName: '#document',
    ns: '',
    attrs: {},
    children: [],
    text: '',
  };
  const stack = [{ node: root, nsMap: { xml: 'http://www.w3.org/XML/1998/namespace' } }];

  const len = src.length;
  let pos = 0;

  while (pos < len) {
    const lt = src.indexOf('<', pos);
    if (lt < 0) {
      const tail = src.slice(pos);
      if (tail) {
        stack[stack.length - 1].node.text += htmlUnescape(tail);
      }
      break;
    }

    if (lt > pos) {
      const textChunk = src.slice(pos, lt);
      stack[stack.length - 1].node.text += htmlUnescape(textChunk);
    }

    if (src.startsWith('<!--', lt)) {
      const end = src.indexOf('-->', lt + 4);
      if (end < 0) throw new Error('Unterminated XML comment');
      pos = end + 3;
      continue;
    }

    if (src.startsWith('<![CDATA[', lt)) {
      const end = src.indexOf(']]>', lt + 9);
      if (end < 0) throw new Error('Unterminated XML CDATA section');
      stack[stack.length - 1].node.text += src.slice(lt + 9, end);
      pos = end + 3;
      continue;
    }

    if (src.startsWith('<?', lt)) {
      const end = src.indexOf('?>', lt + 2);
      if (end < 0) throw new Error('Unterminated XML processing instruction');
      pos = end + 2;
      continue;
    }

    if (src.startsWith('<!', lt)) {
      // Skip DOCTYPE or other declarations safely.
      let depth = 1;
      let i = lt + 2;
      let quote = '';
      while (i < len && depth > 0) {
        const ch = src[i];
        if (quote) {
          if (ch === quote) quote = '';
        } else if (ch === '"' || ch === "'") {
          quote = ch;
        } else if (ch === '<') {
          depth += 1;
        } else if (ch === '>') {
          depth -= 1;
        }
        i += 1;
      }
      pos = i;
      continue;
    }

    // Parse element tag respecting quoted attribute values containing '>'.
    let i = lt + 1;
    let quote = '';
    let gt = -1;
    while (i < len) {
      const ch = src[i];
      if (quote) {
        if (ch === quote) quote = '';
      } else if (ch === '"' || ch === "'") {
        quote = ch;
      } else if (ch === '>') {
        gt = i;
        break;
      }
      i += 1;
    }
    if (gt < 0) {
      throw new Error('Malformed XML tag');
    }

    const rawTag = src.slice(lt + 1, gt).trim();
    pos = gt + 1;
    if (!rawTag) continue;

    if (rawTag.startsWith('/')) {
      const closeName = rawTag.slice(1).trim();
      const [, closeLocal] = splitQName(closeName);
      if (stack.length > 1) {
        const top = stack[stack.length - 1];
        if (top.node.name === closeName || top.node.localName === closeLocal) {
          stack.pop();
        } else {
          // Tolerate mismatched optional wrapper close tags by unwinding to match if present.
          for (let idx = stack.length - 1; idx >= 1; idx -= 1) {
            if (stack[idx].node.name === closeName || stack[idx].node.localName === closeLocal) {
              stack.length = idx;
              break;
            }
          }
        }
      }
      continue;
    }

    const selfClosing = rawTag.endsWith('/');
    const tagBody = selfClosing ? rawTag.slice(0, -1).trim() : rawTag;
    const spaceMatch = tagBody.match(/^([^\s/]+)(?:\s+([\s\S]*))?$/);
    if (!spaceMatch) {
      throw new Error('Invalid XML element name');
    }

    const qName = spaceMatch[1];
    const attrStr = spaceMatch[2] || '';
    const attrs = attrStr ? parseXmlAttributes(attrStr) : {};
    const parentFrame = stack[stack.length - 1];
    const nextNsMap = { ...parentFrame.nsMap };

    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'xmlns') {
        nextNsMap[''] = v;
      } else if (k.startsWith('xmlns:')) {
        nextNsMap[k.slice(6)] = v;
      }
    }

    const [prefix, localName] = splitQName(qName);
    const ns = Object.hasOwn(nextNsMap, prefix) ? nextNsMap[prefix] : '';
    const node = {
      name: qName,
      localName,
      ns,
      attrs,
      children: [],
      text: '',
    };
    parentFrame.node.children.push(node);

    if (!selfClosing) {
      stack.push({ node, nsMap: nextNsMap });
    }
  }

  return root.children[0] || root;
}

function isDavOrPlain(node, localName) {
  return node && node.localName.toLowerCase() === localName && (!node.ns || node.ns === 'DAV:');
}

function collectNodes(root, predicate, out = []) {
  if (!root) return out;
  if (predicate(root)) out.push(root);
  if (Array.isArray(root.children)) {
    for (const ch of root.children) {
      collectNodes(ch, predicate, out);
    }
  }
  return out;
}

function nodeFullText(node) {
  if (!node) return '';
  let out = node.text || '';
  if (Array.isArray(node.children)) {
    for (const ch of node.children) {
      out += nodeFullText(ch);
    }
  }
  return out;
}

export function parseWebdavMultistatus(xmlInput) {
  const root = parseXml(xmlInput);
  const responses = collectNodes(root, (n) => isDavOrPlain(n, 'response'));
  const entries = [];

  for (const resp of responses) {
    let href = '';
    for (const child of resp.children) {
      if (isDavOrPlain(child, 'href')) {
        const val = nodeFullText(child).trim();
        if (val) {
          href = val;
          break;
        }
      }
    }
    if (!href) continue;

    let sawResourcetype = false;
    let isCollection = false;
    let etag = '';
    let lastModified = '';
    let contentLength = null;
    let respStatus = '';
    const props = {};

    for (const elem of resp.children) {
      if (!isDavOrPlain(elem, 'propstat')) continue;
      let statusOk = true;
      let propElem = null;
      for (const sub of elem.children) {
        if (isDavOrPlain(sub, 'status')) {
          const stTxt = nodeFullText(sub).trim();
          respStatus = stTxt;
          statusOk = /\b2\d\d\b/.test(stTxt);
        } else if (isDavOrPlain(sub, 'prop')) {
          propElem = sub;
        }
      }
      if (!statusOk || !propElem) continue;

      for (const propChild of propElem.children) {
        const lname = propChild.localName.toLowerCase();
        if (isDavOrPlain(propChild, 'resourcetype')) {
          sawResourcetype = true;
          for (const rtChild of propChild.children) {
            if (isDavOrPlain(rtChild, 'collection')) {
              isCollection = true;
            }
          }
          props.resourcetype = isCollection ? 'collection' : 'resource';
        } else if (isDavOrPlain(propChild, 'getetag')) {
          const v = nodeFullText(propChild).trim();
          if (v) {
            etag = v;
            props.getetag = v;
          }
        } else if (isDavOrPlain(propChild, 'getlastmodified')) {
          const v = nodeFullText(propChild).trim();
          if (v) {
            lastModified = v;
            props.getlastmodified = v;
          }
        } else if (isDavOrPlain(propChild, 'getcontentlength')) {
          const v = nodeFullText(propChild).trim();
          if (/^\d+$/.test(v)) {
            contentLength = Number.parseInt(v, 10);
            props.getcontentlength = contentLength;
          }
        } else {
          const v = nodeFullText(propChild).trim();
          if (v) props[lname] = v;
        }
      }
    }

    if (!sawResourcetype) {
      isCollection = href.endsWith('/');
    }

    entries.push({
      href,
      isCollection,
      etag,
      lastModified,
      contentLength,
      status: respStatus,
      props,
    });
  }

  return entries;
}

export function parseWebdavLockToken(xmlInput) {
  const root = parseXml(xmlInput);
  const lockTokens = collectNodes(root, (n) => isDavOrPlain(n, 'locktoken'));
  for (const lt of lockTokens) {
    const hrefs = collectNodes(lt, (n) => isDavOrPlain(n, 'href'));
    for (const h of hrefs) {
      const txt = nodeFullText(h).trim();
      if (txt) return txt;
    }
  }
  return '';
}

// ============================================================================
// WebDAV HTTP Client (via host.http.request)
// ============================================================================

export class WebDAVHttpError extends Error {
  constructor(url, status, message = '', headers = {}, bodyBytes = new Uint8Array(0)) {
    super(message || `HTTP ${status}`);
    this.name = 'WebDAVHttpError';
    this.isHttpError = true;
    this.url = url;
    this.status = status;
    this.code = status;
    this.headers = headers;
    this.bodyBytes = bodyBytes;
  }
}

export function buildWebdavHeaders(cfg, extra = null) {
  const c = cfg || {};
  const headers = { 'User-Agent': 'block-sync/1.0' };
  const user = String(c.webdav_user || '').trim();
  const passwd = String(c.webdav_pass || '');
  if (user && passwd) {
    headers.Authorization = `Basic ${textToBase64(`${user}:${passwd}`)}`;
  } else if (user) {
    headers.Authorization = `Basic ${textToBase64(`${user}:`)}`;
  } else if (passwd.trim()) {
    const token = passwd.trim();
    const low = token.toLowerCase();
    if (low.startsWith('bearer ') || low.startsWith('basic ')) {
      headers.Authorization = token;
    } else if (token.includes(':')) {
      headers.Authorization = `Basic ${textToBase64(token)}`;
    } else {
      headers.Authorization = `Bearer ${token}`;
    }
  }
  if (extra && typeof extra === 'object') {
    for (const [k, v] of Object.entries(extra)) {
      if (v !== undefined && v !== null) {
        headers[k] = String(v);
      }
    }
  }
  return headers;
}

export function webdavRootUrl(cfg) {
  return normalizeHttpUrl((cfg && cfg.webdav_url) || '');
}

export function webdavBaseUrl(cfg, subdir = '') {
  const root = webdavRootUrl(cfg);
  if (!root) return '';
  const sub = resolveWebdavDir(cfg).replace(/^\/+|\/+$/g, '');
  const parts = sub
    ? sub.split('/').filter((p) => p && p !== '.' && p !== '..').map((p) => percentEncodeSegment(p))
    : [];
  if (subdir) {
    for (const p of String(subdir).replace(/^\/+|\/+$/g, '').split('/')) {
      if (p && p !== '.' && p !== '..') {
        parts.push(percentEncodeSegment(p));
      }
    }
  }
  if (parts.length === 0) return root;
  return `${root}${parts.join('/')}/`;
}

export function encodeWebdavRelUrl(baseUrl, relPath) {
  const encoded = String(relPath)
    .split('/')
    .map((p) => percentEncodeSegment(p))
    .join('/');
  return `${baseUrl}${encoded}`;
}

export function isStrongEtag(etag) {
  const raw = String(etag || '').trim();
  return Boolean(raw) && !raw.toLowerCase().startsWith('w/');
}

function normalizeRespHeaders(rawHeaders) {
  const out = {};
  if (!rawHeaders || typeof rawHeaders !== 'object') return out;
  for (const [k, v] of Object.entries(rawHeaders)) {
    if (Array.isArray(v)) {
      out[k.toLowerCase()] = v.map(String).join(', ');
    } else if (v !== undefined && v !== null) {
      out[k.toLowerCase()] = String(v);
    }
  }
  return out;
}

function extractResponseBytes(res) {
  if (!res || typeof res !== 'object') return new Uint8Array(0);
  if (typeof res.body_base64 === 'string' && res.body_base64.length > 0) {
    return base64ToBytes(res.body_base64);
  }
  if (res.body instanceof Uint8Array) {
    return res.body;
  }
  if (typeof res.body === 'string') {
    return textToBytes(res.body);
  }
  return new Uint8Array(0);
}

export function createWebDAVClient({
  callHost = null,
  locale = 'zh',
  sleepFn = null,
  nowMsFn = () => Date.now(),
} = {}) {
  const getRpc = () => resolveCallHost(callHost);

  const sendSingleHttp = (method, url, headers, body, timeoutMs) => {
    let currentMethod = method;
    let currentUrl = url;
    let currentBody = body;

    for (let hop = 0; hop <= 5; hop += 1) {
      const reqParams = {
        method: currentMethod,
        url: currentUrl,
        headers,
        response_encoding: 'base64',
        timeout_ms: timeoutMs,
        follow_redirects: false,
      };
      if (currentBody !== null && currentBody !== undefined) {
        if (currentBody instanceof Uint8Array) {
          reqParams.body_base64 = bytesToBase64(currentBody);
        } else if (typeof currentBody === 'string') {
          reqParams.body = currentBody;
        } else {
          reqParams.body = String(currentBody);
        }
      }

      const res = getRpc()('host.http.request', reqParams);
      const status = Number.parseInt(res?.status ?? 0, 10) || 0;
      const respHeaders = normalizeRespHeaders(res?.headers);
      const bodyBytes = extractResponseBytes(res);

      if ([301, 302, 303, 307, 308].includes(status) && respHeaders.location) {
        const nextUrl = resolveUrl(currentUrl, respHeaders.location);
        const srcOrigin = urlOriginTuple(currentUrl);
        const dstOrigin = urlOriginTuple(nextUrl);
        if (!srcOrigin || !dstOrigin || srcOrigin !== dstOrigin) {
          throw new WebDAVHttpError(
            currentUrl,
            403,
            'WebDAV redirected outside its origin',
            respHeaders,
            bodyBytes
          );
        }
        currentUrl = nextUrl;
        if (status === 303 && currentMethod !== 'GET' && currentMethod !== 'HEAD') {
          currentMethod = 'GET';
          currentBody = null;
        }
        continue;
      }

      if (status >= 400 || status === 0) {
        throw new WebDAVHttpError(
          currentUrl,
          status || 500,
          res?.error || res?.status_text || `HTTP ${status}`,
          respHeaders,
          bodyBytes
        );
      }

      return { status, bodyBytes, headers: respHeaders };
    }

    throw new WebDAVHttpError(currentUrl, 403, 'Too many WebDAV redirects');
  };

  const requestFull = (
    method,
    url,
    {
      body = null,
      extraHeaders = null,
      timeoutMs = 6000,
      cfg = null,
      retries = null,
      deadlineMs = 0,
    } = {}
  ) => {
    const upper = String(method || 'GET').toUpperCase();
    const hdrs = buildWebdavHeaders(cfg, extraHeaders);
    const hasCond = Object.keys(hdrs).some((k) => {
      const low = k.toLowerCase();
      return low === 'if-match' || low === 'if-none-match';
    });
    const canRetry =
      ['PROPFIND', 'GET', 'HEAD', 'MKCOL'].includes(upper) || (upper === 'PUT' && hasCond);
    const maxRetries = retries === null || retries === undefined
      ? (canRetry ? 2 : 0)
      : Math.max(0, Number.parseInt(retries, 10) || 0);

    for (let attempt = 0; attempt <= maxRetries; attempt += 1) {
      let effectiveTimeout = timeoutMs;
      if (deadlineMs > 0) {
        const remaining = deadlineMs - nowMsFn();
        if (remaining < 1000) {
          const err = new Error('WebDAV sync deadline reached');
          err.name = 'TimeoutError';
          throw err;
        }
        effectiveTimeout = Math.min(timeoutMs, remaining);
      }

      try {
        return sendSingleHttp(upper, url, hdrs, body, effectiveTimeout);
      } catch (exc) {
        if (exc instanceof WebDAVHttpError) {
          if (attempt < maxRetries && [429, 502, 503, 504].includes(exc.status)) {
            sleepMs(computeBackoffMs(attempt), sleepFn);
            continue;
          }
          throw exc;
        }
        if (attempt < maxRetries) {
          sleepMs(computeBackoffMs(attempt), sleepFn);
          continue;
        }
        throw exc;
      }
    }
  };

  const request = (method, url, opts = {}) => {
    const { status, bodyBytes } = requestFull(method, url, opts);
    return { status, bodyBytes };
  };

  const ensureDir = (rootUrl, dirRel, cfg = null, deadlineMs = 0) => {
    const parts = String(dirRel || '')
      .replace(/^\/+|\/+$/g, '')
      .split('/')
      .filter((p) => p && p !== '.' && p !== '..');
    let cur = rootUrl;
    for (const part of parts) {
      cur = `${cur}${percentEncodeSegment(part)}/`;
      try {
        request('MKCOL', cur, { cfg, deadlineMs });
      } catch (exc) {
        if (!(exc instanceof WebDAVHttpError) || ![405, 301, 302, 409].includes(exc.status)) {
          throw exc;
        }
      }
    }
  };

  const ensureParents = (baseUrl, relPath, cfg = null, deadlineMs = 0) => {
    const parts = String(relPath || '').split('/').slice(0, -1);
    let cur = baseUrl;
    for (const part of parts) {
      cur = `${cur}${percentEncodeSegment(part)}/`;
      try {
        request('MKCOL', cur, { cfg, deadlineMs });
      } catch (exc) {
        if (!(exc instanceof WebDAVHttpError) || ![405, 301, 302, 409].includes(exc.status)) {
          throw exc;
        }
      }
    }
  };

  const testConnection = (cfg) => {
    const rootUrl = webdavRootUrl(cfg);
    const baseUrl = webdavBaseUrl(cfg);
    if (!rootUrl || !baseUrl) {
      return [
        false,
        tr(locale, '请填写有效的 WebDAV http(s) 地址', 'Enter a valid HTTP or HTTPS WebDAV address'),
      ];
    }
    try {
      const { status } = request('PROPFIND', baseUrl, {
        extraHeaders: { Depth: '0' },
        cfg,
      });
      if ([200, 204, 207].includes(status)) {
        return [
          true,
          tr(locale, `WebDAV 连接正常 (HTTP ${status})`, `WebDAV connection successful (HTTP ${status})`),
        ];
      }
      return [
        false,
        tr(locale, `WebDAV 响应异常 (HTTP ${status})`, `Unexpected WebDAV response (HTTP ${status})`),
      ];
    } catch (exc) {
      if (exc instanceof WebDAVHttpError) {
        if (exc.status === 404 && baseUrl !== rootUrl) {
          try {
            const { status } = request('PROPFIND', rootUrl, {
              extraHeaders: { Depth: '0' },
              cfg,
            });
            if ([200, 204, 207].includes(status)) {
              return [
                true,
                tr(
                  locale,
                  'WebDAV 连通正常（远端目录将在同步时创建）',
                  'WebDAV connection successful. The remote folder will be created during sync.'
                ),
              ];
            }
          } catch (_fallbackErr) {
            // Fall through to normal error reporting.
          }
        }
        if (exc.status === 401 || exc.status === 403) {
          return [
            false,
            tr(
              locale,
              `WebDAV 认证失败 (HTTP ${exc.status})`,
              `WebDAV authentication failed (HTTP ${exc.status})`
            ),
          ];
        }
        return [
          false,
          tr(locale, `WebDAV 请求失败 (HTTP ${exc.status})`, `WebDAV request failed (HTTP ${exc.status})`),
        ];
      }
      const det = errorDetail(locale, exc);
      return [
        false,
        tr(locale, `WebDAV 连接不可达: ${det}`, `WebDAV server is unreachable: ${det}`),
      ];
    }
  };

  const getBytesWithEtag = (
    fileUrl,
    { cfg = null, timeoutMs = 6000, treat405AsAbsent = false, deadlineMs = 0 } = {}
  ) => {
    try {
      const { status, bodyBytes, headers } = requestFull('GET', fileUrl, {
        timeoutMs,
        cfg,
        deadlineMs,
      });
      if (status >= 200 && status < 300) {
        return { found: true, bytes: bodyBytes, etag: String(headers.etag || '').trim() };
      }
      return { found: false, bytes: new Uint8Array(0), etag: '' };
    } catch (exc) {
      if (exc instanceof WebDAVHttpError) {
        if (exc.status === 404 || (treat405AsAbsent && exc.status === 405)) {
          return { found: false, bytes: new Uint8Array(0), etag: '' };
        }
      }
      throw exc;
    }
  };

  const getBytes = (fileUrl, opts = {}) => {
    const { found, bytes } = getBytesWithEtag(fileUrl, opts);
    return { found, bytes };
  };

  const listDirEntries = (baseUrl, dirParts, { cfg = null, timeoutMs = 6000, deadlineMs = 0 } = {}) => {
    const dirSuffix = dirParts && dirParts.length > 0
      ? `${dirParts.map((p) => percentEncodeSegment(p)).join('/')}/`
      : '';
    const dirUrl = `${baseUrl}${dirSuffix}`;
    const baseParsed = parseUrl(baseUrl);
    let rootPath = `${percentDecode((baseParsed && baseParsed.path) || '/').replace(/\/+$/, '')}/`;
    if (!rootPath.startsWith('/')) rootPath = `/${rootPath}`;
    const dirParsed = parseUrl(dirUrl);
    const dirPath = `${percentDecode((dirParsed && dirParsed.path) || '/').replace(/\/+$/, '')}/`;

    let status;
    let bodyBytes;
    try {
      const res = request('PROPFIND', dirUrl, {
        extraHeaders: { Depth: '1' },
        timeoutMs,
        cfg,
        deadlineMs,
      });
      status = res.status;
      bodyBytes = res.bodyBytes;
    } catch (exc) {
      if (exc instanceof WebDAVHttpError && exc.status === 404) {
        return [];
      }
      throw exc;
    }
    if (status !== 200 && status !== 207) {
      return [];
    }

    const entries = [];
    for (const item of parseWebdavMultistatus(bytesToText(bodyBytes))) {
      const absHref = resolveUrl(dirUrl, item.href);
      const parsedHref = parseUrl(absHref);
      const hrefPath = percentDecode((parsedHref && parsedHref.path) || '');
      if (`${hrefPath.replace(/\/+$/, '')}/` === dirPath || !hrefPath.startsWith(rootPath)) {
        continue;
      }
      const rel = hrefPath.slice(rootPath.length).replace(/^\/+|\/+$/g, '');
      if (rel) {
        entries.push({
          rel,
          isCollection: item.isCollection,
          etag: item.etag,
          lastModified: item.lastModified,
          contentLength: item.contentLength,
        });
      }
    }
    return entries;
  };

  const listFiles = (
    baseUrl,
    filterFn,
    {
      cfg = null,
      timeoutMs = 6000,
      excludedSubdirs = new Set(),
      skipAssets = false,
      deadlineMs = 0,
    } = {}
  ) => {
    const rootParsed = parseUrl(baseUrl);
    let rootPath = `${percentDecode((rootParsed && rootParsed.path) || '/').replace(/\/+$/, '')}/`;
    if (!rootPath.startsWith('/')) rootPath = `/${rootPath}`;

    const queue = [baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`];
    const visited = new Set();
    const items = [];
    const maxDirs = MAX_WEBDAV_DIRS;

    while (queue.length > 0) {
      const dirUrl = queue.shift();
      const dirParsed = parseUrl(dirUrl);
      const dirPath = `${percentDecode((dirParsed && dirParsed.path) || '/').replace(/\/+$/, '')}/`;
      if (visited.has(dirPath)) continue;
      visited.add(dirPath);

      let status;
      let bodyBytes;
      try {
        const res = request('PROPFIND', dirUrl, {
          extraHeaders: { Depth: '1' },
          timeoutMs,
          cfg,
          deadlineMs,
        });
        status = res.status;
        bodyBytes = res.bodyBytes;
      } catch (exc) {
        if (exc instanceof WebDAVHttpError && exc.status === 404) {
          continue;
        }
        throw exc;
      }
      if (status !== 200 && status !== 207) {
        continue;
      }

      for (const entry of parseWebdavMultistatus(bytesToText(bodyBytes))) {
        const absHref = resolveUrl(dirUrl, entry.href);
        const parsedHref = parseUrl(absHref);
        const hrefPath = percentDecode((parsedHref && parsedHref.path) || '');
        const normDir = `${hrefPath.replace(/\/+$/, '')}/`;
        if (normDir === dirPath || !hrefPath.startsWith(rootPath)) {
          continue;
        }

        const rel = hrefPath.slice(rootPath.length).replace(/^\/+/, '');
        if (!rel || inSyncSubdir(rel, excludedSubdirs)) {
          continue;
        }
        if (entry.isCollection) {
          const relDir = rel.replace(/\/+$/, '');
          const segments = relDir.split('/').filter(Boolean);
          if (skipAssets && segments.includes('assets')) continue;
          if (segments.some((part) => part.startsWith('.'))) continue;
          if (!visited.has(normDir)) {
            if (visited.size + queue.length >= maxDirs) {
              throw new Error(
                tr(
                  locale,
                  `WebDAV 远端目录数量超出扫描上限（${maxDirs} 个），已中止同步以避免遗漏`,
                  `WebDAV remote directory count exceeded the scan limit (${maxDirs}); sync aborted to prevent incomplete results`
                )
              );
            }
            const encodedNormDir = normDir
              .split('/')
              .map((seg) => (seg ? percentEncodeSegment(seg) : ''))
              .join('/');
            const childUrl = formatUrl({
              scheme: rootParsed.scheme,
              username: null,
              password: null,
              hostname: rootParsed.hostname,
              port: rootParsed.port,
              path: encodedNormDir,
              query: '',
              fragment: '',
            });
            queue.push(childUrl);
          }
        } else if (filterFn(rel)) {
          items.push(rel);
        }
      }
    }

    return [...new Set(items)].sort();
  };

  const resolveDirCaseVariants = (
    baseUrl,
    dirParts,
    { cfg = null, timeoutMs = 6000, normalize = false, deadlineMs = 0 } = {}
  ) => {
    if (!dirParts || dirParts.length === 0) return [[]];
    let curPrefixes = [[]];
    for (const seg of dirParts) {
      const segKey = foldSyncPath(seg, { caseInsensitive: true, normalize });
      const nextPrefixes = [];
      const seen = new Set();
      for (const prefix of curPrefixes) {
        for (const entry of listDirEntries(baseUrl, prefix, { cfg, timeoutMs, deadlineMs })) {
          if (!entry.isCollection) continue;
          const name = entry.rel.split('/').pop();
          if (foldSyncPath(name, { caseInsensitive: true, normalize }) === segKey) {
            const cand = [...prefix, name];
            const candKey = cand.join('\u0000');
            if (!seen.has(candKey)) {
              seen.add(candKey);
              nextPrefixes.push(cand);
            }
          }
        }
      }
      if (nextPrefixes.length === 0) return [];
      curPrefixes = nextPrefixes;
    }
    return curPrefixes;
  };

  const listScoped = (
    baseUrl,
    filterFn,
    {
      scope = 'all',
      cfg = null,
      timeoutMs = 6000,
      excludedSubdirs = new Set(),
      skipAssets = false,
      normalize = false,
      deadlineMs = 0,
    } = {}
  ) => {
    const sc = String(scope || 'all').trim().replace(/^\/+|\/+$/g, '');
    if (!sc || sc === 'all') {
      return listFiles(baseUrl, filterFn, {
        cfg,
        timeoutMs,
        excludedSubdirs,
        skipAssets,
        deadlineMs,
      });
    }
    const scParts = sc.split('/').filter(Boolean);
    let dirVariants = resolveDirCaseVariants(baseUrl, scParts, {
      cfg,
      timeoutMs,
      normalize,
      deadlineMs,
    });
    if (dirVariants.length === 0) {
      dirVariants = [scParts];
    }
    const out = [];
    const seen = new Set();
    for (const parts of dirVariants) {
      const scActual = parts.join('/');
      const scopePrefix = parts.map((p) => percentEncodeSegment(p)).join('/');
      const scopeUrl = `${baseUrl}${scopePrefix}/`;
      const subItems = listFiles(scopeUrl, (rel) => filterFn(`${scActual}/${rel}`), {
        cfg,
        timeoutMs,
        skipAssets,
        deadlineMs,
      });
      for (const rel of subItems) {
        const fullRel = `${scActual}/${rel}`;
        if (!seen.has(fullRel) && !inSyncSubdir(fullRel, excludedSubdirs)) {
          seen.add(fullRel);
          out.push(fullRel);
        }
      }
    }
    return out;
  };

  const findCaseVariants = (
    baseUrl,
    onlyPath,
    {
      cfg = null,
      timeoutMs = 6000,
      excludedSubdirs = new Set(),
      filterFn = null,
      normalize = false,
      deadlineMs = 0,
    } = {}
  ) => {
    const checkFn = filterFn || isSafeRelMd;
    const targetKey = foldSyncPath(onlyPath, { caseInsensitive: true, normalize });
    const parts = String(onlyPath || '').split('/').filter(Boolean);
    if (parts.length === 0) return [];
    const parentVariants = resolveDirCaseVariants(baseUrl, parts.slice(0, -1), {
      cfg,
      timeoutMs,
      normalize,
      deadlineMs,
    });
    const matches = [];
    const seen = new Set();
    for (const pv of parentVariants) {
      for (const entry of listDirEntries(baseUrl, pv, { cfg, timeoutMs, deadlineMs })) {
        if (entry.isCollection) continue;
        const rel = entry.rel;
        if (
          rel !== onlyPath &&
          foldSyncPath(rel, { caseInsensitive: true, normalize }) === targetKey &&
          checkFn(rel) &&
          !inSyncSubdir(rel, excludedSubdirs) &&
          !seen.has(rel)
        ) {
          seen.add(rel);
          matches.push(rel);
        }
      }
    }
    return matches;
  };

  const lock = (fileUrl, { cfg = null, timeoutMs = 6000, deadlineMs = 0 } = {}) => {
    if (deadlineMs > 0 && deadlineMs - nowMsFn() < 12000) {
      const err = new Error('WebDAV sync deadline reached before acquiring another lock');
      err.name = 'TimeoutError';
      throw err;
    }
    const lockBody =
      '<?xml version="1.0" encoding="utf-8"?>' +
      '<D:lockinfo xmlns:D="DAV:">' +
      '<D:lockscope><D:exclusive/></D:lockscope>' +
      '<D:locktype><D:write/></D:locktype>' +
      '<D:owner><D:href>block-sync</D:href></D:owner>' +
      '</D:lockinfo>';
    try {
      const { status, bodyBytes, headers } = requestFull('LOCK', fileUrl, {
        body: lockBody,
        extraHeaders: {
          'Content-Type': 'application/xml; charset=utf-8',
          Depth: '0',
          Timeout: 'Second-30',
        },
        timeoutMs,
        cfg,
        retries: 0,
        deadlineMs,
      });
      if (status !== 200 && status !== 201) {
        return [null, status];
      }
      let token = String(headers['lock-token'] || '').trim();
      if (!token && bodyBytes.length > 0) {
        try {
          token = parseWebdavLockToken(bytesToText(bodyBytes));
        } catch (_parseErr) {
          token = '';
        }
      }
      if (!token) return [null, status];
      if (!(token.startsWith('<') && token.endsWith('>'))) {
        token = `<${token}>`;
      }
      return [token, status];
    } catch (exc) {
      if (exc instanceof WebDAVHttpError) {
        if (exc.status === 423) throw exc;
        if ([403, 405, 409, 501].includes(exc.status)) {
          return [null, exc.status];
        }
        throw exc;
      }
      throw exc;
    }
  };

  const deletePlaceholder = (
    fileUrl,
    lockToken,
    { cfg = null, timeoutMs = 6000, deadlineMs = 0 } = {}
  ) => {
    if (!lockToken) return [true, ''];
    let found = false;
    let curBytes = new Uint8Array(0);
    try {
      const res = getBytesWithEtag(fileUrl, {
        cfg,
        timeoutMs,
        treat405AsAbsent: true,
        deadlineMs,
      });
      found = res.found;
      curBytes = res.bytes;
    } catch (exc) {
      return [false, errorDetail(locale, exc)];
    }
    if (found && curBytes.length > 0) {
      return [true, ''];
    }
    try {
      requestFull('DELETE', fileUrl, {
        extraHeaders: { If: `(${lockToken})` },
        timeoutMs,
        cfg,
        retries: 2,
        deadlineMs,
      });
      return [true, ''];
    } catch (exc) {
      if (exc instanceof WebDAVHttpError && exc.status === 404) {
        return [true, ''];
      }
      return [false, errorDetail(locale, exc)];
    }
  };

  const unlock = (fileUrl, lockToken, { cfg = null, timeoutMs = 6000, deadlineMs = 0 } = {}) => {
    if (!lockToken) return;
    try {
      requestFull('UNLOCK', fileUrl, {
        extraHeaders: { 'Lock-Token': lockToken },
        timeoutMs,
        cfg,
        retries: 0,
        deadlineMs,
      });
    } catch (_err) {
      // Best-effort unlock.
    }
  };

  const putConditional = (
    baseUrl,
    relPath,
    payloadBytes,
    contentType,
    {
      cfg = null,
      expectedHash = null,
      expectedEtag = null,
      createOnly = false,
      deadlineMs = 0,
    } = {}
  ) => {
    ensureParents(baseUrl, relPath, cfg, deadlineMs);
    const fileUrl = encodeWebdavRelUrl(baseUrl, relPath);
    const rpc = getRpc();
    const contentHash = sha256Bytes(payloadBytes, rpc);
    const changeErr = tr(
      locale,
      `WebDAV 远端文件已变更，已中止覆盖以避免数据丢失：${relPath}`,
      `WebDAV remote file changed during sync; aborted overwrite to protect data: ${relPath}`
    );
    const unsafeErr = tr(
      locale,
      `WebDAV 服务器不支持强 ETag 或写入锁，无法安全执行条件写入：${relPath}`,
      `WebDAV server lacks strong ETag or write LOCK support for safe conditional write: ${relPath}`
    );

    const headers = { 'Content-Type': contentType };
    let lockToken = null;
    let createdLockPlaceholder = false;
    let putOutcomeUnknown = false;
    let cleanupErr = '';

    try {
      if (createOnly) {
        const { found, bytes } = getBytesWithEtag(fileUrl, { cfg, deadlineMs });
        if (found) {
          if (sha256Bytes(bytes, rpc) === contentHash) return;
          throw new Error(changeErr);
        }
        const [tok, lockStatus] = lock(fileUrl, { cfg, deadlineMs });
        lockToken = tok;
        if (lockToken) {
          headers.If = `(${lockToken})`;
          if (lockStatus === 201) {
            createdLockPlaceholder = true;
          } else {
            const check2 = getBytesWithEtag(fileUrl, {
              cfg,
              treat405AsAbsent: true,
              deadlineMs,
            });
            if (check2.found) {
              if (sha256Bytes(check2.bytes, rpc) === contentHash) return;
              throw new Error(changeErr);
            }
            createdLockPlaceholder = true;
          }
        } else {
          headers['If-None-Match'] = '*';
        }
        try {
          requestFull('PUT', fileUrl, {
            body: payloadBytes,
            extraHeaders: headers,
            cfg,
            deadlineMs,
          });
          createdLockPlaceholder = false;
        } catch (putExc) {
          if (lockToken && createdLockPlaceholder) {
            const isTransportErr = !(putExc instanceof WebDAVHttpError);
            if (isTransportErr) {
              putOutcomeUnknown = true;
            }
            try {
              const after = getBytesWithEtag(fileUrl, {
                cfg,
                treat405AsAbsent: true,
                deadlineMs,
              });
              if (after.found && sha256Bytes(after.bytes, rpc) === contentHash) {
                createdLockPlaceholder = false;
                return;
              }
              if (putOutcomeUnknown && after.found && after.bytes.length > 0) {
                createdLockPlaceholder = false;
              }
            } catch (_verifyErr) {
              if (putOutcomeUnknown) {
                createdLockPlaceholder = false;
              }
            }
          }
          throw putExc;
        }
      } else {
        if (expectedHash === null || expectedHash === undefined) {
          throw new Error(changeErr);
        }
        if (isStrongEtag(expectedEtag)) {
          headers['If-Match'] = expectedEtag;
        } else {
          const [tok, lockStatus] = lock(fileUrl, { cfg, deadlineMs });
          lockToken = tok;
          if (lockToken) {
            if (lockStatus === 201) {
              createdLockPlaceholder = true;
              throw new Error(changeErr);
            }
            headers.If = `(${lockToken})`;
            const cur = getBytesWithEtag(fileUrl, {
              cfg,
              treat405AsAbsent: true,
              deadlineMs,
            });
            if (!cur.found) {
              createdLockPlaceholder = true;
              throw new Error(changeErr);
            }
            const curHash = sha256Bytes(cur.bytes, rpc);
            if (curHash !== expectedHash && curHash !== contentHash) {
              throw new Error(changeErr);
            }
          } else {
            const cur = getBytesWithEtag(fileUrl, { cfg, deadlineMs });
            if (!cur.found) {
              throw new Error(changeErr);
            }
            const curHash = sha256Bytes(cur.bytes, rpc);
            if (curHash !== expectedHash && curHash !== contentHash) {
              throw new Error(changeErr);
            }
            if (!isStrongEtag(cur.etag)) {
              throw new Error(unsafeErr);
            }
            headers['If-Match'] = cur.etag;
          }
        }
        try {
          requestFull('PUT', fileUrl, {
            body: payloadBytes,
            extraHeaders: headers,
            cfg,
            deadlineMs,
          });
        } catch (putExc) {
          if (lockToken && !(putExc instanceof WebDAVHttpError)) {
            try {
              const after = getBytesWithEtag(fileUrl, {
                cfg,
                treat405AsAbsent: true,
                deadlineMs,
              });
              if (after.found && sha256Bytes(after.bytes, rpc) === contentHash) {
                return;
              }
            } catch (_verifyErr) {
              // Fall through and rethrow putExc.
            }
          }
          throw putExc;
        }
      }
    } catch (exc) {
      if (exc instanceof WebDAVHttpError) {
        if (exc.status === 412) {
          const cur = getBytesWithEtag(fileUrl, { cfg, deadlineMs });
          if (cur.found && sha256Bytes(cur.bytes, rpc) === contentHash) {
            createdLockPlaceholder = false;
            return;
          }
          throw new Error(changeErr);
        }
        if (exc.status === 423) {
          throw new Error(changeErr);
        }
      }
      throw exc;
    } finally {
      if (lockToken) {
        const cleanupDeadline = deadlineMs > 0 ? deadlineMs + 15000 : 0;
        if (createdLockPlaceholder) {
          const [okDel, delDetail] = deletePlaceholder(fileUrl, lockToken, {
            cfg,
            timeoutMs: deadlineMs > 0 ? 2000 : 6000,
            deadlineMs: cleanupDeadline,
          });
          if (!okDel) {
            cleanupErr = delDetail;
          }
        }
        unlock(fileUrl, lockToken, { cfg, deadlineMs: cleanupDeadline });
      }
    }
    if (cleanupErr) {
      throw new Error(
        tr(
          locale,
          `WebDAV 写入失败且清理临时占位文件失败（${relPath}）：${cleanupErr}`,
          `WebDAV write failed and empty placeholder cleanup also failed (${relPath}): ${cleanupErr}`
        )
      );
    }
  };

  const putText = (baseUrl, relPath, content, opts = {}) => {
    putConditional(baseUrl, relPath, textToBytes(content), 'text/markdown; charset=utf-8', opts);
  };

  const putBytes = (baseUrl, relPath, data, opts = {}) => {
    const view = data instanceof Uint8Array ? data : new Uint8Array(data || 0);
    putConditional(baseUrl, relPath, view, 'application/octet-stream', opts);
  };

  const trashFile = (baseUrl, relPath, matchesFn, cfg = null, deadlineMs = 0) => {
    const fileUrl = encodeWebdavRelUrl(baseUrl, relPath);
    const { found, bytes, etag } = getBytesWithEtag(fileUrl, { cfg, deadlineMs });
    if (!found) return 'missing';
    if (!matchesFn(bytes)) return 'changed';

    const cond = isStrongEtag(etag) ? { 'If-Match': etag } : {};
    const digest = sha256Text(relPath, getRpc()).slice(0, 8);
    const trashName = `${conflictStamp()}-${digest}-${relPath.replace(/\//g, '__')}`;

    try {
      ensureDir(baseUrl, WEBDAV_TRASH_DIR, cfg, deadlineMs);
      const dest =
        `${baseUrl}${percentEncodeSegment(WEBDAV_TRASH_DIR)}/${percentEncodeSegment(trashName)}`;
      requestFull('MOVE', fileUrl, {
        extraHeaders: { Destination: dest, Overwrite: 'F', ...cond },
        cfg,
        retries: 0,
        deadlineMs,
      });
      return 'deleted';
    } catch (exc) {
      if (!(exc instanceof WebDAVHttpError)) throw exc;
      if (exc.status === 404) return 'missing';
      if (exc.status === 412) return 'changed';
      if (![403, 405, 409, 501, 502].includes(exc.status)) throw exc;
    }

    try {
      requestFull('DELETE', fileUrl, {
        extraHeaders: cond,
        cfg,
        retries: 0,
        deadlineMs,
      });
      return 'deleted';
    } catch (exc) {
      if (exc instanceof WebDAVHttpError) {
        if (exc.status === 404) return 'missing';
        if (exc.status === 412) return 'changed';
      }
      throw exc;
    }
  };

  return {
    requestFull,
    request,
    ensureDir,
    ensureParents,
    testConnection,
    getBytesWithEtag,
    getBytes,
    listDirEntries,
    listFiles,
    resolveDirCaseVariants,
    listScoped,
    findCaseVariants,
    lock,
    deletePlaceholder,
    unlock,
    putConditional,
    putText,
    putBytes,
    trashFile,
  };
}

// ============================================================================
// Local Host Adapter (host.notes.* & host.fs.*)
// ============================================================================

export function createHostLocalAdapter({ callHost = null, supportsMultiNotebook = true } = {}) {
  const getRpc = () => resolveCallHost(callHost);

  const listNotePaths = (nbRoot = null) => {
    const params = {};
    if (nbRoot && supportsMultiNotebook) {
      params.notebook_root = nbRoot;
    }
    const res = getRpc()('host.notes.list', params);
    const listed = Array.isArray(res?.notes) ? res.notes : [];
    const paths = [];
    for (const item of listed) {
      const rel = String(item?.path || '').replace(/\\/g, '/');
      if (isSafeRelMd(rel) && !isSafeRelAsset(rel)) {
        paths.push(rel);
      }
    }
    return [...new Set(paths)].sort();
  };

  const readNotes = ({ onlyPath = null, scope = 'all', paths = null, nbRoot = null } = {}) => {
    const rpc = getRpc();
    const notes = {};
    if (onlyPath !== null && onlyPath !== undefined) {
      if (!isSafeRelMd(onlyPath) || isSafeRelAsset(onlyPath)) return notes;
      const params = { path: onlyPath };
      if (nbRoot && supportsMultiNotebook) params.notebook_root = nbRoot;
      try {
        const res = rpc('host.notes.read', params);
        if (res && typeof res === 'object' && res.found !== false && Object.hasOwn(res, 'content')) {
          notes[onlyPath] = String(res.content ?? '');
        }
      } catch (exc) {
        const low = String(exc?.message || exc).toLowerCase();
        if (['not found', 'no such file', 'does not exist', 'missing'].some((tok) => low.includes(tok))) {
          return notes;
        }
        throw exc;
      }
      return notes;
    }

    const allPaths = paths !== null ? paths : listNotePaths(nbRoot);
    for (const relPath of allPaths) {
      if (!isSafeRelMd(relPath) || !matchesScope(relPath, scope)) continue;
      const params = { path: relPath };
      if (nbRoot && supportsMultiNotebook) params.notebook_root = nbRoot;
      const res = rpc('host.notes.read', params);
      notes[relPath] = String(res?.content ?? '');
    }
    return notes;
  };

  const writeNote = (relPath, content, { nbRoot = null, expectedRevision = '' } = {}) => {
    const params = {
      path: relPath,
      content: String(content ?? ''),
      expected_revision: String(expectedRevision ?? ''),
    };
    if (nbRoot && supportsMultiNotebook) {
      params.notebook_root = nbRoot;
    }
    return getRpc()('host.notes.write', params);
  };

  const trashFile = (relPath, revision, { nbRoot = null } = {}) => {
    const params = {
      path: relPath,
      expected_revision: String(revision ?? ''),
    };
    if (nbRoot && supportsMultiNotebook) {
      params.notebook_root = nbRoot;
    }
    try {
      const res = getRpc()('host.notes.trash', params);
      return res && res.trashed ? 'deleted' : 'missing';
    } catch (exc) {
      const low = String(exc?.message || exc).toLowerCase();
      if (low.includes('unknown host method')) return 'unsupported';
      if (low.includes('note changed')) return 'changed';
      throw exc;
    }
  };

  const isCloudPlaceholder = (rootDir, relPath) => {
    if (!rootDir || !relPath) return false;
    const norm = String(relPath).replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
    if (!norm) return false;
    const rpc = getRpc();
    const full = posixJoin(rootDir, norm);
    try {
      const st = rpc('host.fs.stat', { path: full });
      if (st && st.exists && st.is_icloud_placeholder) return true;
    } catch (_err) {
      // Ignore stat errors for missing paths or restricted roots.
    }
    const dirPart = posixDirname(norm);
    const baseName = posixBasename(norm);
    if (!baseName) return false;
    const icloudName = `.${baseName}.icloud`;
    const icloudPath = dirPart ? posixJoin(rootDir, dirPart, icloudName) : posixJoin(rootDir, icloudName);
    try {
      const st = rpc('host.fs.stat', { path: icloudPath });
      return Boolean(st && st.exists);
    } catch (_err) {
      return false;
    }
  };

  const listAssets = (nbRoot, excludedSubdirs = new Set()) => {
    if (!nbRoot) return new Set();
    const cleanRoot = String(nbRoot).replace(/\\/g, '/').replace(/\/+$/, '');
    try {
      const res = getRpc()('host.fs.list', {
        path: cleanRoot,
        recursive: true,
      });
      const rawEntries = Array.isArray(res?.entries) ? res.entries : Array.isArray(res?.files) ? res.files : [];
      const out = new Set();
      for (const item of rawEntries) {
        if (item && typeof item === 'object') {
          if (item.is_dir || item.is_icloud_placeholder) continue;
        }
        let rel = String(
          typeof item === 'string'
            ? item
            : item?.rel_path || item?.path || ''
        ).replace(/\\/g, '/');
        if (rel.startsWith(`${cleanRoot}/`)) {
          rel = rel.slice(cleanRoot.length + 1);
        }
        if (isSafeRelAsset(rel) && !inSyncSubdir(rel, excludedSubdirs)) {
          out.add(rel);
        }
      }
      return out;
    } catch (exc) {
      const low = String(exc?.message || exc).toLowerCase();
      if (low.includes('unknown host method')) return new Set();
      throw exc;
    }
  };

  const readAsset = (nbRoot, relPath) => {
    if (!nbRoot || !isSafeRelAsset(relPath)) return null;
    if (isCloudPlaceholder(nbRoot, relPath)) return null;
    const fullPath = posixJoin(String(nbRoot).replace(/\\/g, '/').replace(/\/+$/, ''), relPath);
    try {
      const res = getRpc()('host.fs.read', {
        path: fullPath,
        encoding: 'base64',
      });
      if (!res || res.found === false) return null;
      if (typeof res.content_base64 === 'string') return base64ToBytes(res.content_base64);
      if (typeof res.base64 === 'string') return base64ToBytes(res.base64);
      if (res.content instanceof Uint8Array) return res.content;
      if (typeof res.content === 'string') return textToBytes(res.content);
      return null;
    } catch (exc) {
      const low = String(exc?.message || exc).toLowerCase();
      if (['not found', 'no such file', 'does not exist', 'missing'].some((tok) => low.includes(tok))) {
        return null;
      }
      throw exc;
    }
  };

  const writeAsset = (nbRoot, relPath, data, { createOnly = false, expectedHash = null } = {}) => {
    const rpc = getRpc();
    const view = data instanceof Uint8Array ? data : new Uint8Array(data || 0);
    const cleanRoot = String(nbRoot || '').replace(/\\/g, '/').replace(/\/+$/, '');
    const fullPath = posixJoin(cleanRoot, relPath);
    if (createOnly) {
      let existing = null;
      try {
        existing = readAsset(cleanRoot, relPath);
      } catch (_err) {
        existing = null;
      }
      if (existing !== null) {
        if (sha256Bytes(existing, rpc) === sha256Bytes(view, rpc)) {
          return { ok: true, skipped: true };
        }
        throw new Error(`Attachment changed during sync; aborted overwrite: ${relPath}`);
      }
    } else if (expectedHash !== null && expectedHash !== undefined) {
      const existing = readAsset(cleanRoot, relPath);
      if (existing === null) {
        throw new Error(`Attachment disappeared during sync; aborted overwrite: ${relPath}`);
      }
      const curHash = sha256Bytes(existing, rpc);
      const nextHash = sha256Bytes(view, rpc);
      if (curHash !== String(expectedHash) && curHash !== nextHash) {
        throw new Error(`Attachment changed during sync; aborted overwrite: ${relPath}`);
      }
    }
    return rpc('host.fs.write', {
      path: fullPath,
      content_base64: bytesToBase64(view),
      atomic: true,
      mkdir_parents: true,
    });
  };

  return {
    listNotePaths,
    readNotes,
    writeNote,
    trashFile,
    isCloudPlaceholder,
    listAssets,
    readAsset,
    writeAsset,
  };
}

// ============================================================================
// WebDAV Sync Engine (Preview, Planning, Risk Assessment, Execution)
// ============================================================================

export function createWebDAVSyncEngine({
  callHost = null,
  notifyHost = null,
  configStore = null,
  client = null,
  localAdapter = null,
  locale = 'zh',
  sleepFn = null,
  nowMsFn = () => Date.now(),
} = {}) {
  const getRpc = () => resolveCallHost(callHost);
  const davClient = client || createWebDAVClient({ callHost, locale, sleepFn, nowMsFn });
  const local = localAdapter || createHostLocalAdapter({
    callHost,
    supportsMultiNotebook: configStore ? configStore.state.supportsMultiNotebook : true,
  });
  const previewCache = new Map();

  const getLocale = () => (configStore ? configStore.state.locale : locale);

  const emitProgress = (params) => {
    if (!params || Object.keys(params).length === 0) return;
    try {
      const notifyFn = typeof notifyHost === 'function'
        ? notifyHost
        : typeof globalThis.notifyHost === 'function'
          ? globalThis.notifyHost
          : null;
      if (notifyFn) {
        notifyFn('host.action.progress', params);
      } else {
        getRpc()('host.action.progress', params);
      }
    } catch (_err) {
      // Progress emission is non-fatal.
    }
  };

  const appendLog = (state, title, status, { tone = '', tooltip = '', logKey = null, logArgs = null } = {}) => {
    const loc = getLocale();
    const raw = {
      title: String(title || tr(loc, '同步任务', 'Sync task')).trim() || tr(loc, '同步任务', 'Sync task'),
      status: String(status || '成功').trim() || '成功',
      time: nowHms(),
      tone,
      tooltip,
      protocol_id: 'webdav',
    };
    if (logKey) {
      raw.log_key = logKey;
      raw.log_args = { ...(logArgs || {}), protocol: 'webdav' };
    }
    if (loc === 'en') {
      raw.locale = 'en';
    }
    state.logs.unshift(raw);
    if (state.logs.length > MAX_LOG_ENTRIES) {
      state.logs.length = MAX_LOG_ENTRIES;
    }
  };

  const fetchWebdavNotes = (
    cfg,
    {
      onlyPath = null,
      scope = 'all',
      timeoutMs = 6000,
      forceRefresh = false,
      subdir = '',
      excludedSubdirs = new Set(),
      deadlineMs = 0,
    } = {}
  ) => {
    const loc = getLocale();
    const rootUrl = webdavRootUrl(cfg);
    const baseUrl = webdavBaseUrl(cfg, subdir);
    if (!rootUrl || !baseUrl) {
      return {
        ok: false,
        notes: {},
        etags: {},
        error: tr(loc, '请先填写有效的 WebDAV http(s) 地址', 'Enter a valid HTTP or HTTPS WebDAV address first'),
      };
    }

    const exKey = [...excludedSubdirs].sort().join('\u0000');
    const cacheKey = `${baseUrl}\u0000${scope}\u0000${onlyPath || ''}\u0000${exKey}`;
    if (!forceRefresh && onlyPath === null && previewCache.has(cacheKey)) {
      const cached = previewCache.get(cacheKey);
      if (nowMsFn() - cached.ts < 15000) {
        return {
          ok: true,
          notes: { ...cached.notes },
          etags: { ...cached.etags },
          error: null,
        };
      }
    }

    try {
      const remotePaths = onlyPath
        ? [onlyPath]
        : davClient.listScoped(baseUrl, isSafeRelMd, {
            scope,
            cfg,
            timeoutMs,
            excludedSubdirs,
            skipAssets: true,
            deadlineMs,
          });

      const remoteNotes = {};
      const remoteEtags = {};
      for (const relPath of remotePaths) {
        if (!isSafeRelMd(relPath) || isSafeRelAsset(relPath) || inSyncSubdir(relPath, excludedSubdirs)) {
          continue;
        }
        const fileUrl = encodeWebdavRelUrl(baseUrl, relPath);
        const { found, bytes, etag } = davClient.getBytesWithEtag(fileUrl, {
          cfg,
          timeoutMs,
          deadlineMs,
        });
        if (found) {
          remoteNotes[relPath] = decodeNoteBytes(bytes, relPath);
          if (etag) remoteEtags[relPath] = etag;
        }
      }

      if (
        onlyPath &&
        Object.keys(remoteNotes).length === 0 &&
        isSafeRelMd(onlyPath) &&
        !isSafeRelAsset(onlyPath) &&
        !inSyncSubdir(onlyPath, excludedSubdirs)
      ) {
        const alts = davClient.findCaseVariants(baseUrl, onlyPath, {
          cfg,
          timeoutMs,
          excludedSubdirs,
          deadlineMs,
        });
        for (const altRel of alts) {
          const altUrl = encodeWebdavRelUrl(baseUrl, altRel);
          const { found, bytes, etag } = davClient.getBytesWithEtag(altUrl, {
            cfg,
            timeoutMs,
            deadlineMs,
          });
          if (found) {
            remoteNotes[altRel] = decodeNoteBytes(bytes, altRel);
            if (etag) remoteEtags[altRel] = etag;
          }
        }
      }

      if (onlyPath === null) {
        previewCache.set(cacheKey, {
          ts: nowMsFn(),
          notes: { ...remoteNotes },
          etags: { ...remoteEtags },
        });
      }

      return { ok: true, notes: remoteNotes, etags: remoteEtags, error: null };
    } catch (exc) {
      const msg = exc?.message && String(exc.message).startsWith('Note is not valid UTF-8')
        ? String(exc.message)
        : tr(
            loc,
            `WebDAV 连接不可达: ${errorDetail(loc, exc)}`,
            `WebDAV server is unreachable: ${errorDetail(loc, exc)}`
          );
      return { ok: false, notes: {}, etags: {}, error: msg };
    }
  };

  const remoteHasAnyContent = (cfg, baseUrl, excludedSubdirs = new Set(), deadlineMs = 0) => {
    if (!baseUrl) return false;
    if (davClient.listFiles(baseUrl, isSafeRelMd, { cfg, excludedSubdirs, skipAssets: true, deadlineMs }).length > 0) {
      return true;
    }
    if (cfg.sync_assets !== false && davClient.listFiles(baseUrl, isSafeRelAsset, { cfg, excludedSubdirs, deadlineMs }).length > 0) {
      return true;
    }
    return false;
  };

  const resolveConflictPair = (relPath, localText, remoteText, baseHash, policy = 'keep_both') => {
    const rpc = getRpc();
    const localHash = sha256Text(localText, rpc);
    const remoteHash = sha256Text(remoteText, rpc);
    if (localHash === remoteHash) {
      return ['skip', localText, null, localHash];
    }
    if (baseHash && baseHash === localHash) {
      return ['pull', remoteText, null, remoteHash];
    }
    if (baseHash && baseHash === remoteHash) {
      return ['push', localText, null, localHash];
    }
    if (policy === 'local_first') {
      return ['push', localText, null, localHash];
    }
    if (policy === 'remote_first') {
      return ['pull', remoteText, null, remoteHash];
    }
    const conflictRel = makeUniqueConflictPath(relPath, remoteText, { callHost: rpc });
    return ['keep_both', localText, [conflictRel, remoteText], localHash];
  };

  const planNotebookAssets = ({
    cfg,
    nbRoot,
    baseUrl,
    baseMap,
    policy,
    scope,
    localNotes,
    remoteNotes,
    onlyPath = null,
    excludedSubdirs = new Set(),
    isFirstSync = false,
    nbKey = 'default',
    deadlineMs = 0,
  }) => {
    const rpc = getRpc();
    const empty = {
      local_assets: {},
      remote_assets: {},
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
    if (cfg.sync_assets === false || !nbRoot) {
      return empty;
    }

    let explicitPaths = null;
    if (onlyPath !== null && onlyPath !== undefined) {
      explicitPaths = new Set([
        ...noteAssetPaths(onlyPath, localNotes[onlyPath] || ''),
        ...noteAssetPaths(onlyPath, remoteNotes[onlyPath] || ''),
      ]);
      if (isSafeRelAsset(onlyPath)) {
        explicitPaths.add(onlyPath);
      }
      if (explicitPaths.size === 0) return empty;
    }

    const localCandidates = explicitPaths !== null ? new Set(explicitPaths) : local.listAssets(nbRoot, excludedSubdirs);
    for (const rel of localCandidates) {
      if (inSyncSubdir(rel, excludedSubdirs)) {
        throw new Error(
          tr(
            getLocale(),
            `附件路径与其他笔记本的同步目录重叠：${rel}`,
            `Attachment path overlaps with another notebook's sync folder: ${rel}`
          )
        );
      }
    }

    const remoteCandidates = explicitPaths !== null
      ? new Set(explicitPaths)
      : new Set(davClient.listScoped(baseUrl, isSafeRelAsset, { scope, cfg, excludedSubdirs, deadlineMs }));

    const referenced = new Set();
    let candidates = new Set([...localCandidates, ...remoteCandidates]);
    if (explicitPaths === null && scope && scope !== 'all') {
      for (const [np, txt] of Object.entries(localNotes)) {
        for (const a of noteAssetPaths(np, txt)) referenced.add(a);
      }
      for (const [np, txt] of Object.entries(remoteNotes)) {
        for (const a of noteAssetPaths(np, txt)) referenced.add(a);
      }
      candidates = new Set([...[...candidates].filter((p) => matchesScope(p, scope)), ...referenced]);
    }
    if (excludedSubdirs.size > 0) {
      candidates = new Set([...candidates].filter((p) => !inSyncSubdir(p, excludedSubdirs)));
    }

    const localAssets = {};
    const remoteAssets = {};
    const remoteAssetEtags = {};
    const remoteAssetPathMap = {};

    for (const rel of [...candidates].sort()) {
      if (excludedSubdirs.size > 0 && inSyncSubdir(rel, excludedSubdirs)) continue;
      if (localCandidates.has(rel) || referenced.has(rel)) {
        const ldata = local.readAsset(nbRoot, rel);
        if (ldata !== null) localAssets[rel] = ldata;
      }
      if (explicitPaths === null && !remoteCandidates.has(rel) && !referenced.has(rel)) {
        continue;
      }
      const fileUrl = encodeWebdavRelUrl(baseUrl, rel);
      const { found, bytes, etag } = davClient.getBytesWithEtag(fileUrl, { cfg, deadlineMs });
      if (found) {
        remoteAssets[rel] = bytes;
        if (etag) remoteAssetEtags[rel] = etag;
      } else if (explicitPaths !== null || referenced.has(rel)) {
        const alts = davClient.findCaseVariants(baseUrl, rel, {
          cfg,
          excludedSubdirs,
          filterFn: isSafeRelAsset,
          deadlineMs,
        });
        for (const altRel of alts) {
          const altUrl = encodeWebdavRelUrl(baseUrl, altRel);
          const altRes = davClient.getBytesWithEtag(altUrl, { cfg, deadlineMs });
          if (altRes.found) {
            remoteAssets[altRel] = altRes.bytes;
            if (altRes.etag) remoteAssetEtags[altRel] = altRes.etag;
            break;
          }
        }
      }
    }

    const pushNew = [];
    const pushOw = [];
    const pullNew = [];
    const pullOw = [];
    const conflicts = [];
    const synced = [];
    const deleteRemote = [];
    const deleteLocal = [];
    const assetDeleteExpectedHashes = {};
    const assetBaseAliases = {};
    const reservedCopies = new Set([...Object.keys(localAssets), ...Object.keys(remoteAssets)]);
    const allowDeleteRemote = !isFirstSync;
    const allowDeleteLocal = !isFirstSync && explicitPaths === null && Object.keys(remoteNotes).length > 0;

    const allAssetPaths = [...new Set([...Object.keys(localAssets), ...Object.keys(remoteAssets)])].sort();
    for (const rel of allAssetPaths) {
      const ldata = localAssets[rel] ?? null;
      const rdata = remoteAssets[rel] ?? null;
      if (ldata === null && rdata === null) continue;
      if (ldata !== null && rdata !== null && bytesEqual(ldata, rdata)) {
        synced.push(rel);
        continue;
      }
      if (ldata === null) {
        if (typeof local.isCloudPlaceholder === 'function' && local.isCloudPlaceholder(nbRoot, rel)) {
          continue;
        }
        const rhash = sha256Bytes(rdata, rpc);
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
          deleteRemote.push(rel);
          assetDeleteExpectedHashes[assetKey] = matchedDelHash;
        } else {
          pullNew.push(rel);
        }
        continue;
      }
      if (rdata === null) {
        const baseDel = allowDeleteLocal ? baseMap[`asset:${rel}`] : undefined;
        if (baseDel !== undefined && sha256Bytes(ldata, rpc) === baseDel) {
          deleteLocal.push(rel);
          assetDeleteExpectedHashes[`asset:${rel}`] = baseDel;
        } else {
          pushNew.push(rel);
        }
        continue;
      }

      const baseKey = `asset:${rel}`;
      const baseHash = baseMap[baseKey];
      const lhash = sha256Bytes(ldata, rpc);
      const rhash = sha256Bytes(rdata, rpc);

      if (baseHash !== undefined && lhash === baseHash && rhash !== baseHash) {
        pullOw.push([rel, false]);
      } else if (baseHash !== undefined && rhash === baseHash && lhash !== baseHash) {
        pushOw.push([rel, false]);
      } else if (policy === 'remote_first') {
        pullOw.push([rel, true]);
      } else if (policy === 'local_first') {
        pushOw.push([rel, true]);
      } else {
        const [stem, ext] = splitExt(rel);
        const fingerprint = rhash.slice(0, 16);
        let attempt = 1;
        let copyRel = '';
        while (true) {
          const suffix = attempt === 1 ? '' : `-${attempt}`;
          copyRel = `${stem}.conflict-${fingerprint}${suffix}${ext}`;
          if (!reservedCopies.has(copyRel)) {
            let lcopy = localAssets[copyRel] ?? null;
            if (lcopy === null) lcopy = local.readAsset(nbRoot, copyRel);
            let rcopy = remoteAssets[copyRel] ?? null;
            if (rcopy === null) {
              const copyUrl = encodeWebdavRelUrl(baseUrl, copyRel);
              const rc = davClient.getBytesWithEtag(copyUrl, { cfg, deadlineMs });
              rcopy = rc.found ? rc.bytes : null;
            }
            const lOk = lcopy === null || bytesEqual(lcopy, rdata);
            const rOk = rcopy === null || bytesEqual(rcopy, rdata);
            if (lOk && rOk) {
              reservedCopies.add(copyRel);
              break;
            }
          }
          attempt += 1;
        }
        conflicts.push([rel, copyRel]);
      }
    }

    return {
      local_assets: localAssets,
      remote_assets: remoteAssets,
      remote_asset_etags: remoteAssetEtags,
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
  };

  const computeSyncPlan = ({
    cfg,
    onlyPath = null,
    inspectRemote = true,
    forceRefresh = false,
    nbRoot = null,
    subdir = '',
    excludedSubdirs = new Set(),
    deadlineMs = 0,
  } = {}) => {
    const rpc = getRpc();
    const loc = getLocale();
    const homeDir = configStore ? configStore.state.homeDir : '';
    const effectiveNbRoot = nbRoot || (configStore ? configStore.state.notebookRoot : '');
    const nbKeyVal = configStore ? configStore.notebookKey(effectiveNbRoot) : notebookKey(effectiveNbRoot, '', homeDir);
    const nbLabelVal = configStore ? configStore.notebookLabel(effectiveNbRoot) : notebookLabel(effectiveNbRoot, loc, '', homeDir);
    const scope = cfg.sync_scope || 'all';
    const policy = cfg.conflict_policy || 'keep_both';

    const localNotes = local.readNotes({ onlyPath, scope, nbRoot: effectiveNbRoot });
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

    const rootBaseUrl = webdavBaseUrl(cfg);
    const baseUrl = webdavBaseUrl(cfg, subdir);
    const metaTarget = rootBaseUrl && subdir ? `${rootBaseUrl}::${subdir}` : rootBaseUrl || 'unconfigured';
    const metaKey = configStore ? configStore.metaKey('webdav', metaTarget, nbKeyVal) : `nb:${nbKeyVal}|webdav:${metaTarget}`;
    const legacyKey = rootBaseUrl && !subdir ? `webdav:${rootBaseUrl}` : null;

    let remoteNotes = {};
    let remoteEtags = {};
    let remoteInspected = true;
    let remoteError = null;

    if (!baseUrl) {
      remoteInspected = false;
      remoteError = tr(loc, '请先填写有效的 WebDAV http(s) 地址', 'Enter a valid HTTP or HTTPS WebDAV address first');
    } else if (inspectRemote || forceRefresh) {
      const fetched = fetchWebdavNotes(cfg, {
        onlyPath,
        scope,
        timeoutMs: inspectRemote ? 6000 : 4000,
        forceRefresh,
        subdir,
        excludedSubdirs,
        deadlineMs,
      });
      if (fetched.ok) {
        remoteNotes = fetched.notes;
        remoteEtags = fetched.etags;
      } else {
        remoteInspected = false;
        remoteError = fetched.error;
      }
    } else {
      const exKey = [...excludedSubdirs].sort().join('\u0000');
      const cacheKey = `${baseUrl}\u0000${scope}\u0000${onlyPath || ''}\u0000${exKey}`;
      if (previewCache.has(cacheKey)) {
        const cached = previewCache.get(cacheKey);
        remoteNotes = { ...cached.notes };
        remoteEtags = { ...cached.etags };
      } else {
        remoteInspected = false;
      }
    }

    const baseMap = configStore ? configStore.getBaseMap(metaKey, legacyKey) : {};
    const initMap = (configStore && configStore.state.syncMeta[INITIALIZED_META_KEY]) || {};
    const hasMeta = Boolean(
      Object.keys(baseMap).length > 0 ||
      (initMap && (initMap[metaKey] || (legacyKey && initMap[legacyKey])))
    );
    const isFirstSync = !hasMeta;

    let remoteNonemptyOnFirstSync = false;
    if (remoteInspected && !remoteError && isFirstSync && onlyPath === null) {
      if (Object.keys(remoteNotes).length > 0) {
        remoteNonemptyOnFirstSync = true;
      } else {
        try {
          remoteNonemptyOnFirstSync = remoteHasAnyContent(cfg, baseUrl, excludedSubdirs, deadlineMs);
        } catch (_err) {
          remoteNonemptyOnFirstSync = false;
        }
      }
    }

    const toPushNew = [];
    const toPushOverwrite = [];
    const toPullNew = [];
    const toPullOverwrite = [];
    const conflicts = [];
    const synced = [];
    const reservedConflictPaths = new Set([...Object.keys(localNotes), ...Object.keys(remoteNotes)]);

    if (remoteInspected && !remoteError) {
      let checkLocalNote = null;
      let checkRemoteNote = null;
      if (onlyPath !== null && onlyPath !== undefined) {
        checkLocalNote = (cand) => local.readNotes({ onlyPath: cand, scope, nbRoot: effectiveNbRoot })[cand];
        checkRemoteNote = (cand) => {
          const candUrl = encodeWebdavRelUrl(baseUrl, cand);
          const { found, bytes } = davClient.getBytesWithEtag(candUrl, { cfg, deadlineMs });
          return found ? decodeNoteBytes(bytes, cand) : null;
        };
      }

      const allPaths = [...new Set([...Object.keys(localNotes), ...Object.keys(remoteNotes)])].sort();
      for (const relPath of allPaths) {
        const inLocal = Object.hasOwn(localNotes, relPath);
        const inRemote = Object.hasOwn(remoteNotes, relPath);
        if (inLocal && !inRemote) {
          toPushNew.push(relPath);
        } else if (inRemote && !inLocal) {
          toPullNew.push(relPath);
        } else {
          const [action] = resolveConflictPair(
            relPath,
            localNotes[relPath],
            remoteNotes[relPath],
            baseMap[relPath],
            policy
          );
          if (action === 'push') {
            toPushOverwrite.push(relPath);
          } else if (action === 'pull') {
            toPullOverwrite.push(relPath);
          } else if (action === 'keep_both') {
            const conflictRel = makeUniqueConflictPath(relPath, remoteNotes[relPath], {
              existingLocal: localNotes,
              existingRemote: remoteNotes,
              reserved: reservedConflictPaths,
              checkLocal: checkLocalNote,
              checkRemote: checkRemoteNote,
              callHost: rpc,
            });
            conflicts.push([relPath, conflictRel, remoteNotes[relPath]]);
          } else {
            synced.push(relPath);
          }
        }
      }
    }

    const toDeleteRemote = [];
    const toDeleteLocal = [];
    const deleteExpectedHashes = {};
    const deletionHeld = new Set();
    if (remoteInspected && !remoteError && !isFirstSync) {
      for (const relPath of [...toPullNew]) {
        const rhash = sha256Text(remoteNotes[relPath], rpc);
        const bhash = baseMap[relPath];
        let matchedDeletedHash = null;
        if (bhash !== undefined) {
          if (rhash === bhash) matchedDeletedHash = bhash;
        } else if (configStore) {
          const thash = configStore.lookupTombstoneHash(nbKeyVal, relPath);
          if (thash !== null && rhash === thash) {
            matchedDeletedHash = thash;
          } else {
            matchedDeletedHash = configStore.lookupOtherProtocolHash(nbKeyVal, relPath, rhash, metaKey);
          }
        }
        if (matchedDeletedHash !== null) {
          const idx = toPullNew.indexOf(relPath);
          if (typeof local.isCloudPlaceholder === 'function' && local.isCloudPlaceholder(effectiveNbRoot, relPath)) {
            if (idx >= 0) toPullNew.splice(idx, 1);
            deletionHeld.add(relPath);
          } else {
            if (idx >= 0) toPullNew.splice(idx, 1);
            toDeleteRemote.push(relPath);
            deleteExpectedHashes[relPath] = matchedDeletedHash;
          }
        }
      }

      if (onlyPath === null && Object.keys(remoteNotes).length > 0) {
        for (const relPath of [...toPushNew]) {
          const bhash = baseMap[relPath];
          if (bhash === undefined) continue;
          if (sha256Text(localNotes[relPath], rpc) === bhash) {
            const idx = toPushNew.indexOf(relPath);
            if (idx >= 0) toPushNew.splice(idx, 1);
            toDeleteLocal.push(relPath);
            deleteExpectedHashes[relPath] = bhash;
          }
        }
      }
    }

    let assetPlan = {
      local_assets: {},
      remote_assets: {},
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

    if (remoteInspected && !remoteError) {
      try {
        assetPlan = planNotebookAssets({
          cfg,
          nbRoot: effectiveNbRoot,
          baseUrl,
          baseMap,
          policy,
          scope,
          localNotes,
          remoteNotes,
          onlyPath,
          excludedSubdirs,
          isFirstSync,
          nbKey: nbKeyVal,
          deadlineMs,
        });
      } catch (exc) {
        remoteInspected = false;
        remoteError = tr(
          loc,
          `附件扫描失败: ${errorDetail(loc, exc)}`,
          `Attachment scan failed: ${errorDetail(loc, exc)}`
        );
      }
    }

    Object.assign(deleteExpectedHashes, assetPlan.delete_expected_hashes || {});

    const assetViewCopies = [];
    if (remoteInspected && !remoteError && policy === 'keep_both' && assetPlan.asset_conflicts.length > 0) {
      const plannedAssetCopyMap = Object.fromEntries(assetPlan.asset_conflicts);
      let checkLocalNote = null;
      let checkRemoteNote = null;
      if (onlyPath !== null && onlyPath !== undefined) {
        checkLocalNote = (cand) => local.readNotes({ onlyPath: cand, scope, nbRoot: effectiveNbRoot })[cand];
        checkRemoteNote = (cand) => {
          const candUrl = encodeWebdavRelUrl(baseUrl, cand);
          const { found, bytes } = davClient.getBytesWithEtag(candUrl, { cfg, deadlineMs });
          return found ? decodeNoteBytes(bytes, cand) : null;
        };
      }
      for (const relPath of synced) {
        const rtext = remoteNotes[relPath];
        if (rtext === undefined) continue;
        const rewritten = rewriteNoteAssetLinks(relPath, rtext, plannedAssetCopyMap);
        if (rewritten !== rtext) {
          const conflictRel = makeUniqueConflictPath(relPath, rewritten, {
            existingLocal: localNotes,
            existingRemote: remoteNotes,
            reserved: reservedConflictPaths,
            checkLocal: checkLocalNote,
            checkRemote: checkRemoteNote,
            callHost: rpc,
          });
          assetViewCopies.push([relPath, conflictRel, rewritten]);
        }
      }
    }

    const remoteMissing = [];
    const localMissing = [...toDeleteRemote];
    if (remoteInspected && !remoteError && !isFirstSync) {
      for (const p of [...toPushNew, ...toDeleteLocal]) {
        if (Object.hasOwn(baseMap, p) && !deletionHeld.has(p) && !remoteMissing.includes(p)) {
          remoteMissing.push(p);
        }
      }
      for (const p of toPullNew) {
        if (Object.hasOwn(baseMap, p) && !deletionHeld.has(p) && !localMissing.includes(p)) {
          localMissing.push(p);
        }
      }
    }

    const fpPayload = JSON.stringify({
      nb_key: nbKeyVal,
      protocol: 'webdav',
      subdir,
      policy,
      scope,
      local: Object.entries(localNotes).sort().map(([p, t]) => [p, sha256Text(t, rpc)]),
      remote: Object.entries(remoteNotes).sort().map(([p, t]) => [p, sha256Text(t, rpc)]),
      local_assets: Object.entries(assetPlan.local_assets).sort().map(([p, b]) => [p, sha256Bytes(b, rpc)]),
      remote_assets: Object.entries(assetPlan.remote_assets).sort().map(([p, b]) => [p, sha256Bytes(b, rpc)]),
      base: Object.entries(baseMap).sort(),
      del_remote: [...toDeleteRemote].sort(),
      del_local: [...toDeleteLocal].sort(),
      del_assets_remote: [...assetPlan.assets_to_delete_remote].sort(),
      del_assets_local: [...assetPlan.assets_to_delete_local].sort(),
    });

    return {
      protocol: 'webdav',
      cfg: { ...cfg },
      nb_root: effectiveNbRoot,
      nb_key: nbKeyVal,
      nb_label: nbLabelVal,
      subdir,
      excluded_subdirs: excludedSubdirs,
      target_display: sanitizeUrlForDisplay(baseUrl || rootBaseUrl || ''),
      base_url: baseUrl,
      meta_key: metaKey,
      base_map: baseMap,
      is_first_sync: isFirstSync,
      remote_nonempty_on_first_sync: remoteNonemptyOnFirstSync,
      local_notes: localNotes,
      remote_notes: remoteNotes,
      remote_etags: remoteEtags,
      remote_path_map: {},
      remote_inspected: remoteInspected,
      remote_error: remoteError,
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
      base_key_aliases: {},
      policy,
      scope,
      fingerprint: sha256Text(fpPayload, rpc),
    };
  };

  const planRiskMetrics = (plan) => {
    const rpc = getRpc();
    const baseMap = plan.base_map || {};
    const localNotes = plan.local_notes || {};
    const remoteNotes = plan.remote_notes || {};
    const nPullNew = plan.to_pull_new.length + (plan.assets_to_pull_new || []).length;
    const nPullTotal = plan.to_pull_overwrite.length + (plan.assets_to_pull_overwrite || []).length;
    const nPullConflict =
      plan.to_pull_overwrite.filter((p) => baseMap[p] !== sha256Text(localNotes[p], rpc)).length +
      (plan.assets_to_pull_overwrite || []).filter(([, isConf]) => Boolean(isConf)).length;
    const nPushConflict =
      plan.to_push_overwrite.filter((p) => baseMap[p] !== sha256Text(remoteNotes[p], rpc)).length +
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
  };

  const assessDangerousChanges = (plan, cfg, nbLabelVal = '') => {
    if (!plan.remote_inspected) return [];
    const items = [];
    const policy = plan.policy || cfg.conflict_policy || 'keep_both';
    const m = planRiskMetrics(plan);

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
  };

  const assessBatchDangerousChanges = (batch, cfg) => {
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
      const nbItems = assessDangerousChanges(plan, cfg, nbLbl);
      for (const it of nbItems) {
        if (it.kind === 'delete_guard') hasDeleteGuard = true;
        else if (it.kind === 'bulk_pull') hasBulkPull = true;
        else if (it.kind === 'pull_conflict') hasPullConflict = true;
        else if (it.kind === 'push_conflict') hasPushConflict = true;
        reasonItems.push(it);
      }
      if (plan.remote_inspected) {
        const m = planRiskMetrics(plan);
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
  };

  const buildPendingConfirm = (batch, reasonItems, { onlyPath = null, onlyNbRoot = null } = {}) => {
    const rpc = getRpc();
    const loc = getLocale();
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
      for (const p of plan.to_pull_overwrite) {
        addSample(baseMap[p] !== sha256Text(localNotes[p], rpc) ? 'pull_ow' : 'pull_upd', `${prefix}${p}`);
      }
      for (const p of plan.to_push_overwrite) {
        addSample(baseMap[p] !== sha256Text(remoteNotes[p], rpc) ? 'push_ow' : 'push_upd', `${prefix}${p}`);
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
      protocol: 'webdav',
      target_display: sanitizeUrlForDisplay(batch.target_display),
      reason_items: reasonItems.slice(0, 30),
      reasons: reasonItems.slice(0, 30).map((r) => formatReasonItem(loc, r, DELETE_GUARD_THRESHOLD)),
      sample_items: sampleItems,
      total_samples: totalSamples,
      only_path: onlyPath,
      only_nb_root: onlyNbRoot,
    };
  };

  const applyNotebookPlan = (plan, { progressState = null, deadlineMs = 0 } = {}) => {
    const rpc = getRpc();
    const loc = getLocale();
    const state = configStore ? configStore.state : { logs: [], syncMeta: {} };
    const cfg = plan.cfg;
    const nbRoot = plan.nb_root;
    const nbKeyVal = plan.nb_key;
    const subdir = plan.subdir || '';
    const baseMap = { ...(plan.base_map || {}) };
    const localNotes = plan.local_notes || {};
    const remoteNotes = plan.remote_notes || {};
    const remoteEtags = plan.remote_etags || {};
    const localAssets = plan.local_assets || {};
    const remoteAssets = plan.remote_assets || {};
    const remoteAssetEtags = plan.remote_asset_etags || {};
    const baseUrl = plan.base_url;

    const rootUrl = webdavRootUrl(cfg);
    const subDir = resolveWebdavDir(cfg).replace(/^\/+|\/+$/g, '');
    const fullSub = [subDir, subdir.replace(/^\/+|\/+$/g, '')].filter(Boolean).join('/');
    if (fullSub) {
      davClient.ensureDir(rootUrl, fullSub, cfg, deadlineMs);
    }

    const writeRemoteNote = (rel, text, { expectedHash = null, createOnly = false } = {}) => {
      davClient.putText(baseUrl, rel, text, {
        cfg,
        expectedHash,
        expectedEtag: remoteEtags[rel],
        createOnly,
        deadlineMs,
      });
    };

    const writeRemoteAsset = (rel, data, { expectedHash = null, createOnly = false } = {}) => {
      davClient.putBytes(baseUrl, rel, data, {
        cfg,
        expectedHash,
        expectedEtag: remoteAssetEtags[rel],
        createOnly,
        deadlineMs,
      });
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
          channel: 'webdav',
          done: progressState.done,
          total: progressState.total,
          label: tr(loc, '同步中', 'Syncing'),
          tone: 'accent',
          running: true,
        });
      }
    };

    try {
      // 1. Sync attachments.
      for (const rel of plan.assets_synced || []) {
        if (Object.hasOwn(localAssets, rel)) {
          baseMap[`asset:${rel}`] = sha256Bytes(localAssets[rel], rpc);
        }
        if (configStore) configStore.clearTombstone(nbKeyVal, `asset:${rel}`);
      }

      for (const rel of plan.assets_to_push_new || []) {
        const data = localAssets[rel];
        writeRemoteAsset(rel, data, { createOnly: true });
        baseMap[`asset:${rel}`] = sha256Bytes(data, rpc);
        if (configStore) configStore.clearTombstone(nbKeyVal, `asset:${rel}`);
        assetCount += 1;
        stepProgress();
      }

      for (const [rel] of plan.assets_to_push_overwrite || []) {
        const data = localAssets[rel];
        const expHash = Object.hasOwn(remoteAssets, rel) ? sha256Bytes(remoteAssets[rel], rpc) : null;
        writeRemoteAsset(rel, data, { expectedHash: expHash });
        baseMap[`asset:${rel}`] = sha256Bytes(data, rpc);
        if (configStore) configStore.clearTombstone(nbKeyVal, `asset:${rel}`);
        assetCount += 1;
        stepProgress();
      }

      for (const rel of plan.assets_to_pull_new || []) {
        const data = remoteAssets[rel];
        const rhash = sha256Bytes(data, rpc);
        if (!plan.is_first_sync && configStore && configStore.lookupTombstoneHash(nbKeyVal, `asset:${rel}`) === rhash) {
          stepProgress();
          continue;
        }
        local.writeAsset(nbRoot, rel, data, { createOnly: true });
        baseMap[`asset:${rel}`] = rhash;
        if (configStore) configStore.clearTombstone(nbKeyVal, `asset:${rel}`);
        assetCount += 1;
        stepProgress();
      }

      for (const [rel] of plan.assets_to_pull_overwrite || []) {
        const data = remoteAssets[rel];
        const expHash = Object.hasOwn(localAssets, rel) ? sha256Bytes(localAssets[rel], rpc) : null;
        local.writeAsset(nbRoot, rel, data, { expectedHash: expHash });
        baseMap[`asset:${rel}`] = sha256Bytes(data, rpc);
        if (configStore) configStore.clearTombstone(nbKeyVal, `asset:${rel}`);
        assetCount += 1;
        stepProgress();
      }

      const deferredAssetOverwrites = [];
      for (const [rel, copyRel] of plan.asset_conflicts || []) {
        const ldata = localAssets[rel];
        const rdata = remoteAssets[rel];
        const rhash = sha256Bytes(rdata, rpc);
        local.writeAsset(nbRoot, copyRel, rdata, { createOnly: true });
        writeRemoteAsset(copyRel, rdata, { createOnly: true });
        baseMap[`asset:${copyRel}`] = rhash;
        if (configStore) configStore.clearTombstone(nbKeyVal, `asset:${copyRel}`);
        assetCopyMap[rel] = copyRel;
        deferredAssetOverwrites.push([rel, ldata, rhash]);
        assetCount += 1;
        stepProgress();
      }

      if (assetCount > 0) {
        appendLog(state, tr(loc, `${prefix}同步 ${assetCount} 个附件`, `${prefix}Synced attachments: ${assetCount}`), '成功', {
          tone: 'success',
          logKey: 'assets_synced',
          logArgs: { prefix, count: assetCount },
        });
      }

      // 2. Sync notes.
      for (const relPath of plan.synced || []) {
        baseMap[relPath] = sha256Text(localNotes[relPath], rpc);
        if (configStore) configStore.clearTombstone(nbKeyVal, relPath);
      }

      for (const [relPath, conflictRel, rewrittenRemoteText] of plan.asset_view_copies || []) {
        local.writeNote(conflictRel, rewrittenRemoteText, { nbRoot });
        writeRemoteNote(conflictRel, rewrittenRemoteText, { createOnly: true });
        baseMap[conflictRel] = sha256Text(rewrittenRemoteText, rpc);
        if (configStore) configStore.clearTombstone(nbKeyVal, conflictRel);
        conflictCount += 1;
        appendLog(state, tr(loc, `冲突保留 ${prefix}${relPath}`, `Keep conflict copy: ${prefix}${relPath}`), '冲突副本', {
          tone: 'warning',
          tooltip: tr(loc, `已保留副本 ${conflictRel}`, `Saved a copy at ${conflictRel}`),
          logKey: 'conflict_copy',
          logArgs: { path: `${prefix}${relPath}`, copy: conflictRel },
        });
        stepProgress();
      }

      for (const relPath of plan.to_push_new || []) {
        const text = localNotes[relPath];
        writeRemoteNote(relPath, text, { createOnly: true });
        baseMap[relPath] = sha256Text(text, rpc);
        if (configStore) configStore.clearTombstone(nbKeyVal, relPath);
        pushed += 1;
        appendLog(state, tr(loc, `推送 ${prefix}${relPath}`, `Push ${prefix}${relPath}`), '成功', {
          tone: 'success',
          tooltip: tr(loc, '已推送到WebDAV', 'Pushed to WebDAV'),
          logKey: 'push_new',
          logArgs: { path: `${prefix}${relPath}` },
        });
        stepProgress();
      }

      for (const relPath of plan.to_push_overwrite || []) {
        const text = localNotes[relPath];
        const remoteHash = sha256Text(remoteNotes[relPath], rpc);
        const isConflict = baseMap[relPath] !== remoteHash;
        writeRemoteNote(relPath, text, { expectedHash: remoteHash });
        baseMap[relPath] = sha256Text(text, rpc);
        if (configStore) configStore.clearTombstone(nbKeyVal, relPath);
        pushed += 1;
        if (isConflict) {
          appendLog(state, tr(loc, `本地覆盖 ${prefix}${relPath}`, `Overwrite remote: ${prefix}${relPath}`), '成功', {
            tone: 'success',
            tooltip: tr(loc, '本地优先覆盖WebDAV', 'Local version took precedence on WebDAV'),
            logKey: 'push_overwrite',
            logArgs: { path: `${prefix}${relPath}` },
          });
        } else {
          appendLog(state, tr(loc, `更新 ${prefix}${relPath}`, `Update ${prefix}${relPath}`), '成功', {
            tone: 'success',
            tooltip: tr(loc, '已同步修改到WebDAV', 'Synced changes to WebDAV'),
            logKey: 'push_update',
            logArgs: { path: `${prefix}${relPath}` },
          });
        }
        stepProgress();
      }

      for (const relPath of plan.to_pull_new || []) {
        const origText = remoteNotes[relPath];
        const origHash = sha256Text(origText, rpc);
        if (!plan.is_first_sync && configStore && configStore.lookupTombstoneHash(nbKeyVal, relPath) === origHash) {
          stepProgress();
          continue;
        }
        const text = rewriteNoteAssetLinks(relPath, origText, assetCopyMap);
        local.writeNote(relPath, text, { nbRoot });
        if (text !== origText) {
          writeRemoteNote(relPath, text, { expectedHash: origHash });
        }
        baseMap[relPath] = sha256Text(text, rpc);
        if (configStore) configStore.clearTombstone(nbKeyVal, relPath);
        pulled += 1;
        appendLog(state, tr(loc, `拉取 ${prefix}${relPath}`, `Pull ${prefix}${relPath}`), '成功', {
          tone: 'success',
          tooltip: tr(loc, '已从WebDAV拉取', 'Pulled from WebDAV'),
          logKey: 'pull_new',
          logArgs: { path: `${prefix}${relPath}` },
        });
        stepProgress();
      }

      for (const relPath of plan.to_pull_overwrite || []) {
        const origText = remoteNotes[relPath];
        const text = rewriteNoteAssetLinks(relPath, origText, assetCopyMap);
        const localHash = sha256Text(localNotes[relPath], rpc);
        const isConflict = baseMap[relPath] !== localHash;
        local.writeNote(relPath, text, { nbRoot, expectedRevision: localHash });
        if (text !== origText) {
          writeRemoteNote(relPath, text, { expectedHash: sha256Text(origText, rpc) });
        }
        baseMap[relPath] = sha256Text(text, rpc);
        if (configStore) configStore.clearTombstone(nbKeyVal, relPath);
        pulled += 1;
        if (isConflict) {
          appendLog(state, tr(loc, `远端覆盖 ${prefix}${relPath}`, `Overwrite local: ${prefix}${relPath}`), '成功', {
            tone: 'success',
            tooltip: tr(loc, 'WebDAV优先更新本地', 'Version from WebDAV replaced the local copy'),
            logKey: 'pull_overwrite',
            logArgs: { path: `${prefix}${relPath}` },
          });
        } else {
          appendLog(state, tr(loc, `拉取更新 ${prefix}${relPath}`, `Pull update: ${prefix}${relPath}`), '成功', {
            tone: 'success',
            tooltip: tr(loc, '已从WebDAV拉取更新', 'Pulled update from WebDAV'),
            logKey: 'pull_update',
            logArgs: { path: `${prefix}${relPath}` },
          });
        }
        stepProgress();
      }

      for (const [relPath, conflictRel, remoteText] of plan.conflicts || []) {
        const localText = localNotes[relPath];
        const savedConflictText = rewriteNoteAssetLinks(conflictRel, remoteText, assetCopyMap);
        local.writeNote(conflictRel, savedConflictText, { nbRoot });
        writeRemoteNote(conflictRel, savedConflictText, { createOnly: true });
        writeRemoteNote(relPath, localText, { expectedHash: sha256Text(remoteText, rpc) });
        baseMap[relPath] = sha256Text(localText, rpc);
        baseMap[conflictRel] = sha256Text(savedConflictText, rpc);
        if (configStore) {
          configStore.clearTombstone(nbKeyVal, relPath);
          configStore.clearTombstone(nbKeyVal, conflictRel);
        }
        conflictCount += 1;
        appendLog(state, tr(loc, `冲突保留 ${prefix}${relPath}`, `Keep conflict copy: ${prefix}${relPath}`), '冲突副本', {
          tone: 'warning',
          tooltip: tr(loc, `已保留副本 ${conflictRel}`, `Saved a copy at ${conflictRel}`),
          logKey: 'conflict_copy',
          logArgs: { path: `${prefix}${relPath}`, copy: conflictRel },
        });
        stepProgress();
      }

      // 3. Complete deferred remote original-asset overwrites.
      for (const [rel, ldata, rhash] of deferredAssetOverwrites) {
        writeRemoteAsset(rel, ldata, { expectedHash: rhash });
        baseMap[`asset:${rel}`] = sha256Bytes(ldata, rpc);
      }

      // 4. Propagate recoverable deletions.
      let deletedCount = 0;
      const deletions = [
        ...(plan.to_delete_remote || []).map((rel) => ['remote', rel, false]),
        ...(plan.assets_to_delete_remote || []).map((rel) => ['remote', rel, true]),
        ...(plan.to_delete_local || []).map((rel) => ['local', rel, false]),
        ...(plan.assets_to_delete_local || []).map((rel) => ['local', rel, true]),
      ];
      const deleteExpectedHashes = plan.delete_expected_hashes || {};

      for (const [side, rel, isAsset] of deletions) {
        const key = isAsset ? `asset:${rel}` : rel;
        const expect =
          deleteExpectedHashes[key] ||
          baseMap[key] ||
          (configStore ? configStore.lookupTombstoneHash(nbKeyVal, key) : null);
        let outcome = 'failed';
        let errText = '';
        try {
          if (side === 'remote') {
            const matchesFn = isAsset
              ? (raw) => sha256Bytes(raw, rpc) === expect
              : (raw) => sha256Text(decodeNoteBytes(raw, rel), rpc) === expect;
            outcome = davClient.trashFile(baseUrl, rel, matchesFn, cfg, deadlineMs);
          } else {
            const revision = isAsset
              ? sha256Bytes(localAssets[rel], rpc)
              : sha256Text(localNotes[rel], rpc);
            outcome = local.trashFile(rel, revision, { nbRoot });
          }
        } catch (exc) {
          outcome = 'failed';
          errText = errorDetail(loc, exc);
        }

        const shown = `${prefix}${rel}`;
        const where = side === 'remote' ? 'WebDAV' : tr(loc, '本地', 'local');
        if (outcome === 'deleted' || outcome === 'missing') {
          delete baseMap[key];
          if (expect && configStore) {
            configStore.recordTombstone(nbKeyVal, key, expect);
          }
        }
        if (outcome === 'deleted') {
          deletedCount += 1;
          appendLog(state, tr(loc, `删除 ${shown}`, `Delete ${shown}`), '成功', {
            tone: 'success',
            tooltip: tr(loc, `已在${where}删除（可找回）`, `Deleted from ${where} (recoverable)`),
            logKey: `delete_${side}`,
            logArgs: { path: shown },
          });
        } else if (outcome === 'changed') {
          appendLog(state, tr(loc, `保留 ${shown}`, `Keep ${shown}`), '无变更', {
            tone: 'warning',
            tooltip: tr(loc, `${where}内容已变化，未删除`, `Changed on ${where}; not deleted`),
            logKey: 'delete_skipped',
            logArgs: { path: shown, side },
          });
        } else if (outcome === 'unsupported') {
          appendLog(
            state,
            tr(loc, '远端删除未同步到本地', 'Remote deletions not applied locally'),
            '待确认',
            {
              tone: 'warning',
              tooltip: tr(loc, '请升级 Block 后重试', 'Update Block and sync again'),
              logKey: 'delete_unsupported',
            }
          );
        } else if (outcome === 'failed') {
          appendLog(state, tr(loc, `删除失败 ${shown}`, `Delete failed: ${shown}`), '失败', {
            tone: 'danger',
            tooltip: errText,
            logKey: 'delete_failed',
            logArgs: { path: shown, error: errText },
          });
        }
        stepProgress();
      }
      plan._deleted_count = deletedCount;
    } catch (exc) {
      if (configStore) {
        configStore.state.syncMeta[plan.meta_key] = baseMap;
      }
      throw exc;
    }

    return { pushed, pulled, conflictCount, assetCount, baseMap };
  };

  const computeBatchPlan = ({
    cfg,
    notebooks,
    onlyPath = null,
    inspectRemote = true,
    forceRefresh = false,
    deadlineMs = 0,
  }) => {
    const rpc = getRpc();
    const loc = getLocale();
    const effectiveCfg = inspectRemote ? resolveCredentials(rpc, cfg, loc) : cfg;
    const rootUrl = webdavBaseUrl(effectiveCfg) || 'unconfigured';
    const targetBases = [rootUrl];

    const { layoutKey, bindings, reservedSubdirs } = computeNotebookSubdirMap({
      notebooks,
      protocol: 'webdav',
      targetBases,
      syncMeta: configStore ? configStore.state.syncMeta : {},
      notebookConfigs: configStore ? configStore.state.notebookConfigs : {},
      knownNotebooks: configStore ? configStore.state.knownNotebooks : [],
      callHost: rpc,
      locale: loc,
      syncTargetBaseFn: (c) => webdavBaseUrl(c) || 'unconfigured',
    });

    for (let i = 0; i < notebooks.length; i += 1) {
      for (let j = 0; j < i; j += 1) {
        if (pathsOverlap(notebooks[j], notebooks[i])) {
          const prevLbl = notebookLabel(notebooks[j], loc);
          const curLbl = notebookLabel(notebooks[i], loc);
          return {
            cfg: { ...effectiveCfg },
            protocol: 'webdav',
            target_display: sanitizeUrlForDisplay(rootUrl),
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

    const plans = [];
    for (const nb of notebooks) {
      const sub = bindings[nb] || '';
      const plan = computeSyncPlan({
        cfg: effectiveCfg,
        onlyPath,
        inspectRemote,
        forceRefresh,
        nbRoot: nb,
        subdir: sub,
        excludedSubdirs: sub ? new Set() : reservedSubdirs,
        deadlineMs,
      });
      if (plan.remote_error) {
        return {
          cfg: { ...effectiveCfg },
          protocol: 'webdav',
          target_display: sanitizeUrlForDisplay(rootUrl),
          plans,
          remote_error: plan.remote_error,
          fingerprint: '',
        };
      }
      plans.push(plan);
    }

    const fp = sha256Text(
      JSON.stringify({ plans: plans.map((p) => p.fingerprint) }),
      rpc
    );

    return {
      cfg: { ...effectiveCfg },
      protocol: 'webdav',
      target_display: sanitizeUrlForDisplay(rootUrl),
      layout_key: layoutKey,
      bindings,
      plans,
      remote_error: null,
      fingerprint: fp,
    };
  };

  const executeBatchPlan = (batch, { reportProgress = false, deadlineMs = 0 } = {}) => {
    const loc = getLocale();
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
      const res = applyNotebookPlan(plan, { progressState, deadlineMs });
      totalPushed += res.pushed;
      totalPulled += res.pulled;
      totalConflicts += res.conflictCount;
      totalAssets += res.assetCount;
      totalDeleted += Number(plan._deleted_count || 0);
      const risks = planRiskMetrics(plan);
      reportedConflicts += risks.conflicts + risks.pull_conflict + risks.push_conflict;
      if (configStore) {
        configStore.state.syncMeta[plan.meta_key] = res.baseMap;
      }
    }

    if (configStore) {
      const initMap = { ...(configStore.state.syncMeta[INITIALIZED_META_KEY] || {}) };
      for (const plan of batch.plans) {
        initMap[plan.meta_key] = true;
      }
      configStore.state.syncMeta[INITIALIZED_META_KEY] = initMap;
      configStore.state.stats.total_synced += totalPushed + totalPulled + totalConflicts;
      configStore.state.stats.last_sync = nowHms();
    }

    previewCache.clear();

    const totalNotes = totalPushed + totalPulled + totalConflicts;
    if (totalNotes === 0 && totalAssets === 0 && totalDeleted === 0) {
      return {
        status: '无变更',
        summary: tr(loc, '已是最新', 'Up to date'),
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

    return {
      status: '成功',
      summary,
      pushed: totalPushed,
      pulled: totalPulled,
      conflicts: reportedConflicts,
      assets: totalAssets,
      deleted: totalDeleted,
    };
  };

  const validateWebdavTarget = (cfg, notebooks) => {
    const loc = getLocale();
    if (!notebooks || notebooks.length === 0) {
      return tr(loc, '请至少选择一个笔记本', 'Select at least one notebook');
    }
    const rawUrl = String((cfg && cfg.webdav_url) || '').trim();
    if (rawUrl && hasEmbeddedUrlCredentials(rawUrl, false)) {
      return tr(
        loc,
        '请不要在 WebDAV 地址中内嵌账号密码，改用下方认证字段填写',
        'Do not embed credentials in the WebDAV URL; use the username and password fields instead'
      );
    }
    if (!webdavBaseUrl(cfg)) {
      return tr(loc, '请填写有效的 WebDAV 地址', 'Enter a valid WebDAV address');
    }
    return '';
  };

  const syncWebdav = ({
    cfg = null,
    notebooks = null,
    onlyPath = null,
    onlyNbRoot = null,
    confirmed = false,
    approvedBatch = null,
    reportProgress = false,
    deadlineMs = 0,
  } = {}) => {
    const loc = getLocale();
    const effectiveCfg = cfg || (configStore ? configStore.state.config : {});
    let targetNotebooks = notebooks;
    if (!targetNotebooks && configStore) {
      targetNotebooks = configStore.selectedNotebooks(effectiveCfg);
    }
    if (onlyNbRoot && targetNotebooks) {
      const normOnly = notebookKey(onlyNbRoot, '', configStore ? configStore.state.homeDir : '');
      targetNotebooks = targetNotebooks.filter((nb) => nb === normOnly);
    }

    const targetErr = validateWebdavTarget(effectiveCfg, targetNotebooks);
    if (targetErr) {
      return { outcome: 'error', error: targetErr };
    }

    const batch =
      approvedBatch ||
      computeBatchPlan({
        cfg: effectiveCfg,
        notebooks: targetNotebooks,
        onlyPath,
        inspectRemote: true,
        forceRefresh: true,
        deadlineMs,
      });

    if (batch.remote_error) {
      return { outcome: 'error', error: batch.remote_error };
    }

    if (!confirmed) {
      const reasonItems = assessBatchDangerousChanges(batch, effectiveCfg);
      if (reasonItems.length > 0) {
        const pending = buildPendingConfirm(batch, reasonItems, {
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

    const result = executeBatchPlan(batch, { reportProgress, deadlineMs });
    if (configStore && confirmed) {
      configStore.clearPendingConfirm('webdav');
    }
    return {
      outcome: 'synced',
      ...result,
      batch,
    };
  };

  return {
    davClient,
    localAdapter: local,
    fetchWebdavNotes,
    remoteHasAnyContent,
    resolveConflictPair,
    planNotebookAssets,
    computeSyncPlan,
    planRiskMetrics,
    assessDangerousChanges,
    assessBatchDangerousChanges,
    buildPendingConfirm,
    applyNotebookPlan,
    computeBatchPlan,
    executeBatchPlan,
    syncWebdav,
    clearPreviewCache: () => previewCache.clear(),
  };
}
