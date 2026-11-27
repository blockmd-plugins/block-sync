/**
 * Entry point and JSON-RPC 2.0 host protocol bridge for block-sync.
 * Pure ES2023 module targeting QuickJS-NG Wasm runtime (zero Node built-ins).
 */

import { serve, callHost, notifyHost } from '/runtime/block-sdk.js';
import {
  CHINESE_TEXT_RE,
  LOG_STATUS_EN,
  tr,
  hasChineseText,
  isEnglishLocale,
  normalizeLocale,
  protocolLabel,
  localizeError,
  errorDetail,
  normalizeLog,
  formatReasonItem,
  formatShortSyncMetric,
  formatSkippedCount,
  formatSyncFailureLabel,
  formatSkippedDetails,
} from './i18n.js';
import {
  nowHms,
  normAbsPath,
  isSafeRelPath,
  isSafeRelMd,
  foldSyncPath,
  matchesScope,
  pathsOverlap,
  sanitizeUrlForDisplay,
  sha256Text,
  classifySyncError,
} from './utils.js';
import {
  VALID_PROTOCOLS,
  PROTOCOL_ENABLED_KEYS,
  MAX_LOG_ENTRIES,
  MAX_HOST_LOG_QUEUE,
  LAYOUTS_META_KEY,
  INITIALIZED_META_KEY,
  TOMBSTONES_META_KEY,
  storageGet,
  storageSet,
  cfgForProtocol,
  protocolHasInput,
  protocolEnabled,
  configMatchesSaved,
  connConfigSignature,
  changedProtocols,
  resolveMirrorDir,
  credentialTarget,
  resolveCredentials,
  createConfigStore,
} from './config.js';
import {
  fsStat,
  dirIsCaseInsensitive,
  dirIsNormalizationInsensitive,
  pathsCollapse,
  clearRecoveryDirCache,
  migrateLegacyRecoveryDirs,
  cleanupRecoveryDirs,
  createLocalMirrorSyncEngine,
} from './local_mirror.js';
import { createWebDAVSyncEngine } from './webdav.js';
import {
  isRemoteGitUrl,
  resolveLocalGitDir,
  hasGitMarker,
  runGit,
  createGitSyncEngine,
} from './git_sync.js';
import {
  targetError,
  protocolError,
  configuredProtocols,
  targetDisplay,
  entryMatchesProtocol,
  getLastResult,
  getProtocolResult,
  buildSettingsPage,
} from './ui.js';

const SYNC_INTERVAL_EVENT = 'scheduler.tick';
const LEGACY_SYNC_INTERVAL_EVENT = 'plugin.sync_interval';
const BG_ERROR_KEY = 'sync_state';
const AUTO_SYNC_JOB_ID = 'auto-sync';
const LEGACY_IGNORED_DIRS = ['.block-sync-replaced', '.block-sync-recovery'];

class SyncStateError extends Error {
  constructor(message, notified = false) {
    super(message);
    this.name = 'SyncStateError';
    this.notified = Boolean(notified);
  }
}

class SyncReportedError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SyncReportedError';
  }
}

function firstLineSummary(msg, maxLen = 80) {
  const firstLine = String(msg ?? '')
    .split(/\r?\n/, 1)[0]
    .trim();
  if (!firstLine) return '';
  if (firstLine.length <= maxLen) return firstLine;
  return `${firstLine.slice(0, maxLen - 3)}...`;
}

function isMethodUnsupportedError(err) {
  if (!err) return false;
  if (typeof err === 'object' && err.code === -32601) return true;
  const msg = String(err && err.message ? err.message : err).toLowerCase();
  return (
    msg.includes('unknown host method') ||
    msg.includes('method not found') ||
    msg.includes('-32601')
  );
}

function splitItemKey(itemKey) {
  const s = String(itemKey || '');
  if (s.startsWith('asset:')) {
    return ['asset:', s.slice(6)];
  }
  return ['', s];
}

function parseHmsSeconds(timeStr) {
  const m = String(timeStr || '').trim().match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
  if (!m) return null;
  return (
    Number.parseInt(m[1], 10) * 3600 +
    Number.parseInt(m[2], 10) * 60 +
    Number.parseInt(m[3] || '0', 10)
  );
}

function inferHomeDir(params) {
  const explicit = String((params && params.home_dir) || '').trim();
  if (explicit) return explicit;
  const dl = String((params && params.downloads_dir) || '').trim().replace(/\\/g, '/').replace(/\/+$/, '');
  if (dl && dl.endsWith('/Downloads') && dl.length > '/Downloads'.length) {
    return dl.slice(0, -'/Downloads'.length);
  }
  return '';
}

function createSyncController() {
  let pluginId = 'block-sync';
  let dataDir = '';
  let downloadsDir = '';
  let homeDir = '';
  let notebookRoot = '';
  let locale = 'zh';

  let kvTooltip = false;
  let supportsChecklist = false;
  let supportsAddFolder = false;
  let supportsFormLayout = false;
  let supportsMultiNotebook = true;
  let supportsLogTimeline = false;
  let supportsActionProgress = false;
  let supportsProgressBar = false;
  let supportsSegmentedStatus = false;
  let supportsFormAutosave = false;
  let supportsButtonLink = false;
  let supportsSystem = false;
  let supportsToastBanner = false;
  let supportsOpenSettings = false;

  let configStore = null;
  let engines = null;

  let lastStatus = '';
  let lastSyncOutcome = 'skipped';
  let lastSyncedNotebooks = [];
  let logProtocol = '';
  let hostLogScope = ['', ''];
  let hostLogQueue = [];
  let hostLogUnsupported = false;
  const queuedLogEntries = new WeakSet();

  let schedulerUnsupported = false;
  let bgErrorUnsupported = false;

  let resultNotice = null;
  let resultNotified = false;
  let backgroundNoticeDeadlineMs = 0;
  let nextSystemNotebook = '';
  const intervalSyncedAt = new Map();
  const protocolNextAllowedMs = new Map();
  const legacyNoticeReceipts = new Map();

  const getLocale = () => (configStore ? configStore.state.locale : locale);
  const t = (zh, en) => tr(getLocale(), zh, en);

  const rebuildEngines = () => {
    const loc = getLocale();
    engines = {
      localMirror: createLocalMirrorSyncEngine({
        callHost,
        notifyHost,
        configStore,
        locale: loc,
        dataDir,
      }),
      webdav: createWebDAVSyncEngine({
        callHost,
        notifyHost,
        configStore,
        locale: loc,
        dataDir,
      }),
      git: createGitSyncEngine({
        callHost,
        notifyHost,
        configStore,
        locale: loc,
        dataDir,
      }),
    };
  };

  const uiContext = () => ({
    callHost,
    configStore,
    locale: getLocale(),
    dataDir,
    homeDir,
    downloadsDir,
    notebookRoot,
    kvTooltip,
    supportsChecklist,
    supportsAddFolder,
    supportsFormLayout,
    supportsMultiNotebook,
    supportsLogTimeline,
    supportsProgressBar,
    supportsSegmentedStatus,
    supportsFormAutosave,
    supportsButtonLink,
    supportsSystem,
    lastStatus,
  });

  const emitProgress = ({
    done = null,
    total = null,
    progress = null,
    label = null,
    channel = null,
    tone = null,
    running = null,
  } = {}) => {
    if (!supportsActionProgress) return;
    if (channel !== null && !supportsProgressBar) return;
    const params = {};
    if (channel) params.channel = String(channel);
    if (done !== null && done !== undefined) params.done = Number.parseInt(done, 10) || 0;
    if (total !== null && total !== undefined) params.total = Number.parseInt(total, 10) || 0;
    if (progress !== null && progress !== undefined) params.progress = Number(progress);
    if (label) params.label = String(label).slice(0, 32);
    if (tone && supportsProgressBar) params.tone = String(tone);
    if (running !== null && running !== undefined && supportsProgressBar) {
      params.running = Boolean(running);
    }
    if (Object.keys(params).length === 0) return;
    try {
      notifyHost('host.action.progress', params);
    } catch (_err) {
      // Progress reporting is best-effort.
    }
  };

  const queueHostLogEntry = (raw, protoOverride = '') => {
    if (hostLogUnsupported || hostLogQueue.length >= MAX_HOST_LOG_QUEUE) return;
    const args = raw && raw.log_args && typeof raw.log_args === 'object' ? raw.log_args : {};
    const [nbRoot, prefix] = hostLogScope;
    let path = String(args.path || '');
    if (prefix && path.startsWith(prefix)) {
      path = path.slice(prefix.length);
    }
    const tone = String((raw && raw.tone) || '');
    const level = tone === 'danger' ? 'error' : tone === 'warning' ? 'warn' : 'info';
    let detail = String((raw && raw.status) || '');
    const extra = String(args.error || (raw && raw.tooltip) || '');
    if (extra && !path) {
      detail = `${detail} ${extra}`.trim();
    } else if (args.error) {
      detail = `${detail} ${args.error}`.trim();
    }
    const proto = String(
      protoOverride || (raw && raw.protocol_id) || args.protocol || logProtocol || ''
    ).trim();
    hostLogQueue.push({
      level,
      event: String((raw && (raw.log_key || raw.title)) || ''),
      notebook_root: path ? nbRoot : '',
      path,
      protocol: VALID_PROTOCOLS.includes(proto) ? proto : '',
      detail,
    });
  };

  const appendLog = (title, status, { tone = '', tooltip = '', logKey = null, logArgs = null } = {}) => {
    if (!configStore) return;
    const raw = {
      title: String(title || t('同步任务', 'Sync task')).trim() || t('同步任务', 'Sync task'),
      status: String(status || '成功').trim() || '成功',
      time: nowHms(),
      tone,
      tooltip,
    };
    if (logKey) {
      raw.log_key = logKey;
      raw.log_args = { ...(logArgs || {}) };
    }
    const proto = String((logArgs && logArgs.protocol) || logProtocol || '').trim();
    if (VALID_PROTOCOLS.includes(proto)) {
      raw.protocol_id = proto;
    }
    const entry = normalizeLog(raw);
    if (isEnglishLocale(getLocale())) {
      entry.locale = 'en';
    }
    queuedLogEntries.add(entry);
    configStore.state.logs.unshift(entry);
    if (configStore.state.logs.length > MAX_LOG_ENTRIES) {
      configStore.state.logs.length = MAX_LOG_ENTRIES;
    }
    queueHostLogEntry(raw, proto);
  };

  const harvestEngineLogs = () => {
    if (!configStore || hostLogUnsupported) return;
    const fresh = [];
    for (const entry of configStore.state.logs) {
      if (!entry || typeof entry !== 'object') continue;
      if (queuedLogEntries.has(entry)) break;
      queuedLogEntries.add(entry);
      fresh.push(entry);
    }
    for (let i = fresh.length - 1; i >= 0; i -= 1) {
      queueHostLogEntry(fresh[i]);
    }
  };

  const markExistingLogsQueued = () => {
    if (!configStore) return;
    for (const entry of configStore.state.logs) {
      if (entry && typeof entry === 'object') {
        queuedLogEntries.add(entry);
      }
    }
  };

  const flushHostLog = () => {
    harvestEngineLogs();
    if (hostLogQueue.length === 0) return;
    const entries = hostLogQueue;
    hostLogQueue = [];
    if (hostLogUnsupported) return;
    try {
      callHost('host.log', { entries });
    } catch (err) {
      if (isMethodUnsupportedError(err)) {
        hostLogUnsupported = true;
      }
    }
  };

  const setBackgroundError = (label, detail, { severity = 'danger', retryAction = 'sync_now' } = {}) => {
    if (bgErrorUnsupported) return;
    const cleanLabel = String(label || '').trim().slice(0, 120);
    if (!cleanLabel) return;
    const cleanDetail = String(detail || '').trim().slice(0, 2000);
    const retryLabel = t('重试同步', 'Retry Sync').slice(0, 64);
    try {
      callHost('host.ui.set_background_error', {
        key: BG_ERROR_KEY,
        label: cleanLabel,
        detail: cleanDetail,
        retry_action: retryAction,
        retry_label: retryLabel,
        retry_payload: {},
        severity,
      });
    } catch (err) {
      if (isMethodUnsupportedError(err)) {
        bgErrorUnsupported = true;
      }
    }
  };

  const clearBackgroundError = () => {
    if (bgErrorUnsupported) return;
    try {
      callHost('host.ui.clear_background_error', { key: BG_ERROR_KEY });
    } catch (err) {
      if (isMethodUnsupportedError(err)) {
        bgErrorUnsupported = true;
      }
    }
  };

  const protocolNeedsNetwork = (protocol, cfg) => {
    if (protocol === 'webdav') return true;
    if (protocol !== 'git') return false;
    const gitTarget = String((cfg && cfg.git_remote) || '').trim();
    const gitUrls = [gitTarget];
    if (gitTarget && !isRemoteGitUrl(gitTarget)) {
      let repo = '';
      try {
        repo = resolveLocalGitDir(callHost, cfg, {
          dataDir,
          nbRoot: notebookRoot,
          homeDir,
          locale: getLocale(),
        });
      } catch (_err) {
        repo = '';
      }
      if (repo && hasGitMarker(callHost, repo)) {
        try {
          const remotesRes = runGit(callHost, ['remote'], {
            cwd: repo,
            cfg,
            timeoutMs: 1000,
            locale: getLocale(),
          });
          if (remotesRes.returncode === 0) {
            const remotes = remotesRes.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
            if (remotes.length > 0) {
              const name = remotes.includes('origin') ? 'origin' : remotes[0];
              for (const flags of [[], ['--push']]) {
                const urlsRes = runGit(callHost, ['remote', 'get-url', ...flags, '--all', name], {
                  cwd: repo,
                  cfg,
                  timeoutMs: 1000,
                  locale: getLocale(),
                });
                if (urlsRes.returncode === 0) {
                  for (const line of urlsRes.stdout.split(/\r?\n/)) {
                    if (line.trim()) gitUrls.push(line.trim());
                  }
                }
              }
            }
          }
        } catch (_err) {
          // Ignore local git inspection errors when checking network dependency.
        }
      }
    }
    return gitUrls.some(
      (url) =>
        url &&
        (url.startsWith('\\\\') ||
          (!url.toLowerCase().startsWith('file://') &&
            !/^[A-Za-z]:/.test(url) &&
            /^(?:[^/@:\\]+@)?[^/\\:]+:/.test(url)))
    );
  };

  const syncAutoSyncScheduler = () => {
    if (schedulerUnsupported || !configStore) return;
    const cfg = configStore.state.config;
    const activeProtos = configuredProtocols(cfg, uiContext());
    const selected = configStore.selectedNotebooks(cfg);
    const shouldRegister =
      Boolean(cfg.auto_sync) &&
      activeProtos.length > 0 &&
      (!supportsMultiNotebook || selected.length > 0);
    try {
      if (shouldRegister) {
        const intervalMin = Number.parseInt(cfg.sync_interval || '5', 10) || 5;
        const intervalSec = Math.max(60, intervalMin * 60);
        const requireNetwork = activeProtos.every((p) => protocolNeedsNetwork(p, cfg));
        callHost('host.scheduler.register', {
          id: AUTO_SYNC_JOB_ID,
          interval_sec: intervalSec,
          event: SYNC_INTERVAL_EVENT,
          require_network: requireNetwork,
          run_on_wake: true,
          run_on_network_restore: true,
          run_on_focus: true,
        });
      } else {
        callHost('host.scheduler.unregister', { id: AUTO_SYNC_JOB_ID });
      }
    } catch (err) {
      if (isMethodUnsupportedError(err)) {
        schedulerUnsupported = true;
      }
    }
  };

  const saveConfig = (nextCfg = null, { forget = null, clearPending = false } = {}) => {
    const res = configStore.saveConfig(nextCfg, { forget, clearPending });
    if (!configStore.state.supportsSystem && clearPending) {
      const clearProtos = clearPending === true ? VALID_PROTOCOLS : [...clearPending];
      for (const proto of clearProtos) {
        configStore.clearPendingConfirm(proto);
      }
      storageSet(callHost, 'pending_confirms', configStore.state.pendingConfirms);
      storageSet(callHost, 'pending_confirm', null);
      configStore.state.savedPendingConfirms = { ...configStore.state.pendingConfirms };
    }
    syncAutoSyncScheduler();
    return res;
  };

  const noticeOrder = (notice) => {
    if (!notice || typeof notice !== 'object') return 0;
    const order = notice.order;
    return typeof order === 'number' && Number.isInteger(order) && order >= 0 && order < 2 ** 52
      ? order
      : 0;
  };

  const isPauseNotice = (notice) => {
    if (!notice || typeof notice !== 'object') return false;
    if (notice.status === '待确认') return true;
    const params = notice.params;
    return Boolean(
      params &&
        typeof params === 'object' &&
        (params.title === '同步等待确认' || params.title === 'Sync needs confirmation')
    );
  };

  const resultNoticeParams = (status, conflicts, noticeKey = '', extra = null) => {
    let title;
    let body;
    let tone;
    if (status === '离线提醒') {
      const offlineMin = Math.max(1, Number.parseInt((extra && extra.offlineMin) || 1, 10) || 1);
      const reasonLine = firstLineSummary(localizeError(getLocale(), extra && extra.reason), 80);
      const suffix = t('网络恢复后会自动同步。', 'Will sync when back online.');
      title = t(`同步已离线 ${offlineMin} 分钟`, `Sync offline for ${offlineMin} min`);
      body = reasonLine ? `${reasonLine} ${suffix}` : suffix;
      tone = 'warning';
    } else if (status === '失败') {
      title = t('同步失败', 'Sync failed');
      const reasonLine = firstLineSummary(localizeError(getLocale(), extra && extra.reason), 80);
      body = reasonLine || t('同步失败', 'Sync failed');
      tone = 'error';
    } else if (status === '状态未保存') {
      title = t('同步状态未保存', 'Sync state could not be saved');
      body = t('打开 Block 同步设置查看详情。', 'Open Block Sync settings for details.');
      tone = 'error';
    } else if (conflicts) {
      title = t('同步发现冲突', 'Sync conflicts detected');
      body = t(
        `同步处理了 ${conflicts} 处冲突。打开同步设置查看结果。`,
        `Sync handled ${conflicts} conflicts. Open Sync settings for details.`
      );
      tone = 'warning';
    } else if (status === '待确认') {
      title = t('同步等待确认', 'Sync needs confirmation');
      body = t(
        '同步已暂停。打开 Block 同步设置查看待确认的变更。',
        'Sync is paused. Open Block Sync settings to review the changes.'
      );
      tone = 'warning';
    } else {
      return null;
    }

    const params = { title, body, tone };
    if (status === '待确认') {
      const pc = configStore ? configStore.state.pendingConfirm : null;
      const fp = (pc && pc.fingerprint) || noticeKey;
      if (fp) params.dedup_key = fp;
    } else if (noticeKey) {
      params.dedup_key = noticeKey;
    }
    if (notebookRoot && configStore && configStore.resultKey() !== '__multi__') {
      const rootKey = configStore.notebookKey();
      const matched = configStore.state.knownNotebooks.find(
        (nb) => configStore.notebookKey(nb.path) === rootKey
      );
      params.notebook_root = matched ? matched.path : notebookRoot;
    }
    return params;
  };

  const sendInAppToast = (params) => {
    if (!supportsToastBanner || !params) return;
    const toastParams = {
      message: params.title,
      body: params.body || '',
      tone: params.tone || 'info',
    };
    if (supportsOpenSettings) {
      toastParams.action = {
        id: 'open_sync_settings',
        label: t('查看', 'View'),
      };
    }
    try {
      callHost('host.ui.toast', toastParams);
    } catch (_err) {
      // Non-fatal UI toast failure.
    }
  };

  const deliverResultNotice = (params) => {
    const receiptKey = JSON.stringify([
      params.notebook_root || '',
      params.dedup_key || '',
      params.title || '',
      params.body || '',
    ]);
    if (legacyNoticeReceipts.has(receiptKey)) {
      return [false, true];
    }
    let result;
    try {
      result = callHost('host.system.notify', params);
    } catch (_err) {
      return [false, false];
    }
    if (result && result.delivered === true) {
      return [true, false];
    }
    if (result && result.queued === true) {
      return [false, true];
    }
    if (result && result.ok === true && !Object.hasOwn(result, 'delivered')) {
      if (legacyNoticeReceipts.size >= 32) {
        const firstKey = legacyNoticeReceipts.keys().next().value;
        if (firstKey !== undefined) legacyNoticeReceipts.delete(firstKey);
      }
      legacyNoticeReceipts.set(receiptKey, true);
      return [false, true];
    }
    return [false, false];
  };

  const sendResultNotice = () => {
    const notice = resultNotice;
    resultNotice = null;
    resultNotified = false;
    if (!notice) return false;
    const params = resultNoticeParams(notice[0], notice[1], notice[2], notice[3]);
    if (!params) return false;
    sendInAppToast(params);
    if (!supportsSystem || !configStore.state.config.system_notifications) {
      return false;
    }
    if (backgroundNoticeDeadlineMs > 0) {
      const remaining = Math.round(backgroundNoticeDeadlineMs - Date.now());
      params.timeout_ms = Math.max(1, Math.min(15000, remaining));
    }
    const [delivered, queued] = deliverResultNotice(params);
    resultNotified = delivered || queued;
    return delivered;
  };

  const ackResultNotices = (keys) => {
    if (!keys || keys.length === 0 || !configStore) return;
    for (const key of keys) {
      delete configStore.state.pendingNotices[key];
    }
    try {
      storageSet(callHost, 'pending_notices', configStore.state.pendingNotices);
    } catch (_err) {
      // Best-effort ack.
    }
  };

  const retryResultNotices = () => {
    if (!configStore || !supportsSystem) return;
    const pendingEntries = Object.entries(configStore.state.pendingNotices || {});
    if (pendingEntries.length === 0) return;

    configStore.refreshKnownNotebooks();
    const knownScopes = new Set(
      configStore.state.knownNotebooks.map((nb) => configStore.notebookKey(nb.path))
    );
    const deadlineMs = Date.now() + 2000;
    const done = [];
    pendingEntries.sort((a, b) => noticeOrder(a[1]) - noticeOrder(b[1]));

    for (const [key, notice] of pendingEntries) {
      const params = notice && typeof notice === 'object' ? notice.params : null;
      const fingerprint = notice && typeof notice === 'object' ? notice.fingerprint : null;
      const scope = notice && typeof notice === 'object' && Object.hasOwn(notice, 'scope')
        ? notice.scope
        : key;
      if (typeof scope !== 'string') {
        done.push(key);
        continue;
      }
      if (supportsMultiNotebook && scope !== '__multi__' && !knownScopes.has(scope)) {
        done.push(key);
        continue;
      }
      let cfg = scope === '__multi__'
        ? configStore.state.storedGlobal
        : configStore.state.notebookConfigs[scope];
      if (!cfg && scope === configStore.resultKey()) {
        cfg = configStore.state.config;
      }
      if (
        !cfg &&
        configStore.state.storedGlobal &&
        !Object.hasOwn(configStore.state.storedGlobal, 'selected_notebooks')
      ) {
        cfg = configStore.state.storedGlobal;
      }
      const plan = configStore.state.pendingConfirms[scope] || {};
      if (
        !params ||
        typeof params !== 'object' ||
        (fingerprint && fingerprint !== plan.fingerprint) ||
        !cfg ||
        !cfg.system_notifications
      ) {
        done.push(key);
        continue;
      }
      const remaining = deadlineMs - Date.now();
      if (remaining <= 0) break;
      const nextParams = { ...params, timeout_ms: Math.min(remaining, 500) };
      if (fingerprint) {
        nextParams.dedup_key = fingerprint;
      } else if ((notice.status === '失败' || notice.status === '离线提醒') && !nextParams.dedup_key) {
        nextParams.dedup_key = `legacy-failure:${sha256Text(key, callHost)}`;
      }
      const [delivered] = deliverResultNotice(nextParams);
      if (delivered) {
        done.push(key);
      }
    }
    ackResultNotices(done);
  };

  const calcOfflineMs = (lastSuccessObj, outageSince, nowMs, nowStr) => {
    if (lastSuccessObj && Number.isFinite(lastSuccessObj.timestamp_ms) && lastSuccessObj.timestamp_ms > 0) {
      return Math.max(0, nowMs - lastSuccessObj.timestamp_ms);
    }
    if (lastSuccessObj && lastSuccessObj.time) {
      const prevSec = parseHmsSeconds(lastSuccessObj.time);
      const curSec = parseHmsSeconds(nowStr);
      if (prevSec !== null && curSec !== null) {
        const diffSec = curSec >= prevSec ? curSec - prevSec : 86400 - prevSec + curSec;
        return diffSec * 1000;
      }
    }
    return outageSince > 0 ? Math.max(0, nowMs - outageSince) : 0;
  };

  const recordResult = (
    status,
    summary,
    {
      protocol = null,
      target = '',
      pushed = 0,
      pulled = 0,
      conflicts = 0,
      assets = 0,
      skippedItems = [],
      noticeKey = '',
      isBackground = false,
    } = {}
  ) => {
    const nbKey = configStore.resultKey();
    const proto = protocol || configStore.state.config.protocol || 'local_mirror';
    const loc = getLocale();
    const protoLabel = protocolLabel(loc, proto);
    const targetStr = String(
      target || targetDisplay(cfgForProtocol(configStore.state.config, proto), uiContext())
    );
    const nowMs = Date.now();
    const nowStr = nowHms();
    const statusStr = String(status || '完成');
    const summaryStr = String(summary || '完成');
    const backoffKey = `${nbKey}:${proto}`;

    const prev = configStore.state.notebookResults[nbKey];
    const prevProtocols =
      prev && typeof prev === 'object' && prev.protocols && typeof prev.protocols === 'object'
        ? { ...prev.protocols }
        : {};
    let prevProto =
      prevProtocols[proto] && typeof prevProtocols[proto] === 'object' ? prevProtocols[proto] : null;
    if (!prevProto && prev && typeof prev === 'object' && entryMatchesProtocol(prev, proto)) {
      prevProto = prev;
    }

    const prevSuccess =
      prev && typeof prev === 'object' && prev.last_success && typeof prev.last_success === 'object'
        ? { ...prev.last_success }
        : null;
    const prevProtoSuccess =
      prevProto && prevProto.last_success && typeof prevProto.last_success === 'object'
        ? { ...prevProto.last_success }
        : null;

    const prevStreak = Number.parseInt((prevProto && prevProto.transient_streak) || 0, 10) || 0;
    const prevOutageNotified = Boolean(prevProto && prevProto.outage_notified);
    const prevNotifiedKey = String((prevProto && prevProto.notified_key) || '');
    const prevOutageSince = Number.parseInt((prevProto && prevProto.outage_since_ms) || 0, 10) || 0;

    let failClass = String((prevProto && prevProto.fail_class) || '');
    let transientStreak = prevStreak;
    let outageNotified = prevOutageNotified;
    let notifiedKey = prevNotifiedKey;
    let outageSinceMs = prevOutageSince;

    let lastSuccess;
    let protoLastSuccess;
    const conflictCount = Number.parseInt(conflicts || 0, 10) || 0;

    if (statusStr === '成功' || statusStr === '无变更') {
      const successSnap = {
        status: statusStr,
        protocol: protoLabel,
        protocol_id: proto,
        target: targetStr,
        time: nowStr,
        timestamp_ms: nowMs,
        pushed: Number.parseInt(pushed || 0, 10) || 0,
        pulled: Number.parseInt(pulled || 0, 10) || 0,
        conflicts: conflictCount,
        assets: Number.parseInt(assets || 0, 10) || 0,
        skipped_count: skippedItems.length,
        skipped_items: skippedItems.slice(0, 8),
        summary: summaryStr,
      };
      lastSuccess = { ...successSnap };
      protoLastSuccess = { ...successSnap };
      failClass = '';
      transientStreak = 0;
      outageNotified = false;
      notifiedKey = '';
      outageSinceMs = 0;
      protocolNextAllowedMs.delete(backoffKey);
      const prevConn = configStore.getConnState(proto);
      if (prevConn && prevConn.ok === false) {
        configStore.setConnState(proto, {
          ok: true,
          message: '',
          target_sig: connConfigSignature(configStore.state.config, proto, downloadsDir, homeDir),
          time: nowStr,
          locale: getLocale(),
        });
      }
      resultNotice = conflictCount > 0
        ? [
            statusStr,
            conflictCount,
            noticeKey || sha256Text(`${backoffKey}:conflict:${nowMs}:${summaryStr}`, callHost),
          ]
        : null;
    } else if (statusStr === '失败') {
      lastSuccess = prevSuccess;
      protoLastSuccess = prevProtoSuccess;
      failClass = classifySyncError(summaryStr);
      if (failClass === 'network') {
        transientStreak = prevStreak + 1;
        outageSinceMs = prevOutageSince > 0 ? prevOutageSince : nowMs;
        const offlineMs = calcOfflineMs(protoLastSuccess, outageSinceMs, nowMs, nowStr);
        const offlineMin = Math.max(1, Math.round(offlineMs / 60000));
        const intervalMin = Number.parseInt(configStore.state.config.sync_interval || '5', 10) || 5;
        const baseIntervalMs = Math.max(60000, intervalMin * 60 * 1000);
        const backoffMs = Math.min(baseIntervalMs * (2 ** Math.max(0, transientStreak - 1)), 60 * 60 * 1000);
        protocolNextAllowedMs.set(backoffKey, nowMs + backoffMs);

        if (!isBackground) {
          resultNotice = null;
        } else if (!prevOutageNotified && (transientStreak >= 3 || offlineMs >= 30 * 60 * 1000)) {
          outageNotified = true;
          const dedupKey = `${proto}:outage`;
          notifiedKey = dedupKey;
          resultNotice = ['离线提醒', 0, dedupKey, { reason: summaryStr, offlineMin, protocol: proto }];
        } else {
          resultNotice = null;
        }
      } else {
        transientStreak = 0;
        outageSinceMs = 0;
        protocolNextAllowedMs.delete(backoffKey);
        const dedupKey = `${proto}:${failClass}`;
        if (!isBackground || prevNotifiedKey === dedupKey) {
          resultNotice = null;
        } else {
          notifiedKey = dedupKey;
          resultNotice = [statusStr, 0, dedupKey, { reason: summaryStr, failClass, protocol: proto }];
        }
      }
    } else {
      lastSuccess = prevSuccess;
      protoLastSuccess = prevProtoSuccess;
      resultNotice = statusStr === '待确认' || conflictCount > 0
        ? [statusStr, conflictCount, noticeKey || '']
        : null;
    }

    const protoEntry = {
      status: statusStr,
      protocol: protoLabel,
      protocol_id: proto,
      target: targetStr,
      time: nowStr,
      pushed: Number.parseInt(pushed || 0, 10) || 0,
      pulled: Number.parseInt(pulled || 0, 10) || 0,
      conflicts: conflictCount,
      assets: Number.parseInt(assets || 0, 10) || 0,
      skipped_count: skippedItems.length,
      skipped_items: skippedItems.slice(0, 8),
      summary: summaryStr,
      fail_class: failClass,
      transient_streak: transientStreak,
      outage_notified: outageNotified,
      notified_key: notifiedKey,
    };
    if (outageSinceMs > 0) {
      protoEntry.outage_since_ms = outageSinceMs;
    }
    if (isEnglishLocale(loc)) {
      protoEntry.locale = 'en';
    }
    if (protoLastSuccess) {
      protoEntry.last_success = protoLastSuccess;
    }
    prevProtocols[proto] = protoEntry;

    const entry = { ...protoEntry, protocols: prevProtocols };
    if (lastSuccess) {
      entry.last_success = lastSuccess;
    } else {
      delete entry.last_success;
    }
    configStore.state.notebookResults[nbKey] = entry;
  };

  const recordNoopLog = (protocol, summary) => {
    const nowStr = nowHms();
    const nowTs = Math.floor(Date.now() / 1000);
    const logs = configStore.state.logs;
    if (logs.length > 0) {
      const top = logs[0];
      if (top && typeof top === 'object' && top.log_key === 'sync_noop') {
        const args = { ...(top.log_args || {}) };
        if (!args.protocol || args.protocol === protocol) {
          const count = Math.max(1, Number.parseInt(args.count || 1, 10) || 1) + 1;
          const firstTime = String(args.first_time || top.time || nowStr).trim() || nowStr;
          let firstTs = Number.parseInt(args.first_ts || 0, 10) || 0;
          if (firstTs <= 0) {
            const fSec = parseHmsSeconds(firstTime);
            const nSec = parseHmsSeconds(nowStr);
            if (fSec !== null && nSec !== null && nSec >= fSec) {
              firstTs = nowTs - (nSec - fSec);
            } else {
              firstTs = nowTs;
            }
          }
          const checks = (Array.isArray(args.checks) ? args.checks : [])
            .map((x) => String(x || '').trim())
            .filter(Boolean);
          if (checks.length === 0 && top.time) {
            checks.push(String(top.time));
          }
          checks.unshift(nowStr);
          args.protocol = protocol;
          args.count = count;
          args.first_time = firstTime;
          args.last_time = nowStr;
          args.first_ts = firstTs;
          args.last_ts = nowTs;
          args.checks = checks.slice(0, 24);
          top.time = nowStr;
          top.tooltip = summary;
          top.log_args = args;
          return;
        }
      }
    }
    const label = protocolLabel(getLocale(), protocol);
    appendLog(t(`${label}同步`, `${label} sync`), '无变更', {
      tone: 'info',
      tooltip: summary,
      logKey: 'sync_noop',
      logArgs: {
        protocol,
        count: 1,
        first_time: nowStr,
        last_time: nowStr,
        first_ts: nowTs,
        last_ts: nowTs,
        checks: [nowStr],
      },
    });
  };

  const saveRuntime = ({ onlyPath = null, notebookRoot: onlyNbRoot = null, clearPending = false, protocol = null } = {}) => {
    if (clearPending) {
      configStore.clearPendingConfirm(protocol);
    }
    const scopeKey = configStore.resultKey();
    const nbRootForNotice = onlyNbRoot || notebookRoot;
    const notice = resultNotice;
    const queueNotice = Boolean(
      supportsSystem &&
        configStore.state.config.system_notifications &&
        notice &&
        (notice[0] === '待确认' || notice[0] === '失败' || notice[0] === '离线提醒' || notice[1] > 0)
    );
    const queued = { ...(configStore.state.pendingNotices || {}) };
    let noticeChanged = false;

    if (notice && (notice[0] === '成功' || notice[0] === '无变更')) {
      for (const [entryKey, previous] of Object.entries(queued)) {
        if (!previous || typeof previous !== 'object') continue;
        if ((previous.scope ?? entryKey) !== scopeKey) continue;
        if (protocol && previous.protocol && previous.protocol !== protocol) continue;
        if (previous.status !== '失败' && previous.status !== '离线提醒' && !isPauseNotice(previous)) continue;
        const legacyPause = !Object.hasOwn(previous, 'order') && !previous.path && !previous.fingerprint;
        if (
          onlyPath === null ||
          legacyPause ||
          (previous.path === onlyPath && previous.notebook_root === nbRootForNotice)
        ) {
          delete queued[entryKey];
          noticeChanged = true;
        }
      }
    }

    let noticeKey = scopeKey;
    if (queueNotice) {
      const scopedFile = (notice[0] === '待确认' || notice[0] === '失败') && onlyPath !== null;
      if (scopedFile) {
        const prefix = notice[0] === '待确认' ? 'note:' : 'failure:';
        noticeKey =
          prefix +
          sha256Text(JSON.stringify([scopeKey, protocol || '', nbRootForNotice, onlyPath]), callHost);
      } else if (notice[0] === '失败' || notice[0] === '离线提醒') {
        noticeKey = `failure:${sha256Text(`${scopeKey}:${protocol || ''}`, callHost)}`;
      } else if (notice[1] > 0) {
        noticeKey = `conflict:${notice[2]}`;
      }
      delete queued[noticeKey];
      const pcForNotice = protocol
        ? configStore.getPendingConfirm(protocol)
        : configStore.state.pendingConfirm;
      const maxOrder = Object.values(queued).reduce((m, item) => Math.max(m, noticeOrder(item)), 0);
      const noticeEntry = {
        params: resultNoticeParams(notice[0], notice[1], notice[2], notice[3]),
        fingerprint: notice[0] === '待确认' && pcForNotice ? pcForNotice.fingerprint || '' : '',
        status: notice[0],
        scope: scopeKey,
        protocol: protocol || '',
        order: maxOrder + 1,
      };
      if (scopedFile) {
        noticeEntry.path = onlyPath;
        noticeEntry.notebook_root = nbRootForNotice;
      }
      queued[noticeKey] = noticeEntry;
      const sortedEntries = Object.entries(queued)
        .sort((a, b) => noticeOrder(a[1]) - noticeOrder(b[1]))
        .slice(-32);
      const trimmed = Object.fromEntries(sortedEntries);
      noticeChanged = true;
      Object.keys(queued).forEach((k) => delete queued[k]);
      Object.assign(queued, trimmed);
    }

    try {
      configStore.saveRuntime();
      if (noticeChanged) {
        storageSet(callHost, 'pending_notices', queued);
        configStore.state.pendingNotices = queued;
      }
      clearBackgroundError();
    } catch (err) {
      configStore.state.pendingConfirms = { ...configStore.state.savedPendingConfirms };
      configStore.state.pendingConfirm = configStore.getPendingConfirm();
      if (resultNotice) {
        resultNotice = ['状态未保存', 0, ''];
      }
      const msg = t(
        '同步状态未保存，请检查后重试',
        'Sync state could not be saved. Check settings and retry.'
      );
      lastStatus = msg;
      sendResultNotice();
      setBackgroundError(
        t('同步状态未保存', 'Sync state not saved'),
        errorDetail(getLocale(), err),
        { severity: 'danger', retryAction: 'sync_now' }
      );
      throw new SyncStateError(msg, resultNotified);
    }

    const delivered = sendResultNotice();
    if (queueNotice && delivered) {
      ackResultNotices([noticeKey]);
    }
  };

  const syncFailure = (message) =>
    resultNotified ? new SyncReportedError(message) : new Error(message);

  const runTestConn = (cfg = null) => {
    const rawCfg = cfg || configStore.state.config;
    const protocol = rawCfg.protocol || 'local_mirror';
    const sig = connConfigSignature(rawCfg, protocol, downloadsDir, homeDir);
    const err = targetError(rawCfg, { ...uiContext(), requireNotebooks: false });
    if (err) {
      if (protocolHasInput(rawCfg, protocol, downloadsDir, homeDir)) {
        configStore.setConnState(protocol, {
          ok: false,
          message: err,
          target_sig: sig,
          time: nowHms(),
          locale: getLocale(),
        });
      }
      lastStatus = err;
      return [false, err];
    }
    let c;
    try {
      c = resolveCredentials(callHost, rawCfg, getLocale());
    } catch (exc) {
      lastStatus = errorDetail(getLocale(), exc);
      configStore.setConnState(protocol, {
        ok: false,
        message: lastStatus,
        target_sig: sig,
        time: nowHms(),
        locale: getLocale(),
      });
      return [false, lastStatus];
    }

    let ok;
    let msg;
    if (protocol === 'webdav') {
      [ok, msg] = engines.webdav.davClient.testConnection(c);
    } else if (protocol === 'git') {
      [ok, msg] = engines.git.testConnection(c);
    } else {
      [ok, msg] = engines.localMirror.testConnection(c);
    }

    configStore.setConnState(protocol, {
      ok: Boolean(ok),
      message: msg,
      target_sig: sig,
      time: nowHms(),
      locale: getLocale(),
    });
    const pLabel = protocolLabel(getLocale(), protocol);
    logProtocol = protocol;
    appendLog(t(`测试连接 (${pLabel})`, `Test connection (${pLabel})`), ok ? '通过' : '未连通', {
      tone: ok ? 'success' : 'danger',
      tooltip: msg,
      logKey: 'test_conn',
      logArgs: { protocol },
    });
    lastStatus = msg;
    return [Boolean(ok), msg];
  };

  const computeBatchPlanForProtocol = (proto, cfg, notebooks, { onlyPath = null, deadlineMs = 0 } = {}) => {
    if (proto === 'webdav') {
      return engines.webdav.computeBatchPlan({
        cfg,
        notebooks,
        onlyPath,
        inspectRemote: true,
        forceRefresh: true,
        deadlineMs,
      });
    }
    if (proto === 'git') {
      return engines.git.computeBatchPlan({
        cfg,
        notebooks,
        onlyPath,
        inspectRemote: true,
        deadlineMs,
      });
    }
    return engines.localMirror.computeBatchPlan({
      cfg,
      notebooks,
      onlyPath,
    });
  };

  const assessBatchForProtocol = (proto, batch, cfg) => {
    if (proto === 'webdav') return engines.webdav.assessBatchDangerousChanges(batch, cfg);
    if (proto === 'git') return engines.git.assessBatchDangerousChanges(batch, cfg);
    return engines.localMirror.assessBatchDangerousChanges(batch, cfg);
  };

  const buildPendingForProtocol = (proto, batch, reasonItems, opts) => {
    if (proto === 'webdav') return engines.webdav.buildPendingConfirm(batch, reasonItems, opts);
    if (proto === 'git') return engines.git.buildPendingConfirm(batch, reasonItems, opts);
    return engines.localMirror.buildPendingConfirm(batch, reasonItems, opts);
  };

  const runSync = ({
    onlyPath = null,
    onlyNbRoot = null,
    confirmed = false,
    approvedBatch = null,
    reportProgress = false,
    protocol = null,
    progressMeta = null,
    deadlineMs = 0,
    isBackground = false,
  } = {}) => {
    lastSyncOutcome = 'skipped';
    lastSyncedNotebooks = [];
    configStore.refreshKnownNotebooks();
    let proto =
      protocol ||
      (approvedBatch && approvedBatch.protocol) ||
      configStore.state.config.protocol ||
      'local_mirror';
    logProtocol = proto;
    const protoCfg = cfgForProtocol(configStore.state.config, proto);
    const tErr = targetError(protoCfg, uiContext());
    if (tErr) {
      lastStatus = tErr;
      return tErr;
    }

    const pm = progressMeta || {};
    const batchCount = Number.parseInt(pm.batch_count || 1, 10) || 1;
    const batchIndex = Number.parseInt(pm.batch_index || 0, 10) || 0;
    const overallLabel = pm.overall_label || '';

    if (reportProgress) {
      emitProgress({
        channel: proto,
        label: t('比对变更…', 'Checking changes…'),
        tone: 'accent',
        running: true,
      });
      if (batchCount > 1) {
        emitProgress({ progress: batchIndex / batchCount, label: overallLabel });
      }
    }

    const handleSyncFailure = (msg, target = '') => {
      const failClass = classifySyncError(msg);
      const isTransientBg = isBackground && failClass === 'network';
      if (reportProgress) {
        emitProgress({
          channel: proto,
          progress: 1.0,
          label: isTransientBg
            ? t('等待网络，稍后自动重试', 'Offline, will retry')
            : formatSyncFailureLabel(getLocale(), failClass),
          tone: isTransientBg ? 'warning' : 'danger',
          running: false,
        });
      }
      const pLabel = protocolLabel(getLocale(), proto);
      appendLog(t(`${pLabel}同步`, `${pLabel} sync`), '失败', {
        tone: 'danger',
        tooltip: msg,
      });
      recordResult('失败', msg, { protocol: proto, target, isBackground });
      saveRuntime({ onlyPath, notebookRoot: onlyNbRoot, protocol: proto });
      lastStatus = msg;
      throw syncFailure(msg);
    };

    let res;
    try {
      const notebooks = configStore.selectedNotebooks(protoCfg);
      if (onlyNbRoot) {
        const normOnly = normAbsPath(onlyNbRoot, homeDir);
        if (!normOnly || !notebooks.includes(normOnly)) return '';
      }
      if (!notebooks || notebooks.length === 0) {
        const msg = t('请至少选择一个笔记本', 'Select at least one notebook');
        lastStatus = msg;
        return msg;
      }

      const opts = {
        cfg: protoCfg,
        notebooks,
        onlyPath,
        onlyNbRoot,
        confirmed,
        approvedBatch,
        reportProgress,
        deadlineMs,
      };
      if (proto === 'webdav') {
        res = engines.webdav.syncWebdav(opts);
      } else if (proto === 'git') {
        res = engines.git.syncGit(opts);
      } else {
        res = engines.localMirror.syncLocalMirror(opts);
      }
    } catch (exc) {
      const pLabel = protocolLabel(getLocale(), proto);
      const det = errorDetail(getLocale(), exc);
      const msg =
        det.startsWith(pLabel) || det.includes('Git')
          ? det
          : t(`${pLabel}同步未完成: ${det}`, `${pLabel} sync failed: ${det}`);
      handleSyncFailure(msg);
    }

    if (res.outcome === 'error') {
      handleSyncFailure(res.error || t('同步失败', 'Sync failed'));
    }

    if (res.outcome === 'pending_confirm') {
      lastSyncOutcome = 'pending_confirm';
      const pending = res.pendingConfirm || {};
      const reasonItems = Array.isArray(pending.reason_items) ? pending.reason_items : [];
      const firstReason =
        reasonItems.length > 0
          ? formatReasonItem(getLocale(), reasonItems[0])
          : t('检测到危险变更', 'Risky changes detected');

      if (reportProgress) {
        emitProgress({
          channel: proto,
          progress: 0.5,
          label: t('待确认', 'Needs confirm'),
          tone: 'warning',
          running: false,
        });
      }
      if (onlyPath !== null) {
        const cta = t('请前往同步页确认', 'Open Sync settings to review and confirm');
        const msg = t(
          `自动同步暂停（${firstReason}），${cta}`,
          `Auto-sync paused (${firstReason}). ${cta}.`
        );
        appendLog(
          t(`自动同步暂停 (${onlyPath})`, `Auto-sync paused (${onlyPath})`),
          '待确认',
          {
            tone: 'warning',
            tooltip: msg,
            logKey: 'auto_paused',
            logArgs: { path: onlyPath, protocol: proto },
          }
        );
        recordResult('待确认', msg, {
          protocol: proto,
          target: (res.batch && res.batch.target_display) || '',
          noticeKey: pending.fingerprint || '',
        });
        saveRuntime({ onlyPath, notebookRoot: onlyNbRoot, protocol: proto });
        lastStatus = msg;
        return msg;
      }

      const msg = t(
        '检测到危险变更，请先确认后执行',
        'Risky changes detected. Confirm to continue.'
      );
      appendLog(firstReason, '待确认', {
        tone: 'warning',
        tooltip: msg,
        logKey: 'confirm_required',
        logArgs: { reason_item: reasonItems[0], protocol: proto },
      });
      recordResult('待确认', firstReason, {
        protocol: proto,
        target: (res.batch && res.batch.target_display) || '',
      });
      saveRuntime({ protocol: proto });
      lastStatus = msg;
      return msg;
    }

    // Outcome: synced
    const batch = res.batch || {};
    const target = batch.target_display || '';
    const pushed = Number(res.pushed || 0);
    const pulled = Number(res.pulled || 0);
    const conflicts = Number(res.conflicts || 0);
    const assets = Number(res.assets || 0);
    const deleted = Number(res.deleted || 0);
    const totalNotes = pushed + pulled + conflicts;
    const summary = String(res.summary || t('已是最新', 'Up to date'));
    const skippedItems = res.skipped_items || [];
    if (skippedItems.length > 0) {
      appendLog(formatSkippedCount(getLocale(), skippedItems.length), '已跳过', {
        tone: 'warning',
        tooltip: formatSkippedDetails(skippedItems),
        logKey: 'sync_skipped',
        logArgs: { protocol: proto, count: skippedItems.length, items: skippedItems.slice(0, 8) },
      });
    }

    if (totalNotes === 0 && assets === 0 && deleted === 0) {
      if (res.did_push) {
        const pLabel = protocolLabel(getLocale(), proto);
        appendLog(t(`推送 ${pLabel} 提交`, `Push commits to ${pLabel}`), '成功', {
          tone: 'success',
          tooltip: summary,
        });
        recordResult('成功', summary, { protocol: proto, target, skippedItems });
      } else {
        if (onlyPath === null && skippedItems.length === 0) {
          recordNoopLog(proto, summary);
        }
        recordResult('无变更', summary, { protocol: proto, target, skippedItems });
      }
    } else {
      recordResult('成功', summary, {
        protocol: proto,
        target,
        pushed,
        pulled,
        conflicts,
        assets,
        skippedItems,
      });
    }

    lastSyncOutcome = 'synced';
    lastSyncedNotebooks = (batch.plans || []).map((p) => p.nb_root).filter(Boolean);
    saveRuntime({
      onlyPath,
      notebookRoot: onlyNbRoot,
      clearPending: confirmed,
      protocol: proto,
    });

    if (reportProgress) {
      const protoRes = getProtocolResult(configStore, proto);
      const doneLbl = formatShortSyncMetric(getLocale(), protoRes);
      emitProgress({
        channel: proto,
        progress: 1.0,
        label: doneLbl,
        tone: 'success',
        running: false,
      });
      if (batchCount > 1) {
        emitProgress({ progress: (batchIndex + 1) / batchCount, label: overallLabel });
      }
    }

    lastStatus =
      res.status === '无变更'
        ? summary
        : t(`同步完成：${summary}`, `Synced: ${summary}`);
    return lastStatus;
  };

  const runMultiProtocolSync = (protocols, reportProgress = false) => {
    const totalTargets = protocols.length;
    if (reportProgress && totalTargets > 1) {
      for (const proto of protocols) {
        if (configStore.getPendingConfirm(proto)) {
          emitProgress({
            channel: proto,
            progress: 0.5,
            label: t('待确认', 'Needs confirm'),
            tone: 'warning',
            running: false,
          });
        } else {
          emitProgress({
            channel: proto,
            progress: 0.0,
            label: t('等待同步', 'Queued'),
            running: false,
          });
        }
      }
    }

    const succeeded = [];
    const pending = [];
    const failed = [];
    const syncedNotebooks = [];
    const seenNbs = new Set();
    let lastErr = '';

    for (let idx = 0; idx < protocols.length; idx += 1) {
      const proto = protocols[idx];
      const pLabel = protocolLabel(getLocale(), proto);
      const overallLabel = `${pLabel} (${idx + 1}/${totalTargets})`;
      if (configStore.getPendingConfirm(proto)) {
        pending.push(proto);
        if (reportProgress) {
          emitProgress({
            channel: proto,
            progress: 0.5,
            label: t('待确认', 'Needs confirm'),
            tone: 'warning',
            running: false,
          });
        }
        continue;
      }
      try {
        runSync({
          reportProgress,
          protocol: proto,
          progressMeta: {
            batch_index: idx,
            batch_count: totalTargets,
            overall_label: overallLabel,
          },
        });
      } catch (exc) {
        failed.push(proto);
        lastErr = errorDetail(getLocale(), exc);
        continue;
      }

      if (lastSyncOutcome === 'pending_confirm') {
        pending.push(proto);
      } else {
        succeeded.push(proto);
        for (const nb of lastSyncedNotebooks) {
          if (!seenNbs.has(nb)) {
            seenNbs.add(nb);
            syncedNotebooks.push(nb);
          }
        }
      }
    }

    lastSyncedNotebooks = syncedNotebooks;
    const sep = t('、', ', ');
    if (failed.length > 0 && succeeded.length === 0 && pending.length === 0) {
      const msg = lastErr || t('全部同步目标均未完成', 'All sync targets failed');
      lastStatus = msg;
      return [false, 'danger', msg];
    }
    if (failed.length > 0) {
      const failNames = failed.map((p) => protocolLabel(getLocale(), p)).join(sep);
      const msg = t(
        `已完成 ${succeeded.length}/${totalTargets} 个目标，${failNames} 失败`,
        `${succeeded.length}/${totalTargets} targets synced; ${failNames} failed`
      );
      lastStatus = msg;
      return [false, 'danger', msg];
    }
    if (pending.length > 0) {
      const pendNames = pending.map((p) => protocolLabel(getLocale(), p)).join(sep);
      const msg = succeeded.length > 0
        ? t(
            `已完成 ${succeeded.length}/${totalTargets} 个目标，${pendNames} 待确认`,
            `${succeeded.length}/${totalTargets} targets synced; ${pendNames} needs confirmation`
          )
        : t(
            `${pendNames} 检测到危险变更，请先确认`,
            `${pendNames} detected risky changes; confirmation required`
          );
      lastStatus = msg;
      return [true, 'warning', msg];
    }
    const names = succeeded.map((p) => protocolLabel(getLocale(), p)).join(sep);
    const msg = t(
      `已同步 ${succeeded.length} 个目标（${names}）`,
      `Synced ${succeeded.length} targets (${names})`
    );
    lastStatus = msg;
    return [true, 'success', msg];
  };

  const runBackgroundSync = ({
    onlyPath = null,
    onlyNbRoot = null,
    deadlineMs = 0,
    protocol = null,
  } = {}) => {
    const proto = protocol || configStore.state.config.protocol || 'local_mirror';
    const effectiveDeadline = deadlineMs > 0 ? deadlineMs : Date.now() + 95000;
    backgroundNoticeDeadlineMs = effectiveDeadline + 20000;
    const protoDeadline = proto === 'git' ? effectiveDeadline - 8000 : effectiveDeadline;
    try {
      return runSync({
        onlyPath,
        onlyNbRoot,
        protocol: proto,
        deadlineMs: protoDeadline,
        isBackground: true,
      });
    } finally {
      backgroundNoticeDeadlineMs = 0;
    }
  };

  const syncSystemTarget = (eventName, params, deadlineMs = 0) => {
    const skipped = { handled: true, outcome: 'skipped' };
    const cfg = configStore.state.config;
    if (!cfg.auto_sync || configStore.selectedNotebooks(cfg).length === 0) {
      return skipped;
    }
    const activeProtocols = configuredProtocols(cfg, uiContext());
    if (activeProtocols.length === 0) {
      return skipped;
    }

    const trigger = String((params && params.trigger) || '').trim();
    const isNetworkTrigger =
      eventName === 'network.changed' || (eventName === SYNC_INTERVAL_EVENT && trigger === 'network');
    const isIntervalTrigger =
      eventName === LEGACY_SYNC_INTERVAL_EVENT ||
      (eventName === SYNC_INTERVAL_EVENT && (!trigger || trigger === 'interval'));

    const outcomes = new Set();
    const synced = [];
    const seenNbs = new Set();
    let notified = false;

    for (const protocol of activeProtocols) {
      if (deadlineMs > 0 && Date.now() >= deadlineMs) break;
      if (configStore.getPendingConfirm(protocol)) continue;
      if (protocolError(cfg, protocol, { ...uiContext(), requireNotebooks: true })) continue;
      const needsNetwork = protocolNeedsNetwork(protocol, cfg);
      if (isNetworkTrigger && (params.online !== true || !needsNetwork)) continue;
      if (
        (eventName === 'system.wake' || eventName === SYNC_INTERVAL_EVENT || eventName === LEGACY_SYNC_INTERVAL_EVENT) &&
        params.online === false &&
        needsNetwork
      ) {
        continue;
      }

      const intervalKey = `${configStore.resultKey()}:${protocol}`;
      if (isIntervalTrigger) {
        const nextAllowed = protocolNextAllowedMs.get(intervalKey) || 0;
        if (Date.now() < nextAllowed) {
          continue;
        }
        const lastMs = intervalSyncedAt.get(intervalKey);
        const intervalSec = (Number.parseInt(cfg.sync_interval || '5', 10) || 5) * 60;
        if (lastMs !== undefined && Date.now() - lastMs < intervalSec * 1000 - 5000) {
          continue;
        }
      }
      intervalSyncedAt.set(intervalKey, Date.now());
      try {
        runBackgroundSync({ deadlineMs, protocol });
        outcomes.add(lastSyncOutcome);
        for (const nb of lastSyncedNotebooks) {
          if (!seenNbs.has(nb)) {
            seenNbs.add(nb);
            synced.push(nb);
          }
        }
      } catch (exc) {
        if (exc instanceof SyncStateError) {
          outcomes.add('state_error');
          notified = notified || exc.notified;
        } else if (exc instanceof SyncReportedError) {
          outcomes.add('failed');
          notified = true;
        } else {
          outcomes.add('failed');
        }
      }
    }

    const outcome =
      ['state_error', 'failed', 'pending_confirm', 'synced'].find((v) => outcomes.has(v)) || 'skipped';
    const res = { handled: true, outcome };
    if (synced.length > 0) res.synced_notebooks = synced;
    if (notified) res.notified = true;
    return res;
  };

  const syncAfterSystemEvent = (eventName, params) => {
    configStore.refreshKnownNotebooks();
    const st = configStore.state;
    if (
      !supportsMultiNotebook ||
      (st.storedGlobal && Object.hasOwn(st.storedGlobal, 'selected_notebooks'))
    ) {
      const result = syncSystemTarget(eventName, params);
      const nbKey = (params && params.notebook_root) || notebookRoot;
      return { ...result, notebook_outcomes: { [nbKey]: result } };
    }
    if (
      Object.keys(st.pendingConfirms).some(
        (k) => k === '__multi__' || k.startsWith('__multi__:')
      )
    ) {
      return { handled: true, outcome: 'skipped' };
    }

    const savedState = {
      notebookRoot: st.notebookRoot,
      config: st.config,
      pendingConfirm: st.pendingConfirm,
      lastStatus,
    };
    const activeKey = configStore.notebookKey();
    const results = {};
    const synced = [];
    const deadlineMs = Date.now() + 95000;
    const roots = st.knownNotebooks.map((nb) => nb.path);
    const start = roots.includes(nextSystemNotebook) ? roots.indexOf(nextSystemNotebook) : 0;

    try {
      for (let offset = 0; offset < roots.length; offset += 1) {
        const index = (start + offset) % roots.length;
        const root = roots[index];
        if (Date.now() >= deadlineMs) break;
        nextSystemNotebook = roots[(index + 1) % roots.length];
        const key = configStore.notebookKey(root);
        const saved =
          st.notebookConfigs[key] || (key === activeKey ? st.storedGlobal : null);
        if (!saved) continue;
        st.notebookRoot = root;
        st.config = { ...saved, selected_notebooks: [root] };
        st.pendingConfirm = configStore.getPendingConfirm();
        const result = syncSystemTarget(eventName, params, deadlineMs);
        results[root] = result;
        if (Array.isArray(result.synced_notebooks)) {
          synced.push(...result.synced_notebooks);
        }
      }
    } finally {
      st.notebookRoot = savedState.notebookRoot;
      st.config = savedState.config;
      lastStatus = savedState.lastStatus;
      st.pendingConfirm = configStore.getPendingConfirm();
    }

    const outcomes = new Set(Object.values(results).map((r) => r.outcome));
    const outcome =
      ['state_error', 'failed', 'pending_confirm', 'synced'].find((v) => outcomes.has(v)) || 'skipped';
    return {
      handled: true,
      outcome,
      synced_notebooks: synced,
      notebook_outcomes: results,
    };
  };

  const recordDeletedEventTombstones = (nbKey, localDir, relPath, folder) => {
    if (!nbKey || (!folder && !relPath)) return false;
    const nbPrefix = `nb:${nbKey}|`;
    const defaultNb = nbKey === configStore.notebookKey();
    let dirOk = false;
    if (localDir) {
      try {
        const st = fsStat(callHost, localDir);
        dirOk = Boolean(st.exists && st.is_dir);
      } catch (_err) {
        dirOk = false;
      }
    }

    let recorded = false;
    if (folder) {
      const folderPrefix = `${folder}/`;
      let isCi = false;
      let isNorm = false;
      let foldedPrefix = '';
      if (dirOk) {
        isCi = dirIsCaseInsensitive(callHost, localDir, [folder]);
        isNorm = dirIsNormalizationInsensitive(callHost, localDir);
        if (isCi || isNorm) {
          foldedPrefix = `${foldSyncPath(folder, { caseInsensitive: isCi, normalize: isNorm })}/`;
        }
      }
      for (const [mk, entry] of Object.entries(configStore.state.syncMeta)) {
        if (
          mk === LAYOUTS_META_KEY ||
          mk === INITIALIZED_META_KEY ||
          mk === TOMBSTONES_META_KEY ||
          !entry ||
          typeof entry !== 'object'
        ) {
          continue;
        }
        if (!(mk.startsWith(nbPrefix) || (!mk.startsWith('nb:') && defaultNb))) continue;
        for (const [itemKey, itemHash] of Object.entries(entry)) {
          if (typeof itemHash !== 'string' || !itemHash) continue;
          const [, itemRel] = splitItemKey(itemKey);
          let matched = itemRel.startsWith(folderPrefix);
          if (!matched && foldedPrefix) {
            matched = foldSyncPath(itemRel, { caseInsensitive: isCi, normalize: isNorm }).startsWith(
              foldedPrefix
            );
          }
          if (matched && configStore.recordTombstone(nbKey, itemKey, itemHash)) {
            recorded = true;
          }
        }
      }
      return recorded;
    }

    const targetFold = foldSyncPath(relPath, { caseInsensitive: true, normalize: true });
    for (const [mk, entry] of Object.entries(configStore.state.syncMeta)) {
      if (
        mk === LAYOUTS_META_KEY ||
        mk === INITIALIZED_META_KEY ||
        mk === TOMBSTONES_META_KEY ||
        !entry ||
        typeof entry !== 'object'
      ) {
        continue;
      }
      if (!(mk.startsWith(nbPrefix) || (!mk.startsWith('nb:') && defaultNb))) continue;
      for (const [itemKey, itemHash] of Object.entries(entry)) {
        if (typeof itemHash !== 'string' || !itemHash) continue;
        const [, itemRel] = splitItemKey(itemKey);
        const matched =
          itemRel === relPath ||
          (dirOk &&
            foldSyncPath(itemRel, { caseInsensitive: true, normalize: true }) === targetFold &&
            pathsCollapse(callHost, localDir, relPath, itemRel));
        if (matched && configStore.recordTombstone(nbKey, itemKey, itemHash)) {
          recorded = true;
        }
      }
    }
    return recorded;
  };

  const runInitialMaintenance = () => {
    if (!configStore) return;
    try {
      const nbs = configStore.state.knownNotebooks.map((nb) => nb.path).filter(Boolean);
      for (const nbPath of nbs) {
        migrateLegacyRecoveryDirs(callHost, nbPath, { dataDir });
      }
      cleanupRecoveryDirs(callHost, { dataDir, notebooks: nbs });
    } catch (_err) {
      // Best-effort maintenance; never fail initialization.
    }
    if (supportsSystem) {
      for (let i = 0; i < 4; i += 1) {
        const res = configStore.migrateCredentials();
        if (res !== 'migration_pending') break;
      }
      try {
        retryResultNotices();
      } catch (_err) {
        // Non-fatal during initialization or tick.
      }
    }
  };

  const handleInitialize = (params) => {
    pluginId = String(params.plugin_id || 'block-sync');
    dataDir = String(params.data_dir || '');
    downloadsDir = String(params.downloads_dir || '').trim();
    homeDir = inferHomeDir(params);
    notebookRoot = String(params.notebook_root || '');
    locale = normalizeLocale(params.locale || 'zh');

    const caps = new Set(Array.isArray(params.ui_capabilities) ? params.ui_capabilities : []);
    kvTooltip = caps.has('kv_tooltip');
    supportsChecklist = caps.has('checklist');
    supportsAddFolder = caps.has('checklist_add_folder');
    supportsFormLayout = caps.has('form_layout');
    supportsMultiNotebook = caps.has('multi_notebook');
    supportsLogTimeline = caps.has('log_timeline');
    supportsActionProgress = caps.has('action_progress');
    supportsProgressBar = caps.has('progress_bar');
    supportsSegmentedStatus = caps.has('segmented_status');
    supportsFormAutosave = caps.has('form_autosave');
    supportsButtonLink = caps.has('button_link');
    supportsSystem = caps.has('system_integration');
    supportsToastBanner = caps.has('toast_banner');
    supportsOpenSettings = caps.has('open_settings');

    configStore = createConfigStore({
      callHost,
      locale,
      supportsSystem,
      supportsMultiNotebook,
      notebookRoot,
      downloadsDir,
      homeDir,
    });

    if (Array.isArray(params.notebooks)) {
      configStore.state.knownNotebooks = params.notebooks
        .map((p) => String(p || '').trim())
        .filter(Boolean)
        .map((p) => ({
          path: normAbsPath(p, homeDir),
          name: normAbsPath(p, homeDir).split('/').pop() || p,
          active: Boolean(notebookRoot && normAbsPath(p, homeDir) === normAbsPath(notebookRoot, homeDir)),
        }));
    }

    configStore.loadState();
    markExistingLogsQueued();
    rebuildEngines();
    runInitialMaintenance();
    syncAutoSyncScheduler();
    try {
      callHost('host.sidebar.set_ignored_dirs', { dirs: LEGACY_IGNORED_DIRS });
    } catch (err) {
      // Silently ignore on older hosts that do not implement sidebar ignored_dirs.
      if (!isMethodUnsupportedError(err)) {
        // Non-fatal: sidebar directory hiding should never block plugin initialization.
      }
    }
    return { ready: true };
  };

  const handleRender = (params) => {
    configStore.refreshKnownNotebooks();
    const values = params.values;
    let renderStatus = '';
    const accepted = {};
    let cfg;

    if (values && typeof values === 'object' && !Array.isArray(values) && Object.keys(values).length > 0) {
      cfg = configStore.normalizeConfig(values);
      const nextConfig = { ...configStore.state.config };
      const clearProtocols = new Set();
      let nextStatus = lastStatus;
      let schedulerNeedsSync = false;

      if (
        Object.hasOwn(values, 'selected_notebooks') &&
        JSON.stringify(cfg.selected_notebooks) !== JSON.stringify(configStore.state.config.selected_notebooks)
      ) {
        nextConfig.selected_notebooks = [...cfg.selected_notebooks];
        for (const p of VALID_PROTOCOLS) clearProtocols.add(p);
        nextStatus = '';
        schedulerNeedsSync = true;
      }

      if (cfg.auto_sync !== configStore.state.config.auto_sync) {
        schedulerNeedsSync = true;
      }
      if (cfg.sync_interval !== configStore.state.config.sync_interval) {
        schedulerNeedsSync = true;
      }
      nextConfig.auto_sync = cfg.auto_sync;
      nextConfig.sync_interval = cfg.sync_interval;
      nextConfig.system_notifications = cfg.system_notifications;

      if (cfg.conflict_policy !== configStore.state.config.conflict_policy) {
        nextConfig.conflict_policy = cfg.conflict_policy;
        for (const p of VALID_PROTOCOLS) clearProtocols.add(p);
        nextStatus = '';
      }
      if (Object.hasOwn(values, 'protocol') && cfg.protocol !== configStore.state.config.protocol) {
        nextConfig.protocol = cfg.protocol;
        nextStatus = '';
      }

      if (!supportsFormAutosave) {
        for (const [proto, enabledKey] of Object.entries(PROTOCOL_ENABLED_KEYS)) {
          if (Object.hasOwn(values, enabledKey) && cfg[enabledKey] !== configStore.state.config[enabledKey]) {
            nextConfig[enabledKey] = cfg[enabledKey];
            schedulerNeedsSync = true;
            const pLabel = protocolLabel(getLocale(), proto);
            if (!cfg[enabledKey]) {
              clearProtocols.add(proto);
              nextStatus = t(`已停用${pLabel}`, `${pLabel} disabled`);
            } else if (!protocolError(nextConfig, proto, { ...uiContext(), requireNotebooks: false })) {
              nextStatus = t(`已启用${pLabel}`, `${pLabel} enabled`);
            } else {
              nextStatus = '';
            }
          }
        }

        if (Object.hasOwn(values, 'mirror_dir')) {
          if (!cfg.mirror_dir) {
            if (configStore.state.config.mirror_dir || configStore.state.config.local_mirror_enabled) {
              nextConfig.mirror_dir = '';
              nextConfig.local_mirror_enabled = false;
              clearProtocols.add('local_mirror');
              schedulerNeedsSync = true;
              nextStatus = t('已停用目录镜像', 'Local mirror disabled');
            }
          } else {
            const mirrorErr = protocolError(cfg, 'local_mirror', {
              ...uiContext(),
              requireNotebooks: false,
            });
            if (!mirrorErr) {
              if (configStore.state.config.mirror_dir !== cfg.mirror_dir) {
                nextConfig.mirror_dir = cfg.mirror_dir;
                nextConfig.local_mirror_enabled = true;
                cfg.local_mirror_enabled = true;
                clearProtocols.add('local_mirror');
                schedulerNeedsSync = true;
                nextStatus = t('已启用本地镜像目录', 'Local mirror folder enabled');
              }
            } else {
              renderStatus = mirrorErr;
            }
          }
        }
      }

      if (JSON.stringify(nextConfig) !== JSON.stringify(configStore.state.config)) {
        saveConfig(nextConfig, {
          clearPending: clearProtocols.size > 0 ? clearProtocols : false,
        });
        lastStatus = nextStatus;
      } else if (schedulerNeedsSync) {
        syncAutoSyncScheduler();
      }

      const acceptedKeys = [
        'selected_notebooks',
        'auto_sync',
        'sync_interval',
        'system_notifications',
        'conflict_policy',
        'protocol',
        ...(supportsFormAutosave
          ? []
          : ['mirror_dir', 'local_mirror_enabled', 'webdav_enabled', 'git_enabled']),
      ];
      for (const key of acceptedKeys) {
        if (
          Object.hasOwn(values, key) &&
          JSON.stringify(cfg[key]) === JSON.stringify(configStore.state.config[key])
        ) {
          accepted[key] = configStore.state.config[key];
        }
      }
      if (
        !supportsFormAutosave &&
        Object.hasOwn(values, 'mirror_dir') &&
        configStore.state.config.local_mirror_enabled !== values.local_mirror_enabled
      ) {
        accepted.local_mirror_enabled = configStore.state.config.local_mirror_enabled;
      }
    } else {
      cfg = {
        ...configStore.state.config,
        selected_notebooks: [...(configStore.state.config.selected_notebooks || [])],
      };
    }

    const page = buildSettingsPage(uiContext(), cfg);
    if (renderStatus) {
      page.status = renderStatus;
    }
    return { page, values: accepted };
  };

  const configValues = (cfg) => {
    const out = {};
    for (const [k, v] of Object.entries(cfg || {})) {
      if (supportsSystem && (k === 'git_token' || k === 'webdav_pass' || k === 'credential_refs')) {
        continue;
      }
      out[k] = v;
    }
    if (supportsSystem) {
      out.git_token = '';
      out.webdav_pass = '';
    }
    return out;
  };

  const isTargetDraftIncomplete = (cfg, proto) => {
    if (proto === 'local_mirror') {
      return !resolveMirrorDir(cfg, downloadsDir, homeDir);
    }
    if (proto === 'webdav') {
      return !String(cfg.webdav_url || '').trim();
    }
    if (proto === 'git') {
      return !String(cfg.git_remote || '').trim();
    }
    return false;
  };

  const hasConnectionFieldChanged = (prevCfg, nextCfg, proto) => {
    if (
      connConfigSignature(prevCfg, proto, downloadsDir, homeDir) !==
      connConfigSignature(nextCfg, proto, downloadsDir, homeDir)
    ) {
      return true;
    }
    if (!protocolEnabled(prevCfg, proto) && protocolEnabled(nextCfg, proto)) {
      return true;
    }
    if (proto === 'webdav' && nextCfg.webdav_pass && nextCfg.webdav_pass !== prevCfg.webdav_pass) {
      return true;
    }
    if (proto === 'git' && nextCfg.git_token && nextCfg.git_token !== prevCfg.git_token) {
      return true;
    }
    return false;
  };

  const handleAction = (params) => {
    const actionId = String(params.action_id || '');
    const isAutosave = String(params.trigger || '') === 'autosave';
    if (actionId === 'open_sync_settings') {
      if (supportsOpenSettings) {
        try {
          callHost('host.ui.open_settings', {});
        } catch (_err) {
          // Non-fatal.
        }
      }
      return { ok: true };
    }

    configStore.refreshKnownNotebooks();
    const values = params.values && typeof params.values === 'object' ? params.values : {};
    let ok = true;
    let tone = 'info';
    let status = '';

    if (actionId === 'save_config') {
      const prevCfg = configStore.state.config;
      const nextCfg = configStore.normalizeConfig(values);
      const proto = nextCfg.protocol;
      const enabledKey = PROTOCOL_ENABLED_KEYS[proto];
      const explicitDisable =
        Object.hasOwn(values, enabledKey) &&
        values[enabledKey] === false &&
        Boolean(prevCfg[enabledKey]);

      if (isAutosave && explicitDisable) {
        nextCfg[enabledKey] = false;
        const changed = changedProtocols(prevCfg, nextCfg);
        saveConfig(nextCfg, { clearPending: changed.size > 0 ? changed : false });
        configStore.clearConnState(proto);
        saveRuntime();
        syncAutoSyncScheduler();
        const pLabel = protocolLabel(getLocale(), proto);
        lastStatus = t(`已停用${pLabel}`, `${pLabel} disabled`);
        return {
          ok: true,
          tone: 'success',
          values: configValues(configStore.state.config),
          page: buildSettingsPage(uiContext(), configStore.state.config),
          status: '',
        };
      }

      if (
        isAutosave &&
        !protocolEnabled(nextCfg, proto) &&
        !protocolHasInput(nextCfg, proto, downloadsDir, homeDir)
      ) {
        const optionKeys = [
          'selected_notebooks',
          'conflict_policy',
          'auto_sync',
          'sync_interval',
          'max_file_size_mb',
          'ignore_patterns',
          'system_notifications',
        ];
        const optionsChanged = optionKeys.some(
          (k) => JSON.stringify(prevCfg[k]) !== JSON.stringify(nextCfg[k])
        );
        if (optionsChanged) {
          const mergedOptionsCfg = { ...prevCfg, protocol: proto };
          for (const k of optionKeys) {
            mergedOptionsCfg[k] = nextCfg[k];
          }
          const changed = changedProtocols(prevCfg, mergedOptionsCfg);
          saveConfig(mergedOptionsCfg, { clearPending: changed.size > 0 ? changed : false });
          syncAutoSyncScheduler();
          return {
            ok: true,
            tone: 'success',
            values: configValues(configStore.state.config),
            page: buildSettingsPage(uiContext(), configStore.state.config),
            status: '',
          };
        }
        return { ok: true, tone: 'info', status: '' };
      }

      const hasOtherConfigured = VALID_PROTOCOLS.some(
        (p) =>
          p !== proto &&
          protocolEnabled(nextCfg, p) &&
          !protocolError(nextCfg, p, { ...uiContext(), requireNotebooks: false })
      );
      const clearingConfigured =
        hasOtherConfigured &&
        ((proto === 'webdav' && !nextCfg.webdav_url && Boolean(prevCfg.webdav_url)) ||
          (proto === 'git' && !nextCfg.git_remote && Boolean(prevCfg.git_remote)) ||
          (proto === 'local_mirror' && !nextCfg.mirror_dir && Boolean(prevCfg.mirror_dir)));

      const pErr = clearingConfigured
        ? ''
        : protocolError(nextCfg, proto, { ...uiContext(), requireNotebooks: false });
      if (pErr) {
        if (isAutosave) {
          const optionKeys = [
            'max_file_size_mb',
            'ignore_patterns',
            'conflict_policy',
            'auto_sync',
            'sync_interval',
            'system_notifications',
          ];
          const optionsChanged = optionKeys.some(
            (k) => JSON.stringify(prevCfg[k]) !== JSON.stringify(nextCfg[k])
          );
          if (optionsChanged) {
            const mergedOptionsCfg = { ...prevCfg };
            for (const k of optionKeys) mergedOptionsCfg[k] = nextCfg[k];
            const changed = changedProtocols(prevCfg, mergedOptionsCfg);
            saveConfig(mergedOptionsCfg, { clearPending: changed.size > 0 ? changed : false });
            syncAutoSyncScheduler();
          }
          if (!protocolEnabled(nextCfg, proto) || isTargetDraftIncomplete(nextCfg, proto)) {
            return { ok: true, tone: 'info', status: '' };
          }
          return { ok: false, tone: 'danger', status: pErr };
        }
        lastStatus = pErr;
        return {
          ok: false,
          tone: 'danger',
          values: configValues(nextCfg),
          page: buildSettingsPage(uiContext(), nextCfg),
          status: pErr,
        };
      }

      if (clearingConfigured) {
        nextCfg[enabledKey] = false;
      } else if (
        !protocolEnabled(nextCfg, proto) &&
        (!Object.hasOwn(values, enabledKey) ||
          !protocolHasInput(prevCfg, proto, downloadsDir, homeDir))
      ) {
        nextCfg[enabledKey] = true;
      }
      const connChanged = hasConnectionFieldChanged(prevCfg, nextCfg, proto);
      const changed = changedProtocols(prevCfg, nextCfg);
      saveConfig(nextCfg, { clearPending: changed.size > 0 ? changed : false });
      syncAutoSyncScheduler();

      if (isAutosave) {
        if (clearingConfigured) {
          configStore.clearConnState(proto);
          saveRuntime();
        } else if (connChanged && protocolEnabled(configStore.state.config, proto)) {
          emitProgress({
            channel: proto,
            label: t('已保存 · 正在检测连接…', 'Saved · Checking connection…'),
            tone: 'accent',
            running: true,
          });
          runTestConn(configStore.state.config);
          saveRuntime();
        }
        return {
          ok: true,
          tone: 'success',
          values: configValues(configStore.state.config),
          page: buildSettingsPage(uiContext(), configStore.state.config),
          status: '',
        };
      }

      const pLabel = protocolLabel(getLocale(), proto);
      status = clearingConfigured
        ? t(`已停用${pLabel}同步`, `${pLabel} sync disabled`)
        : t('已保存同步目标配置', 'Sync destination saved');
      lastStatus = status;
      ok = true;
      tone = 'success';
    } else if (actionId === 'forget_credential' && supportsSystem) {
      const draft = configStore.normalizeConfig(values);
      const proto = draft.protocol;
      const field = proto === 'git' ? 'git_token' : proto === 'webdav' ? 'webdav_pass' : null;
      const cur = configStore.state.config;
      if (
        field &&
        (cur[field] || (cur.credential_refs && cur.credential_refs[field])) &&
        credentialTarget(draft, field) === credentialTarget(cur, field)
      ) {
        saveConfig(null, { forget: field, clearPending: new Set([proto]) });
        configStore.clearConnState(proto);
        saveRuntime();
        status = configStore.state.credentialCleanup.size > 0
          ? t(
              '已取消使用此目标的凭据，系统凭据库中的删除将重试',
              'Sync will stop using this credential. Deletion from the system store will be retried.'
            )
          : t('已清除此目标的同步凭据', 'Sync credential cleared for this destination');
        tone = 'success';
      } else {
        status = t('请先保存同步目标和账号', 'Save the sync destination and account first');
        return {
          ok: false,
          tone: 'warning',
          status,
          page: buildSettingsPage(uiContext(), draft),
          values: configValues(draft),
        };
      }
      lastStatus = status;
    } else if (actionId === 'test_conn') {
      const nextCfg = configStore.normalizeConfig(values);
      const [testOk, testMsg] = runTestConn(nextCfg);
      saveRuntime();
      return {
        ok: testOk,
        tone: testOk ? 'success' : 'danger',
        page: buildSettingsPage(uiContext(), nextCfg),
        status: testMsg,
      };
    } else if (
      actionId === 'sync_local_mirror' ||
      actionId === 'sync_webdav' ||
      actionId === 'sync_git'
    ) {
      const proto = actionId.slice('sync_'.length);
      if (Object.keys(values).length > 0) {
        const nextCfg = configStore.normalizeConfig(values);
        nextCfg.protocol = proto;
        const err = protocolError(nextCfg, proto, { ...uiContext(), requireNotebooks: true });
        if (err) {
          lastStatus = err;
          return {
            ok: false,
            tone: 'danger',
            values: configValues(nextCfg),
            page: buildSettingsPage(uiContext(), nextCfg),
            status: err,
          };
        }
        if (JSON.stringify(nextCfg) !== JSON.stringify(configStore.state.config)) {
          const changed = changedProtocols(configStore.state.config, nextCfg);
          saveConfig(nextCfg, { clearPending: changed.size > 0 ? changed : false });
        }
      }
      const err = protocolError(configStore.state.config, proto, {
        ...uiContext(),
        requireNotebooks: true,
      });
      if (!protocolEnabled(configStore.state.config, proto)) {
        const pLabel = protocolLabel(getLocale(), proto);
        status = t(`请先启用${pLabel}`, `Enable ${pLabel} first`);
        lastStatus = status;
        ok = false;
        tone = 'warning';
      } else if (err || configStore.selectedNotebooks(configStore.state.config).length === 0) {
        status = err || t('请至少选择一个笔记本', 'Select at least one notebook');
        lastStatus = status;
        ok = false;
        tone = 'danger';
      } else if (configStore.getPendingConfirm(proto)) {
        status = t('请先确认或取消已暂停的同步', 'Confirm or cancel the paused sync first');
        lastStatus = status;
        ok = false;
        tone = 'warning';
      } else {
        status = runSync({ reportProgress: true, protocol: proto });
        if (configStore.getPendingConfirm(proto)) {
          ok = true;
          tone = 'warning';
        } else {
          ok = true;
          tone = 'success';
        }
      }
    } else if (actionId === 'sync_now') {
      if (Object.keys(values).length > 0) {
        const nextCfg = configStore.normalizeConfig(values);
        for (const p of VALID_PROTOCOLS) {
          if (
            protocolEnabled(nextCfg, p) &&
            protocolHasInput(nextCfg, p, downloadsDir, homeDir)
          ) {
            const pErr = protocolError(nextCfg, p, { ...uiContext(), requireNotebooks: false });
            if (pErr) {
              lastStatus = pErr;
              return {
                ok: false,
                tone: 'danger',
                values: configValues(nextCfg),
                page: buildSettingsPage(uiContext(), nextCfg),
                status: pErr,
              };
            }
          }
        }
        if (!configuredProtocols(nextCfg, uiContext()).length) {
          const anyEnabled = VALID_PROTOCOLS.some((p) => protocolEnabled(nextCfg, p));
          const err = anyEnabled
            ? targetError(nextCfg, uiContext())
            : t('请先启用至少一个同步目标', 'Enable at least one sync destination first');
          lastStatus = err;
          return {
            ok: false,
            tone: 'danger',
            values: configValues(nextCfg),
            page: buildSettingsPage(uiContext(), nextCfg),
            status: err,
          };
        }
        if (JSON.stringify(nextCfg) !== JSON.stringify(configStore.state.config)) {
          const changed = changedProtocols(configStore.state.config, nextCfg);
          saveConfig(nextCfg, { clearPending: changed.size > 0 ? changed : false });
        }
      }

      const activeProtocols = configuredProtocols(configStore.state.config, uiContext());
      const selectedNbs = configStore.selectedNotebooks(configStore.state.config);
      if (activeProtocols.length === 0) {
        const anyEnabled = VALID_PROTOCOLS.some((p) => protocolEnabled(configStore.state.config, p));
        status = anyEnabled
          ? targetError(configStore.state.config, uiContext())
          : t('请先启用至少一个同步目标', 'Enable at least one sync destination first');
        lastStatus = status;
        ok = false;
        tone = 'danger';
      } else if (selectedNbs.length === 0) {
        status = t('请至少选择一个笔记本', 'Select at least one notebook');
        lastStatus = status;
        ok = false;
        tone = 'danger';
      } else {
        const nbErr = protocolError(configStore.state.config, activeProtocols[0], {
          ...uiContext(),
          requireNotebooks: true,
        });
        if (nbErr) {
          status = nbErr;
          lastStatus = status;
          ok = false;
          tone = 'danger';
        } else if (activeProtocols.length === 1) {
          const onlyProto = activeProtocols[0];
          if (configStore.getPendingConfirm(onlyProto)) {
            status = t('请先确认或取消已暂停的同步', 'Confirm or cancel the paused sync first');
            lastStatus = status;
            ok = false;
            tone = 'warning';
          } else {
            status = runSync({ reportProgress: true, protocol: onlyProto });
            if (configStore.getPendingConfirm(onlyProto)) {
              ok = true;
              tone = 'warning';
            } else {
              ok = true;
              tone = 'success';
            }
          }
        } else {
          [ok, tone, status] = runMultiProtocolSync(activeProtocols, true);
        }
      }
    } else if (actionId === 'confirm_sync' || actionId === 'confirm_sync_card') {
      let draftProto = configStore.state.config.protocol || 'local_mirror';
      if (Object.keys(values).length > 0) {
        const draftCfg = configStore.normalizeConfig(values);
        draftProto = draftCfg.protocol || draftProto;
        if (!configMatchesSaved(draftCfg, configStore.state.config)) {
          status = t(
            '同步配置有未保存修改，请先保存或点击「立即同步」重新预览',
            'Sync settings have unsaved edits; save them or click Sync Now to review the new target'
          );
          lastStatus = status;
          return {
            ok: false,
            tone: 'warning',
            page: buildSettingsPage(uiContext(), draftCfg),
            status,
          };
        }
      }

      const pc = configStore.getPendingConfirm(draftProto) || configStore.getPendingConfirm();
      if (!pc || pc.scope_key !== configStore.resultKey()) {
        status = t(
          '待确认的同步计划已失效，请重新点击「立即同步」',
          'The pending sync confirmation expired; click Sync Now to review again'
        );
        lastStatus = status;
        ok = false;
        tone = 'warning';
      } else {
        const protocol = pc.protocol || configStore.state.config.protocol || 'local_mirror';
        logProtocol = protocol;
        const protoCfg = cfgForProtocol(configStore.state.config, protocol);
        let notebooks = configStore.selectedNotebooks(protoCfg);
        const onlyPath = pc.only_path || null;
        const onlyNbRoot = pc.only_nb_root || null;
        if (onlyNbRoot) {
          if (!notebooks.includes(onlyNbRoot)) {
            configStore.clearPendingConfirm(protocol);
            saveRuntime({ clearPending: true, protocol });
            lastStatus = t(
              '待确认的笔记本已移除，请重新同步',
              'The pending notebook was removed. Start sync again.'
            );
            return {
              ok: false,
              tone: 'warning',
              page: buildSettingsPage(uiContext()),
              status: lastStatus,
            };
          }
          notebooks = [onlyNbRoot];
        }

        let batch;
        try {
          batch = computeBatchPlanForProtocol(protocol, protoCfg, notebooks, { onlyPath });
        } catch (exc) {
          const pLabel = protocolLabel(getLocale(), protocol);
          const msg = t(
            `${pLabel}同步未完成: ${errorDetail(getLocale(), exc)}`,
            `${pLabel} sync failed: ${errorDetail(getLocale(), exc)}`
          );
          appendLog(t(`${pLabel}同步`, `${pLabel} sync`), '失败', {
            tone: 'danger',
            tooltip: msg,
          });
          recordResult('失败', msg, { protocol });
          saveRuntime({ onlyPath, notebookRoot: onlyNbRoot, protocol });
          lastStatus = msg;
          throw syncFailure(msg);
        }

        if (batch.remote_error) {
          const bProto = batch.protocol || protocol;
          const pLabel = protocolLabel(getLocale(), bProto);
          const msg = batch.remote_error;
          appendLog(t(`${pLabel}同步`, `${pLabel} sync`), '失败', {
            tone: 'danger',
            tooltip: msg,
          });
          recordResult('失败', msg, { protocol: bProto, target: batch.target_display || '' });
          saveRuntime({ onlyPath, notebookRoot: onlyNbRoot, protocol });
          lastStatus = msg;
          throw syncFailure(msg);
        }

        if (batch.fingerprint !== pc.fingerprint) {
          const reasonItems = assessBatchForProtocol(protocol, batch, protoCfg);
          if (reasonItems.length > 0) {
            const nextPc = buildPendingForProtocol(protocol, batch, reasonItems, {
              onlyPath,
              onlyNbRoot,
            });
            configStore.setPendingConfirm(nextPc);
            appendLog(formatReasonItem(getLocale(), reasonItems[0]), '待确认', {
              tone: 'warning',
              tooltip: t(
                '同步计划已变化，请重新确认',
                'The sync plan changed. Review and confirm it again.'
              ),
              logKey: 'confirm_required',
              logArgs: { reason_item: reasonItems[0], protocol },
            });
            recordResult(
              '待确认',
              t('同步计划已变化，请重新确认', 'The sync plan changed. Review and confirm it again.'),
              { protocol: batch.protocol || protocol, target: batch.target_display || '' }
            );
            saveRuntime({ protocol });
            status = t('同步计划已变化，请重新确认', 'The sync plan changed. Review and confirm it again.');
            lastStatus = status;
            ok = false;
            tone = 'warning';
          } else {
            configStore.clearPendingConfirm(protocol);
            appendLog(t('同步计划已变化', 'The sync plan changed'), '已更新', {
              tone: 'info',
              tooltip: t(
                '原危险变更已消除，请重新同步',
                'The original risks are gone. Start sync again.'
              ),
              logKey: 'plan_changed',
            });
            recordResult(
              '已更新',
              t('同步计划已变化，请重新同步', 'The sync plan changed. Start sync again.'),
              { protocol: batch.protocol || protocol, target: batch.target_display || '' }
            );
            saveRuntime({ clearPending: true, protocol });
            status = t('同步计划已变化，请重新同步', 'The sync plan changed. Start sync again.');
            lastStatus = status;
            ok = false;
            tone = 'info';
          }
        } else {
          const err = protocolError(configStore.state.config, protocol, {
            ...uiContext(),
            requireNotebooks: true,
          });
          if (err || configStore.selectedNotebooks(configStore.state.config).length === 0) {
            configStore.clearPendingConfirm(protocol);
            saveRuntime({ clearPending: true, protocol });
            status = err || t('请至少选择一个笔记本', 'Select at least one notebook');
            lastStatus = status;
            ok = false;
            tone = 'danger';
          } else {
            status = runSync({
              onlyPath,
              onlyNbRoot,
              confirmed: true,
              approvedBatch: batch,
              reportProgress: true,
              protocol,
            });
            ok = true;
            tone = 'success';
          }
        }
      }
    } else if (actionId === 'cancel_confirm') {
      const draftProto =
        Object.keys(values).length > 0
          ? configStore.normalizeConfig(values).protocol
          : configStore.state.config.protocol;
      const pc = configStore.getPendingConfirm(draftProto) || configStore.getPendingConfirm();
      const proto = (pc && pc.protocol) || configStore.state.config.protocol || 'local_mirror';
      configStore.clearPendingConfirm(proto);
      logProtocol = proto;
      appendLog(t('危险变更同步', 'Sync with risky changes'), '已取消', {
        tone: 'info',
        tooltip: t('用户已取消本次同步', 'The user canceled this sync'),
        logKey: 'sync_canceled',
      });
      recordResult(
        '已取消',
        t('用户已取消危险变更', 'The user canceled the risky changes'),
        { protocol: proto }
      );
      saveRuntime({ clearPending: true, protocol: proto });
      status = t('已取消本次同步', 'Sync canceled');
      lastStatus = status;
      ok = true;
      tone = 'info';
    } else {
      status = t('已完成操作', 'Action complete');
      lastStatus = status;
      ok = true;
      tone = 'info';
    }

    const res = {
      ok,
      tone,
      values: configValues(configStore.state.config),
      page: buildSettingsPage(uiContext(), configStore.state.config),
      status,
    };
    const syncActionIds = new Set([
      'sync_now',
      'sync_local_mirror',
      'sync_webdav',
      'sync_git',
      'confirm_sync',
      'confirm_sync_card',
    ]);
    if (syncActionIds.has(actionId) && lastSyncedNotebooks.length > 0) {
      res.synced_notebooks = [...lastSyncedNotebooks];
    }
    return res;
  };

  const handleEvent = (params) => {
    const eventName = String(params.event || '');

    if (eventName === 'locale.changed') {
      const nextLoc = normalizeLocale(params.locale || getLocale());
      locale = nextLoc;
      if (configStore) configStore.state.locale = nextLoc;
      lastStatus = '';
      rebuildEngines();
      return { handled: true, locale: nextLoc };
    }

    if (eventName === 'notebook.renamed') {
      const renamed = configStore.onNotebookRenamed(params);
      if (renamed.activeRenamed && renamed.newPath) {
        notebookRoot = renamed.newPath;
      }
      if (renamed.oldPath) {
        clearRecoveryDirCache(callHost, renamed.oldPath);
      }
      if (renamed.newPath) {
        try {
          migrateLegacyRecoveryDirs(callHost, renamed.newPath, {
            dataDir,
            extraHashRoots: renamed.oldPath ? [renamed.oldPath] : [],
          });
        } catch (_err) {
          // Best-effort migration.
        }
      }
      lastStatus = '';
      rebuildEngines();
      syncAutoSyncScheduler();
      return { handled: true, outcome: 'updated' };
    }

    if (eventName === 'notebook.removed') {
      configStore.onNotebookRemoved();
      syncAutoSyncScheduler();
      return { handled: true, outcome: 'skipped' };
    }

    if (eventName === 'plugin.credentials_migrate') {
      return { handled: true, outcome: configStore.migrateCredentials() };
    }

    if (eventName === SYNC_INTERVAL_EVENT) {
      runInitialMaintenance();
      return syncAfterSystemEvent(eventName, params);
    }

    if (
      (eventName === 'app.focus' ||
        eventName === 'system.wake' ||
        eventName === 'network.changed' ||
        eventName === 'plugin.notifications_retry') &&
      Object.keys(configStore.state.pendingNotices || {}).length > 0
    ) {
      retryResultNotices();
    }

    if (eventName === 'app.focus' || eventName === 'plugin.notifications_retry') {
      return { handled: true, outcome: 'skipped' };
    }

    if (
      eventName === 'system.wake' ||
      eventName === 'network.changed' ||
      eventName === LEGACY_SYNC_INTERVAL_EVENT
    ) {
      return syncAfterSystemEvent(eventName, params);
    }

    if (eventName !== 'note.saved' && eventName !== 'note.deleted') {
      return { handled: false };
    }

    const relPath = String(params.path || '').replace(/\\/g, '/');
    const folder = String(params.folder || '').replace(/\\/g, '/').replace(/^\/+|\/+$/g, '');
    const eventNb = normAbsPath(params.notebook_root || notebookRoot, homeDir);
    const localDir = eventNb || notebookRoot;
    const nbKey = configStore.notebookKey(localDir);
    let outcome = 'skipped';
    const eventScopeCi = Boolean(localDir && dirIsCaseInsensitive(callHost, localDir));

    let shouldSync;
    let syncOnlyPath;
    if (eventName === 'note.deleted') {
      const cleanRel = relPath.replace(/^\/+|\/+$/g, '');
      if (recordDeletedEventTombstones(nbKey, localDir, cleanRel, folder)) {
        saveRuntime({
          onlyPath: cleanRel && !folder ? cleanRel : null,
          notebookRoot: localDir,
        });
      }
      shouldSync =
        Boolean(configStore.state.config.auto_sync) &&
        (folder
          ? isSafeRelPath(folder)
          : isSafeRelMd(cleanRel) &&
            matchesScope(cleanRel, configStore.state.config.sync_scope || 'all', {
              caseInsensitive: eventScopeCi,
            }));
      syncOnlyPath = folder ? null : cleanRel;
    } else {
      shouldSync =
        Boolean(configStore.state.config.auto_sync) &&
        isSafeRelMd(relPath) &&
        matchesScope(relPath, configStore.state.config.sync_scope || 'all', {
          caseInsensitive: eventScopeCi,
        });
      syncOnlyPath = relPath;
    }

    if (shouldSync) {
      configStore.refreshKnownNotebooks();
      const activeProtocols = configuredProtocols(configStore.state.config, uiContext());
      const selected = configStore.selectedNotebooks(configStore.state.config);
      if (
        activeProtocols.length > 0 &&
        (!supportsMultiNotebook || (eventNb && selected.includes(eventNb)))
      ) {
        const outcomes = new Set();
        let lastExc = null;
        for (const proto of activeProtocols) {
          if (
            protocolError(configStore.state.config, proto, {
              ...uiContext(),
              requireNotebooks: true,
            })
          ) {
            continue;
          }
          if (configStore.getPendingConfirm(proto)) {
            outcomes.add('pending_confirm');
            continue;
          }
          try {
            runBackgroundSync({
              onlyPath: syncOnlyPath,
              onlyNbRoot: eventNb || null,
              protocol: proto,
            });
            outcomes.add(lastSyncOutcome);
          } catch (exc) {
            if (exc instanceof SyncStateError) {
              outcomes.add('state_error');
            } else {
              outcomes.add('failed');
            }
            lastExc = exc;
          }
        }
        outcome =
          ['state_error', 'failed', 'pending_confirm', 'synced'].find((v) => outcomes.has(v)) ||
          'skipped';
        if ((outcome === 'state_error' || outcome === 'failed') && activeProtocols.length === 1 && lastExc) {
          throw lastExc;
        }
      }
    }

    return { handled: true, outcome };
  };

  return (method, params) => {
    try {
      if (method === 'plugin.initialize') {
        return handleInitialize(params);
      }
      if (!configStore) {
        throw new Error('plugin is not initialized');
      }
      if (method === 'plugin.render') {
        return handleRender(params);
      }
      if (method === 'plugin.action') {
        return handleAction(params);
      }
      if (method === 'plugin.event') {
        return handleEvent(params);
      }
      if (method === 'plugin.shutdown') {
        return { ok: true };
      }
      throw new Error(`unsupported method: ${method}`);
    } catch (err) {
      const msg = localizeError(getLocale(), err && err.message ? err.message : String(err));
      if (err && typeof err === 'object' && 'code' in err) {
        throw err;
      }
      throw new Error(msg);
    } finally {
      hostLogScope = ['', ''];
      flushHostLog();
    }
  };
}

serve(createSyncController());
