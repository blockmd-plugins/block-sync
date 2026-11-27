/**
 * Declarative settings_page builder, protocol/target validation, timeline
 * aggregation, and dangerous-change preview cards for block-sync.
 * Pure ES2023, QuickJS-NG compatible (zero Node built-in dependencies).
 */

import {
  LOG_STATUS_EN,
  tr,
  hasChineseText,
  isEnglishLocale,
  protocolLabel,
  formatReasonItem,
  formatSampleItem,
  logForPage,
  formatShortSyncMetric,
  localizeResultSummary,
  normalizeLog,
} from './i18n.js';
import {
  formatHm,
  posixBasename,
  displayPath,
  hasEmbeddedUrlCredentials,
  normalizeHttpUrl,
  pathsOverlap,
  sanitizeUrlForDisplay,
} from './utils.js';
import {
  VALID_PROTOCOLS,
  PROTOCOL_ENABLED_KEYS,
  resolveMirrorDir,
  cfgForProtocol,
  protocolHasInput,
  protocolEnabled,
  configMatchesSaved,
  credentialPlaceholder,
  notebookLabel,
} from './config.js';
import { webdavBaseUrl } from './webdav.js';
import { isRemoteGitUrl, gitBranch, resolveLocalGitDir } from './git_sync.js';

export function syncButtonFeedback(locale) {
  return {
    busy_label: tr(locale, '同步中…', 'Syncing…'),
    success_label: tr(locale, '已同步', 'Synced'),
    error_label: tr(locale, '同步失败', 'Sync Failed'),
    retry_label: tr(locale, '重试同步', 'Retry Sync'),
  };
}

export function testButtonFeedback(locale) {
  return {
    busy_label: tr(locale, '测试中…', 'Testing…'),
    success_label: tr(locale, '已连通', 'Connected'),
    error_label: tr(locale, '未连通', 'Connection Failed'),
    retry_label: tr(locale, '重新测试', 'Retry'),
  };
}

export function targetError(
  cfg,
  {
    callHost = null,
    configStore = null,
    locale = 'zh',
    dataDir = '',
    homeDir = '',
    downloadsDir = '',
    notebookRoot = '',
    supportsMultiNotebook = true,
    requireNotebooks = true,
  } = {}
) {
  const c = cfg || {};
  const loc = configStore ? configStore.state.locale : locale;
  const hDir = configStore ? configStore.state.homeDir : homeDir;
  const dlDir = configStore ? configStore.state.downloadsDir : downloadsDir;
  const nbRoot = configStore ? configStore.state.notebookRoot : notebookRoot;
  const multi = configStore ? configStore.state.supportsMultiNotebook : supportsMultiNotebook;
  const selected = configStore
    ? configStore.selectedNotebooks(c)
    : Array.isArray(c.selected_notebooks)
      ? c.selected_notebooks
      : [];

  if (requireNotebooks && multi && selected.length === 0) {
    return tr(loc, '请至少选择一个笔记本', 'Select at least one notebook');
  }
  for (let i = 0; i < selected.length; i += 1) {
    const nb = selected[i];
    for (let j = 0; j < i; j += 1) {
      const prevNb = selected[j];
      if (pathsOverlap(prevNb, nb)) {
        const prevLbl = notebookLabel(prevNb, loc, nbRoot, hDir);
        const curLbl = notebookLabel(nb, loc, nbRoot, hDir);
        return tr(
          loc,
          `笔记本「${prevLbl}」与「${curLbl}」的本地目录重叠，请取消其中一个`,
          `Local folders for ${prevLbl} and ${curLbl} overlap; deselect one`
        );
      }
    }
  }

  const rootsToCheck = selected.length > 0 ? selected : nbRoot ? [nbRoot] : [];
  const protocol = c.protocol || 'local_mirror';

  if (protocol === 'webdav') {
    const rawUrl = String(c.webdav_url || '').trim();
    if (rawUrl && hasEmbeddedUrlCredentials(rawUrl, false)) {
      return tr(
        loc,
        '请不要在 WebDAV 地址中内嵌账号密码，改用下方认证字段填写',
        'Do not embed credentials in the WebDAV URL; use the username and password fields instead'
      );
    }
    if (!webdavBaseUrl(c)) {
      return tr(loc, '请填写有效的 WebDAV 地址', 'Enter a valid WebDAV address');
    }
  } else if (protocol === 'git') {
    const rawRemote = String(c.git_remote || '').trim();
    if (!rawRemote) {
      return tr(loc, '请填写 Git 仓库地址', 'Enter a Git repository address');
    }
    if (isRemoteGitUrl(rawRemote)) {
      if (hasEmbeddedUrlCredentials(rawRemote, true)) {
        return tr(
          loc,
          '请不要在 Git 仓库地址中内嵌账号或令牌，改用下方认证方式填写',
          'Do not embed credentials in the Git URL; use the authentication fields instead'
        );
      }
      if (/^https?:\/\//i.test(rawRemote) && !normalizeHttpUrl(rawRemote)) {
        return tr(loc, '请填写有效的 Git HTTP(S) 仓库地址', 'Enter a valid Git HTTP(S) repository URL');
      }
    } else {
      let localGit = rawRemote;
      try {
        localGit = resolveLocalGitDir(callHost, c, {
          dataDir,
          nbRoot: rootsToCheck[0] || nbRoot,
          homeDir: hDir,
          locale: loc,
        });
      } catch (_err) {
        localGit = rawRemote;
      }
      for (const nb of rootsToCheck) {
        if (pathsOverlap(nb, localGit)) {
          const lbl = notebookLabel(nb, loc, nbRoot, hDir);
          return tr(
            loc,
            `Git 本地仓库目录不能与笔记本「${lbl}」重叠`,
            `The local Git folder cannot overlap with notebook ${lbl}`
          );
        }
      }
    }
  } else if (protocol === 'local_mirror') {
    const target = resolveMirrorDir(c, dlDir, hDir);
    if (!target) {
      return tr(loc, '请先选择同步文件夹', 'Select a sync folder first');
    }
    for (const nb of rootsToCheck) {
      if (pathsOverlap(nb, target)) {
        const lbl = notebookLabel(nb, loc, nbRoot, hDir);
        return tr(
          loc,
          `同步文件夹不能与笔记本「${lbl}」重叠`,
          `The sync folder cannot overlap with notebook ${lbl}`
        );
      }
    }
  }

  return '';
}

export function protocolError(cfg, protocol, opts = {}) {
  return targetError(cfgForProtocol(cfg, protocol), opts);
}

export function configuredProtocols(cfg, opts = {}) {
  const c = cfg || {};
  return VALID_PROTOCOLS.filter(
    (p) => protocolEnabled(c, p) && !protocolError(c, p, { ...opts, requireNotebooks: false })
  );
}

export function targetDisplay(
  cfg,
  {
    callHost = null,
    configStore = null,
    locale = 'zh',
    dataDir = '',
    homeDir = '',
    downloadsDir = '',
    notebookRoot = '',
  } = {}
) {
  const c = cfg || {};
  const loc = configStore ? configStore.state.locale : locale;
  const hDir = configStore ? configStore.state.homeDir : homeDir;
  const dlDir = configStore ? configStore.state.downloadsDir : downloadsDir;
  const nbRoot = configStore ? configStore.state.notebookRoot : notebookRoot;
  const protocol = c.protocol || 'local_mirror';

  if (protocol === 'local_mirror') {
    return resolveMirrorDir(c, dlDir, hDir);
  }
  if (protocol === 'webdav') {
    return sanitizeUrlForDisplay(webdavBaseUrl(c)) || tr(loc, '未配置 WebDAV 地址', 'WebDAV address is missing');
  }
  const target = sanitizeUrlForDisplay(c.git_remote || '');
  const branch = gitBranch(c);
  let repoDir = '';
  try {
    repoDir = resolveLocalGitDir(callHost, c, {
      dataDir,
      nbRoot,
      homeDir: hDir,
      locale: loc,
    });
  } catch (_err) {
    repoDir = c.git_remote || '';
  }
  return target ? `${target} (${branch})` : `${repoDir} (${branch})`;
}

export function entryMatchesProtocol(entry, protocol) {
  if (!entry || typeof entry !== 'object') return false;
  const pid = String(entry.protocol_id || '').trim();
  if (pid) return pid === protocol;
  const label = String(entry.protocol || '').trim();
  const aliases = {
    local_mirror: ['目录镜像', 'Local mirror', '本地目录镜像'],
    webdav: ['WebDAV'],
    git: ['Git 仓库', 'Git repository'],
  }[protocol] || [];
  return aliases.includes(label);
}

export function getLastResult(configStore) {
  if (!configStore) return null;
  const res = configStore.state.notebookResults || {};
  return res[configStore.resultKey()] || res[configStore.notebookKey()] || null;
}

export function getProtocolResult(configStore, protocol) {
  const last = getLastResult(configStore);
  if (!last || typeof last !== 'object') return {};
  if (last.protocols && typeof last.protocols === 'object' && last.protocols[protocol] && typeof last.protocols[protocol] === 'object') {
    return last.protocols[protocol];
  }
  if (entryMatchesProtocol(last, protocol)) {
    return last;
  }
  return {};
}

export function logsForProtocol(logs, protocol = null) {
  const list = Array.isArray(logs) ? logs : [];
  if (!protocol) return list;
  const out = [];
  for (const entry of list) {
    if (!entry || typeof entry !== 'object') continue;
    const norm = normalizeLog(entry);
    const pid = norm.protocol_id || '';
    if (!pid || pid === protocol) {
      out.push(entry);
    }
  }
  return out;
}

function parseHmsSeconds(timeStr) {
  const m = String(timeStr || '').trim().match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
  if (!m) return null;
  return Number.parseInt(m[1], 10) * 3600 + Number.parseInt(m[2], 10) * 60 + Number.parseInt(m[3] || '0', 10);
}

function formatQuietDuration(locale, seconds) {
  const secs = Math.max(0, Number.parseInt(seconds || 0, 10) || 0);
  if (secs < 60) return '';
  if (secs < 3600) {
    const mins = Math.max(1, Math.round(secs / 60));
    return tr(locale, `${mins} 分钟`, `${mins} min`);
  }
  const hrs = Math.floor(secs / 3600);
  const mins = Math.floor((secs % 3600) / 60);
  if (mins > 0) {
    return tr(locale, `${hrs} 小时 ${mins} 分钟`, `${hrs}h ${mins}m`);
  }
  return tr(locale, `${hrs} 小时`, `${hrs} hr`);
}

function isNoopEntry(entry) {
  if (!entry || typeof entry !== 'object') return false;
  if (entry.log_key === 'sync_noop') return true;
  return normalizeLog(entry).status === '无变更';
}

const BATCHABLE_LOG_KEYS = new Set([
  'push_new',
  'push_update',
  'push_overwrite',
  'pull_new',
  'pull_update',
  'pull_overwrite',
  'assets_synced',
]);

function isBatchableChange(entry) {
  return Boolean(entry && typeof entry === 'object' && BATCHABLE_LOG_KEYS.has(entry.log_key));
}

export function buildTimelineEntries(logs, locale, { protocol = null, limit = 8 } = {}) {
  const rawLogs = logsForProtocol(logs, protocol);
  const out = [];
  let i = 0;
  const n = rawLogs.length;

  while (i < n && out.length < limit) {
    const entry = rawLogs[i];

    // 1. Collapse consecutive no-change checks into a single quiet span.
    if (isNoopEntry(entry)) {
      let totalCount = 0;
      let firstTime = '';
      let lastTime = '';
      let firstTs = 0;
      let lastTs = 0;
      const checks = [];

      while (i < n && isNoopEntry(rawLogs[i])) {
        const cur = rawLogs[i];
        const args = cur.log_args && typeof cur.log_args === 'object' ? cur.log_args : {};
        const cCount = Math.max(1, Number.parseInt(args.count || 1, 10) || 1);
        totalCount += cCount;
        const cLast = String(args.last_time || cur.time || '').trim();
        const cFirst = String(args.first_time || cur.time || '').trim();
        if (!lastTime && cLast) lastTime = cLast;
        if (cFirst) firstTime = cFirst;
        const cLts = Number.parseInt(args.last_ts || 0, 10) || 0;
        const cFts = Number.parseInt(args.first_ts || 0, 10) || 0;
        if (cLts > lastTs) lastTs = cLts;
        if (cFts > 0 && (firstTs === 0 || cFts < firstTs)) firstTs = cFts;

        const cChecks = Array.isArray(args.checks) ? args.checks : null;
        if (cChecks && cChecks.length > 0) {
          for (const ck of cChecks) {
            const sCk = String(ck || '').trim();
            if (sCk && checks.length < 24) checks.push(sCk);
          }
        } else if (cLast && checks.length < 24) {
          checks.push(cLast);
        }
        i += 1;
      }

      if (!firstTime) firstTime = lastTime;
      let durSecs = 0;
      if (firstTs > 0 && lastTs >= firstTs) {
        durSecs = lastTs - firstTs;
      } else {
        const fs = parseHmsSeconds(firstTime);
        const ls = parseHmsSeconds(lastTime);
        if (fs !== null && ls !== null && ls >= fs) durSecs = ls - fs;
      }

      const durText = formatQuietDuration(locale, durSecs);
      const badge = durText
        ? tr(locale, `静默 ${durText}`, `Quiet ${durText}`)
        : tr(locale, '无改动', 'No changes');
      const title =
        totalCount === 1
          ? tr(locale, '1 次检查，无改动', '1 check, no changes')
          : tr(locale, `${totalCount} 次检查，无改动`, `${totalCount} checks, no changes`);
      const firstHm = formatHm(firstTime);
      const lastHm = formatHm(lastTime);
      const spanStr =
        totalCount > 1 && firstHm && lastHm && firstHm !== lastHm
          ? `${firstHm} → ${lastHm}`
          : lastTime || lastHm;

      const spanItem = {
        kind: 'span',
        time: lastHm || lastTime,
        badge,
        title,
        span: spanStr,
        tone: 'info',
      };
      if (checks.length > 1) {
        spanItem.details = checks.slice(0, 24);
      }
      out.push(spanItem);
      continue;
    }

    // 2. Group file & attachment changes from the same sync second into one timeline event.
    if (isBatchableChange(entry)) {
      const batchTime = String(entry.time || '').trim();
      let pushedNotes = 0;
      let pulledNotes = 0;
      let attachments = 0;
      const tags = [];
      const assetPrefixes = [];

      while (
        i < n &&
        isBatchableChange(rawLogs[i]) &&
        String(rawLogs[i].time || '').trim() === batchTime
      ) {
        const cur = rawLogs[i];
        const k = cur.log_key;
        const args = cur.log_args && typeof cur.log_args === 'object' ? cur.log_args : {};
        if (k === 'push_new' || k === 'push_update' || k === 'push_overwrite') {
          pushedNotes += 1;
          const p = String(args.path || '').trim();
          if (p && !tags.includes(p)) tags.push(p);
        } else if (k === 'pull_new' || k === 'pull_update' || k === 'pull_overwrite') {
          pulledNotes += 1;
          const p = String(args.path || '').trim();
          if (p && !tags.includes(p)) tags.push(p);
        } else if (k === 'assets_synced') {
          const cnt = Math.max(1, Number.parseInt(args.count || 1, 10) || 1);
          attachments += cnt;
          const pfx = String(args.prefix || '').trim().replace(/[/·\s]+$/g, '').trim();
          if (pfx && !assetPrefixes.includes(pfx)) assetPrefixes.push(pfx);
        }
        i += 1;
      }

      if (attachments > 0) {
        if (pushedNotes === 0 && pulledNotes === 0 && assetPrefixes.length > 0) {
          for (const pfx of assetPrefixes) {
            if (!tags.includes(pfx)) tags.push(pfx);
          }
        } else {
          tags.push(
            tr(
              locale,
              `${attachments} 个附件`,
              attachments === 1 ? '1 attachment' : `${attachments} attachments`
            )
          );
        }
      }

      const noteParts = [];
      if (pushedNotes > 0 && pulledNotes === 0) {
        noteParts.push(
          tr(
            locale,
            `推送 ${pushedNotes} 篇笔记`,
            pushedNotes === 1 ? 'Pushed 1 note' : `Pushed ${pushedNotes} notes`
          )
        );
      } else if (pulledNotes > 0 && pushedNotes === 0) {
        noteParts.push(
          tr(
            locale,
            `拉取 ${pulledNotes} 篇笔记`,
            pulledNotes === 1 ? 'Pulled 1 note' : `Pulled ${pulledNotes} notes`
          )
        );
      } else if (pushedNotes > 0 && pulledNotes > 0) {
        const totalN = pushedNotes + pulledNotes;
        noteParts.push(tr(locale, `同步 ${totalN} 篇笔记`, `Synced ${totalN} notes`));
      }

      if (attachments > 0) {
        if (noteParts.length > 0) {
          noteParts.push(
            tr(
              locale,
              `${attachments} 个附件`,
              attachments === 1 ? '1 attachment' : `${attachments} attachments`
            )
          );
        } else {
          noteParts.push(
            tr(
              locale,
              `同步 ${attachments} 个附件`,
              attachments === 1 ? 'Synced 1 attachment' : `Synced ${attachments} attachments`
            )
          );
        }
      }

      const ev = {
        kind: 'event',
        time: formatHm(batchTime) || batchTime,
        title: noteParts.length > 0 ? noteParts.join(' · ') : tr(locale, '同步完成', 'Sync complete'),
        tone: 'success',
      };
      if (tags.length > 0) ev.tags = tags.slice(0, 12);
      if (batchTime) ev.tooltip = batchTime;
      out.push(ev);
      continue;
    }

    // 3. Single event.
    const item = logForPage(locale, entry);
    const tone = item.tone || 'info';
    const title = item.title || '';
    const status = item.status || '';
    const subText = item.tooltip || '';
    const evTime = formatHm(item.time || '') || item.time || '';
    const ev = {
      kind: 'event',
      time: evTime,
      title,
      tone,
    };
    if (tone === 'danger') {
      if (isEnglishLocale(locale)) {
        if (!title.toLowerCase().includes('fail')) {
          ev.title = `${title} failed`;
        }
      } else if (!title.includes('失败') && !title.includes('未连通')) {
        ev.title = `${title}失败`;
      }
    } else if (status && tone !== 'success') {
      ev.status = status;
    }
    if (subText) ev.sub_text = subText;
    out.push(ev);
    i += 1;
  }
  return out;
}

export function buildConfirmationCard(pending, locale) {
  const reasonItems = Array.isArray(pending.reason_items) ? pending.reason_items : [];
  const reasonTexts = reasonItems.length > 0
    ? reasonItems.map((r) => formatReasonItem(locale, r))
    : [...(pending.reasons || [])];
  const nReasons = reasonTexts.length;

  const sampleItems = Array.isArray(pending.sample_items) ? pending.sample_items : [];
  const sampleTexts = (
    sampleItems.length > 0
      ? sampleItems.map((s) => formatSampleItem(locale, s))
      : [...(pending.sample_lines || [])]
  ).filter(Boolean);
  const totalSamples = Math.max(Number.parseInt(pending.total_samples || 0, 10) || 0, sampleTexts.length);

  // Fit strictly within Block's 10-line preview box without silent truncation.
  const maxLines = 10;
  const lines = [];
  const maxReasonLines = sampleTexts.length > 0 ? 4 : maxLines - 1;
  if (nReasons > maxReasonLines) {
    for (const r of reasonTexts.slice(0, maxReasonLines)) {
      lines.push(tr(locale, `[风险] ${r}`, `[Risk] ${r}`));
    }
    lines.push(
      tr(
        locale,
        `… 其余 ${nReasons - maxReasonLines} 项风险`,
        `… ${nReasons - maxReasonLines} more risks`
      )
    );
  } else {
    for (const r of reasonTexts) {
      lines.push(tr(locale, `[风险] ${r}`, `[Risk] ${r}`));
    }
  }

  const slotsLeft = Math.max(0, maxLines - lines.length);
  if (totalSamples > 0 && slotsLeft > 0) {
    if (totalSamples > slotsLeft) {
      const showN = Math.max(0, slotsLeft - 1);
      lines.push(...sampleTexts.slice(0, showN));
      const hidden = totalSamples - showN;
      lines.push(tr(locale, `… 其余 ${hidden} 项变更`, `… ${hidden} more changes`));
    } else {
      lines.push(...sampleTexts.slice(0, slotsLeft));
    }
  }

  const preview = {
    variant: 'plan',
    title: protocolLabel(locale, pending.protocol),
    badge: tr(locale, `需确认 · ${nReasons} 项风险`, `Confirmation required · Risks: ${nReasons}`),
    body: lines.join('\n'),
  };
  if (pending.target_display) {
    preview.subtitle = sanitizeUrlForDisplay(pending.target_display);
  }

  return {
    id: 'preview-card',
    title: tr(locale, '确认同步变更', 'Review Sync Changes'),
    items: [
      { kind: 'preview', preview },
      {
        kind: 'actions',
        buttons: [
          {
            id: 'confirm_sync_card',
            label: tr(locale, '确认同步', 'Confirm Sync'),
            variant: 'danger',
            ...syncButtonFeedback(locale),
          },
          {
            id: 'cancel_confirm',
            label: tr(locale, '取消', 'Cancel'),
            variant: 'secondary',
          },
        ],
      },
    ],
  };
}

function protocolEnableSwitch(protocol, config, locale) {
  const key = PROTOCOL_ENABLED_KEYS[protocol];
  const label = {
    local_mirror: tr(locale, '启用目录镜像', 'Enable Local Mirror'),
    webdav: tr(locale, '启用 WebDAV', 'Enable WebDAV'),
    git: tr(locale, '启用 Git 仓库', 'Enable Git Repository'),
  }[protocol];
  return {
    kind: 'switch',
    id: key,
    label,
    value: Boolean(config[key]),
    visible_when: { control_id: 'protocol', equals: protocol },
  };
}

function conflictPolicyItem(cfg, locale) {
  return {
    kind: 'segmented',
    id: 'conflict_policy',
    label: tr(locale, '双端冲突处理', 'Conflict Resolution'),
    value: cfg.conflict_policy,
    options: [
      { value: 'keep_both', label: tr(locale, '生成冲突副本', 'Keep Both Copies') },
      { value: 'local_first', label: tr(locale, '优先本地', 'Prefer Local') },
      { value: 'remote_first', label: tr(locale, '优先远端', 'Prefer Remote') },
    ],
  };
}

function autoSyncSwitch(cfg, locale) {
  return {
    kind: 'switch',
    id: 'auto_sync',
    label: tr(locale, '自动同步', 'Sync Automatically'),
    value: Boolean(cfg.auto_sync),
  };
}

function syncIntervalItem(cfg, locale) {
  return {
    kind: 'segmented',
    id: 'sync_interval',
    label: tr(locale, '定时同步间隔', 'Scheduled Sync Interval'),
    value: String(cfg.sync_interval || '5'),
    options: [
      { value: '5', label: tr(locale, '5 分钟', '5 min') },
      { value: '30', label: tr(locale, '30 分钟', '30 min') },
      { value: '60', label: tr(locale, '1 小时', '1 hour') },
    ],
    visible_when: { control_id: 'auto_sync', equals: true },
  };
}

function notificationSwitch(cfg, locale) {
  return {
    kind: 'switch',
    id: 'system_notifications',
    label: tr(locale, '同步失败或冲突时通知', 'Notify on Sync Errors or Conflicts'),
    value: Boolean(cfg.system_notifications),
  };
}

function credFieldValue(c, field, supportsSystem) {
  if (!supportsSystem) return String(c[field] || '');
  return '';
}

function credPlaceholder(c, field, defaultText, supportsSystem, locale) {
  return credentialPlaceholder(c, field, defaultText, { supportsSystem, locale });
}

function configButtons(ctx, protocol, c) {
  const { configStore, locale, supportsSystem } = ctx;
  const savedCfg = configStore ? configStore.state.config : c;
  const buttons = [
    {
      id: 'test_conn',
      label: tr(locale, '测试连接', 'Test Connection'),
      variant: 'secondary',
      ...testButtonFeedback(locale),
    },
    {
      id: 'save_config',
      label: tr(locale, '保存', 'Save'),
      variant: 'primary',
    },
  ];
  if (
    (protocol === 'webdav' || protocol === 'git') &&
    protocolEnabled(c, protocol) &&
    !protocolError(c, protocol, { ...ctx, requireNotebooks: true })
  ) {
    const syncLabel =
      protocol === 'webdav'
        ? tr(locale, '同步 WebDAV', 'Sync WebDAV')
        : tr(locale, '同步 Git', 'Sync Git');
    buttons.unshift({
      id: `sync_${protocol}`,
      label: syncLabel,
      variant: 'secondary',
      ...syncButtonFeedback(locale),
    });
  }
  const field = protocol === 'git' ? 'git_token' : protocol === 'webdav' ? 'webdav_pass' : null;
  if (
    supportsSystem &&
    field &&
    (savedCfg[field] || (savedCfg.credential_refs && savedCfg.credential_refs[field]))
  ) {
    buttons.unshift({
      id: 'forget_credential',
      label: tr(locale, '清除凭据', 'Forget Credential'),
      variant: 'secondary',
    });
  }
  return buttons;
}

function protocolSegmentStatus(ctx, protocol, cfg) {
  const { configStore, locale } = ctx;
  const savedCfg = configStore ? configStore.state.config : cfg;
  if (!protocolEnabled(cfg, protocol)) {
    if (protocolHasInput(cfg, protocol, ctx.downloadsDir, ctx.homeDir)) {
      return ['', tr(locale, '已停用', 'Disabled')];
    }
    return ['', tr(locale, '未配置', 'Not configured')];
  }
  const protoErr = protocolError(cfg, protocol, { ...ctx, requireNotebooks: false });
  if (protoErr) {
    if (protocolHasInput(cfg, protocol, ctx.downloadsDir, ctx.homeDir)) {
      return ['warning', protoErr];
    }
    return ['', tr(locale, '未配置', 'Not configured')];
  }
  const pc = configStore && configMatchesSaved(cfg, savedCfg)
    ? configStore.getPendingConfirm(protocol)
    : null;
  if (pc) {
    return ['warning', tr(locale, '已启用 · 待确认变更', 'Enabled · Confirmation required')];
  }
  const res = getProtocolResult(configStore, protocol);
  const st = String(res.status || '').trim();
  if (st === '失败' && res.fail_class === 'network') {
    return ['warning', tr(locale, '已启用 · 等待网络，稍后自动重试', 'Enabled · Offline, will retry')];
  }
  if (st === '失败' || st === '未连通') {
    const hm = formatHm(res.time || '');
    const tip = hm
      ? tr(locale, `已启用 · ${hm} 同步失败`, `Enabled · ${hm} sync failed`)
      : tr(locale, '已启用 · 上次同步失败', 'Enabled · Last sync failed');
    return ['danger', tip];
  }
  if (st === '已取消') {
    return ['warning', tr(locale, '已启用 · 上次同步已取消', 'Enabled · Last sync canceled')];
  }
  const okRec =
    st === '成功' || st === '无变更'
      ? res
      : res.last_success && typeof res.last_success === 'object'
        ? res.last_success
        : null;
  if (okRec && okRec.time) {
    const hm = formatHm(okRec.time || '');
    const metric = formatShortSyncMetric(locale, okRec);
    return ['success', tr(locale, `已启用 · ${hm} ${metric}`, `Enabled · ${hm} ${metric}`)];
  }
  return ['success', tr(locale, '已启用 · 等待同步', 'Enabled · Ready to sync')];
}

function buildProgressItem(ctx, protocol, cfg) {
  const { configStore, locale } = ctx;
  const savedCfg = configStore ? configStore.state.config : cfg;
  const label = {
    local_mirror: tr(locale, '目录镜像同步进度', 'Local Mirror Progress'),
    webdav: tr(locale, 'WebDAV 同步进度', 'WebDAV Sync Progress'),
    git: tr(locale, 'Git 仓库同步进度', 'Git Sync Progress'),
  }[protocol] || tr(locale, '同步进度', 'Sync Progress');

  const protoErr = protocolError(cfg, protocol, { ...ctx, requireNotebooks: false });
  const targetTip = targetDisplay(cfgForProtocol(cfg, protocol), ctx);
  let status = tr(locale, '未启用', 'Not enabled');
  let progress = 0.0;
  let tone = '';
  let tooltip = tr(locale, '配置完成后自动启用此同步目标', 'Configure above to enable this sync target');

  if (!protocolEnabled(cfg, protocol)) {
    if (protocolHasInput(cfg, protocol, ctx.downloadsDir, ctx.homeDir)) {
      status = tr(locale, '已停用', 'Disabled');
      tooltip = tr(locale, '打开上方开关以恢复此同步目标', 'Turn on the switch above to re-enable this sync target');
    } else {
      status = tr(locale, '未启用', 'Not enabled');
      tooltip = tr(locale, '完成配置并打开上方开关以启用此同步目标', 'Configure and turn on the switch above to enable this sync target');
    }
  } else if (protoErr) {
    if (protocolHasInput(cfg, protocol, ctx.downloadsDir, ctx.homeDir)) {
      status = tr(locale, '配置待修正', 'Needs attention');
      tone = 'warning';
      tooltip = protoErr;
    }
  } else {
    const pc = configStore && configMatchesSaved(cfg, savedCfg)
      ? configStore.getPendingConfirm(protocol)
      : null;
    const res = getProtocolResult(configStore, protocol);
    const st = String(res.status || '').trim();
    const okRec =
      st === '成功' || st === '无变更'
        ? res
        : res.last_success && typeof res.last_success === 'object'
          ? res.last_success
          : null;

    if (pc) {
      status = tr(locale, '待确认同步变更', 'Confirmation required');
      progress = 0.5;
      tone = 'warning';
      const reasonItems = pc.reason_items || [];
      tooltip = reasonItems.length > 0
        ? formatReasonItem(locale, reasonItems[0])
        : tr(locale, '检测到危险变更，请先确认', 'Risky changes require confirmation');
    } else if (st === '失败' || st === '未连通') {
      const hm = formatHm(res.time || '');
      const offline = st === '失败' && res.fail_class === 'network';
      status = offline
        ? tr(locale, '等待网络，稍后自动重试', 'Offline, will retry')
        : hm
          ? tr(locale, `${hm} · 同步失败`, `${hm} · Sync failed`)
          : tr(locale, '上次同步失败', 'Last sync failed');
      progress = 1.0;
      tone = offline ? 'warning' : 'danger';
      tooltip = localizeResultSummary(
        locale,
        res,
        '同步失败，请查看同步记录',
        'Sync failed. Check recent sync activity.'
      );
    } else if (st === '已取消') {
      const hm = formatHm(res.time || '');
      status = hm
        ? tr(locale, `${hm} · 已取消`, `${hm} · Canceled`)
        : tr(locale, '已取消同步', 'Sync canceled');
      progress = 0.0;
      tone = 'warning';
      tooltip = tr(locale, '上次危险变更同步已取消', 'Last risky sync was canceled');
    } else if (okRec && okRec.time) {
      const hm = formatHm(okRec.time || '');
      const metric = formatShortSyncMetric(locale, okRec);
      status = hm ? `${hm} · ${metric}` : metric;
      progress = 1.0;
      tone = 'success';
      tooltip = targetTip;
    } else {
      status = tr(locale, '已启用 · 等待同步', 'Enabled · Ready to sync');
      progress = 0.0;
      tone = 'accent';
      tooltip = targetTip;
    }
  }

  const item = {
    kind: 'progress',
    id: `progress_${protocol}`,
    channel: protocol,
    label,
    status,
    progress,
    visible_when: { control_id: 'protocol', equals: protocol },
  };
  if (tone) item.tone = tone;
  if (tooltip) item.tooltip = tooltip;
  return item;
}

function buildLegacyCards(ctx, c) {
  const { locale, supportsSystem, downloadsDir, homeDir } = ctx;
  const protocol = c.protocol;
  const targetItems = [
    {
      kind: 'segmented',
      id: 'protocol',
      label: tr(locale, '同步方式', 'Sync Method'),
      value: protocol,
      options: [
        { value: 'local_mirror', label: tr(locale, '目录镜像', 'Local mirror') },
        { value: 'webdav', label: 'WebDAV' },
        { value: 'git', label: tr(locale, 'Git 仓库', 'Git repository') },
      ],
    },
    protocolEnableSwitch('local_mirror', c, locale),
    protocolEnableSwitch('webdav', c, locale),
    protocolEnableSwitch('git', c, locale),
    {
      kind: 'folder',
      id: 'mirror_dir',
      label: tr(locale, '同步文件夹', 'Sync Folder'),
      value: resolveMirrorDir(c, downloadsDir, homeDir),
      visible_when: { control_id: 'protocol', equals: 'local_mirror' },
    },
  ];

  const webdavFields = [
    ['input', 'webdav_url', tr(locale, '服务器地址', 'Server Address'), 'https://dav.example.com'],
    ['input', 'webdav_dir', tr(locale, '远端目录', 'Remote Folder'), '/BlockNotes'],
    ['input', 'webdav_user', tr(locale, '用户名', 'Username'), ''],
    ['secret', 'webdav_pass', tr(locale, '密码', 'Password'), ''],
  ];
  for (const [kind, key, label, placeholder] of webdavFields) {
    targetItems.push({
      kind,
      id: key,
      label,
      value: kind === 'secret' ? credFieldValue(c, key, supportsSystem) : String(c[key] || ''),
      placeholder: kind === 'secret'
        ? credPlaceholder(c, key, placeholder, supportsSystem, locale)
        : placeholder,
      visible_when: { control_id: 'protocol', equals: 'webdav' },
    });
  }

  targetItems.push(
    {
      kind: 'input',
      id: 'git_remote',
      label: tr(locale, '仓库地址', 'Repository Address'),
      value: String(c.git_remote || ''),
      placeholder: 'git@github.com:user/notes.git',
      visible_when: { control_id: 'protocol', equals: 'git' },
    },
    {
      kind: 'input',
      id: 'git_branch',
      label: tr(locale, '分支', 'Branch'),
      value: String(c.git_branch || ''),
      placeholder: 'main',
      visible_when: { control_id: 'protocol', equals: 'git' },
    },
    {
      kind: 'segmented',
      id: 'git_auth',
      label: tr(locale, '认证方式', 'Authentication'),
      value: c.git_auth,
      options: [
        { value: 'ssh', label: 'SSH' },
        { value: 'token', label: tr(locale, 'HTTPS 令牌', 'HTTPS Token') },
      ],
      visible_when: { control_id: 'protocol', equals: 'git' },
    }
  );

  if (protocol === 'git') {
    targetItems.push({
      kind: 'secret',
      id: 'git_token',
      label: tr(locale, '访问令牌', 'Access Token'),
      value: credFieldValue(c, 'git_token', supportsSystem),
      placeholder: credPlaceholder(c, 'git_token', 'ghp_...', supportsSystem, locale),
      visible_when: { control_id: 'git_auth', equals: 'token' },
    });
  }

  targetItems.push(
    conflictPolicyItem(c, locale),
    autoSyncSwitch(c, locale),
    syncIntervalItem(c, locale),
    {
      kind: 'actions',
      visible_when: { control_id: 'protocol', in: ['webdav', 'git'] },
      buttons: configButtons(ctx, protocol, c),
    }
  );

  if (supportsSystem) {
    targetItems.push(notificationSwitch(c, locale));
  }

  return [{ id: 'target-card', title: tr(locale, '同步设置', 'Sync Settings'), items: targetItems }];
}

export function buildSettingsPage(ctx, cfg = null) {
  const {
    configStore,
    locale = 'zh',
    homeDir = '',
    downloadsDir = '',
    supportsChecklist = false,
    supportsAddFolder = false,
    supportsFormLayout = false,
    supportsMultiNotebook = true,
    supportsLogTimeline = false,
    supportsProgressBar = false,
    supportsSegmentedStatus = false,
    supportsSystem = true,
    lastStatus = '',
  } = ctx;

  const savedCfg = configStore ? configStore.state.config : {};
  const c = cfg || savedCfg;
  const protocol = c.protocol || 'local_mirror';
  const selected = configStore ? configStore.selectedNotebooks(c) : [];
  const knownNotebooks = configStore ? configStore.state.knownNotebooks : [];

  let cards;
  if (supportsChecklist && supportsFormLayout) {
    let listed;
    if (supportsAddFolder) {
      const knownByPath = new Map(knownNotebooks.map((e) => [e.path, e]));
      listed = selected.map(
        (p) => knownByPath.get(p) || { path: p, name: posixBasename(p) || p, active: false }
      );
    } else {
      listed = knownNotebooks;
    }

    const nbOptions = listed.map((entry) => {
      const p = entry.path;
      const opt = {
        value: p,
        label: entry.name,
        detail: displayPath(p, homeDir),
        tooltip: p,
      };
      if (entry.active) {
        opt.badge = tr(locale, '当前', 'Current');
      }
      return opt;
    });

    const nbEmpty = supportsAddFolder
      ? tr(locale, '点击右上角 + 添加要同步的文件夹', 'Click + to add a folder to sync')
      : tr(locale, '暂无已打开的笔记本', 'No open notebooks');

    const checklistItem = {
      kind: 'checklist',
      id: 'selected_notebooks',
      value: selected,
      options: nbOptions,
      empty_text: nbEmpty,
    };
    if (supportsAddFolder) {
      checklistItem.add_folder = true;
    }

    const notebooksCard = {
      id: 'notebooks-card',
      title: tr(locale, '同步笔记本', 'Notebooks to Sync'),
      items: [checklistItem],
    };

    const protocolOptions = VALID_PROTOCOLS.map((p) => {
      const opt = { value: p, label: protocolLabel(locale, p) };
      if (supportsSegmentedStatus) {
        opt.channel = p;
        const [segTone, segTip] = protocolSegmentStatus(ctx, p, c);
        if (segTone) opt.tone = segTone;
        if (segTip) opt.tooltip = segTip;
      }
      return opt;
    });

    const targetItems = [
      {
        kind: 'segmented',
        id: 'protocol',
        layout: 'full',
        value: protocol,
        options: protocolOptions,
      },
      protocolEnableSwitch('local_mirror', c, locale),
      protocolEnableSwitch('webdav', c, locale),
      protocolEnableSwitch('git', c, locale),
      {
        kind: 'folder',
        id: 'mirror_dir',
        label: tr(locale, '目标文件夹', 'Destination Folder'),
        layout: 'stacked',
        value: resolveMirrorDir(c, downloadsDir, homeDir),
        visible_when: { control_id: 'protocol', equals: 'local_mirror' },
      },
      {
        kind: 'input',
        id: 'webdav_url',
        label: tr(locale, '服务器地址', 'Server Address'),
        layout: 'stacked',
        value: String(c.webdav_url || ''),
        placeholder: 'https://dav.example.com',
        visible_when: { control_id: 'protocol', equals: 'webdav' },
      },
      {
        kind: 'input',
        id: 'webdav_dir',
        label: tr(locale, '远端目录', 'Remote Folder'),
        layout: 'stacked',
        value: String(c.webdav_dir || ''),
        placeholder: '/BlockNotes',
        visible_when: { control_id: 'protocol', equals: 'webdav' },
      },
      {
        kind: 'group',
        visible_when: { control_id: 'protocol', equals: 'webdav' },
        fields: [
          {
            kind: 'input',
            id: 'webdav_user',
            label: tr(locale, '用户名', 'Username'),
            layout: 'stacked',
            value: String(c.webdav_user || ''),
            placeholder: tr(locale, '账号', 'Account'),
          },
          {
            kind: 'secret',
            id: 'webdav_pass',
            label: tr(locale, '密码', 'Password'),
            layout: 'stacked',
            value: credFieldValue(c, 'webdav_pass', supportsSystem),
            placeholder: credPlaceholder(
              c,
              'webdav_pass',
              tr(locale, '应用密码或口令', 'App password or passphrase'),
              supportsSystem,
              locale
            ),
          },
        ],
      },
      {
        kind: 'input',
        id: 'git_remote',
        label: tr(locale, '仓库地址', 'Repository Address'),
        layout: 'stacked',
        value: String(c.git_remote || ''),
        placeholder: 'git@github.com:user/notes.git',
        visible_when: { control_id: 'protocol', equals: 'git' },
      },
      {
        kind: 'input',
        id: 'git_branch',
        label: tr(locale, '分支', 'Branch'),
        layout: 'stacked',
        value: String(c.git_branch || ''),
        placeholder: 'main',
        visible_when: { control_id: 'protocol', equals: 'git' },
      },
      {
        kind: 'group',
        visible_when: { control_id: 'protocol', equals: 'git' },
        fields: [
          {
            kind: 'segmented',
            id: 'git_auth',
            label: tr(locale, '认证方式', 'Authentication'),
            layout: 'stacked',
            value: c.git_auth,
            options: [
              { value: 'ssh', label: 'SSH' },
              { value: 'token', label: tr(locale, 'HTTPS 令牌', 'HTTPS Token') },
            ],
          },
          {
            kind: 'secret',
            id: 'git_token',
            label: tr(locale, '访问令牌', 'Access Token'),
            layout: 'stacked',
            value: credFieldValue(c, 'git_token', supportsSystem),
            placeholder: credPlaceholder(c, 'git_token', 'ghp_...', supportsSystem, locale),
            visible_when: { control_id: 'git_auth', equals: 'token' },
          },
        ],
      },
    ];

    if (supportsProgressBar) {
      for (const p of VALID_PROTOCOLS) {
        targetItems.push(buildProgressItem(ctx, p, c));
      }
    }

    targetItems.push({
      kind: 'actions',
      visible_when: { control_id: 'protocol', in: ['webdav', 'git'] },
      buttons: configButtons(ctx, protocol, c),
    });

    if (
      protocolEnabled(c, 'local_mirror') &&
      !protocolError(c, 'local_mirror', { ...ctx, requireNotebooks: true })
    ) {
      targetItems.push({
        kind: 'actions',
        visible_when: { control_id: 'protocol', equals: 'local_mirror' },
        buttons: [
          {
            id: 'sync_local_mirror',
            label: tr(locale, '同步目录镜像', 'Sync Mirror'),
            variant: 'secondary',
            ...syncButtonFeedback(locale),
          },
        ],
      });
    }

    const enabledProtocols = configuredProtocols(c, ctx);
    let targetMeta = '';
    if (enabledProtocols.length >= 2) {
      targetMeta = tr(
        locale,
        `同时启用 ${enabledProtocols.length}/3`,
        `${enabledProtocols.length}/3 active`
      );
    } else if (enabledProtocols.length === 1) {
      targetMeta = tr(locale, '已启用 1/3', '1/3 active');
    }

    const targetCard = {
      id: 'target-card',
      title: tr(locale, '同步目标', 'Sync Destination'),
      items: targetItems,
    };
    if (targetMeta) targetCard.meta = targetMeta;

    const optionsCard = {
      id: 'options-card',
      title: tr(locale, '同步选项', 'Sync Options'),
      items: [
        conflictPolicyItem(c, locale),
        autoSyncSwitch(c, locale),
        syncIntervalItem(c, locale),
      ],
    };
    if (supportsSystem) {
      optionsCard.items.push(notificationSwitch(c, locale));
    }

    cards = [notebooksCard, targetCard, optionsCard];
  } else {
    cards = buildLegacyCards(ctx, c);
  }

  const activePc = configStore
    ? configStore.getPendingConfirm(protocol) || configStore.getPendingConfirm()
    : null;
  const scopeKey = configStore ? configStore.resultKey() : 'default';
  const hasPendingConfirm = Boolean(
    activePc && activePc.scope_key === scopeKey && configMatchesSaved(c, savedCfg)
  );
  if (hasPendingConfirm) {
    cards.unshift(buildConfirmationCard(activePc, locale));
  }

  const enabledProtocols = configuredProtocols(c, ctx);
  let nbOverlap = false;
  for (let i = 0; i < selected.length && !nbOverlap; i += 1) {
    for (let j = 0; j < i; j += 1) {
      if (pathsOverlap(selected[i], selected[j])) {
        nbOverlap = true;
        break;
      }
    }
  }
  const configured =
    enabledProtocols.length > 0 && (!supportsMultiNotebook || selected.length > 0) && !nbOverlap;

  const lastResult = getLastResult(configStore) || {};
  const lastOk = lastResult.last_success;
  const logs = configStore ? configStore.state.logs : [];
  const historyItems = [];

  for (const proto of enabledProtocols) {
    const protoOk = getProtocolResult(configStore, proto).last_success;
    const item = supportsLogTimeline
      ? {
          kind: 'log_list',
          id: `sync_logs_${proto}`,
          variant: 'timeline',
          empty_text: tr(locale, '暂无同步记录', 'No sync activity yet'),
          entries: buildTimelineEntries(logs, locale, { protocol: proto, limit: 8 }),
        }
      : {
          kind: 'log_list',
          id: `sync_logs_${proto}`,
          empty_text: tr(locale, '暂无同步记录', 'No sync activity yet'),
          entries: logsForProtocol(logs, proto)
            .slice(0, 6)
            .map((e) => logForPage(locale, e)),
        };
    if (protoOk && typeof protoOk === 'object' && protoOk.time) {
      item.label = tr(locale, `上次成功 ${protoOk.time}`, `Last synced: ${protoOk.time}`);
    }
    item.visible_when = { control_id: 'protocol', equals: proto };
    historyItems.push(item);
  }

  if (historyItems.length > 0) {
    cards.push({
      id: 'history-card',
      title: tr(locale, '最近同步记录', 'Recent Sync Activity'),
      items: historyItems,
    });
  }

  let status = lastStatus;
  if (!status && configured && configMatchesSaved(c, savedCfg)) {
    const latestState = String(lastResult.status || '').trim();
    if (hasPendingConfirm) {
      status = tr(locale, '待确认同步变更', 'Confirmation required');
    } else if (latestState === '失败' && lastResult.fail_class === 'network') {
      status = tr(locale, '等待网络，稍后自动重试', 'Offline, will retry');
    } else if (latestState === '失败' || latestState === '未连通') {
      status = tr(locale, '上次同步失败', 'Last sync failed');
    } else if (latestState === '已取消') {
      status = tr(locale, '已取消同步', 'Sync canceled');
    } else if (latestState === '待确认') {
      status = tr(locale, '有待确认的变更', 'Pending confirmation');
    } else if (lastOk && typeof lastOk === 'object' && lastOk.time) {
      const syncHm = formatHm(lastOk.time);
      status = tr(locale, `上次同步 ${syncHm}`, `Last sync ${syncHm}`);
    } else if (lastResult.summary) {
      status = String(lastResult.summary);
      if (isEnglishLocale(locale) && lastResult.locale !== 'en' && hasChineseText(status)) {
        status = LOG_STATUS_EN[latestState] || 'See recent sync activity for the last result';
      }
    }
  }

  let headerActions = [];
  if (hasPendingConfirm) {
    headerActions = [
      {
        id: 'confirm_sync',
        label: tr(locale, '确认同步', 'Confirm Sync'),
        variant: 'danger',
        ...syncButtonFeedback(locale),
      },
    ];
  } else if (configured) {
    const syncAllLabel =
      enabledProtocols.length >= 2
        ? tr(locale, `全部同步 (${enabledProtocols.length})`, `Sync All (${enabledProtocols.length})`)
        : tr(locale, '立即同步', 'Sync Now');
    headerActions = [
      {
        id: 'sync_now',
        label: syncAllLabel,
        variant: 'primary',
        ...syncButtonFeedback(locale),
      },
    ];
  }

  return {
    title: tr(locale, '同步', 'Sync'),
    status,
    header_actions: headerActions,
    cards,
  };
}
