/**
 * Bilingual (zh/en) localization, structured log rendering, and error sanitization
 * for block-sync. Pure ES2023, QuickJS-NG compatible.
 */

export const CHINESE_TEXT_RE = /[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]/;
export const DELETE_GUARD_THRESHOLD_DEFAULT = 5;

export const LOG_STATUS_EN = Object.freeze({
  '完成': 'Complete',
  '成功': 'Success',
  '通过': 'Passed',
  '无变更': 'No Changes',
  '已更新': 'Updated',
  '待确认': 'Confirmation Required',
  '失败': 'Failed',
  '未连通': 'Connection Failed',
  '已取消': 'Canceled',
  '已跳过': 'Skipped',
  '冲突副本': 'Conflict Copy',
});

export function hasChineseText(text) {
  return CHINESE_TEXT_RE.test(String(text || ''));
}

export function normalizeLocale(locale) {
  return String(locale || '').toLowerCase().startsWith('en') ? 'en' : 'zh';
}

export function isEnglishLocale(locale) {
  return normalizeLocale(locale) === 'en';
}

export function tr(locale, zh, en) {
  return isEnglishLocale(locale) ? en : zh;
}

export function mergeOnlyRoundNote(locale) {
  return tr(locale, '本轮仅合并未删文件', 'Merge-only this round (no deletions)');
}

export function sanitizeUrlCredentialsInText(text) {
  let msg = String(text ?? '').trim().replace(/[\r\n]+/g, ' ');
  msg = msg.replace(/((?:https?|ssh):\/\/)([^/\s@]+)@/gi, '$1***@');
  if (msg.length > 120) {
    msg = `${msg.slice(0, 117)}...`;
  }
  return msg;
}

export function sanitizeErrorText(exc) {
  const raw = exc && typeof exc === 'object' && 'message' in exc ? exc.message : exc;
  const msg = sanitizeUrlCredentialsInText(raw);
  if (msg) {
    return msg;
  }
  if (exc && typeof exc === 'object' && exc.constructor && exc.constructor.name) {
    return exc.constructor.name;
  }
  return 'Error';
}

export function localizeError(locale, detail) {
  const text = String(detail ?? '');
  if (isEnglishLocale(locale) && hasChineseText(text)) {
    return 'The underlying error is unavailable in English';
  }
  return text;
}

export function errorDetail(locale, exc) {
  return localizeError(locale, sanitizeErrorText(exc));
}

export function protocolLabel(locale, protocol) {
  switch (protocol) {
    case 'local_mirror':
      return tr(locale, '目录镜像', 'Local mirror');
    case 'webdav':
      return 'WebDAV';
    case 'git':
      return tr(locale, 'Git 仓库', 'Git repository');
    default:
      return tr(locale, '目录镜像', 'Local mirror');
  }
}

function formatHmLocal(timeStr) {
  const raw = String(timeStr || '').trim();
  const m = raw.match(/^(\d{1,2}:\d{2})(?::\d{2})?$/);
  return m ? m[1] : raw;
}

export function classifyLogStatus(rawStatus) {
  const s = String(rawStatus || '').trim();
  if (!s) {
    return ['完成', 'info', ''];
  }
  const exact = {
    '成功': ['成功', 'success'],
    '通过': ['通过', 'success'],
    '完成': ['成功', 'success'],
    '无变更': ['无变更', 'info'],
    '待确认': ['待确认', 'warning'],
    '失败': ['失败', 'danger'],
    '未连通': ['未连通', 'danger'],
    '已取消': ['已取消', 'info'],
    '已跳过': ['已跳过', 'warning'],
    '冲突副本': ['冲突副本', 'warning'],
  };
  if (Object.hasOwn(exact, s)) {
    const [st, tn] = exact[s];
    return [st, tn, ''];
  }
  if (s === '用户已取消' || s.includes('已取消')) {
    return ['已取消', 'info', s];
  }
  if (s.includes('未连通')) {
    return ['未连通', 'danger', s];
  }
  if (['失败', '未完成', '异常', '错误', '请先填写'].some((tok) => s.includes(tok))) {
    return ['失败', 'danger', s];
  }
  if (['删除保护', '暂停', '待确认', '危险变更'].some((tok) => s.includes(tok))) {
    return ['待确认', 'warning', s];
  }
  if (s.includes('冲突')) {
    return ['冲突副本', 'warning', s];
  }
  if (['已是最新', '无变更'].some((tok) => s.includes(tok))) {
    return ['无变更', 'info', s];
  }
  if (['已镜像', '已从', '优先', '已推送', '已上传', '已下载', '已拉取', '同步 ', '模式:'].some((tok) => s.includes(tok))) {
    return ['成功', 'success', s];
  }
  return [s, 'info', ''];
}

export function inferLogProtocol(entry, validProtocols = ['local_mirror', 'webdav', 'git']) {
  if (!entry || typeof entry !== 'object') {
    return '';
  }
  const pid = String(entry.protocol_id || '').trim();
  if (validProtocols.includes(pid)) {
    return pid;
  }
  const args = entry.log_args && typeof entry.log_args === 'object' ? entry.log_args : {};
  const argPid = String(args.protocol || '').trim();
  if (validProtocols.includes(argPid)) {
    return argPid;
  }
  const title = String(entry.title || '');
  const labelsMap = [
    ['local_mirror', ['目录镜像', 'Local mirror']],
    ['webdav', ['WebDAV']],
    ['git', ['Git 仓库', 'Git repository']],
  ];
  for (const [proto, labels] of labelsMap) {
    if (labels.some((lbl) => title.includes(lbl))) {
      return proto;
    }
  }
  return '';
}

export function normalizeLog(entry, validProtocols = ['local_mirror', 'webdav', 'git']) {
  const src = entry && typeof entry === 'object' ? entry : {};
  const title = String(src.title || '同步事件').trim() || '同步事件';
  const time = String(src.time || '').trim();
  const rawStatus = String(src.status || '').trim();
  const rawTone = String(src.tone || '').trim().toLowerCase();
  const rawTooltip = String(src.tooltip || '').trim();

  const [status, inferredTone, extraTip] = classifyLogStatus(rawStatus);
  const tone = ['success', 'warning', 'danger', 'info'].includes(rawTone) ? rawTone : inferredTone;
  const tooltip = rawTooltip || extraTip;

  const item = { title, status, time, tone };
  if (tooltip && tooltip !== title && tooltip !== status) {
    item.tooltip = tooltip;
  }
  if (src.locale === 'en') {
    item.locale = 'en';
  }
  if (typeof src.log_key === 'string' && src.log_key) {
    item.log_key = src.log_key;
    if (src.log_args && typeof src.log_args === 'object' && !Array.isArray(src.log_args)) {
      item.log_args = { ...src.log_args };
    }
  }
  const proto = inferLogProtocol(src, validProtocols);
  if (proto) {
    item.protocol_id = proto;
  }
  return item;
}

export function formatReasonItem(locale, item, deleteGuardThreshold = DELETE_GUARD_THRESHOLD_DEFAULT) {
  if (typeof item === 'string') {
    return isEnglishLocale(locale) && hasChineseText(item)
      ? 'Risky changes detected'
      : item;
  }
  if (!item || typeof item !== 'object') {
    return tr(locale, '存在风险变更', 'Risky changes detected');
  }
  const kind = item.kind || '';
  const nb = String(item.nb_label || '').trim();
  const prefix = nb ? `${nb}: ` : '';

  if (kind === 'first_sync') {
    const pNew = Number.parseInt(item.pull_new || 0, 10) || 0;
    const pOw = Number.parseInt(item.pull_ow || 0, 10) || 0;
    const uOw = Number.parseInt(item.push_ow || 0, 10) || 0;
    const conf = Number.parseInt(item.conflicts || 0, 10) || 0;
    return (
      prefix +
      tr(
        locale,
        `首次同步且远端已有内容（拉取 ${pNew} · 覆盖本地 ${pOw} · 覆盖远端 ${uOw} · 冲突 ${conf}）`,
        `The remote already contains content on first sync (pull: ${pNew}, overwrite local: ${pOw}, overwrite remote: ${uOw}, conflicts: ${conf})`
      )
    );
  }
  if (kind === 'first_sync_nonempty') {
    return prefix + tr(locale, '首次同步且远端已有其他内容', 'The remote already contains other notes on first sync');
  }
  if (kind === 'pull_conflict') {
    const n = Number.parseInt(item.count || 0, 10) || 0;
    return prefix + tr(locale, `远端内容将覆盖本地 ${n} 项冲突文件`, `Remote content will overwrite ${n} conflicting local items`);
  }
  if (kind === 'push_conflict') {
    const n = Number.parseInt(item.count || 0, 10) || 0;
    return prefix + tr(locale, `本地内容将覆盖远端 ${n} 项冲突文件`, `Local content will overwrite ${n} conflicting remote items`);
  }
  if (kind === 'delete_guard') {
    const rm = Number.parseInt(item.remote_missing || 0, 10) || 0;
    const lm = Number.parseInt(item.local_missing || 0, 10) || 0;
    return (
      prefix +
      tr(
        locale,
        `触发批量缺失保护（远端缺失 ${rm} 篇 / 本地缺失 ${lm} 篇，阈值 ${deleteGuardThreshold}）`,
        `Deletion protection triggered (missing remotely: ${rm}, missing locally: ${lm}, limit: ${deleteGuardThreshold})`
      )
    );
  }
  if (kind === 'remote_missing_single') {
    const p = String(item.path || '');
    return (
      prefix +
      tr(
        locale,
        `已同步笔记在远端已缺失（${p}），需确认是否重新上传`,
        `Previously synced note is missing remotely (${p}); confirm before re-uploading`
      )
    );
  }
  if (kind === 'bulk_pull') {
    const n = Number.parseInt(item.count || 0, 10) || 0;
    return (
      prefix +
      tr(
        locale,
        `将向本地批量写入 ${n} 项内容（超 ${deleteGuardThreshold} 项）`,
        `Bulk write to local workspace: ${n} items (limit: ${deleteGuardThreshold})`
      )
    );
  }
  const fallback = String(item.text || '');
  if (fallback) {
    return isEnglishLocale(locale) && hasChineseText(fallback)
      ? 'Risky changes detected'
      : fallback;
  }
  return prefix + tr(locale, '存在风险变更', 'Risky changes detected');
}

export function formatSampleItem(locale, item) {
  if (typeof item === 'string') {
    return isEnglishLocale(locale) && hasChineseText(item) ? '' : item;
  }
  if (!item || typeof item !== 'object') {
    return '';
  }
  const kind = item.kind || '';
  const path = String(item.path || '');
  const extra = String(item.extra || '');
  const mapping = {
    pull_ow: [`[覆盖本地] ${path}`, `[Overwrite local] ${path}`],
    pull_upd: [`[更新本地] ${path}`, `[Update local] ${path}`],
    push_ow: [`[覆盖远端] ${path}`, `[Overwrite remote] ${path}`],
    push_upd: [`[更新远端] ${path}`, `[Update remote] ${path}`],
    conflict: [`[冲突副本] ${path} -> ${extra}`, `[Conflict copy] ${path} -> ${extra}`],
    pull_new: [`[拉取] ${path}`, `[Pull] ${path}`],
    push_new: [`[推送] ${path}`, `[Push] ${path}`],
    rm_miss: [`[远端缺失] ${path}`, `[Missing remotely] ${path}`],
    loc_miss: [`[本地缺失] ${path}`, `[Missing locally] ${path}`],
  };
  const pair = mapping[kind] || [path, path];
  return tr(locale, pair[0], pair[1]);
}

export function renderStructuredLog(locale, key, args) {
  const a = args && typeof args === 'object' ? args : {};
  const path = String(a.path || '');
  const proto = protocolLabel(locale, a.protocol || 'local_mirror');

  switch (key) {
    case 'push_new':
      return [tr(locale, `推送 ${path}`, `Push ${path}`), tr(locale, `已推送到${proto}`, `Pushed to ${proto}`)];
    case 'push_update':
      return [tr(locale, `更新 ${path}`, `Update ${path}`), tr(locale, `已同步修改到${proto}`, `Synced changes to ${proto}`)];
    case 'push_overwrite':
      return [
        tr(locale, `本地覆盖 ${path}`, `Overwrite remote: ${path}`),
        tr(locale, `本地优先覆盖${proto}`, `Local version took precedence on ${proto}`),
      ];
    case 'pull_new':
      return [tr(locale, `拉取 ${path}`, `Pull ${path}`), tr(locale, `已从${proto}拉取`, `Pulled from ${proto}`)];
    case 'pull_update':
      return [tr(locale, `拉取更新 ${path}`, `Pull update: ${path}`), tr(locale, `已从${proto}拉取更新`, `Pulled update from ${proto}`)];
    case 'pull_overwrite':
      return [
        tr(locale, `远端覆盖 ${path}`, `Overwrite local: ${path}`),
        tr(locale, `${proto}优先更新本地`, `Version from ${proto} replaced the local copy`),
      ];
    case 'conflict_copy': {
      const copyRel = String(a.copy || '');
      return [
        tr(locale, `冲突保留 ${path}`, `Keep conflict copy: ${path}`),
        tr(locale, `已保留副本 ${copyRel}`, `Saved a copy at ${copyRel}`),
      ];
    }
    case 'delete_remote':
    case 'delete_local': {
      const where = key === 'delete_remote' ? proto : tr(locale, '本地', 'local');
      return [
        tr(locale, `删除 ${path}`, `Delete ${path}`),
        tr(locale, `已在${where}删除（可找回）`, `Deleted from ${where} (recoverable)`),
      ];
    }
    case 'delete_skipped': {
      const where = a.side === 'remote' ? proto : tr(locale, '本地', 'local');
      return [
        tr(locale, `保留 ${path}`, `Keep ${path}`),
        tr(locale, `${where}内容已变化，未删除`, `Changed on ${where}; not deleted`),
      ];
    }
    case 'delete_unsupported':
      return [
        tr(locale, '远端删除未同步到本地', 'Remote deletions not applied locally'),
        tr(locale, '请升级 Block 后重试', 'Update Block and sync again'),
      ];
    case 'delete_failed': {
      const errStr = localizeError(locale, String(a.error || ''));
      return [tr(locale, `删除失败 ${path}`, `Delete failed: ${path}`), errStr];
    }
    case 'sync_skipped':
      return [formatSkippedCount(locale, a.count), formatSkippedDetails(a.items)];
    case 'assets_synced': {
      const prefix = String(a.prefix || '');
      const count = Number.parseInt(a.count || 0, 10) || 0;
      return [tr(locale, `${prefix}同步 ${count} 个附件`, `${prefix}Synced attachments: ${count}`), ''];
    }
    case 'test_conn':
      return [tr(locale, `测试连接 (${proto})`, `Test connection (${proto})`), ''];
    case 'sync_noop': {
      const count = Math.max(1, Number.parseInt(a.count || 1, 10) || 1);
      if (count > 1) {
        const firstHm = formatHmLocal(a.first_time || '');
        const lastHm = formatHmLocal(a.last_time || '');
        const spanTip = firstHm && lastHm && firstHm !== lastHm
          ? `${firstHm} → ${lastHm}`
          : tr(locale, '已是最新', 'Up to date');
        return [tr(locale, `${proto}同步（${count} 次无改动）`, `${proto} sync (${count} checks)`), spanTip];
      }
      return [tr(locale, `${proto}同步`, `${proto} sync`), tr(locale, '已是最新', 'Up to date')];
    }
    case 'sync_canceled':
      return [tr(locale, '危险变更同步', 'Sync with risky changes'), tr(locale, '用户已取消本次同步', 'The user canceled this sync')];
    case 'plan_changed':
      return [
        tr(locale, '同步计划已变化', 'The sync plan changed'),
        tr(locale, '原危险变更已消除，请重新同步', 'The original risks are gone. Start sync again.'),
      ];
    case 'auto_paused':
      return [tr(locale, `自动同步暂停 (${path})`, `Auto-sync paused (${path})`), ''];
    case 'confirm_required':
      if (a.reason_item && typeof a.reason_item === 'object') {
        return [
          formatReasonItem(locale, a.reason_item),
          tr(locale, '检测到危险变更，请先确认后执行', 'Risky changes detected. Confirm to continue.'),
        ];
      }
      return [null, null];
    case 'identity_unverified': {
      const pfx = String(a.prefix || '');
      return [
        tr(locale, `${pfx}未验证笔记本身份，已降级为仅合并`, `${pfx}Notebook identity unverified; downgraded to merge-only`),
        tr(locale, '当前仅合并不删文件', 'Merged without deleting files'),
      ];
    }
    case 'merge_only_refresh': {
      const pfx = String(a.prefix || '');
      return [
        tr(locale, `${pfx}本轮仅合并未删文件`, `${pfx}Merge-only this round (no deletions)`),
        tr(locale, '已更新基线状态指纹，下轮恢复正常同步', 'Baseline fingerprint updated; normal sync resumes next round'),
      ];
    }
    case 'deletions_aborted': {
      const pfx = String(a.prefix || '');
      return [
        tr(locale, `${pfx}执行删除前笔记本身份已变化，已跳过删除`, `${pfx}Notebook identity changed before delete; deletions skipped`),
        tr(locale, '已跳过全部删除以保护数据', 'All deletions were skipped to protect data'),
      ];
    }
    case 'sync_migration_pending':
      return [
        tr(locale, '笔记本迁移尚未完成，同步已暂停', 'Notebook migration is pending; sync paused'),
        tr(locale, '迁移重试完成后将自动恢复同步', 'Sync will resume once the pending migration finishes'),
      ];
    default:
      return [null, null];
  }
}

export function logForPage(locale, entry) {
  const item = normalizeLog(entry);
  const logKey = item.log_key;
  const logArgs = item.log_args;
  delete item.log_key;
  delete item.log_args;
  delete item.protocol_id;
  const recordedInEnglish = item.locale === 'en';
  delete item.locale;

  if (logKey) {
    const [locTitle, locTip] = renderStructuredLog(locale, logKey, logArgs);
    if (locTitle) {
      item.title = locTitle;
    }
    if (locTip) {
      item.tooltip = locTip;
    }
  }
  if (!isEnglishLocale(locale)) {
    return item;
  }

  const mappedStatus = LOG_STATUS_EN[item.status] || item.status;
  item.status = hasChineseText(mappedStatus) ? 'Complete' : mappedStatus;

  if (!logKey && !recordedInEnglish) {
    if (hasChineseText(item.title)) {
      const prefixes = [
        ['推送 ', 'Push '],
        ['更新 ', 'Update '],
        ['本地覆盖 ', 'Overwrite remote: '],
        ['拉取更新 ', 'Pull update: '],
        ['拉取 ', 'Pull '],
        ['远端覆盖 ', 'Overwrite local: '],
        ['冲突保留 ', 'Keep conflict copy: '],
      ];
      for (const [zhPfx, enPfx] of prefixes) {
        if (item.title.startsWith(zhPfx)) {
          item.title = enPfx + item.title.slice(zhPfx.length);
          break;
        }
      }
      if (hasChineseText(item.title)) {
        item.title = 'Sync event';
      }
    }
    if (item.tooltip && hasChineseText(item.tooltip)) {
      delete item.tooltip;
    }
  }

  // Hard guard: never leak Chinese characters to English UI.
  if (hasChineseText(item.title)) {
    item.title = 'Sync event';
  }
  if (item.tooltip && hasChineseText(item.tooltip)) {
    delete item.tooltip;
  }
  return item;
}

export function formatSyncFailureLabel(locale, code) {
  if (code === 'file_limit') return tr(locale, '文件超过大小上限', 'File size limit exceeded');
  if (code === 'quota_full') return tr(locale, '存储空间不足', 'Insufficient storage');
  if (code === 'fs_error') return tr(locale, '文件访问失败', 'File access failed');
  if (code === 'scope') return tr(locale, '目录未授权', 'Folder access denied');
  return tr(locale, '同步失败', 'Sync failed');
}

export function formatSkippedCount(locale, count) {
  return tr(locale, `已跳过 ${count} 个文件`, `Skipped ${count} files`);
}

export function formatSkippedDetails(items) {
  if (!Array.isArray(items)) return '';
  return items.slice(0, 8).map(({ path, reason }) => {
    const shown = /[\u0000-\u001f\u007f]/.test(path) ? JSON.stringify(path) : path;
    return `${shown}: ${reason}`;
  }).join('\n');
}

export function formatShortSyncMetric(locale, rec) {
  if (!rec || typeof rec !== 'object') {
    return tr(locale, '已是最新', 'Up to date');
  }
  const pushed = Number.parseInt(rec.pushed || 0, 10) || 0;
  const pulled = Number.parseInt(rec.pulled || 0, 10) || 0;
  const conflicts = Number.parseInt(rec.conflicts || 0, 10) || 0;
  const assets = Number.parseInt(rec.assets || 0, 10) || 0;
  const parts = [];
  if (pushed > 0) parts.push(tr(locale, `推 ${pushed}`, `${pushed} pushed`));
  if (pulled > 0) parts.push(tr(locale, `拉 ${pulled}`, `${pulled} pulled`));
  if (conflicts > 0) parts.push(tr(locale, `冲突 ${conflicts}`, `${conflicts} conflicts`));
  if (assets > 0) parts.push(tr(locale, `附件 ${assets}`, `${assets} assets`));
  if (rec.skipped_count > 0) parts.push(formatSkippedCount(locale, rec.skipped_count));
  if (parts.length > 0) {
    return parts.join(' / ');
  }
  return tr(locale, '已是最新', 'Up to date');
}

export function localizeResultSummary(locale, rec, fallbackZh, fallbackEn) {
  const summary = String((rec && rec.summary) || '').trim();
  if (summary && !(isEnglishLocale(locale) && hasChineseText(summary))) {
    return summary;
  }
  return tr(locale, fallbackZh, fallbackEn);
}

export function createTranslator(getLocale = () => 'zh') {
  const resolve = () => (typeof getLocale === 'function' ? getLocale() : getLocale);
  return {
    get locale() {
      return normalizeLocale(resolve());
    },
    isEn: () => isEnglishLocale(resolve()),
    tr: (zh, en) => tr(resolve(), zh, en),
    protocolLabel: (protocol) => protocolLabel(resolve(), protocol),
    localizeError: (detail) => localizeError(resolve(), detail),
    errorDetail: (exc) => errorDetail(resolve(), exc),
    normalizeLog: (entry) => normalizeLog(entry),
    classifyLogStatus,
    renderStructuredLog: (key, args) => renderStructuredLog(resolve(), key, args),
    logForPage: (entry) => logForPage(resolve(), entry),
    formatReasonItem: (item, threshold) => formatReasonItem(resolve(), item, threshold),
    formatSampleItem: (item) => formatSampleItem(resolve(), item),
    formatShortSyncMetric: (rec) => formatShortSyncMetric(resolve(), rec),
    localizeResultSummary: (rec, zh, en) => localizeResultSummary(resolve(), rec, zh, en),
  };
}
