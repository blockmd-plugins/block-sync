/**
 * Git sync engine for block-sync. All Git commands go through host.exec.run,
 * target worktree I/O goes through host.fs.*, local notes go through
 * host.notes.* / host.fs.*, credentials go through host.secrets.*, and
 * hashing goes through host.crypto.hash. Pure ES2023, QuickJS-NG compatible.
 */

import {
  tr,
  errorDetail,
  protocolLabel,
  formatSkippedCount,
} from './i18n.js';
import {
  resolveCallHost,
  sha256Text,
  sha256Bytes,
  textToBytes,
  bytesToText,
  bytesEqual,
  textToBase64,
  nowHms,
  sleepMs,
  posixDirname,
  posixBasename,
  posixJoin,
  normAbsPath,
  isSafeRelMd,
  isSafeRelAsset,
  foldSyncPath,
  inSyncSubdir,
  matchesScope,
  pathsOverlap,
  noteAssetPaths,
  rewriteNoteAssetLinks,
  sanitizeUrlForDisplay,
  createSyncSkips,
  collectSkippedItems,
  classifySyncError,
  hashSyncFile,
  sha256File,
  restoreSkippedBase,
  pruneSkippedPatchEntries,
} from './utils.js';
import {
  INITIALIZED_META_KEY,
  LAYOUTS_META_KEY,
  resolveCredentials,
  computeNotebookSubdirMap,
  notebookKey,
  notebookLabel,
  notebookSlug,
} from './config.js';
import { createHostLocalAdapter } from './webdav.js';
import {
  fsStat,
  fsList,
  fsReadBytes,
  fsReadText,
  fsWriteBytes,
  fsWriteText,
  fsMkdir,
  fsDelete,
  deleteDataPath,
  fsReadNoteText,
  dirIsCaseInsensitive,
  dirIsNormalizationInsensitive,
  pathsCollapse,
  groupCollapses,
  collapsedNameError,
  scanDirSnapshot,
  snapshotHasCloudPlaceholder,
  scanMirrorFiles,
  cleanupStaleTempFiles,
  withTargetLock,
  validatePhysicalTargets,
  computeThreeWaySyncPlan,
  planRiskMetrics,
  assessDangerousChanges,
  assessBatchDangerousChanges,
  buildPendingConfirm,
  applyMirrorOrGitNotebookPlan,
  isConfirmedAbsentOnRoot,
  commitPlanBaseline,
  resolvePluginDataDir,
  migrateLegacyRecoveryDirs,
} from './local_mirror.js';

const GIT_NETWORK_OPS = new Set(['clone', 'fetch', 'ls-remote', 'pull', 'push']);
const EMPTY_TREE_OID = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';

function trimTrailingSlash(p) {
  const s = String(p ?? '').replace(/\\/g, '/');
  return s.length > 1 ? s.replace(/\/+$/, '') : s;
}

function normalizeGitRel(p) {
  return String(p ?? '').replace(/\\/g, '/').replace(/^\/+/, '');
}

function isUtf8Exact(rawBytes) {
  if (!(rawBytes instanceof Uint8Array)) return false;
  return bytesEqual(textToBytes(bytesToText(rawBytes)), rawBytes);
}

// ============================================================================
// Git URL, Branch, Env & Exec Wrappers (host.exec.run)
// ============================================================================

/** Return true if target is a remote Git URL (https/http/ssh/git@/file). */
export function isRemoteGitUrl(target) {
  const low = String(target ?? '').trim().toLowerCase();
  return (
    low.startsWith('https://') ||
    low.startsWith('http://') ||
    low.startsWith('ssh://') ||
    low.startsWith('git@') ||
    low.startsWith('file://')
  );
}

/** Return configured Git branch name (default 'main'). */
export function gitBranch(cfg) {
  return String((cfg && cfg.git_branch) || '').trim() || 'main';
}

/** Sanitize stdout/stderr so HTTP Basic credentials and raw tokens never leak. */
export function sanitizeGitOutput(text, secrets = []) {
  let out = String(text ?? '');
  for (const sec of secrets) {
    if (sec && typeof sec === 'string') {
      out = out.split(sec).join('***');
    }
  }
  return out;
}

/** Build sanitized Git process environment + optional GIT_CONFIG_COUNT token header injection. */
export function buildGitEnv({ cfg = null, args = [], locale = 'zh', baseEnv = null } = {}) {
  const env = baseEnv && typeof baseEnv === 'object' ? { ...baseEnv } : {};
  env.GIT_TERMINAL_PROMPT = '0';
  if (locale === 'en') {
    env.LC_ALL = 'C';
  }

  const c = cfg || {};
  const token = String(c.git_token || '').trim();
  const target = String(c.git_remote || '').trim();
  const lowTarget = target.toLowerCase();
  const op = Array.isArray(args) && args.length > 0 ? String(args[0] || '') : '';
  let encoded = '';

  if (op === 'push') {
    // Git's sparse pack walk can miss uninteresting trees (seen with Unicode paths)
    // and resend most of the repo, making pushes time out on slow links.
    let count = Number.parseInt(String(env.GIT_CONFIG_COUNT || '0'), 10);
    if (!Number.isFinite(count) || count < 0) count = 0;
    env[`GIT_CONFIG_KEY_${count}`] = 'pack.useSparse';
    env[`GIT_CONFIG_VALUE_${count}`] = 'false';
    env.GIT_CONFIG_COUNT = String(count + 1);
  }

  if (
    c.git_auth === 'token' &&
    token &&
    (lowTarget.startsWith('https://') || lowTarget.startsWith('http://')) &&
    GIT_NETWORK_OPS.has(op)
  ) {
    encoded = textToBase64(`x-access-token:${token}`);
    for (const key of Object.keys(env)) {
      if (key.startsWith('GIT_TRACE') || key === 'GIT_CURL_VERBOSE') {
        delete env[key];
      }
    }
    let count = Number.parseInt(String(env.GIT_CONFIG_COUNT || '0'), 10);
    if (!Number.isFinite(count) || count < 0) count = 0;
    const pairs = [
      [`http.${target}.extraHeader`, `Authorization: Basic ${encoded}`],
      [`http.${target}.followRedirects`, 'false'],
    ];
    for (const [k, v] of pairs) {
      env[`GIT_CONFIG_KEY_${count}`] = k;
      env[`GIT_CONFIG_VALUE_${count}`] = v;
      count += 1;
    }
    env.GIT_CONFIG_COUNT = String(count);
  }

  return { env, encoded, token };
}

/** Execute a git command via host.exec.run and desensitize any secret output. */
export function runGit(
  callHost,
  args,
  {
    cwd = '',
    timeoutMs = 8000,
    cfg = null,
    locale = 'zh',
    stdin = undefined,
    extraEnv = null,
  } = {}
) {
  const rpc = resolveCallHost(callHost);
  const { env, encoded, token } = buildGitEnv({ cfg, args, locale, baseEnv: extraEnv });
  const params = {
    program: 'git',
    args: Array.isArray(args) ? args.map((a) => String(a)) : [],
    env,
    timeout_ms: Math.max(1000, Math.round(timeoutMs)),
  };
  if (cwd) {
    params.cwd = trimTrailingSlash(cwd);
  }
  if (stdin !== undefined && stdin !== null) {
    params.stdin = String(stdin);
  }

  let res;
  try {
    res = rpc('host.exec.run', params);
  } catch (exc) {
    const msg = encoded
      ? sanitizeGitOutput(exc?.message || String(exc), [encoded, token])
      : String(exc?.message || exc || '');
    return {
      returncode: 1,
      stdout: '',
      stderr: msg,
      timed_out: false,
    };
  }

  const returncode = typeof res?.exit_code === 'number' ? res.exit_code : res?.timed_out ? 124 : 0;
  let stdout = String(res?.stdout ?? '');
  let stderr = String(res?.stderr ?? '');
  if (encoded && returncode !== 0) {
    stdout = sanitizeGitOutput(stdout, [encoded, token]);
    stderr = sanitizeGitOutput(stderr, [encoded, token]);
  }
  return {
    returncode: res?.timed_out && returncode === 0 ? 124 : returncode,
    stdout,
    stderr,
    stdout_truncated: Boolean(res?.stdout_truncated || res?.truncated),
    stderr_truncated: Boolean(res?.stderr_truncated),
    timed_out: Boolean(res?.timed_out),
  };
}

function assertGitOutputComplete(proc, cmdLabel, { nulTerminated = false, locale = 'zh' } = {}) {
  if (
    proc?.stdout_truncated ||
    (nulTerminated && typeof proc?.stdout === 'string' && proc.stdout.length > 0 && !proc.stdout.endsWith('\u0000'))
  ) {
    throw new Error(
      tr(
        locale,
        `Git 输出已截断（${cmdLabel}），已中止同步`,
        `Git output was truncated (${cmdLabel}); sync aborted`
      )
    );
  }
}

/** Return true if raw_text looks like a transient network/SSH/TLS failure worth retrying. */
export function isTransientGitError(rawText) {
  const lower = String(rawText || '').toLowerCase();
  if (!lower) return false;
  const errorClass = classifySyncError(rawText);
  if (['file_limit', 'quota_full', 'fs_error'].includes(errorClass)) return false;
  const nonTransient = [
    'permission denied (publickey)',
    'authentication failed',
    'invalid username or token',
    'invalid username or password',
    'http basic: access denied',
    'repository not found',
    'could not read username',
    'terminal prompts disabled',
    'returned error: 401',
    'returned error: 403',
    'returned error: 404',
    'non-fast-forward',
    'could not apply',
    'gh013',
    'protected branch',
    'pre-receive hook declined',
    'index.lock',
    'submodule',
  ];
  if (nonTransient.some((tok) => lower.includes(tok))) return false;
  const transient = [
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
  ];
  return transient.some((tok) => lower.includes(tok));
}

/** Map raw git stderr/stdout into a user-friendly bilingual diagnostic message. */
export function gitErrorMessage(locale, rawText, fallback = '') {
  const lower = String(rawText || '').toLowerCase();
  const detail = errorDetail(locale, rawText || fallback);
  if (lower.includes('gh001') || lower.includes('large files detected')) {
    return tr(locale, `GH001：文件超过 GitHub 的 100 MiB 上限。移除历史中的大文件或迁移到 Git LFS。\n${detail}`, `GH001: A file exceeds GitHub's 100 MiB limit. Remove the large file from history or migrate it to Git LFS.\n${detail}`);
  }
  if (lower.includes('gh013')) {
    return tr(locale, 'GH013：推送违反仓库规则。若触发密钥保护，请撤销并轮换泄露的密钥，再从提交历史移除；其他情况请检查 GitHub 仓库规则。', 'GH013: The push violated repository rules. If secret protection triggered, revoke and rotate the secret and remove it from commit history. Otherwise, check the repository rules on GitHub.');
  }
  if (/protected branch|pre-receive hook declined/.test(lower)) {
    return tr(locale, `远端拒绝推送。请核对分支保护或服务器钩子，必要时改用可写分支。\n${detail}`, `The remote rejected the push. Check branch protection or server hooks, and use a writable branch if required.\n${detail}`);
  }
  if (lower.includes('index.lock')) {
    return tr(locale, 'Git 索引被 index.lock 锁定。请先结束正在运行的 Git 操作，确认没有 Git 进程后再删除残留锁文件。', 'Git index is locked by index.lock. Finish any running Git operations and remove the stale lock only after confirming Git is no longer running.');
  }
  if (/no space left|\benospc\b/.test(lower)) {
    return tr(locale, '磁盘空间不足（ENOSPC）。请释放空间后重试。', 'No space left on disk (ENOSPC). Free disk space and retry.');
  }
  if (lower.includes('submodule') && /conflict|merge|unmerged|entry/.test(lower)) {
    return tr(locale, `Git 子模块冲突。请在仓库中解决子模块引用冲突并完成 Git 操作。\n${detail}`, `Git submodule conflict. Resolve the submodule reference in the repository and finish the Git operation.\n${detail}`);
  }
  if (lower.includes('permission denied (publickey)')) {
    return tr(
      locale,
      'SSH 公钥认证失败，请检查本机 SSH 密钥配置',
      'SSH public key authentication failed; check your SSH key setup'
    );
  }
  if (
    [
      'authentication failed',
      'invalid username or token',
      'invalid username or password',
      'http basic: access denied',
      'returned error: 401',
      'returned error: 403',
      'could not read username',
      'terminal prompts disabled',
    ].some((tok) => lower.includes(tok))
  ) {
    return tr(
      locale,
      '身份认证失败，请检查访问令牌或仓库权限',
      'Authentication failed; check your access token or repository permissions'
    );
  }
  if (lower.includes('repository not found') || lower.includes('returned error: 404')) {
    return tr(
      locale,
      '未找到远端仓库，请检查仓库地址和访问权限',
      'Remote repository not found; check the URL and access permissions'
    );
  }
  if (['timed out', 'timeout', 'curl 28'].some((tok) => lower.includes(tok))) {
    return tr(
      locale,
      '连接超时，请检查网络或代理设置后重试',
      'Connection timed out; check your network or proxy and try again'
    );
  }
  if (
    [
      'connection closed',
      'connection reset',
      'broken pipe',
      'kex_exchange_identification',
      'banner exchange',
      'early eof',
      'unexpected disconnect',
      'the remote end hung up unexpectedly',
      'recv failure',
      'empty reply from server',
    ].some((tok) => lower.includes(tok))
  ) {
    return tr(
      locale,
      '网络连接中断，请检查网络或代理后重试',
      'Network connection was closed; check your network or proxy and try again'
    );
  }
  if (
    [
      'could not resolve host',
      'temporary failure in name resolution',
      'failed to connect',
      "couldn't connect to server",
      'network is unreachable',
      'no route to host',
      'connection refused',
      'ssl_connect',
      'gnutls_handshake',
      'curl 7',
      'curl 35',
      'curl 56',
    ].some((tok) => lower.includes(tok))
  ) {
    return tr(
      locale,
      '无法连接远端服务器，请检查网络或代理设置',
      'Could not reach the remote server; check your network or proxy'
    );
  }
  return errorDetail(locale, rawText || fallback);
}

/** Run a network Git command with bounded total budget and transient-error retries. */
export function runGitNetwork(
  callHost,
  args,
  {
    cwd = '',
    timeoutMs = 12000,
    cfg = null,
    retries = 2,
    retryDelayMs = 1000,
    totalBudgetMs = 22000,
    onRetry = null,
    locale = 'zh',
    nowMsFn = () => Date.now(),
    sleepFn = null,
    deadlineMs = 0,
  } = {}
) {
  let deadline = nowMsFn() + totalBudgetMs;
  if (deadlineMs && deadlineMs > 0) {
    deadline = Math.min(deadline, deadlineMs);
  }
  let lastProc = {
    returncode: 124,
    stdout: '',
    stderr: 'Connection timed out',
    timed_out: true,
  };
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    const remaining = deadline - nowMsFn();
    if (remaining <= 0 || (attempt > 0 && remaining <= 2000)) {
      break;
    }
    const stepTimeoutMs = Math.min(timeoutMs, Math.max(1000, remaining));
    const proc = runGit(callHost, args, {
      cwd,
      timeoutMs: stepTimeoutMs,
      cfg,
      locale,
    });
    if (proc.timed_out && !proc.stderr) {
      proc.stderr = `Connection timed out after ${Math.floor(stepTimeoutMs / 1000)}s`;
    }
    lastProc = proc;
    if (proc.returncode === 0) return proc;
    const rawErr = proc.stderr || proc.stdout;
    if (attempt >= retries || !isTransientGitError(rawErr)) {
      return proc;
    }
    if (typeof onRetry === 'function') {
      try {
        onRetry();
      } catch (_err) {
        // Ignore retry hook errors.
      }
    }
    const afterRemaining = deadline - nowMsFn();
    if (afterRemaining <= 2000) break;
    sleepMs(Math.min(retryDelayMs * (attempt + 1), Math.max(0, afterRemaining - 1500)), sleepFn);
  }
  return lastProc;
}

// ============================================================================
// Git Directory, Safety & Branch Metadata Helpers
// ============================================================================

/** Return true if repoDir contains a .git file or directory. */
export function hasGitMarker(callHost, repoDir) {
  if (!repoDir) return false;
  try {
    return Boolean(fsStat(callHost, posixJoin(trimTrailingSlash(repoDir), '.git')).exists);
  } catch (_err) {
    return false;
  }
}

/** Return [workTreeRoot, actualGitDir] if startDir is inside a Git repo. */
export function resolveGitDir(callHost, startDir) {
  let cur = trimTrailingSlash(startDir);
  while (cur) {
    const gitEntry = posixJoin(cur, '.git');
    try {
      const st = fsStat(callHost, gitEntry);
      if (st.exists) {
        if (st.is_dir) {
          return [cur, st.path ? trimTrailingSlash(st.path) : gitEntry];
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
                return [cur, gdSt.path ? trimTrailingSlash(gdSt.path) : gd];
              }
            }
          }
        }
      }
    } catch (_err) {
      break;
    }
    const parent = posixDirname(cur);
    if (!parent || parent === cur) break;
    cur = parent;
  }
  return ['', ''];
}

/** Return true if repoDir is a managed clone directory under <dataDir>/git-repos/. */
export function isManagedGitDir(repoDir, dataDir = '') {
  if (!repoDir || !dataDir) return false;
  const cleanData = normAbsPath(dataDir);
  const cleanRepo = normAbsPath(repoDir);
  if (!cleanData || !cleanRepo) return false;
  const managedRoot = posixJoin(cleanData, 'git-repos');
  return posixDirname(cleanRepo) === managedRoot;
}

/** Verify that a managed Git checkout under <dataDir>/git-repos/ is safe to mutate. */
export function managedGitCheckoutIsSafe(callHost, repoDir, dataDir, cfg = null, locale = 'zh') {
  if (!isManagedGitDir(repoDir, dataDir)) return false;
  const cleanRepo = normAbsPath(repoDir);
  const gitDir = posixJoin(cleanRepo, '.git');
  const gitSt = fsStat(callHost, gitDir);
  if (!gitSt.exists) {
    const repoSt = fsStat(callHost, cleanRepo);
    if (!repoSt.exists) return true;
    if (!repoSt.is_dir) return false;
    try {
      return fsList(callHost, cleanRepo, false).length === 0;
    } catch (_err) {
      return false;
    }
  }
  if (!gitSt.is_dir) return false;
  const res = runGit(
    callHost,
    ['rev-parse', '--path-format=absolute', '--show-toplevel', '--absolute-git-dir', '--git-common-dir'],
    { cwd: cleanRepo, cfg, locale }
  );
  if (res.returncode !== 0) return false;
  const lines = res.stdout
    .split(/\r?\n/)
    .map((ln) => trimTrailingSlash(ln.trim()))
    .filter(Boolean);
  const expectedTop = trimTrailingSlash(fsStat(callHost, cleanRepo).path || cleanRepo);
  const expectedGit = trimTrailingSlash(gitSt.path || gitDir);
  return (
    lines.length === 3 &&
    lines[0] === expectedTop &&
    lines[1] === expectedGit &&
    lines[2] === expectedGit
  );
}

/** Return current checked-out branch name, or '' if detached/unborn. */
export function gitCurrentBranch(callHost, repoDir, cfg = null, locale = 'zh') {
  const proc = runGit(callHost, ['symbolic-ref', '--short', 'HEAD'], { cwd: repoDir, cfg, locale });
  return proc.returncode === 0 ? proc.stdout.trim() : '';
}

/** Return [canonical, ...legacy] repo directories for cfg. */
export function gitRepoDirs(
  callHost,
  cfg,
  {
    dataDir = '',
    nbRoot = '',
    homeDir = '',
    locale = 'zh',
  } = {}
) {
  const target = String((cfg && cfg.git_remote) || '').trim();
  const branch = gitBranch(cfg);
  const cleanData = dataDir ? normAbsPath(dataDir, homeDir) : '';
  if (target && !isRemoteGitUrl(target)) {
    const expanded = target.startsWith('~') ? normAbsPath(target, homeDir) : target.replace(/\\/g, '/');
    if (expanded.startsWith('/') || /^[a-zA-Z]:\//.test(expanded)) {
      return [normAbsPath(expanded, homeDir)];
    }
    return [cleanData ? posixJoin(cleanData, expanded) : normAbsPath(expanded, homeDir)];
  }

  const base = cleanData ? posixJoin(cleanData, 'git-repos') : 'git-repos';
  if (!target) {
    return [posixJoin(base, notebookSlug(nbRoot, callHost, '', homeDir))];
  }

  const repoKey = `${target}\n${branch}`;
  const canonical = posixJoin(base, `repo-${sha256Text(repoKey, callHost).slice(0, 12)}`);
  const legacy = [];
  const legacyUnbranched = posixJoin(base, `repo-${sha256Text(target, callHost).slice(0, 12)}`);
  if (cleanData && isManagedGitDir(canonical, cleanData)) {
    const baseSt = fsStat(callHost, base);
    if (baseSt.exists && baseSt.is_dir) {
      const candidates = [];
      if (legacyUnbranched !== canonical && hasGitMarker(callHost, legacyUnbranched)) {
        candidates.push(legacyUnbranched);
      }
      try {
        const entries = fsList(callHost, base, false)
          .map((e) => String(e?.name || ''))
          .filter(Boolean)
          .sort();
        for (const name of entries) {
          const p = posixJoin(base, name);
          if (p === canonical || p === legacyUnbranched || !/-[0-9a-f]{8}$/.test(name)) continue;
          if (hasGitMarker(callHost, p)) {
            candidates.push(p);
          }
        }
      } catch (_err) {
        // Ignore listing errors.
      }
      for (const p of candidates) {
        if (!managedGitCheckoutIsSafe(callHost, p, cleanData, cfg, locale)) continue;
        const res = runGit(callHost, ['config', '--local', '--get', 'remote.origin.url'], {
          cwd: p,
          cfg,
          locale,
        });
        if (res.returncode === 0 && res.stdout.trim() === target) {
          const curBr = gitCurrentBranch(callHost, p, cfg, locale);
          if (curBr === branch) {
            legacy.push(p);
          }
        }
      }
    }
  }
  return [canonical, ...legacy];
}

/** Resolve active local Git worktree path for cfg. */
export function resolveLocalGitDir(callHost, cfg, opts = {}) {
  const dirs = gitRepoDirs(callHost, cfg, opts);
  for (const d of dirs) {
    if (hasGitMarker(callHost, d)) return d;
  }
  return dirs[0];
}

/** Resolve a path inside the repository's .git metadata dir. */
export function gitPath(callHost, repoDir, rel, cfg = null, locale = 'zh') {
  const proc = runGit(callHost, ['rev-parse', '--git-path', rel], { cwd: repoDir, cfg, locale });
  if (proc.returncode === 0 && proc.stdout.trim()) {
    const raw = proc.stdout.trim().replace(/\\/g, '/');
    return raw.startsWith('/') || /^[a-zA-Z]:\//.test(raw) ? raw : posixJoin(trimTrailingSlash(repoDir), raw);
  }
  const [, gitDir] = resolveGitDir(callHost, repoDir);
  return gitDir ? posixJoin(gitDir, rel) : '';
}

function assertGitOperationFinished(callHost, repoDir, locale) {
  const [, gitDir] = resolveGitDir(callHost, repoDir);
  if (!gitDir) return;
  for (const [marker, operation] of [
    ['MERGE_HEAD', 'merge'], ['REBASE_HEAD', 'rebase'], ['rebase-merge', 'rebase'],
    ['rebase-apply', 'rebase'], ['CHERRY_PICK_HEAD', 'cherry-pick'],
  ]) {
    if (!fsStat(callHost, posixJoin(gitDir, marker)).exists) continue;
    throw new Error(tr(locale, `Git ${operation} 尚未结束。请先完成操作，或在仓库中运行 git ${operation} --abort，再重试同步。`, `A Git ${operation} is in progress. Finish it or run git ${operation} --abort in the repository before syncing.`));
  }
}

function loadGitPushedRefs(callHost, repoDir, cfg = null, locale = 'zh') {
  const p = gitPath(callHost, repoDir, 'block-sync-pushed-refs.json', cfg, locale);
  if (!p) return {};
  const raw = fsReadText(callHost, p);
  if (!raw) return {};
  try {
    const data = JSON.parse(raw);
    return data && typeof data === 'object' && !Array.isArray(data) ? data : {};
  } catch (_err) {
    return {};
  }
}

function recordGitSyncedBranch(callHost, repoDir, branch, oid, { remoteName = 'origin', cfg = null, locale = 'zh' } = {}) {
  const cleanOid = String(oid || '').trim();
  if (!cleanOid || !branch) return;
  const p = gitPath(callHost, repoDir, 'block-sync-pushed-refs.json', cfg, locale);
  if (!p) return;
  try {
    const data = loadGitPushedRefs(callHost, repoDir, cfg, locale);
    data[`${remoteName}:${branch}`] = cleanOid;
    delete data[`pending_initial:${remoteName}:${branch}`];
    fsWriteText(callHost, p, JSON.stringify(data), { atomic: true, mkdirParents: true });
  } catch (_err) {
    // Non-fatal metadata write.
  }
}

function recordGitPendingInitial(callHost, repoDir, branch, oid, { remoteName = 'origin', cfg = null, locale = 'zh' } = {}) {
  const cleanOid = String(oid || '').trim();
  if (!cleanOid || !branch) return;
  const p = gitPath(callHost, repoDir, 'block-sync-pushed-refs.json', cfg, locale);
  if (!p) return;
  try {
    const data = loadGitPushedRefs(callHost, repoDir, cfg, locale);
    if (!data[`${remoteName}:${branch}`]) {
      data[`pending_initial:${remoteName}:${branch}`] = cleanOid;
      fsWriteText(callHost, p, JSON.stringify(data), { atomic: true, mkdirParents: true });
    }
  } catch (_err) {
    // Non-fatal metadata write.
  }
}

function hasGitPendingInitial(callHost, repoDir, branch, { remoteName = 'origin', cfg = null, locale = 'zh' } = {}) {
  if (!repoDir || !branch || !hasGitMarker(callHost, repoDir)) return false;
  const data = loadGitPushedRefs(callHost, repoDir, cfg, locale);
  return Boolean(data[`pending_initial:${remoteName}:${branch}`]) && !Boolean(data[`${remoteName}:${branch}`]);
}

function getGitSyncedBranchOid(callHost, repoDir, branch, { remoteName = 'origin', cfg = null, locale = 'zh' } = {}) {
  if (!repoDir || !branch || !hasGitMarker(callHost, repoDir)) return '';
  const refProc = runGit(callHost, ['rev-parse', '--verify', `refs/remotes/${remoteName}/${branch}`], {
    cwd: repoDir,
    cfg,
    locale,
  });
  if (refProc.returncode === 0 && refProc.stdout.trim()) {
    return refProc.stdout.trim();
  }
  const data = loadGitPushedRefs(callHost, repoDir, cfg, locale);
  return String(data[`${remoteName}:${branch}`] || '').trim();
}

function gitBranchHasUpstreamConfig(callHost, repoDir, branch, { remoteName = 'origin', cfg = null, locale = 'zh' } = {}) {
  if (!repoDir || !branch || !hasGitMarker(callHost, repoDir)) return false;
  if (runGit(callHost, ['rev-parse', '--verify', `refs/heads/${branch}`], { cwd: repoDir, cfg, locale }).returncode !== 0) {
    return false;
  }
  const rProc = runGit(callHost, ['config', '--get', `branch.${branch}.remote`], { cwd: repoDir, cfg, locale });
  if (rProc.returncode !== 0 || rProc.stdout.trim() !== remoteName) return false;
  const mProc = runGit(callHost, ['config', '--get', `branch.${branch}.merge`], { cwd: repoDir, cfg, locale });
  if (mProc.returncode !== 0) return false;
  const merged = mProc.stdout.trim();
  return merged === `refs/heads/${branch}` || merged === branch;
}

function wasGitBranchSynced(callHost, repoDir, branch, { remoteName = 'origin', cfg = null, locale = 'zh' } = {}) {
  if (getGitSyncedBranchOid(callHost, repoDir, branch, { remoteName, cfg, locale })) return true;
  if (hasGitPendingInitial(callHost, repoDir, branch, { remoteName, cfg, locale })) return false;
  return gitBranchHasUpstreamConfig(callHost, repoDir, branch, { remoteName, cfg, locale });
}

/** Query remote branch heads using git ls-remote --heads. */
export function gitRemoteHeads(
  callHost,
  target,
  {
    cfg = null,
    cwd = '',
    timeoutMs = 10000,
    retries = 1,
    totalBudgetMs = 18000,
    locale = 'zh',
    nowMsFn = () => Date.now(),
    sleepFn = null,
    deadlineMs = 0,
  } = {}
) {
  const proc = runGitNetwork(callHost, ['ls-remote', '--heads', target], {
    cwd,
    timeoutMs,
    cfg,
    retries,
    totalBudgetMs,
    locale,
    nowMsFn,
    sleepFn,
    deadlineMs,
  });
  if (proc.returncode !== 0) {
    return [false, gitErrorMessage(locale, proc.stderr || proc.stdout, tr(locale, '连接失败', 'Connection failed'))];
  }
  if (proc.stdout_truncated) {
    return [false, tr(locale, 'Git 远端分支列表输出已截断', 'Git remote branch list output was truncated')];
  }
  const heads = [];
  for (const line of proc.stdout.split(/\r?\n/)) {
    const parts = line.trim().split('\t');
    if (parts.length >= 2 && parts[1].startsWith('refs/heads/')) {
      heads.push(parts[1].slice('refs/heads/'.length));
    }
  }
  return [true, heads];
}

/** Ensure every unpushed commit on branch was created by Block Sync. */
export function verifyGitPushHistory(callHost, repo, branch, head, remote, cfg, locale = 'zh') {
  const revRange = remote ? `${remote}..${head}` : head;
  const commits = runGit(callHost, ['rev-list', revRange], { cwd: repo, cfg, locale });
  if (commits.returncode === 0) assertGitOutputComplete(commits, 'git rev-list', { locale });
  const commitList = commits.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  if (commits.returncode === 0 && commitList.length === 0) return;

  const reflog = runGit(
    callHost,
    ['reflog', 'show', '--format=%H%x00%gs', `refs/heads/${branch}`],
    { cwd: repo, cfg, locale }
  );
  if (reflog.returncode === 0) assertGitOutputComplete(reflog, 'git reflog', { locale });
  const owned = new Set();
  for (const line of reflog.stdout.split(/\r?\n/)) {
    const idx = line.indexOf('\u0000');
    if (idx < 0) continue;
    const oid = line.slice(0, idx).trim();
    const message = line.slice(idx + 1).trim();
    if (message === 'sync: update markdown notes' && oid) {
      owned.add(oid);
    }
  }
  if (commits.returncode !== 0 || reflog.returncode !== 0 || commitList.some((oid) => !owned.has(oid))) {
    throw new Error(
      tr(
        locale,
        'Git 分支包含尚未推送的非同步提交。请先在 Git 中检查并处理这些提交，再重试同步。',
        'The Git branch has unpushed commits outside Block Sync. Review and handle them in Git, then retry sync.'
      )
    );
  }
}

// ============================================================================
// Git Maintenance & Pending-Push Branch Deduplication / Cleanup
// ============================================================================

const GIT_AUTO_GC_THRESHOLD = 256;
const GIT_AUTO_GC_INTERVAL_MS = 12 * 60 * 60 * 1000;
const GIT_AUTO_GC_SYNC_COUNT = 20;
const MIN_GIT_GC_BUDGET_MS = 12000;
const MAX_GIT_GC_TIMEOUT_MS = 30000;
const LS_TREE_BATCH_SIZE = 150;

function listPendingPushRefs(callHost, repoDir, branch, { cfg = null, locale = 'zh' } = {}) {
  const prefix = `pending-push-${branch}-`;
  const proc = runGit(
    callHost,
    ['for-each-ref', '--sort=-creatordate', '--format=%(refname)%09%(objectname)', 'refs/heads/'],
    { cwd: repoDir, cfg, locale }
  );
  if (proc.returncode !== 0 || proc.stdout_truncated) return null;
  if (!proc.stdout) return [];
  const items = [];
  for (const line of proc.stdout.split(/\r?\n/)) {
    if (!line) continue;
    const tab = line.indexOf('\t');
    if (tab < 0) continue;
    const fullRef = line.slice(0, tab).trim();
    const oid = line.slice(tab + 1).trim();
    if (!fullRef.startsWith('refs/heads/')) continue;
    const ref = fullRef.slice('refs/heads/'.length);
    if (ref.startsWith(prefix) && oid) {
      items.push({ ref, fullRef, oid });
    }
  }
  return items;
}

function isShallowGitRepo(callHost, repoDir, { cfg = null, locale = 'zh' } = {}) {
  const shallowFile = gitPath(callHost, repoDir, 'shallow', cfg, locale);
  if (shallowFile) {
    try {
      if (fsStat(callHost, shallowFile).exists) return true;
    } catch (_err) {
      return true;
    }
  }
  const proc = runGit(callHost, ['rev-parse', '--is-shallow-repository'], { cwd: repoDir, cfg, locale });
  if (proc.returncode !== 0) return true;
  return proc.stdout.trim() === 'true';
}

function cleanupPendingPushBranches(
  callHost,
  repoDir,
  branch,
  { targetRemoteRef = '', keepOid = '', cfg = null, locale = 'zh' } = {}
) {
  const refs = listPendingPushRefs(callHost, repoDir, branch, { cfg, locale });
  if (!refs || refs.length === 0) return '';

  let keptRefForKeepOid = '';
  if (keepOid) {
    for (const { ref, oid } of refs) {
      if (oid === keepOid) {
        keptRefForKeepOid = ref;
        break;
      }
    }
  }

  if (!targetRemoteRef) return keptRefForKeepOid;
  const chk = runGit(callHost, ['rev-parse', '--verify', `${targetRemoteRef}^{commit}`], { cwd: repoDir, cfg, locale });
  const remoteOid = chk.returncode === 0 ? chk.stdout.trim() : '';
  if (!remoteOid || isShallowGitRepo(callHost, repoDir, { cfg, locale })) {
    return keptRefForKeepOid;
  }

  for (const { ref, fullRef, oid } of refs) {
    const anc = runGit(callHost, ['merge-base', '--is-ancestor', oid, remoteOid], {
      cwd: repoDir,
      cfg,
      locale,
    });
    if (anc.returncode === 0) {
      const delProc = runGit(callHost, ['update-ref', '--no-deref', '-d', fullRef, oid], { cwd: repoDir, cfg, locale });
      if (delProc.returncode === 0 && ref === keptRefForKeepOid) {
        keptRefForKeepOid = '';
      }
    }
  }
  return keptRefForKeepOid;
}

function ensurePendingPushBackupRef(
  callHost,
  repoDir,
  branch,
  localOid,
  _localRef,
  { targetRemoteRef = '', cfg = null, locale = 'zh' } = {}
) {
  const existing = cleanupPendingPushBranches(callHost, repoDir, branch, {
    targetRemoteRef,
    keepOid: localOid,
    cfg,
    locale,
  });
  if (existing) return existing;
  if (!localOid) return '';
  const shortOid = String(localOid).slice(0, 12);
  const baseName = `pending-push-${branch}-${shortOid}`;
  for (let attempt = 0; attempt < 16; attempt += 1) {
    const candShort = attempt === 0 ? baseName : `${baseName}-${attempt + 1}`;
    const candFull = `refs/heads/${candShort}`;
    const checkProc = runGit(callHost, ['rev-parse', '--verify', candFull], { cwd: repoDir, cfg, locale });
    if (checkProc.returncode === 0) {
      if (checkProc.stdout.trim() === localOid) return candShort;
      continue;
    }
    const createProc = runGit(callHost, ['update-ref', candFull, localOid, ''], { cwd: repoDir, cfg, locale });
    if (createProc.returncode === 0) return candShort;
    const verifyProc = runGit(callHost, ['rev-parse', '--verify', candFull], { cwd: repoDir, cfg, locale });
    if (verifyProc.returncode === 0 && verifyProc.stdout.trim() === localOid) return candShort;
  }
  return '';
}

function maybeRunGitAutoGc(
  callHost,
  repoDir,
  { dataDir = '', nowMsFn = () => Date.now(), cfg = null, locale = 'zh', didCommit = false, deadlineMs = 0 } = {}
) {
  if (!repoDir || !isManagedGitDir(repoDir, dataDir)) return false;
  const rpc = resolveCallHost(callHost);
  const [hasMarker, rawGitDir] = resolveGitDir(rpc, repoDir);
  if (!hasMarker || !rawGitDir) return false;
  const metaPath = posixJoin(trimTrailingSlash(rawGitDir), 'block-sync-maintenance.json');
  const now = nowMsFn();
  let meta = { last_gc_ms: 0, syncs_since_gc: 0 };
  try {
    const raw = fsReadText(rpc, metaPath);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        meta = {
          last_gc_ms: Number(parsed.last_gc_ms) || 0,
          syncs_since_gc: Number(parsed.syncs_since_gc) || 0,
        };
      }
    }
  } catch (_err) {
    // Missing or corrupt maintenance state; reinitialize safely.
  }

  const nextCount = didCommit ? meta.syncs_since_gc + 1 : meta.syncs_since_gc;
  const persistDeferredCount = () => {
    if (!didCommit) return;
    try {
      fsWriteText(rpc, metaPath, JSON.stringify({ last_gc_ms: meta.last_gc_ms, syncs_since_gc: nextCount }), {
        atomic: false,
      });
    } catch (_err) {
      // Best-effort counter update.
    }
  };
  const due =
    meta.last_gc_ms <= 0 ||
    now - meta.last_gc_ms >= GIT_AUTO_GC_INTERVAL_MS ||
    nextCount >= GIT_AUTO_GC_SYNC_COUNT;
  if (!due) {
    persistDeferredCount();
    return false;
  }

  let gcTimeoutMs = MAX_GIT_GC_TIMEOUT_MS;
  if (deadlineMs > 0) {
    const remaining = deadlineMs - nowMsFn();
    if (remaining < MIN_GIT_GC_BUDGET_MS) {
      persistDeferredCount();
      return false;
    }
    gcTimeoutMs = Math.min(MAX_GIT_GC_TIMEOUT_MS, Math.max(1000, remaining - 2000));
  }

  try {
    const proc = runGit(
      rpc,
      ['-c', `gc.auto=${GIT_AUTO_GC_THRESHOLD}`, '-c', 'gc.autoDetach=false', 'gc', '--auto', '--quiet'],
      { cwd: repoDir, timeoutMs: gcTimeoutMs, cfg, locale }
    );
    if (proc.returncode === 0 && !proc.timed_out) {
      try {
        fsWriteText(rpc, metaPath, JSON.stringify({ last_gc_ms: nowMsFn(), syncs_since_gc: 0 }), { atomic: false });
      } catch (_writeErr) {
        // Best-effort maintenance timestamp write.
      }
      return true;
    }
    persistDeferredCount();
    return false;
  } catch (_err) {
    persistDeferredCount();
    return false;
  }
}

// ============================================================================
// Git Repo Preparation, Tracked Paths, Checkout Guard & Index Recovery
// ============================================================================

/** Prepare a managed remote clone or validate a local Git repository worktree. */
function buildGitNotebookTargets({
  notebooks = [],
  bindings = null,
  subdir = '',
  repoDir = '',
  targetBases = [],
  branch = '',
  excludedSubdirs = new Set(),
  configStore = null,
  homeDir = '',
} = {}) {
  const targets = [];
  for (const nb of notebooks) {
    if (!nb) continue;
    const sub = bindings ? String(bindings[nb] || '') : String(subdir || '');
    const nbKeyVal = configStore ? configStore.notebookKey(nb) : notebookKey(nb, '', homeDir);
    const metaTarget = sub ? `${repoDir}:${branch}::${sub}` : `${repoDir}:${branch}`;
    const metaKey = configStore ? configStore.metaKey('git', metaTarget, nbKeyVal) : `nb:${nbKeyVal}|git:${metaTarget}`;
    const legacyKey = !sub ? `git:${repoDir}:${branch}` : null;
    const aliases = (targetBases || []).map((base) => {
      const mt = sub ? `${base}::${sub}` : base;
      return configStore ? configStore.metaKey('git', mt, nbKeyVal) : `nb:${nbKeyVal}|git:${mt}`;
    });
    const legacyAliases = !sub ? (targetBases || []).map((base) => `git:${base}`) : [];
    const candidateLegacy = [legacyKey, ...legacyAliases].filter(Boolean);
    const allowLegacy =
      candidateLegacy.length > 0 &&
      Boolean(configStore) &&
      (!(typeof configStore.allowLegacyFallback === 'function') ||
        configStore.allowLegacyFallback(nbKeyVal, 'git', candidateLegacy));
    targets.push({
      nbRoot: nb,
      nbKeyVal,
      subdir: sub,
      metaKey,
      aliases,
      legacyKeys: allowLegacy ? candidateLegacy : [],
      excludedSubdirs: sub ? new Set() : excludedSubdirs,
    });
  }
  return targets;
}

function pruneUnverifiedGitDeletionsBeforePush(
  rpc,
  activeRepoDir,
  branch,
  localOid,
  expOid,
  { cfg = null, locale = 'zh', configStore = null, notebookTargets = null } = {}
) {
  if (!expOid || !localOid || localOid === expOid) {
    return { localOid, hasPush: Boolean(localOid && localOid !== expOid) };
  }
  const diffProc = runGit(
    rpc,
    ['-c', 'core.quotePath=false', 'diff', '--name-only', '--no-renames', '--diff-filter=D', '-z', expOid, localOid],
    { cwd: activeRepoDir, cfg, locale }
  );
  if (diffProc.returncode !== 0 || diffProc.stdout_truncated) {
    throw new Error(
      tr(
        locale,
        '无法确认上次未推送提交中的删除条目，已中止推送以保护数据',
        'Could not inspect deleted paths in pending unpushed commits; push aborted to protect data'
      )
    );
  }
  const deletedPaths = diffProc.stdout.split('\u0000').filter(Boolean);
  if (deletedPaths.length === 0) {
    return { localOid, hasPush: true };
  }

  const sortedTargets = [...(notebookTargets || [])].sort(
    (a, b) => (b.subdir || '').length - (a.subdir || '').length
  );
  const hasBaselineEntry = (t) => {
    if (!configStore || !configStore.state || !configStore.state.syncMeta) return false;
    const sm = configStore.state.syncMeta;
    const initMap = sm[INITIALIZED_META_KEY] || {};
    const keys = [t.metaKey, ...(t.aliases || []), ...(t.legacyKeys || [])].filter(Boolean);
    return keys.some(
      (k) => Boolean(initMap[k]) || (sm[k] && typeof sm[k] === 'object' && Object.keys(sm[k]).length > 0)
    );
  };
  const checkTargetVerified = (t) => {
    if (!t || !t.nbRoot || !configStore || typeof configStore.verifyNotebookIdentity !== 'function') {
      return false;
    }
    if (!hasBaselineEntry(t)) return false;
    const chk = configStore.verifyNotebookIdentity(t.nbRoot, {
      metaKey: t.metaKey,
      aliases: t.aliases || [],
      legacyKeys: t.legacyKeys || [],
      nbKeyVal: t.nbKeyVal,
      hasExistingBaseline: true,
    });
    return Boolean(
      chk &&
        chk.identity_ok === true &&
        chk.verified === true &&
        chk.root_identity &&
        chk.recorded_root_identity &&
        chk.root_identity === chk.recorded_root_identity
    );
  };

  const withdrawn = [];
  const verifiedCache = new Map();
  for (const repoRel of deletedPaths) {
    let matchedTarget = null;
    let relInNb = '';
    for (const t of sortedTargets) {
      const sub = (t.subdir || '').replace(/^\/+|\/+$/g, '');
      if (sub) {
        if (repoRel.startsWith(`${sub}/`)) {
          matchedTarget = t;
          relInNb = repoRel.slice(sub.length + 1);
          break;
        }
      } else if (!inSyncSubdir(repoRel, t.excludedSubdirs || new Set())) {
        matchedTarget = t;
        relInNb = repoRel;
        break;
      }
    }
    if (!matchedTarget || !relInNb) {
      withdrawn.push(repoRel);
      continue;
    }
    let idOk = verifiedCache.get(matchedTarget);
    if (idOk === undefined) {
      idOk = checkTargetVerified(matchedTarget);
      verifiedCache.set(matchedTarget, idOk);
    }
    if (!idOk || !isConfirmedAbsentOnRoot(rpc, matchedTarget.nbRoot, relInNb) || !checkTargetVerified(matchedTarget)) {
      withdrawn.push(repoRel);
    }
  }

  if (withdrawn.length === 0) {
    return { localOid, hasPush: true };
  }

  // Only rewrite unpushed commits created by Block Sync itself.
  verifyGitPushHistory(rpc, activeRepoDir, branch, localOid, expOid, cfg, locale);

  const expTreeProc = runGit(rpc, ['rev-parse', '--verify', `${expOid}^{tree}`], { cwd: activeRepoDir, cfg, locale });
  const localTreeProc = runGit(rpc, ['rev-parse', '--verify', `${localOid}^{tree}`], { cwd: activeRepoDir, cfg, locale });
  if (expTreeProc.returncode !== 0 || localTreeProc.returncode !== 0) {
    throw new Error(tr(locale, '撤回未确认 Git 删除时读取提交树失败', 'Failed to resolve Git tree while withdrawing deletions'));
  }
  const expTree = expTreeProc.stdout.trim();
  const localTree = localTreeProc.stdout.trim();

  const restoreEntries = [];
  for (let i = 0; i < withdrawn.length; i += LS_TREE_BATCH_SIZE) {
    const chunk = withdrawn.slice(i, i + LS_TREE_BATCH_SIZE);
    const lsProc = runGit(
      rpc,
      ['--literal-pathspecs', 'ls-tree', '-r', '-z', expOid, '--', ...chunk],
      { cwd: activeRepoDir, cfg, locale }
    );
    if (lsProc.returncode !== 0) {
      throw new Error(tr(locale, '撤回未确认 Git 删除失败，已中止推送', 'Failed to withdraw unverified Git deletions; push aborted'));
    }
    assertGitOutputComplete(lsProc, 'git ls-tree', { nulTerminated: true, locale });
    for (const item of parseLsTreeEntries(lsProc.stdout)) {
      restoreEntries.push([item.name, item.mode, item.oid]);
    }
  }
  if (restoreEntries.length !== withdrawn.length) {
    throw new Error(tr(locale, '撤回未确认 Git 删除时条目数量不一致，已中止推送', 'Git tree mismatch while withdrawing unverified deletions; push aborted'));
  }

  const newTree = buildGitTreeFromChanges(rpc, activeRepoDir, localTree, restoreEntries, { cfg, locale });
  const localRef = `refs/heads/${branch}`;
  const commitEnv = {
    GIT_AUTHOR_NAME: 'Block Sync',
    GIT_AUTHOR_EMAIL: 'sync@blockmd.local',
    GIT_COMMITTER_NAME: 'Block Sync',
    GIT_COMMITTER_EMAIL: 'sync@blockmd.local',
  };
  if (newTree === expTree) {
    const urProc = runGit(
      rpc,
      ['update-ref', '-m', 'sync: update markdown notes', localRef, expOid, localOid],
      { cwd: activeRepoDir, cfg, locale, extraEnv: commitEnv }
    );
    if (urProc.returncode !== 0) {
      throw new Error(tr(locale, '重置待推送 Git 提交失败', 'Failed to reset pending unpushed Git commit'));
    }
    return { localOid: expOid, hasPush: false };
  }

  const ctProc = runGit(
    rpc,
    ['commit-tree', newTree, '-p', expOid, '-m', 'sync: update markdown notes'],
    { cwd: activeRepoDir, cfg, locale, extraEnv: commitEnv }
  );
  if (ctProc.returncode !== 0 || !ctProc.stdout.trim()) {
    throw new Error(tr(locale, '重建待推送 Git 提交失败', 'Failed to rebuild pending Git commit without withdrawn deletions'));
  }
  const rebuiltOid = ctProc.stdout.trim();
  const urProc = runGit(
    rpc,
    ['update-ref', '-m', 'sync: update markdown notes', localRef, rebuiltOid, localOid],
    { cwd: activeRepoDir, cfg, locale, extraEnv: commitEnv }
  );
  if (urProc.returncode !== 0) {
    throw new Error(tr(locale, '更新重建后的 Git 分支失败', 'Failed to advance rebuilt Git branch'));
  }
  return { localOid: rebuiltOid, hasPush: true };
}

export function prepareGitRepo(
  callHost,
  cfg,
  {
    allowInitOrClone = true,
    allowPull = true,
    repoDir = null,
    dataDir = '',
    nbRoot = '',
    homeDir = '',
    locale = 'zh',
    nowMsFn = () => Date.now(),
    sleepFn = null,
    deadlineMs = 0,
    configStore = null,
    notebookTargets = null,
  } = {}
) {
  const rpc = resolveCallHost(callHost);
  const verProc = runGit(rpc, ['--version'], { cfg, locale });
  if (verProc.returncode !== 0) {
    return [false, tr(locale, '当前环境未安装 git 命令', 'Git is not installed')];
  }

  const target = String((cfg && cfg.git_remote) || '').trim();
  const branch = gitBranch(cfg);
  const activeRepoDir = repoDir || resolveLocalGitDir(rpc, cfg, { dataDir, nbRoot, homeDir, locale });
  const managedRemote = Boolean(target && isRemoteGitUrl(target));

  if (managedRemote && !managedGitCheckoutIsSafe(rpc, activeRepoDir, dataDir, cfg, locale)) {
    return [false, tr(locale, 'Git 缓存位置不安全，已停止同步', 'Git cache location is unsafe. Sync stopped.')];
  }
  if (activeRepoDir && hasGitMarker(rpc, activeRepoDir)) {
    try {
      assertGitOperationFinished(rpc, activeRepoDir, locale);
    } catch (exc) {
      return [false, errorDetail(locale, exc)];
    }
    recoverAbandonedGitIndex(rpc, activeRepoDir, { cfg, locale });
  }

  if (managedRemote) {
    const [okHeads, headsOrErr] = gitRemoteHeads(rpc, target, {
      cfg,
      timeoutMs: 10000,
      retries: 2,
      totalBudgetMs: 22000,
      locale,
      nowMsFn,
      sleepFn,
      deadlineMs,
    });
    if (!okHeads) {
      return [false, tr(locale, `Git 远端不可达: ${headsOrErr}`, `Git remote is unreachable: ${headsOrErr}`)];
    }
    const heads = headsOrErr;
    if (heads.length > 0 && !heads.includes(branch)) {
      const avail = heads.slice(0, 4).join(', ') + (heads.length > 4 ? '...' : '');
      return [
        false,
        tr(
          locale,
          `远端仓库不存在分支 ${branch}（已有分支：${avail}），请核对分支名后重试`,
          `Remote branch ${branch} does not exist (available: ${avail}); check the branch name and retry`
        ),
      ];
    }

    if (heads.length === 0) {
      if (!hasGitMarker(rpc, activeRepoDir)) {
        if (!allowInitOrClone) return [false, null];
        fsMkdir(rpc, activeRepoDir, true);
        let initProc = runGit(rpc, ['init', '-b', branch], { cwd: activeRepoDir, cfg, locale });
        if (initProc.returncode !== 0) {
          initProc = runGit(rpc, ['init'], { cwd: activeRepoDir, cfg, locale });
          if (initProc.returncode === 0) {
            runGit(rpc, ['symbolic-ref', 'HEAD', `refs/heads/${branch}`], { cwd: activeRepoDir, cfg, locale });
          }
        }
        if (initProc.returncode !== 0) {
          return [false, tr(locale, 'Git 仓库初始化失败', 'Could not initialize the Git repository')];
        }
        runGit(rpc, ['remote', 'add', 'origin', target], { cwd: activeRepoDir, cfg, locale });
      } else {
        const urlProc = runGit(rpc, ['remote', 'get-url', 'origin'], { cwd: activeRepoDir, cfg, locale });
        if (urlProc.returncode !== 0) {
          runGit(rpc, ['remote', 'add', 'origin', target], { cwd: activeRepoDir, cfg, locale });
        } else if (urlProc.stdout.trim() !== target) {
          runGit(rpc, ['remote', 'set-url', 'origin', target], { cwd: activeRepoDir, cfg, locale });
        }
        if (allowPull) {
          if (wasGitBranchSynced(rpc, activeRepoDir, branch, { remoteName: 'origin', cfg, locale })) {
            return [
              false,
              tr(
                locale,
                `远端分支 ${branch} 已不存在（疑似被删除或重置），为避免未经确认重建远端历史已中止同步`,
                `Remote branch ${branch} no longer exists (it may have been deleted or reset); sync aborted to avoid silently recreating remote history`
              ),
            ];
          }
          if (!managedGitCheckoutIsSafe(rpc, activeRepoDir, dataDir, cfg, locale)) {
            return [false, tr(locale, 'Git 缓存位置不安全，已停止同步', 'Git cache location is unsafe. Sync stopped.')];
          }
          runGit(rpc, ['rebase', '--abort'], { cwd: activeRepoDir, cfg, locale });
          runGit(rpc, ['merge', '--abort'], { cwd: activeRepoDir, cfg, locale });
          if (!hasGitPendingInitial(rpc, activeRepoDir, branch, { remoteName: 'origin', cfg, locale })) {
            const headChk = runGit(rpc, ['rev-parse', '--verify', 'HEAD'], { cwd: activeRepoDir, cfg, locale });
            if (headChk.returncode === 0) {
              try {
                deleteDataPath(rpc, activeRepoDir, { recursive: true, baseDir: dataDir });
              } catch (_err) {
                // Ignore if direct root; re-init below.
              }
              fsMkdir(rpc, activeRepoDir, true);
              let initProc = runGit(rpc, ['init', '-b', branch], { cwd: activeRepoDir, cfg, locale });
              if (initProc.returncode !== 0) {
                runGit(rpc, ['init'], { cwd: activeRepoDir, cfg, locale });
                runGit(rpc, ['symbolic-ref', 'HEAD', `refs/heads/${branch}`], { cwd: activeRepoDir, cfg, locale });
              }
              runGit(rpc, ['remote', 'add', 'origin', target], { cwd: activeRepoDir, cfg, locale });
            } else {
              runGit(rpc, ['symbolic-ref', 'HEAD', `refs/heads/${branch}`], { cwd: activeRepoDir, cfg, locale });
              runGit(rpc, ['clean', '-fdx'], { cwd: activeRepoDir, cfg, locale });
            }
          }
        }
      }
      return [true, activeRepoDir];
    }

    // Remote has the requested branch.
    if (!hasGitMarker(rpc, activeRepoDir)) {
      if (!allowInitOrClone) return [false, null];
      const parentDir = posixDirname(activeRepoDir);
      if (parentDir) fsMkdir(rpc, parentDir, true);
      const existedBefore = Boolean(fsStat(rpc, activeRepoDir).exists);

      const cleanupPartialClone = () => {
        if (!existedBefore && fsStat(rpc, activeRepoDir).exists) {
          try {
            deleteDataPath(rpc, activeRepoDir, { recursive: true, baseDir: dataDir });
          } catch (_err) {
            // Best-effort cleanup.
          }
        }
      };

      const cloneProc = runGitNetwork(
        rpc,
        ['clone', '--branch', branch, '--single-branch', target, activeRepoDir],
        {
          timeoutMs: 15000,
          cfg,
          retries: 2,
          totalBudgetMs: 30000,
          onRetry: cleanupPartialClone,
          locale,
          nowMsFn,
          sleepFn,
          deadlineMs,
        }
      );
      if (cloneProc.returncode !== 0) {
        cleanupPartialClone();
        const err = gitErrorMessage(locale, cloneProc.stderr || cloneProc.stdout, tr(locale, 'clone 失败', 'Clone failed'));
        return [false, tr(locale, `Git 远端不可达: ${err}`, `Git remote is unreachable: ${err}`)];
      }
      const oidP = runGit(rpc, ['rev-parse', '--verify', `refs/remotes/origin/${branch}`], {
        cwd: activeRepoDir,
        cfg,
        locale,
      });
      if (oidP.returncode === 0 && oidP.stdout.trim()) {
        recordGitSyncedBranch(rpc, activeRepoDir, branch, oidP.stdout.trim(), { remoteName: 'origin', cfg, locale });
      }
    } else {
      const urlProc = runGit(rpc, ['remote', 'get-url', 'origin'], { cwd: activeRepoDir, cfg, locale });
      if (urlProc.returncode !== 0) {
        runGit(rpc, ['remote', 'add', 'origin', target], { cwd: activeRepoDir, cfg, locale });
      } else if (urlProc.stdout.trim() !== target) {
        runGit(rpc, ['remote', 'set-url', 'origin', target], { cwd: activeRepoDir, cfg, locale });
      }

      if (allowPull) {
        runGit(rpc, ['rebase', '--abort'], { cwd: activeRepoDir, cfg, locale });
        runGit(rpc, ['merge', '--abort'], { cwd: activeRepoDir, cfg, locale });
        const fetchProc = runGitNetwork(
          rpc,
          ['fetch', 'origin', `refs/heads/${branch}:refs/remotes/origin/${branch}`],
          {
            cwd: activeRepoDir,
            timeoutMs: 12000,
            cfg,
            retries: 2,
            totalBudgetMs: 22000,
            locale,
            nowMsFn,
            sleepFn,
            deadlineMs,
          }
        );
        if (fetchProc.returncode !== 0) {
          const err = gitErrorMessage(locale, fetchProc.stderr || fetchProc.stdout, tr(locale, 'fetch 失败', 'Fetch failed'));
          return [false, tr(locale, `Git 拉取失败: ${err}`, `Git pull failed: ${err}`)];
        }
        const oidP = runGit(rpc, ['rev-parse', '--verify', `refs/remotes/origin/${branch}`], {
          cwd: activeRepoDir,
          cfg,
          locale,
        });
        if (oidP.returncode === 0 && oidP.stdout.trim()) {
          recordGitSyncedBranch(rpc, activeRepoDir, branch, oidP.stdout.trim(), { remoteName: 'origin', cfg, locale });
        }

        if (isManagedGitDir(activeRepoDir, dataDir)) {
          const localRef = `refs/heads/${branch}`;
          const remoteRef = `refs/remotes/origin/${branch}`;
          const localOidProc = runGit(rpc, ['rev-parse', '--verify', localRef], { cwd: activeRepoDir, cfg, locale });
          const localOid = localOidProc.returncode === 0 ? localOidProc.stdout.trim() : '';
          if (localOid) {
            const aheadP = runGit(rpc, ['rev-list', '--count', `${remoteRef}..${localOid}`], {
              cwd: activeRepoDir,
              cfg,
              locale,
            });
            const behindP = runGit(rpc, ['rev-list', '--count', `${localOid}..${remoteRef}`], {
              cwd: activeRepoDir,
              cfg,
              locale,
            });
            const aheadN = aheadP.returncode === 0 ? Number.parseInt(aheadP.stdout.trim() || '0', 10) || 0 : 0;
            const behindN = behindP.returncode === 0 ? Number.parseInt(behindP.stdout.trim() || '0', 10) || 0 : 0;
            if (aheadN > 0) {
              if (behindN === 0) {
                const expOidP = runGit(rpc, ['rev-parse', '--verify', remoteRef], { cwd: activeRepoDir, cfg, locale });
                const expOid = expOidP.returncode === 0 ? expOidP.stdout.trim() : '';
                const pruned = pruneUnverifiedGitDeletionsBeforePush(
                  rpc,
                  activeRepoDir,
                  branch,
                  localOid,
                  expOid,
                  { cfg, locale, configStore, notebookTargets }
                );
                if (pruned.hasPush) {
                  const pushOid = pruned.localOid;
                  verifyGitPushHistory(rpc, activeRepoDir, branch, pushOid, expOid, cfg, locale);
                  const leaseArg = `--force-with-lease=refs/heads/${branch}:${expOid}`;
                  const retryPush = runGitNetwork(
                    rpc,
                    ['push', leaseArg, '-u', 'origin', `${pushOid}:refs/heads/${branch}`],
                    {
                      cwd: activeRepoDir,
                      timeoutMs: 60000,
                      cfg,
                      retries: 1,
                      totalBudgetMs: 80000,
                      locale,
                      nowMsFn,
                      sleepFn,
                      deadlineMs,
                    }
                  );
                  if (retryPush.returncode === 0) {
                    runGitNetwork(
                      rpc,
                      ['fetch', 'origin', `refs/heads/${branch}:refs/remotes/origin/${branch}`],
                      {
                        cwd: activeRepoDir,
                        timeoutMs: 12000,
                        cfg,
                        retries: 1,
                        totalBudgetMs: 15000,
                        locale,
                        nowMsFn,
                        sleepFn,
                        deadlineMs,
                      }
                    );
                    const oidP2 = runGit(rpc, ['rev-parse', '--verify', remoteRef], { cwd: activeRepoDir, cfg, locale });
                    const syncedOid = oidP2.returncode === 0 ? oidP2.stdout.trim() : '';
                    if (syncedOid) {
                      recordGitSyncedBranch(rpc, activeRepoDir, branch, syncedOid, {
                        remoteName: 'origin',
                        cfg,
                        locale,
                      });
                    }
                    cleanupPendingPushBranches(rpc, activeRepoDir, branch, {
                      targetRemoteRef: syncedOid || remoteRef,
                      cfg,
                      locale,
                    });
                  } else {
                    const backupRef = ensurePendingPushBackupRef(rpc, activeRepoDir, branch, pushOid, localRef, {
                      targetRemoteRef: remoteRef,
                      cfg,
                      locale,
                    });
                    const err = gitErrorMessage(
                      locale,
                      retryPush.stderr || retryPush.stdout,
                      tr(locale, 'push 失败', 'Push failed')
                    );
                    return [
                      false,
                      backupRef
                        ? tr(
                            locale,
                            `上次未推送的 Git 提交重试推送失败（已保留于分支 ${backupRef}）: ${err}`,
                            `Retry push of pending Git commits failed (preserved on branch ${backupRef}): ${err}`
                          )
                        : tr(
                            locale,
                            `上次未推送的 Git 提交重试推送失败（未能创建备份分支，请检查本地 Git 状态）: ${err}`,
                            `Retry push of pending Git commits failed (backup branch could not be created; check local Git state): ${err}`
                          ),
                    ];
                  }
                }
              } else {
                const backupRef = ensurePendingPushBackupRef(rpc, activeRepoDir, branch, localOid, localRef, {
                  targetRemoteRef: remoteRef,
                  cfg,
                  locale,
                });
                return [
                  false,
                  backupRef
                    ? tr(
                        locale,
                        `检测到 ${aheadN} 个尚未推送的本地提交与远端 ${branch} 分叉，已保留于分支 ${backupRef}，请先处理分叉`,
                        `Found ${aheadN} unpushed local commits diverged from remote ${branch}; preserved on branch ${backupRef}`
                      )
                    : tr(
                        locale,
                        `检测到 ${aheadN} 个尚未推送的本地提交与远端 ${branch} 分叉，且未能创建备份分支，请先手动检查本地仓库后再处理分叉`,
                        `Found ${aheadN} unpushed local commits diverged from remote ${branch}, and failed to create a backup branch; inspect the local repository manually`
                      ),
                ];
              }
            }
          }
        }

        if (!managedGitCheckoutIsSafe(rpc, activeRepoDir, dataDir, cfg, locale)) {
          return [false, tr(locale, 'Git 缓存位置不安全，已停止同步', 'Git cache location is unsafe. Sync stopped.')];
        }
        const coProc = runGit(rpc, ['checkout', '-f', '-B', branch, `refs/remotes/origin/${branch}`], {
          cwd: activeRepoDir,
          cfg,
          locale,
        });
        if (coProc.returncode !== 0) {
          const err = gitErrorMessage(locale, coProc.stderr || coProc.stdout, tr(locale, '切换分支失败', 'Checkout failed'));
          return [false, tr(locale, `Git 切换分支失败: ${err}`, `Git branch checkout failed: ${err}`)];
        }
        runGit(rpc, ['reset', '--hard', `refs/remotes/origin/${branch}`], { cwd: activeRepoDir, cfg, locale });
        runGit(rpc, ['clean', '-fdx'], { cwd: activeRepoDir, cfg, locale });
        if (isManagedGitDir(activeRepoDir, dataDir)) {
          cleanupPendingPushBranches(rpc, activeRepoDir, branch, {
            targetRemoteRef: `refs/remotes/origin/${branch}`,
            cfg,
            locale,
          });
        }
      }
    }
    return [true, activeRepoDir];
  }

  // Local Git repository mode.
  if (!hasGitMarker(rpc, activeRepoDir)) {
    if (!allowInitOrClone) return [false, null];
    fsMkdir(rpc, activeRepoDir, true);
    let initProc = runGit(rpc, ['init', '-b', branch], { cwd: activeRepoDir, cfg, locale });
    if (initProc.returncode !== 0) {
      initProc = runGit(rpc, ['init'], { cwd: activeRepoDir, cfg, locale });
      if (initProc.returncode === 0) {
        runGit(rpc, ['symbolic-ref', 'HEAD', `refs/heads/${branch}`], { cwd: activeRepoDir, cfg, locale });
      }
    }
    if (initProc.returncode !== 0) {
      return [false, tr(locale, 'Git 仓库初始化失败', 'Could not initialize the Git repository')];
    }
    return [true, activeRepoDir];
  }

  const curBr = gitCurrentBranch(rpc, activeRepoDir, cfg, locale);
  if (curBr !== branch) {
    const curLabel = curBr || 'detached HEAD';
    return [
      false,
      tr(
        locale,
        `本地 Git 仓库当前位于 ${curLabel}，请先切换到 ${branch}`,
        `Local Git repository is at {curLabel}. Switch to ${branch} before syncing.`.replace('{curLabel}', curLabel)
      ),
    ];
  }

  if (allowPull) {
    const remoteProc = runGit(rpc, ['remote'], { cwd: activeRepoDir, cfg, locale });
    const remotes =
      remoteProc.returncode === 0
        ? remoteProc.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean)
        : [];
    if (remotes.length > 0) {
      const remoteName = remotes.includes('origin') ? 'origin' : remotes[0];
      const [okHeads, headsOrErr] = gitRemoteHeads(rpc, remoteName, {
        cfg,
        cwd: activeRepoDir,
        timeoutMs: 10000,
        retries: 1,
        totalBudgetMs: 18000,
        locale,
        nowMsFn,
        sleepFn,
        deadlineMs,
      });
      if (!okHeads) {
        return [false, tr(locale, `Git 远端拉取失败: ${headsOrErr}`, `Git remote pull failed: ${headsOrErr}`)];
      }
      if (headsOrErr.length > 0 && !headsOrErr.includes(branch)) {
        const avail = headsOrErr.slice(0, 4).join(', ') + (headsOrErr.length > 4 ? '...' : '');
        return [
          false,
          tr(
            locale,
            `远端 ${remoteName} 不存在分支 ${branch}（已有分支：${avail}）`,
            `Remote ${remoteName} does not have branch ${branch} (available: ${avail})`
          ),
        ];
      }
      if (
        headsOrErr.length === 0 &&
        wasGitBranchSynced(rpc, activeRepoDir, branch, { remoteName, cfg, locale })
      ) {
        return [
          false,
          tr(
            locale,
            `远端 ${remoteName} 的分支 ${branch} 已不存在（疑似被删除或重置），为避免未经确认重建远端历史已中止同步`,
            `Remote ${remoteName} branch ${branch} no longer exists (it may have been deleted or reset); sync aborted to avoid silently recreating remote history`
          ),
        ];
      }
      if (headsOrErr.includes(branch)) {
        const fetchProc = runGitNetwork(
          rpc,
          ['fetch', remoteName, `refs/heads/${branch}:refs/remotes/${remoteName}/${branch}`],
          {
            cwd: activeRepoDir,
            timeoutMs: 12000,
            cfg,
            retries: 2,
            totalBudgetMs: 22000,
            locale,
            nowMsFn,
            sleepFn,
            deadlineMs,
          }
        );
        if (fetchProc.returncode !== 0) {
          const err = gitErrorMessage(locale, fetchProc.stderr || fetchProc.stdout, tr(locale, 'fetch 失败', 'Fetch failed'));
          return [false, tr(locale, `Git 拉取失败: ${err}`, `Git pull failed: ${err}`)];
        }
        const remoteRef = `refs/remotes/${remoteName}/${branch}`;
        const oidP = runGit(rpc, ['rev-parse', '--verify', remoteRef], { cwd: activeRepoDir, cfg, locale });
        const remoteOid = oidP.returncode === 0 ? oidP.stdout.trim() : '';
        if (!remoteOid) {
          return [false, tr(locale, '无法读取 Git 远端提交', 'Could not read the fetched Git commit')];
        }
        recordGitSyncedBranch(rpc, activeRepoDir, branch, remoteOid, { remoteName, cfg, locale });
        const headChk = runGit(rpc, ['rev-parse', '--verify', 'HEAD'], { cwd: activeRepoDir, cfg, locale });
        const head = headChk.returncode === 0 ? headChk.stdout.trim() : '';
        if (
          head === remoteOid ||
          (head &&
            runGit(rpc, ['merge-base', '--is-ancestor', remoteOid, head], {
              cwd: activeRepoDir,
              cfg,
              locale,
            }).returncode === 0)
        ) {
          return [true, activeRepoDir];
        }
        if (
          head &&
          runGit(rpc, ['merge-base', '--is-ancestor', head, remoteOid], {
            cwd: activeRepoDir,
            cfg,
            locale,
          }).returncode !== 0
        ) {
          return [
            false,
            tr(
              locale,
              `本地 Git 仓库与远端 ${remoteName}/${branch} 已分叉，请先手动合并`,
              `Local Git repository diverged from ${remoteName}/${branch}; resolve manually.`
            ),
          ];
        }
        return [
          false,
          tr(
            locale,
            `请先在 Git 中将本地工作区的 ${branch} 更新到 ${remoteName}/${branch}，再重试同步`,
            `Update the local Git worktree on ${branch} to ${remoteName}/${branch} in Git, then retry sync.`
          ),
        ];
      }
    }
  }

  return [true, activeRepoDir];
}

/** Return Set of git-tracked paths relative to subdir (or repoRoot). */
export function gitTrackedRelPaths(callHost, repoRoot, { subdir = '', cfg = null, strict = false, locale = 'zh' } = {}) {
  if (!repoRoot || !hasGitMarker(callHost, repoRoot)) {
    if (strict) {
      throw new Error(
        tr(
          locale,
          'Git 托管副本缺少仓库元数据，已中止同步',
          'Managed Git clone is missing repository metadata; sync aborted'
        )
      );
    }
    return null;
  }
  const proc = runGit(callHost, ['ls-files', '-z'], { cwd: repoRoot, cfg, locale });
  if (proc.returncode !== 0) {
    if (strict) {
      const err = errorDetail(locale, proc.stderr || proc.stdout || tr(locale, 'git ls-files 失败', 'git ls-files failed'));
      throw new Error(
        tr(
          locale,
          `无法读取 Git 托管副本的跟踪文件清单: ${err}`,
          `Could not read tracked file list for managed Git clone: ${err}`
        )
      );
    }
    return null;
  }
  if (proc.stdout_truncated || (proc.stdout && !proc.stdout.endsWith('\u0000'))) {
    if (strict) {
      assertGitOutputComplete(proc, 'git ls-files', { nulTerminated: true, locale });
    }
    return null;
  }
  const sub = String(subdir || '').replace(/^\/+|\/+$/g, '');
  const prefix = sub ? `${sub}/` : '';
  const tracked = new Set();
  for (const raw of proc.stdout.split('\u0000')) {
    if (!raw) continue;
    const rel = raw.replace(/\\/g, '/');
    if (prefix) {
      if (rel.startsWith(prefix)) tracked.add(rel.slice(prefix.length));
    } else {
      tracked.add(rel);
    }
  }
  return tracked;
}

/** Align worktree item keys to exact git-tracked path casings when disks fold case/NFC. */
export function alignPathsToTracked(callHost, itemsMap, trackedPaths, targetDir) {
  if (!trackedPaths || !itemsMap) return itemsMap;
  const trackedByFold = new Map();
  for (const tp of [...trackedPaths].sort()) {
    const fk = foldSyncPath(tp, { caseInsensitive: true, normalize: true });
    if (!trackedByFold.has(fk)) trackedByFold.set(fk, []);
    trackedByFold.get(fk).push(tp);
  }
  const aligned = {};
  for (const [k, v] of Object.entries(itemsMap)) {
    if (trackedPaths.has(k)) {
      aligned[k] = v;
      continue;
    }
    const fk = foldSyncPath(k, { caseInsensitive: true, normalize: true });
    const hits = (trackedByFold.get(fk) || []).filter((tp) => pathsCollapse(callHost, targetDir, k, tp));
    if (hits.length === 1) {
      aligned[hits[0]] = v;
    }
  }
  return aligned;
}

/** Align Map<relPath, entry> keys to exact git-tracked path casings when disks fold case/NFC. */
export function alignEntryMapToTracked(callHost, entriesMap, trackedPaths, targetDir) {
  if (!trackedPaths || !(entriesMap instanceof Map)) return entriesMap;
  const trackedByFold = new Map();
  for (const tp of [...trackedPaths].sort()) {
    const fk = foldSyncPath(tp, { caseInsensitive: true, normalize: true });
    if (!trackedByFold.has(fk)) trackedByFold.set(fk, []);
    trackedByFold.get(fk).push(tp);
  }
  const aligned = new Map();
  for (const [k, v] of entriesMap.entries()) {
    if (trackedPaths.has(k)) {
      aligned.set(k, v);
      continue;
    }
    const fk = foldSyncPath(k, { caseInsensitive: true, normalize: true });
    const hits = (trackedByFold.get(fk) || []).filter((tp) => pathsCollapse(callHost, targetDir, k, tp));
    if (hits.length === 1) {
      aligned.set(hits[0], v);
    }
  }
  return aligned;
}

function gitCheckoutState(callHost, repo, cfg, expected = null, locale = 'zh') {
  const branch = gitBranch(cfg);
  const head = runGit(callHost, ['rev-parse', '--verify', `refs/heads/${branch}`], { cwd: repo, cfg, locale });
  const st = fsStat(callHost, trimTrailingSlash(repo));
  const state = [st.path || trimTrailingSlash(repo), head.returncode === 0 ? head.stdout.trim() : ''];
  const curBr = gitCurrentBranch(callHost, repo, cfg, locale);
  if (curBr !== branch || (expected && (state[0] !== expected[0] || state[1] !== expected[1]))) {
    throw new Error(
      tr(locale, 'Git 工作区已切换或更新，请重试同步', 'The Git worktree switched branches or changed. Retry sync.')
    );
  }
  return state;
}

function writeGitIndexOwner(callHost, repoRoot, { cfg = null, pid = 1, locale = 'zh' } = {}) {
  const p = gitPath(callHost, repoRoot, 'block-sync-index.owner', cfg, locale);
  if (!p) return '';
  fsWriteText(callHost, p, `${pid}\n`, { atomic: true, mkdirParents: true });
  return p;
}

function clearGitIndexOwner(callHost, ownerPath) {
  if (!ownerPath) return;
  try {
    fsDelete(callHost, ownerPath);
  } catch (_err) {
    // Ignore cleanup errors.
  }
}

/** Repair .git/index to match HEAD when a prior index replacement was interrupted. */
export function repairGitIndexToHead(callHost, repoRoot, { cfg = null, locale = 'zh' } = {}) {
  const head = runGit(callHost, ['rev-parse', '--verify', 'HEAD'], { cwd: repoRoot, cfg, locale });
  if (head.returncode !== 0 || !head.stdout.trim()) return;
  const headOid = head.stdout.trim();

  const parent = runGit(callHost, ['rev-parse', '--verify', 'HEAD^'], { cwd: repoRoot, cfg, locale });
  const parentOid = parent.returncode === 0 ? parent.stdout.trim() : '';
  const parentEntries = new Map();
  if (parentOid) {
    const listed = runGit(callHost, ['ls-tree', '-r', '-z', parentOid], { cwd: repoRoot, cfg, locale });
    if (listed.returncode !== 0) {
      throw new Error(
        tr(
          locale,
          `Git 索引修复失败: ${errorDetail(locale, listed.stderr || listed.stdout)}`,
          `Git index repair failed: ${errorDetail(locale, listed.stderr || listed.stdout)}`
        )
      );
    }
    assertGitOutputComplete(listed, 'git ls-tree', { nulTerminated: true, locale });
    for (const entry of listed.stdout.split('\u0000')) {
      const tabIdx = entry.indexOf('\t');
      if (tabIdx < 0) continue;
      const parts = entry.slice(0, tabIdx).split(/\s+/);
      if (parts.length >= 3) {
        parentEntries.set(entry.slice(tabIdx + 1).replace(/\\/g, '/'), parts[2]);
      }
    }
  }

  const diff = runGit(callHost, ['diff-index', '--cached', '-z', headOid], { cwd: repoRoot, cfg, locale });
  if (diff.returncode !== 0) {
    throw new Error(
      tr(
        locale,
        `Git 索引修复失败: ${errorDetail(locale, diff.stderr || diff.stdout)}`,
        `Git index repair failed: ${errorDetail(locale, diff.stderr || diff.stdout)}`
      )
    );
  }
  assertGitOutputComplete(diff, 'git diff-index', { nulTerminated: true, locale });

  const rawParts = diff.stdout.split('\u0000');
  const updates = [];
  let cursor = 0;
  while (cursor < rawParts.length - 1) {
    const meta = rawParts[cursor];
    const pathStr = rawParts[cursor + 1];
    cursor += 2;
    if (!meta.startsWith(':')) continue;
    const fields = meta.slice(1).split(' ');
    if (fields.length < 5) continue;
    const status = fields[4];
    if ((status.startsWith('R') || status.startsWith('C')) && cursor < rawParts.length) {
      cursor += 1;
      continue;
    }
    const cleanPath = pathStr.replace(/\\/g, '/');
    const headMode = fields[0];
    const headSha = fields[2];
    const indexSha = fields[3];
    const parentSha = parentEntries.get(cleanPath) || '';
    const indexMissing = /^0+$/.test(indexSha);
    if (indexSha === parentSha || (indexMissing && !parentSha)) {
      if (headMode && !/^0+$/.test(headSha)) {
        updates.push([headMode, headSha, cleanPath]);
      }
    }
  }
  if (updates.length === 0) return;

  const payload = updates.map(([mode, oid, p]) => `${mode} ${oid}\t${p}\u0000`).join('');
  const updated = runGit(callHost, ['update-index', '-z', '--index-info'], {
    cwd: repoRoot,
    cfg,
    locale,
    stdin: payload,
  });
  if (updated.returncode !== 0) {
    throw new Error(
      tr(
        locale,
        `Git 索引修复失败: ${errorDetail(locale, updated.stderr || updated.stdout)}`,
        `Git index repair failed: ${errorDetail(locale, updated.stderr || updated.stdout)}`
      )
    );
  }
}

/** Recover from an abandoned prior index replacement owned by a dead/same process. */
export function recoverAbandonedGitIndex(callHost, repoRoot, { cfg = null, pid = 1, locale = 'zh' } = {}) {
  const ownerPath = gitPath(callHost, repoRoot, 'block-sync-index.owner', cfg, locale);
  if (!ownerPath) return;
  const st = fsStat(callHost, ownerPath);
  if (!st.exists) return;
  const raw = fsReadText(callHost, ownerPath) || '';
  const ownerPid = Number.parseInt(raw.trim() || '0', 10) || 0;
  if (ownerPid && ownerPid !== pid) {
    // Only clean stale owner older than 30s if PID differs (no process table access in plugin runtime).
    if (st.mod_time_ms && Date.now() - st.mod_time_ms < 30000) {
      return;
    }
  }
  const indexPath = gitPath(callHost, repoRoot, 'index', cfg, locale);
  if (indexPath) {
    try {
      fsDelete(callHost, `${indexPath}.lock`);
    } catch (_err) {
      // Ignore missing lock.
    }
  }
  repairGitIndexToHead(callHost, repoRoot, { cfg, locale });
  clearGitIndexOwner(callHost, ownerPath);
}

/** Abort if any planned sync path already has independent staged changes in Git index. */
export function checkGitStagedConflicts(
  callHost,
  repoRoot,
  relPaths,
  { cfg = null, recover = true, dataDir = '', pid = 1, locale = 'zh' } = {}
) {
  const cleaned = [...new Set((relPaths || []).map(normalizeGitRel).filter(Boolean))].sort();
  if (!repoRoot || !hasGitMarker(callHost, repoRoot)) return;
  if (recover) recoverAbandonedGitIndex(callHost, repoRoot, { cfg, pid, locale });
  if (cleaned.length === 0) return;
  if (isManagedGitDir(repoRoot, dataDir)) return;

  const hasHead = runGit(callHost, ['rev-parse', '--verify', 'HEAD'], { cwd: repoRoot, cfg, locale }).returncode === 0;
  const stagedSet = new Set();
  for (let i = 0; i < cleaned.length; i += LS_TREE_BATCH_SIZE) {
    const chunk = cleaned.slice(i, i + LS_TREE_BATCH_SIZE);
    const args = hasHead
      ? ['--literal-pathspecs', 'diff', '--cached', '--name-only', '-z', '--', ...chunk]
      : ['--literal-pathspecs', 'ls-files', '--cached', '-z', '--', ...chunk];
    const proc = runGit(callHost, args, { cwd: repoRoot, cfg, locale });
    if (proc.returncode !== 0) {
      const err = errorDetail(locale, proc.stderr || proc.stdout || tr(locale, 'git 暂存区检查失败', 'git staged index check failed'));
      throw new Error(tr(locale, `Git 暂存区检查失败: ${err}`, `Git staged index check failed: ${err}`));
    }
    assertGitOutputComplete(proc, hasHead ? 'git diff --cached' : 'git ls-files --cached', { nulTerminated: true, locale });
    for (const raw of proc.stdout.split('\u0000')) {
      const p = raw.replace(/\\/g, '/');
      if (p) stagedSet.add(p);
    }
  }
  const stagedHits = [...stagedSet].sort();
  if (stagedHits.length > 0) {
    const sample = stagedHits.slice(0, 3).join(', ') + (stagedHits.length > 3 ? '...' : '');
    throw new Error(
      tr(
        locale,
        `Git 暂存区已有这些文件的待提交改动，请先提交或取消暂存后再同步：${sample}`,
        `Git index already has staged changes for planned sync files; commit or unstage them first: ${sample}`
      )
    );
  }
}

/** Fail loudly if .gitignore / .git/info/exclude blocks any file in the sync plan. */
export function checkGitIgnored(callHost, repoRoot, relPaths, { cfg = null, locale = 'zh' } = {}) {
  const normPaths = [...new Set((relPaths || []).map(normalizeGitRel).filter(Boolean))].sort();
  if (normPaths.length === 0) return;
  const chkInput = normPaths.map((p) => `./${p}\u0000`).join('');
  const chk = runGit(callHost, ['check-ignore', '-z', '--stdin'], {
    cwd: repoRoot,
    cfg,
    locale,
    stdin: chkInput,
  });
  if (chk.returncode !== 0 && chk.returncode !== 1) {
    const err = errorDetail(locale, chk.stderr || chk.stdout || tr(locale, 'git check-ignore 失败', 'git check-ignore failed'));
    throw new Error(tr(locale, `Git 忽略规则检查失败: ${err}`, `Git ignore check failed: ${err}`));
  }
  assertGitOutputComplete(chk, 'git check-ignore', { nulTerminated: true, locale });
  const ignored = [];
  for (const raw of chk.stdout.split('\u0000')) {
    if (!raw) continue;
    ignored.push(raw.startsWith('./') ? raw.slice(2) : raw);
  }
  if (ignored.length > 0) {
    const sample = ignored.slice(0, 3).join(', ') + (ignored.length > 3 ? '...' : '');
    throw new Error(
      tr(
        locale,
        `Git 仓库的忽略规则阻止了待同步文件，无法上传：${sample}`,
        `Files planned for sync are ignored by Git ignore rules: ${sample}`
      )
    );
  }
}

// ============================================================================
// Pure Object-Database Commit & Push (Zero GIT_INDEX_FILE Dependency)
// ============================================================================

function parseLsTreeEntries(stdout) {
  const out = [];
  for (const rec of String(stdout || '').split('\u0000')) {
    if (!rec) continue;
    const tabIdx = rec.indexOf('\t');
    if (tabIdx < 0) continue;
    const meta = rec.slice(0, tabIdx).split(/\s+/);
    if (meta.length < 3) continue;
    const name = rec.slice(tabIdx + 1).replace(/\\/g, '/');
    out.push({ mode: meta[0], type: meta[1], oid: meta[2], name });
  }
  return out;
}

/**
 * Build a new root Git tree purely in the Git object database via ls-tree + mktree,
 * applying changedEntries ([path, mode, oid]) on top of oldTree without mutating .git/index.
 */
function buildGitTreeFromChanges(callHost, repoRoot, oldTree, changedEntries, { cfg = null, locale = 'zh' } = {}) {
  const dirChanges = new Map(); // dirPath -> Map(childName -> { mode, type, oid } | null)
  const ensureDir = (dirPath) => {
    if (!dirChanges.has(dirPath)) dirChanges.set(dirPath, new Map());
    return dirChanges.get(dirPath);
  };
  ensureDir('');

  for (const [relPath, mode, oid] of changedEntries) {
    const parts = relPath.split('/').filter(Boolean);
    if (parts.length === 0) continue;
    let cur = '';
    for (let i = 0; i < parts.length - 1; i += 1) {
      ensureDir(cur);
      cur = cur ? `${cur}/${parts[i]}` : parts[i];
    }
    const parent = parts.slice(0, -1).join('/');
    const leaf = parts[parts.length - 1];
    ensureDir(parent).set(
      leaf,
      mode === '0' ? null : { mode, type: 'blob', oid }
    );
  }

  const dirsBottomUp = [...dirChanges.keys()].sort((a, b) => {
    const da = a ? a.split('/').length : 0;
    const db = b ? b.split('/').length : 0;
    if (db !== da) return db - da;
    return a < b ? -1 : a > b ? 1 : 0;
  });

  const rebuiltTrees = new Map(); // dirPath -> treeOid | null (empty)

  for (const dirPath of dirsBottomUp) {
    const entriesMap = new Map(); // childName -> { mode, type, oid }
    if (oldTree) {
      const treeSpec = dirPath ? `${oldTree}:${dirPath}` : oldTree;
      const checkType = dirPath
        ? runGit(callHost, ['cat-file', '-t', treeSpec], { cwd: repoRoot, cfg, locale })
        : { returncode: 0, stdout: 'tree' };
      if (checkType.returncode === 0 && checkType.stdout.trim() === 'tree') {
        const lsProc = runGit(callHost, ['ls-tree', '-z', treeSpec], { cwd: repoRoot, cfg, locale });
        if (lsProc.returncode !== 0) {
          const err = errorDetail(locale, lsProc.stderr || lsProc.stdout || 'git ls-tree failed');
          throw new Error(tr(locale, `Git 树读取失败: ${err}`, `Git ls-tree failed: ${err}`));
        }
        assertGitOutputComplete(lsProc, 'git ls-tree', { nulTerminated: true, locale });
        for (const item of parseLsTreeEntries(lsProc.stdout)) {
          entriesMap.set(item.name, { mode: item.mode, type: item.type, oid: item.oid });
        }
      }
    }

    // Apply rebuilt child subtrees first.
    for (const [subPath, subTreeOid] of rebuiltTrees.entries()) {
      const subParent = posixDirname(subPath);
      if (subParent !== dirPath) continue;
      const subName = posixBasename(subPath);
      if (!subTreeOid) {
        entriesMap.delete(subName);
      } else {
        entriesMap.set(subName, { mode: '040000', type: 'tree', oid: subTreeOid });
      }
    }

    // Apply direct blob changes/deletions.
    const leafChanges = dirChanges.get(dirPath);
    if (leafChanges) {
      for (const [name, entry] of leafChanges.entries()) {
        if (entry === null) {
          entriesMap.delete(name);
        } else {
          entriesMap.set(name, entry);
        }
      }
    }

    if (entriesMap.size === 0) {
      if (dirPath !== '') {
        rebuiltTrees.set(dirPath, null);
        continue;
      }
      const emptyProc = runGit(callHost, ['mktree', '-z'], { cwd: repoRoot, cfg, locale, stdin: '' });
      if (emptyProc.returncode !== 0) {
        const err = errorDetail(locale, emptyProc.stderr || emptyProc.stdout || 'git mktree failed');
        throw new Error(tr(locale, `Git 树构建失败: ${err}`, `Git mktree failed: ${err}`));
      }
      return emptyProc.stdout.trim() || EMPTY_TREE_OID;
    }

    const input = [...entriesMap.entries()]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([name, e]) => `${e.mode} ${e.type} ${e.oid}\t${name}\u0000`)
      .join('');
    const mkProc = runGit(callHost, ['mktree', '-z'], {
      cwd: repoRoot,
      cfg,
      locale,
      stdin: input,
    });
    if (mkProc.returncode !== 0) {
      const err = errorDetail(locale, mkProc.stderr || mkProc.stdout || 'git mktree failed');
      throw new Error(tr(locale, `Git 树构建失败: ${err}`, `Git mktree failed: ${err}`));
    }
    rebuiltTrees.set(dirPath, mkProc.stdout.trim());
  }

  return rebuiltTrees.get('') || EMPTY_TREE_OID;
}

function gitFileLimitError(locale, relPath) {
  return new Error(tr(locale, `文件超过大小上限（Git 的 100 MiB）。请改用 Git LFS：${relPath}`, `File exceeds size limit (Git's 100 MiB). Configure Git LFS for: ${relPath}`));
}

/** Write a blob using a verified on-disk file, stdin for UTF-8, or a temporary binary file. */
function gitHashObjectWrite(callHost, repoRoot, gitDir, relPath, rawData, {
  cfg = null, pid = 1, nowMsFn = () => Date.now(), locale = 'zh', filePath = '',
} = {}) {
  if (filePath) {
    const proc = runGit(callHost, ['hash-object', '-w', '--path', relPath, '--', filePath], {
      cwd: repoRoot, cfg, locale,
    });
    if (proc.returncode !== 0) {
      throw new Error(`${relPath}: ${gitErrorMessage(locale, proc.stderr || proc.stdout, 'git hash-object failed')}`);
    }
    return proc.stdout.trim();
  }
  const bytes = rawData instanceof Uint8Array ? rawData : textToBytes(String(rawData ?? ''));
  if (isUtf8Exact(bytes)) {
    const proc = runGit(callHost, ['hash-object', '-w', '--path', relPath, '--stdin'], {
      cwd: repoRoot,
      cfg,
      locale,
      stdin: bytesToText(bytes),
    });
    if (proc.returncode !== 0) {
      const err = errorDetail(locale, proc.stderr || proc.stdout || tr(locale, 'git hash-object 失败', 'git hash-object failed'));
      throw new Error(tr(locale, `Git 对象写入失败: ${err}`, `Git object write failed: ${err}`));
    }
    return proc.stdout.trim();
  }

  const baseDir = gitDir || repoRoot;
  const tmpPath = posixJoin(baseDir, `block-sync-blob-${pid}-${nowMsFn()}.tmp`);
  try {
    fsWriteBytes(callHost, tmpPath, bytes, { atomic: false, mkdirParents: true });
    const proc = runGit(callHost, ['hash-object', '-w', '--path', relPath, '--', tmpPath], {
      cwd: repoRoot,
      cfg,
      locale,
    });
    if (proc.returncode !== 0) {
      const err = errorDetail(locale, proc.stderr || proc.stdout || tr(locale, 'git hash-object 失败', 'git hash-object failed'));
      throw new Error(tr(locale, `Git 对象写入失败: ${err}`, `Git object write failed: ${err}`));
    }
    return proc.stdout.trim();
  } finally {
    try {
      fsDelete(callHost, tmpPath);
    } catch (_err) {
      // Best-effort cleanup.
    }
  }
}

/** Commit planned changes strictly from plannedBlobs and push to remote if configured. */
export function commitAndPushGit(
  callHost,
  repoRoot,
  cfg,
  {
    stagedRelPaths = [],
    trackedPlanPaths = [],
    plannedBlobs = {},
    onFileError = null,
    onFileSuccess = null,
    checkout = null,
    deletedRelPaths = [],
    dataDir = '',
    pid = 1,
    nowMsFn = () => Date.now(),
    sleepFn = null,
    deadlineMs = 0,
    locale = 'zh',
    skipStaleTmpScan = false,
  } = {}
) {
  const rpc = resolveCallHost(callHost);
  assertGitOperationFinished(rpc, repoRoot, locale);
  if (checkout) {
    gitCheckoutState(rpc, repoRoot, cfg, checkout, locale);
  }
  if (!skipStaleTmpScan) {
    cleanupStaleTempFiles(rpc, repoRoot, { locale });
  }
  recoverAbandonedGitIndex(rpc, repoRoot, { cfg, pid, locale });

  const branch = gitBranch(cfg);
  const curBr = gitCurrentBranch(rpc, repoRoot, cfg, locale);
  if (curBr !== branch) {
    const curLabel = curBr || 'detached HEAD';
    throw new Error(
      tr(
        locale,
        `Git 工作区当前位于 ${curLabel}，与目标分支 ${branch} 不一致，已中止推送`,
        `Git checkout is at ${curLabel} instead of ${branch}; push aborted`
      )
    );
  }

  const deleted = new Set((deletedRelPaths || []).map(normalizeGitRel).filter(Boolean));
  const written = new Set((stagedRelPaths || []).map(normalizeGitRel).filter((p) => p && !deleted.has(p)));
  const candidateTracked = new Set(
    (trackedPlanPaths || []).map(normalizeGitRel).filter((p) => p && !written.has(p) && !deleted.has(p))
  );
  const allCheckPaths = [...new Set([...written, ...candidateTracked, ...deleted])].sort();
  const blobMap = {};
  for (const [k, v] of Object.entries(plannedBlobs || {})) {
    const nk = normalizeGitRel(k);
    if (nk) blobMap[nk] = v;
  }

  checkGitIgnored(rpc, repoRoot, allCheckPaths, { cfg, locale });

  const branchRef = `refs/heads/${branch}`;
  const headChk = runGit(rpc, ['rev-parse', '--verify', branchRef], { cwd: repoRoot, cfg, locale });
  const oldHead = headChk.returncode === 0 && headChk.stdout.trim() ? headChk.stdout.trim() : '';
  if (checkout && oldHead !== checkout[1]) {
    throw new Error(tr(locale, 'Git 分支已更新，请重试同步', 'The Git branch advanced. Retry sync.'));
  }

  let oldTree = '';
  const headEntries = {};
  if (oldHead) {
    const treeChk = runGit(rpc, ['rev-parse', '--verify', `${oldHead}^{tree}`], { cwd: repoRoot, cfg, locale });
    if (treeChk.returncode === 0 && treeChk.stdout.trim()) {
      oldTree = treeChk.stdout.trim();
    }
    if (allCheckPaths.length > 0) {
      for (let i = 0; i < allCheckPaths.length; i += LS_TREE_BATCH_SIZE) {
        const chunk = allCheckPaths.slice(i, i + LS_TREE_BATCH_SIZE);
        const lsProc = runGit(
          rpc,
          ['--literal-pathspecs', 'ls-tree', '-r', '-z', oldHead, '--', ...chunk],
          { cwd: repoRoot, cfg, locale }
        );
        if (lsProc.returncode !== 0) {
          const err = errorDetail(locale, lsProc.stderr || lsProc.stdout || tr(locale, 'git ls-tree 失败', 'git ls-tree failed'));
          throw new Error(tr(locale, `Git 树检查失败: ${err}`, `Git tree inspection failed: ${err}`));
        }
        assertGitOutputComplete(lsProc, 'git ls-tree', { nulTerminated: true, locale });
        for (const item of parseLsTreeEntries(lsProc.stdout)) {
          headEntries[item.name] = [item.mode, item.oid];
        }
      }
    }
  }

  const [, gitDir] = resolveGitDir(rpc, repoRoot);
  const fileInfo = new Map();
  const skipped = new Set();
  const isolateFileError = (path, exc) => {
    if (!onFileError || !['fs_error', 'file_limit'].includes(classifySyncError(exc))) throw exc;
    onFileError(path, exc);
    skipped.add(path);
  };
  const gitMaxSize = 100 * 1024 * 1024;
  for (const p of allCheckPaths) {
    if (deleted.has(p)) continue;
    const plannedBlob = Object.hasOwn(blobMap, p) ? blobMap[p] : undefined;
    const diskPath = posixJoin(trimTrailingSlash(repoRoot), p);
    const filePath = plannedBlob?.file_path || (plannedBlob === undefined ? diskPath : '');
    if (filePath && filePath !== diskPath) throw new Error(`Invalid planned Git file: ${p}`);
    let size;
    try {
      const stat = filePath ? fsStat(rpc, filePath) : null;
      if (filePath && stat?.exists === false) {
        if (plannedBlob !== undefined) throw new Error('Attachment changed while opening');
        skipped.add(p);
        continue;
      }
      if (stat?.is_dir || stat?.is_regular === false) throw new Error('Must be a regular file');
      size = stat?.size ?? (plannedBlob instanceof Uint8Array ? plannedBlob.length : textToBytes(String(plannedBlob ?? '')).length);
    } catch (exc) {
      isolateFileError(p, exc);
      continue;
    }
    if (size > gitMaxSize) {
      const attr = runGit(rpc, ['check-attr', '-z', 'filter', '--', p], { cwd: repoRoot, cfg, locale });
      if (attr.returncode !== 0 || attr.stdout.split('\u0000')[2] !== 'lfs') throw gitFileLimitError(locale, p);
    }
    fileInfo.set(p, { filePath, size, plannedBlob });
    if (onFileSuccess) onFileSuccess(p);
  }
  const changedEntries = [];
  for (const p of allCheckPaths) {
    if (skipped.has(p)) continue;
    if (deleted.has(p)) {
      const prevOid = (headEntries[p] || ['', ''])[1];
      if (prevOid) changedEntries.push([p, '0', '0'.repeat(prevOid.length)]);
      continue;
    }
    if (!fileInfo.has(p)) continue;
    const { filePath, size, plannedBlob } = fileInfo.get(p);
    const [prevMode, prevOid] = headEntries[p] || ['100644', ''];
    if (prevMode === '160000') {
      throw new Error(gitErrorMessage(locale, `submodule conflict: ${p}`));
    }
    let newOid;
    try {
      const diskHash = () => hashSyncFile(filePath, rpc, () => fsReadBytes(rpc, filePath));
      const expected = filePath ? plannedBlob?.hash || diskHash() : null;
      const verifySource = () => {
        if (filePath && (!expected || diskHash() !== expected)) {
          throw new Error(`Attachment changed during sync: ${p}`);
        }
      };
      verifySource();
      newOid = gitHashObjectWrite(rpc, repoRoot, gitDir, p, plannedBlob, { cfg, pid, nowMsFn, locale, filePath });
      verifySource();
      if (filePath || size > gitMaxSize) {
        const blobSize = runGit(rpc, ['cat-file', '-s', newOid], { cwd: repoRoot, cfg, locale });
        if (blobSize.returncode !== 0) throw new Error(`${p}: ${gitErrorMessage(locale, blobSize.stderr, 'git cat-file failed')}`);
        if (Number(blobSize.stdout.trim()) > gitMaxSize) throw gitFileLimitError(locale, p);
      }
    } catch (exc) {
      isolateFileError(p, exc);
      continue;
    }
    if (onFileSuccess) onFileSuccess(p);
    const mode = prevMode === '100755' ? prevMode : '100644';
    if (!oldHead || newOid !== prevOid) changedEntries.push([p, mode, newOid]);
  }

  if (allCheckPaths.length > 0) {
    checkGitStagedConflicts(rpc, repoRoot, allCheckPaths, { cfg, dataDir, pid, locale });
  }

  let didCommit = false;
  if (changedEntries.length > 0) {
    const realIndex = gitPath(rpc, repoRoot, 'index', cfg, locale);
    if (!realIndex) {
      throw new Error(tr(locale, '无法定位 Git 索引文件', 'Could not locate Git index file'));
    }

    const newTree = buildGitTreeFromChanges(rpc, repoRoot, oldTree, changedEntries, { cfg, locale });
    const commitEnv = {
      GIT_AUTHOR_NAME: 'Block Sync',
      GIT_AUTHOR_EMAIL: 'sync@blockmd.local',
      GIT_COMMITTER_NAME: 'Block Sync',
      GIT_COMMITTER_EMAIL: 'sync@blockmd.local',
    };
    const ctArgs = ['commit-tree', newTree, '-m', 'sync: update markdown notes'];
    if (oldHead) ctArgs.push('-p', oldHead);
    const ctProc = runGit(rpc, ctArgs, { cwd: repoRoot, cfg, locale, extraEnv: commitEnv });
    if (ctProc.returncode !== 0) {
      const err = errorDetail(locale, ctProc.stderr || ctProc.stdout || 'git commit-tree failed');
      throw new Error(tr(locale, `Git 提交对象创建失败: ${err}`, `Git commit-tree failed: ${err}`));
    }
    const newCommit = ctProc.stdout.trim();

    const indexLock = `${realIndex}.lock`;
    const lockDeadline = nowMsFn() + 2000;
    while (fsStat(rpc, indexLock).exists) {
      if (nowMsFn() >= lockDeadline) {
        throw new Error(gitErrorMessage(locale, `${realIndex}.lock`));
      }
      sleepMs(50, sleepFn);
    }

    let ownerPath = '';
    let refAdvanced = false;
    let indexUpdated = false;
    try {
      ownerPath = writeGitIndexOwner(rpc, repoRoot, { cfg, pid, locale });
      assertGitOperationFinished(rpc, repoRoot, locale);
      if (checkout) {
        gitCheckoutState(rpc, repoRoot, cfg, checkout, locale);
      }
      checkGitStagedConflicts(rpc, repoRoot, allCheckPaths, { cfg, recover: false, dataDir, pid, locale });

      const urProc = runGit(
        rpc,
        ['update-ref', '-m', 'sync: update markdown notes', branchRef, newCommit, oldHead],
        { cwd: repoRoot, cfg, locale, extraEnv: commitEnv }
      );
      if (urProc.returncode !== 0) {
        const err = errorDetail(locale, urProc.stderr || urProc.stdout || 'git update-ref failed');
        throw new Error(
          tr(
            locale,
            `Git 分支更新失败（可能存在并发提交）: ${err}`,
            `Git branch update failed (concurrent commit?): ${err}`
          )
        );
      }
      refAdvanced = true;

      const indexInfoPayload = changedEntries
        .map(([p, mode, oid]) => `${mode} ${oid}\t${p}\u0000`)
        .join('');
      const uiProc = runGit(rpc, ['update-index', '-z', '--index-info'], {
        cwd: repoRoot,
        cfg,
        locale,
        stdin: indexInfoPayload,
      });
      if (uiProc.returncode !== 0) {
        const err = gitErrorMessage(locale, uiProc.stderr || uiProc.stdout, 'git update-index failed');
        throw new Error(tr(locale, `Git 索引同步失败: ${err}`, `Git index sync failed: ${err}`));
      }
      indexUpdated = true;
    } finally {
      if (refAdvanced && !indexUpdated) {
        try {
          repairGitIndexToHead(rpc, repoRoot, { cfg, locale });
        } catch (_repErr) {
          // Best-effort index repair.
        }
      }
      if (indexUpdated || !refAdvanced) {
        clearGitIndexOwner(rpc, ownerPath);
      }
    }
    didCommit = true;
  }

  const remoteProc = runGit(rpc, ['remote'], { cwd: repoRoot, cfg, locale });
  if (remoteProc.returncode !== 0) {
    const err = errorDetail(locale, remoteProc.stderr || remoteProc.stdout || tr(locale, 'git remote 失败', 'git remote failed'));
    throw new Error(tr(locale, `Git 远端检查失败: ${err}`, `Git remote check failed: ${err}`));
  }
  const remotes = remoteProc.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
  if (remotes.length > 0) {
    const remoteName = remotes.includes('origin') ? 'origin' : remotes[0];
    const headProc = runGit(rpc, ['rev-parse', '--verify', branchRef], { cwd: repoRoot, cfg, locale });
    if (headProc.returncode === 0 && headProc.stdout.trim()) {
      const headOid = headProc.stdout.trim();
      let needsPush = false;
      const expectedRemoteOid = getGitSyncedBranchOid(rpc, repoRoot, branch, { remoteName, cfg, locale });
      const refProc = runGit(rpc, ['rev-parse', '--verify', `refs/remotes/${remoteName}/${branch}`], {
        cwd: repoRoot,
        cfg,
        locale,
      });
      if (refProc.returncode !== 0) {
        needsPush = true;
      } else {
        const aheadProc = runGit(
          rpc,
          ['rev-list', '--count', `refs/remotes/${remoteName}/${branch}..${headOid}`],
          { cwd: repoRoot, cfg, locale }
        );
        const aheadN = aheadProc.returncode === 0 ? Number.parseInt(aheadProc.stdout.trim() || '0', 10) || 0 : 1;
        if (aheadN > 0) needsPush = true;
      }

      if (needsPush) {
        verifyGitPushHistory(rpc, repoRoot, branch, headOid, expectedRemoteOid, cfg, locale);
        let leaseArg;
        if (expectedRemoteOid) {
          const ancProc = runGit(rpc, ['merge-base', '--is-ancestor', expectedRemoteOid, headOid], {
            cwd: repoRoot,
            cfg,
            locale,
          });
          if (ancProc.returncode !== 0) {
            throw new Error(
              tr(
                locale,
                `本地 Git 分支 ${branch} 与远端记录分叉，为避免覆盖远端历史已中止推送`,
                `Local Git branch ${branch} diverged from last synced remote commit; push aborted`
              )
            );
          }
          leaseArg = `--force-with-lease=refs/heads/${branch}:${expectedRemoteOid}`;
        } else if (
          oldHead &&
          !hasGitPendingInitial(rpc, repoRoot, branch, { remoteName, cfg, locale }) &&
          gitBranchHasUpstreamConfig(rpc, repoRoot, branch, { remoteName, cfg, locale })
        ) {
          throw new Error(
            tr(
              locale,
              `远端 ${remoteName} 的分支 ${branch} 已不存在（疑似被删除或重置），为避免未经确认重建远端历史已中止同步`,
              `Remote ${remoteName} branch ${branch} no longer exists (it may have been deleted or reset); sync aborted to avoid silently recreating remote history`
            )
          );
        } else {
          if (!oldHead) {
            recordGitPendingInitial(rpc, repoRoot, branch, headOid, { remoteName, cfg, locale });
          }
          leaseArg = `--force-with-lease=refs/heads/${branch}:`;
        }

        const pushProc = runGitNetwork(
          rpc,
          ['push', leaseArg, '-u', remoteName, `${headOid}:refs/heads/${branch}`],
          {
            cwd: repoRoot,
            timeoutMs: 60000,
            cfg,
            retries: 1,
            totalBudgetMs: 80000,
            locale,
            nowMsFn,
            sleepFn,
            deadlineMs,
          }
        );
        if (pushProc.returncode !== 0) {
          const err = gitErrorMessage(locale, pushProc.stderr || pushProc.stdout, tr(locale, 'push 失败', 'Push failed'));
          throw new Error(tr(locale, `已提交到本地 Git，但远端推送未完成: ${err}`, `Committed locally. Git push failed: ${err}`));
        }
        recordGitSyncedBranch(rpc, repoRoot, branch, headOid, { remoteName, cfg, locale });
        if (isManagedGitDir(repoRoot, dataDir)) {
          cleanupPendingPushBranches(rpc, repoRoot, branch, {
            targetRemoteRef: headOid,
            cfg,
            locale,
          });
        }
        return true;
      }
    }
  }
  return didCommit;
}

// ============================================================================
// Git Sync Engine (Test, Planning, Risk Assessment, Execution)
// ============================================================================

/**
 * Create a Git sync engine wired to host.exec.run, host.fs.*, host.notes.*,
 * host.secrets.*, and host.crypto.hash via callHost.
 */
export function createGitSyncEngine({
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
  const getHomeDir = () => (configStore ? configStore.state.homeDir : '');
  const getNbRoot = () => (configStore ? configStore.state.notebookRoot : '');
  const resolveDataDir = () => resolvePluginDataDir(getRpc(), dataDir);

  const resolveCfgCredentials = (cfg) => {
    const rpc = getRpc();
    const loc = getLocale();
    if (configStore && typeof configStore.resolveCredentials === 'function') {
      return configStore.resolveCredentials(cfg);
    }
    return resolveCredentials(rpc, cfg, loc);
  };

  const emitProgress = (params) => {
    try {
      const notifyFn = typeof notifyHost === 'function'
        ? notifyHost
        : typeof globalThis.notifyHost === 'function'
          ? globalThis.notifyHost
          : null;
      if (notifyFn) notifyFn('host.action.progress', params);
      else getRpc()('host.action.progress', params);
    } catch (_err) {
      // Best-effort progress reporting.
    }
  };

  const testConnection = (cfgInput = null, { deadlineMs = 0 } = {}) => {
    const rpc = getRpc();
    const loc = getLocale();
    const dDir = resolveDataDir();
    let cfg = cfgInput || (configStore ? configStore.state.config : {});
    try {
      cfg = resolveCfgCredentials({ ...cfg, protocol: 'git' });
    } catch (exc) {
      return [false, errorDetail(loc, exc)];
    }

    const verProc = runGit(rpc, ['--version'], { cfg, locale: loc });
    if (verProc.returncode !== 0) {
      return [false, tr(loc, '当前环境未安装 git 命令', 'Git is not installed')];
    }

    const target = String((cfg && cfg.git_remote) || '').trim();
    const branch = gitBranch(cfg);
    try {
      if (target && isRemoteGitUrl(target)) {
        const [ok, res] = gitRemoteHeads(rpc, target, {
          cfg,
          timeoutMs: 10000,
          retries: 1,
          totalBudgetMs: 20000,
          locale: loc,
          nowMsFn,
          sleepFn,
          deadlineMs,
        });
        if (!ok) {
          return [false, tr(loc, `Git 远端不可达: ${res}`, `Git remote is unreachable: ${res}`)];
        }
        if (res.length === 0) {
          const repoDir = resolveLocalGitDir(rpc, cfg, {
            dataDir: dDir,
            nbRoot: getNbRoot(),
            homeDir: getHomeDir(),
            locale: loc,
          });
          if (wasGitBranchSynced(rpc, repoDir, branch, { remoteName: 'origin', cfg, locale: loc })) {
            return [
              false,
              tr(
                loc,
                `远端分支 ${branch} 已不存在（疑似被删除或重置），请先确认远端状态`,
                `Remote branch ${branch} no longer exists (it may have been deleted or reset); verify remote state first`
              ),
            ];
          }
          return [
            true,
            tr(
              loc,
              `Git 远端为空仓库（首次同步将创建分支 ${branch}）`,
              `Git remote is empty (first sync will create branch ${branch})`
            ),
          ];
        }
        if (res.includes(branch)) {
          return [
            true,
            tr(
              loc,
              `Git 远端仓库连接正常（分支 ${branch}）`,
              `Git remote connection successful (branch: ${branch})`
            ),
          ];
        }
        const avail = res.slice(0, 4).join(', ') + (res.length > 4 ? '...' : '');
        return [
          false,
          tr(
            loc,
            `远端仓库不存在分支 ${branch}（已有分支：${avail}）`,
            `Remote branch ${branch} does not exist (available: ${avail})`
          ),
        ];
      }

      const repoDir = resolveLocalGitDir(rpc, cfg, {
        dataDir: dDir,
        nbRoot: getNbRoot(),
        homeDir: getHomeDir(),
        locale: loc,
      });
      const dirSt = fsStat(rpc, repoDir);
      if (!dirSt.exists || !dirSt.is_dir) {
        return [
          false,
          tr(loc, `本地 Git 仓库目录不存在: ${repoDir}`, `Local Git repository folder does not exist: ${repoDir}`),
        ];
      }
      const proc = runGit(rpc, ['rev-parse', '--is-inside-work-tree'], { cwd: repoDir, cfg, locale: loc });
      if (proc.returncode !== 0 || proc.stdout.trim() !== 'true') {
        return [
          false,
          tr(loc, `目录不是有效的 Git 仓库: ${repoDir}`, `Folder is not a valid Git repository: ${repoDir}`),
        ];
      }
      const remoteProc = runGit(rpc, ['remote'], { cwd: repoDir, cfg, locale: loc });
      const remotes = remoteProc.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      if (remotes.length > 0) {
        const remoteName = remotes.includes('origin') ? 'origin' : remotes[0];
        const [ok, res] = gitRemoteHeads(rpc, remoteName, {
          cfg,
          cwd: repoDir,
          timeoutMs: 10000,
          retries: 1,
          totalBudgetMs: 20000,
          locale: loc,
          nowMsFn,
          sleepFn,
          deadlineMs,
        });
        if (ok) {
          if (res.length === 0 && wasGitBranchSynced(rpc, repoDir, branch, { remoteName, cfg, locale: loc })) {
            return [
              false,
              tr(
                loc,
                `远端 ${remoteName} 的分支 ${branch} 已不存在（疑似被删除或重置），请先确认远端状态`,
                `Remote ${remoteName} branch ${branch} no longer exists (it may have been deleted or reset); verify remote state first`
              ),
            ];
          }
          if (res.length === 0 || res.includes(branch)) {
            return [
              true,
              tr(loc, `Git 仓库及远端 ${remoteName} 正常`, `Git repository and remote ${remoteName} are available`),
            ];
          }
          const avail = res.slice(0, 4).join(', ') + (res.length > 4 ? '...' : '');
          return [
            false,
            tr(
              loc,
              `远端 ${remoteName} 不存在分支 ${branch}（已有分支：${avail}）`,
              `Remote ${remoteName} does not have branch ${branch} (available: ${avail})`
            ),
          ];
        }
        return [
          true,
          tr(
            loc,
            `本地 Git 仓库可用（远端 ${remoteName} 当前离线）`,
            `Local Git repository is available (remote ${remoteName} is offline)`
          ),
        ];
      }
      return [true, tr(loc, `本地 Git 仓库可用: ${repoDir}`, `Local Git repository is available: ${repoDir}`)];
    } catch (exc) {
      return [false, tr(loc, `Git 检测异常: ${errorDetail(loc, exc)}`, `Git connection test failed: ${errorDetail(loc, exc)}`)];
    }
  };

  const computeSyncPlan = ({
    cfg,
    onlyPath = null,
    inspectRemote = true,
    nbRoot = null,
    subdir = '',
    preparedRepoDir = null,
    targetBases = [],
    excludedSubdirs = new Set(),
    deadlineMs = 0,
    skipRound,
  } = {}) => {
    const rpc = getRpc();
    const loc = getLocale();
    const homeDir = getHomeDir();
    const dDir = resolveDataDir();
    const effectiveNbRoot = nbRoot || getNbRoot();
    const nbKeyVal = configStore
      ? configStore.notebookKey(effectiveNbRoot)
      : notebookKey(effectiveNbRoot, '', homeDir);
    const nbLabelVal = configStore
      ? configStore.notebookLabel(effectiveNbRoot)
      : notebookLabel(effectiveNbRoot, loc, '', homeDir);
    const scope = cfg.sync_scope || 'all';
    const skips = createSyncSkips(cfg, loc, skipRound);

    const branch = gitBranch(cfg);
    let repoDir = preparedRepoDir || resolveLocalGitDir(rpc, cfg, { dataDir: dDir, nbRoot: effectiveNbRoot, homeDir, locale: loc });
    let repoRoot = repoDir;
    let targetDir = subdir ? posixJoin(repoDir, subdir) : repoDir;
    const metaTarget = subdir ? `${repoDir}:${branch}::${subdir}` : `${repoDir}:${branch}`;
    const metaKey = configStore
      ? configStore.metaKey('git', metaTarget, nbKeyVal)
      : `nb:${nbKeyVal}|git:${metaTarget}`;
    const legacyKey = !subdir ? `git:${repoDir}:${branch}` : null;

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
    const scanOptions = { onlyPath, scope, excludedSubdirs, locale: loc, cfg, skips };

    if (preparedRepoDir) {
      // Prepared by caller (computeBatchPlan).
    } else if (inspectRemote) {
      const singleTargets = buildGitNotebookTargets({
        notebooks: [effectiveNbRoot],
        subdir,
        repoDir,
        targetBases,
        branch,
        excludedSubdirs,
        configStore,
        homeDir,
      });
      const [ok, res] = prepareGitRepo(rpc, cfg, {
        allowInitOrClone: true,
        allowPull: true,
        repoDir,
        dataDir: dDir,
        nbRoot: effectiveNbRoot,
        homeDir,
        locale: loc,
        nowMsFn,
        sleepFn,
        deadlineMs,
        configStore,
        notebookTargets: singleTargets,
      });
      if (ok) {
        repoRoot = res;
        targetDir = subdir ? posixJoin(res, subdir) : res;
      } else {
        remoteInspected = false;
        remoteError = res;
      }
    } else if (!hasGitMarker(rpc, repoDir)) {
      remoteInspected = false;
    }

    if (remoteInspected && !remoteError) {
      if (onlyPath === null) {
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
          readRemoteNote = (relPath, entry = null) =>
            fsReadNoteText(rpc, entry?.path || posixJoin(remoteSnapshot.cleanRoot, relPath), relPath, entry);
        }
      } else {
        remoteNotes = scanMirrorFiles(rpc, targetDir, scanOptions);
      }

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

    let trackedRemotePaths = null;
    let gitTreePaths = null;
    if (remoteInspected && isManagedGitDir(repoRoot, dDir)) {
      try {
        trackedRemotePaths = gitTrackedRelPaths(rpc, repoRoot, { subdir, cfg, strict: true, locale: loc });
        gitTreePaths = trackedRemotePaths;
        if (remoteNoteEntries) {
          remoteNoteEntries = alignEntryMapToTracked(rpc, remoteNoteEntries, trackedRemotePaths, targetDir);
        } else {
          remoteNotes = alignPathsToTracked(rpc, remoteNotes, trackedRemotePaths, targetDir);
        }
      } catch (exc) {
        remoteInspected = false;
        remoteError = errorDetail(loc, exc);
      }
    } else if (remoteInspected && hasGitMarker(rpc, repoRoot)) {
      try {
        gitTreePaths = gitTrackedRelPaths(rpc, repoRoot, { subdir, cfg, strict: false, locale: loc });
      } catch (_err) {
        gitTreePaths = null;
      }
    }

    if (remoteInspected && !remoteError && gitTreePaths) {
      const trackedFolded = new Map();
      const onlyKey = onlyPath ? foldSyncPath(onlyPath, { caseInsensitive: true, normalize: true }) : null;
      const syncAssetsOn = cfg.sync_assets !== false;
      const onlyAssetCfs = new Set();
      if (onlyPath !== null && onlyPath !== undefined && syncAssetsOn) {
        for (const ap of noteAssetPaths(onlyPath, localNotes[onlyPath] || '')) {
          onlyAssetCfs.add(foldSyncPath(ap, { caseInsensitive: true, normalize: true }));
        }
        for (const [rnp, rtxt] of Object.entries(remoteNotes)) {
          if (foldSyncPath(rnp, { caseInsensitive: true, normalize: true }) === onlyKey) {
            for (const ap of noteAssetPaths(rnp, rtxt)) {
              onlyAssetCfs.add(foldSyncPath(ap, { caseInsensitive: true, normalize: true }));
            }
          }
        }
        if (isSafeRelAsset(onlyPath)) onlyAssetCfs.add(onlyKey);
      }
      const localNoteKeyList = localNoteEntries ? [...localNoteEntries.keys()] : Object.keys(localNotes);
      const remoteNoteKeyList = remoteNoteEntries ? [...remoteNoteEntries.keys()] : Object.keys(remoteNotes);
      const gitScopeCi =
        dirIsCaseInsensitive(rpc, effectiveNbRoot, localNoteKeyList) ||
        dirIsCaseInsensitive(rpc, targetDir, remoteNoteKeyList);
      const gitScopeNorm =
        dirIsNormalizationInsensitive(rpc, effectiveNbRoot) ||
        dirIsNormalizationInsensitive(rpc, targetDir);
      for (const tp of [...gitTreePaths].sort()) {
        if (inSyncSubdir(tp, excludedSubdirs) || skips.has(tp)) continue;
        const isMd = isSafeRelMd(tp) && !isSafeRelAsset(tp);
        const isAs = syncAssetsOn && isSafeRelAsset(tp);
        if (!isMd && !isAs) continue;
        if (isMd && !matchesScope(tp, scope, { caseInsensitive: gitScopeCi, normalize: gitScopeNorm })) continue;
        if (onlyKey !== null) {
          const tpKey = foldSyncPath(tp, { caseInsensitive: true, normalize: true });
          if (isMd && tpKey !== onlyKey) continue;
          if (isAs && !onlyAssetCfs.has(tpKey)) continue;
        }
        const fk = foldSyncPath(tp, { caseInsensitive: true, normalize: true });
        if (!trackedFolded.has(fk)) trackedFolded.set(fk, []);
        trackedFolded.get(fk).push(tp);
      }
      for (const grp of trackedFolded.values()) {
        if (groupCollapses(rpc, grp, effectiveNbRoot) || groupCollapses(rpc, grp, targetDir)) {
          remoteInspected = false;
          remoteError = collapsedNameError(loc, grp.slice(0, 2).join(' / '));
          break;
        }
      }
    }

    const aliases = (targetBases || []).map((base) => {
      const mt = subdir ? `${base}::${subdir}` : base;
      return configStore ? configStore.metaKey('git', mt, nbKeyVal) : `nb:${nbKeyVal}|git:${mt}`;
    });
    const legacyAliases = !subdir ? (targetBases || []).map((base) => `git:${base}`) : [];

    const plan = computeThreeWaySyncPlan({
      callHost: rpc,
      configStore,
      localAdapter: local,
      protocol: 'git',
      cfg,
      nbRoot: effectiveNbRoot,
      nbKeyVal,
      nbLabelVal,
      subdir,
      excludedSubdirs,
      targetDisplay: sanitizeUrlForDisplay(cfg.git_remote || ''),
      targetDir,
      repoRoot,
      metaKey,
      legacyKey,
      aliases,
      legacyAliases,
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
      trackedRemotePaths,
      gitTreePaths,
      onlyPath,
      locale: loc,
      skips,
    });
    plan._remote_stale_tmp_clear = Boolean(remoteSnapshot && remoteSnapshot.staleTmpPaths.length === 0);
    return plan;
  };

  const computeBatchPlan = ({
    cfg: rawCfg,
    notebooks = [],
    onlyPath = null,
    inspectRemote = true,
    deadlineMs = 0,
  } = {}) => {
    const rpc = getRpc();
    const loc = getLocale();
    const homeDir = getHomeDir();
    const dDir = resolveDataDir();
    let cfg = { ...(rawCfg || {}), protocol: 'git' };
    if (inspectRemote) {
      try {
        cfg = resolveCfgCredentials(cfg);
      } catch (exc) {
        return {
          cfg,
          protocol: 'git',
          target_display: sanitizeUrlForDisplay(cfg.git_remote || ''),
          repo_root: '',
          plans: [],
          remote_error: errorDetail(loc, exc),
          fingerprint: '',
        };
      }
    }

    const effectiveNotebooks = Array.isArray(notebooks) ? notebooks : [];
    const branch = gitBranch(cfg);
    const targetDisplay = sanitizeUrlForDisplay(cfg.git_remote || '');
    const repoDirs = gitRepoDirs(rpc, cfg, {
      dataDir: dDir,
      nbRoot: effectiveNotebooks[0] || getNbRoot(),
      homeDir,
      locale: loc,
    });
    const repoDir = repoDirs.find((p) => hasGitMarker(rpc, p)) || repoDirs[0];
    const targetBases = repoDirs.map((p) => `${p}:${branch}`);

    const { layoutKey, bindings, reservedSubdirs } = computeNotebookSubdirMap({
      notebooks:
        configStore && configStore.selectedNotebooks(cfg).length > 0
          ? configStore.selectedNotebooks(cfg)
          : effectiveNotebooks,
      protocol: 'git',
      targetBases,
      syncMeta: configStore ? configStore.state.syncMeta : {},
      notebookConfigs: configStore ? configStore.state.notebookConfigs : {},
      knownNotebooks: configStore ? configStore.state.knownNotebooks : [],
      callHost: rpc,
      locale: loc,
      syncTargetBaseFn: (c) =>
        `${resolveLocalGitDir(rpc, c, { dataDir: dDir, nbRoot: getNbRoot(), homeDir, locale: loc })}:${gitBranch(c)}`,
    });

    let preparedRepoDir = '';
    if (inspectRemote) {
      const batchTargets = buildGitNotebookTargets({
        notebooks: effectiveNotebooks,
        bindings,
        repoDir,
        targetBases,
        branch,
        excludedSubdirs: reservedSubdirs,
        configStore,
        homeDir,
      });
      const [ok, res] = prepareGitRepo(rpc, cfg, {
        allowInitOrClone: true,
        allowPull: true,
        repoDir,
        dataDir: dDir,
        nbRoot: effectiveNotebooks[0] || getNbRoot(),
        homeDir,
        locale: loc,
        nowMsFn,
        sleepFn,
        deadlineMs,
        configStore,
        notebookTargets: batchTargets,
      });
      if (!ok) {
        return {
          cfg: { ...cfg },
          protocol: 'git',
          target_display: targetDisplay,
          repo_root: '',
          plans: [],
          remote_error: res,
          fingerprint: '',
        };
      }
      preparedRepoDir = res;
    }

    for (let i = 0; i < effectiveNotebooks.length; i += 1) {
      for (let j = 0; j < i; j += 1) {
        if (pathsOverlap(effectiveNotebooks[j], effectiveNotebooks[i])) {
          const prevLbl = notebookLabel(effectiveNotebooks[j], loc, '', homeDir);
          const curLbl = notebookLabel(effectiveNotebooks[i], loc, '', homeDir);
          return {
            cfg: { ...cfg },
            protocol: 'git',
            target_display: targetDisplay,
            repo_root: preparedRepoDir,
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

    const baseRoot = preparedRepoDir || repoDir;
    const { identities: targetIdentities, error: physErr } = validatePhysicalTargets(
      rpc,
      'git',
      bindings,
      baseRoot,
      { locale: loc, homeDir }
    );
    if (physErr) {
      return {
        cfg: { ...cfg },
        protocol: 'git',
        target_display: targetDisplay,
        repo_root: preparedRepoDir,
        plans: [],
        remote_error: physErr,
        fingerprint: '',
      };
    }

    const checkout = baseRoot && hasGitMarker(rpc, baseRoot) ? gitCheckoutState(rpc, baseRoot, cfg, null, loc) : null;
    const plans = [];
    const skipRound = { consecutive: 0 };
    for (const nb of effectiveNotebooks) {
      const sub = bindings[nb] || '';
      const plan = computeSyncPlan({
        cfg,
        onlyPath,
        inspectRemote,
        nbRoot: nb,
        subdir: sub,
        preparedRepoDir,
        targetBases,
        excludedSubdirs: sub ? new Set() : reservedSubdirs,
        deadlineMs,
        skipRound,
      });
      plan.batch_base_root = baseRoot;
      plan.batch_bindings = { ...bindings };
      plan.target_identities = { ...targetIdentities };
      if (plan.remote_error) {
        return {
          cfg: { ...cfg },
          protocol: 'git',
          target_display: targetDisplay,
          repo_root: preparedRepoDir,
          plans,
          remote_error: plan.remote_error,
          fingerprint: '',
        };
      }
      plans.push(plan);
    }

    if (checkout) {
      gitCheckoutState(rpc, baseRoot, cfg, checkout, loc);
    }

    const physFp = Object.keys(targetIdentities)
      .sort()
      .map((nb) => [
        nb,
        targetIdentities[nb].path,
        targetIdentities[nb].exists,
        targetIdentities[nb].is_dir,
      ]);
    const fpPayload = { plans: plans.map((p) => p.fingerprint), targets: physFp };
    if (checkout) fpPayload.git_checkout = checkout;
    const fp = sha256Text(JSON.stringify(fpPayload), rpc);

    return {
      cfg: { ...cfg },
      protocol: 'git',
      target_display: targetDisplay,
      repo_root: preparedRepoDir || (plans[0] ? plans[0].repo_root : ''),
      layout_key: layoutKey,
      bindings,
      git_checkout: checkout,
      plans,
      remote_error: null,
      fingerprint: fp,
    };
  };

  const applyNotebookPlan = (plan, { progressState = null, skipLock = false } = {}) =>
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
      skipLock,
      beforeRemoteWrite: () => assertGitOperationFinished(getRpc(), plan.repo_root || plan.target_dir, getLocale()),
    });

  const executeBatchPlan = (batch, { reportProgress = false, deadlineMs = 0 } = {}) => {
    const rpc = getRpc();
    const loc = getLocale();
    const dDir = resolveDataDir();
    if (deadlineMs && nowMsFn() >= deadlineMs) {
      throw new Error(
        tr(loc, 'Git 同步已到达后台执行时限，请重试', 'Git sync reached the background deadline. Retry to continue.')
      );
    }
    const cfg = batch.cfg;
    const repo = batch.repo_root;
    if (repo) assertGitOperationFinished(rpc, repo, loc);
    const legacyRoots = new Set();
    if (repo) legacyRoots.add(repo);
    for (const plan of batch.plans) {
      if (plan.target_dir) legacyRoots.add(plan.target_dir);
    }
    for (const rootDir of legacyRoots) {
      migrateLegacyRecoveryDirs(rpc, rootDir, { dataDir: dDir, nowMsFn });
    }
    if (repo && !isRemoteGitUrl(cfg.git_remote || '')) {
      const branch = gitBranch(cfg);
      const remotes = runGit(rpc, ['remote'], { cwd: repo, cfg, locale: loc });
      if (remotes.returncode !== 0) {
        throw new Error(tr(loc, '无法读取 Git 远端配置', 'Could not read Git remotes'));
      }
      const names = remotes.stdout.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
      if (names.length > 0) {
        const name = names.includes('origin') ? 'origin' : names[0];
        const head = runGit(rpc, ['rev-parse', '--verify', `refs/heads/${branch}`], { cwd: repo, cfg, locale: loc });
        if (head.returncode === 0 && head.stdout.trim()) {
          const remoteOid = getGitSyncedBranchOid(rpc, repo, branch, { remoteName: name, cfg, locale: loc });
          verifyGitPushHistory(rpc, repo, branch, head.stdout.trim(), remoteOid, cfg, loc);
        }
      }
    }

    let totalPushed = 0;
    let totalPulled = 0;
    let totalConflicts = 0;
    let reportedConflicts = 0;
    let totalAssets = 0;
    let totalDeleted = 0;

    let totalItems = 0;
    for (const p of batch.plans) {
      totalItems +=
        p.to_push_new.length +
        p.to_push_overwrite.length +
        p.to_pull_new.length +
        p.to_pull_overwrite.length +
        p.conflicts.length +
        (p.asset_view_copies || []).length +
        (p.assets_to_push_new || []).length +
        (p.assets_to_push_overwrite || []).length +
        (p.assets_to_pull_new || []).length +
        (p.assets_to_pull_overwrite || []).length +
        (p.asset_conflicts || []).length +
        (p.to_delete_remote || []).length +
        (p.to_delete_local || []).length +
        (p.assets_to_delete_remote || []).length +
        (p.assets_to_delete_local || []).length;
    }

    const progressState = reportProgress ? { done: 0, total: totalItems } : null;
    if (configStore && batch.layout_key && batch.bindings) {
      const layouts = { ...(configStore.state.syncMeta[LAYOUTS_META_KEY] || {}) };
      layouts[batch.layout_key] = { ...batch.bindings };
      configStore.state.syncMeta[LAYOUTS_META_KEY] = layouts;
    }

    const allPlannedGitWrites = [];
    if (repo) {
      for (const plan of batch.plans) {
        const sub = String(plan.subdir || '').replace(/^\/+|\/+$/g, '');
        const subPrefix = sub ? `${sub}/` : '';
        const rpm = plan.remote_path_map || {};
        const rapm = plan.remote_asset_path_map || {};
        const assetCopyMap = Object.fromEntries(plan.asset_conflicts || []);
        const remoteNotes = plan.remote_notes || {};
        for (const p of plan.to_push_new) allPlannedGitWrites.push(`${subPrefix}${rpm[p] || p}`);
        for (const p of plan.to_push_overwrite) allPlannedGitWrites.push(`${subPrefix}${rpm[p] || p}`);
        if (Object.keys(assetCopyMap).length > 0) {
          const readVerifiedRemote = (p) => {
            if (Object.hasOwn(remoteNotes, p)) return remoteNotes[p];
            if (typeof plan.read_remote_note !== 'function') return undefined;
            return plan.skips.run(p, () => {
              const txt = plan.read_remote_note(p);
              const expected = plan.remote_hashes?.[p];
              if (txt !== undefined && expected && sha256Text(txt, rpc) !== expected) {
                const err = new Error(tr(loc, `笔记在扫描后发生变化，已跳过等待重试：${p}`, `Note changed after scanning; skipped for retry: ${p}`));
                err.code = 'fs_error';
                throw err;
              }
              return txt;
            });
          };
          for (const p of plan.to_pull_new) {
            const origText = readVerifiedRemote(p);
            if (!plan.skips.has(p) && origText !== undefined && rewriteNoteAssetLinks(p, origText, assetCopyMap) !== origText) {
              allPlannedGitWrites.push(`${subPrefix}${rpm[p] || p}`);
            }
          }
          for (const p of plan.to_pull_overwrite) {
            const origText = readVerifiedRemote(p);
            if (!plan.skips.has(p) && origText !== undefined && rewriteNoteAssetLinks(p, origText, assetCopyMap) !== origText) {
              allPlannedGitWrites.push(`${subPrefix}${rpm[p] || p}`);
            }
          }
        }
        for (const [p, cp] of plan.conflicts) {
          allPlannedGitWrites.push(`${subPrefix}${rpm[p] || p}`);
          allPlannedGitWrites.push(`${subPrefix}${cp}`);
        }
        for (const [, cp] of plan.asset_view_copies || []) {
          allPlannedGitWrites.push(`${subPrefix}${cp}`);
        }
        for (const p of plan.assets_to_push_new || []) allPlannedGitWrites.push(`${subPrefix}${rapm[p] || p}`);
        for (const [p] of plan.assets_to_push_overwrite || []) allPlannedGitWrites.push(`${subPrefix}${rapm[p] || p}`);
        for (const [p, cp] of plan.asset_conflicts || []) {
          allPlannedGitWrites.push(`${subPrefix}${rapm[p] || p}`);
          allPlannedGitWrites.push(`${subPrefix}${cp}`);
        }
        for (const p of plan.synced) allPlannedGitWrites.push(`${subPrefix}${rpm[p] || p}`);
        for (const p of plan.assets_synced || []) allPlannedGitWrites.push(`${subPrefix}${rapm[p] || p}`);
        for (const p of plan.to_delete_remote || []) allPlannedGitWrites.push(`${subPrefix}${rpm[p] || p}`);
        for (const p of plan.assets_to_delete_remote || []) allPlannedGitWrites.push(`${subPrefix}${rapm[p] || p}`);
      }
    }

    const checkout = batch.git_checkout || null;
    if (repo && checkout) {
      gitCheckoutState(rpc, repo, cfg, checkout, loc);
    }
    if (repo && allPlannedGitWrites.length > 0) {
      checkGitIgnored(rpc, repo, allPlannedGitWrites, { cfg, locale: loc });
      checkGitStagedConflicts(rpc, repo, allPlannedGitWrites, {
        cfg,
        recover: !checkout,
        dataDir: dDir,
        pid,
        locale: loc,
      });
    }

    const pendingBaseMaps = [];
    const stagedGitPaths = [];
    const trackedGitPaths = [];
    const deletedGitPaths = [];
    const plannedGitBlobs = {};
    const pathOwners = new Map();

    for (const plan of batch.plans) {
      const res = applyNotebookPlan(plan, { progressState });
      totalPushed += res.pushed;
      totalPulled += res.pulled;
      totalConflicts += res.conflictCount;
      totalAssets += res.assetCount;
      totalDeleted += Number(plan._deleted_count || 0);
      const risks = planRiskMetrics(rpc, plan);
      reportedConflicts += risks.conflicts + risks.pull_conflict + risks.push_conflict;
      pendingBaseMaps.push([plan, res]);
      const prefix = plan.subdir ? `${plan.subdir}/` : '';
      const paths = [...res.writtenRemotePaths, ...res.syncedRepoPaths];
      for (const path of paths) {
        pathOwners.set(path, { plan, rel: path.slice(prefix.length) });
      }
      stagedGitPaths.push(...res.writtenRemotePaths);
      trackedGitPaths.push(...res.syncedRepoPaths);
      deletedGitPaths.push(...(plan._deleted_git_paths || []));
      Object.assign(plannedGitBlobs, res.plannedGitBlobs);
    }

    let didPush = false;
    if (repo) {
      if (reportProgress) {
        emitProgress({
          channel: 'git',
          done: totalItems > 0 ? totalItems : undefined,
          total: totalItems > 0 ? totalItems : undefined,
          label: tr(loc, '推送 Git…', 'Pushing Git…'),
          tone: 'accent',
          running: true,
        });
      }
      const skipStaleTmpScan = Boolean(
        batch.plans.length === 1 && !batch.plans[0].subdir && batch.plans[0]._remote_stale_tmp_clear === true
      );
      didPush = withTargetLock(
        rpc,
        repo,
        () => {
          const committed = commitAndPushGit(rpc, repo, cfg, {
            stagedRelPaths: stagedGitPaths,
            trackedPlanPaths: trackedGitPaths,
            plannedBlobs: plannedGitBlobs,
            onFileError: (path, exc) => {
              const owner = pathOwners.get(path);
              if (!owner?.plan.skips) throw exc;
              owner.plan.skips.recordError(owner.rel, exc);
            },
            onFileSuccess: (path) => pathOwners.get(path)?.plan.skips?.succeeded(),
            checkout,
            deletedRelPaths: deletedGitPaths,
            dataDir: dDir,
            pid,
            nowMsFn,
            sleepFn,
            deadlineMs,
            locale: loc,
            skipStaleTmpScan,
          });
          maybeRunGitAutoGc(rpc, repo, {
            dataDir: dDir,
            nowMsFn,
            cfg,
            locale: loc,
            didCommit: committed,
            deadlineMs,
          });
          return committed;
        },
        { dataDir: dDir, pid, nowMsFn, sleepFn }
      );
      if (configStore) {
        for (const [plan, res] of pendingBaseMaps) {
          const origBase = plan.identity_verified === true ? (plan.original_base_map || plan.base_map || {}) : (plan.base_map || {});
          if (plan.skips) {
            restoreSkippedBase(res.baseMap, origBase, plan.skips);
            pruneSkippedPatchEntries(res.partialBaseMap, res.deletedKeys, plan.skips);
          }
          commitPlanBaseline(configStore, plan, res, { markInitialized: true });
        }
      }
    }

    if (configStore) {
      configStore.state.stats.total_synced += totalPushed + totalPulled + totalConflicts;
      configStore.state.stats.last_sync = nowHms();
    }

    const skippedItems = collectSkippedItems(batch.plans);
    const skippedSummary = skippedItems.length ? formatSkippedCount(loc, skippedItems.length) : '';
    const totalNotes = totalPushed + totalPulled + totalConflicts;
    if (totalNotes === 0 && totalAssets === 0 && totalDeleted === 0) {
      if (didPush) {
        const summary = tr(loc, '已推送本地提交', 'Pushed local commits');
        return {
          status: '成功',
          summary: skippedSummary ? `${summary} · ${skippedSummary}` : summary,
          skipped_items: skippedItems,
          pushed: 0,
          pulled: 0,
          conflicts: 0,
          assets: 0,
          deleted: 0,
          did_push: true,
        };
      }
      return {
        status: '无变更',
        summary: skippedSummary || tr(loc, '已是最新', 'Up to date'),
        skipped_items: skippedItems,
        pushed: 0,
        pulled: 0,
        conflicts: 0,
        assets: 0,
        deleted: 0,
        did_push: false,
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
      did_push: didPush,
    };
  };

  const validateTarget = (cfg, notebooks) => {
    const loc = getLocale();
    const dDir = resolveDataDir();
    const homeDir = getHomeDir();
    if (!notebooks || notebooks.length === 0) {
      return tr(loc, '请至少选择一个笔记本', 'Select at least one notebook');
    }
    const rawRemote = String((cfg && cfg.git_remote) || '').trim();
    if (!rawRemote) {
      return tr(loc, '请先填写 Git 仓库地址', 'Enter a Git repository URL or folder first');
    }
    if (!isRemoteGitUrl(rawRemote)) {
      const localGit = resolveLocalGitDir(getRpc(), cfg, {
        dataDir: dDir,
        nbRoot: notebooks[0] || getNbRoot(),
        homeDir,
        locale: loc,
      });
      for (const nb of notebooks) {
        if (pathsOverlap(nb, localGit)) {
          const lbl = notebookLabel(nb, loc, '', homeDir);
          return tr(
            loc,
            `Git 本地仓库目录不能与笔记本「${lbl}」重合或互为父子目录`,
            `Local Git repository folder cannot match or nest inside notebook ${lbl}`
          );
        }
      }
    }
    return '';
  };

  const syncGit = ({
    cfg = null,
    notebooks = null,
    onlyPath = null,
    onlyNbRoot = null,
    confirmed = false,
    approvedBatch = null,
    reportProgress = false,
    deadlineMs = 0,
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

    const dDir = resolveDataDir();
    if (!isRemoteGitUrl(String((effectiveCfg && effectiveCfg.git_remote) || '').trim())) {
      const localGit = resolveLocalGitDir(rpc, effectiveCfg, {
        dataDir: dDir,
        nbRoot: targetNotebooks[0] || getNbRoot(),
        homeDir: getHomeDir(),
        locale: loc,
      });
      migrateLegacyRecoveryDirs(rpc, localGit, { dataDir: dDir, nowMsFn });
    }

    const batch =
      approvedBatch ||
      computeBatchPlan({
        cfg: effectiveCfg,
        notebooks: targetNotebooks,
        onlyPath,
        inspectRemote: true,
        deadlineMs,
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

    const result = executeBatchPlan(batch, { reportProgress, deadlineMs });
    if (configStore && confirmed) {
      configStore.clearPendingConfirm('git');
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
    syncGit,
  };
}
